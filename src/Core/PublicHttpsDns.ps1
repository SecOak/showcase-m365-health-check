function Invoke-SecOakPublicHttpsGet {
    <#
    .SYNOPSIS
        Issues one read-only HTTPS GET to an approved public source and logs it.
    .DESCRIPTION
        Only these hosts are accepted: crt.sh, rdap.org, login.microsoftonline.com (the
        /getuserrealm.srf path only), cloudflare-dns.com, and mta-sts.<domain>. Redirects are
        not followed unless -FollowRedirect is set (used for rdap.org, which redirects to the
        registry's own RDAP server); each hop is logged separately and must also be HTTPS.
        No credentials, cookies, or tokens are sent. Failures are returned, never thrown.
    .PARAMETER Check
        Check name for the endpoint log.
    .PARAMETER Uri
        The HTTPS address to read.
    .PARAMETER TimeoutSeconds
        Request timeout. Defaults to 20 seconds.
    .PARAMETER Accept
        Optional Accept header, for example application/dns-json.
    .PARAMETER FollowRedirect
        Follow up to three HTTPS redirects (rdap.org only).
    .OUTPUTS
        Object with Success, StatusCode, Content, Json, FinalUri, and Error.
    .EXAMPLE
        Invoke-SecOakPublicHttpsGet -Check 'Domain/Registration' -Uri 'https://rdap.org/domain/contoso.com' -FollowRedirect
    .NOTES
        No tenant permissions. The domain name in the address is disclosed to the host contacted.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidatePattern('^https://')][string]$Uri,
        [Parameter()][ValidateRange(5, 120)][int]$TimeoutSeconds = 20,
        [Parameter()][string]$Accept = '',
        [Parameter()][switch]$FollowRedirect
    )
    $current = [uri]$Uri
    $hostName = $current.Host.ToLowerInvariant()
    $allowed = ($hostName -in $script:PublicHttpsHosts -and ($hostName -ne 'login.microsoftonline.com' -or $current.AbsolutePath -eq '/getuserrealm.srf')) -or
        ($hostName -match '^mta-sts\.' -and $current.AbsolutePath -eq '/.well-known/mta-sts.txt')
    if (-not $allowed) { throw "Refusing to contact $hostName; it is not on the approved list of public sources." }
    if ($FollowRedirect -and $hostName -ne 'rdap.org') { throw 'Redirects are followed for rdap.org only.' }

    $headers = @{}
    if ($Accept) { $headers.Accept = $Accept }
    $hops = 0
    while ($true) {
        $statusCode = 0
        $content = $null
        $location = $null
        $errorText = $null
        try {
            $response = Invoke-WebRequest -Method Get -Uri $current -Headers $headers -UserAgent $script:PublicUserAgent `
                -MaximumRedirection 0 -TimeoutSec $TimeoutSeconds -ErrorAction Stop
            $statusCode = [int]$response.StatusCode
            $content = if ($response.Content -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($response.Content) } else { [string]$response.Content }
        }
        catch {
            $httpResponse = $_.Exception.PSObject.Properties['Response']
            if ($httpResponse -and $httpResponse.Value) {
                $statusCode = [int]$httpResponse.Value.StatusCode
                if ($httpResponse.Value.Headers.Location) { $location = $httpResponse.Value.Headers.Location }
            }
            $errorText = ($_.Exception.Message -replace '\s+', ' ')
        }
        $isRedirect = $statusCode -ge 300 -and $statusCode -lt 400 -and $location
        $resultText = if ($statusCode) { "$statusCode" } else { 'error' }
        $notes = if ($isRedirect) { "redirect to $(([uri]::new($current, $location)).Host)" } elseif ($errorText) { $errorText } else { "bytes=$(if ($content) { $content.Length } else { 0 })" }
        Add-SecOakEndpointLogEntry -Check $Check -Tool HTTPS -Method GET -EndpointOrCmdlet $current.AbsoluteUri -HttpStatusOrResult $resultText `
            -AuthUsed none -AppOnlyResult 'not attempted' -Notes $notes

        if ($isRedirect -and $FollowRedirect -and $hops -lt 3) {
            $next = [uri]::new($current, $location)
            if ($next.Scheme -ne 'https') {
                return [pscustomobject]@{ Success = $false; StatusCode = $statusCode; Content = $null; Json = $null; FinalUri = $current.AbsoluteUri; Error = 'Redirect to a non-HTTPS address was not followed.' }
            }
            $current = $next
            $hops++
            continue
        }
        $success = $statusCode -ge 200 -and $statusCode -lt 300
        $json = $null
        $trimmed = if ($content) { $content.TrimStart() } else { '' }
        if ($success -and $trimmed.Length -and $trimmed.Substring(0, 1) -in '{', '[') {
            try { $json = $content | ConvertFrom-Json -Depth 30 -ErrorAction Stop }
            catch { Write-Verbose "Response from $($current.Host) is not valid JSON: $($_.Exception.Message)" }
        }
        if (-not $success -and -not $errorText) { $errorText = "HTTP $statusCode" }
        return [pscustomobject]@{ Success = $success; StatusCode = $statusCode; Content = $content; Json = $json; FinalUri = $current.AbsoluteUri; Error = $errorText }
    }
}

function ConvertFrom-SecOakDohData {
    <#
    .SYNOPSIS
        Converts one DNS over HTTPS JSON answer value into the text form Resolve-DnsName returns.
    .PARAMETER Type
        The record type that was queried.
    .PARAMETER Data
        The data field of the answer.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Data
    )
    if ($Type -eq 'TXT') {
        $parts = [regex]::Matches($Data, '"((?:[^"\\]|\\.)*)"')
        if ($parts.Count) { return (($parts | ForEach-Object { $_.Groups[1].Value -replace '\\"', '"' }) -join '') }
        return $Data
    }
    if ($Type -eq 'CAA' -and $Data -match '^\\#\s+\d+\s+(.+)$') {
        # Generic encoding (RFC 3597): flags byte, tag length byte, tag, value.
        $bytes = [byte[]]@($Matches[1] -split '\s+' | Where-Object { $_ } | ForEach-Object { [Convert]::ToByte($_, 16) })
        if ($bytes.Count -lt 2) { return $Data }
        $tagLength = $bytes[1]
        $tag = [System.Text.Encoding]::ASCII.GetString($bytes, 2, $tagLength)
        $value = [System.Text.Encoding]::ASCII.GetString($bytes, 2 + $tagLength, $bytes.Count - 2 - $tagLength)
        return ('{0} {1} "{2}"' -f $bytes[0], $tag, $value)
    }
    if ($Type -eq 'MX' -and $Data -match '^\d+\s+(\S+)$') { return $Matches[1] }
    $Data
}

function Resolve-SecOakDnsRecord {
    <#
    .SYNOPSIS
        Resolves one public DNS record type for a name and logs the lookup.
    .DESCRIPTION
        Uses Resolve-DnsName with the system resolver. Record types that Resolve-DnsName
        cannot query on this machine (CAA, or every type when the cmdlet is missing) are
        read through DNS over HTTPS from cloudflare-dns.com instead, which is logged as an
        HTTPS GET. Status distinguishes a name that does not exist (nxdomain) from a name
        that exists without the record type (no record).
    .PARAMETER Check
        Check name for the endpoint log.
    .PARAMETER Name
        The DNS name to query.
    .PARAMETER Type
        A, AAAA, CNAME, MX, NS, TXT, DS, or CAA.
    .OUTPUTS
        Object with Found, Values, Status (ok, no record, nxdomain, error), Error, and Source.
        MX values are the mail server names ("." for a null MX); DS values are
        "key-tag algorithm digest-type".
    .EXAMPLE
        Resolve-SecOakDnsRecord -Check 'Domain/Spf' -Name contoso.com -Type TXT
    .NOTES
        No tenant permissions. Public DNS only; the DNS over HTTPS fallback discloses the
        queried name to Cloudflare.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9\.\-_]+$')][string]$Name,
        [Parameter(Mandatory)][ValidateSet('A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'DS', 'CAA')][string]$Type
    )
    $values = @()
    $status = 'ok'
    $errorText = $null
    $useDoh = $Type -eq 'CAA' -or -not (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue)

    if ($useDoh) {
        $uri = 'https://cloudflare-dns.com/dns-query?name={0}&type={1}' -f [uri]::EscapeDataString($Name), $Type
        $response = Invoke-SecOakPublicHttpsGet -Check $Check -Uri $uri -Accept 'application/dns-json' -TimeoutSeconds 15
        if (-not $response.Success -or -not $response.Json) {
            $status = 'error'
            $errorText = "DNS over HTTPS failed: $($response.Error)"
        }
        elseif ($response.Json.Status -eq 3) { $status = 'nxdomain' }
        elseif ($response.Json.Status -ne 0) { $status = 'error'; $errorText = "DNS over HTTPS response code $($response.Json.Status)" }
        else {
            $typeNumber = $script:DnsTypeNumbers[$Type]
            $values = @($response.Json.Answer | Where-Object { $_ -and $_.type -eq $typeNumber } |
                    ForEach-Object { ConvertFrom-SecOakDohData -Type $Type -Data "$($_.data)" })
            if ($Type -in 'CNAME', 'NS', 'MX') { $values = @($values | ForEach-Object { if ($_ -eq '.') { $_ } else { $_.TrimEnd('.') } }) }
            if (-not $values) { $status = 'no record' }
        }
        return [pscustomobject]@{ Found = [bool]$values; Values = $values; Status = $status; Error = $errorText; Source = 'DNS over HTTPS' }
    }

    try {
        $records = @(Resolve-DnsName -Name $Name -Type $Type -DnsOnly -QuickTimeout -ErrorAction Stop | Where-Object { "$($_.Section)" -eq 'Answer' })
        $values = switch ($Type) {
            'TXT'   { @($records | Where-Object { "$($_.Type)" -eq 'TXT' } | ForEach-Object { ($_.Strings -join '') }) }
            'CNAME' { @($records | Where-Object { "$($_.Type)" -eq 'CNAME' } | Select-Object -First 1 | ForEach-Object NameHost) }
            'NS'    { @($records | Where-Object { "$($_.Type)" -eq 'NS' } | ForEach-Object NameHost) }
            'MX'    { @($records | Where-Object { "$($_.Type)" -eq 'MX' } | Sort-Object Preference | ForEach-Object { if ("$($_.NameExchange)" -in '', '.') { '.' } else { "$($_.NameExchange)" } }) }
            'DS'    { @($records | Where-Object { "$($_.Type)" -eq 'DS' } | ForEach-Object { '{0} {1} {2}' -f $_.KeyTag, $_.Algorithm, $_.DigestType }) }
            default { @($records | Where-Object { "$($_.Type)" -eq $Type } | ForEach-Object { "$($_.IPAddress)" }) }
        }
        $values = @($values | Where-Object { $_ })
        if (-not $values) { $status = 'no record' }
    }
    catch {
        $errorText = ($_.Exception.Message -replace '\s+', ' ')
        $status = if ($errorText -match 'DNS name does not exist|does not exist|No such host|9003') { 'nxdomain' }
        elseif ($errorText -match 'No records|9501') { 'no record' }
        else { 'error' }
        if ($errorText -match 'DNS server failure|9002') {
            $errorText = 'DNS server failure (SERVFAIL): the resolver could not get an answer from the authoritative DNS servers for this name. This usually points to a problem at the DNS host, such as a broken delegation or a DNSSEC signing fault.'
        }
    }
    Add-SecOakEndpointLogEntry -Check $Check -Tool DNS -Method QUERY -EndpointOrCmdlet "$Type $Name" -HttpStatusOrResult $status -AuthUsed none -AppOnlyResult 'not attempted' `
        -Notes $(if ($status -eq 'error') { $errorText } else { '' })
    [pscustomobject]@{ Found = [bool]$values; Values = $values; Status = $status; Error = if ($status -eq 'error') { $errorText } else { $null }; Source = 'Resolve-DnsName' }
}
