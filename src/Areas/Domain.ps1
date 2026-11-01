function Get-SecOakRegistrableDomain {
    <#
    .SYNOPSIS
        Returns the registrable domain (for example contoso.com or contoso.co.uk) for a name.
    .DESCRIPTION
        A small heuristic, not the full public suffix list: two labels, or three when the
        name ends in a common two-part country suffix such as co.uk or com.au.
    .PARAMETER Domain
        The domain or host name.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Domain)
    $labels = @($Domain.ToLowerInvariant().TrimEnd('.').Split('.'))
    if ($labels.Count -le 2) { return ($labels -join '.') }
    $secondLevels = @('co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'ltd', 'plc', 'nhs', 'sch', 'nom', 'gv', 'mil')
    $take = if ($labels[-1].Length -eq 2 -and $labels[-2] -in $secondLevels) { 3 } else { 2 }
    (@($labels | Select-Object -Last $take)) -join '.'
}

function Measure-SecOakSpfRecord {
    <#
    .SYNOPSIS
        Walks one SPF record, counting DNS-querying terms and following include and redirect.
    .PARAMETER Record
        The SPF record text.
    .PARAMETER State
        Shared evaluation state (lookup count, record cache, problems).
    .PARAMETER Depth
        Current include depth.
    .OUTPUTS
        Hashtable with AllQualifier and AuthorizesSenders for this record.
    .NOTES
        Internal helper. Public DNS only. Counting follows RFC 7208 section 4.6.4: include,
        a, mx, ptr, exists, and redirect each cost one lookup; ip4, ip6, and all cost none.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][string]$Record,
        [Parameter(Mandatory)][hashtable]$State,
        [Parameter(Mandatory)][int]$Depth
    )
    $allQualifier = $null
    $redirect = $null
    $authorizes = $false
    $resolveChild = {
        param([string]$Target)
        if ($Target -match '%\{') { $State.Problems.Add("Macro in '$Target' was not expanded; its lookups are not counted."); return $null }
        $name = $Target.TrimEnd('.').ToLowerInvariant()
        if ($Depth -ge 10 -or $State.Lookups -gt 30) { $State.Problems.Add("Stopped following '$name': include depth or lookup limit reached."); return $null }
        if (-not $State.Records.ContainsKey($name)) {
            try {
                $lookup = Resolve-SecOakDnsRecord -Check 'Domain/SpfLookups' -Name $name -Type TXT -ErrorAction Stop
                $State.Records[$name] = [pscustomobject]@{ Status = $lookup.Status; Spf = @($lookup.Values | Where-Object { $_ -match '^(?i)v=spf1(\s|$)' }) }
            }
            catch { $State.Records[$name] = [pscustomobject]@{ Status = 'invalid name'; Spf = @() } }
        }
        $child = $State.Records[$name]
        if ($child.Status -eq 'error') { $State.Problems.Add("Lookup for '$name' failed; its lookups are not counted."); return $null }
        if ($child.Spf.Count -eq 0) { $State.Problems.Add("'$name' has no SPF record (permanent error for receivers)."); $State.PermanentError = $true; return $null }
        if ($child.Spf.Count -gt 1) { $State.Problems.Add("'$name' publishes more than one SPF record (permanent error for receivers)."); $State.PermanentError = $true }
        Measure-SecOakSpfRecord -Record $child.Spf[0] -State $State -Depth ($Depth + 1)
    }

    foreach ($term in @($Record -split '\s+' | Select-Object -Skip 1 | Where-Object { $_ })) {
        $qualifier = '+'
        $body = $term
        if ($term.Substring(0, 1) -in '+', '-', '~', '?') { $qualifier = $term.Substring(0, 1); $body = $term.Substring(1) }
        $mechanism = ($body -split '[:=/]', 2)[0].ToLowerInvariant()
        $target = if ($body -match '^[^:=]+[:=]([^/]+)') { $Matches[1] } else { $null }
        switch ($mechanism) {
            'include' {
                $State.Lookups++
                $authorizes = $true
                if ($target) {
                    $State.Includes.Add($target.ToLowerInvariant())
                    $null = & $resolveChild $target
                }
            }
            'redirect' { $State.Lookups++; $redirect = $target }
            { $_ -in 'a', 'mx', 'exists' } { $State.Lookups++; $authorizes = $true }
            'ptr' { $State.Lookups++; $State.UsesPtr = $true; $authorizes = $true }
            { $_ -in 'ip4', 'ip6' } { $authorizes = $true }
            'all' { $allQualifier = "${qualifier}all" }
        }
    }
    if (-not $allQualifier -and $redirect) {
        $State.Includes.Add($redirect.ToLowerInvariant())
        $child = & $resolveChild $redirect
        if ($child) { $allQualifier = $child.AllQualifier; $authorizes = $authorizes -or $child.AuthorizesSenders }
    }
    @{ AllQualifier = if ($allQualifier) { $allQualifier } else { 'none' }; AuthorizesSenders = $authorizes }
}

function Get-SecOakSpfEvaluation {
    <#
    .SYNOPSIS
        Evaluates an SPF record: recursive DNS lookup count, final all qualifier, ptr use.
    .PARAMETER Record
        The SPF record text.
    .OUTPUTS
        Object with LookupCount, AllQualifier, UsesPtr, AuthorizesSenders, Includes,
        PermanentError, and Problems.
    .NOTES
        Internal helper. Public DNS only (each include and redirect target is resolved once).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string]$Record)
    $state = @{
        Lookups        = 0
        UsesPtr        = $false
        PermanentError = $false
        Includes       = [System.Collections.Generic.List[string]]::new()
        Problems       = [System.Collections.Generic.List[string]]::new()
        Records        = @{}
    }
    $top = Measure-SecOakSpfRecord -Record $Record -State $state -Depth 0
    [pscustomobject][ordered]@{
        LookupCount       = $state.Lookups
        AllQualifier      = $top.AllQualifier
        UsesPtr           = $state.UsesPtr
        AuthorizesSenders = [bool]$top.AuthorizesSenders
        Includes          = @($state.Includes | Select-Object -Unique)
        PermanentError    = $state.PermanentError -or $state.Lookups -gt 10
        Problems          = $state.Problems.ToArray()
    }
}

function Get-SecOakLookalikeCandidate {
    <#
    .SYNOPSIS
        Generates a bounded list of lookalike domains for a registrable domain.
    .DESCRIPTION
        Top-level domain swaps (.com .net .org .co .io .us), common homoglyphs (rn/m, l/1,
        o/0, i/l, vv/w, cl/d), character omission, adjacent character swaps, and character
        repetition of the second-level label. No dictionary or brute-force generation.
    .PARAMETER RegistrableDomain
        For example contoso.com.
    .PARAMETER Maximum
        Maximum number of candidates. Defaults to 150.
    .NOTES
        Internal helper. No network access.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$RegistrableDomain,
        [Parameter()][ValidateRange(1, 300)][int]$Maximum = 150
    )
    $original = $RegistrableDomain.ToLowerInvariant()
    $label, $suffix = $original.Split('.', 2)
    $candidates = [System.Collections.Generic.List[string]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $add = {
        param([string]$Label, [string]$Suffix)
        $candidate = "$Label.$Suffix"
        if ($Label -match '^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$' -and $candidate -ne $original -and $seen.Add($candidate)) { $candidates.Add($candidate) }
    }
    foreach ($topLevel in 'com', 'net', 'org', 'co', 'io', 'us') { & $add $label $topLevel }
    $homoglyphs = @(@('rn', 'm'), @('m', 'rn'), @('l', '1'), @('1', 'l'), @('o', '0'), @('0', 'o'), @('i', 'l'), @('l', 'i'), @('vv', 'w'), @('w', 'vv'), @('cl', 'd'), @('d', 'cl'))
    foreach ($pair in $homoglyphs) {
        $index = $label.IndexOf($pair[0])
        while ($index -ge 0) {
            & $add ($label.Substring(0, $index) + $pair[1] + $label.Substring($index + $pair[0].Length)) $suffix
            $index = $label.IndexOf($pair[0], $index + 1)
        }
    }
    for ($i = 0; $i -lt $label.Length; $i++) { & $add $label.Remove($i, 1) $suffix }
    for ($i = 0; $i -lt $label.Length - 1; $i++) {
        if ($label[$i] -ne $label[$i + 1]) { & $add ($label.Substring(0, $i) + $label[$i + 1] + $label[$i] + $label.Substring($i + 2)) $suffix }
    }
    for ($i = 0; $i -lt $label.Length; $i++) { & $add $label.Insert($i, [string]$label[$i]) $suffix }
    @($candidates | Select-Object -First $Maximum)
}

function Get-SecOakDomainPosture {
    <#
    .SYNOPSIS
        Collects the public posture of one domain and returns its findings and summary.
    .DESCRIPTION
        Mail routing (MX), SPF with a recursive lookup count, DMARC, Microsoft 365 DKIM
        selector CNAMEs, MTA-STS, TLS reporting, BIMI, DNSSEC, CAA, registration (RDAP),
        certificate transparency hostnames (crt.sh), dangling CNAMEs among those hostnames,
        the Microsoft Entra sign-in realm, and registered lookalike domains. A failed source
        becomes a gap; the other checks still run.
    .PARAMETER Context
        The run context (for gaps, raw exports, and the shared cache).
    .PARAMETER Domain
        The domain to check.
    .PARAMETER TenantDomain
        The domain is a verified domain of the Microsoft 365 tenant being checked.
    .PARAMETER KnownDomain
        Domains known to belong to the client; they are never reported as lookalikes.
    .OUTPUTS
        Object with Domain, Summary, and Findings.
    .NOTES
        Internal helper. No tenant permissions. Public DNS queries plus HTTPS GET to crt.sh,
        rdap.org (and the registry RDAP server it redirects to), login.microsoftonline.com
        (getuserrealm.srf), mta-sts.<domain>, and cloudflare-dns.com (CAA lookups). Each of
        those services receives the domain name.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidateScript({ $_ -match $script:HostnamePattern })][string]$Domain,
        [Parameter()][switch]$TenantDomain,
        [Parameter()][AllowEmptyCollection()][string[]]$KnownDomain = @()
    )
    $domain = $Domain.ToLowerInvariant().TrimEnd('.')
    $registrable = Get-SecOakRegistrableDomain -Domain $domain
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{ domain = $domain; registrableDomain = $registrable }
    $raw = [ordered]@{ domain = $domain; collectedUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') }
    $dnsFix = 'Rerun from a network with working DNS resolution. No permission is involved.'
    $progress = @{ Id = 2; Activity = "Domain checks: $domain" }

    $addFinding = {
        param([string]$Id, [string]$Severity, [string]$Title, [System.Collections.IDictionary]$Evidence, [string]$Risk, [string]$Recommendation)
        $fullEvidence = [ordered]@{ domain = $domain }
        foreach ($key in $Evidence.Keys) { $fullEvidence[$key] = $Evidence[$key] }
        $findings.Add((New-SecOakFinding -Id $Id -Area 'Domain' -Severity $Severity -BaselineControl 'None' -Title "$Title ($domain)" `
                    -Evidence $fullEvidence -Risk $Risk -Recommendation $Recommendation))
    }
    $addGap = {
        param([string]$Check, [string]$Endpoint, [string]$Result, [string]$Reason, [string]$FillWith)
        Add-SecOakGap -Context $Context -Area 'Domain' -Check $Check -EndpointOrCmdlet $Endpoint -Result $Result -Reason $Reason -FillWith $FillWith
    }

    #--- Mail routing
    Write-Progress @progress -Status 'Mail routing (MX)' -PercentComplete 5
    $mx = Resolve-SecOakDnsRecord -Check 'Domain/Mx' -Name $domain -Type MX
    $mxHosts = @($mx.Values | Where-Object { $_ -ne '.' } | ForEach-Object { "$_".TrimEnd('.').ToLowerInvariant() })
    $nullMx = $mx.Found -and -not $mxHosts
    $microsoftMx = @($mxHosts | Where-Object { $_ -like '*.mail.protection.outlook.com' })
    $gatewayMx = @($mxHosts | Where-Object { $_ -notlike '*.mail.protection.outlook.com' })
    if ($mx.Status -eq 'error') { & $addGap 'Domain/Mx' "MX $domain" 'error' "MX lookup failed: $($mx.Error)" $dnsFix }
    $receivesMail = [bool]$mxHosts -or $mx.Status -eq 'error'
    $summary.mx = [ordered]@{ status = $mx.Status; hosts = $mxHosts; nullMx = $nullMx; routesToMicrosoft365 = [bool]$microsoftMx; thirdPartyGateway = $gatewayMx }
    $raw.mx = $mx
    if ($gatewayMx) {
        & $addFinding 'DOMAIN-01' 'Low' 'Inbound mail routes through a third-party gateway' ([ordered]@{ mxHosts = $mxHosts; gatewayHosts = $gatewayMx }) `
            'All inbound mail passes through the gateway provider first. If Microsoft 365 also accepts mail sent straight to the tenant, attackers can skip the gateway filtering.' `
            'Confirm the gateway is approved and monitored. If it delivers into Microsoft 365, restrict the inbound connector to the gateway and turn on enhanced filtering for connectors.'
    }

    #--- SPF
    Write-Progress @progress -Status 'SPF' -PercentComplete 10
    $txt = Resolve-SecOakDnsRecord -Check 'Domain/Spf' -Name $domain -Type TXT
    $spfRecords = @($txt.Values | Where-Object { $_ -match '^(?i)v=spf1(\s|$)' })
    $spf = $null
    if ($txt.Status -eq 'error') { & $addGap 'Domain/Spf' "TXT $domain" 'error' "TXT lookup failed: $($txt.Error)" $dnsFix }
    elseif ($spfRecords.Count -ge 1) { $spf = Get-SecOakSpfEvaluation -Record $spfRecords[0] }
    $sendsMail = $spf -and $spf.AuthorizesSenders
    $isMailDomain = $receivesMail -or $sendsMail
    $summary.mailDomain = $isMailDomain
    $summary.spf = [ordered]@{
        records      = $spfRecords
        lookupCount  = if ($spf) { $spf.LookupCount } else { $null }
        allQualifier = if ($spf) { $spf.AllQualifier } else { $null }
        usesPtr      = if ($spf) { $spf.UsesPtr } else { $null }
        includes     = @(if ($spf) { $spf.Includes })
        problems     = @(if ($spf) { $spf.Problems })
    }
    $raw.txt = $txt
    $raw.spfEvaluation = $spf

    #--- DMARC (with the organizational domain record as the fallback for subdomains)
    Write-Progress @progress -Status 'DMARC' -PercentComplete 15
    $dmarcLookup = Resolve-SecOakDnsRecord -Check 'Domain/Dmarc' -Name "_dmarc.$domain" -Type TXT
    $dmarcRecords = @($dmarcLookup.Values | Where-Object { $_ -match '^(?i)v=DMARC1' })
    $dmarcSource = $domain
    if (-not $dmarcRecords -and $dmarcLookup.Status -ne 'error' -and $registrable -ne $domain) {
        $organizational = Resolve-SecOakDnsRecord -Check 'Domain/Dmarc' -Name "_dmarc.$registrable" -Type TXT
        $dmarcRecords = @($organizational.Values | Where-Object { $_ -match '^(?i)v=DMARC1' })
        if ($dmarcRecords) { $dmarcSource = $registrable }
    }
    if ($dmarcLookup.Status -eq 'error') { & $addGap 'Domain/Dmarc' "TXT _dmarc.$domain" 'error' "DMARC lookup failed: $($dmarcLookup.Error)" $dnsFix }
    $dmarcTags = @{}
    if ($dmarcRecords.Count -eq 1) {
        foreach ($pair in ($dmarcRecords[0] -split ';')) {
            $key, $value = $pair.Split('=', 2)
            if ($key -and $null -ne $value) { $dmarcTags[$key.Trim().ToLowerInvariant()] = $value.Trim() }
        }
    }
    $policyRank = @{ none = 0; quarantine = 1; reject = 2 }
    $dmarcPolicy = if ($dmarcRecords.Count -eq 1) { if ($dmarcTags.p -and $policyRank.ContainsKey($dmarcTags.p.ToLowerInvariant())) { $dmarcTags.p.ToLowerInvariant() } else { 'none' } } else { $null }
    $subdomainPolicy = if ($dmarcTags.sp -and $policyRank.ContainsKey($dmarcTags.sp.ToLowerInvariant())) { $dmarcTags.sp.ToLowerInvariant() } else { $null }
    # A subdomain that inherits the organizational record is governed by sp when it is set.
    $effectivePolicy = if ($dmarcSource -ne $domain -and $subdomainPolicy) { $subdomainPolicy } else { $dmarcPolicy }
    $dmarcPercent = if ($dmarcTags.pct -match '^\d+$') { [int]$dmarcTags.pct } elseif ($dmarcPolicy) { 100 } else { $null }
    $summary.dmarc = [ordered]@{
        records = $dmarcRecords; source = $dmarcSource; policy = $dmarcPolicy; subdomainPolicy = $subdomainPolicy
        effectivePolicy = $effectivePolicy; percent = $dmarcPercent; aggregateReporting = [bool]$dmarcTags.rua
    }
    $raw.dmarc = [ordered]@{ lookup = $dmarcLookup; records = $dmarcRecords; source = $dmarcSource }
    $dmarcEnforcing = $effectivePolicy -in 'quarantine', 'reject'

    if ($isMailDomain) {
        if ($txt.Status -ne 'error' -and $spfRecords.Count -eq 0) {
            & $addFinding 'DOMAIN-02' 'High' 'SPF record missing' ([ordered]@{ mxHosts = $mxHosts; txtRecords = $txt.Values.Count }) `
                'Receiving mail systems cannot tell which servers may send mail as this domain, so forged mail is much more likely to be delivered.' `
                'Publish exactly one SPF record listing every legitimate sender (include:spf.protection.outlook.com for Microsoft 365) ending in -all, or ~all while DMARC is enforcing.'
        }
        if ($spf) {
            $severity = switch ($spf.AllQualifier) { '+all' { 'High' } '?all' { 'Medium' } 'none' { 'Medium' } '~all' { if ($dmarcEnforcing) { $null } else { 'Low' } } default { $null } }
            if ($severity) {
                & $addFinding 'DOMAIN-05' $severity 'SPF record does not fail unauthorized senders' ([ordered]@{ allQualifier = $spf.AllQualifier; dmarcPolicy = $effectivePolicy; record = $spfRecords[0] }) `
                    $(if ($spf.AllQualifier -eq '+all') { 'The +all ending authorizes every server on the internet to send as this domain, which makes SPF useless.' } else { 'Mail from unauthorized servers is not failed by SPF, and without an enforcing DMARC policy receivers are not told to reject it.' }) `
                    'End the SPF record with -all (or ~all once DMARC is at quarantine or reject), after confirming every legitimate sender is listed.'
            }
        }
        if (-not $dmarcRecords -or $dmarcRecords.Count -gt 1) {
            if ($dmarcLookup.Status -ne 'error') {
                & $addFinding 'DOMAIN-07' 'High' $(if ($dmarcRecords.Count -gt 1) { 'DMARC record invalid (more than one record)' } else { 'DMARC record missing' }) ([ordered]@{ records = $dmarcRecords.Count; queried = "_dmarc.$domain" }) `
                    'Receiving mail systems are not told to reject forged mail from this domain, which makes invoice fraud and phishing that impersonates the company easy.' `
                    'Publish one DMARC record with rua reporting, review the reports for two to four weeks, then move to p=quarantine and p=reject.'
            }
        }
        else {
            if ($effectivePolicy -eq 'none') {
                & $addFinding 'DOMAIN-08' 'Medium' 'DMARC policy is monitor-only (p=none)' ([ordered]@{ record = $dmarcRecords[0]; source = $dmarcSource }) `
                    'Forged mail that fails DMARC is still delivered; the record only produces reports.' `
                    'Review the aggregate reports, fix legitimate senders, then move to p=quarantine and p=reject.'
            }
            if ($dmarcEnforcing -and $dmarcPercent -lt 100) {
                & $addFinding 'DOMAIN-09' 'Low' 'DMARC policy applies to only part of the mail (pct under 100)' ([ordered]@{ percent = $dmarcPercent; policy = $effectivePolicy }) `
                    'Receivers apply the policy to only a sample of failing mail; the rest is treated as p=none.' `
                    'Raise pct to 100 (or remove the tag) once reports show legitimate mail passes.'
            }
            if ($dmarcSource -eq $domain -and $subdomainPolicy -and $policyRank[$subdomainPolicy] -lt $policyRank[$dmarcPolicy]) {
                & $addFinding 'DOMAIN-10' 'Low' 'DMARC subdomain policy is weaker than the domain policy' ([ordered]@{ policy = $dmarcPolicy; subdomainPolicy = $subdomainPolicy }) `
                    'Attackers can forge mail from made-up subdomains (for example billing.<domain>) and receivers apply the weaker policy.' `
                    'Set sp to the same value as p, or remove sp so subdomains inherit p.'
            }
            if (-not $dmarcTags.rua) {
                & $addFinding 'DOMAIN-11' 'Low' 'DMARC record without aggregate reporting' ([ordered]@{ record = $dmarcRecords[0] }) `
                    'Without reports nobody sees who is sending mail as the domain, legitimate or not.' `
                    'Add rua=mailto:<reporting address> to the DMARC record and send reports to a monitored mailbox or DMARC service.'
            }
        }
    }
    else {
        $spfLocked = $spfRecords.Count -eq 1 -and (($spfRecords[0] -replace '\s+', ' ').Trim().ToLowerInvariant() -eq 'v=spf1 -all')
        if (-not $spfLocked -or $effectivePolicy -ne 'reject') {
            & $addFinding 'DOMAIN-13' 'Medium' 'Domain that does not send mail is not locked against spoofing' ([ordered]@{ nullMx = $nullMx; spf = $(if ($spfRecords) { $spfRecords[0] } else { 'none' }); dmarcPolicy = $(if ($effectivePolicy) { $effectivePolicy } else { 'none' }) }) `
                'Domains with no mail servers are attractive for spoofing because nobody watches them. Without SPF and DMARC saying "no mail from here", forged mail can be delivered.' `
                'Publish "v=spf1 -all" as the SPF record and "v=DMARC1; p=reject;" as the DMARC record (optionally a null MX "0 .").'
        }
    }
    if ($spfRecords.Count -gt 1) {
        & $addFinding 'DOMAIN-03' 'High' 'More than one SPF record' ([ordered]@{ records = $spfRecords }) `
            'Receivers treat more than one SPF record as a permanent error, so SPF fails for all mail from the domain.' `
            'Merge the records into a single SPF record.'
    }
    if ($spf -and $spf.PermanentError) {
        & $addFinding 'DOMAIN-04' 'High' 'SPF record causes a permanent error (more than 10 DNS lookups or a broken include)' ([ordered]@{ lookupCount = $spf.LookupCount; problems = (Select-SecOakExample $spf.Problems -Count 5); includes = (Select-SecOakExample $spf.Includes -Count 10) }) `
            'Receivers stop evaluating SPF after 10 DNS lookups or on a broken include and return a permanent error, so SPF fails for legitimate mail and gives no protection.' `
            'Remove unused include entries, replace includes with ip4 or ip6 ranges where the provider allows it, and keep the total at 10 lookups or fewer.'
    }
    if ($spf -and $spf.UsesPtr) {
        & $addFinding 'DOMAIN-06' 'Low' 'SPF record uses the ptr mechanism' ([ordered]@{ record = $spfRecords[0] }) `
            'The ptr mechanism is slow, unreliable, and discouraged by RFC 7208; some receivers ignore it.' `
            'Replace ptr with explicit ip4, ip6, a, or include entries.'
    }

    #--- DKIM selector CNAMEs for Microsoft 365
    Write-Progress @progress -Status 'DKIM' -PercentComplete 20
    $usesMicrosoft365 = $TenantDomain -or [bool]$microsoftMx -or ($spf -and ($spf.Includes -contains 'spf.protection.outlook.com'))
    $selector1 = Resolve-SecOakDnsRecord -Check 'Domain/Dkim' -Name "selector1._domainkey.$domain" -Type CNAME
    $selector2 = Resolve-SecOakDnsRecord -Check 'Domain/Dkim' -Name "selector2._domainkey.$domain" -Type CNAME
    $summary.dkim = [ordered]@{ microsoft365 = $usesMicrosoft365; selector1 = $selector1.Values; selector2 = $selector2.Values }
    $raw.dkim = [ordered]@{ selector1 = $selector1; selector2 = $selector2 }
    if ($selector1.Status -eq 'error' -or $selector2.Status -eq 'error') {
        & $addGap 'Domain/Dkim' "CNAME selector1/selector2._domainkey.$domain" 'error' 'DKIM selector lookup failed.' $dnsFix
    }
    elseif ($isMailDomain -and $usesMicrosoft365 -and -not ($selector1.Found -and $selector2.Found)) {
        & $addFinding 'DOMAIN-12' 'Medium' 'Microsoft 365 DKIM selector records missing' ([ordered]@{ selector1Cname = [bool]$selector1.Found; selector2Cname = [bool]$selector2.Found }) `
            'Without both selector CNAME records Microsoft 365 cannot sign outgoing mail for this domain with its own key, which weakens DMARC and deliverability.' `
            'Publish the selector1 and selector2 CNAME records shown in the Defender portal (Email authentication settings, DKIM), then enable DKIM signing.'
    }

    #--- MTA-STS and TLS reporting (inbound mail only)
    Write-Progress @progress -Status 'MTA-STS and TLS reporting' -PercentComplete 25
    $mtaStsTxt = Resolve-SecOakDnsRecord -Check 'Domain/MtaSts' -Name "_mta-sts.$domain" -Type TXT
    $mtaStsRecord = @($mtaStsTxt.Values | Where-Object { $_ -match '^(?i)v=STSv1' }) | Select-Object -First 1
    $mtaStsMode = $null
    if ($mtaStsRecord) {
        $policy = Invoke-SecOakPublicHttpsGet -Check 'Domain/MtaSts' -Uri "https://mta-sts.$domain/.well-known/mta-sts.txt" -TimeoutSeconds 20
        $mtaStsMode = if ($policy.Success -and $policy.Content -match '(?im)^\s*mode\s*:\s*(\w+)') { $Matches[1].ToLowerInvariant() } else { 'unreadable' }
        $raw.mtaStsPolicy = [ordered]@{ status = $policy.StatusCode; content = $policy.Content; error = $policy.Error }
    }
    $tlsRpt = Resolve-SecOakDnsRecord -Check 'Domain/TlsReporting' -Name "_smtp._tls.$domain" -Type TXT
    $tlsRptRecord = @($tlsRpt.Values | Where-Object { $_ -match '^(?i)v=TLSRPTv1' }) | Select-Object -First 1
    $summary.mtaSts = [ordered]@{ record = $mtaStsRecord; mode = $mtaStsMode }
    $summary.tlsReporting = $tlsRptRecord
    $raw.mtaSts = $mtaStsTxt
    $raw.tlsReporting = $tlsRpt
    if ($mxHosts) {
        if ($mtaStsTxt.Status -eq 'error') { & $addGap 'Domain/MtaSts' "TXT _mta-sts.$domain" 'error' 'MTA-STS lookup failed.' $dnsFix }
        elseif (-not $mtaStsRecord) {
            & $addFinding 'DOMAIN-14' 'Low' 'MTA-STS not published' ([ordered]@{ queried = "_mta-sts.$domain" }) `
                'Sending servers are not told to require encrypted, authenticated delivery, so inbound mail can be downgraded to plain text by an attacker on the network path.' `
                'Publish an MTA-STS policy (start in testing mode, move to enforce) and the _mta-sts TXT record. Exchange Online supports inbound MTA-STS.'
        }
        elseif ($mtaStsMode -ne 'enforce') {
            & $addFinding 'DOMAIN-15' 'Low' 'MTA-STS policy is not enforcing' ([ordered]@{ mode = $mtaStsMode; policyUrl = "https://mta-sts.$domain/.well-known/mta-sts.txt" }) `
                'In testing or none mode (or when the policy file cannot be read) senders still deliver when encryption fails, so the protection is not in effect.' `
                'Confirm the policy file is reachable over HTTPS with a valid certificate, review TLS reports, then set mode: enforce.'
        }
        if ($tlsRpt.Status -eq 'error' -and $tlsRpt.Error -match 'SERVFAIL') {
            & $addFinding 'DOMAIN-16' 'Low' 'SMTP TLS reporting record does not resolve' ([ordered]@{ queried = "_smtp._tls.$domain"; lookupResult = 'DNS server failure (SERVFAIL)' }) `n                'Sending servers get a DNS server failure for this name, so no TLS reporting policy is in effect and encryption failures go unreported. The failure also suggests a fault in the DNS zone itself.' `n                'Ask the DNS host why _smtp._tls.<domain> returns SERVFAIL (check the delegation and DNSSEC signing), then publish "v=TLSRPTv1; rua=mailto:<reporting address>".'
        }
        elseif ($tlsRpt.Status -eq 'error') { & $addGap 'Domain/TlsReporting' "TXT _smtp._tls.$domain" 'error' "TLS reporting lookup failed: $($tlsRpt.Error)" $dnsFix }
        elseif (-not $tlsRptRecord) {
            & $addFinding 'DOMAIN-16' 'Low' 'SMTP TLS reporting not published' ([ordered]@{ queried = "_smtp._tls.$domain" }) `
                'Nobody is told when sending servers fail to deliver over encrypted connections, so downgrade attacks and certificate problems go unnoticed.' `
                'Publish "v=TLSRPTv1; rua=mailto:<reporting address>" at _smtp._tls.<domain>.'
        }
    }

    #--- BIMI (informational only)
    $bimi = Resolve-SecOakDnsRecord -Check 'Domain/Bimi' -Name "default._bimi.$domain" -Type TXT
    $summary.bimi = @($bimi.Values | Where-Object { $_ -match '^(?i)v=BIMI1' }) | Select-Object -First 1
    $raw.bimi = $bimi

    #--- DNSSEC and CAA
    Write-Progress @progress -Status 'DNSSEC and CAA' -PercentComplete 30
    $ds = Resolve-SecOakDnsRecord -Check 'Domain/Dnssec' -Name $registrable -Type DS
    $summary.dnssec = [ordered]@{ zone = $registrable; delegationSigner = $ds.Values; status = $ds.Status }
    $raw.dnssec = $ds
    if ($ds.Status -eq 'error') { & $addGap 'Domain/Dnssec' "DS $registrable" 'error' "DS lookup failed: $($ds.Error)" $dnsFix }
    elseif (-not $ds.Found) {
        & $addFinding 'DOMAIN-17' 'Low' 'DNSSEC not enabled' ([ordered]@{ zone = $registrable }) `
            'DNS answers for the domain are not signed, so a resolver can be fed forged records (for example a fake MX). This is uncommon in practice; treat it as hardening.' `
            'Consider enabling DNSSEC at the DNS host and publishing the DS record at the registrar, if both support it.'
    }
    $caa = Resolve-SecOakDnsRecord -Check 'Domain/Caa' -Name $domain -Type CAA
    $caaOwner = $domain
    if (-not $caa.Found -and $caa.Status -ne 'error' -and $registrable -ne $domain) {
        $caa = Resolve-SecOakDnsRecord -Check 'Domain/Caa' -Name $registrable -Type CAA
        $caaOwner = $registrable
    }
    $summary.caa = [ordered]@{ owner = $caaOwner; records = $caa.Values; status = $caa.Status }
    $raw.caa = $caa
    if ($caa.Status -eq 'error') { & $addGap 'Domain/Caa' "CAA $domain" 'error' "CAA lookup failed: $($caa.Error)" 'Rerun when cloudflare-dns.com (DNS over HTTPS) is reachable. No permission is involved.' }
    elseif (-not $caa.Found) {
        & $addFinding 'DOMAIN-18' 'Low' 'No CAA record' ([ordered]@{ queried = @($domain, $registrable) | Select-Object -Unique }) `
            'Any public certificate authority may issue certificates for the domain, which widens the options for an attacker who can pass domain validation.' `
            'Publish CAA records naming only the certificate authorities the company uses (for example 0 issue "digicert.com").'
    }

    #--- Registration (RDAP), once per registrable domain
    Write-Progress @progress -Status 'Registration (RDAP)' -PercentComplete 35
    $rdapKey = "Rdap:$registrable"
    if (-not $Context.Cache.ContainsKey($rdapKey)) {
        $rdapUri = "https://rdap.org/domain/$registrable"
        $rdap = Invoke-SecOakPublicHttpsGet -Check 'Domain/Registration' -Uri $rdapUri -TimeoutSeconds 30 -Accept 'application/rdap+json' -FollowRedirect
        $registration = $null
        if ($rdap.Success -and $rdap.Json) {
            $expiration = ConvertTo-SecOakUtcDate (@($rdap.Json.events) | Where-Object { $_.eventAction -eq 'expiration' } | Select-Object -First 1).eventDate
            $registrarEntity = @($rdap.Json.entities) | Where-Object { @($_.roles) -contains 'registrar' } | Select-Object -First 1
            $registrarName = $null
            if ($registrarEntity -and $registrarEntity.vcardArray) {
                foreach ($item in @($registrarEntity.vcardArray[1])) { if (@($item)[0] -eq 'fn') { $registrarName = @($item)[3] } }
            }
            $registration = [ordered]@{
                registrar  = $registrarName
                expiresUtc = if ($expiration) { $expiration.ToString('yyyy-MM-dd') } else { $null }
                daysLeft   = if ($expiration) { [int][math]::Floor(($expiration - [datetime]::UtcNow).TotalDays) } else { $null }
                statuses   = @($rdap.Json.status)
                rdapServer = ([uri]$rdap.FinalUri).Host
            }
        }
        else {
            & $addGap 'Domain/Registration' $rdapUri "$(if ($rdap.StatusCode) { $rdap.StatusCode } else { 'error' })" "RDAP lookup failed: $($rdap.Error)" `
                'Check the registrar portal or WHOIS by hand; some country-code registries do not publish RDAP. No permission is involved.'
        }
        $Context.Cache[$rdapKey] = $registration
        $raw.registration = $registration
        if ($registration) {
            if ($null -ne $registration.daysLeft -and $registration.daysLeft -lt 90) {
                & $addFinding 'DOMAIN-19' $(if ($registration.daysLeft -lt 30) { 'High' } else { 'Medium' }) 'Domain registration expires soon' ([ordered]@{ registrableDomain = $registrable; expiresUtc = $registration.expiresUtc; daysLeft = $registration.daysLeft; registrar = $registration.registrar }) `
                    'If the registration lapses, mail and sign-in for the domain stop and someone else can register it and receive the company''s mail.' `
                    'Renew the domain now, turn on automatic renewal, and make sure the registrar contact address is a monitored shared mailbox.'
            }
            $normalizedStatuses = @($registration.statuses | ForEach-Object { ("$_" -replace '\s', '').ToLowerInvariant() })
            if ($normalizedStatuses.Count -and -not ($normalizedStatuses -contains 'clienttransferprohibited' -or $normalizedStatuses -contains 'servertransferprohibited')) {
                & $addFinding 'DOMAIN-20' 'Medium' 'Registrar transfer lock not set' ([ordered]@{ registrableDomain = $registrable; statuses = $registration.statuses; registrar = $registration.registrar }) `
                    'Without a transfer lock, anyone who gets into the registrar account or tricks the registrar can move the domain away and take over mail and sign-in.' `
                    'Turn on the transfer lock (client transfer prohibited) at the registrar and protect the registrar account with multifactor sign-in.'
            }
        }
    }
    $summary.registration = $Context.Cache[$rdapKey]

    #--- Microsoft Entra sign-in realm
    Write-Progress @progress -Status 'Sign-in realm' -PercentComplete 40
    $realmUri = 'https://login.microsoftonline.com/getuserrealm.srf?login={0}&json=1' -f [uri]::EscapeDataString("nobody@$domain")
    $realm = Invoke-SecOakPublicHttpsGet -Check 'Domain/SignInRealm' -Uri $realmUri -TimeoutSeconds 20
    if ($realm.Success -and $realm.Json) {
        $authHost = if ($realm.Json.AuthURL) { try { ([uri]"$($realm.Json.AuthURL)").Host } catch { $null } } else { $null }
        $summary.signInRealm = [ordered]@{ nameSpaceType = "$($realm.Json.NameSpaceType)"; federationBrandName = $realm.Json.FederationBrandName; authUrlHost = $authHost; cloudInstance = $realm.Json.CloudInstanceName }
        if ("$($realm.Json.NameSpaceType)" -eq 'Federated') {
            & $addFinding 'DOMAIN-22' 'Low' 'Sign-in for this domain is federated to an external identity provider' ([ordered]@{ federationBrand = $realm.Json.FederationBrandName; authUrlHost = $authHost }) `
                'Informational. Passwords for this domain are checked by the federation server, not Microsoft Entra ID. That server is an internet-facing sign-in surface and its security (patching, multifactor, token-signing certificates) protects the whole tenant.' `
                'Confirm the federation server is still needed, patched, and requires multifactor. Consider moving to managed authentication (password hash sync or pass-through) if it is not.'
        }
    }
    else {
        $summary.signInRealm = $null
        & $addGap 'Domain/SignInRealm' 'https://login.microsoftonline.com/getuserrealm.srf' "$(if ($realm.StatusCode) { $realm.StatusCode } else { 'error' })" "Realm lookup failed: $($realm.Error)" 'Rerun later. No permission is involved.'
    }
    $raw.signInRealm = $summary.signInRealm

    #--- Certificate transparency and dangling CNAMEs
    Write-Progress @progress -Status 'Certificate transparency (crt.sh)' -PercentComplete 45
    $ctUri = 'https://crt.sh/?q=%25.{0}&output=json' -f $domain
    $ct = Invoke-SecOakPublicHttpsGet -Check 'Domain/CertificateTransparency' -Uri $ctUri -TimeoutSeconds 60
    $hostnames = @()
    if ($ct.Success -and $null -ne $ct.Json) {
        $escaped = [regex]::Escape($domain)
        $hostnames = @(@($ct.Json) | ForEach-Object { "$($_.name_value)" -split '\s+' } |
                ForEach-Object { $_.Trim().TrimEnd('.').ToLowerInvariant() -replace '^\*\.', '' } |
                Where-Object { $_ -match '^[a-z0-9\-_\.]+$' -and ($_ -eq $domain -or $_ -match "\.$escaped$") } |
                Sort-Object -Unique)
        $summary.certificateTransparency = [ordered]@{ certificates = @($ct.Json).Count; uniqueHostnames = $hostnames.Count; examples = (Select-SecOakExample $hostnames -Count 10) }
    }
    else {
        $summary.certificateTransparency = $null
        & $addGap 'Domain/CertificateTransparency' $ctUri "$(if ($ct.StatusCode) { $ct.StatusCode } else { 'error' })" "crt.sh lookup failed: $($ct.Error)" `
            'crt.sh is often slow or overloaded; rerun later. Dangling CNAME checks depend on this list. No permission is involved.'
    }
    $raw.certificateTransparency = [ordered]@{ certificates = if ($ct.Json) { @($ct.Json).Count } else { $null }; hostnames = $hostnames }

    $toResolve = @($hostnames | Where-Object { $_ -ne $domain } | Select-Object -First 200)
    $cloudCnames = [System.Collections.Generic.List[object]]::new()
    $dangling = [System.Collections.Generic.List[object]]::new()
    $index = 0
    foreach ($hostname in $toResolve) {
        $index++
        Write-Progress @progress -Status "Dangling CNAME check $index of $($toResolve.Count)" -PercentComplete (45 + [int](30 * $index / [math]::Max(1, $toResolve.Count)))
        try { $cname = Resolve-SecOakDnsRecord -Check 'Domain/DanglingCname' -Name $hostname -Type CNAME -ErrorAction Stop }
        catch { Write-Warning "Skipped ${hostname}: $($_.Exception.Message)"; continue }
        if (-not $cname.Found) { continue }
        $target = "$($cname.Values[0])".TrimEnd('.').ToLowerInvariant()
        $prone = @($script:TakeoverSuffixPatterns | Where-Object { $target -match $_ })
        if (-not $prone) { continue }
        try { $targetLookup = Resolve-SecOakDnsRecord -Check 'Domain/DanglingCname' -Name $target -Type A -ErrorAction Stop }
        catch { Write-Warning "Skipped ${target}: $($_.Exception.Message)"; continue }
        $cloudCnames.Add([pscustomobject][ordered]@{ hostname = $hostname; target = $target; targetStatus = $targetLookup.Status })
        if ($targetLookup.Status -eq 'nxdomain') { $dangling.Add([pscustomobject][ordered]@{ hostname = $hostname; target = $target }) }
    }
    $summary.cloudServiceCnames = [ordered]@{ hostnamesResolved = $toResolve.Count; cnamesToCloudServices = $cloudCnames.Count; examples = (Select-SecOakExample @($cloudCnames | ForEach-Object { '{0} -> {1}' -f $_.hostname, $_.target }) -Count 10) }
    $raw.cloudServiceCnames = $cloudCnames.ToArray()
    if ($hostnames.Count -gt 200) {
        & $addGap 'Domain/DanglingCname' 'CNAME (certificate transparency hostnames)' 'partial' "Only the first 200 of $($hostnames.Count) hostnames were resolved." 'Review the full list in the raw export if a complete takeover check is needed.'
    }
    if ($dangling.Count) {
        & $addFinding 'DOMAIN-21' 'High' 'Subdomains point to cloud resources that no longer exist (subdomain takeover)' ([ordered]@{ hostnames = $dangling.Count; examples = (Select-SecOakExample @($dangling | ForEach-Object { '{0} -> {1}' -f $_.hostname, $_.target }) -Count 10) }) `
            'Anyone can create a cloud resource with the missing name and then serve content, collect credentials, or receive cookies on the company''s own subdomain.' `
            'Delete the listed CNAME records, or recreate the target resource, today. Remove DNS records whenever the cloud resource behind them is deleted.'
    }

    #--- Lookalike domains, once per registrable domain
    $lookalikeKey = "Lookalikes:$registrable"
    if (-not $Context.Cache.ContainsKey($lookalikeKey)) {
        $known = @($KnownDomain | ForEach-Object { $_.ToLowerInvariant() })
        $candidates = @(Get-SecOakLookalikeCandidate -RegistrableDomain $registrable -Maximum 150 | Where-Object { $_ -notin $known })
        $registered = [System.Collections.Generic.List[object]]::new()
        $lookupErrors = 0
        $index = 0
        foreach ($candidate in $candidates) {
            $index++
            Write-Progress @progress -Status "Lookalike domains $index of $($candidates.Count)" -PercentComplete (75 + [int](25 * $index / [math]::Max(1, $candidates.Count)))
            Start-Sleep -Milliseconds 150
            $ns = Resolve-SecOakDnsRecord -Check 'Domain/Lookalikes' -Name $candidate -Type NS
            if ($ns.Status -eq 'nxdomain') { continue }
            if ($ns.Status -eq 'error') { $lookupErrors++; continue }
            $a = Resolve-SecOakDnsRecord -Check 'Domain/Lookalikes' -Name $candidate -Type A
            $candidateMx = Resolve-SecOakDnsRecord -Check 'Domain/Lookalikes' -Name $candidate -Type MX
            $mailServers = @($candidateMx.Values | Where-Object { $_ -ne '.' })
            if ($ns.Found -or $a.Found -or $mailServers) {
                $registered.Add([pscustomobject][ordered]@{ domain = $candidate; nameServers = @($ns.Values | Select-Object -First 2); hasAddress = [bool]$a.Found; mailServers = @($mailServers | Select-Object -First 3) })
            }
        }
        $withMx = @($registered | Where-Object { $_.mailServers.Count -gt 0 })
        $withoutMx = @($registered | Where-Object { $_.mailServers.Count -eq 0 })
        $Context.Cache[$lookalikeKey] = [ordered]@{ candidatesChecked = $candidates.Count; registered = $registered.Count; withMailServers = $withMx.Count; lookupErrors = $lookupErrors; examples = (Select-SecOakExample $registered.domain -Count 10) }
        $raw.lookalikes = [ordered]@{ candidates = $candidates; registered = $registered.ToArray() }
        if ($lookupErrors -gt [math]::Max(5, $candidates.Count / 2)) {
            & $addGap 'Domain/Lookalikes' 'NS (lookalike candidates)' 'partial' "$lookupErrors of $($candidates.Count) lookalike lookups failed." $dnsFix
        }
        if ($withMx.Count) {
            & $addFinding 'DOMAIN-23' 'Medium' 'Registered lookalike domains that can send and receive mail' ([ordered]@{ registrableDomain = $registrable; domains = $withMx.Count; examples = (Select-SecOakExample @($withMx | ForEach-Object { '{0} (MX {1})' -f $_.domain, ($_.mailServers -join ', ') }) -Count 10) }) `
                'Someone can send and receive mail pretending to be the company from these near-identical domains, which is the usual setup for invoice fraud and supplier impersonation.' `
                'Confirm which of these the company owns. For the rest, tag external mail, add the domains to impersonation protection in Defender for Office 365, block them in the Tenant Allow/Block List, and consider buying or taking down the most convincing ones.'
        }
        if ($withoutMx.Count) {
            & $addFinding 'DOMAIN-24' 'Low' 'Registered lookalike domains' ([ordered]@{ registrableDomain = $registrable; domains = $withoutMx.Count; examples = (Select-SecOakExample $withoutMx.domain -Count 10) }) `
                'These near-identical domains are registered but have no mail servers today. They can host phishing pages or gain mail servers at any time.' `
                'Confirm which the company owns and watch the rest for mail servers or web content; block them in the Tenant Allow/Block List if they are not the company''s.'
        }
    }
    $summary.lookalikes = $Context.Cache[$lookalikeKey]

    Write-Progress @progress -Completed
    $raw.findingIds = @($findings.id)
    Save-SecOakRawData -Context $Context -Name ('domain-' + ($domain -replace '[^a-z0-9\-]', '-')) -Data $raw
    [pscustomobject]@{ Domain = $domain; Summary = $summary; Findings = $findings.ToArray() }
}

function Invoke-SecOakDomainCheck {
    <#
    .SYNOPSIS
        Domain area: public (OSINT) posture of the client's domains, with no tenant permissions.
    .DESCRIPTION
        For each domain: mail routing, SPF (with a recursive DNS lookup count), DMARC,
        Microsoft 365 DKIM selector CNAMEs, lock-down of domains that do not send mail,
        MTA-STS, TLS reporting, BIMI (informational), DNSSEC, CAA, registration expiry and
        transfer lock (RDAP), certificate transparency hostnames (crt.sh), dangling CNAMEs
        to cloud services among those hostnames, the Microsoft Entra sign-in realm, and
        registered lookalike domains.

        Read-only and passive: DNS queries and HTTPS GET requests only. No port scans, no
        subdomain guessing, no sign-in attempts. Every lookup and request is written to the
        endpoint log. A failed source becomes a gap; the area keeps going.
    .PARAMETER Context
        The run context. A tenantless context (New-SecOakRunContext -Tenantless) works when
        -Domain is given.
    .PARAMETER Domain
        Domains to check. When omitted, the tenant's verified domains are read from Microsoft
        Graph (GET /v1.0/domains), excluding *.onmicrosoft.com.
    .OUTPUTS
        Area result object with Area, Summary, and Findings. Findings and gaps are also added
        to the context.
    .EXAMPLE
        Invoke-SecOakDomainCheck -Context $context
    .EXAMPLE
        Invoke-SecOakDomainCheck -Context $context -Domain contoso.com, contoso.net
    .NOTES
        Permissions: none for the checks themselves (public sources). Only the domain list
        read from Graph, when -Domain is omitted, needs Directory.Read.All (application).
        Third-party services that receive each domain name: crt.sh (certificate
        transparency), rdap.org and the registry RDAP server it redirects to (registration),
        login.microsoftonline.com (getuserrealm.srf sign-in realm), cloudflare-dns.com (DNS
        over HTTPS, CAA lookups), mta-sts.<domain> (the client's own policy host, only when an
        MTA-STS record exists), and the DNS resolver configured on this machine.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter()][ValidateScript({ $_ -match $script:HostnamePattern })][string[]]$Domain
    )
    $area = 'Domain'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $tenantDomains = $false

    if (-not $Domain) {
        if ($Context.Tenantless) { throw 'No domains were given and this run has no tenant to read them from. Pass -Domain.' }
        Write-Verbose 'Domain: reading verified domains from Microsoft Graph'
        $result = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Domain/TenantDomains' -Path '/domains' -RawName 'domain-tenant-domains'
        if (-not $result.Success) {
            $Context.AreaSummaries[$area] = $summary
            return [pscustomobject]@{ Area = $area; Summary = $summary; Findings = @() }
        }
        $requested = @($result.Items | Where-Object { $_.isVerified -and "$($_.id)" -notmatch '\.onmicrosoft\.com$' } | ForEach-Object { "$($_.id)" })
        $tenantDomains = $true
    }
    else { $requested = @($Domain) }
    # Filtered into a new variable: the parameter keeps its validation attribute.
    $domains = @($requested |ForEach-Object { $_.ToLowerInvariant().TrimEnd('.') } | Where-Object { $_ -match $script:HostnamePattern } | Sort-Object -Unique)
    $summary.domainsChecked = $domains.Count
    $summary.source = if ($tenantDomains) { 'tenant verified domains (Microsoft Graph)' } else { 'supplied list' }
    $summary.domains = [ordered]@{}

    $step = 0
    foreach ($name in $domains) {
        $step++
        Write-Progress -Id 3 -Activity 'Domain area' -Status "$name ($step of $($domains.Count))" -PercentComplete ([int](100 * ($step - 1) / [math]::Max(1, $domains.Count)))
        Write-Verbose "Domain: checking $name"
        try {
            $posture = Get-SecOakDomainPosture -Context $Context -Domain $name -TenantDomain:$tenantDomains -KnownDomain $domains -ErrorAction Stop
            foreach ($finding in $posture.Findings) { $findings.Add($finding) }
            $summary.domains[$name] = $posture.Summary
        }
        catch {
            Write-Warning "Domain checks for $name failed: $($_.Exception.Message)"
            Add-SecOakGap -Context $Context -Area $area -Check 'Domain/*' -EndpointOrCmdlet $name -Result 'error' `
                -Reason ($_.Exception.Message -replace '\s+', ' ') -FillWith 'See run-log.txt; rerun the Domain area for this domain.'
        }
    }
    Write-Progress -Id 3 -Activity 'Domain area' -Completed

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
