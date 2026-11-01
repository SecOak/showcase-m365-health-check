#Requires -Version 7.2

<#
.SYNOPSIS
    Runs the Security Oak Domain checks against one or more domains, with no tenant access.

.DESCRIPTION
    Checks the public posture of each domain: mail routing (MX), SPF with a recursive DNS
    lookup count, DMARC, Microsoft 365 DKIM selector CNAMEs, lock-down of domains that do
    not send mail, MTA-STS, TLS reporting, BIMI (informational), DNSSEC, CAA, registration
    expiry and transfer lock (RDAP), certificate transparency hostnames (crt.sh), dangling
    CNAMEs among those hostnames, the Microsoft Entra sign-in realm, and registered
    lookalike domains.

    There is no tenant, no sign-in, and no confirmation prompt, because nothing here is read
    from a tenant: every source is public DNS or a public HTTPS lookup that anyone on the
    internet can make. That makes it usable before a client has granted any access, for
    example during a first conversation or a proposal.

    Read-only and passive: DNS queries and HTTPS GET requests only. No port scans, no
    subdomain guessing, no sign-in attempts. Every lookup and request is logged.

    Output goes to $HOME\SecurityOak\client-data\<ClientName>\<yyyyMMdd>-domain\ by default:
        raw\domain-*.json   raw data per domain
        endpoint-log.csv    one row per DNS lookup and HTTPS request
        findings.json       findings (DOMAIN-01 onward) with severity, evidence, risk, and fix
        gaps.md             sources that failed and what would fill each one
        run-summary.json    counts per severity plus the Domain area summary
        run-log.txt         transcript

.PARAMETER Domain
    One or more domain names, for example contoso.com.

.PARAMETER ClientName
    Short client name used for the output folder.

.PARAMETER OutputPath
    Output folder. Defaults to $HOME\SecurityOak\client-data\<ClientName>\<yyyyMMdd>-domain.
    Must be outside the repository.

.EXAMPLE
    ./tools/Invoke-SecurityOakDomainScan.ps1 -Domain contoso.com -ClientName contoso

.EXAMPLE
    ./tools/Invoke-SecurityOakDomainScan.ps1 -Domain contoso.com, contoso.net -ClientName contoso -Verbose

.NOTES
    Permissions: none. No tenant, account, or token is used.
    Sources are public. Third-party services that receive each domain name: crt.sh
    (certificate transparency), rdap.org and the registry RDAP server it redirects to
    (registration), login.microsoftonline.com (getuserrealm.srf sign-in realm lookup),
    cloudflare-dns.com (DNS over HTTPS, CAA lookups), mta-sts.<domain> (the domain's own
    policy host, only when an MTA-STS record exists), and the DNS resolver configured on
    this machine. Lookalike checks send about 150 permutations of the name to that resolver.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({ $_ -match '^(?=.{4,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63}|xn--[A-Za-z0-9\-]{1,59})$' })]
    [string[]]$Domain,
    [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9\-_]{0,62}$')][string]$ClientName,
    [Parameter()][ValidateNotNullOrEmpty()][string]$OutputPath
)

$ErrorActionPreference = 'Stop'
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $repositoryRoot 'src\SecurityOak.HealthCheck.psd1') -Force -Verbose:$false

if (-not $OutputPath) {
    $OutputPath = Join-Path $HOME ('SecurityOak\client-data\{0}\{1}-domain' -f $ClientName.ToLowerInvariant(), (Get-Date -Format 'yyyyMMdd'))
}
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
if ($resolvedOutput.StartsWith($repositoryRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputPath is inside the repository. Client data must stay outside it.'
}

$context = New-SecOakRunContext -ClientName $ClientName -Tenantless -OutputPath $resolvedOutput
$transcriptStarted = $false
try {
    Initialize-SecOakOutputFolder -Context $context
    Start-Transcript -Path (Join-Path $resolvedOutput 'run-log.txt') -Append | Out-Null
    $transcriptStarted = $true
    Write-Verbose "Output: $resolvedOutput"
    try { $null = Invoke-SecOakDomainCheck -Context $context -Domain $Domain }
    catch {
        Write-Warning "Domain area failed: $($_.Exception.Message)"
        $context.Gaps.Add([pscustomobject][ordered]@{
                Area = 'Domain'; Check = 'Domain/*'; EndpointOrCmdlet = 'area'; Result = 'error'
                Reason = ($_.Exception.Message -replace '\s+', ' '); FillWith = 'See run-log.txt; rerun after fixing the cause.'
            })
    }
    Export-SecOakRunReport -Context $context
}
finally {
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
