#Requires -Version 7.2

<#
.SYNOPSIS
    Runs the read-only Security Oak Microsoft 365 health check against one client tenant.

.DESCRIPTION
    Signs in app-only with the Security Oak reader app, shows the tenant display name and
    ID, and collects nothing until the tenant is confirmed. Confirmation is either an
    interactive "yes" or the -ConfirmedTenantId parameter, which must match the tenant the
    token was issued for.

    Output goes to $HOME\SecurityOak\client-data\<ClientName>\<yyyyMMdd>\ by default:
        raw\*.json          raw data per check
        endpoint-log.csv    one row per Graph call, Exchange cmdlet, DNS lookup, and public HTTPS request
        token-scopes.txt    permission names carried by each token (never the token)
        findings.json       findings with severity, evidence, risk, fix, baseline control
        gaps.md             what could not be checked and what would fill it
        run-summary.json    counts per area and severity plus area summaries
        run-log.txt         transcript

    Read-only: Graph requests are GET only and Exchange cmdlets are Get-* only. The one
    non-GET request is the OAuth token request to login.microsoftonline.com. The Domain
    area also sends each domain name to crt.sh, rdap.org (and the registry RDAP server),
    login.microsoftonline.com (getuserrealm.srf), and cloudflare-dns.com (CAA lookups).

.PARAMETER ConfigPath
    JSON file with ClientName, TenantId, AppId, CertificateThumbprint, and InitialDomain.
    Keep real client configs outside the repository, for example
    $HOME\SecurityOak\clients\<client>.json. Explicit parameters override the file.

.PARAMETER ClientName
    Short client name used for the output folder.

.PARAMETER TenantId
    Client tenant ID.

.PARAMETER AppId
    Application (client) ID of the Security Oak reader app in the client tenant.

.PARAMETER CertificateThumbprint
    Thumbprint of the reader app certificate in Cert:\CurrentUser\My. When empty, the
    client secret is read from the SECOAK_APP_SECRET environment variable (Exchange
    app-only access then falls back to interactive sign-in if allowed).

.PARAMETER InitialDomain
    The tenant's initial onmicrosoft.com domain. Discovered from Graph when omitted.

.PARAMETER OutputPath
    Output folder. Defaults to $HOME\SecurityOak\client-data\<ClientName>\<yyyyMMdd>.

.PARAMETER ShowTenant
    Only sign in and show the tenant display name and ID, then stop. Nothing is collected.

.PARAMETER ConfirmedTenantId
    Non-interactive confirmation. Must equal the tenant ID in the app-only token.

.PARAMETER Area
    Areas to run. Defaults to all eighteen. Access (the permission self-audit) always runs last so it
    sees every endpoint the other areas used. The Domain area uses public sources only (DNS, crt.sh,
    RDAP, the Microsoft sign-in realm lookup); see Invoke-SecOakDomainCheck.

.PARAMETER Domain
    Domains for the Domain area. When omitted, the tenant's verified domains are used
    (excluding onmicrosoft.com). For a check with no tenant at all, use
    tools\Invoke-SecurityOakDomainScan.ps1.

.PARAMETER PermissionAudit
    Run only the Security Oak access self-audit and the endpoint log, to review what the
    reader app holds against what the health check uses.

.PARAMETER AzureCliFallback
    Retry Graph calls that fail with 401 or 403 using the Azure CLI delegated token.
    Requires a prior: az login --tenant <tenant> --allow-no-subscriptions

.PARAMETER ExchangeInteractiveFallback
    Replay Exchange steps that fail app-only through an interactive sign-in.

.PARAMETER ExchangeUserPrincipalName
    Account to pre-fill for the interactive Exchange sign-in.

.EXAMPLE
    ./Invoke-SecurityOakHealthCheck.ps1 -ConfigPath $HOME\SecurityOak\clients\contoso.json -ShowTenant

.EXAMPLE
    ./Invoke-SecurityOakHealthCheck.ps1 -ConfigPath $HOME\SecurityOak\clients\contoso.json -ConfirmedTenantId <tenant-id>

.NOTES
    Required modules: ExchangeOnlineManagement 3.x (Email area). Azure CLI is optional.
    Reader app: Microsoft Graph read permissions listed in docs/permissions.md,
    Office 365 Exchange Online Exchange.ManageAsApp, and the Global Reader role.
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter()][ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })][string]$ConfigPath,
    [Parameter()][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9\-_]{0,62}$')][string]$ClientName,
    [Parameter()][ValidateScript({ [guid]::TryParse($_, [ref][guid]::Empty) })][string]$TenantId,
    [Parameter()][ValidateScript({ [guid]::TryParse($_, [ref][guid]::Empty) })][string]$AppId,
    [Parameter()][ValidatePattern('^[0-9A-Fa-f]{40}$')][string]$CertificateThumbprint,
    [Parameter()][ValidatePattern('^[A-Za-z0-9\-]+\.onmicrosoft\.com$')][string]$InitialDomain,
    [Parameter()][string]$OutputPath,
    [Parameter(ParameterSetName = 'Show')][switch]$ShowTenant,
    [Parameter(ParameterSetName = 'Run')][ValidateScript({ [guid]::TryParse($_, [ref][guid]::Empty) })][string]$ConfirmedTenantId,
    [Parameter(ParameterSetName = 'Run')][ValidateSet(
        'Identity', 'Email', 'Domain', 'Devices', 'Sharing', 'Licensing', 'Posture', 'Entra', 'Intune', 'Defender', 'Exchange', 'SharePoint', 'Teams', 'Purview', 'ServiceHealth', 'Backup', 'Azure', 'Access')][string[]]$Area =
        @('Identity', 'Email', 'Domain', 'Devices', 'Sharing', 'Licensing', 'Posture', 'Entra', 'Intune', 'Defender', 'Exchange', 'SharePoint', 'Teams', 'Purview', 'ServiceHealth', 'Backup', 'Azure', 'Access'),
    [Parameter(ParameterSetName = 'Run')]
    [ValidateScript({ $_ -match '^(?=.{4,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63}|xn--[A-Za-z0-9\-]{1,59})$' })]
    [string[]]$Domain,
    [Parameter(ParameterSetName = 'Run')][switch]$PermissionAudit,
    [Parameter()][switch]$AzureCliFallback,
    [Parameter(ParameterSetName = 'Run')][switch]$ExchangeInteractiveFallback,
    [Parameter(ParameterSetName = 'Run')][string]$ExchangeUserPrincipalName
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'src\SecurityOak.HealthCheck.psd1') -Force -Verbose:$false

#--- Settings: config file first, explicit parameters override
$settings = @{ ClientName = ''; TenantId = ''; AppId = ''; CertificateThumbprint = ''; InitialDomain = '' }
if ($ConfigPath) {
    try { $file = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Could not read config '$ConfigPath': $($_.Exception.Message)" }
    foreach ($key in @($settings.Keys)) { if ($file.$key) { $settings[$key] = "$($file.$key)" } }
}
foreach ($key in @($settings.Keys)) { if ($PSBoundParameters.ContainsKey($key)) { $settings[$key] = $PSBoundParameters[$key] } }
foreach ($required in 'ClientName', 'TenantId', 'AppId') {
    if (-not $settings[$required]) { throw "$required is required (parameter or config file)." }
}
if ($settings.TenantId -match '^0{8}-') { throw 'The config still holds placeholder values.' }
if (-not $OutputPath) {
    $OutputPath = Join-Path $HOME ('SecurityOak\client-data\{0}\{1}' -f $settings.ClientName.ToLowerInvariant(), (Get-Date -Format 'yyyyMMdd'))
}
$repositoryRoot = (Resolve-Path $PSScriptRoot).Path
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
if ($resolvedOutput.StartsWith($repositoryRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'OutputPath is inside the repository. Client data must stay outside it.'
}

$contextParameters = @{
    ClientName                  = $settings.ClientName
    TenantId                    = $settings.TenantId
    AppId                       = $settings.AppId
    CertificateThumbprint       = $settings.CertificateThumbprint
    InitialDomain               = $settings.InitialDomain
    OutputPath                  = $resolvedOutput
    AzureCliFallback            = $AzureCliFallback
    ExchangeInteractiveFallback = $ExchangeInteractiveFallback
    ExchangeUserPrincipalName   = [string]$ExchangeUserPrincipalName
}
$context = New-SecOakRunContext @contextParameters
$transcriptStarted = $false

try {
    #--- Sign in and show the tenant before anything is collected
    Write-Verbose 'Requesting app-only Microsoft Graph token'
    try { $null = Connect-SecOakGraph -Context $context }
    catch {
        if (-not $AzureCliFallback) { throw }
        Write-Warning "App-only sign-in failed, continuing with Azure CLI delegated access only: $($_.Exception.Message)"
    }
    $tenant = Get-SecOakTenantIdentity -Context $context

    if ($ShowTenant) {
        $tenant
        return
    }

    if ($ConfirmedTenantId) {
        if ($ConfirmedTenantId.ToLowerInvariant() -ne "$($tenant.TenantId)".ToLowerInvariant()) {
            throw "ConfirmedTenantId does not match the signed-in tenant ($($tenant.TenantDisplayName)). Nothing was collected."
        }
    }
    else {
        $tenant | Format-List | Out-String | Write-Information -InformationAction Continue
        $answer = Read-Host 'Type yes to collect from this tenant'
        if ($answer -ne 'yes') { Write-Warning 'Not confirmed. Nothing was collected.'; return }
    }

    #--- Collect
    Initialize-SecOakOutputFolder -Context $context
    Start-Transcript -Path (Join-Path $resolvedOutput 'run-log.txt') -Append | Out-Null
    $transcriptStarted = $true
    Write-Verbose "Output: $resolvedOutput"

    $plan = if ($PermissionAudit) { @('Access') } else { $Area }
    $checks = [ordered]@{
        Identity      = { Invoke-SecOakIdentityCheck -Context $context }
        Email         = { Invoke-SecOakEmailCheck -Context $context }
        Domain        = { if ($Domain) { Invoke-SecOakDomainCheck -Context $context -Domain $Domain } else { Invoke-SecOakDomainCheck -Context $context } }
        Devices       = { Invoke-SecOakDeviceCheck -Context $context }
        Sharing       = { Invoke-SecOakSharingCheck -Context $context }
        Licensing     = { Invoke-SecOakLicensingCheck -Context $context }
        Posture       = { Invoke-SecOakPostureCheck -Context $context }
        Entra         = { Invoke-SecOakEntraCheck -Context $context }
        Intune        = { Invoke-SecOakIntuneCheck -Context $context }
        Defender      = { Invoke-SecOakDefenderCheck -Context $context }
        Exchange      = { Invoke-SecOakExchangeCheck -Context $context }
        SharePoint    = { Invoke-SecOakSharePointCheck -Context $context }
        Teams         = { Invoke-SecOakTeamsCheck -Context $context }
        Purview       = { Invoke-SecOakPurviewCheck -Context $context }
        ServiceHealth = { Invoke-SecOakServiceHealthCheck -Context $context }
        Backup        = { Invoke-SecOakBackupCheck -Context $context }
        Azure         = { Invoke-SecOakAzureCheck -Context $context }
        Access        = { Invoke-SecOakAccessAudit -Context $context }
    }
    $step = 0
    foreach ($name in $checks.Keys) {
        if ($name -notin $plan) { continue }
        $step++
        Write-Progress -Id 1 -Activity 'Security Oak health check' -Status "$name ($step of $($plan.Count))" -PercentComplete ([int](100 * ($step - 1) / $plan.Count))
        try { $null = & $checks[$name] }
        catch {
            Write-Warning "$name area failed: $($_.Exception.Message)"
            $context.Gaps.Add([pscustomobject][ordered]@{
                    Area = $name; Check = "$name/*"; EndpointOrCmdlet = 'area'; Result = 'error'
                    Reason = ($_.Exception.Message -replace '\s+', ' '); FillWith = 'See run-log.txt; rerun this area after fixing the cause.'
                })
        }
    }
    Write-Progress -Id 1 -Activity 'Security Oak health check' -Completed

    Export-SecOakRunReport -Context $context
}
finally {
    Disconnect-SecOakSession -Context $context
    if ($transcriptStarted) { Stop-Transcript | Out-Null }
}
