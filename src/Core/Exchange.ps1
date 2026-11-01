function Connect-SecOakExchange {
    <#
    .SYNOPSIS
        Connects to Exchange Online app-only, falling back to interactive when allowed.
    .DESCRIPTION
        App-only needs a certificate. With a secret, or when app-only fails, the interactive
        sign-in is used only if the run allows it. The connected tenant is verified against
        the configured tenant ID and the session is closed if it does not match.
    .PARAMETER Context
        The run context.
    .PARAMETER Mode
        App or Interactive.
    .OUTPUTS
        The connection mode string: exo-app, exo-interactive, or none.
    .NOTES
        Requires ExchangeOnlineManagement 3.x. App-only needs Exchange.ManageAsApp and an
        Entra role (Global Reader) on the reader app's service principal.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidateSet('App', 'Interactive')][string]$Mode
    )
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        throw 'The ExchangeOnlineManagement module is not installed. Install-Module ExchangeOnlineManagement -Scope CurrentUser'
    }
    Import-Module ExchangeOnlineManagement -ErrorAction Stop -Verbose:$false
    if (-not $Context.InitialDomain) { throw 'The initial domain is unknown; set InitialDomain in the config.' }

    $connectParameters = @{ ShowBanner = $false; ErrorAction = 'Stop' }
    if ($Mode -eq 'App') {
        if ($Context.CredentialType -ne 'Certificate') { throw 'Exchange app-only access requires a certificate; the app is configured with a secret.' }
        $connectParameters.AppId = $Context.AppId
        $connectParameters.CertificateThumbprint = $Context.CertificateThumbprint
        $connectParameters.Organization = $Context.InitialDomain
        $modeName = 'exo-app'
    }
    else {
        if ($Context.ExchangeUserPrincipalName) { $connectParameters.UserPrincipalName = $Context.ExchangeUserPrincipalName }
        $modeName = 'exo-interactive'
    }

    try {
        Connect-ExchangeOnline @connectParameters | Out-Null
        # A Security and Compliance connection (IsEopSession) may coexist in this session; pick the Exchange Online one.
        # https://learn.microsoft.com/powershell/module/exchangepowershell/get-connectioninformation?view=exchange-ps
        $connection = Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' -and -not $_.IsEopSession } | Select-Object -Last 1
        if (-not $connection -or "$($connection.TenantID)".ToLowerInvariant() -ne $Context.TenantId) {
            if ($connection) { Disconnect-ExchangeOnline -ConnectionId $connection.ConnectionId -Confirm:$false -ErrorAction SilentlyContinue }
            throw 'Exchange Online connected to a different tenant than the one configured. Disconnected.'
        }
        $Context.ExchangeConnectionId = "$($connection.ConnectionId)"
        $Context.ExchangeMode = $modeName
        Add-SecOakEndpointLogEntry -Check 'Email/Connect' -Tool Exchange -Method Connect -EndpointOrCmdlet 'Connect-ExchangeOnline' -HttpStatusOrResult 'connected' `
            -AuthUsed $modeName -AppOnlyResult $(if ($Mode -eq 'App') { 'success' } else { 'not attempted' })
        return $modeName
    }
    catch {
        $message = $_.Exception.Message
        Add-SecOakEndpointLogEntry -Check 'Email/Connect' -Tool Exchange -Method Connect -EndpointOrCmdlet 'Connect-ExchangeOnline' -HttpStatusOrResult 'failed' `
            -AuthUsed $modeName -AppOnlyResult $(if ($Mode -eq 'App') { 'forbidden' } else { 'not attempted' }) -Notes ($message -replace '\s+', ' ')
        throw "Exchange Online $Mode connection failed: $message"
    }
}

function Disconnect-SecOakExchange {
    <#
    .SYNOPSIS
        Disconnects Exchange Online if this module connected it.
    .PARAMETER Context
        The run context.
    .NOTES
        Requires ExchangeOnlineManagement.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    if ($Context.ExchangeMode -ne 'none') {
        # Disconnect by ConnectionId so a coexisting Security and Compliance connection stays open.
        # https://learn.microsoft.com/powershell/module/exchangepowershell/disconnect-exchangeonline?view=exchange-ps
        try {
            if ($Context.ExchangeConnectionId) { Disconnect-ExchangeOnline -ConnectionId $Context.ExchangeConnectionId -Confirm:$false -ErrorAction Stop | Out-Null }
            else { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop | Out-Null }
        }
        catch { Write-Warning "Exchange Online disconnect reported: $($_.Exception.Message)" }
        $Context.ExchangeMode = 'none'
        $Context.ExchangeConnectionId = ''
    }
}

function Invoke-SecOakExchangeGet {
    <#
    .SYNOPSIS
        Runs one read-only Exchange Online Get-* cmdlet and logs it.
    .DESCRIPTION
        Rejects any cmdlet not named Get-*. A cmdlet missing from the session (role-based
        access control hides cmdlets the caller cannot run) or an access-denied error is
        classified as forbidden.
    .PARAMETER Context
        The run context.
    .PARAMETER Check
        Check name for the endpoint log.
    .PARAMETER Cmdlet
        The Get-* cmdlet name.
    .PARAMETER Parameters
        Splatted parameters.
    .PARAMETER AppOnlyResult
        Override for the AppOnlyResult column (used when replaying a step interactively).
    .PARAMETER LogLabel
        Optional extra text for the Notes column (for example the mailbox being read).
    .OUTPUTS
        Object with Success, Forbidden, Data, ErrorMessage.
    .EXAMPLE
        Invoke-SecOakExchangeGet -Context $context -Check 'Email/Domains' -Cmdlet Get-AcceptedDomain
    .NOTES
        Requires an Exchange Online session opened by Connect-SecOakExchange.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidatePattern('^Get-[A-Za-z0-9]+$')][string]$Cmdlet,
        [Parameter()][hashtable]$Parameters = @{},
        [Parameter()][ValidateSet('', 'success', 'forbidden', 'error', 'not attempted')][string]$AppOnlyResult = '',
        [Parameter()][string]$LogLabel = ''
    )
    $success = $false
    $forbidden = $false
    $data = $null
    $message = $null
    try {
        if (-not (Get-Command -Name $Cmdlet -ErrorAction SilentlyContinue)) {
            throw [System.Management.Automation.CommandNotFoundException]::new("$Cmdlet is not available in this session (not granted by role-based access control).")
        }
        $data = @(& $Cmdlet @Parameters -ErrorAction Stop)
        $success = $true
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $forbidden = $true
        $message = $_.Exception.Message
    }
    catch {
        $message = ($_.Exception.Message -replace '\s+', ' ')
        if ($message -match 'access ?denied|not authorized|unauthorized|forbidden|permission|isn''t within your current write scope|RBAC|role assignment') { $forbidden = $true }
    }
    if ($message -and $message.Length -gt 240) { $message = $message.Substring(0, 240) + '...' }

    $appColumn = $AppOnlyResult
    if (-not $appColumn) {
        $appColumn = if ($Context.ExchangeMode -eq 'exo-app') { if ($success) { 'success' } elseif ($forbidden) { 'forbidden' } else { 'error' } } else { 'not attempted' }
    }
    $resultText = if ($success) { "ok ($(@($data).Count) objects)" } elseif ($forbidden) { 'forbidden' } else { 'error' }
    $notes = (@($LogLabel, $message) | Where-Object { $_ }) -join ' | '
    Add-SecOakEndpointLogEntry -Check $Check -Tool Exchange -Method 'Invoke' -EndpointOrCmdlet $Cmdlet -HttpStatusOrResult $resultText `
        -AuthUsed $(if ($Context.ExchangeMode -eq 'none') { 'none' } else { $Context.ExchangeMode }) -AppOnlyResult $appColumn -Notes $notes

    [pscustomobject]@{ Success = $success; Forbidden = $forbidden; Data = $data; ErrorMessage = $message }
}
