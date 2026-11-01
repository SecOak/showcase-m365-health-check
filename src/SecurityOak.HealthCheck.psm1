#Requires -Version 7.2
<#
.SYNOPSIS
    Read-only Microsoft 365 security health check functions for Security Oak.

.DESCRIPTION
    Core plumbing (token acquisition, read-only Microsoft Graph and Exchange Online
    wrappers, endpoint logging) plus one check function per area:

        Invoke-SecOakIdentityCheck     Identity
        Invoke-SecOakEmailCheck        Email
        Invoke-SecOakDomainCheck       Domain (public sources only, no tenant permissions)
        Invoke-SecOakDeviceCheck       Devices
        Invoke-SecOakSharingCheck      Sharing
        Invoke-SecOakLicensingCheck    Licensing
        Invoke-SecOakPostureCheck      Posture
        Invoke-SecOakAccessAudit       Security Oak access (self-audit of the reader app)

    Read-only guarantee, enforced structurally:
      * Invoke-SecOakGraphGet is the only function that calls Microsoft Graph and it only
        issues HTTP GET. There is no parameter that changes the method.
      * Invoke-SecOakExchangeGet is the only function that runs Exchange cmdlets and it
        rejects any cmdlet whose name does not start with "Get-".
      * The only non-GET HTTP request is the OAuth token request to
        login.microsoftonline.com, which reads nothing from and changes nothing in the tenant.
      * The Domain area uses public DNS queries and HTTPS GET requests to a fixed list of
        public hosts (Invoke-SecOakPublicHttpsGet enforces the list). It needs no tenant
        permissions, sends no credentials, and never scans ports or guesses subdomains.

    This file loads the module's functions from src\Core (shared plumbing) and
    src\Areas (one file per check area), in a fixed order, then re-applies the
    original module's Export-ModuleMember call.

.NOTES
    Author:           Security Oak
    Required modules: ExchangeOnlineManagement 3.x (Email area only)
    Optional tools:   Azure CLI (delegated fallback for calls the app cannot make)
    Permissions:      see docs/permissions.md and the permission hints in this module.
#>

#region Core (load first, fixed order)
. $PSScriptRoot\Core\Constants.ps1
. $PSScriptRoot\Core\Helpers.ps1
. $PSScriptRoot\Core\Findings.ps1
. $PSScriptRoot\Core\EndpointLog.ps1
. $PSScriptRoot\Core\RunContext.ps1
. $PSScriptRoot\Core\OutputFolder.ps1
. $PSScriptRoot\Core\Token.ps1
. $PSScriptRoot\Core\Graph.ps1
. $PSScriptRoot\Core\TenantIdentity.ps1
. $PSScriptRoot\Core\Exchange.ps1
. $PSScriptRoot\Core\Apis.ps1
. $PSScriptRoot\Core\PublicHttpsDns.ps1
. $PSScriptRoot\Core\Inventory.ps1
#endregion

#region Areas (load after Core, fixed order)
. $PSScriptRoot\Areas\Identity.ps1
. $PSScriptRoot\Areas\Email.ps1
. $PSScriptRoot\Areas\Domain.ps1
. $PSScriptRoot\Areas\Devices.ps1
. $PSScriptRoot\Areas\Sharing.ps1
. $PSScriptRoot\Areas\Licensing.ps1
. $PSScriptRoot\Areas\Posture.ps1
. $PSScriptRoot\Areas\Access.ps1
. $PSScriptRoot\Areas\Entra.ps1
. $PSScriptRoot\Areas\Intune.ps1
. $PSScriptRoot\Areas\Defender.ps1
. $PSScriptRoot\Areas\Exchange.ps1
. $PSScriptRoot\Areas\SharePoint.ps1
. $PSScriptRoot\Areas\Teams.ps1
. $PSScriptRoot\Areas\Purview.ps1
. $PSScriptRoot\Areas\ServiceHealth.ps1
. $PSScriptRoot\Areas\Backup.ps1
. $PSScriptRoot\Areas\Azure.ps1
. $PSScriptRoot\Areas\Report.ps1
#endregion

Export-ModuleMember -Function @(
    'New-SecOakRunContext', 'Initialize-SecOakOutputFolder', 'Connect-SecOakGraph', 'Get-SecOakTenantIdentity',
    'Invoke-SecOakGraphGet', 'Connect-SecOakExchange', 'Disconnect-SecOakExchange', 'Invoke-SecOakExchangeGet',
    'Disconnect-SecOakSession', 'Get-SecOakEndpointLog', 'Save-SecOakRawData',
    'Invoke-SecOakIdentityCheck', 'Invoke-SecOakEmailCheck', 'Invoke-SecOakDomainCheck', 'Invoke-SecOakDeviceCheck', 'Invoke-SecOakSharingCheck',
    'Invoke-SecOakLicensingCheck', 'Invoke-SecOakPostureCheck', 'Invoke-SecOakAccessAudit', 'Export-SecOakRunReport',
    'Invoke-SecOakEntraCheck', 'Invoke-SecOakIntuneCheck', 'Invoke-SecOakDefenderCheck', 'Invoke-SecOakExchangeCheck', 'Invoke-SecOakSharePointCheck',
    'Invoke-SecOakTeamsCheck', 'Invoke-SecOakPurviewCheck', 'Invoke-SecOakServiceHealthCheck', 'Invoke-SecOakBackupCheck', 'Invoke-SecOakAzureCheck'
)
