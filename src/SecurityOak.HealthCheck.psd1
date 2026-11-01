@{
    RootModule           = 'SecurityOak.HealthCheck.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '5b0f7d3e-2a61-4c1e-9a4f-8d3c6e2b9f10'
    Author               = 'Security Oak'
    CompanyName          = 'Security Oak'
    Description          = 'Read-only Microsoft 365 security health check functions for Security Oak client tenants.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    # ExchangeOnlineManagement is loaded on demand by the Email area only, so it is not a hard requirement here.
    FunctionsToExport    = @(
        'New-SecOakRunContext', 'Initialize-SecOakOutputFolder', 'Connect-SecOakGraph', 'Get-SecOakTenantIdentity',
        'Invoke-SecOakGraphGet', 'Connect-SecOakExchange', 'Disconnect-SecOakExchange', 'Invoke-SecOakExchangeGet',
        'Disconnect-SecOakSession', 'Get-SecOakEndpointLog', 'Save-SecOakRawData',
        'Invoke-SecOakIdentityCheck', 'Invoke-SecOakEmailCheck', 'Invoke-SecOakDomainCheck', 'Invoke-SecOakDeviceCheck', 'Invoke-SecOakSharingCheck',
        'Invoke-SecOakLicensingCheck', 'Invoke-SecOakPostureCheck', 'Invoke-SecOakAccessAudit', 'Export-SecOakRunReport',
        'Invoke-SecOakEntraCheck', 'Invoke-SecOakIntuneCheck', 'Invoke-SecOakDefenderCheck', 'Invoke-SecOakExchangeCheck', 'Invoke-SecOakSharePointCheck',
        'Invoke-SecOakTeamsCheck', 'Invoke-SecOakPurviewCheck', 'Invoke-SecOakServiceHealthCheck', 'Invoke-SecOakBackupCheck', 'Invoke-SecOakAzureCheck'
    )
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{ PSData = @{ Tags = @('Microsoft365', 'Security', 'HealthCheck', 'ReadOnly') } }
}
