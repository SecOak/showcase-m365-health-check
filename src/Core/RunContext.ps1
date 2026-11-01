function New-SecOakRunContext {
    <#
    .SYNOPSIS
        Creates the run context that every check function receives.
    .DESCRIPTION
        Holds tenant settings, output paths, collected findings and gaps, and a cache of
        data shared between areas. Contains no tokens or secrets.
    .PARAMETER ClientName
        Short client name used for the output folder.
    .PARAMETER TenantId
        Expected tenant ID (GUID). Tokens for any other tenant are rejected.
    .PARAMETER AppId
        Application (client) ID of the Security Oak reader app in the client tenant.
    .PARAMETER CertificateThumbprint
        Thumbprint of the certificate in Cert:\CurrentUser\My. Omit to use a client secret
        from the SECOAK_APP_SECRET environment variable.
    .PARAMETER InitialDomain
        The tenant's initial domain (contoso.onmicrosoft.com). Discovered from Graph if omitted.
    .PARAMETER OutputPath
        Folder for this run's output.
    .PARAMETER AzureCliFallback
        Retry calls the app cannot make (401 or 403) with an Azure CLI delegated token.
    .PARAMETER ExchangeInteractiveFallback
        Fall back to an interactive Exchange Online sign-in when app-only access is not possible.
    .PARAMETER ExchangeUserPrincipalName
        Optional account to pre-fill for the interactive Exchange Online sign-in.
    .PARAMETER Tenantless
        Creates a context with no tenant and no app, for checks that use public sources only
        (the Domain area run by tools\Invoke-SecurityOakDomainScan.ps1). No token can be
        acquired with such a context.
    .EXAMPLE
        $context = New-SecOakRunContext -ClientName contoso -TenantId $tenantId -AppId $appId -CertificateThumbprint $thumb -OutputPath $out
    .EXAMPLE
        $context = New-SecOakRunContext -ClientName contoso -Tenantless -OutputPath $out
    .NOTES
        No permissions required.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Tenant')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9\-_]{0,62}$')][string]$ClientName,
        [Parameter(Mandatory, ParameterSetName = 'Tenant')][ValidateScript({ [guid]::TryParse($_, [ref][guid]::Empty) })][string]$TenantId,
        [Parameter(Mandatory, ParameterSetName = 'Tenant')][ValidateScript({ [guid]::TryParse($_, [ref][guid]::Empty) })][string]$AppId,
        [Parameter(ParameterSetName = 'Tenant')][AllowEmptyString()][ValidatePattern('^([0-9A-Fa-f]{40})?$')][string]$CertificateThumbprint = '',
        [Parameter(ParameterSetName = 'Tenant')][AllowEmptyString()][string]$InitialDomain = '',
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$OutputPath,
        [Parameter(ParameterSetName = 'Tenant')][switch]$AzureCliFallback,
        [Parameter(ParameterSetName = 'Tenant')][switch]$ExchangeInteractiveFallback,
        [Parameter(ParameterSetName = 'Tenant')][AllowEmptyString()][string]$ExchangeUserPrincipalName = '',
        [Parameter(Mandatory, ParameterSetName = 'Tenantless')][switch]$Tenantless
    )
    # Parameter variables keep their validation attributes, so tenantless values go into new variables.
    $tenantValue = if ($Tenantless) { '' } else { $TenantId.ToLowerInvariant() }
    $appValue = if ($Tenantless) { '' } else { $AppId.ToLowerInvariant() }
    [pscustomobject]@{
        ClientName                  = $ClientName
        Tenantless                  = [bool]$Tenantless
        TenantId                    = $tenantValue
        AppId                       = $appValue
        CertificateThumbprint       = $CertificateThumbprint.ToUpperInvariant()
        CredentialType              = if ($CertificateThumbprint) { 'Certificate' } else { 'Secret' }
        InitialDomain               = $InitialDomain
        OutputPath                  = $OutputPath
        RawPath                     = $null
        AzureCliFallback            = [bool]$AzureCliFallback
        ExchangeInteractiveFallback = [bool]$ExchangeInteractiveFallback
        ExchangeUserPrincipalName   = $ExchangeUserPrincipalName
        ExchangeMode                = 'none'
        ExchangeConnectionId        = ''
        ComplianceMode              = 'none'
        ComplianceConnectionId      = ''
        TeamsMode                   = 'none'
        ApiState                    = @{}
        AppTokenAvailable           = $false
        AzureCliTokenState          = 'not requested'
        StartedUtc                  = [datetime]::UtcNow
        Findings                    = [System.Collections.Generic.List[object]]::new()
        Gaps                        = [System.Collections.Generic.List[object]]::new()
        AreaSummaries               = [ordered]@{}
        Cache                       = @{}
    }
}

function Disconnect-SecOakSession {
    <#
    .SYNOPSIS
        Clears cached tokens and disconnects Security and Compliance, Teams, and Exchange Online
        if this module connected them.
    .PARAMETER Context
        The run context.
    .NOTES
        No permissions required.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    Disconnect-SecOakCompliance -Context $Context
    Disconnect-SecOakTeams -Context $Context
    Disconnect-SecOakExchange -Context $Context
    $script:Tokens.Clear()
}
