function Get-SecOakTenantIdentity {
    <#
    .SYNOPSIS
        Returns the tenant display name, ID, and initial domain for the confirmation step.
    .PARAMETER Context
        The run context. The app token must already be available.
    .EXAMPLE
        Get-SecOakTenantIdentity -Context $context
    .NOTES
        Permission: Directory.Read.All (application).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $result = Invoke-SecOakGraphGet -Context $Context -Area 'Run' -Check 'Run/TenantConfirmation' -Path '/organization?$select=id,displayName,verifiedDomains' -NoGap
    if (-not $result.Success -or -not $result.Items) {
        throw "Could not read the tenant identity from /organization ($($result.StatusCode) $($result.ErrorMessage)). Nothing was collected."
    }
    $organization = $result.Items[0]
    if ("$($organization.id)".ToLowerInvariant() -ne $Context.TenantId) {
        throw 'Graph returned an organization whose ID does not match the configured tenant. Stopping.'
    }
    $initial = ($organization.verifiedDomains | Where-Object isInitial | Select-Object -First 1).name
    if (-not $Context.InitialDomain) { $Context.InitialDomain = $initial }
    [pscustomobject]@{
        TenantDisplayName = $organization.displayName
        TenantId          = $organization.id
        InitialDomain     = $initial
        VerifiedDomains   = @($organization.verifiedDomains).Count
    }
}
