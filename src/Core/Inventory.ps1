function Get-SecOakUserInventory {
    <#
    .SYNOPSIS
        Loads all users once (with sign-in activity when licensed) and caches them for every area.
    .PARAMETER Context
        The run context.
    .NOTES
        Permissions: Directory.Read.All, plus AuditLog.Read.All for signInActivity (Entra ID P1 or P2).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    if ($Context.Cache.ContainsKey('Users')) { return }
    $select = 'id,displayName,userPrincipalName,mail,accountEnabled,userType,createdDateTime,assignedLicenses,assignedPlans'
    $result = Invoke-SecOakGraphGet -Context $Context -Area 'Identity' -Check 'Identity/UserInventory' -Path "/users?`$select=$select,signInActivity&`$top=500" -RawName 'identity-users' -NoGap
    $Context.Cache.SignInActivityAvailable = $result.Success
    if (-not $result.Success) {
        Add-SecOakGap -Context $Context -Area 'Identity' -Check 'Identity/UserInventory' -EndpointOrCmdlet '/v1.0/users?$select=...,signInActivity' `
            -Result "$($result.StatusCode)" -Reason "Sign-in activity unreadable: $($result.ErrorCode): $($result.ErrorMessage)" `
            -FillWith 'Application permissions Directory.Read.All and AuditLog.Read.All; signInActivity also needs Microsoft Entra ID P1 or P2.'
        $result = Invoke-SecOakGraphGet -Context $Context -Area 'Identity' -Check 'Identity/UserInventory' -Path "/users?`$select=$select&`$top=999" -RawName 'identity-users'
    }
    $users = if ($result.Success) { @($result.Items) } else { @() }
    $byId = @{}
    foreach ($user in $users) { $byId[$user.id] = $user }
    $Context.Cache.Users = $users
    $Context.Cache.UsersById = $byId
    $Context.Cache.UsersAvailable = $result.Success
}

function Test-SecOakUserHasMailbox {
    <#
    .SYNOPSIS
        True when a user has an enabled Exchange Online service plan (a licensed mailbox).
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][AllowNull()][object]$User)
    if (-not $User) { return $false }
    [bool](@($User.assignedPlans) | Where-Object { $_.service -eq 'exchange' -and $_.capabilityStatus -eq 'Enabled' })
}

function Get-SecOakOwnServicePrincipal {
    <#
    .SYNOPSIS
        Returns (and caches) the Security Oak reader app's service principal.
    .NOTES
        Permission: Directory.Read.All.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Check
    )
    if ($Context.Cache.ContainsKey('OwnServicePrincipal')) { return $Context.Cache.OwnServicePrincipal }
    $result = Invoke-SecOakGraphGet -Context $Context -Area 'Security Oak access' -Check $Check `
        -Path ("/servicePrincipals?`$filter=appId eq '{0}'" -f $Context.AppId) -RawName 'access-service-principal'
    $sp = if ($result.Success) { $result.Items | Select-Object -First 1 } else { $null }
    $Context.Cache.OwnServicePrincipal = $sp
    $sp
}

function Get-SecOakResourceAppRoleMap {
    <#
    .SYNOPSIS
        Returns a hashtable of app role ID to permission name for a resource service principal.
    .NOTES
        Permission: Directory.Read.All.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$ResourceServicePrincipalId
    )
    $key = "AppRoles:$ResourceServicePrincipalId"
    if ($Context.Cache.ContainsKey($key)) { return $Context.Cache[$key] }
    $result = Invoke-SecOakGraphGet -Context $Context -Area $Area -Check $Check -Path "/servicePrincipals/$ResourceServicePrincipalId`?`$select=id,appId,displayName,appRoles"
    $map = @{ DisplayName = ''; Roles = @{} }
    if ($result.Success) {
        $map.DisplayName = $result.Body.displayName
        foreach ($role in @($result.Body.appRoles)) { $map.Roles[$role.id] = $role.value }
    }
    $Context.Cache[$key] = $map
    $map
}

function Get-SecOakPermissionRisk {
    <#
    .SYNOPSIS
        Classifies an application permission name as Write, SensitiveRead, or Read.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Permission)
    if ($Permission -eq 'Exchange.ManageAsApp') { return 'Elevated' }
    if ($Permission -eq 'full_access_as_app') { return 'Write' }
    # Judge the access segments (after the resource name), so names such as
    # DeviceManagementManagedDevices.Read.All are not mistaken for manage rights.
    $segments = @($Permission -split '\.' | Select-Object -Skip 1)
    foreach ($segment in $segments) {
        if ($segment -match '^(ReadWrite\w*|Write|Manage\w*|FullControl|Send|Create|Delete|Grant|Invite)$') { return 'Write' }
    }
    if ($Permission -in $script:SensitiveReadPermissions) { return 'SensitiveRead' }
    'Read'
}
