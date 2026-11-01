#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Audits, and optionally aligns, the Security Oak reader app in one client tenant against
    the approved least-privilege set.

.DESCRIPTION
    Signs in with delegated Microsoft Graph access, shows the tenant display name and ID, and
    does nothing until the tenant is confirmed. Confirmation is either an interactive "yes" or
    the -ConfirmedTenantId parameter, which must match the signed-in tenant.

    Default mode is report only: every Microsoft Graph request is a GET. The script finds the
    reader app (by -AppId, otherwise by -DisplayName), then compares it with the approved set
    in config\reader-app-permissions.json (the single source of truth, see -PermissionFile):
        requested permissions (requiredResourceAccess)
        granted application permissions (appRoleAssignments on the service principal)
        Microsoft Entra directory roles assigned to the service principal
        certificates (count, end date, days remaining), client secrets, owners
        sign-in audience and delegated permission grants

    It returns one object describing the app, what is missing, what is extra (with a risk
    label), whether the app is compliant, and the changes -Apply would make.

    With -Apply, the script creates the app and service principal when they do not exist
    (single tenant), sets the requested permissions, grants admin consent for missing
    application permissions, assigns the approved directory roles (Global Reader), and adds
    the certificate from -CertificatePath (in the create request itself when the app is new).
    Extra granted permissions are removed only with -RemoveExtraPermissions.
    Owners, client secrets, certificates, other directory roles, and delegated grants are never
    removed; they are reported for manual follow-up. Every change goes through ShouldProcess, so
    -WhatIf previews and -Confirm prompts. After applying, the audit runs again and the fresh
    result is returned with an AppliedChanges list.

    Safety: when any approved permission cannot be resolved in the tenant, or any part of the
    audit could not be read, nothing is removed even with -RemoveExtraPermissions, and the
    requested permissions are only added to, never reduced. The reason is listed under
    ManualFollowUp. Azure roles in the permission file are informational: they are reported
    as a manual step and the script makes no Azure calls.

.PARAMETER TenantId
    Client tenant ID. The signed-in context must be in this tenant.

.PARAMETER AppId
    Application (client) ID of an existing reader app to audit. When omitted, the app is found
    by -DisplayName. When given and not found, -Apply does not create a new app.

.PARAMETER DisplayName
    Display name used to find the app when -AppId is omitted, and to create it with -Apply.

.PARAMETER CertificatePath
    Public key certificate file (.cer, DER or PEM) to add to the app with -Apply. The file must
    be a plain certificate: PFX or PKCS#12 content and any PEM private key block are refused
    before the file is loaded. In report mode it is only checked against the certificates on
    the application object.

.PARAMETER PermissionFile
    JSON file holding the approved set. Defaults to config\reader-app-permissions.json beside
    the setup folder. It is validated before anything connects.

.PARAMETER ConfirmedTenantId
    Non-interactive confirmation. Must equal -TenantId and the signed-in tenant.

.PARAMETER Apply
    Make the planned changes. Without it, the script only reads.

.PARAMETER RemoveExtraPermissions
    With -Apply, remove granted application permissions outside the approved set and drop
    extra entries from the requested permissions. Without it, extras are only reported.

.PARAMETER UseDeviceCode
    Sign in with a device code instead of an interactive window, for terminals that cannot
    show the Web Account Manager sign-in window.

.EXAMPLE
    ./setup/New-SecurityOakReaderApp.ps1 -TenantId 00000000-0000-0000-0000-000000000000

    Report only. Finds 'Security Oak - Read-Only Assessment' in the tenant and prompts for
    "yes" after showing the tenant.

.EXAMPLE
    ./setup/New-SecurityOakReaderApp.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -AppId 00000000-0000-0000-0000-000000000000 -ConfirmedTenantId 00000000-0000-0000-0000-000000000000

    Report only, non-interactive, for a known app.

.EXAMPLE
    ./setup/New-SecurityOakReaderApp.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -Apply -CertificatePath $HOME\SecurityOak\certificates\contoso-reader.cer -WhatIf

    Previews creating or aligning the reader app for the contoso tenant without changing it.

.EXAMPLE
    ./setup/New-SecurityOakReaderApp.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -Apply -RemoveExtraPermissions

    Aligns an existing reader app and removes granted permissions outside the approved set.
    Nothing is removed if the approved set did not fully resolve or the audit has gaps.

.EXAMPLE
    ./setup/New-SecurityOakReaderApp.ps1 -TenantId 00000000-0000-0000-0000-000000000000 -ConfirmedTenantId 00000000-0000-0000-0000-000000000000 -Apply -Confirm:$false

    Automation: applies every planned change without the per-change prompts that
    ConfirmImpact High raises otherwise. Run the same command with -WhatIf first.

.OUTPUTS
    PSCustomObject with TenantDisplayName, TenantId, Mode, AppFound, AppId, ServicePrincipalId,
    Missing, Extra, RequiredResourceAccessAligned, GlobalReaderAssigned (every approved
    directory role assigned at tenant scope), OtherDirectoryRoles, CertificateCount and
    CertificateExpiry (application object only), ServicePrincipalKeyCount, ClientSecretCount
    (application and service principal), OwnerCount, SignInAudience, DelegatedGrantCount,
    Compliant, PlannedChanges, ManualFollowUp, AuditGaps, AppliedChanges.

.NOTES
    Required modules: Microsoft.Graph.Authentication 2.x (Invoke-MgGraphRequest only).

    Delegated Microsoft Graph scopes, report mode:
        Directory.Read.All, RoleManagement.Read.Directory (Directory.Read.All is needed for the
        service principal's delegated grants; it also covers applications and the organization)
    Delegated Microsoft Graph scopes, -Apply mode (in addition to the report scopes):
        Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All,
        RoleManagement.ReadWrite.Directory

    Signed-in role: report mode works with Global Reader. -Apply needs Privileged Role
    Administrator (admin consent for application permissions and the Global Reader
    assignment) plus Application Administrator or Cloud Application Administrator. Activate
    the role through Privileged Identity Management on the admin account before running.

    If the delegated permission grants read is still refused, the count is reported as an
    audit gap and the app is not marked Compliant.

    Nothing identifying a client belongs in this file. Keep client values in parameters.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
[OutputType([pscustomobject])]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter()][guid]$AppId,
    [Parameter()][ValidateNotNullOrEmpty()][ValidateLength(1, 120)][string]$DisplayName = 'Security Oak - Read-Only Assessment',
    [Parameter()][ValidateScript({
            (Test-Path -LiteralPath $_ -PathType Leaf) -and ([System.IO.Path]::GetExtension($_) -eq '.cer')
        }, ErrorMessage = 'CertificatePath must be an existing .cer public key file.')][string]$CertificatePath,
    [Parameter()][guid]$ConfirmedTenantId,
    [Parameter()][switch]$Apply,
    [Parameter()][switch]$RemoveExtraPermissions,
    [Parameter()][switch]$UseDeviceCode,
    [Parameter()][ValidateNotNullOrEmpty()][string]$PermissionFile = (Join-Path $PSScriptRoot '..\config\reader-app-permissions.json')
)

$ErrorActionPreference = 'Stop'

#region Approved least-privilege set

# The approved set lives in config\reader-app-permissions.json (see -PermissionFile) and is
# loaded by Import-ReaderPermissionSet before anything connects. Role IDs are resolved at
# runtime from each resource service principal's appRoles by value; expectedRoleId, when
# set in the file, is asserted against the resolved ID.
$script:ApprovedApplicationPermissions = @()
$script:ApprovedDirectoryRoles = @()
$script:ApprovedAzureRoles = @()
$script:DefaultAccessRoleId = '00000000-0000-0000-0000-000000000000'
$script:AllowedAreas = @('Identity', 'Email', 'Devices', 'Sharing', 'Licensing', 'Posture', 'Access', 'Defender', 'Intune', 'Azure', 'Purview', 'Teams', 'ServiceHealth', 'Backup', 'Domain')

# Same list and rules as Get-SecOakPermissionRisk in src\SecurityOak.HealthCheck.psm1.
# That function is not exported, so the rules are repeated here; keep both in step.
$script:SensitiveReadPermissions = @(
    'Mail.Read', 'Mail.ReadBasic.All', 'Mail.ReadBasic', 'MailboxSettings.Read', 'Calendars.Read',
    'Contacts.Read', 'Files.Read.All', 'Sites.Read.All', 'Chat.Read.All', 'ChannelMessage.Read.All',
    'Notes.Read.All', 'OnlineMeetingTranscript.Read.All', 'OnlineMeetingRecording.Read.All',
    'UserAuthenticationMethod.Read.All', 'AuditLog.Read.All', 'Directory.Read.All',
    'IdentityRiskyUser.Read.All', 'SecurityEvents.Read.All'
)

$script:ReportScopes = @('Directory.Read.All', 'RoleManagement.Read.Directory')
$script:ApplyScopes = @('Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All', 'RoleManagement.ReadWrite.Directory')

#endregion

#region Helpers

function Invoke-ReaderGraphGet {
    <#
    .SYNOPSIS
        Sends a Microsoft Graph GET request. With -Collection, follows every next link and
        returns the items.
    .NOTES
        Uses Invoke-MgGraphRequest from Microsoft.Graph.Authentication.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri,
        [Parameter()][switch]$Collection
    )
    Write-Verbose "GET $Uri"
    $response = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
    if (-not $Collection) { return $response }
    $items = [System.Collections.Generic.List[object]]::new()
    while ($true) {
        foreach ($item in @($response.value)) { if ($null -ne $item) { $items.Add($item) } }
        $next = $response.'@odata.nextLink'
        if (-not $next) { break }
        Write-Verbose "GET $next"
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
    }
    $items.ToArray()
}

function Invoke-ReaderGraphWrite {
    <#
    .SYNOPSIS
        Sends a Microsoft Graph POST, PATCH, or DELETE request, retrying when asked (used right
        after creating an object, while it replicates).
    .NOTES
        Called only from inside a ShouldProcess block in the apply section.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][ValidateSet('POST', 'PATCH', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Uri,
        [Parameter()][object]$Body,
        [Parameter()][ValidateRange(1, 6)][int]$Attempts = 1
    )
    $request = @{ Method = $Method; Uri = $Uri; OutputType = 'PSObject'; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $request.Body = $Body | ConvertTo-Json -Depth 10 -Compress
        $request.ContentType = 'application/json'
    }
    for ($attempt = 1; ; $attempt++) {
        try {
            Write-Verbose "$Method $Uri (attempt $attempt of $Attempts)"
            return Invoke-MgGraphRequest @request
        }
        catch {
            if ($attempt -ge $Attempts) { throw }
            Write-Verbose "Request failed, waiting 10 seconds for replication: $($_.Exception.Message)"
            Start-Sleep -Seconds 10
        }
    }
}

function ConvertTo-ReaderODataString {
    <#
    .SYNOPSIS
        Escapes a value for use inside single quotes in an OData filter, then URL-encodes it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value)
    [uri]::EscapeDataString($Value.Replace("'", "''"))
}

function ConvertTo-ReaderUtcDate {
    <#
    .SYNOPSIS
        Converts a Graph date (string or already-parsed date) to a UTC date, or $null.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param([Parameter()][AllowNull()][object]$Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $parsed = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
        return $parsed.UtcDateTime
    }
    $null
}

function Import-ReaderPermissionSet {
    <#
    .SYNOPSIS
        Loads and validates the approved set from the permission file, then stores it in the
        script-level approved tables.
    .NOTES
        Local file read only. Collects every problem and throws them together.
    #>
    [CmdletBinding()]
    [OutputType([void])]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Permission file '$Path' was not found." }
    try { $data = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Permission file '$Path' is not valid JSON: $($_.Exception.Message)" }

    $problems = [System.Collections.Generic.List[string]]::new()
    $isGuid = { param($Value) $parsed = [guid]::Empty; [guid]::TryParse("$Value", [ref]$parsed) }
    if ($data.schemaVersion -ne 1) { $problems.Add("schemaVersion must be 1 (found '$($data.schemaVersion)').") }

    $permissions = [System.Collections.Generic.List[object]]::new()
    $seen = @{}
    $resources = @($data.resources | Where-Object { $_ })
    if (-not $resources.Count) { $problems.Add('resources must list at least one resource.') }
    foreach ($resource in $resources) {
        $label = if ($resource.name) { "$($resource.name)" } else { '(unnamed resource)' }
        if (-not $resource.name) { $problems.Add('Every resource needs a name.') }
        if (-not (& $isGuid $resource.resourceAppId)) { $problems.Add("${label}: resourceAppId must be a GUID.") }
        $entries = @($resource.permissions | Where-Object { $_ })
        if (-not $entries.Count) { $problems.Add("${label}: permissions must list at least one permission.") }
        foreach ($entry in $entries) {
            $name = "$($entry.permission)"
            if ($name -notmatch '^[A-Za-z0-9_.\-]+$') { $problems.Add("${label}: permission '$name' is empty or has unexpected characters."); continue }
            $key = "$($resource.resourceAppId)|$name".ToLowerInvariant()
            if ($seen.ContainsKey($key)) { $problems.Add("${label}: $name is listed more than once.") }
            $seen[$key] = $true
            if ($null -ne $entry.expectedRoleId -and -not (& $isGuid $entry.expectedRoleId)) { $problems.Add("${label} ${name}: expectedRoleId must be null or a GUID.") }
            $areas = @($entry.areas | Where-Object { $_ })
            if (-not $areas.Count) { $problems.Add("${label} ${name}: areas must list at least one area.") }
            foreach ($area in $areas) {
                if ($area -notin $script:AllowedAreas) { $problems.Add("${label} ${name}: unknown area '$area'. Allowed: $($script:AllowedAreas -join ', ').") }
            }
            $permissions.Add([pscustomobject]@{
                    ResourceAppId  = "$($resource.resourceAppId)".ToLowerInvariant()
                    ResourceName   = "$($resource.name)"
                    Permission     = $name
                    ExpectedRoleId = if ($null -ne $entry.expectedRoleId) { "$($entry.expectedRoleId)".ToLowerInvariant() } else { $null }
                    Areas          = $areas
                })
        }
    }

    $directoryRoles = [System.Collections.Generic.List[object]]::new()
    foreach ($role in @($data.directoryRoles | Where-Object { $_ })) {
        if (-not $role.name) { $problems.Add('Every directory role needs a name.') }
        if (-not (& $isGuid $role.roleTemplateId)) { $problems.Add("Directory role '$($role.name)': roleTemplateId must be a GUID.") }
        $areas = @($role.areas | Where-Object { $_ })
        foreach ($area in $areas) {
            if ($area -notin $script:AllowedAreas) { $problems.Add("Directory role '$($role.name)': unknown area '$area'.") }
        }
        $directoryRoles.Add([pscustomobject]@{ RoleName = "$($role.name)"; RoleTemplateId = "$($role.roleTemplateId)".ToLowerInvariant(); Areas = $areas })
    }

    $azureRoles = [System.Collections.Generic.List[object]]::new()
    foreach ($role in @($data.azureRoles | Where-Object { $_ })) {
        if (-not $role.name -or -not $role.scope) { $problems.Add('Every Azure role needs a name and a scope.') }
        $azureRoles.Add([pscustomobject]@{ RoleName = "$($role.name)"; Scope = "$($role.scope)" })
    }

    if ($problems.Count) {
        $newLine = [Environment]::NewLine
        throw "Permission file '$Path' is invalid:$newLine  $($problems -join "$newLine  ")"
    }
    $script:ApprovedApplicationPermissions = $permissions.ToArray()
    $script:ApprovedDirectoryRoles = $directoryRoles.ToArray()
    $script:ApprovedAzureRoles = $azureRoles.ToArray()
    Write-Verbose "Loaded $($permissions.Count) application permissions, $($directoryRoles.Count) directory roles, and $($azureRoles.Count) Azure roles from $Path"
}

function Import-ReaderPublicCertificate {
    <#
    .SYNOPSIS
        Loads a public key certificate file after checking, before loading, that it is a
        plain certificate with no private key material.
    .NOTES
        Local file read only. Refuses PFX or PKCS#12 content and any PEM private key block.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param([Parameter(Mandatory)][string]$Path)
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $text = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($resolved))
    if ($text -match 'PRIVATE KEY-----') {
        throw "'$Path' contains a private key block. Supply the public key certificate only."
    }
    $contentType = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($resolved)
    if ($contentType -ne [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert) {
        throw "'$Path' is not a plain certificate (content type $contentType). Supply the public key .cer file only."
    }
    $loaded = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($resolved)
    if ($loaded.HasPrivateKey) { $loaded.Dispose(); throw "'$Path' holds a private key. Supply the public key .cer file only." }
    if ($loaded.NotAfter.ToUniversalTime() -le [datetime]::UtcNow) { $loaded.Dispose(); throw "The certificate in '$Path' has expired." }
    $loaded
}

function Test-ReaderSafeToRemove {
    <#
    .SYNOPSIS
        True only when every approved permission resolved to a role and a resource service
        principal and the audit has no gaps, so an extra permission can be told apart from an
        approved one with certainty.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)][hashtable]$State)
    $unresolved = @($State.Approved | Where-Object { -not $_.AppRoleId -or -not $_.ResourceServicePrincipalId })
    (@($State.Approved).Count -gt 0) -and ($unresolved.Count -eq 0) -and ($State.Gaps.Count -eq 0)
}

function Get-ReaderPermissionRisk {
    <#
    .SYNOPSIS
        Classifies a permission outside the approved set as Elevated, Write, SensitiveRead, or
        Read, using the same rules as Get-SecOakPermissionRisk.
    .NOTES
        Only called for permissions outside the approved set, so Exchange.ManageAsApp reaching
        this function is never the approved grant and is labelled Elevated.
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

function Get-ReaderResourceServicePrincipal {
    <#
    .SYNOPSIS
        Returns a resource service principal (with appRoles and delegated scopes) by appId or
        object ID, cached for the run. Returns $null when it does not exist in the tenant.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)][hashtable]$Cache,
        [Parameter(Mandatory, ParameterSetName = 'AppId')][string]$ResourceAppId,
        [Parameter(Mandatory, ParameterSetName = 'Id')][string]$ServicePrincipalId
    )
    $select = 'id,appId,displayName,appRoles,oauth2PermissionScopes'
    if ($PSCmdlet.ParameterSetName -eq 'Id') {
        if ($Cache.ContainsKey("id:$ServicePrincipalId")) { return $Cache["id:$ServicePrincipalId"] }
        $servicePrincipal = Invoke-ReaderGraphGet -Uri "/v1.0/servicePrincipals/$ServicePrincipalId`?`$select=$select"
    }
    else {
        if ($Cache.ContainsKey("app:$ResourceAppId")) { return $Cache["app:$ResourceAppId"] }
        $filter = ConvertTo-ReaderODataString -Value $ResourceAppId
        $servicePrincipal = @(Invoke-ReaderGraphGet -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$filter'&`$select=$select" -Collection) | Select-Object -First 1
    }
    if ($servicePrincipal) {
        $Cache["id:$($servicePrincipal.id)"] = $servicePrincipal
        $Cache["app:$($servicePrincipal.appId)"] = $servicePrincipal
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'AppId') {
        $Cache["app:$ResourceAppId"] = $null
    }
    $servicePrincipal
}

function Resolve-ReaderApprovedPermission {
    <#
    .SYNOPSIS
        Resolves each approved application permission to its resource service principal and
        app role ID, by value. Asserts ExpectedRoleId where one is set.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][hashtable]$Cache)
    foreach ($approved in $script:ApprovedApplicationPermissions) {
        $resource = $null
        try { $resource = Get-ReaderResourceServicePrincipal -Cache $Cache -ResourceAppId $approved.ResourceAppId }
        catch { Write-Warning "Could not read the $($approved.ResourceName) service principal: $($_.Exception.Message)" }
        $roleId = $null
        if ($resource) {
            $role = @($resource.appRoles) | Where-Object { $_.value -eq $approved.Permission -and @($_.allowedMemberTypes) -contains 'Application' } | Select-Object -First 1
            if ($role) { $roleId = "$($role.id)" }
            else { Write-Warning "$($approved.ResourceName) does not publish an application permission named $($approved.Permission)." }
        }
        else {
            Write-Warning "$($approved.ResourceName) ($($approved.ResourceAppId)) has no service principal in this tenant; $($approved.Permission) cannot be resolved."
        }
        if ($roleId -and $approved.ExpectedRoleId -and $roleId -ne $approved.ExpectedRoleId) {
            throw "Assertion failed: $($approved.ResourceName) $($approved.Permission) resolved to role ID $roleId, expected $($approved.ExpectedRoleId). Stopping before anything else is read or changed."
        }
        [pscustomobject]@{
            ResourceAppId              = $approved.ResourceAppId
            ResourceName               = $approved.ResourceName
            ResourceServicePrincipalId = if ($resource) { "$($resource.id)" } else { $null }
            Permission                 = $approved.Permission
            AppRoleId                  = $roleId
            Areas                      = $approved.Areas
        }
    }
}

function Get-ReaderPermissionName {
    <#
    .SYNOPSIS
        Returns the permission value for an app role or delegated scope ID on a resource.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()][AllowNull()][object]$Resource,
        [Parameter(Mandatory)][string]$PermissionId,
        [Parameter(Mandatory)][ValidateSet('Role', 'Scope')][string]$Type
    )
    if ($PermissionId -eq $script:DefaultAccessRoleId) { return '(default access)' }
    if (-not $Resource) { return "(unknown $PermissionId)" }
    $list = if ($Type -eq 'Role') { @($Resource.appRoles) } else { @($Resource.oauth2PermissionScopes) }
    $match = $list | Where-Object { "$($_.id)" -eq $PermissionId } | Select-Object -First 1
    if ($match) { "$($match.value)" } else { "(unknown $PermissionId)" }
}

function ConvertTo-ReaderRequiredResourceAccess {
    <#
    .SYNOPSIS
        Builds the requiredResourceAccess body: the approved set, plus any extra requested
        entries passed in -KeepEntries, grouped by resource.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)][object[]]$Approved,
        [Parameter()][object[]]$KeepEntries = @()
    )
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $Approved) {
        if ($item.AppRoleId) { $entries.Add([pscustomobject]@{ ResourceAppId = $item.ResourceAppId; Id = $item.AppRoleId; Type = 'Role' }) }
    }
    foreach ($item in $KeepEntries) { $entries.Add([pscustomobject]@{ ResourceAppId = $item.ResourceAppId; Id = $item.Id; Type = $item.Type }) }
    $body = foreach ($group in ($entries | Group-Object ResourceAppId)) {
        @{
            resourceAppId  = $group.Name
            resourceAccess = @($group.Group | Sort-Object Type, Id -Unique | ForEach-Object { @{ id = $_.Id; type = $_.Type } })
        }
    }
    , @($body)
}

function Get-ReaderAppState {
    <#
    .SYNOPSIS
        Reads the reader app and everything the audit compares. GET requests only.
    .OUTPUTS
        Hashtable of raw state used by the report and the apply steps.
    .NOTES
        Delegated scopes: Directory.Read.All, RoleManagement.Read.Directory.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()][AllowNull()][object]$RequestedAppId,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][AllowNull()][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $activity = 'Security Oak reader app audit'
    $now = [datetime]::UtcNow
    $state = @{
        Cache                  = @{}
        Approved               = @()
        Application            = $null
        ServicePrincipal       = $null
        RequestedEntries       = @()
        GrantedAssignments     = @()
        MissingGrants          = @()
        ExtraGrants            = @()
        MissingRequested       = @()
        ExtraRequested         = @()
        GlobalReaderAssigned   = $false
        MissingDirectoryRoles  = @($script:ApprovedDirectoryRoles)
        OtherDirectoryRoles    = @()
        Certificates           = @()
        ServicePrincipalKeyCount = 0
        ClientSecretCount      = 0
        OwnerCount             = $null
        DelegatedGrantCount    = $null
        CertificateAlreadyOnApp = $false
        Gaps                   = [System.Collections.Generic.List[string]]::new()
    }

    Write-Progress -Id 2 -Activity $activity -Status 'Resolving approved permissions' -PercentComplete 5
    $state.Approved = @(Resolve-ReaderApprovedPermission -Cache $state.Cache)
    # An unresolved approved entry is an audit gap: the app cannot be called compliant, and
    # nothing is removed, because an approved grant could not be told apart from an extra one.
    foreach ($item in $state.Approved | Where-Object { -not $_.AppRoleId -or -not $_.ResourceServicePrincipalId }) {
        $state.Gaps.Add("Approved permission $($item.ResourceName) $($item.Permission) could not be resolved in this tenant (resource service principal or role ID missing).")
    }

    #--- Application
    Write-Progress -Id 2 -Activity $activity -Status 'Finding the application' -PercentComplete 15
    $select = 'id,appId,displayName,signInAudience,keyCredentials,passwordCredentials,requiredResourceAccess,createdDateTime'
    $filter = if ($RequestedAppId) { "appId eq '$(ConvertTo-ReaderODataString -Value "$RequestedAppId")'" } else { "displayName eq '$(ConvertTo-ReaderODataString -Value $Name)'" }
    $applications = @(Invoke-ReaderGraphGet -Uri "/v1.0/applications?`$filter=$filter&`$select=$select" -Collection)
    if ($applications.Count -gt 1) {
        $list = ($applications | ForEach-Object { "  $($_.displayName)  appId $($_.appId)  created $($_.createdDateTime)" }) -join [Environment]::NewLine
        throw "More than one application is named '$Name'. Rerun with -AppId set to one of:$([Environment]::NewLine)$list"
    }
    $state.Application = $applications | Select-Object -First 1
    $lookupAppId = if ($state.Application) { "$($state.Application.appId)" } elseif ($RequestedAppId) { "$RequestedAppId" } else { $null }

    #--- Service principal
    if ($lookupAppId) {
        Write-Progress -Id 2 -Activity $activity -Status 'Finding the service principal' -PercentComplete 25
        try {
            $spFilter = ConvertTo-ReaderODataString -Value $lookupAppId
            $state.ServicePrincipal = @(Invoke-ReaderGraphGet -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$spFilter'&`$select=id,appId,displayName,keyCredentials,passwordCredentials" -Collection) | Select-Object -First 1
        }
        catch {
            Write-Warning "Could not read the service principal: $($_.Exception.Message)"
            $state.Gaps.Add('Service principal could not be read.')
        }
    }

    #--- Requested permissions (requiredResourceAccess)
    if ($state.Application) {
        Write-Progress -Id 2 -Activity $activity -Status 'Comparing requested permissions' -PercentComplete 35
        $requested = foreach ($resourceEntry in @($state.Application.requiredResourceAccess)) {
            if (-not $resourceEntry) { continue }
            $resource = $null
            try { $resource = Get-ReaderResourceServicePrincipal -Cache $state.Cache -ResourceAppId "$($resourceEntry.resourceAppId)" }
            catch { Write-Warning "Could not read resource $($resourceEntry.resourceAppId): $($_.Exception.Message)" }
            foreach ($access in @($resourceEntry.resourceAccess)) {
                if (-not $access) { continue }
                [pscustomobject]@{
                    ResourceAppId = "$($resourceEntry.resourceAppId)"
                    ResourceName  = if ($resource) { "$($resource.displayName)" } else { "$($resourceEntry.resourceAppId)" }
                    Id            = "$($access.id)"
                    Type          = "$($access.type)"
                    Permission    = Get-ReaderPermissionName -Resource $resource -PermissionId "$($access.id)" -Type $(if ($access.type -eq 'Scope') { 'Scope' } else { 'Role' })
                }
            }
        }
        $state.RequestedEntries = @($requested)
        $state.MissingRequested = @($state.Approved | Where-Object {
                $item = $_
                -not ($state.RequestedEntries | Where-Object { $_.Type -eq 'Role' -and $_.ResourceAppId -eq $item.ResourceAppId -and $item.AppRoleId -and $_.Id -eq $item.AppRoleId })
            })
        $state.ExtraRequested = @($state.RequestedEntries | Where-Object {
                $entry = $_
                -not ($entry.Type -eq 'Role' -and ($state.Approved | Where-Object { $_.ResourceAppId -eq $entry.ResourceAppId -and $_.AppRoleId -eq $entry.Id }))
            })
    }

    #--- Granted application permissions
    if ($state.ServicePrincipal) {
        Write-Progress -Id 2 -Activity $activity -Status 'Reading granted application permissions' -PercentComplete 50
        try {
            $assignments = @(Invoke-ReaderGraphGet -Uri "/v1.0/servicePrincipals/$($state.ServicePrincipal.id)/appRoleAssignments" -Collection)
            $granted = foreach ($assignment in $assignments) {
                $resource = $null
                try { $resource = Get-ReaderResourceServicePrincipal -Cache $state.Cache -ServicePrincipalId "$($assignment.resourceId)" }
                catch { Write-Warning "Could not read resource $($assignment.resourceId): $($_.Exception.Message)" }
                [pscustomobject]@{
                    AssignmentId               = "$($assignment.id)"
                    ResourceServicePrincipalId = "$($assignment.resourceId)"
                    ResourceAppId              = if ($resource) { "$($resource.appId)" } else { $null }
                    ResourceName               = "$($assignment.resourceDisplayName)"
                    AppRoleId                  = "$($assignment.appRoleId)"
                    Permission                 = Get-ReaderPermissionName -Resource $resource -PermissionId "$($assignment.appRoleId)" -Type Role
                }
            }
            $state.GrantedAssignments = @($granted)
            $state.MissingGrants = @($state.Approved | Where-Object {
                    $item = $_
                    -not ($state.GrantedAssignments | Where-Object { $item.AppRoleId -and $_.AppRoleId -eq $item.AppRoleId -and $_.ResourceServicePrincipalId -eq $item.ResourceServicePrincipalId })
                })
            $state.ExtraGrants = @($state.GrantedAssignments | Where-Object {
                    $grant = $_
                    -not ($state.Approved | Where-Object { $_.AppRoleId -and $_.AppRoleId -eq $grant.AppRoleId -and $_.ResourceServicePrincipalId -eq $grant.ResourceServicePrincipalId })
                })
        }
        catch {
            Write-Warning "Could not read granted application permissions: $($_.Exception.Message)"
            $state.Gaps.Add('Granted application permissions could not be read.')
            $state.MissingGrants = @($state.Approved)
        }

        #--- Directory roles
        Write-Progress -Id 2 -Activity $activity -Status 'Reading directory role assignments' -PercentComplete 65
        try {
            $roleAssignments = @(Invoke-ReaderGraphGet -Uri "/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($state.ServicePrincipal.id)'&`$expand=roleDefinition" -Collection)
            $approvedTemplateIds = @($script:ApprovedDirectoryRoles | ForEach-Object { $_.RoleTemplateId })
            $assignedApproved = [System.Collections.Generic.List[string]]::new()
            foreach ($roleAssignment in $roleAssignments) {
                $templateId = if ($roleAssignment.roleDefinition.templateId) { "$($roleAssignment.roleDefinition.templateId)" } else { "$($roleAssignment.roleDefinitionId)" }
                $roleName = if ($roleAssignment.roleDefinition.displayName) { "$($roleAssignment.roleDefinition.displayName)" } else { "role $templateId" }
                if ($templateId.ToLowerInvariant() -in $approvedTemplateIds -and $roleAssignment.directoryScopeId -eq '/') { $assignedApproved.Add($templateId.ToLowerInvariant()); continue }
                $scopeNote = if ($roleAssignment.directoryScopeId -ne '/') { " (scope $($roleAssignment.directoryScopeId))" } else { '' }
                $state.OtherDirectoryRoles += "$roleName$scopeNote"
            }
            $state.MissingDirectoryRoles = @($script:ApprovedDirectoryRoles | Where-Object { $_.RoleTemplateId -notin $assignedApproved })
            $state.GlobalReaderAssigned = $state.MissingDirectoryRoles.Count -eq 0
        }
        catch {
            Write-Warning "Could not read directory role assignments: $($_.Exception.Message)"
            $state.Gaps.Add('Directory role assignments could not be read.')
        }

        #--- Delegated permission grants
        Write-Progress -Id 2 -Activity $activity -Status 'Reading delegated permission grants' -PercentComplete 75
        try {
            $state.DelegatedGrantCount = @(Invoke-ReaderGraphGet -Uri "/v1.0/servicePrincipals/$($state.ServicePrincipal.id)/oauth2PermissionGrants" -Collection).Count
        }
        catch {
            Write-Warning "Could not read delegated permission grants (documented as needing Directory.Read.All): $($_.Exception.Message)"
            $state.Gaps.Add('Delegated permission grants could not be read.')
        }
    }
    elseif ($state.Application) {
        $state.MissingGrants = @($state.Approved)
    }

    #--- Owners
    if ($state.Application) {
        Write-Progress -Id 2 -Activity $activity -Status 'Reading owners' -PercentComplete 85
        try {
            $state.OwnerCount = @(Invoke-ReaderGraphGet -Uri "/v1.0/applications/$($state.Application.id)/owners?`$select=id" -Collection).Count
        }
        catch {
            Write-Warning "Could not read application owners: $($_.Exception.Message)"
            $state.Gaps.Add('Application owners could not be read.')
        }
    }

    #--- Credentials (never output key values or identifiers)
    # Certificates are counted on the application object only: that is where the app
    # authenticates from. Keys on the service principal are counted separately. Client
    # secrets count on both objects.
    Write-Progress -Id 2 -Activity $activity -Status 'Reading credentials' -PercentComplete 95
    $certificates = [System.Collections.Generic.List[object]]::new()
    if ($state.Application) {
        foreach ($key in @($state.Application.keyCredentials)) {
            if (-not $key) { continue }
            $end = ConvertTo-ReaderUtcDate -Value $key.endDateTime
            $certificates.Add([pscustomobject]@{
                    EndDateUtc    = if ($end) { $end.ToString('yyyy-MM-dd') } else { $null }
                    DaysRemaining = if ($end) { [int][math]::Floor(($end - $now).TotalDays) } else { $null }
                })
            if ($Certificate -and $key.customKeyIdentifier) {
                try {
                    if ([Convert]::ToHexString([Convert]::FromBase64String("$($key.customKeyIdentifier)")) -eq $Certificate.Thumbprint) { $state.CertificateAlreadyOnApp = $true }
                }
                catch { Write-Verbose 'A certificate identifier was not in the expected format; skipped for matching.' }
            }
        }
        $state.ClientSecretCount += @(@($state.Application.passwordCredentials) | Where-Object { $_ }).Count
    }
    if ($state.ServicePrincipal) {
        $state.ServicePrincipalKeyCount = @(@($state.ServicePrincipal.keyCredentials) | Where-Object { $_ }).Count
        $state.ClientSecretCount += @(@($state.ServicePrincipal.passwordCredentials) | Where-Object { $_ }).Count
    }
    $state.Certificates = $certificates.ToArray()
    Write-Progress -Id 2 -Activity $activity -Completed
    $state
}

function Get-ReaderPlannedChange {
    <#
    .SYNOPSIS
        Describes the changes -Apply would make for a given state and switches.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][hashtable]$State,
        [Parameter(Mandatory)][string]$Name,
        [Parameter()][bool]$AppIdGiven,
        [Parameter()][bool]$RemoveExtra,
        [Parameter()][AllowNull()][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $plan = [System.Collections.Generic.List[string]]::new()
    if (-not $State.Application) {
        if ($AppIdGiven) {
            $plan.Add('None possible: no application has the given AppId. Rerun without -AppId to create one by display name.')
            return $plan.ToArray()
        }
        $plan.Add("Create application '$Name' (single tenant, AzureADMyOrg) requesting the approved permissions.")
    }
    if (-not $State.ServicePrincipal) { $plan.Add('Create the service principal for the application.') }
    $removeNow = $RemoveExtra -and (Test-ReaderSafeToRemove -State $State)
    if ($State.Application) {
        $addable = @($State.MissingRequested | Where-Object { $_.AppRoleId })
        $needsUpdate = $addable.Count -gt 0 -or ($removeNow -and $State.ExtraRequested.Count -gt 0)
        if ($needsUpdate) {
            $description = if ($removeNow) { 'Set requested permissions (requiredResourceAccess) to exactly the approved set.' } else { "Add $($addable.Count) approved permission(s) to the requested permissions (requiredResourceAccess), keeping every existing entry." }
            $plan.Add($description)
        }
    }
    $grants = if ($State.ServicePrincipal) { $State.MissingGrants } else { $State.Approved }
    foreach ($item in $grants) {
        if ($item.AppRoleId -and $item.ResourceServicePrincipalId) { $plan.Add("Grant admin consent: $($item.ResourceName) application permission $($item.Permission).") }
    }
    foreach ($role in $State.MissingDirectoryRoles) { $plan.Add("Assign the Microsoft Entra role $($role.RoleName) to the service principal (tenant scope).") }
    if ($Certificate -and -not $State.CertificateAlreadyOnApp) {
        $where = if ($State.Application) { 'to the application' } else { 'in the application create request' }
        $plan.Add("Add certificate $($Certificate.Subject) (expires $($Certificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd'))) $where.")
    }
    if ($removeNow) {
        foreach ($grant in $State.ExtraGrants) { $plan.Add("Remove granted permission: $($grant.ResourceName) $($grant.Permission).") }
    }
    elseif ($RemoveExtra -and ($State.ExtraGrants.Count -or $State.ExtraRequested.Count)) {
        $plan.Add('Remove nothing: the approved set did not fully resolve or the audit has gaps (see AuditGaps).')
    }
    $plan.ToArray()
}

function ConvertTo-ReaderReport {
    <#
    .SYNOPSIS
        Builds the output object from the audit state.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][hashtable]$State,
        [Parameter(Mandatory)][pscustomobject]$Tenant,
        [Parameter(Mandatory)][string]$Mode,
        [Parameter()][bool]$RemoveExtra,
        [Parameter()][AllowNull()][string[]]$PlannedChanges = @(),
        [Parameter()][AllowNull()][object[]]$AppliedChanges = @()
    )
    $missing = [System.Collections.Generic.List[object]]::new()
    $missingItems = if ($State.ServicePrincipal -or $State.Application) { $State.MissingGrants } else { $State.Approved }
    foreach ($item in $missingItems) {
        $missing.Add([pscustomobject]@{
                Kind       = 'ApplicationPermission'
                Resource   = $item.ResourceName
                Permission = $item.Permission
                Areas      = $item.Areas -join ', '
                Requested  = -not ($State.MissingRequested | Where-Object { $_.Permission -eq $item.Permission -and $_.ResourceAppId -eq $item.ResourceAppId }) -and [bool]$State.Application
                Granted    = $false
            })
    }
    foreach ($role in $State.MissingDirectoryRoles) {
        $missing.Add([pscustomobject]@{ Kind = 'DirectoryRole'; Resource = 'Microsoft Entra ID'; Permission = $role.RoleName; Areas = $role.Areas -join ', '; Requested = $null; Granted = $false })
    }

    $extra = [System.Collections.Generic.List[object]]::new()
    foreach ($grant in $State.ExtraGrants) {
        $requestedToo = [bool]($State.ExtraRequested | Where-Object { $_.Type -eq 'Role' -and $_.Id -eq $grant.AppRoleId -and $_.ResourceAppId -eq $grant.ResourceAppId })
        $extra.Add([pscustomobject]@{ Kind = 'ApplicationPermission'; Resource = $grant.ResourceName; Permission = $grant.Permission; Risk = Get-ReaderPermissionRisk -Permission $grant.Permission; Granted = $true; Requested = $requestedToo })
    }
    foreach ($entry in $State.ExtraRequested) {
        $alreadyListed = $entry.Type -eq 'Role' -and ($State.ExtraGrants | Where-Object { $_.AppRoleId -eq $entry.Id -and $_.ResourceAppId -eq $entry.ResourceAppId })
        if ($alreadyListed) { continue }
        $kind = if ($entry.Type -eq 'Scope') { 'DelegatedPermission' } else { 'ApplicationPermission' }
        $extra.Add([pscustomobject]@{ Kind = $kind; Resource = $entry.ResourceName; Permission = $entry.Permission; Risk = Get-ReaderPermissionRisk -Permission $entry.Permission; Granted = $false; Requested = $true })
    }

    $validCertificates = @($State.Certificates | Where-Object { $null -ne $_.DaysRemaining -and $_.DaysRemaining -ge 0 })
    $signInAudience = if ($State.Application) { "$($State.Application.signInAudience)" } else { $null }
    $aligned = [bool]$State.Application -and $State.MissingRequested.Count -eq 0 -and $State.ExtraRequested.Count -eq 0

    $followUp = [System.Collections.Generic.List[string]]::new()
    if ($State.ClientSecretCount) { $followUp.Add("$($State.ClientSecretCount) client secret(s) present. Remove them in the Microsoft Entra admin center; this script never removes secrets.") }
    if ($State.OwnerCount) { $followUp.Add("$($State.OwnerCount) owner(s) can add credentials to the app. Review and remove owners who do not need it; this script never removes owners.") }
    if ($State.OtherDirectoryRoles.Count) { $followUp.Add("Directory roles beyond the approved set ($(@($script:ApprovedDirectoryRoles.RoleName) -join ', ')): $($State.OtherDirectoryRoles -join ', '). Remove them manually.") }
    if ($signInAudience -and $signInAudience -ne 'AzureADMyOrg') { $followUp.Add("Sign-in audience is $signInAudience. Change it to single tenant (AzureADMyOrg).") }
    if ($State.DelegatedGrantCount) { $followUp.Add("$($State.DelegatedGrantCount) delegated permission grant(s) exist. The reader app uses application permissions only; revoke them manually.") }
    $expiredCount = @($State.Certificates | Where-Object { $null -ne $_.DaysRemaining -and $_.DaysRemaining -lt 0 }).Count
    if ($expiredCount) { $followUp.Add("$expiredCount expired certificate(s). Remove them manually once a valid certificate is confirmed working.") }
    if ($State.Application -and -not $validCertificates.Count) { $followUp.Add('No valid certificate on the app. Supply -CertificatePath with -Apply to add one.') }
    $soon = @($validCertificates | Where-Object { $_.DaysRemaining -lt 60 })
    if ($soon.Count) { $followUp.Add("$($soon.Count) certificate(s) expire within 60 days. Add a new certificate, confirm a run works, then remove the old one.") }
    if ($State.ServicePrincipalKeyCount) { $followUp.Add("$($State.ServicePrincipalKeyCount) key credential(s) on the service principal. The reader app authenticates with application certificates; review and remove these manually.") }
    $safeToRemove = Test-ReaderSafeToRemove -State $State
    if (($State.ExtraGrants.Count -or $State.ExtraRequested.Count) -and -not $safeToRemove) {
        $followUp.Add('Extra permissions were not removed and requested permissions were not reduced: the approved set did not fully resolve or the audit has gaps. Fix the AuditGaps, then rerun.')
    }
    elseif ($State.ExtraGrants.Count -and -not $RemoveExtra) { $followUp.Add("$($State.ExtraGrants.Count) extra granted permission(s). Rerun with -Apply -RemoveExtraPermissions to remove them.") }
    foreach ($role in $script:ApprovedAzureRoles) {
        $followUp.Add("Azure (manual, not checked by this script): assign $($role.RoleName) at the $($role.Scope) to the service principal.")
    }

    $compliant = [bool]$State.Application -and [bool]$State.ServicePrincipal -and
    $missing.Count -eq 0 -and $extra.Count -eq 0 -and $State.GlobalReaderAssigned -and
    $State.OtherDirectoryRoles.Count -eq 0 -and $State.ClientSecretCount -eq 0 -and
    $signInAudience -eq 'AzureADMyOrg' -and $State.DelegatedGrantCount -eq 0 -and
    $validCertificates.Count -gt 0 -and $State.Gaps.Count -eq 0

    [pscustomobject][ordered]@{
        TenantDisplayName             = $Tenant.TenantDisplayName
        TenantId                      = $Tenant.TenantId
        Mode                          = $Mode
        AppFound                      = [bool]$State.Application
        AppId                         = if ($State.Application) { "$($State.Application.appId)" } elseif ($State.ServicePrincipal) { "$($State.ServicePrincipal.appId)" } else { $null }
        ServicePrincipalId            = if ($State.ServicePrincipal) { "$($State.ServicePrincipal.id)" } else { $null }
        Missing                       = $missing.ToArray()
        Extra                         = $extra.ToArray()
        RequiredResourceAccessAligned = $aligned
        GlobalReaderAssigned          = $State.GlobalReaderAssigned
        OtherDirectoryRoles           = @($State.OtherDirectoryRoles)
        CertificateCount              = @($State.Certificates).Count
        CertificateExpiry             = @($State.Certificates)
        ServicePrincipalKeyCount      = $State.ServicePrincipalKeyCount
        ClientSecretCount             = $State.ClientSecretCount
        OwnerCount                    = $State.OwnerCount
        SignInAudience                = $signInAudience
        DelegatedGrantCount           = $State.DelegatedGrantCount
        Compliant                     = $compliant
        PlannedChanges                = @($PlannedChanges | Where-Object { $_ })
        ManualFollowUp                = $followUp.ToArray()
        AuditGaps                     = $State.Gaps.ToArray()
        AppliedChanges                = @($AppliedChanges | Where-Object { $_ })
    }
}

#endregion

#region Main

$connectedHere = $false
$certificate = $null
$mode = if ($Apply) { 'Apply' } else { 'Report' }
$appIdGiven = $PSBoundParameters.ContainsKey('AppId')
$requestedAppId = if ($appIdGiven) { $AppId } else { $null }

if ($RemoveExtraPermissions -and -not $Apply) {
    Write-Warning '-RemoveExtraPermissions has effect only with -Apply. Extra permissions are reported, not removed.'
}

try {
    #--- Approved set, validated before anything connects
    Import-ReaderPermissionSet -Path $PermissionFile

    #--- Certificate file: public key only, content checked before it is loaded
    if ($CertificatePath) {
        $certificate = Import-ReaderPublicCertificate -Path $CertificatePath
    }

    #--- Sign in
    $scopes = if ($Apply) { $script:ReportScopes + $script:ApplyScopes } else { $script:ReportScopes }
    Write-Verbose "Connecting to Microsoft Graph for tenant $TenantId with scopes: $($scopes -join ', ')"
    Connect-MgGraph -TenantId $TenantId.ToString() -Scopes $scopes -ContextScope Process -NoWelcome -UseDeviceCode:$UseDeviceCode -ErrorAction Stop
    $connectedHere = $true
    $context = Get-MgContext
    $missingScopes = @($scopes | Where-Object { $_ -notin @($context.Scopes) })
    if ($missingScopes.Count) { Write-Warning "The token does not carry these scopes: $($missingScopes -join ', '). Some reads or changes may fail." }

    #--- Show and confirm the tenant before anything else
    $organization = @(Invoke-ReaderGraphGet -Uri '/v1.0/organization?$select=id,displayName' -Collection) | Select-Object -First 1
    if (-not $organization) { throw 'Could not read the organization. Nothing was done.' }
    $tenant = [pscustomobject][ordered]@{ TenantDisplayName = "$($organization.displayName)"; TenantId = "$($organization.id)" }
    $tenant | Format-List | Out-String | Write-Information -InformationAction Continue

    if ("$($context.TenantId)" -ne $TenantId.ToString() -or $tenant.TenantId -ne $TenantId.ToString()) {
        throw "Signed-in tenant ($($context.TenantId), organization $($tenant.TenantId)) does not match -TenantId $TenantId. Nothing was done."
    }
    if ($PSBoundParameters.ContainsKey('ConfirmedTenantId')) {
        if ($ConfirmedTenantId -ne $TenantId) {
            throw "ConfirmedTenantId does not match the signed-in tenant ($($tenant.TenantDisplayName)). Nothing was done."
        }
    }
    else {
        $answer = Read-Host "Type yes to $(if ($Apply) { 'audit and change' } else { 'audit' }) the reader app in this tenant"
        if ($answer -ne 'yes') { Write-Warning 'Not confirmed. Nothing was done.'; return }
    }

    #--- Audit
    Write-Verbose 'Auditing the reader app (GET requests only)'
    $state = Get-ReaderAppState -RequestedAppId $requestedAppId -Name $DisplayName -Certificate $certificate
    $plan = Get-ReaderPlannedChange -State $state -Name $DisplayName -AppIdGiven $appIdGiven -RemoveExtra ([bool]$RemoveExtraPermissions) -Certificate $certificate

    if (-not $Apply) {
        return (ConvertTo-ReaderReport -State $state -Tenant $tenant -Mode $mode -RemoveExtra ([bool]$RemoveExtraPermissions) -PlannedChanges $plan)
    }

    #--- Apply
    $applied = [System.Collections.Generic.List[object]]::new()
    $record = {
        param($Step, $Result, $Detail)
        $applied.Add([pscustomobject][ordered]@{ Step = $Step; Result = $Result; Detail = $Detail })
    }
    $target = "$($tenant.TenantDisplayName) ($($tenant.TenantId))"
    $application = $state.Application
    $servicePrincipal = $state.ServicePrincipal
    $createdNow = $false
    $certificateInCreate = $false
    $safeToRemove = Test-ReaderSafeToRemove -State $state
    $removeNow = [bool]$RemoveExtraPermissions -and $safeToRemove
    if ($RemoveExtraPermissions -and -not $safeToRemove) {
        Write-Warning 'The approved set did not fully resolve or the audit has gaps, so nothing will be removed and the requested permissions will only be added to. See AuditGaps.'
    }
    $totalSteps = 7
    $activity = 'Security Oak reader app changes'

    # Each step keeps its ShouldProcess call inside its own try, so a declined prompt or a
    # prompt that cannot be shown (non-interactive run without -Confirm:$false) is recorded
    # for that step and the remaining steps still run.

    # 1. Application
    Write-Progress -Id 3 -Activity $activity -Status 'Application' -PercentComplete 0
    if (-not $application) {
        if ($appIdGiven) {
            Write-Warning "No application has AppId $AppId. Not creating a new one; rerun without -AppId to create '$DisplayName'."
            & $record 'Create application' 'Skipped' 'AppId given but not found.'
        }
        else {
            try {
                $createNote = if ($certificate) { ", with certificate $($certificate.Subject)" } else { '' }
                if ($PSCmdlet.ShouldProcess($target, "Create single-tenant application '$DisplayName' requesting the approved permissions$createNote")) {
                    $body = @{
                        displayName            = $DisplayName
                        signInAudience         = 'AzureADMyOrg'
                        requiredResourceAccess = ConvertTo-ReaderRequiredResourceAccess -Approved $state.Approved
                    }
                    # A new application has no keys to preserve, so the certificate goes in the
                    # create request. A separate read and update right after creating would hit
                    # replication delay.
                    if ($certificate) {
                        $body.keyCredentials = @(@{
                                type          = 'AsymmetricX509Cert'
                                usage         = 'Verify'
                                key           = [Convert]::ToBase64String($certificate.RawData)
                                displayName   = $certificate.Subject
                                startDateTime = $certificate.NotBefore.ToUniversalTime().ToString('o')
                                endDateTime   = $certificate.NotAfter.ToUniversalTime().ToString('o')
                            })
                    }
                    $application = Invoke-ReaderGraphWrite -Method POST -Uri '/v1.0/applications' -Body $body
                    $createdNow = $true
                    $certificateInCreate = [bool]$certificate
                    & $record 'Create application' 'Done' "appId $($application.appId)$createNote"
                }
                else { & $record 'Create application' 'NotRun' 'WhatIf or declined.' }
            }
            catch {
                Write-Warning "Creating the application failed: $($_.Exception.Message)"
                & $record 'Create application' 'Failed' $_.Exception.Message
            }
        }
    }

    if ($application) {
        # 2. Service principal
        Write-Progress -Id 3 -Activity $activity -Status 'Service principal' -PercentComplete ([int](100 * 1 / $totalSteps))
        if (-not $servicePrincipal) {
            try {
                if ($PSCmdlet.ShouldProcess($target, "Create the service principal for appId $($application.appId)")) {
                    $servicePrincipal = Invoke-ReaderGraphWrite -Method POST -Uri '/v1.0/servicePrincipals' -Body @{ appId = "$($application.appId)" } -Attempts $(if ($createdNow) { 4 } else { 1 })
                    $createdNow = $true
                    & $record 'Create service principal' 'Done' "id $($servicePrincipal.id)"
                }
                else { & $record 'Create service principal' 'NotRun' 'WhatIf or declined.' }
            }
            catch {
                Write-Warning "Creating the service principal failed: $($_.Exception.Message)"
                & $record 'Create service principal' 'Failed' $_.Exception.Message
            }
        }

        # 3. Requested permissions (only for an application that existed before this run).
        #    Only when removal is safe and asked for does the list become exactly the
        #    approved set; otherwise every existing entry is kept and approved ones are added.
        Write-Progress -Id 3 -Activity $activity -Status 'Requested permissions' -PercentComplete ([int](100 * 2 / $totalSteps))
        if ($state.Application) {
            $addable = @($state.MissingRequested | Where-Object { $_.AppRoleId })
            $needsUpdate = $addable.Count -gt 0 -or ($removeNow -and $state.ExtraRequested.Count -gt 0)
            if ($needsUpdate) {
                $keep = if ($removeNow) { @() } else { @($state.RequestedEntries) }
                $description = if ($removeNow) { 'Set requested permissions to exactly the approved set' } else { "Add $($addable.Count) approved permission(s) to the requested permissions, keeping all $($keep.Count) existing entries" }
                try {
                    if ($PSCmdlet.ShouldProcess($target, $description)) {
                        $body = @{ requiredResourceAccess = ConvertTo-ReaderRequiredResourceAccess -Approved $state.Approved -KeepEntries $keep }
                        $null = Invoke-ReaderGraphWrite -Method PATCH -Uri "/v1.0/applications/$($application.id)" -Body $body
                        & $record 'Set requested permissions' 'Done' $description
                    }
                    else { & $record 'Set requested permissions' 'NotRun' 'WhatIf or declined.' }
                }
                catch {
                    Write-Warning "Setting requested permissions failed: $($_.Exception.Message)"
                    & $record 'Set requested permissions' 'Failed' $_.Exception.Message
                }
            }
        }

        if ($servicePrincipal) {
            # 4. Admin consent for missing application permissions
            Write-Progress -Id 3 -Activity $activity -Status 'Admin consent' -PercentComplete ([int](100 * 3 / $totalSteps))
            $toGrant = if ($state.ServicePrincipal) { $state.MissingGrants } else { $state.Approved }
            foreach ($item in $toGrant) {
                $step = "Grant $($item.ResourceName) $($item.Permission)"
                if (-not $item.AppRoleId -or -not $item.ResourceServicePrincipalId) {
                    Write-Warning "$step skipped: the permission or its resource could not be resolved in this tenant."
                    & $record $step 'Skipped' 'Not resolved in this tenant.'
                    continue
                }
                try {
                    if ($PSCmdlet.ShouldProcess($target, "Grant admin consent for $($item.ResourceName) application permission $($item.Permission)")) {
                        $body = @{ principalId = "$($servicePrincipal.id)"; resourceId = $item.ResourceServicePrincipalId; appRoleId = $item.AppRoleId }
                        $null = Invoke-ReaderGraphWrite -Method POST -Uri "/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments" -Body $body -Attempts $(if ($createdNow) { 4 } else { 1 })
                        & $record $step 'Done' 'Admin consent granted.'
                    }
                    else { & $record $step 'NotRun' 'WhatIf or declined.' }
                }
                catch {
                    Write-Warning "$step failed: $($_.Exception.Message)"
                    & $record $step 'Failed' $_.Exception.Message
                }
            }

            # 5. Approved directory roles (Global Reader)
            Write-Progress -Id 3 -Activity $activity -Status 'Directory roles' -PercentComplete ([int](100 * 4 / $totalSteps))
            foreach ($role in $state.MissingDirectoryRoles) {
                $step = "Assign $($role.RoleName)"
                try {
                    if ($PSCmdlet.ShouldProcess($target, "Assign the Microsoft Entra role $($role.RoleName) to the service principal at tenant scope")) {
                        $body = @{ principalId = "$($servicePrincipal.id)"; roleDefinitionId = $role.RoleTemplateId; directoryScopeId = '/' }
                        $null = Invoke-ReaderGraphWrite -Method POST -Uri '/v1.0/roleManagement/directory/roleAssignments' -Body $body -Attempts $(if ($createdNow) { 4 } else { 1 })
                        & $record $step 'Done' 'Tenant scope.'
                    }
                    else { & $record $step 'NotRun' 'WhatIf or declined.' }
                }
                catch {
                    Write-Warning "$step failed: $($_.Exception.Message)"
                    & $record $step 'Failed' $_.Exception.Message
                }
            }
        }
        else {
            Write-Warning 'No service principal, so admin consent and directory roles were not applied.'
            & $record 'Admin consent and directory roles' 'Skipped' 'No service principal.'
        }

        # 6. Certificate on an application that existed before this run (public key only).
        #    PATCH replaces the whole keyCredentials collection, so the existing public keys
        #    are read back and included; if any cannot be read the step stops rather than
        #    remove a certificate. A new application got its certificate in step 1.
        Write-Progress -Id 3 -Activity $activity -Status 'Certificate' -PercentComplete ([int](100 * 5 / $totalSteps))
        if ($certificate -and -not $state.CertificateAlreadyOnApp -and -not $certificateInCreate -and $state.Application) {
            $step = "Add certificate $($certificate.Subject)"
            try {
                if ($PSCmdlet.ShouldProcess($target, "$step (expires $($certificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-dd'))) to the application")) {
                    $current = Invoke-ReaderGraphGet -Uri "/v1.0/applications/$($application.id)?`$select=keyCredentials"
                    $newKey = [Convert]::ToBase64String($certificate.RawData)
                    $keys = [System.Collections.Generic.List[object]]::new()
                    foreach ($existing in @($current.keyCredentials)) {
                        if (-not $existing) { continue }
                        if (-not $existing.key) { throw 'An existing certificate''s public key could not be read back, so updating keyCredentials would remove it. Add the certificate in the Microsoft Entra admin center instead.' }
                        if ("$($existing.key)" -eq $newKey) { throw 'The certificate is already on the application.' }
                        $entry = @{ type = "$($existing.type)"; usage = "$($existing.usage)"; key = "$($existing.key)" }
                        if ($existing.keyId) { $entry.keyId = "$($existing.keyId)" }
                        if ($existing.displayName) { $entry.displayName = "$($existing.displayName)" }
                        if ($existing.customKeyIdentifier) { $entry.customKeyIdentifier = "$($existing.customKeyIdentifier)" }
                        $start = ConvertTo-ReaderUtcDate -Value $existing.startDateTime
                        $end = ConvertTo-ReaderUtcDate -Value $existing.endDateTime
                        if ($start) { $entry.startDateTime = $start.ToString('o') }
                        if ($end) { $entry.endDateTime = $end.ToString('o') }
                        $keys.Add($entry)
                    }
                    $expectedCount = $keys.Count + 1
                    $keys.Add(@{
                            type          = 'AsymmetricX509Cert'
                            usage         = 'Verify'
                            key           = $newKey
                            displayName   = $certificate.Subject
                            startDateTime = $certificate.NotBefore.ToUniversalTime().ToString('o')
                            endDateTime   = $certificate.NotAfter.ToUniversalTime().ToString('o')
                        })
                    $null = Invoke-ReaderGraphWrite -Method PATCH -Uri "/v1.0/applications/$($application.id)" -Body @{ keyCredentials = $keys.ToArray() }
                    $after = @((Invoke-ReaderGraphGet -Uri "/v1.0/applications/$($application.id)?`$select=keyCredentials").keyCredentials | Where-Object { $_ }).Count
                    if ($after -ne $expectedCount) { Write-Warning "Expected $expectedCount certificates on the application after the update, found $after. Check the app in the Microsoft Entra admin center." }
                    & $record $step 'Done' "Certificates on the application: $after."
                }
                else { & $record $step 'NotRun' 'WhatIf or declined.' }
            }
            catch {
                Write-Warning "$step failed: $($_.Exception.Message)"
                & $record $step 'Failed' $_.Exception.Message
            }
        }

        # 7. Extra granted permissions, only with -RemoveExtraPermissions and only when the
        #    approved set fully resolved and the audit has no gaps.
        Write-Progress -Id 3 -Activity $activity -Status 'Extra permissions' -PercentComplete ([int](100 * 6 / $totalSteps))
        if ($RemoveExtraPermissions -and -not $safeToRemove -and ($state.ExtraGrants.Count -or $state.ExtraRequested.Count)) {
            & $record 'Remove extra permissions' 'Skipped' 'Approved set not fully resolved or audit gaps present; nothing removed.'
        }
        elseif ($removeNow -and $servicePrincipal) {
            foreach ($grant in $state.ExtraGrants) {
                $step = "Remove $($grant.ResourceName) $($grant.Permission)"
                try {
                    if ($PSCmdlet.ShouldProcess($target, "Remove granted permission $($grant.ResourceName) $($grant.Permission) from the service principal")) {
                        $null = Invoke-ReaderGraphWrite -Method DELETE -Uri "/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments/$($grant.AssignmentId)"
                        & $record $step 'Done' 'Assignment removed.'
                    }
                    else { & $record $step 'NotRun' 'WhatIf or declined.' }
                }
                catch {
                    Write-Warning "$step failed: $($_.Exception.Message)"
                    & $record $step 'Failed' $_.Exception.Message
                }
            }
        }
    }
    Write-Progress -Id 3 -Activity $activity -Completed

    #--- Audit again and return the fresh result
    Write-Verbose 'Auditing the reader app again after the changes'
    $auditAppId = if ($application) { [guid]"$($application.appId)" } else { $requestedAppId }
    $fresh = Get-ReaderAppState -RequestedAppId $auditAppId -Name $DisplayName -Certificate $certificate
    $freshPlan = Get-ReaderPlannedChange -State $fresh -Name $DisplayName -AppIdGiven $appIdGiven -RemoveExtra ([bool]$RemoveExtraPermissions) -Certificate $certificate
    ConvertTo-ReaderReport -State $fresh -Tenant $tenant -Mode $mode -RemoveExtra ([bool]$RemoveExtraPermissions) -PlannedChanges $freshPlan -AppliedChanges $applied.ToArray()
}
finally {
    if ($certificate) { $certificate.Dispose() }
    if ($connectedHere) {
        try { $null = Disconnect-MgGraph -ErrorAction Stop }
        catch { Write-Warning "Disconnect-MgGraph failed: $($_.Exception.Message)" }
    }
}

#endregion
