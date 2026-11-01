function Get-SecOakAzureProperty {
    <#
    .SYNOPSIS
        Reads a dotted property path from an Azure Resource Manager object, or $null.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][object]$InputObject,
        [Parameter(Mandatory)][string]$Path
    )
    $current = $InputObject
    foreach ($segment in $Path.Split('.')) {
        if ($null -eq $current) { return $null }
        if ($current -is [System.Collections.IDictionary]) { $current = $current[$segment]; continue }
        $property = $current.PSObject.Properties[$segment]
        if (-not $property) { return $null }
        $current = $property.Value
    }
    $current
}

function Get-SecOakAzureResourceGroup {
    <#
    .SYNOPSIS
        Returns the resource group name from an Azure resource ID, or an empty string.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$ResourceId)
    if ($ResourceId -match '(?i)/resourceGroups/([^/]+)') { return $Matches[1] }
    ''
}

function Test-SecOakAzurePortInRange {
    <#
    .SYNOPSIS
        Tests whether a TCP port falls inside a network security group port range list.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][int]$Port,
        [Parameter()][AllowNull()][AllowEmptyCollection()][string[]]$Ranges
    )
    foreach ($range in @($Ranges | Where-Object { $_ })) {
        $text = "$range".Trim()
        if ($text -eq '*') { return $true }
        if ($text -match '^(\d+)-(\d+)$') { if ($Port -ge [int]$Matches[1] -and $Port -le [int]$Matches[2]) { return $true }; continue }
        if ($text -match '^\d+$' -and [int]$text -eq $Port) { return $true }
    }
    $false
}

function Get-SecOakAzureNsgExposure {
    <#
    .SYNOPSIS
        Statically evaluates one network security group for internet-open management ports.
    .DESCRIPTION
        Merges custom and default rules and applies Azure precedence (lowest priority number
        wins). A port counts as exposed when the winning inbound rule for an any-source
        request on that port is an Allow. Rules whose source is an application security group
        are returned separately as indeterminate. This replaces the Network Watcher effective
        rules action, which is a POST and therefore not used.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][object]$Nsg)

    # String keys on purpose: an integer index on an ordered dictionary is positional, not a key lookup.
    $sensitivePorts = [ordered]@{ '3389' = @('RDP', 'Critical'); '22' = @('SSH', 'Critical'); '445' = @('SMB', 'Critical'); '1433' = @('SQL Server', 'High'); '3306' = @('MySQL', 'High'); '5985' = @('WinRM', 'High'); '5986' = @('WinRM over HTTPS', 'High') }
    $anySources = @('*', '0.0.0.0/0', 'internet', 'any')
    $rules = @(@(Get-SecOakAzureProperty $Nsg 'properties.securityRules') + @(Get-SecOakAzureProperty $Nsg 'properties.defaultSecurityRules')) | Where-Object { $_ }
    $inbound = @($rules | Where-Object { (Get-SecOakAzureProperty $_ 'properties.direction') -eq 'Inbound' } | Sort-Object { [int](Get-SecOakAzureProperty $_ 'properties.priority') })
    $exposed = [System.Collections.Generic.List[object]]::new()
    $indeterminate = [System.Collections.Generic.List[object]]::new()
    foreach ($portKey in @($sensitivePorts.Keys)) {
        $port = [int]$portKey
        foreach ($rule in $inbound) {
            $p = $rule.properties
            $protocol = "$($p.protocol)".ToLowerInvariant()
            if ($protocol -notin '*', 'tcp') { continue }
            $ports = @(@($p.destinationPortRange) + @($p.destinationPortRanges) | Where-Object { $_ })
            if (-not (Test-SecOakAzurePortInRange -Port $port -Ranges $ports)) { continue }
            $sources = @(@($p.sourceAddressPrefix) + @($p.sourceAddressPrefixes) | Where-Object { $_ } | ForEach-Object { "$_".ToLowerInvariant() })
            $asgSources = @(Get-SecOakAzureProperty $p 'sourceApplicationSecurityGroups' | Where-Object { $_ })
            if ($asgSources.Count -and $p.access -eq 'Allow') {
                $indeterminate.Add([pscustomobject]@{ Rule = $rule.name; Port = $port; Service = $sensitivePorts[$portKey][0] })
                continue
            }
            $matchesAny = [bool]($sources | Where-Object { $_ -in $anySources })
            if (-not $matchesAny) { continue }
            # First any-source rule that covers this port decides the outcome.
            if ($p.access -eq 'Allow') {
                $exposed.Add([pscustomobject]@{ Rule = $rule.name; Priority = $p.priority; Port = $port; Service = $sensitivePorts[$portKey][0]; Severity = $sensitivePorts[$portKey][1] })
            }
            break
        }
    }
    [pscustomobject]@{ Exposed = $exposed.ToArray(); Indeterminate = $indeterminate.ToArray() }
}

function Invoke-SecOakAzureCheck {
    <#
    .SYNOPSIS
        Azure area: subscription privileged access, Defender for Cloud, policy compliance, logging,
        locks, network exposure, virtual machines, backup, and data service configuration.
    .DESCRIPTION
        Runs AZURE-01 to AZURE-30 from the Azure catalogue with Azure Resource Manager GET calls
        only, plus one approved read-only POST (Azure Policy compliance summary). Every check runs
        against each enabled subscription the app can see. When the subscription list is empty or
        forbidden, one gap is recorded and the rest of the area is skipped.
        AZURE-06 (classic administrators), AZURE-11 (legacy agent auto-provisioning), and AZURE-30
        (Microsoft 365 Backup) have no Azure Resource Manager endpoint and are documented as not
        applicable rather than checked.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakAzureCheck -Context $context
    .NOTES
        Azure role-based access control: Reader and Security Reader on the tenant root management
        group. Microsoft Graph application permission Directory.Read.All is used only to tell guest
        users from members among Owner holders and to identify the app's own service principal.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Azure'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $api = 'AzureResourceManager'
    $readerGapFill = 'Assign the Azure roles Reader and Security Reader to the Security Oak app at the tenant root management group (portal: Management groups > Tenant Root Group > Access control).'
    $builtInRoles = @{
        '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' = 'Owner'
        'b24988ac-6180-42a0-ab88-20f7382dd24c' = 'Contributor'
        '18d7d88d-d35e-4fb5-a5c3-7773c20a72d9' = 'User Access Administrator'
        'acdd72a7-3385-48ef-bd42-f606fba81ae7' = 'Reader'
        '39bc4728-0917-49c7-9d2c-d95423bc2eb4' = 'Security Reader'
    }
    $privilegedRoles = @('Owner', 'User Access Administrator')
    $perItemCap = 25
    $summary.mappedTo = [ordered]@{
        'AZURE-15' = 'Public IP inventory is reported under inventory.publicIps and feeds AZURE-16 and AZURE-18; it produces no finding of its own.'
    }
    $summary.notApplicable = [ordered]@{
        'AZURE-06' = 'Classic administrators were retired in 2025; any holdover appears as an Owner assignment in AZURE-04.'
        'AZURE-11' = 'Log Analytics agent auto-provisioning was retired in November 2024; coverage comes from AZURE-09 assessments.'
        'AZURE-30' = 'Microsoft 365 Backup has no Azure Resource Manager resource; it is a Microsoft Graph and admin center feature.'
    }

    # ----- AZURE-01: subscriptions (gate for the whole area) -----
    $check = 'Azure/Subscriptions'
    $subscriptionsResult = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check $check -Path '/subscriptions?api-version=2022-12-01' -RawName 'azure-subscriptions' -NoGap
    $allSubscriptions = if ($subscriptionsResult.Success) { @($subscriptionsResult.Items) } else { @() }
    $subscriptions = @($allSubscriptions | Where-Object { $_.state -eq 'Enabled' })
    $summary.subscriptions = [ordered]@{
        visible  = $allSubscriptions.Count
        enabled  = $subscriptions.Count
        disabled = @($allSubscriptions | Where-Object { $_.state -ne 'Enabled' }).Count
        names    = @($subscriptions | ForEach-Object { $_.displayName })
    }
    $accessProblem = $null
    if (-not $subscriptionsResult.Success) {
        $accessProblem = if ($subscriptionsResult.StatusCode -in 401, 403) { 'forbidden' } else { 'error' }
    }
    elseif ($allSubscriptions.Count -eq 0) {
        # Zero subscriptions also happens when the Reader role was never assigned: the list is filtered by access.
        $probe = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check 'Azure/ManagementGroups' -Path '/providers/Microsoft.Management/managementGroups?api-version=2020-05-01' -NoGap
        if ($probe.Success) { $Context.Cache.AzureManagementGroups = @($probe.Items) } else { $accessProblem = 'empty' }
    }
    if ($accessProblem) {
        $reason = switch ($accessProblem) {
            'forbidden' { "Subscription list returned $($subscriptionsResult.StatusCode). The app holds no Azure role, so no Azure check can run." }
            'empty' { 'Subscription list is empty and the management group list is not readable. Either the tenant has no Azure subscriptions or the app has no Azure role.' }
            default { "Subscription list failed: $($subscriptionsResult.ErrorCode): $($subscriptionsResult.ErrorMessage)" }
        }
        Add-SecOakGap -Context $Context -Area $area -Check $check -EndpointOrCmdlet '/subscriptions?api-version=2022-12-01' `
            -Result $(if ($accessProblem -eq 'empty') { 'empty' } else { "$($subscriptionsResult.StatusCode)" }) `
            -Reason "Azure Reader not assigned at root management group. $reason AZURE-01 to AZURE-30 skipped." -FillWith $readerGapFill
        $summary.skipped = 'All Azure checks skipped: Azure Reader not assigned at root management group (or no subscriptions exist).'
        $Context.AreaSummaries[$area] = $summary
        return [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
    }
    if ($allSubscriptions.Count -eq 0) {
        # Management groups are readable, so the role is in place: the tenant simply has no subscriptions.
        $summary.skipped = 'No Azure subscriptions found; subscription-scoped checks (AZURE-04 to AZURE-29) skipped. Root management group checks still ran.'
        Add-SecOakGap -Context $Context -Area $area -Check $check -EndpointOrCmdlet '/subscriptions?api-version=2022-12-01' -Result 'empty' `
            -Reason 'No Azure subscriptions found; subscription-scoped checks (AZURE-04 to AZURE-29) skipped. AZURE-02 and AZURE-03 still ran at the root management group.' `
            -FillWith 'Confirm in the Azure portal that the tenant has no subscriptions. If it does, the app is missing Reader on them.'
    }

    # ----- AZURE-02: management groups and the tenant root group -----
    $check = 'Azure/ManagementGroups'
    $managementGroups = $null
    if ($Context.Cache.ContainsKey('AzureManagementGroups')) { $managementGroups = @($Context.Cache.AzureManagementGroups) }
    else {
        $mgResult = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check $check -Path '/providers/Microsoft.Management/managementGroups?api-version=2020-05-01' -RawName 'azure-management-groups'
        if ($mgResult.Success) { $managementGroups = @($mgResult.Items) }
    }
    $rootGroupId = $null
    if ($null -ne $managementGroups) {
        $root = $managementGroups | Where-Object { "$($_.name)" -eq "$($Context.TenantId)" } | Select-Object -First 1
        if (-not $root) { $root = $managementGroups | Where-Object { (Get-SecOakAzureProperty $_ 'properties.displayName') -eq 'Tenant Root Group' } | Select-Object -First 1 }
        if (-not $root -and $managementGroups.Count) { $root = $managementGroups[0] }
        if ($root) { $rootGroupId = "$($root.name)" }
        $summary.managementGroups = [ordered]@{ total = $managementGroups.Count; rootGroupFound = [bool]$rootGroupId; names = @($managementGroups | ForEach-Object { Get-SecOakAzureProperty $_ 'properties.displayName' }) }
    }

    # ----- AZURE-05: role definitions (reference data, custom role inventory) -----
    $check = 'Azure/RoleDefinitions'
    $roleNames = @{} + $builtInRoles
    $customRoles = [System.Collections.Generic.List[object]]::new()
    $definitionScope = if ($rootGroupId) { "/providers/Microsoft.Management/managementGroups/$rootGroupId" } elseif ($subscriptions.Count) { "/subscriptions/$($subscriptions[0].subscriptionId)" } else { $null }
    if ($definitionScope) {
        $definitions = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check $check -Path "$definitionScope/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
        if ($definitions.Success) {
            foreach ($definition in @($definitions.Items)) {
                $roleNames["$($definition.name)".ToLowerInvariant()] = Get-SecOakAzureProperty $definition 'properties.roleName'
                if ((Get-SecOakAzureProperty $definition 'properties.type') -eq 'CustomRole') { $customRoles.Add($definition) }
            }
        }
    }
    $resolveRole = {
        param($roleDefinitionId)
        $guid = ("$roleDefinitionId" -split '/')[-1].ToLowerInvariant()
        if ($roleNames.ContainsKey($guid)) { $roleNames[$guid] } else { "unknown role $guid" }
    }

    # Identity helpers: guests among privileged holders, and the app's own service principal (excluded).
    $ownServicePrincipalId = $null
    $sp = Get-SecOakOwnServicePrincipal -Context $Context -Check 'Azure/RoleAssignments'
    if ($sp) { $ownServicePrincipalId = "$($sp.id)".ToLowerInvariant() }
    $usersById = if ($Context.Cache.ContainsKey('UsersById')) { $Context.Cache.UsersById } else { $null }

    $classifyAssignments = {
        param($items, $scopeLabel)
        $rows = foreach ($assignment in @($items | Where-Object { $_ })) {
            $p = $assignment.properties
            $principalId = "$($p.principalId)".ToLowerInvariant()
            if ($ownServicePrincipalId -and $principalId -eq $ownServicePrincipalId) { continue }
            $role = & $resolveRole $p.roleDefinitionId
            $user = if ($usersById -and $usersById.ContainsKey($p.principalId)) { $usersById[$p.principalId] } else { $null }
            [pscustomobject]@{
                Scope         = $scopeLabel
                Role          = $role
                PrincipalType = "$($p.principalType)"
                PrincipalId   = $principalId
                DisplayName   = if ($user) { $user.displayName } else { "$($p.principalType) $($principalId.Substring(0, [math]::Min(8, $principalId.Length)))..." }
                IsGuest       = [bool]($user -and $user.userType -eq 'Guest')
                UserKnown     = [bool]$user
            }
        }
        , @($rows)
    }

    # ----- AZURE-03: role assignments at the tenant root management group -----
    $rootRows = @()
    if ($rootGroupId) {
        $check = 'Azure/RootRoleAssignments'
        $rootResult = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check $check -RawName 'azure-root-role-assignments' `
            -Path "/providers/Microsoft.Management/managementGroups/$rootGroupId/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=atScope()"
        if ($rootResult.Success) {
            $rootRows = & $classifyAssignments $rootResult.Items 'Tenant Root Group'
            $rootPrivileged = @($rootRows | Where-Object Role -in $privilegedRoles)
            $rootOwners = @($rootRows | Where-Object Role -eq 'Owner')
            $summary.rootRoleAssignments = [ordered]@{
                total    = $rootRows.Count
                owners   = $rootOwners.Count
                byRole   = @($rootRows | Group-Object Role | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
                guestPrivileged = @($rootPrivileged | Where-Object IsGuest).Count
                servicePrincipalPrivileged = @($rootPrivileged | Where-Object PrincipalType -eq 'ServicePrincipal').Count
            }
            $guestRoot = @($rootPrivileged | Where-Object IsGuest)
            $spRoot = @($rootPrivileged | Where-Object PrincipalType -eq 'ServicePrincipal')
            if ($guestRoot.Count -or $spRoot.Count -or $rootOwners.Count -gt 2) {
                $severity = if ($guestRoot.Count) { 'Critical' } elseif ($spRoot.Count) { 'High' } else { 'Medium' }
                $findings.Add((New-SecOakFinding -Id 'AZURE-03' -Area $area -Severity $severity -BaselineControl 'Separate admin accounts' `
                            -Title 'Broad privileged access at the tenant root management group' `
                            -Evidence ([ordered]@{ owners = $rootOwners.Count; guestsWithOwnerOrUserAccessAdministrator = $guestRoot.Count; servicePrincipalsWithOwnerOrUserAccessAdministrator = $spRoot.Count; examples = (Select-SecOakExample @($rootPrivileged | ForEach-Object { '{0} ({1}, {2})' -f $_.DisplayName, $_.PrincipalType, $_.Role })) }) `
                            -Risk 'Owner or User Access Administrator at the root management group controls every Azure subscription the company will ever create. A guest account or an application holding it can be compromised outside the company''s own security controls, and too many Owners means one stolen password can delete everything.' `
                            -Recommendation 'Keep root-level Owner to at most two dedicated admin accounts protected by multifactor authentication, remove guests and applications from Owner and User Access Administrator, and grant day-to-day access at subscription or resource group level instead.'))
            }
        }
    }
    elseif ($null -ne $managementGroups) {
        Add-SecOakGap -Context $Context -Area $area -Check 'Azure/RootRoleAssignments' -EndpointOrCmdlet '/providers/Microsoft.Management/managementGroups' -Result 'not found' `
            -Reason 'No tenant root management group could be identified from the management group list.' -FillWith $readerGapFill
    }

    # ----- Per-subscription collection -----
    $hits = @{}
    foreach ($id in 'AZURE-04', 'AZURE-05', 'AZURE-07', 'AZURE-08', 'AZURE-09', 'AZURE-10', 'AZURE-12', 'AZURE-13', 'AZURE-14', 'AZURE-16', 'AZURE-17', 'AZURE-18', 'AZURE-19', 'AZURE-20', 'AZURE-21', 'AZURE-22', 'AZURE-23', 'AZURE-24', 'AZURE-25', 'AZURE-26', 'AZURE-27', 'AZURE-28', 'AZURE-29') {
        $hits[$id] = [System.Collections.Generic.List[object]]::new()
    }
    $inventory = [ordered]@{ virtualMachines = 0; publicIps = 0; networkSecurityGroups = 0; storageAccounts = 0; keyVaults = 0; sqlServers = 0; webApps = 0; recoveryVaults = 0; gateways = 0; domainServices = 0; locks = 0 }
    $secureScores = [System.Collections.Generic.List[object]]::new()
    $assessmentTotals = [ordered]@{ high = 0; medium = 0; low = 0 }
    $policyTotals = [ordered]@{ nonCompliantResources = 0; nonCompliantPolicies = 0; evaluatedResources = 0 }
    $capped = [System.Collections.Generic.List[string]]::new()

    # AZURE-09 reference data: assessment severity lives in the tenant-level metadata, one call per run.
    # https://learn.microsoft.com/rest/api/defenderforcloud/assessments-metadata/list
    $assessmentSeverity = @{}
    if ($subscriptions.Count) {
        $metadata = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check 'Azure/Assessments' -Path '/providers/Microsoft.Security/assessmentMetadata?api-version=2020-01-01' -NoGap
        if ($metadata.Success) {
            foreach ($entry in @($metadata.Items)) { $assessmentSeverity["$($entry.name)"] = "$(Get-SecOakAzureProperty $entry 'properties.severity')" }
        }
    }

    $index = 0
    foreach ($subscription in $subscriptions) {
        $index++
        $subId = "$($subscription.subscriptionId)"
        $subName = "$($subscription.displayName)"
        $base = "/subscriptions/$subId"
        $raw = "azure-$index"
        $list = {
            param($checkName, $path, $rawName)
            $r = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check $checkName -Path $path -RawName $rawName
            if ($r.Success) { , @($r.Items) } else { $null }
        }

        # AZURE-04: subscription-scope role assignments
        $subAssignments = & $list 'Azure/SubscriptionRoleAssignments' "$base/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&`$filter=atScope()" "$raw-role-assignments"
        if ($null -ne $subAssignments) {
            $rows = & $classifyAssignments $subAssignments $subName
            $privileged = @($rows | Where-Object Role -in $privilegedRoles)
            $owners = @($rows | Where-Object Role -eq 'Owner')
            foreach ($row in @($privileged | Where-Object { $_.IsGuest -or $_.PrincipalType -eq 'ServicePrincipal' })) {
                $hits['AZURE-04'].Add([pscustomobject]@{ Subscription = $subName; Severity = $(if ($row.IsGuest) { 'Critical' } else { 'High' }); Text = ('{0}: {1} ({2}{3}, {4})' -f $subName, $row.DisplayName, $row.PrincipalType, $(if ($row.IsGuest) { ', guest' } else { '' }), $row.Role) })
            }
            if ($owners.Count -gt 2) {
                $hits['AZURE-04'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}: {1} Owners' -f $subName, $owners.Count) })
            }
        }

        # AZURE-05: custom roles defined at this subscription
        $subCustom = & $list 'Azure/RoleDefinitions' "$base/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01&`$filter=type%20eq%20'CustomRole'" $null
        if ($null -ne $subCustom) { foreach ($d in $subCustom) { if ("$($d.name)" -notin @($customRoles | ForEach-Object { "$($_.name)" })) { $customRoles.Add($d) } } }

        # Resource inventories used by several checks.
        $vms = & $list 'Azure/VirtualMachines' "$base/providers/Microsoft.Compute/virtualMachines?api-version=2026-04-01" "$raw-virtual-machines"
        # AZURE-15: public IP inventory (informational). Counted in the summary and joined to AZURE-16 and AZURE-18; no finding of its own.
        $publicIps = & $list 'Azure/PublicIpAddresses' "$base/providers/Microsoft.Network/publicIPAddresses?api-version=2025-09-01" "$raw-public-ips"
        $nsgs = & $list 'Azure/NetworkSecurityGroups' "$base/providers/Microsoft.Network/networkSecurityGroups?api-version=2025-09-01" "$raw-network-security-groups"
        $nics = & $list 'Azure/NetworkInterfaces' "$base/providers/Microsoft.Network/networkInterfaces?api-version=2025-09-01" "$raw-network-interfaces"
        $storage = & $list 'Azure/StorageAccounts' "$base/providers/Microsoft.Storage/storageAccounts?api-version=2026-06-01" "$raw-storage-accounts"
        $keyVaults = & $list 'Azure/KeyVaults' "$base/providers/Microsoft.KeyVault/vaults?api-version=2024-11-01" "$raw-key-vaults"
        $sqlServers = & $list 'Azure/SqlServers' "$base/providers/Microsoft.Sql/servers?api-version=2025-01-01" "$raw-sql-servers"
        $sites = & $list 'Azure/WebApps' "$base/providers/Microsoft.Web/sites?api-version=2026-07-15" "$raw-web-apps"
        $vaults = & $list 'Azure/RecoveryServicesVaults' "$base/providers/Microsoft.RecoveryServices/vaults?api-version=2026-07-01" "$raw-recovery-vaults"
        $domainServices = & $list 'Azure/DomainServices' "$base/providers/Microsoft.AAD/domainServices?api-version=2025-06-01" "$raw-domain-services"
        $locks = & $list 'Azure/ResourceLocks' "$base/providers/Microsoft.Authorization/locks?api-version=2016-09-01" "$raw-locks"
        foreach ($pair in @(@('virtualMachines', $vms), @('publicIps', $publicIps), @('networkSecurityGroups', $nsgs), @('storageAccounts', $storage), @('keyVaults', $keyVaults), @('sqlServers', $sqlServers), @('webApps', $sites), @('recoveryVaults', $vaults), @('domainServices', $domainServices), @('locks', $locks))) {
            if ($null -ne $pair[1]) { $inventory[$pair[0]] += @($pair[1]).Count }
        }

        # AZURE-07: Defender for Cloud plans
        $pricings = & $list 'Azure/DefenderPlans' "$base/providers/Microsoft.Security/pricings?api-version=2024-01-01" "$raw-defender-plans"
        if ($null -ne $pricings) {
            $planNeeds = @(
                @{ Plan = 'VirtualMachines'; Count = @($vms).Count; Label = 'virtual machines' }
                @{ Plan = 'SqlServers'; Count = @($sqlServers).Count; Label = 'SQL servers' }
                @{ Plan = 'StorageAccounts'; Count = @($storage).Count; Label = 'storage accounts' }
                @{ Plan = 'AppServices'; Count = @($sites).Count; Label = 'App Service apps' }
            )
            foreach ($need in $planNeeds) {
                $plan = $pricings | Where-Object { "$($_.name)" -eq $need.Plan } | Select-Object -First 1
                $tier = if ($plan) { Get-SecOakAzureProperty $plan 'properties.pricingTier' } else { 'Free' }
                if ($tier -ne 'Standard' -and $need.Count -gt 0) {
                    $hits['AZURE-07'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'High'; Text = ('{0}: Defender for {1} is off ({2} {3})' -f $subName, $need.Plan, $need.Count, $need.Label) })
                }
            }
            $posture = $pricings | Where-Object { "$($_.name)" -eq 'CloudPosture' } | Select-Object -First 1
            if (-not $posture -or (Get-SecOakAzureProperty $posture 'properties.pricingTier') -ne 'Standard') {
                $hits['AZURE-07'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}: Defender Cloud Security Posture Management is off' -f $subName) })
            }
        }

        # AZURE-08: secure score
        $scores = & $list 'Azure/SecureScore' "$base/providers/Microsoft.Security/secureScores?api-version=2020-01-01" "$raw-secure-score"
        if ($null -ne $scores) {
            $asc = $scores | Where-Object { "$($_.name)" -eq 'ascScore' } | Select-Object -First 1
            if ($asc) {
                $percentage = [double](Get-SecOakAzureProperty $asc 'properties.score.percentage')
                $percent = [math]::Round(100 * $percentage, 1)
                $secureScores.Add([pscustomobject]@{ Subscription = $subName; Percent = $percent; Current = (Get-SecOakAzureProperty $asc 'properties.score.current'); Max = (Get-SecOakAzureProperty $asc 'properties.score.max') })
                if ($percentage -lt 0.75) {
                    $hits['AZURE-08'].Add([pscustomobject]@{ Subscription = $subName; Severity = $(if ($percentage -lt 0.5) { 'Medium' } else { 'Low' }); Text = ('{0}: {1} percent' -f $subName, $percent) })
                }
            }
        }

        # AZURE-09: unhealthy Defender for Cloud assessments
        $assessments = & $list 'Azure/Assessments' "$base/providers/Microsoft.Security/assessments?api-version=2020-01-01" "$raw-assessments"
        if ($null -ne $assessments) {
            $unhealthy = @($assessments | Where-Object { (Get-SecOakAzureProperty $_ 'properties.status.code') -eq 'Unhealthy' })
            $bySeverity = @{ High = 0; Medium = 0; Low = 0 }
            $rated = foreach ($item in $unhealthy) {
                # Severity comes from the tenant-level assessment metadata (joined on the assessment key in name).
                $sev = "$(Get-SecOakAzureProperty $item 'properties.metadata.severity')"
                if (-not $sev -and $assessmentSeverity.ContainsKey("$($item.name)")) { $sev = $assessmentSeverity["$($item.name)"] }
                if (-not $bySeverity.ContainsKey($sev)) { $sev = 'Low' }
                $bySeverity[$sev]++
                [pscustomobject]@{ Severity = $sev; DisplayName = "$(Get-SecOakAzureProperty $item 'properties.displayName')" }
            }
            $assessmentTotals.high += $bySeverity.High; $assessmentTotals.medium += $bySeverity.Medium; $assessmentTotals.low += $bySeverity.Low
            if ($unhealthy.Count) {
                $topNames = @($rated | Where-Object Severity -eq 'High' | Group-Object DisplayName | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Count })
                $hits['AZURE-09'].Add([pscustomobject]@{ Subscription = $subName; Severity = $(if ($bySeverity.High) { 'High' } elseif ($bySeverity.Medium) { 'Medium' } else { 'Low' }); Text = ('{0}: {1} high, {2} medium, {3} low' -f $subName, $bySeverity.High, $bySeverity.Medium, $bySeverity.Low); Examples = $topNames })
            }
        }

        # AZURE-10: security contacts
        $contacts = & $list 'Azure/SecurityContacts' "$base/providers/Microsoft.Security/securityContacts?api-version=2023-12-01-preview" "$raw-security-contacts"
        if ($null -ne $contacts) {
            $active = @($contacts | Where-Object {
                    $p = $_.properties
                    $emails = "$($p.emails)".Trim()
                    $alertSource = @(Get-SecOakAzureProperty $p 'notificationsSources') | Where-Object { "$($_.sourceType)" -eq 'Alert' }
                    ($null -eq $p.isEnabled -or $p.isEnabled) -and ($emails -or @(Get-SecOakAzureProperty $p 'notificationsByRole.roles' | Where-Object { $_ }).Count) -and $alertSource
                })
            if (-not $active.Count) {
                $hits['AZURE-10'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}: {1}' -f $subName, $(if (@($contacts).Count) { 'contact exists but is disabled, has no recipient, or is not notified of alerts' } else { 'no security contact configured' })) })
            }
            else {
                $strict = @($active | Where-Object { @(Get-SecOakAzureProperty $_.properties 'notificationsSources') | Where-Object { "$($_.sourceType)" -eq 'Alert' -and "$($_.minimalSeverity)" -eq 'High' } })
                if ($strict.Count -eq $active.Count) {
                    $hits['AZURE-10'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Low'; Text = ('{0}: only High severity alerts are emailed' -f $subName) })
                }
            }
        }

        # AZURE-12: Azure Policy compliance summary (approved read-only POST)
        $policy = Invoke-SecOakReadOnlyPost -Context $Context -Api $api -Area $area -Check 'Azure/PolicyCompliance' -Body $null `
            -Path "$base/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01"
        if ($policy.Success) {
            $summaryItem = @($policy.Items) | Select-Object -First 1
            if (-not $summaryItem -and $policy.Body) { $summaryItem = @(Get-SecOakAzureProperty $policy.Body 'value') | Select-Object -First 1 }
            if ($summaryItem) {
                $results = Get-SecOakAzureProperty $summaryItem 'results'
                $nonCompliantResources = [int](Get-SecOakAzureProperty $results 'nonCompliantResources')
                $nonCompliantPolicies = [int](Get-SecOakAzureProperty $results 'nonCompliantPolicies')
                $evaluated = 0
                foreach ($detail in @(Get-SecOakAzureProperty $results 'resourceDetails')) { $evaluated += [int]$detail.count }
                $policyTotals.nonCompliantResources += $nonCompliantResources; $policyTotals.nonCompliantPolicies += $nonCompliantPolicies; $policyTotals.evaluatedResources += $evaluated
                if ($nonCompliantResources -gt 0) {
                    $ratio = if ($evaluated) { $nonCompliantResources / $evaluated } else { 1 }
                    $hits['AZURE-12'].Add([pscustomobject]@{ Subscription = $subName; Severity = $(if ($ratio -gt 0.1) { 'Medium' } else { 'Low' }); Text = ('{0}: {1} non-compliant resources across {2} policies' -f $subName, $nonCompliantResources, $nonCompliantPolicies) })
                }
            }
        }

        # AZURE-13: activity log export
        $diagnostics = & $list 'Azure/ActivityLogExport' "$base/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview" "$raw-activity-log-settings"
        if ($null -ne $diagnostics) {
            if (-not @($diagnostics).Count) {
                $hits['AZURE-13'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}: activity log is not exported anywhere' -f $subName) })
            }
            else {
                $enabledCategories = @($diagnostics | ForEach-Object { @(Get-SecOakAzureProperty $_ 'properties.logs') } | Where-Object { $_.enabled } | ForEach-Object { "$($_.category)" } | Select-Object -Unique)
                $missing = @('Administrative', 'Security', 'Policy' | Where-Object { $_ -notin $enabledCategories })
                if ($missing.Count) {
                    $hits['AZURE-13'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Low'; Text = ('{0}: export omits {1}' -f $subName, ($missing -join ', ')) })
                }
            }
        }

        # AZURE-14: resource locks
        if ($null -ne $locks) {
            if (-not @($locks).Count) {
                $hits['AZURE-14'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Low'; Text = ('{0}: no resource locks' -f $subName) })
            }
        }

        # AZURE-16: network security group exposure
        $nsgExposures = @{}
        $indeterminateRules = [System.Collections.Generic.List[string]]::new()
        if ($null -ne $nsgs) {
            foreach ($nsg in $nsgs) {
                $evaluation = Get-SecOakAzureNsgExposure -Nsg $nsg
                $attached = (@(Get-SecOakAzureProperty $nsg 'properties.subnets' | Where-Object { $_ }).Count + @(Get-SecOakAzureProperty $nsg 'properties.networkInterfaces' | Where-Object { $_ }).Count) -gt 0
                foreach ($rule in $evaluation.Indeterminate) { $indeterminateRules.Add(('{0}/{1} rule {2} port {3}' -f $subName, $nsg.name, $rule.Rule, $rule.Port)) }
                if ($evaluation.Exposed.Count) {
                    $nsgExposures["$($nsg.id)".ToLowerInvariant()] = $evaluation.Exposed
                    $top = $evaluation.Exposed | Sort-Object { $script:SeverityRank[$_.Severity] } | Select-Object -First 1
                    $hits['AZURE-16'].Add([pscustomobject]@{ Subscription = $subName; Severity = $(if ($attached) { $top.Severity } else { 'Low' }); Text = ('{0}/{1}: {2} open to the internet via rule {3}{4}' -f $subName, $nsg.name, (($evaluation.Exposed | ForEach-Object { '{0} ({1})' -f $_.Service, $_.Port } | Select-Object -Unique) -join ', '), $top.Rule, $(if ($attached) { '' } else { ' (group not attached to anything)' })) })
                }
            }
        }

        # AZURE-17: virtual machine encryption; AZURE-18: public exposure of virtual machines
        $vmIds = @{}
        if ($null -ne $vms) {
            foreach ($vm in $vms) {
                $vmIds["$($vm.id)".ToLowerInvariant()] = $vm
                # The instance view is not available on the subscription-wide list (its $expand needs a scale set
                # filter), so the model properties are used: encryption at host, confidential disk encryption,
                # Azure Disk Encryption settings on the OS disk, a customer-managed key set, or the extension resource.
                $osDisk = Get-SecOakAzureProperty $vm 'properties.storageProfile.osDisk'
                $encryptionAtHost = [bool](Get-SecOakAzureProperty $vm 'properties.securityProfile.encryptionAtHost')
                $confidential = [bool](Get-SecOakAzureProperty $osDisk 'managedDisk.securityProfile.securityEncryptionType')
                $customerKey = [bool](Get-SecOakAzureProperty $osDisk 'managedDisk.diskEncryptionSet.id')
                $ade = (Get-SecOakAzureProperty $osDisk 'encryptionSettings.enabled') -eq $true
                foreach ($extension in @(Get-SecOakAzureProperty $vm 'resources')) {
                    if ("$(Get-SecOakAzureProperty $extension 'properties.type')" -match 'AzureDiskEncryption') { $ade = $true }
                }
                $unmanaged = [bool](Get-SecOakAzureProperty $osDisk 'vhd.uri')
                if ($unmanaged -and -not $ade) {
                    $hits['AZURE-17'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'High'; Text = ('{0}/{1}: unmanaged disk without Azure Disk Encryption' -f $subName, $vm.name) })
                }
                elseif (-not ($encryptionAtHost -or $confidential -or $customerKey -or $ade)) {
                    $hits['AZURE-17'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: platform encryption only' -f $subName, $vm.name) })
                }
            }
        }
        if ($null -ne $nics -and $null -ne $publicIps) {
            $publicIpIds = @{}
            foreach ($ip in $publicIps) { $publicIpIds["$($ip.id)".ToLowerInvariant()] = $ip }
            $subnetNsg = @{}
            foreach ($nsg in @($nsgs | Where-Object { $_ })) { foreach ($subnet in @(Get-SecOakAzureProperty $nsg 'properties.subnets' | Where-Object { $_.id })) { $subnetNsg["$($subnet.id)".ToLowerInvariant()] = "$($nsg.id)".ToLowerInvariant() } }
            foreach ($nic in $nics) {
                $vmId = "$(Get-SecOakAzureProperty $nic 'properties.virtualMachine.id')".ToLowerInvariant()
                if (-not $vmId) { continue }
                $configs = @(Get-SecOakAzureProperty $nic 'properties.ipConfigurations' | Where-Object { $_ })
                $attachedIps = @($configs | ForEach-Object { "$(Get-SecOakAzureProperty $_ 'properties.publicIPAddress.id')".ToLowerInvariant() } | Where-Object { $_ -and $publicIpIds.ContainsKey($_) })
                if (-not $attachedIps.Count) { continue }
                $vmName = if ($vmIds.ContainsKey($vmId)) { $vmIds[$vmId].name } else { ($vmId -split '/')[-1] }
                $nsgIds = @("$(Get-SecOakAzureProperty $nic 'properties.networkSecurityGroup.id')".ToLowerInvariant())
                foreach ($config in $configs) { $subnetId = "$(Get-SecOakAzureProperty $config 'properties.subnet.id')".ToLowerInvariant(); if ($subnetId -and $subnetNsg.ContainsKey($subnetId)) { $nsgIds += $subnetNsg[$subnetId] } }
                $nsgIds = @($nsgIds | Where-Object { $_ } | Select-Object -Unique)
                $exposedHere = @($nsgIds | Where-Object { $nsgExposures.ContainsKey($_) } | ForEach-Object { $nsgExposures[$_] })
                if (-not $nsgIds.Count) {
                    $hits['AZURE-18'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'High'; Text = ('{0}/{1}: public IP with no network security group' -f $subName, $vmName) })
                }
                elseif ($exposedHere.Count) {
                    $hits['AZURE-18'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'High'; Text = ('{0}/{1}: public IP and {2} open to the internet' -f $subName, $vmName, (($exposedHere | ForEach-Object { $_.Service } | Select-Object -Unique) -join ', ')) })
                }
                else {
                    $hits['AZURE-18'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: public IP, management ports filtered' -f $subName, $vmName) })
                }
            }
        }

        # AZURE-19: virtual machine backup; AZURE-29: vault security settings
        if ($null -ne $vaults) {
            $protectedVmIds = @{}
            $vaultCount = 0
            foreach ($vault in $vaults) {
                $vaultCount++
                if ($vaultCount -gt $perItemCap) { $capped.Add("$subName recovery vaults"); break }
                $resourceGroup = Get-SecOakAzureResourceGroup $vault.id
                $items = & $list 'Azure/BackupProtectedItems' "$base/resourceGroups/$resourceGroup/providers/Microsoft.RecoveryServices/vaults/$($vault.name)/backupProtectedItems?api-version=2026-08-01&`$filter=backupManagementType%20eq%20'AzureIaasVM'%20and%20itemType%20eq%20'VM'" $null
                foreach ($item in @($items | Where-Object { $_ })) {
                    $protectedId = "$(Get-SecOakAzureProperty $item 'properties.virtualMachineId')".ToLowerInvariant()
                    if (-not $protectedId) { $protectedId = "$(Get-SecOakAzureProperty $item 'properties.sourceResourceId')".ToLowerInvariant() }
                    if ($protectedId) { $protectedVmIds[$protectedId] = $true }
                }
                $softDelete = "$(Get-SecOakAzureProperty $vault 'properties.securitySettings.softDeleteSettings.softDeleteState')"
                if ($softDelete -eq 'Disabled') {
                    $hits['AZURE-29'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: soft delete disabled' -f $subName, $vault.name) })
                }
                $immutability = "$(Get-SecOakAzureProperty $vault 'properties.securitySettings.immutabilitySettings.state')"
                if ($immutability -notin 'Unlocked', 'Locked') {
                    $hits['AZURE-29'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Low'; Text = ('{0}/{1}: immutability not enabled' -f $subName, $vault.name) })
                }
                if ("$(Get-SecOakAzureProperty $vault 'properties.publicNetworkAccess')" -eq 'Enabled') {
                    $hits['AZURE-29'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: public network access enabled' -f $subName, $vault.name) })
                }
            }
            if ($null -ne $vms) {
                foreach ($vm in $vms) {
                    if (-not $protectedVmIds.ContainsKey("$($vm.id)".ToLowerInvariant())) {
                        $hits['AZURE-19'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}' -f $subName, $vm.name) })
                    }
                }
            }
        }

        # AZURE-20: virtual network gateways (resource group scoped list, discovered through the generic resource list)
        $gatewayResources = & $list 'Azure/VirtualNetworkGateways' "$base/resources?`$filter=resourceType%20eq%20'Microsoft.Network/virtualNetworkGateways'&api-version=2021-04-01" $null
        if ($null -ne $gatewayResources -and @($gatewayResources).Count) {
            $groups = @($gatewayResources | ForEach-Object { Get-SecOakAzureResourceGroup $_.id } | Where-Object { $_ } | Select-Object -Unique)
            $groupCount = 0
            foreach ($group in $groups) {
                $groupCount++
                if ($groupCount -gt $perItemCap) { $capped.Add("$subName gateway resource groups"); break }
                $gateways = & $list 'Azure/VirtualNetworkGateways' "$base/resourceGroups/$group/providers/Microsoft.Network/virtualNetworkGateways?api-version=2025-09-01" "$raw-gateways-$groupCount"
                foreach ($gateway in @($gateways | Where-Object { $_ })) {
                    $inventory.gateways++
                    $sku = "$(Get-SecOakAzureProperty $gateway 'sku.name')"
                    $vpnType = "$(Get-SecOakAzureProperty $gateway 'properties.vpnType')"
                    if ($sku -eq 'Basic' -or $vpnType -eq 'PolicyBased') {
                        $hits['AZURE-20'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: {2}{3}' -f $subName, $gateway.name, $(if ($sku -eq 'Basic') { 'Basic SKU' } else { '' }), $(if ($vpnType -eq 'PolicyBased') { ' policy-based VPN' } else { '' })) })
                    }
                }
            }
        }

        # AZURE-21: Microsoft Entra Domain Services
        if ($null -ne $domainServices) {
            foreach ($domain in $domainServices) {
                $security = Get-SecOakAzureProperty $domain 'properties.domainSecuritySettings'
                $weak = @('ntlmV1', 'tlsV1', 'syncNtlmPasswords' | Where-Object { "$(Get-SecOakAzureProperty $security $_)" -eq 'Enabled' })
                if ($weak.Count) { $hits['AZURE-21'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'High'; Text = ('{0}/{1}: {2} enabled' -f $subName, $domain.name, ($weak -join ', ')) }) }
                $ldaps = Get-SecOakAzureProperty $domain 'properties.ldapsSettings'
                if ("$(Get-SecOakAzureProperty $ldaps 'ldaps')" -eq 'Disabled') { $hits['AZURE-21'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: secure LDAP disabled' -f $subName, $domain.name) }) }
                if ("$(Get-SecOakAzureProperty $ldaps 'externalAccess')" -eq 'Enabled') { $hits['AZURE-21'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: secure LDAP reachable from the internet' -f $subName, $domain.name) }) }
                $notify = Get-SecOakAzureProperty $domain 'properties.notificationSettings'
                if ("$(Get-SecOakAzureProperty $notify 'notifyDcAdmins')" -eq 'Disabled' -and "$(Get-SecOakAzureProperty $notify 'notifyGlobalAdmins')" -eq 'Disabled' -and -not @(Get-SecOakAzureProperty $notify 'additionalRecipients' | Where-Object { $_ }).Count) {
                    $hits['AZURE-21'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Low'; Text = ('{0}/{1}: nobody is notified of health alerts' -f $subName, $domain.name) })
                }
            }
        }

        # AZURE-22: storage accounts
        if ($null -ne $storage) {
            foreach ($account in $storage) {
                $p = $account.properties
                $problems = @()
                if ($p.allowBlobPublicAccess -eq $true) { $problems += @{ Severity = 'High'; Text = 'anonymous blob access allowed' } }
                if ($p.supportsHttpsTrafficOnly -eq $false) { $problems += @{ Severity = 'High'; Text = 'unencrypted HTTP allowed' } }
                if ("$($p.minimumTlsVersion)" -in 'TLS1_0', 'TLS1_1') { $problems += @{ Severity = 'Medium'; Text = "minimum TLS $($p.minimumTlsVersion)" } }
                if ("$($p.publicNetworkAccess)" -ne 'Disabled' -and "$(Get-SecOakAzureProperty $p 'networkAcls.defaultAction')" -ne 'Deny') { $problems += @{ Severity = 'Medium'; Text = 'reachable from any network' } }
                if ($null -eq $p.allowSharedKeyAccess -or $p.allowSharedKeyAccess -eq $true) { $problems += @{ Severity = 'Low'; Text = 'shared key access allowed' } }
                foreach ($problem in $problems) { $hits['AZURE-22'].Add([pscustomobject]@{ Subscription = $subName; Severity = $problem.Severity; Text = ('{0}/{1}: {2}' -f $subName, $account.name, $problem.Text) }) }
            }
        }

        # AZURE-23: key vaults
        if ($null -ne $keyVaults) {
            foreach ($vault in $keyVaults) {
                $p = $vault.properties
                $problems = @()
                if ($p.enableSoftDelete -eq $false) { $problems += @{ Severity = 'High'; Text = 'soft delete disabled' } }
                if ($p.enablePurgeProtection -ne $true) { $problems += @{ Severity = 'Medium'; Text = 'purge protection off' } }
                $publicAccess = "$($p.publicNetworkAccess)"
                $defaultAction = "$(Get-SecOakAzureProperty $p 'networkAcls.defaultAction')"
                if ($publicAccess -ne 'Disabled') {
                    if ($defaultAction -eq 'Deny') { $problems += @{ Severity = 'Medium'; Text = 'public endpoint with firewall rules' } }
                    else { $problems += @{ Severity = 'High'; Text = 'open to the internet, no firewall' } }
                }
                if ($p.enableRbacAuthorization -ne $true) { $problems += @{ Severity = 'Low'; Text = 'legacy access policies instead of role-based access' } }
                foreach ($problem in $problems) { $hits['AZURE-23'].Add([pscustomobject]@{ Subscription = $subName; Severity = $problem.Severity; Text = ('{0}/{1}: {2}' -f $subName, $vault.name, $problem.Text) }) }
            }
        }

        # AZURE-24, 25, 26: SQL servers
        if ($null -ne $sqlServers) {
            $serverCount = 0
            foreach ($server in $sqlServers) {
                $serverCount++
                if ($serverCount -gt $perItemCap) { $capped.Add("$subName SQL servers"); break }
                $p = $server.properties
                if ("$($p.publicNetworkAccess)" -eq 'Enabled') { $hits['AZURE-24'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: public network access enabled' -f $subName, $server.name) }) }
                $tls = "$($p.minimalTlsVersion)"
                if ($tls -in '1.0', '1.1', 'None', '') { $hits['AZURE-24'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: minimum TLS {2}' -f $subName, $server.name, $(if ($tls) { $tls } else { 'not set' })) }) }
                $resourceGroup = Get-SecOakAzureResourceGroup $server.id
                $serverBase = "$base/resourceGroups/$resourceGroup/providers/Microsoft.Sql/servers/$($server.name)"
                $entraOnly = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check 'Azure/SqlEntraOnlyAuthentication' -Path "$serverBase/azureADOnlyAuthentications/Default?api-version=2025-01-01" -NoGap
                $entraOnlyValue = if ($entraOnly.Success) { [bool](Get-SecOakAzureProperty $entraOnly.Body 'properties.azureADOnlyAuthentication') } elseif ($entraOnly.StatusCode -eq 404) { $false } else { $null }
                if ($null -eq $entraOnlyValue) {
                    Add-SecOakGap -Context $Context -Area $area -Check 'Azure/SqlEntraOnlyAuthentication' -EndpointOrCmdlet "$serverBase/azureADOnlyAuthentications/Default" -Result "$($entraOnly.StatusCode)" -Reason "$($entraOnly.ErrorCode): $($entraOnly.ErrorMessage)" -FillWith $readerGapFill
                }
                elseif (-not $entraOnlyValue) {
                    $hits['AZURE-25'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'High'; Text = ('{0}/{1}' -f $subName, $server.name) })
                }
                $auditing = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check 'Azure/SqlAuditing' -Path "$serverBase/auditingSettings/default?api-version=2025-01-01"
                if ($auditing.Success -and "$(Get-SecOakAzureProperty $auditing.Body 'properties.state')" -ne 'Enabled') {
                    $hits['AZURE-26'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}' -f $subName, $server.name) })
                }
            }
        }

        # AZURE-27, 28: App Service
        if ($null -ne $sites) {
            $siteCount = 0
            foreach ($site in $sites) {
                $siteCount++
                if ($siteCount -gt $perItemCap) { $capped.Add("$subName web apps"); break }
                if ((Get-SecOakAzureProperty $site 'properties.httpsOnly') -ne $true) { $hits['AZURE-27'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'High'; Text = ('{0}/{1}' -f $subName, $site.name) }) }
                $resourceGroup = Get-SecOakAzureResourceGroup $site.id
                $config = Invoke-SecOakApiGet -Context $Context -Api $api -Area $area -Check 'Azure/WebAppConfiguration' -Path "$base/resourceGroups/$resourceGroup/providers/Microsoft.Web/sites/$($site.name)/config/web?api-version=2026-07-15"
                if ($config.Success) {
                    $ftps = "$(Get-SecOakAzureProperty $config.Body 'properties.ftpsState')"
                    $minTls = "$(Get-SecOakAzureProperty $config.Body 'properties.minTlsVersion')"
                    if ($ftps -eq 'AllAllowed') { $hits['AZURE-28'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'High'; Text = ('{0}/{1}: plain FTP allowed' -f $subName, $site.name) }) }
                    if ($minTls -in '1.0', '1.1') { $hits['AZURE-28'].Add([pscustomobject]@{ Subscription = $subName; Severity = 'Medium'; Text = ('{0}/{1}: minimum TLS {2}' -f $subName, $site.name, $minTls) }) }
                }
            }
        }
        if ($indeterminateRules.Count) {
            if (-not $summary.Contains('nsgRulesForManualReview')) { $summary.nsgRulesForManualReview = [System.Collections.Generic.List[string]]::new() }
            foreach ($rule in $indeterminateRules) { $summary.nsgRulesForManualReview.Add($rule) }
        }
    }

    # Custom roles with broad write or authorization rights (AZURE-05, informational)
    foreach ($definition in $customRoles) {
        $actions = @(Get-SecOakAzureProperty $definition 'properties.permissions' | ForEach-Object { @($_.actions) })
        if ($actions | Where-Object { $_ -in '*', '*/write' -or $_ -like 'Microsoft.Authorization/*' }) {
            $hits['AZURE-05'].Add([pscustomobject]@{ Subscription = ''; Severity = 'Low'; Text = ('{0}: {1}' -f (Get-SecOakAzureProperty $definition 'properties.roleName'), (($actions | Where-Object { $_ -in '*', '*/write' -or $_ -like 'Microsoft.Authorization/*' } | Select-Object -First 3) -join ', ')) })
        }
    }

    $summary.inventory = $inventory
    $summary.customRoles = $customRoles.Count
    if ($secureScores.Count) { $summary.secureScore = @($secureScores | ForEach-Object { '{0}: {1} percent ({2} of {3})' -f $_.Subscription, $_.Percent, $_.Current, $_.Max }) }
    $summary.unhealthyAssessments = $assessmentTotals
    $summary.policyCompliance = $policyTotals
    if ($capped.Count) { $summary.enumerationCapped = @($capped | Select-Object -Unique | ForEach-Object { '{0} (first {1} checked)' -f $_, $perItemCap }) }

    # ----- Findings: one per check, worst severity across subscriptions -----
    $definitionsTable = @(
        @{ Id = 'AZURE-04'; Baseline = 'Separate admin accounts'; Title = 'Guests, applications, or too many Owners hold privileged access to a subscription'
            Risk = 'Anyone with Owner or User Access Administrator on a subscription can read, change, or delete every resource in it and grant that power to others. Guest accounts and applications sit outside the company''s password and multifactor controls.'
            Recommendation = 'Limit each subscription to two named Owner accounts with multifactor authentication, remove guest and application Owners, and give applications only the specific role they need at resource group level.' }
        @{ Id = 'AZURE-05'; Baseline = 'None'; Title = 'Custom roles grant broad write or permission-management rights'
            Risk = 'A custom role with wildcard write or Microsoft.Authorization rights is effectively Owner under a different name and is easy to overlook in access reviews.'
            Recommendation = 'Review each custom role, replace wildcard actions with the exact operations needed, and prefer built-in roles where one fits.' }
        @{ Id = 'AZURE-07'; Baseline = 'None'; Title = 'Defender for Cloud plans are off for resources that exist'
            Risk = 'Without the paid Defender plans, Azure will not detect malware, brute-force sign-ins, or suspicious database queries against these resources, and posture recommendations stay basic.'
            Recommendation = 'Enable the Defender for Servers, SQL, Storage, and App Service plans on subscriptions that host those resources, and Defender CSPM for attack path analysis. Costs are per resource per month and can be trialed for 30 days.' }
        @{ Id = 'AZURE-08'; Baseline = 'None'; Title = 'Defender for Cloud secure score is low'
            Risk = 'A low score means many of Microsoft''s baseline hardening recommendations for this subscription are still open. The score is an indicator, not a measure of risk by itself.'
            Recommendation = 'Work through the Defender for Cloud recommendations page starting with High severity items and track the score monthly.' }
        @{ Id = 'AZURE-09'; Baseline = 'None'; Title = 'Open Defender for Cloud recommendations'
            Risk = 'Each unhealthy assessment is a resource that fails a Microsoft security recommendation, such as missing updates, open ports, or unencrypted data.'
            Recommendation = 'Fix the High severity recommendations first; Defender for Cloud gives a step-by-step remediation for each one.' }
        @{ Id = 'AZURE-10'; Baseline = 'None'; Title = 'Nobody is emailed when Defender for Cloud raises an alert'
            Risk = 'Defender for Cloud alerts only help if a person sees them. With no working security contact, an attack in progress goes unnoticed until damage is visible.'
            Recommendation = 'In Defender for Cloud, Environment settings, Email notifications, add a monitored mailbox, tick the subscription Owner role, and send alerts of Medium severity and above.' }
        @{ Id = 'AZURE-12'; Baseline = 'None'; Title = 'Resources are not compliant with assigned Azure policies'
            Risk = 'Non-compliant resources are breaking rules the organization or Microsoft set, for example on encryption, logging, or allowed regions.'
            Recommendation = 'Open Azure Policy, Compliance, sort by non-compliant resources, and remediate or formally exempt each one.' }
        @{ Id = 'AZURE-13'; Baseline = 'None'; Title = 'Azure activity log is not exported for long-term retention'
            Risk = 'The activity log records every change to Azure resources but is kept for only 90 days. Without an export, an investigation into a change made months ago has no evidence to work from.'
            Recommendation = 'Add a subscription diagnostic setting that sends the Administrative, Security, Policy, and Alert categories to a Log Analytics workspace or a storage account with at least one year of retention.' }
        @{ Id = 'AZURE-14'; Baseline = 'None'; Title = 'No resource locks protect against accidental deletion'
            Risk = 'Without a lock, one wrong click or script can delete a production virtual machine, database, or storage account permanently.'
            Recommendation = 'Add a CanNotDelete lock to each production resource group; it costs nothing and is removed in seconds when a deletion is intended.' }
        @{ Id = 'AZURE-16'; Baseline = 'None'; Title = 'Network security groups allow management ports from the internet'
            Risk = 'Remote Desktop, SSH, SMB, database, and remote management ports open to any internet address are scanned and brute-forced within minutes of going live and are the most common way ransomware enters Azure.'
            Recommendation = 'Remove the any-source allow rules, use Azure Bastion or a VPN for administration, or at minimum restrict the source to the office public IP address. Note: this is a static reading of the rules; Azure''s effective rules view was not queried because it requires a POST.' }
        @{ Id = 'AZURE-17'; Baseline = 'None'; Title = 'Virtual machines rely on default platform encryption only'
            Risk = 'Azure encrypts managed disks at rest by default, but without encryption at host, Azure Disk Encryption, or customer-managed keys the temporary disk and caches are not covered and a copied disk can be read by anyone with the file. Unmanaged disks in storage accounts are not encrypted at all unless Azure Disk Encryption is on.'
            Recommendation = 'Enable encryption at host (requires a one-time feature registration and a restart) on each virtual machine, or use Azure Disk Encryption with keys in Key Vault. Migrate any unmanaged disks to managed disks first.' }
        @{ Id = 'AZURE-18'; Baseline = 'None'; Title = 'Virtual machines reachable directly from the internet'
            Risk = 'A virtual machine with a public IP address is reachable by every attacker on the internet. Where management ports are also open, or no network security group filters traffic, compromise is a matter of time.'
            Recommendation = 'Remove public IP addresses from virtual machines and reach them through Azure Bastion or a VPN. Where a public address is required, attach a network security group that allows only the needed ports from known sources.' }
        @{ Id = 'AZURE-19'; Baseline = 'Tested backups'; Title = 'Virtual machines not protected by Azure Backup'
            Risk = 'A virtual machine outside a Recovery Services vault has no restore point. Ransomware, a bad update, or an accidental deletion means rebuilding from scratch.'
            Recommendation = 'Enable Azure Backup on every virtual machine with a daily policy, keep at least 30 days of restore points, and test a restore once a quarter.' }
        @{ Id = 'AZURE-20'; Baseline = 'None'; Title = 'VPN gateways on a retired SKU or policy-based configuration'
            Risk = 'Basic SKU and policy-based gateways are legacy configurations with fewer security features, limited throughput, and an announced retirement path.'
            Recommendation = 'Plan a migration to a route-based VpnGw1 or higher gateway during a maintenance window.' }
        @{ Id = 'AZURE-21'; Baseline = 'None'; Title = 'Microsoft Entra Domain Services allows weak protocols or exposes LDAP'
            Risk = 'NTLM version 1, TLS 1.0, and synchronized NTLM password hashes let attackers relay or crack credentials; LDAP open to the internet exposes the whole directory to password spraying.'
            Recommendation = 'Disable NTLM v1, TLS 1.0, and NTLM password sync in the domain security settings; keep secure LDAP internal-only and add a notification recipient for domain health alerts.' }
        @{ Id = 'AZURE-22'; Baseline = 'None'; Title = 'Storage accounts with anonymous access, weak transport security, or open networks'
            Risk = 'Storage accounts often hold backups, exports, and documents. Anonymous blob access or plain HTTP lets anyone read them; open network access and shared keys make a leaked key a full data breach.'
            Recommendation = 'Disable anonymous blob access, require secure transfer, set minimum TLS to 1.2, restrict public network access to known addresses or private endpoints, and move to Microsoft Entra authorization instead of shared keys.' }
        @{ Id = 'AZURE-23'; Baseline = 'None'; Title = 'Key vaults without deletion protection or open to the internet'
            Risk = 'Key vaults hold the secrets and certificates that everything else depends on. Without soft delete and purge protection, an attacker or a mistake can destroy them permanently; an internet-reachable vault is one leaked credential away from exposure.'
            Recommendation = 'Turn on soft delete and purge protection, restrict public network access with a firewall or private endpoint, and switch to Azure role-based access control for the data plane.' }
        @{ Id = 'AZURE-24'; Baseline = 'None'; Title = 'SQL servers reachable from the internet or accepting old TLS'
            Risk = 'A database server with public network access enabled depends entirely on its firewall rules; old TLS versions allow connections that can be intercepted.'
            Recommendation = 'Set minimum TLS to 1.2, review the server firewall rules, and where possible disable public network access in favor of a private endpoint.' }
        @{ Id = 'AZURE-25'; Baseline = 'Multifactor for every user'; Title = 'SQL servers still allow SQL password logins'
            Risk = 'SQL authentication uses standalone passwords that bypass Microsoft Entra multifactor authentication and conditional access, so a leaked connection string gives direct database access.'
            Recommendation = 'Move applications to Microsoft Entra authentication (managed identities where possible) and then enable Microsoft Entra-only authentication on each server.' }
        @{ Id = 'AZURE-26'; Baseline = 'None'; Title = 'SQL server auditing is disabled'
            Risk = 'Without auditing there is no record of who queried, changed, or exported data, which makes a breach investigation or a compliance request impossible to answer.'
            Recommendation = 'Enable server-level auditing to a Log Analytics workspace or storage account with at least 90 days of retention.' }
        @{ Id = 'AZURE-27'; Baseline = 'None'; Title = 'Web apps accept unencrypted HTTP'
            Risk = 'Visitors and sign-in forms can be served over plain HTTP, exposing session cookies and credentials to anyone on the network path.'
            Recommendation = 'Turn on HTTPS Only in each app''s configuration; it redirects all HTTP requests to HTTPS with no code change.' }
        @{ Id = 'AZURE-28'; Baseline = 'None'; Title = 'Web apps allow plain FTP or old TLS versions'
            Risk = 'Plain FTP sends deployment credentials in clear text; TLS 1.0 and 1.1 are broken protocols that browsers and compliance frameworks reject.'
            Recommendation = 'Set FTP state to FTPS only or disabled and the minimum TLS version to 1.2 in each app''s configuration.' }
        @{ Id = 'AZURE-29'; Baseline = 'Tested backups'; Title = 'Recovery Services vaults without soft delete, immutability, or network restriction'
            Risk = 'Ransomware operators delete backups before encrypting data. Soft delete and immutability stop backups from being deleted even by an administrator account they have taken over.'
            Recommendation = 'Keep soft delete on (the default), enable immutability on production vaults, and disable public network access once private endpoints are in place.' }
    )
    foreach ($definition in $definitionsTable) {
        $items = @($hits[$definition.Id])
        if (-not $items.Count) { continue }
        $severity = ($items | Sort-Object { $script:SeverityRank[$_.Severity] } | Select-Object -First 1).Severity
        $evidence = [ordered]@{ affected = $items.Count; subscriptions = @($items.Subscription | Where-Object { $_ } | Select-Object -Unique).Count }
        foreach ($level in 'Critical', 'High', 'Medium', 'Low') {
            $count = @($items | Where-Object Severity -eq $level).Count
            if ($count) { $evidence["$($level.ToLowerInvariant())Items"] = $count }
        }
        $evidence.examples = Select-SecOakExample @($items | Sort-Object { $script:SeverityRank[$_.Severity] } | ForEach-Object { $_.Text }) -Count 8
        $extra = @($items | Where-Object { $_.PSObject.Properties['Examples'] } | ForEach-Object { @($_.Examples) })
        if ($extra.Count) { $evidence.topRecommendations = Select-SecOakExample $extra -Count 8 }
        $findings.Add((New-SecOakFinding -Id $definition.Id -Area $area -Severity $severity -BaselineControl $definition.Baseline `
                    -Title $definition.Title -Evidence $evidence -Risk $definition.Risk -Recommendation $definition.Recommendation))
    }

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
