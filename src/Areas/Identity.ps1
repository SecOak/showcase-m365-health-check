function Invoke-SecOakIdentityCheck {
    <#
    .SYNOPSIS
        Identity area: multifactor coverage, security defaults and conditional access, admin
        role sprawl, stale accounts, guests, app consent, and risky users.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        Area result object with Area, Summary, and Findings. Findings and gaps are also added
        to the context.
    .EXAMPLE
        Invoke-SecOakIdentityCheck -Context $context
    .NOTES
        Application permissions: Directory.Read.All, AuditLog.Read.All, Policy.Read.All,
        RoleManagement.Read.Directory, IdentityRiskyUser.Read.All, IdentityRiskEvent.Read.All.
        Several items need Microsoft Entra ID P1 or P2.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Identity'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $now = [datetime]::UtcNow
    $staleCutoff = $now.AddDays(-90)

    Write-Verbose 'Identity: loading user inventory'
    Get-SecOakUserInventory -Context $Context
    $users = @($Context.Cache.Users)
    $usersById = $Context.Cache.UsersById
    $enabledMembers = @($users | Where-Object { $_.accountEnabled -and $_.userType -ne 'Guest' })
    $summary.users = [ordered]@{ total = $users.Count; enabledMembers = $enabledMembers.Count; guests = @($users | Where-Object userType -eq 'Guest').Count }

    #--- Multifactor registration
    Write-Verbose 'Identity: multifactor registration'
    $registration = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/Multifactor' -Path '/reports/authenticationMethods/userRegistrationDetails' -RawName 'identity-mfa-registration'
    if ($registration.Success) {
        $rows = @($registration.Items)
        if ($Context.Cache.UsersAvailable) {
            $enabledIds = [System.Collections.Generic.HashSet[string]]::new([string[]]@($enabledMembers.id))
            $rows = @($rows | Where-Object { $enabledIds.Contains([string]$_.id) })
        }
        else { $rows = @($rows | Where-Object userType -ne 'guest') }
        $notCapable = @($rows | Where-Object { -not $_.isMfaCapable })
        $adminsNotRegistered = @($rows | Where-Object { $_.isAdmin -and -not $_.isMfaRegistered })
        $summary.multifactor = [ordered]@{
            usersInScope     = $rows.Count
            mfaRegistered    = @($rows | Where-Object isMfaRegistered).Count
            mfaCapable       = @($rows | Where-Object isMfaCapable).Count
            notCapable       = $notCapable.Count
            adminsInReport   = @($rows | Where-Object isAdmin).Count
            adminsNotRegistered = $adminsNotRegistered.Count
        }
        if ($adminsNotRegistered.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-01' -Area $area -Severity Critical -BaselineControl 'Multifactor for every user' `
                        -Title 'Administrators without multifactor registered' `
                        -Evidence ([ordered]@{ adminsWithoutMultifactor = $adminsNotRegistered.Count; examples = (Select-SecOakExample $adminsNotRegistered.userPrincipalName) }) `
                        -Risk 'An administrator account protected only by a password can be taken over by phishing or password spraying, giving an attacker control of the whole tenant.' `
                        -Recommendation 'Register a phishing-resistant or authenticator-app method for every administrator and require multifactor for all admin roles through conditional access.'))
        }
        if ($notCapable.Count -gt 0) {
            $percent = if ($rows.Count) { [math]::Round(100 * $notCapable.Count / $rows.Count, 1) } else { 0 }
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-02' -Area $area -Severity $(if ($percent -ge 10) { 'High' } else { 'Medium' }) -BaselineControl 'Multifactor for every user' `
                        -Title 'Users who cannot complete multifactor sign-in' `
                        -Evidence ([ordered]@{ usersNotCapable = $notCapable.Count; usersInScope = $rows.Count; percent = $percent; examples = (Select-SecOakExample $notCapable.userPrincipalName) }) `
                        -Risk 'Accounts without a registered multifactor method rely on the password alone and are the most common entry point for account takeover.' `
                        -Recommendation 'Run a registration campaign, require registration through conditional access, and follow up with the listed users.'))
        }
    }

    #--- Security defaults and conditional access
    Write-Verbose 'Identity: security defaults and conditional access'
    $defaults = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/SecurityDefaults' -Path '/policies/identitySecurityDefaultsEnforcementPolicy' -RawName 'identity-security-defaults'
    $conditional = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/ConditionalAccess' -Path '/identity/conditionalAccess/policies' -RawName 'identity-conditional-access'
    $securityDefaultsOn = $defaults.Success -and [bool]$defaults.Body.isEnabled
    if ($conditional.Success) {
        $policies = @($conditional.Items)
        $describe = foreach ($policy in $policies) {
            $users = $policy.conditions.users
            $grant = $policy.grantControls
            [pscustomobject][ordered]@{
                name              = $policy.displayName
                state             = $policy.state
                includeUsers      = @($users.includeUsers)
                includeRoles      = @($users.includeRoles).Count
                includeGroups     = @($users.includeGroups).Count
                excludeUsers      = @($users.excludeUsers).Count
                excludeGroups     = @($users.excludeGroups).Count
                excludeRoles      = @($users.excludeRoles).Count
                excludeGuests     = [bool]$users.excludeGuestsOrExternalUsers
                includeApps       = @($policy.conditions.applications.includeApplications)
                clientAppTypes    = @($policy.conditions.clientAppTypes)
                builtInControls   = @($grant.builtInControls)
                authStrength      = $grant.authenticationStrength.displayName
                allUsers          = @($users.includeUsers) -contains 'All'
                allApps           = @($policy.conditions.applications.includeApplications) -contains 'All'
                requiresMfa       = (@($grant.builtInControls) -contains 'mfa') -or [bool]$grant.authenticationStrength
                blocks            = @($grant.builtInControls) -contains 'block'
                excludedUserIds   = @($users.excludeUsers | Where-Object { $_ -notin 'GuestsOrExternalUsers', 'None' })
                targetsGlobalAdmin = @($users.includeRoles) -contains $script:GlobalAdminTemplateId
            }
        }
        $describe = @($describe)
        $enabled = @($describe | Where-Object state -eq 'enabled')
        $reportOnly = @($describe | Where-Object state -eq 'enabledForReportingButNotEnforced')
        $legacyPolicies = @($enabled | Where-Object { $_.blocks -and $_.allUsers -and $_.allApps -and ($_.clientAppTypes -contains 'exchangeActiveSync') -and ($_.clientAppTypes -contains 'other') })
        $mfaAllPolicies = @($enabled | Where-Object { $_.requiresMfa -and $_.allUsers -and $_.allApps })
        $adminMfaPolicies = @($enabled | Where-Object { $_.requiresMfa -and ($_.allUsers -or $_.targetsGlobalAdmin) })
        $summary.conditionalAccess = [ordered]@{
            securityDefaultsEnabled = $securityDefaultsOn
            policies                = $describe.Count
            enabled                 = $enabled.Count
            reportOnly              = $reportOnly.Count
            disabled                = @($describe | Where-Object state -eq 'disabled').Count
            blocksLegacyAuth        = [bool]($securityDefaultsOn -or $legacyPolicies)
            mfaForAllUsers          = [bool]($securityDefaultsOn -or $mfaAllPolicies)
            mfaForAdmins            = [bool]($securityDefaultsOn -or $adminMfaPolicies)
            policyList              = @($describe | Select-Object name, state, includeUsers, includeRoles, includeGroups, excludeUsers, excludeGroups, excludeRoles, excludeGuests, includeApps, clientAppTypes, builtInControls, authStrength)
        }

        if (-not ($securityDefaultsOn -or $legacyPolicies)) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-03' -Area $area -Severity High -BaselineControl 'Legacy authentication blocked' `
                        -Title 'Legacy authentication is not blocked' `
                        -Evidence ([ordered]@{ securityDefaultsEnabled = $securityDefaultsOn; enabledPolicies = $enabled.Count; reportOnlyLegacyPolicies = @($reportOnly | Where-Object { $_.blocks -and ($_.clientAppTypes -contains 'other') }).name }) `
                        -Risk 'Legacy protocols (IMAP, POP, SMTP basic authentication, older Office clients) cannot do multifactor, so a stolen password is enough to sign in.' `
                        -Recommendation 'Create an enabled conditional access policy for all users and all cloud apps, client apps "Exchange ActiveSync" and "Other clients", grant control Block, with only break-glass accounts excluded.'))
        }
        if (-not ($securityDefaultsOn -or $adminMfaPolicies)) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-04' -Area $area -Severity Critical -BaselineControl 'Multifactor for every user' `
                        -Title 'Administrators are not required to use multifactor' `
                        -Evidence ([ordered]@{ securityDefaultsEnabled = $securityDefaultsOn; enabledPolicies = $enabled.Count; mfaPoliciesTargetingAdmins = 0 }) `
                        -Risk 'Nothing forces administrators to prove their identity with a second factor, so one phished password can hand over the tenant.' `
                        -Recommendation 'Enforce multifactor (ideally phishing-resistant authentication strength) for all directory roles with a conditional access policy.'))
        }
        if (-not ($securityDefaultsOn -or $mfaAllPolicies)) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-05' -Area $area -Severity High -BaselineControl 'Multifactor for every user' `
                        -Title 'No policy requires multifactor for all users' `
                        -Evidence ([ordered]@{ securityDefaultsEnabled = $securityDefaultsOn; enabledPolicies = $enabled.Count; reportOnlyPolicies = $reportOnly.Count }) `
                        -Risk 'Users can sign in with a password alone. Password spraying and phishing succeed without any further barrier.' `
                        -Recommendation 'Enable a conditional access policy requiring multifactor for all users and all cloud apps, or enable security defaults if the tenant has no Entra ID P1.'))
        }
        $broad = @($enabled | Where-Object { ($_.requiresMfa -or $_.blocks) -and ($_.excludeUsers -gt 2 -or $_.excludeGroups -gt 0 -or $_.excludeRoles -gt 0 -or $_.excludeGuests) })
        if ($broad.Count -gt 0) {
            $excludedNames = @($broad.excludedUserIds | Select-Object -Unique | ForEach-Object { if ($usersById -and $usersById[$_]) { $usersById[$_].userPrincipalName } else { $_ } })
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-06' -Area $area -Severity Medium -BaselineControl 'Multifactor for every user' `
                        -Title 'Conditional access policies with broad exclusions' `
                        -Evidence ([ordered]@{ policiesWithBroadExclusions = $broad.Count; policies = @($broad | ForEach-Object { '{0} (users {1}, groups {2}, roles {3}, guests {4})' -f $_.name, $_.excludeUsers, $_.excludeGroups, $_.excludeRoles, $_.excludeGuests }); excludedUserExamples = (Select-SecOakExample $excludedNames) }) `
                        -Risk 'Every excluded account or group member bypasses the protection. Group exclusions grow silently as members are added.' `
                        -Recommendation 'Limit exclusions to two monitored break-glass accounts. Replace group and role exclusions with narrowly scoped policies and review them quarterly.'))
        }
    }
    elseif ($defaults.Success) {
        $summary.conditionalAccess = [ordered]@{ securityDefaultsEnabled = $securityDefaultsOn; policies = 'unreadable' }
    }

    #--- Admin role sprawl
    Write-Verbose 'Identity: directory role assignments'
    $definitions = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/AdminRoles' -Path '/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn' -RawName 'identity-role-definitions'
    $assignments = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/AdminRoles' -Path '/roleManagement/directory/roleAssignments?$expand=principal' -RawName 'identity-role-assignments'
    $eligible = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/AdminRoles' -Path '/roleManagement/directory/roleEligibilitySchedules?$expand=principal' -RawName 'identity-role-eligibility'
    if ($definitions.Success -and $assignments.Success) {
        $roleNames = @{}
        foreach ($definition in $definitions.Items) { $roleNames[$definition.id] = $definition.displayName; if ($definition.templateId) { $roleNames[$definition.templateId] = $definition.displayName } }
        $ownSp = Get-SecOakOwnServicePrincipal -Context $Context -Check 'Identity/AdminRoles'
        $rows = foreach ($set in @(@{ Kind = 'Active'; Items = $assignments.Items }, @{ Kind = 'Eligible'; Items = $(if ($eligible.Success) { $eligible.Items } else { @() }) })) {
            foreach ($assignment in @($set.Items)) {
                $principal = $assignment.principal
                $type = "$($principal.'@odata.type')" -replace '#microsoft.graph.', ''
                $user = if ($type -eq 'user' -and $usersById) { $usersById[$assignment.principalId] } else { $null }
                [pscustomobject][ordered]@{
                    PrincipalId   = $assignment.principalId
                    PrincipalType = $type
                    Name          = if ($principal.userPrincipalName) { $principal.userPrincipalName } else { $principal.displayName }
                    Role          = $roleNames[$assignment.roleDefinitionId]
                    Assignment    = $set.Kind
                    Privileged    = $roleNames[$assignment.roleDefinitionId] -in $script:PrivilegedRoleNames
                    IsGuest       = ($user -and $user.userType -eq 'Guest') -or ($principal.userPrincipalName -like '*#EXT#*')
                    HasMailbox    = Test-SecOakUserHasMailbox -User $user
                    IsOwnApp      = [bool]($ownSp -and $assignment.principalId -eq $ownSp.id)
                }
            }
        }
        $rows = @($rows)
        Save-SecOakRawData -Context $Context -Name 'identity-admin-summary' -Data $rows
        $globalAdmins = @($rows | Where-Object Role -eq 'Global Administrator' | Select-Object -ExpandProperty PrincipalId -Unique)
        $userAdmins = @($rows | Where-Object PrincipalType -eq 'user')
        $mailboxAdmins = @($userAdmins | Where-Object HasMailbox)
        $privilegedMailboxAdmins = @($mailboxAdmins | Where-Object Privileged | Select-Object -ExpandProperty Name -Unique)
        $guestAdmins = @($rows | Where-Object IsGuest)
        $servicePrincipalAdmins = @($rows | Where-Object { $_.PrincipalType -eq 'servicePrincipal' -and -not $_.IsOwnApp })
        $summary.adminRoles = [ordered]@{
            activeAssignments       = @($assignments.Items).Count
            eligibleAssignments     = if ($eligible.Success) { @($eligible.Items).Count } else { 'unreadable' }
            distinctAdmins          = @($rows.PrincipalId | Select-Object -Unique).Count
            globalAdministrators    = $globalAdmins.Count
            adminsWithMailbox       = @($mailboxAdmins.Name | Select-Object -Unique).Count
            guestAdmins             = @($guestAdmins.Name | Select-Object -Unique).Count
            servicePrincipalAdmins  = @($servicePrincipalAdmins.Name | Select-Object -Unique).Count
            groupAssignments        = @($rows | Where-Object PrincipalType -eq 'group').Count
            roleCounts              = @($rows | Group-Object Role | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
        }
        $Context.Cache.AdminPrincipalIds = @($rows.PrincipalId | Select-Object -Unique)
        if ($globalAdmins.Count -gt 4) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-07' -Area $area -Severity High -BaselineControl 'Separate admin accounts' `
                        -Title 'Too many Global Administrators' `
                        -Evidence ([ordered]@{ globalAdministrators = $globalAdmins.Count; examples = (Select-SecOakExample @($rows | Where-Object Role -eq 'Global Administrator' | Select-Object -ExpandProperty Name -Unique)) }) `
                        -Risk 'Each Global Administrator can do anything in the tenant. More of them means more targets and more chances of one being compromised.' `
                        -Recommendation 'Keep two to four Global Administrators including break-glass accounts; move everyone else to the least-privileged role that fits their job, ideally eligible through Privileged Identity Management.'))
        }
        elseif ($globalAdmins.Count -lt 2) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-07' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                        -Title 'Fewer than two Global Administrators' `
                        -Evidence ([ordered]@{ globalAdministrators = $globalAdmins.Count }) `
                        -Risk 'If the only Global Administrator is locked out, nobody can recover the tenant without a lengthy Microsoft support process.' `
                        -Recommendation 'Create a second, cloud-only break-glass Global Administrator with a strong credential stored offline and monitored sign-ins.'))
        }
        if ($mailboxAdmins.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-08' -Area $area -Severity $(if ($privilegedMailboxAdmins.Count) { 'High' } else { 'Medium' }) -BaselineControl 'Separate admin accounts' `
                        -Title 'Admin roles held by everyday accounts with licensed mailboxes' `
                        -Evidence ([ordered]@{ adminsWithMailbox = @($mailboxAdmins.Name | Select-Object -Unique).Count; privilegedAdminsWithMailbox = $privilegedMailboxAdmins.Count; examples = (Select-SecOakExample @($mailboxAdmins | ForEach-Object { "$($_.Name) ($($_.Role))" } | Select-Object -Unique)) }) `
                        -Risk 'An account that reads email and browses the web is the one most likely to be phished. If it also holds an admin role, the attacker gets admin rights too.' `
                        -Recommendation 'Give each administrator a separate cloud-only admin account without a mailbox license, and remove admin roles from everyday accounts.'))
        }
        if ($guestAdmins.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-09' -Area $area -Severity High -BaselineControl 'Separate admin accounts' `
                        -Title 'Guest accounts hold admin roles' `
                        -Evidence ([ordered]@{ guestAdmins = @($guestAdmins.Name | Select-Object -Unique).Count; examples = (Select-SecOakExample @($guestAdmins | ForEach-Object { "$($_.Name) ($($_.Role))" } | Select-Object -Unique)) }) `
                        -Risk 'Guest identities are secured by another organization. Their password and multifactor policies are outside your control.' `
                        -Recommendation 'Remove admin roles from guests. Use GDAP for partners, or create a member admin account governed by your own policies.'))
        }
        if ($servicePrincipalAdmins.Count -gt 0) {
            $privilegedSp = @($servicePrincipalAdmins | Where-Object Privileged)
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-10' -Area $area -Severity $(if ($privilegedSp.Count) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Applications (service principals) hold directory roles' `
                        -Evidence ([ordered]@{ servicePrincipalsWithRoles = @($servicePrincipalAdmins.Name | Select-Object -Unique).Count; privileged = $privilegedSp.Count; examples = (Select-SecOakExample @($servicePrincipalAdmins | ForEach-Object { "$($_.Name) ($($_.Role))" } | Select-Object -Unique)) }) `
                        -Risk 'An application with an admin role acts without multifactor or conditional access. Anyone holding its credential has those rights.' `
                        -Recommendation 'Confirm each application still needs its role, replace privileged roles with narrower Graph permissions, and rotate or remove unused credentials.'))
        }
    }

    #--- Stale accounts
    if ($Context.Cache.SignInActivityAvailable) {
        $stale = @($enabledMembers | Where-Object {
                (ConvertTo-SecOakUtcDate $_.createdDateTime) -lt $staleCutoff -and
                ($null -eq ($last = Get-SecOakLastSignIn -User $_) -or $last -lt $staleCutoff)
            })
        $never = @($stale | Where-Object { $null -eq (Get-SecOakLastSignIn -User $_) })
        $adminIds = if ($Context.Cache.ContainsKey('AdminPrincipalIds')) { $Context.Cache.AdminPrincipalIds } else { @() }
        $staleAdmins = @($stale | Where-Object { $_.id -in $adminIds })
        $summary.staleAccounts = [ordered]@{ enabledMembersNoSignIn90Days = $stale.Count; neverSignedIn = $never.Count; staleAdmins = $staleAdmins.Count }
        if ($stale.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-11' -Area $area -Severity $(if ($staleAdmins.Count) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Enabled accounts with no sign-in for 90 days or more' `
                        -Evidence ([ordered]@{ staleAccounts = $stale.Count; neverSignedIn = $never.Count; staleAdmins = $staleAdmins.Count; examples = (Select-SecOakExample $stale.userPrincipalName) }) `
                        -Risk 'Unused accounts are not watched by anyone, so a compromise goes unnoticed. Former staff accounts keep access to company data.' `
                        -Recommendation 'Confirm each account with the business owner, then disable it and remove licenses. Add a monthly review or an access review for inactive users.'))
        }
    }
    else {
        $summary.staleAccounts = 'unavailable (sign-in activity not readable)'
    }

    #--- Guests and invite settings
    Write-Verbose 'Identity: guests and authorization policy'
    $authorization = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/Guests' -Path '/policies/authorizationPolicy' -RawName 'identity-authorization-policy'
    $guests = @($users | Where-Object userType -eq 'Guest')
    $guestSummary = [ordered]@{ total = $guests.Count; enabled = @($guests | Where-Object accountEnabled).Count }
    if ($Context.Cache.SignInActivityAvailable) {
        $staleGuests = @($guests | Where-Object { $_.accountEnabled -and ($null -eq ($last = Get-SecOakLastSignIn -User $_) -or $last -lt $staleCutoff) })
        $guestSummary.enabledNoSignIn90Days = $staleGuests.Count
        if ($staleGuests.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-12' -Area $area -Severity $(if ($staleGuests.Count -gt 10) { 'Medium' } else { 'Low' }) -BaselineControl 'None' `
                        -Title 'Guest accounts unused for 90 days or more' `
                        -Evidence ([ordered]@{ staleGuests = $staleGuests.Count; totalGuests = $guests.Count; examples = (Select-SecOakExample $staleGuests.mail) }) `
                        -Risk 'Old guest accounts keep access to shared files and Teams long after the collaboration ended.' `
                        -Recommendation 'Remove guests with no recent activity and set up a recurring guest access review.'))
        }
    }
    $guestRoles = @{
        'a0b1b346-4d3e-4e8b-98f8-753987be4970' = 'Same access as members'
        '10dae51f-b6af-4016-8d66-8c2a99b929b3' = 'Limited access (default)'
        '2af84b1e-32c8-42b7-82bc-daa82404023b' = 'Restricted access'
    }
    if ($authorization.Success) {
        $policy = $authorization.Body
        if ($policy.PSObject.Properties['value']) { $policy = @($policy.value)[0] }
        $consentPolicies = @($policy.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
        $guestSummary.allowInvitesFrom = $policy.allowInvitesFrom
        $guestSummary.guestUserRole = $guestRoles["$($policy.guestUserRoleId)"]
        $summary.guests = $guestSummary
        $summary.userConsent = [ordered]@{
            permissionGrantPoliciesAssigned = $consentPolicies
            usersCanRegisterApps           = [bool]$policy.defaultUserRolePermissions.allowedToCreateApps
            usersCanCreateTenants          = $policy.defaultUserRolePermissions.allowedToCreateTenants
        }
        if ($policy.allowInvitesFrom -eq 'everyone') {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-13' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Anyone, including guests, can invite new guests' `
                        -Evidence ([ordered]@{ allowInvitesFrom = $policy.allowInvitesFrom }) `
                        -Risk 'Guests can bring in further outside accounts without any employee or admin involvement.' `
                        -Recommendation 'Set guest invite restrictions to "Only users assigned to specific admin roles" or at least "Member users and users assigned to specific admin roles".'))
        }
        if ("$($policy.guestUserRoleId)" -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-14' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Guests have the same directory access as members' `
                        -Evidence ([ordered]@{ guestUserRole = $guestRoles["$($policy.guestUserRoleId)"] }) `
                        -Risk 'Any guest can enumerate every user, group, and device in the directory, which helps attackers plan phishing and privilege escalation.' `
                        -Recommendation 'Set guest user access to "Guest users have limited access" or "restricted access".'))
        }
        if ($consentPolicies -match 'user-default-legacy') {
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-15' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Users can consent to any application' `
                        -Evidence ([ordered]@{ permissionGrantPoliciesAssigned = $consentPolicies }) `
                        -Risk 'Consent phishing: a user clicks "Accept" on a malicious app and grants it ongoing access to their mail and files, which survives password resets and multifactor.' `
                        -Recommendation 'Allow user consent only for verified publishers and low-impact permissions, or disable it and turn on the admin consent workflow.'))
        }
    }
    else { $summary.guests = $guestSummary }

    #--- Enterprise apps holding high-privilege application permissions
    Write-Verbose 'Identity: application permissions granted to enterprise apps'
    $ownSp = Get-SecOakOwnServicePrincipal -Context $Context -Check 'Identity/AppPermissions'
    $appGrants = [System.Collections.Generic.List[object]]::new()
    foreach ($resourceAppId in @($script:GraphResourceAppId, $script:ExchangeResourceAppId)) {
        $resource = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/AppPermissions' -Path ("/servicePrincipals?`$filter=appId eq '{0}'&`$select=id,displayName" -f $resourceAppId)
        if (-not $resource.Success -or -not $resource.Items) { continue }
        $resourceSp = $resource.Items[0]
        $roleMap = Get-SecOakResourceAppRoleMap -Context $Context -Area $area -Check 'Identity/AppPermissions' -ResourceServicePrincipalId $resourceSp.id
        $assigned = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/AppPermissions' -Path "/servicePrincipals/$($resourceSp.id)/appRoleAssignedTo?`$top=999"
        if (-not $assigned.Success) { continue }
        foreach ($grant in $assigned.Items) {
            if ($grant.principalType -ne 'ServicePrincipal') { continue }
            $permission = $roleMap.Roles[$grant.appRoleId]
            $appGrants.Add([pscustomobject][ordered]@{
                    App        = $grant.principalDisplayName
                    PrincipalId = $grant.principalId
                    Resource   = $resourceSp.displayName
                    Permission = $permission
                    Risk       = Get-SecOakPermissionRisk -Permission "$permission"
                    IsOwnApp   = [bool]($ownSp -and $grant.principalId -eq $ownSp.id)
                })
        }
    }
    Save-SecOakRawData -Context $Context -Name 'identity-app-permissions' -Data $appGrants.ToArray()
    $others = @($appGrants | Where-Object { -not $_.IsOwnApp })
    $writeApps = @($others | Where-Object { $_.Risk -in 'Write', 'Elevated' } | Group-Object App)
    $sensitiveApps = @($others | Where-Object Risk -eq 'SensitiveRead' | Group-Object App | Where-Object { $_.Name -notin $writeApps.Name })
    $summary.applicationPermissions = [ordered]@{ appsWithApplicationPermissions = @($others.App | Select-Object -Unique).Count; appsWithWriteLevel = $writeApps.Count; appsWithSensitiveRead = $sensitiveApps.Count }
    if ($writeApps.Count -gt 0) {
        $findings.Add((New-SecOakFinding -Id 'IDENTITY-16' -Area $area -Severity High -BaselineControl 'None' `
                    -Title 'Enterprise apps with high-privilege application permissions' `
                    -Evidence ([ordered]@{ apps = $writeApps.Count; examples = (Select-SecOakExample @($writeApps | ForEach-Object { '{0}: {1}' -f $_.Name, ((@($_.Group | Where-Object { $_.Risk -in 'Write', 'Elevated' }).Permission | Select-Object -First 4) -join ', ') })) }) `
                    -Risk 'Application permissions work without a signed-in user. Anyone holding one of these app credentials can change the tenant or read or send mail as anyone.' `
                    -Recommendation 'Confirm an owner and business need for each app, remove unneeded permissions, prefer certificates over secrets, and monitor their sign-ins.'))
    }
    if ($sensitiveApps.Count -gt 0) {
        $findings.Add((New-SecOakFinding -Id 'IDENTITY-17' -Area $area -Severity Medium -BaselineControl 'None' `
                    -Title 'Enterprise apps that can read sensitive data tenant-wide' `
                    -Evidence ([ordered]@{ apps = $sensitiveApps.Count; examples = (Select-SecOakExample @($sensitiveApps | ForEach-Object { '{0}: {1}' -f $_.Name, ((@($_.Group).Permission | Select-Object -First 4) -join ', ') })) }) `
                    -Risk 'These apps can read every mailbox, file, or chat without a user present. A leaked credential exposes all of it.' `
                    -Recommendation 'Confirm each app is still used, scope mailbox access with application access policies or RBAC for Applications, and remove what is not needed.'))
    }

    #--- Risky users and risk detections
    Write-Verbose 'Identity: risky users and risk detections'
    $risky = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/RiskyUsers' -Path '/identityProtection/riskyUsers' -RawName 'identity-risky-users'
    $since = $now.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $detections = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Identity/RiskDetections' -Path "/identityProtection/riskDetections?`$filter=detectedDateTime ge $since" -RawName 'identity-risk-detections'
    $riskSummary = [ordered]@{}
    if ($risky.Success) {
        $atRisk = @($risky.Items | Where-Object riskState -in 'atRisk', 'confirmedCompromised')
        $riskSummary.usersAtRisk = $atRisk.Count
        $riskSummary.byLevel = [ordered]@{ high = @($atRisk | Where-Object riskLevel -eq 'high').Count; medium = @($atRisk | Where-Object riskLevel -eq 'medium').Count; low = @($atRisk | Where-Object riskLevel -eq 'low').Count; hidden = @($atRisk | Where-Object riskLevel -eq 'hidden').Count }
        if (@($atRisk | Where-Object riskLevel -eq 'hidden').Count) { $riskSummary.note = 'Risk level hidden: the tenant lacks Microsoft Entra ID P2, so detail is limited.' }
        if ($atRisk.Count -gt 0) {
            $high = @($atRisk | Where-Object { $_.riskLevel -eq 'high' -or $_.riskState -eq 'confirmedCompromised' })
            $findings.Add((New-SecOakFinding -Id 'IDENTITY-18' -Area $area -Severity $(if ($high.Count) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Users currently flagged at risk' `
                        -Evidence ([ordered]@{ usersAtRisk = $atRisk.Count; highOrCompromised = $high.Count; examples = (Select-SecOakExample $atRisk.userPrincipalName) }) `
                        -Risk 'Microsoft has seen signs such as leaked credentials or suspicious sign-ins for these accounts. They may already be compromised.' `
                        -Recommendation 'Investigate each user, reset passwords and revoke sessions where warranted, then confirm safe or compromised. Add a user-risk conditional access policy if licensed.'))
        }
    }
    if ($detections.Success) {
        $riskSummary.detectionsLast30Days = @($detections.Items).Count
        $riskSummary.detectionTypes = @($detections.Items | Group-Object riskEventType | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
    }
    $summary.risk = $riskSummary

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
