function Get-SecOakEntraPremium {
    <#
    .SYNOPSIS
        Returns the tenant's Entra ID licence flags (P1, P2, Governance), reading subscribed SKUs once.
    .NOTES
        Permission: Directory.Read.All. Internal helper for the Entra area (ENTRA-01).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context, [Parameter(Mandatory)][string]$Area)

    if ($Context.Cache.ContainsKey('Premium') -and $Context.Cache.Premium.Contains('Governance')) { return $Context.Cache.Premium }
    $result = Invoke-SecOakGraphGet -Context $Context -Area $Area -Check 'Entra/Licence' -Path '/subscribedSkus?$select=skuPartNumber,capabilityStatus,prepaidUnits,servicePlans' -RawName 'entra-subscribed-skus'
    $plans = @()
    if ($result.Success) {
        $plans = @($result.Items | Where-Object capabilityStatus -eq 'Enabled' | ForEach-Object { @($_.servicePlans | Where-Object provisioningStatus -ne 'Disabled' | Select-Object -ExpandProperty servicePlanName) })
    }
    $premium = if ($Context.Cache.ContainsKey('Premium')) { $Context.Cache.Premium } else { [ordered]@{} }
    $premium.EntraIdP1 = [bool]($plans -contains 'AAD_PREMIUM' -or $plans -contains 'AAD_PREMIUM_P2')
    $premium.EntraIdP2 = [bool]($plans -contains 'AAD_PREMIUM_P2')
    $premium.Governance = [bool]($plans -match '^(Entra_Identity_Governance|AAD_GOVERNANCE|Microsoft_Entra_ID_Governance)')
    $premium.LicenceReadable = [bool]$result.Success
    $Context.Cache.Premium = $premium
    $premium
}

function Get-SecOakEntraConditionalAccess {
    <#
    .SYNOPSIS
        Fetches the conditional access policy list once per run and caches it on the context.
    .NOTES
        Permission: Policy.Read.All. Internal helper for the Entra area.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context, [Parameter(Mandatory)][string]$Area)

    if ($Context.Cache.ContainsKey('ConditionalAccess')) { return $Context.Cache.ConditionalAccess }
    $result = Invoke-SecOakGraphGet -Context $Context -Area $Area -Check 'Entra/ConditionalAccess' -Path '/identity/conditionalAccess/policies' -RawName 'entra-conditional-access'
    $Context.Cache.ConditionalAccess = $result
    $result
}

function Get-SecOakEntraRoles {
    <#
    .SYNOPSIS
        Fetches directory role definitions, active assignments and eligibility schedules once and caches a flat row list.
    .NOTES
        Permission: RoleManagement.Read.Directory. Internal helper for the Entra area.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context, [Parameter(Mandatory)][string]$Area)

    if ($Context.Cache.ContainsKey('EntraRoles')) { return $Context.Cache.EntraRoles }
    $check = 'Entra/Roles'
    $definitions = Invoke-SecOakGraphGet -Context $Context -Area $Area -Check $check -Path '/roleManagement/directory/roleDefinitions?$select=id,displayName,templateId,isBuiltIn'
    $assignments = Invoke-SecOakGraphGet -Context $Context -Area $Area -Check $check -Path '/roleManagement/directory/roleAssignments?$expand=principal'
    $eligible = Invoke-SecOakGraphGet -Context $Context -Area $Area -Check $check -Path '/roleManagement/directory/roleEligibilitySchedules?$expand=principal'
    $names = @{}
    $templates = @{}
    if ($definitions.Success) {
        foreach ($definition in $definitions.Items) {
            $names[$definition.id] = $definition.displayName
            if ($definition.templateId) { $names[$definition.templateId] = $definition.displayName; $templates[$definition.displayName] = $definition.templateId }
        }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($set in @(@{ Kind = 'Active'; Result = $assignments }, @{ Kind = 'Eligible'; Result = $eligible })) {
        if (-not $set.Result.Success) { continue }
        foreach ($assignment in @($set.Result.Items)) {
            $principal = $assignment.principal
            $role = $names[$assignment.roleDefinitionId]
            $principalType = ("$($principal.'@odata.type')" -replace '#microsoft.graph.', '')
            $principalName = if ($principal.userPrincipalName) { $principal.userPrincipalName } else { $principal.displayName }
            $row = [pscustomobject][ordered]@{
                PrincipalId   = $assignment.principalId
                PrincipalType = $principalType
                Name          = $principalName
                Role          = $role
                Kind          = $set.Kind
                Privileged    = ($role -in $script:PrivilegedRoleNames)
            }
            $rows.Add($row)
        }
    }
    $roles = [pscustomobject]@{
        Available          = [bool]($definitions.Success -and $assignments.Success)
        EligibleAvailable  = [bool]$eligible.Success
        EligibleCount      = if ($eligible.Success) { @($eligible.Items).Count } else { 0 }
        RoleNames          = $names
        TemplateIds        = $templates
        Rows               = $rows.ToArray()
    }
    $Context.Cache.EntraRoles = $roles
    $roles
}

function Get-SecOakEntraUserSync {
    <#
    .SYNOPSIS
        Reads the on-premises synchronisation fields for every user once (the shared inventory does not select them).
    .NOTES
        Permission: Directory.Read.All. Internal helper for the Entra area.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context, [Parameter(Mandatory)][string]$Area)

    if ($Context.Cache.ContainsKey('EntraUserSyncById')) { return $Context.Cache.EntraUserSyncById }
    $result = Invoke-SecOakGraphGet -Context $Context -Area $Area -Check 'Entra/UserSync' -Path '/users?$select=id,userPrincipalName,accountEnabled,userType,onPremisesSyncEnabled,onPremisesImmutableId&$top=999'
    $byId = @{}
    if ($result.Success) { foreach ($user in $result.Items) { $byId[$user.id] = $user } }
    $Context.Cache.EntraUserSyncById = $byId
    $Context.Cache.EntraUserSyncAvailable = [bool]$result.Success
    $byId
}

function Test-SecOakEntraBroadCidr {
    <#
    .SYNOPSIS
        True when an IP range is wider than /16 (IPv4) or /48 (IPv6), or is the whole internet.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$Cidr)
    if (-not $Cidr) { return $false }
    if ($Cidr -match '^0\.0\.0\.0/0$' -or $Cidr -match '^::/0$') { return $true }
    $parts = $Cidr -split '/'
    if ($parts.Count -ne 2) { return $false }
    $prefix = 0
    if (-not [int]::TryParse($parts[1], [ref]$prefix)) { return $false }
    if ($parts[0] -match ':') { return $prefix -lt 48 }
    $prefix -lt 16
}

function ConvertTo-SecOakEntraTimeSpan {
    <#
    .SYNOPSIS
        Converts an ISO 8601 duration such as PT8H to a TimeSpan, or $null.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$Value)
    if (-not $Value) { return $null }
    try { [System.Xml.XmlConvert]::ToTimeSpan($Value) } catch { $null }
}

function Add-SecOakEntraLicenceGap {
    <#
    .SYNOPSIS
        Records a "not assessed: licence" gap for a check the tenant cannot use.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$What,
        [Parameter(Mandatory)][string]$Licence
    )
    Add-SecOakGap -Context $Context -Area $Area -Check $Check -EndpointOrCmdlet $What -Result 'not assessed: licence' `
        -Reason "The feature needs $Licence, which this tenant does not have, so it is not scored." -FillWith "Licence: $Licence."
}

function Invoke-SecOakEntraCheck {
    <#
    .SYNOPSIS
        Entra area: authentication methods, conditional access depth, Privileged Identity
        Management, access reviews, external collaboration, consent, passwords, stale objects,
        application credentials, synchronisation, groups, administrative units, audit and
        sign-in log summaries, token lifetimes, Windows LAPS and BitLocker escrow.
    .DESCRIPTION
        Implements the ENTRA catalogue. Checks already covered by the Identity area are not
        repeated here: ENTRA-08 (IDENTITY-03), ENTRA-09 (IDENTITY-04), ENTRA-10 (IDENTITY-05
        and 06), ENTRA-30 (IDENTITY-11 and 12), the "everyone can invite" rule of ENTRA-22
        (IDENTITY-13) and the "legacy user consent" rule of ENTRA-24 (IDENTITY-15).
        Features the tenant is not licensed for are recorded as "not assessed: licence".
    .PARAMETER Context
        The run context.
    .OUTPUTS
        Area result object with Area, Summary, and Findings. Findings and gaps are also added
        to the context.
    .EXAMPLE
        Invoke-SecOakEntraCheck -Context $context
    .NOTES
        Application permissions: Directory.Read.All, Policy.Read.All,
        RoleManagement.Read.Directory, AuditLog.Read.All, plus (new) AccessReview.Read.All,
        Policy.Read.PermissionGrant, Policy.Read.DeviceConfiguration,
        DeviceLocalCredential.ReadBasic.All, BitlockerKey.ReadBasic.All. Several items need
        Microsoft Entra ID P1 or P2. Metadata only: never requests LAPS passwords or BitLocker keys.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Entra'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $now = [datetime]::UtcNow
    $phishingResistantStrengthId = '00000000-0000-0000-0000-000000000004'
    $microsoftFirstPartyTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'

    #--- ENTRA-01 licence flags
    Write-Verbose 'Entra: licence detection'
    $premium = Get-SecOakEntraPremium -Context $Context -Area $area
    $p1 = [bool]$premium.EntraIdP1
    $p2 = [bool]$premium.EntraIdP2
    $governance = [bool]$premium.Governance
    $summary.licence = [ordered]@{ entraIdP1 = $p1; entraIdP2 = $p2; governance = $governance; readable = [bool]$premium.LicenceReadable }

    Get-SecOakUserInventory -Context $Context
    $users = @($Context.Cache.Users)
    $usersById = $Context.Cache.UsersById
    $guests = @($users | Where-Object userType -eq 'Guest')
    $enabledMembers = @($users | Where-Object { $_.accountEnabled -and $_.userType -ne 'Guest' })
    $roles = Get-SecOakEntraRoles -Context $Context -Area $area
    $syncById = Get-SecOakEntraUserSync -Context $Context -Area $area
    $privilegedUserIds = @($roles.Rows | Where-Object { $_.Privileged -and $_.PrincipalType -eq 'user' } | Select-Object -ExpandProperty PrincipalId -Unique)
    $globalAdminUserIds = @($roles.Rows | Where-Object { $_.Role -eq 'Global Administrator' -and $_.PrincipalType -eq 'user' } | Select-Object -ExpandProperty PrincipalId -Unique)
    $privilegedTemplateIds = @($script:PrivilegedRoleNames | ForEach-Object { $roles.TemplateIds[$_] } | Where-Object { $_ })
    if (-not $privilegedTemplateIds) { $privilegedTemplateIds = @($script:GlobalAdminTemplateId) }

    #--- ENTRA-02 to ENTRA-05 authentication methods policy
    Write-Verbose 'Entra: authentication methods policy'
    $methods = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/AuthenticationMethods' -Path '/policies/authenticationMethodsPolicy' -RawName 'entra-authentication-methods-policy'
    if ($methods.Success) {
        $policy = $methods.Body
        $configurations = @{}
        foreach ($configuration in @($policy.authenticationMethodConfigurations)) { $configurations[$configuration.id] = $configuration }
        $state = { param($id) $c = $configurations[$id]; if ($c) { "$($c.state)" } else { 'absent' } }
        $isEnabledForAll = {
            param($id)
            $c = $configurations[$id]
            if (-not $c -or $c.state -ne 'enabled') { return $false }
            $targets = @($c.includeTargets)
            [bool]($targets | Where-Object { $_.id -eq 'all_users' })
        }
        $campaign = $policy.registrationEnforcement.authenticationMethodsRegistrationCampaign
        $summary.authenticationMethods = [ordered]@{
            policyMigrationState      = $policy.policyMigrationState
            registrationCampaign      = $campaign.state
            reportSuspiciousActivity  = $policy.reportSuspiciousActivitySettings.state
            methods                   = @($configurations.Keys | Sort-Object | ForEach-Object { '{0}: {1}' -f $_, (& $state $_) })
        }
        if ($policy.policyMigrationState -and $policy.policyMigrationState -ne 'migrationComplete') {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-02' -Area $area -Severity Medium -BaselineControl 'Multifactor for every user' `
                        -Title 'Authentication methods policy migration not completed' `
                        -Evidence ([ordered]@{ policyMigrationState = $policy.policyMigrationState }) `
                        -Risk 'Two sets of settings (the legacy multifactor and self-service password reset pages plus the new policy) decide which sign-in methods are allowed, so a method thought to be off may still work.' `
                        -Recommendation 'Finish the migration to the authentication methods policy in the Entra admin center and set the migration status to Complete.'))
        }
        if ("$($campaign.state)" -eq 'disabled') {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-02' -Area $area -Severity Low -BaselineControl 'Multifactor for every user' `
                        -Title 'Authenticator registration campaign is disabled' `
                        -Evidence ([ordered]@{ registrationCampaignState = $campaign.state }) `
                        -Risk 'Users who still rely on text message or phone call are never nudged to move to the Microsoft Authenticator app, which is harder to phish.' `
                        -Recommendation 'Enable the registration campaign for all users with a short snooze allowance.'))
        }
        if ("$($policy.reportSuspiciousActivitySettings.state)" -ne 'enabled') {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-02' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Users cannot report suspicious multifactor prompts' `
                        -Evidence ([ordered]@{ reportSuspiciousActivityState = "$($policy.reportSuspiciousActivitySettings.state)" }) `
                        -Risk 'When someone receives a multifactor prompt they did not start, nothing lets them flag it, so a password theft can go unnoticed.' `
                        -Recommendation 'Enable "Report suspicious activity" in the authentication methods settings so a report raises the user risk and alerts administrators.'))
        }
        $smsAll = & $isEnabledForAll 'Sms'
        $voiceAll = & $isEnabledForAll 'Voice'
        if ($smsAll -or $voiceAll) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-03' -Area $area -Severity Medium -BaselineControl 'Multifactor for every user' `
                        -Title 'Text message or voice call authentication is enabled for all users' `
                        -Evidence ([ordered]@{ smsForAllUsers = $smsAll; voiceForAllUsers = $voiceAll }) `
                        -Risk 'Phone-based codes can be intercepted through SIM swapping and real-time phishing pages, so they are the weakest form of multifactor.' `
                        -Recommendation 'Move users to the Microsoft Authenticator app or passkeys, then limit text message and voice call to a small exception group and finally disable them.'))
        }
        $email = $configurations['Email']
        if ($email -and $email.state -eq 'enabled' -and "$($email.allowExternalIdToUseEmailOtp)" -ne 'enabled' -and (& $isEnabledForAll 'Email')) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-03' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Email one-time passcode is enabled for member users' `
                        -Evidence ([ordered]@{ emailState = $email.state }) `
                        -Risk 'A code sent to a mailbox can be read by anyone who already has access to that mailbox, which weakens self-service password reset.' `
                        -Recommendation 'Keep email one-time passcode for guests only and remove members from its target list.'))
        }
        $authenticator = $configurations['MicrosoftAuthenticator']
        $fido2 = $configurations['Fido2']
        $fido2Enabled = [bool]($fido2 -and $fido2.state -eq 'enabled')
        $phishingResistant = $fido2Enabled -or [bool]($configurations['X509Certificate'] -and $configurations['X509Certificate'].state -eq 'enabled')
        if (-not ($authenticator -and $authenticator.state -eq 'enabled') -and -not $phishingResistant) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-04' -Area $area -Severity Medium -BaselineControl 'Multifactor for every user' `
                        -Title 'Microsoft Authenticator is disabled and no phishing-resistant method is enabled' `
                        -Evidence ([ordered]@{ authenticatorState = (& $state 'MicrosoftAuthenticator'); fido2State = (& $state 'Fido2'); certificateState = (& $state 'X509Certificate') }) `
                        -Risk 'Users are left with phone-based codes only, which are the easiest second factor for an attacker to defeat.' `
                        -Recommendation 'Enable Microsoft Authenticator for all users and plan passkeys (FIDO2) for administrators.'))
        }
        elseif ($authenticator -and $authenticator.state -eq 'enabled') {
            $appInfo = "$($authenticator.featureSettings.displayAppInformationRequiredState.state)"
            $location = "$($authenticator.featureSettings.displayLocationInformationRequiredState.state)"
            if ($appInfo -eq 'disabled' -or $location -eq 'disabled') {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-04' -Area $area -Severity Low -BaselineControl 'Multifactor for every user' `
                            -Title 'Authenticator prompts do not show the application name or sign-in location' `
                            -Evidence ([ordered]@{ displayAppInformation = $appInfo; displayLocationInformation = $location }) `
                            -Risk 'Without the application name and map, users cannot tell a genuine prompt from one triggered by an attacker using their password.' `
                            -Recommendation 'Enable "Show application name" and "Show geographic location" in the Microsoft Authenticator settings for all users.'))
            }
        }
        if (-not $fido2Enabled) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-05' -Area $area -Severity Low -BaselineControl 'Multifactor for every user' `
                        -Title 'Passkeys (FIDO2) are not enabled' `
                        -Evidence ([ordered]@{ fido2State = (& $state 'Fido2') }) `
                        -Risk 'Administrators have no phishing-resistant sign-in option, so a convincing fake sign-in page can still capture an approval.' `
                        -Recommendation 'Enable passkeys (FIDO2) at least for administrators and require the phishing-resistant authentication strength for admin roles.'))
        }
        elseif ("$($fido2.isAttestationEnforced)" -eq 'False' -and -not @($fido2.keyRestrictions.aaGuids).Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-05' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Passkeys accept any key without attestation or model restrictions' `
                        -Evidence ([ordered]@{ isAttestationEnforced = $false; keyRestrictions = 'none' }) `
                        -Risk 'Any passkey provider, including unmanaged software keys, can be registered; this is acceptable for most small businesses but weakens a hardware-key policy.' `
                        -Recommendation 'If the business issues hardware keys, enforce attestation and allow only those key models.'))
        }
        $tap = $configurations['TemporaryAccessPass']
        if ($tap -and $tap.state -eq 'enabled' -and "$($tap.isUsableOnce)" -eq 'False' -and [int]$tap.maximumLifetimeInMinutes -gt 480) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-05' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Temporary Access Pass can be reused for a long lifetime' `
                        -Evidence ([ordered]@{ isUsableOnce = $false; maximumLifetimeMinutes = $tap.maximumLifetimeInMinutes }) `
                        -Risk 'A multi-use pass that lives for days is a temporary password; if it is shared over chat or email it can be used by someone else.' `
                        -Recommendation 'Set Temporary Access Pass to one-time use or a maximum lifetime of 8 hours.'))
        }
    }

    #--- Conditional access payload (shared by ENTRA-06, 07, 11 to 14, 37)
    Write-Verbose 'Entra: conditional access depth'
    $conditional = Get-SecOakEntraConditionalAccess -Context $Context -Area $area
    $described = @()
    $enabledPolicies = @()
    $reportOnlyPolicies = @()
    if ($conditional.Success) {
        $described = @(foreach ($policy in @($conditional.Items)) {
                $conditions = $policy.conditions
                $grant = $policy.grantControls
                $includeRoles = @($conditions.users.includeRoles)
                [pscustomobject][ordered]@{
                    id                 = $policy.id
                    name               = $policy.displayName
                    state              = $policy.state
                    modified           = ConvertTo-SecOakUtcDate $(if ($policy.modifiedDateTime) { $policy.modifiedDateTime } else { $policy.createdDateTime })
                    allUsers           = @($conditions.users.includeUsers) -contains 'All'
                    allApps            = @($conditions.applications.includeApplications) -contains 'All'
                    userActions        = @($conditions.applications.includeUserActions)
                    includeRoles       = $includeRoles
                    targetsAdmins      = [bool](@($includeRoles | Where-Object { $_ -in $privilegedTemplateIds }).Count)
                    includeGroups      = @($conditions.users.includeGroups)
                    excludeGroups      = @($conditions.users.excludeGroups)
                    excludedUserIds    = @($conditions.users.excludeUsers | Where-Object { $_ -notin 'GuestsOrExternalUsers', 'None' })
                    excludeLocations   = @($conditions.locations.excludeLocations)
                    userRiskLevels     = @($conditions.userRiskLevels)
                    signInRiskLevels   = @($conditions.signInRiskLevels)
                    builtInControls    = @($grant.builtInControls)
                    strengthId         = "$($grant.authenticationStrength.id)"
                    requiresMfa        = (@($grant.builtInControls) -contains 'mfa') -or [bool]$grant.authenticationStrength
                    blocks             = @($grant.builtInControls) -contains 'block'
                    requiresDevice     = (@($grant.builtInControls) -contains 'compliantDevice') -or (@($grant.builtInControls) -contains 'domainJoinedDevice')
                    signInFrequency    = [bool]$policy.sessionControls.signInFrequency.isEnabled
                    persistentNever    = "$($policy.sessionControls.persistentBrowser.mode)" -eq 'never' -and [bool]$policy.sessionControls.persistentBrowser.isEnabled
                }
            })
        $enabledPolicies = @($described | Where-Object state -eq 'enabled')
        $reportOnlyPolicies = @($described | Where-Object state -eq 'enabledForReportingButNotEnforced')
        $summary.conditionalAccess = [ordered]@{ policies = $described.Count; enabled = $enabledPolicies.Count; reportOnly = $reportOnlyPolicies.Count }
    }
    $conditionalUsable = $conditional.Success -and $p1

    #--- ENTRA-06 authentication strengths
    $strengths = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/AuthenticationStrengths' -Path '/policies/authenticationStrengthPolicies' -RawName 'entra-authentication-strengths'
    if ($strengths.Success) {
        $custom = @($strengths.Items | Where-Object policyType -eq 'custom')
        $weakCustom = @($custom | Where-Object { @($_.allowedCombinations) -match '(^|,)(sms|voice)' })
        $summary.authenticationStrengths = [ordered]@{ builtIn = @($strengths.Items | Where-Object policyType -eq 'builtIn').Count; custom = $custom.Count; customAllowingSmsOrVoice = $weakCustom.Count }
        if ($conditionalUsable) {
            $adminPhishingResistant = @($enabledPolicies | Where-Object { $_.targetsAdmins -and $_.strengthId -eq $phishingResistantStrengthId })
            if (-not $adminPhishingResistant.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-06' -Area $area -Severity Medium -BaselineControl 'Multifactor for every user' `
                            -Title 'No conditional access policy requires phishing-resistant sign-in for administrators' `
                            -Evidence ([ordered]@{ enabledPoliciesTargetingAdminRoles = @($enabledPolicies | Where-Object targetsAdmins).Count; policiesWithPhishingResistantStrength = 0 }) `
                            -Risk 'Administrators can still approve a push or type a code on a fake sign-in page. One phished administrator means the whole tenant is lost.' `
                            -Recommendation 'Create a conditional access policy for all directory roles that requires the built-in "Phishing-resistant MFA" authentication strength, after administrators register passkeys.'))
            }
        }
        elseif ($conditional.Success -and -not $p1) { Add-SecOakEntraLicenceGap -Context $Context -Area $area -Check 'Entra/AuthenticationStrengths' -What 'ENTRA-06 phishing-resistant strength for administrators' -Licence 'Microsoft Entra ID P1' }
        if ($weakCustom.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-06' -Area $area -Severity Low -BaselineControl 'Multifactor for every user' `
                        -Title 'Custom authentication strengths allow text message or voice call' `
                        -Evidence ([ordered]@{ customStrengths = $weakCustom.Count; examples = (Select-SecOakExample $weakCustom.displayName) }) `
                        -Risk 'A policy that references one of these strengths is satisfied by a phone code, which defeats the purpose of choosing a strength.' `
                        -Recommendation 'Remove the sms and voice combinations from these custom strengths or use the built-in "Multifactor authentication" strength instead.'))
        }
    }

    #--- ENTRA-07 named locations
    $locations = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/NamedLocations' -Path '/identity/conditionalAccess/namedLocations' -RawName 'entra-named-locations'
    if ($locations.Success) {
        $ipLocations = @($locations.Items | Where-Object { "$($_.'@odata.type')" -match 'ipNamedLocation' })
        $countryLocations = @($locations.Items | Where-Object { "$($_.'@odata.type')" -match 'countryNamedLocation' })
        $broadTrusted = @($ipLocations | Where-Object { $_.isTrusted -and (@($_.ipRanges | Where-Object { Test-SecOakEntraBroadCidr -Cidr "$($_.cidrAddress)" }).Count) })
        $summary.namedLocations = [ordered]@{
            ipLocations         = $ipLocations.Count
            trustedIpLocations  = @($ipLocations | Where-Object isTrusted).Count
            countryLocations    = @($countryLocations | ForEach-Object { '{0} ({1} countries, unknown regions {2})' -f $_.displayName, @($_.countriesAndRegions).Count, [bool]$_.includeUnknownCountriesAndRegions })
        }
        if ($broadTrusted.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-07' -Area $area -Severity Medium -BaselineControl 'Multifactor for every user' `
                        -Title 'Trusted named locations contain very wide IP ranges' `
                        -Evidence ([ordered]@{ locations = $broadTrusted.Count; examples = (Select-SecOakExample @($broadTrusted | ForEach-Object { '{0}: {1}' -f $_.displayName, ((@($_.ipRanges.cidrAddress) | Where-Object { Test-SecOakEntraBroadCidr -Cidr "$_" } | Select-Object -First 3) -join ', ') })) }) `
                        -Risk 'Any policy that skips multifactor from trusted locations is skipped for every address in these ranges, which can include whole internet providers or the entire internet.' `
                        -Recommendation 'Narrow trusted locations to the exact office public addresses (ideally single /32 addresses) and remove ranges wider than /24 unless they are genuinely owned by the business.'))
        }
        if ($conditionalUsable) {
            $adminMfaExcludingTrusted = @($enabledPolicies | Where-Object { $_.requiresMfa -and ($_.targetsAdmins -or $_.allUsers) -and ($_.excludeLocations -contains 'AllTrusted') })
            if ($adminMfaExcludingTrusted.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-07' -Area $area -Severity Low -BaselineControl 'Multifactor for every user' `
                            -Title 'Multifactor policies covering administrators skip trusted locations' `
                            -Evidence ([ordered]@{ policies = $adminMfaExcludingTrusted.Count; examples = (Select-SecOakExample $adminMfaExcludingTrusted.name) }) `
                            -Risk 'An attacker inside the office network, or a compromised device on it, can use an administrator password without a second factor.' `
                            -Recommendation 'Require multifactor for administrators from every location; keep location exclusions for ordinary users only if the office network is well controlled.'))
            }
        }
    }

    if ($conditionalUsable) {
        #--- ENTRA-11 device compliance
        $deviceEnabled = @($enabledPolicies | Where-Object { $_.requiresDevice -and ($_.allUsers -or $_.targetsAdmins) })
        $deviceReportOnly = @($reportOnlyPolicies | Where-Object { $_.requiresDevice })
        if (-not $deviceEnabled.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-11' -Area $area -Severity $(if ($deviceReportOnly.Count) { 'Low' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'No conditional access policy requires a compliant or joined device' `
                        -Evidence ([ordered]@{ enabledDevicePolicies = 0; reportOnlyDevicePolicies = $deviceReportOnly.Count; intuneLicensed = [bool]$premium.Intune }) `
                        -Risk 'Company data can be opened from any personal or unmanaged computer, where there is no encryption, patching or malware protection the business controls.' `
                        -Recommendation 'Once devices are enrolled in Intune with a compliance policy, add a conditional access policy that requires a compliant device for company applications, starting with administrators.'))
        }

        #--- ENTRA-12 risk-based policies
        if ($p2) {
            $userRisk = @($enabledPolicies | Where-Object { ($_.userRiskLevels -contains 'high') -and ($_.blocks -or (($_.builtInControls -contains 'passwordChange') -and $_.requiresMfa)) })
            $signInRisk = @($enabledPolicies | Where-Object { ($_.signInRiskLevels -contains 'high') -and ($_.blocks -or $_.requiresMfa) })
            $summary.riskPolicies = [ordered]@{ userRiskPolicies = $userRisk.Count; signInRiskPolicies = $signInRisk.Count }
            if (-not $userRisk.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-12' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'No user risk policy forces a password change for high-risk users' `
                            -Evidence ([ordered]@{ enabledPoliciesWithUserRiskHigh = 0 }) `
                            -Risk 'The tenant pays for Entra ID P2 risk detection, but a user whose password Microsoft believes is leaked keeps working with that password.' `
                            -Recommendation 'Create a conditional access policy for user risk "High" that requires multifactor and a secure password change.'))
            }
            if (-not $signInRisk.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-12' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'No sign-in risk policy challenges risky sign-ins' `
                            -Evidence ([ordered]@{ enabledPoliciesWithSignInRiskHigh = 0 }) `
                            -Risk 'Sign-ins from anonymous networks or impossible travel are detected but allowed through without an extra check.' `
                            -Recommendation 'Create a conditional access policy for sign-in risk "Medium and high" that requires multifactor.'))
            }
        }
        else { Add-SecOakEntraLicenceGap -Context $Context -Area $area -Check 'Entra/ConditionalAccess' -What 'ENTRA-12 risk-based conditional access policies' -Licence 'Microsoft Entra ID P2' }

        #--- ENTRA-13 break-glass exclusions
        $protective = @($enabledPolicies | Where-Object { $_.requiresMfa -or $_.blocks })
        if ($protective.Count) {
            $excludedFromAll = @($protective[0].excludedUserIds)
            foreach ($policy in $protective) { $excludedFromAll = @($excludedFromAll | Where-Object { $_ -in $policy.excludedUserIds }) }
            $describeUser = { param($id) if ($usersById -and $usersById[$id]) { $usersById[$id].userPrincipalName } else { $id } }
            $isCloudOnly = { param($id) -not ($syncById[$id] -and $syncById[$id].onPremisesSyncEnabled) }
            $breakGlass = @($excludedFromAll | Where-Object { ($_ -in $globalAdminUserIds) -and (& $isCloudOnly $_) })
            $notBreakGlass = @($excludedFromAll | Where-Object { $_ -notin $breakGlass })
            $summary.breakGlass = [ordered]@{ protectivePolicies = $protective.Count; accountsExcludedFromAll = $excludedFromAll.Count; cloudOnlyGlobalAdminsExcludedFromAll = $breakGlass.Count }
            if (-not $breakGlass.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-13' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                            -Title 'No cloud-only emergency access account is excluded from every blocking or multifactor policy' `
                            -Evidence ([ordered]@{ protectivePolicies = $protective.Count; accountsExcludedFromAll = $excludedFromAll.Count }) `
                            -Risk 'A misconfigured policy, a broken multifactor provider or a federation outage can lock every administrator out of the tenant with no way back in.' `
                            -Recommendation 'Create two cloud-only emergency access accounts with Global Administrator, exclude them from every conditional access policy, store their credentials offline and alert on their sign-ins.'))
            }
            if ($notBreakGlass.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-13' -Area $area -Severity Medium -BaselineControl 'Multifactor for every user' `
                            -Title 'Accounts excluded from every protective policy that are not cloud-only Global Administrators' `
                            -Evidence ([ordered]@{ accounts = $notBreakGlass.Count; examples = (Select-SecOakExample @($notBreakGlass | ForEach-Object { & $describeUser $_ })) }) `
                            -Risk 'These accounts bypass multifactor and every block. If one is a synchronised or everyday account, a stolen password gives full access with no second factor.' `
                            -Recommendation 'Limit blanket exclusions to the two emergency access accounts; give service accounts their own narrowly scoped policy instead of a blanket exclusion.'))
            }
            if ($excludedFromAll.Count -gt 2) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-13' -Area $area -Severity Low -BaselineControl 'Multifactor for every user' `
                            -Title 'More than two accounts are excluded from every protective policy' `
                            -Evidence ([ordered]@{ accountsExcludedFromAll = $excludedFromAll.Count }) `
                            -Risk 'Each extra exclusion is another account that can be used without multifactor.' `
                            -Recommendation 'Reduce blanket exclusions to two emergency access accounts.'))
            }
            if ($Context.Cache.SignInActivityAvailable) {
                $untested = @($breakGlass | Where-Object { $u = $usersById[$_]; $u -and ($null -eq ($last = Get-SecOakLastSignIn -User $u) -or $last -lt $now.AddDays(-365)) })
                if ($untested.Count) {
                    $findings.Add((New-SecOakFinding -Id 'ENTRA-13' -Area $area -Severity Low -BaselineControl 'Separate admin accounts' `
                                -Title 'Emergency access accounts not signed in for over a year' `
                                -Evidence ([ordered]@{ accounts = $untested.Count; examples = (Select-SecOakExample @($untested | ForEach-Object { & $describeUser $_ })) }) `
                                -Risk 'Credentials that are never tested may have expired, been changed or been lost; the emergency door might not open when it is needed.' `
                                -Recommendation 'Sign in with each emergency access account at least every 90 days as a test and record the result.'))
                }
            }
        }

        #--- ENTRA-14 hygiene: stale report-only, admin session controls, registration protection
        $staleReportOnly = @($reportOnlyPolicies | Where-Object { $_.modified -and $_.modified -lt $now.AddDays(-30) })
        if ($staleReportOnly.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-14' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Report-only conditional access policies left unchanged for over 30 days' `
                        -Evidence ([ordered]@{ policies = $staleReportOnly.Count; examples = (Select-SecOakExample @($staleReportOnly | ForEach-Object { '{0} (modified {1:yyyy-MM-dd})' -f $_.name, $_.modified })) }) `
                        -Risk 'Report-only policies protect nothing. A policy parked in this state usually means a planned protection was never switched on.' `
                        -Recommendation 'Review the report-only results, then enable each policy or delete it.'))
        }
        $adminSession = @($enabledPolicies | Where-Object { $_.targetsAdmins -and ($_.signInFrequency -or $_.persistentNever) })
        if (-not $adminSession.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-14' -Area $area -Severity Low -BaselineControl 'Separate admin accounts' `
                        -Title 'No sign-in frequency or non-persistent browser session for administrators' `
                        -Evidence ([ordered]@{ enabledPoliciesTargetingAdminRoles = @($enabledPolicies | Where-Object targetsAdmins).Count; withSessionControls = 0 }) `
                        -Risk 'An administrator browser session stays valid for days, so a stolen session cookie keeps working long after the password is changed.' `
                        -Recommendation 'Add a policy for directory roles with sign-in frequency of a few hours and "Persistent browser session: Never".'))
        }
        $registrationProtected = @($described | Where-Object { $_.state -ne 'disabled' -and ($_.userActions -contains 'urn:user:registersecurityinfo') })
        if (-not $registrationProtected.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-14' -Area $area -Severity Low -BaselineControl 'Multifactor for every user' `
                        -Title 'Registering security information is not protected by conditional access' `
                        -Evidence ([ordered]@{ policiesTargetingRegisterSecurityInfo = 0 }) `
                        -Risk 'Someone with a stolen password can register their own phone as the multifactor method before the real user does.' `
                        -Recommendation 'Create a policy on the user action "Register security information" that requires multifactor or a trusted location, or use a Temporary Access Pass for onboarding.'))
        }
    }
    elseif ($conditional.Success -and -not $p1) {
        Add-SecOakEntraLicenceGap -Context $Context -Area $area -Check 'Entra/ConditionalAccess' -What 'ENTRA-11, 13, 14 conditional access depth' -Licence 'Microsoft Entra ID P1'
    }

    #--- ENTRA-15 to ENTRA-17 Privileged Identity Management role settings
    Write-Verbose 'Entra: Privileged Identity Management role settings'
    if ($p2 -or $governance) {
        $pimPolicies = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/RoleManagementPolicies' -RawName 'entra-role-management-policies' `
            -Path "/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&`$expand=policy(`$expand=rules)"
        if ($pimPolicies.Success -and $roles.EligibleCount -gt 0) {
            $topRoles = @{ $script:GlobalAdminTemplateId = 'Global Administrator' }
            $praTemplate = $roles.TemplateIds['Privileged Role Administrator']
            if ($praTemplate) { $topRoles[$praTemplate] = 'Privileged Role Administrator' }
            $summary.privilegedIdentityManagement = [ordered]@{ rolePolicies = @($pimPolicies.Items).Count; eligibleAssignments = $roles.EligibleCount }
            foreach ($assignment in @($pimPolicies.Items | Where-Object { $topRoles.ContainsKey("$($_.roleDefinitionId)") })) {
                $roleName = $topRoles["$($assignment.roleDefinitionId)"]
                $rules = @{}
                foreach ($rule in @($assignment.policy.rules)) { $rules[$rule.id] = $rule }
                $enablement = $rules['Enablement_EndUser_Assignment']
                $authContext = $rules['AuthenticationContext_EndUser_Assignment']
                $enabledRules = @($enablement.enabledRules)
                if ($enablement -and ($enabledRules -notcontains 'MultiFactorAuthentication') -and -not ($authContext -and $authContext.isEnabled)) {
                    $findings.Add((New-SecOakFinding -Id 'ENTRA-15' -Area $area -Severity High -BaselineControl 'Multifactor for every user' `
                                -Title "Activating $roleName does not require multifactor authentication" `
                                -Evidence ([ordered]@{ role = $roleName; enabledRules = $enabledRules; authenticationContext = [bool]($authContext -and $authContext.isEnabled) }) `
                                -Risk 'An eligible administrator can turn on the most powerful role with only a password session, which removes the main benefit of just-in-time access.' `
                                -Recommendation "In Privileged Identity Management, edit the $roleName role settings and require multifactor authentication (or an authentication context) on activation."))
                }
                $expiration = $rules['Expiration_EndUser_Assignment']
                $maxDuration = ConvertTo-SecOakEntraTimeSpan -Value "$($expiration.maximumDuration)"
                if ($maxDuration -and $maxDuration -gt [timespan]::FromHours(8)) {
                    $findings.Add((New-SecOakFinding -Id 'ENTRA-15' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                                -Title "$roleName activations can last longer than 8 hours" `
                                -Evidence ([ordered]@{ role = $roleName; maximumDuration = $expiration.maximumDuration }) `
                                -Risk 'Long activations keep the powerful role live overnight, widening the window in which a compromised session can be abused.' `
                                -Recommendation "Set the maximum activation duration for $roleName to 8 hours or less."))
                }
                if ($enablement -and ($enabledRules -notcontains 'Justification')) {
                    $findings.Add((New-SecOakFinding -Id 'ENTRA-15' -Area $area -Severity Low -BaselineControl 'None' `
                                -Title "Activating $roleName does not require a justification" `
                                -Evidence ([ordered]@{ role = $roleName; enabledRules = $enabledRules }) `
                                -Risk 'Without a reason recorded per activation, nobody can tell routine use from misuse when reviewing the audit log.' `
                                -Recommendation "Require a justification on activation of $roleName."))
                }
                $permanent = @('Expiration_Admin_Eligibility', 'Expiration_Admin_Assignment' | Where-Object { $rules[$_] -and "$($rules[$_].isExpirationRequired)" -eq 'False' })
                if ($permanent.Count) {
                    $findings.Add((New-SecOakFinding -Id 'ENTRA-16' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                                -Title "Permanent $roleName assignments are allowed" `
                                -Evidence ([ordered]@{ role = $roleName; rulesWithoutExpiry = $permanent }) `
                                -Risk 'Assignments that never expire are never re-justified, so people keep the role long after their job changed.' `
                                -Recommendation "Require an expiry on eligible and active $roleName assignments (for example one year) so they come up for review."))
                }
                $approval = $rules['Approval_EndUser_Assignment']
                if ($roleName -eq 'Global Administrator' -and $approval -and "$($approval.setting.isApprovalRequired)" -eq 'False') {
                    $findings.Add((New-SecOakFinding -Id 'ENTRA-16' -Area $area -Severity Low -BaselineControl 'Separate admin accounts' `
                                -Title 'Global Administrator activation needs no approval' `
                                -Evidence ([ordered]@{ role = $roleName; isApprovalRequired = $false }) `
                                -Risk 'A single person can grant themselves full control at any time without a second pair of eyes.' `
                                -Recommendation 'Require approval for Global Administrator activation where the business has more than one administrator; keep the emergency access accounts outside Privileged Identity Management.'))
                }
                $notification = $rules['Notification_Admin_EndUser_Assignment']
                if ($roleName -eq 'Global Administrator' -and $notification -and "$($notification.isDefaultRecipientsEnabled)" -eq 'False' -and -not @($notification.notificationRecipients).Count) {
                    $findings.Add((New-SecOakFinding -Id 'ENTRA-17' -Area $area -Severity Low -BaselineControl 'None' `
                                -Title 'Nobody is notified when Global Administrator is activated' `
                                -Evidence ([ordered]@{ role = $roleName; isDefaultRecipientsEnabled = $false; notificationRecipients = 0 }) `
                                -Risk 'An attacker activating the role from a compromised eligible account raises no alert.' `
                                -Recommendation 'Enable the default recipients or add a monitored mailbox to the activation notification for Global Administrator.'))
                }
            }
        }
        elseif ($pimPolicies.Success) {
            $summary.privilegedIdentityManagement = [ordered]@{ rolePolicies = @($pimPolicies.Items).Count; eligibleAssignments = $roles.EligibleCount; note = 'No eligible assignments: Privileged Identity Management is not in use, so role settings are not scored.' }
        }
    }
    else { Add-SecOakEntraLicenceGap -Context $Context -Area $area -Check 'Entra/RoleManagementPolicies' -What 'ENTRA-15 to 17 Privileged Identity Management role settings' -Licence 'Microsoft Entra ID P2 or Entra ID Governance' }

    #--- ENTRA-18 and ENTRA-19 access reviews
    Write-Verbose 'Entra: access reviews'
    $reviews = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/AccessReviews' -Path '/identityGovernance/accessReviews/definitions?$top=100' -RawName 'entra-access-review-definitions'
    if ($reviews.Success) {
        if ($p2 -or $governance) {
            $definitions = @($reviews.Items)
            $active = @($definitions | Where-Object { "$($_.status)" -ne 'Completed' })
            $guestReviews = @($active | Where-Object { "$($_.scope.query)" -match "userType eq 'Guest'" -or "$($_.scope.queryType)" -match 'Guest' -or "$($_.displayName)" -match 'guest' })
            $roleReviews = @($active | Where-Object { "$($_.scope.query)" -match 'roleManagement|directoryRole' -or "$($_.scope.'@odata.type')" -match 'principalResourceMembershipsScope' -and "$($_.scope.resourceScopes.query)" -match 'roleManagement' })
            $oneOff = @($definitions | Where-Object { -not $_.settings.recurrence -or -not $_.settings.recurrence.pattern })
            $summary.accessReviews = [ordered]@{ definitions = $definitions.Count; active = $active.Count; guestReviews = $guestReviews.Count; privilegedRoleReviews = $roleReviews.Count; oneOff = $oneOff.Count }
            if ($guests.Count -and -not $guestReviews.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-18' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'No recurring access review for guest users' `
                            -Evidence ([ordered]@{ guests = $guests.Count; activeGuestReviews = 0 }) `
                            -Risk 'Guests keep access to files and Teams indefinitely because nobody is asked whether they still need it.' `
                            -Recommendation 'Create a quarterly access review of all guest users, reviewed by group or resource owners, that removes access when nobody responds.'))
            }
            if (-not $roleReviews.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-18' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                            -Title 'No recurring access review for privileged role assignments' `
                            -Evidence ([ordered]@{ activePrivilegedRoleReviews = 0; privilegedUsers = $privilegedUserIds.Count }) `
                            -Risk 'Administrator roles are never re-justified, so access collects over time and leavers or role changes are missed.' `
                            -Recommendation 'Create a quarterly access review of Global Administrator and other privileged roles in Privileged Identity Management.'))
            }
            if ($oneOff.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-18' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Access reviews that run only once' `
                            -Evidence ([ordered]@{ oneOffReviews = $oneOff.Count; examples = (Select-SecOakExample $oneOff.displayName) }) `
                            -Risk 'A one-off review cleans up once; access grows back without a schedule.' `
                            -Recommendation 'Set these reviews to recur quarterly or semi-annually.'))
            }
            $noAutoApply = @($active | Where-Object { "$($_.settings.autoApplyDecisionsEnabled)" -eq 'False' })
            $noDefault = @($guestReviews | Where-Object { "$($_.settings.defaultDecision)" -in 'None', '' })
            if ($noAutoApply.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-19' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Access reviews do not apply their results automatically' `
                            -Evidence ([ordered]@{ reviews = $noAutoApply.Count; examples = (Select-SecOakExample $noAutoApply.displayName) }) `
                            -Risk 'Decisions to remove access sit unapplied until an administrator remembers to apply them.' `
                            -Recommendation 'Enable "Auto apply results to resource" on each review.'))
            }
            if ($noDefault.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-19' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Guest access reviews keep access when reviewers do not respond' `
                            -Evidence ([ordered]@{ reviews = $noDefault.Count; examples = (Select-SecOakExample $noDefault.displayName) }) `
                            -Risk 'If the reviewer ignores the request, the guest keeps access, so the review changes nothing.' `
                            -Recommendation 'Set "If reviewers don''t respond" to "Remove access" for guest reviews.'))
            }
            $lateRecurring = [System.Collections.Generic.List[string]]::new()
            foreach ($definition in @($active | Where-Object { $_.settings.recurrence -and $_.settings.recurrence.pattern } | Select-Object -First 20)) {
                $instances = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/AccessReviews' -NoGap -NoPaging `
                    -Path "/identityGovernance/accessReviews/definitions/$($definition.id)/instances?`$filter=status eq 'Completed'&`$top=10"
                if (-not $instances.Success) { continue }
                $latest = @($instances.Items | ForEach-Object { ConvertTo-SecOakUtcDate $_.endDateTime } | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1)
                if ($latest.Count -and $latest[0] -lt $now.AddDays(-120)) { $lateRecurring.Add("$($definition.displayName) (last completed $($latest[0].ToString('yyyy-MM-dd')))") }
            }
            if ($lateRecurring.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-19' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Recurring access reviews with no completed instance in 120 days' `
                            -Evidence ([ordered]@{ reviews = $lateRecurring.Count; examples = (Select-SecOakExample $lateRecurring.ToArray()) }) `
                            -Risk 'The review exists on paper but is not completing, so access is not actually being re-checked.' `
                            -Recommendation 'Check the reviewers and the recurrence, and chase incomplete instances.'))
            }
        }
        else { Add-SecOakEntraLicenceGap -Context $Context -Area $area -Check 'Entra/AccessReviews' -What 'ENTRA-18, 19 access reviews' -Licence 'Microsoft Entra ID P2 or Entra ID Governance' }
    }

    #--- ENTRA-20 and ENTRA-21 cross-tenant access
    Write-Verbose 'Entra: cross-tenant access'
    $allowsAll = {
        param($setting)
        $usersAll = ("$($setting.usersAndGroups.accessType)" -eq 'allowed') -and [bool](@($setting.usersAndGroups.targets) | Where-Object { $_.target -eq 'AllUsers' })
        $appsAll = ("$($setting.applications.accessType)" -eq 'allowed') -and [bool](@($setting.applications.targets) | Where-Object { $_.target -eq 'AllApplications' })
        $usersAll -and $appsAll
    }
    $crossDefault = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/CrossTenantAccess' -Path '/policies/crossTenantAccessPolicy/default' -RawName 'entra-cross-tenant-default'
    if ($crossDefault.Success) {
        $d = $crossDefault.Body
        $directConnectOpen = & $allowsAll $d.b2bDirectConnectInbound
        $summary.crossTenantDefault = [ordered]@{
            isServiceDefault           = [bool]$d.isServiceDefault
            b2bDirectConnectInboundOpen = $directConnectOpen
            inboundMfaAccepted         = [bool]$d.inboundTrust.isMfaAccepted
            automaticConsentInbound    = [bool]$d.automaticUserConsentSettings.inboundAllowed
        }
        if ($directConnectOpen) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-20' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'B2B direct connect is open to all external users and applications by default' `
                        -Evidence ([ordered]@{ b2bDirectConnectInbound = 'all users, all applications' }) `
                        -Risk 'People from any Microsoft 365 tenant can be added to shared Teams channels without a guest account, so the usual guest controls and reviews do not apply.' `
                        -Recommendation 'Set the default inbound B2B direct connect to blocked and allow it per partner organisation only.'))
        }
        if ($d.inboundTrust.isMfaAccepted) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-20' -Area $area -Severity Low -BaselineControl 'Multifactor for every user' `
                        -Title 'Multifactor from any external tenant is trusted by default' `
                        -Evidence ([ordered]@{ inboundTrustIsMfaAccepted = $true }) `
                        -Risk 'Guests satisfy your multifactor policies with whatever their home tenant did, which you cannot see or verify.' `
                        -Recommendation 'Trust external multifactor only for named partner organisations, not in the default settings.'))
        }
        if ($d.automaticUserConsentSettings.inboundAllowed) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-20' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Automatic invitation redemption is enabled for all tenants by default' `
                        -Evidence ([ordered]@{ automaticUserConsentInboundAllowed = $true }) `
                        -Risk 'Guests from any tenant skip the consent prompt on first sign-in, removing a small but useful checkpoint.' `
                        -Recommendation 'Enable automatic redemption only for specific partner organisations.'))
        }
    }
    $partners = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/CrossTenantAccess' -RawName 'entra-cross-tenant-partners' `
        -Path '/policies/crossTenantAccessPolicy/partners?$select=tenantId,inboundTrust,b2bCollaborationInbound,b2bDirectConnectInbound,b2bDirectConnectOutbound,automaticUserConsentSettings,isServiceProvider'
    if ($partners.Success) {
        $partnerList = @($partners.Items)
        $directOpen = @($partnerList | Where-Object { $_.b2bDirectConnectInbound -and (& $allowsAll $_.b2bDirectConnectInbound) })
        $deviceTrust = @($partnerList | Where-Object { $_.inboundTrust -and ($_.inboundTrust.isCompliantDeviceAccepted -or $_.inboundTrust.isHybridAzureADJoinedDeviceAccepted) })
        $autoConsent = @($partnerList | Where-Object { $_.automaticUserConsentSettings -and $_.automaticUserConsentSettings.inboundAllowed })
        $summary.crossTenantPartners = [ordered]@{ partners = $partnerList.Count; serviceProviders = @($partnerList | Where-Object isServiceProvider).Count; directConnectOpen = $directOpen.Count; deviceTrust = $deviceTrust.Count; automaticConsent = $autoConsent.Count }
        if ($directOpen.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-21' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Partner organisations with B2B direct connect open to all users and applications' `
                        -Evidence ([ordered]@{ partners = $directOpen.Count }) `
                        -Risk 'Everyone in these partner tenants can join shared channels without a guest account or review.' `
                        -Recommendation 'Limit direct connect per partner to specific groups and applications.'))
        }
        $tenantUsesDeviceCompliance = [bool](@($enabledPolicies | Where-Object requiresDevice).Count)
        if ($deviceTrust.Count -and -not $tenantUsesDeviceCompliance) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-21' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Partner device compliance is trusted while the tenant does not use device compliance itself' `
                        -Evidence ([ordered]@{ partners = $deviceTrust.Count }) `
                        -Risk 'Trusting another organisation''s device claims has no benefit here and widens what an attacker in that tenant can present.' `
                        -Recommendation 'Remove the compliant and hybrid-joined device trust from these partner settings.'))
        }
        if ($autoConsent.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-21' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Partner organisations with automatic invitation redemption' `
                        -Evidence ([ordered]@{ partners = $autoConsent.Count }) `
                        -Risk 'Users from these tenants are added silently; confirm each is an active partner.' `
                        -Recommendation 'Keep automatic redemption only for partners with an active contract and review the list yearly.'))
        }
    }

    #--- ENTRA-22 and ENTRA-24 authorization policy and self-service sign-up
    Write-Verbose 'Entra: authorization policy and consent'
    $authorization = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/AuthorizationPolicy' -Path '/policies/authorizationPolicy' -RawName 'entra-authorization-policy'
    $authorizationPolicy = $null
    $consentPolicies = @()
    if ($authorization.Success) {
        $authorizationPolicy = $authorization.Body
        if ($authorizationPolicy.PSObject.Properties['value']) { $authorizationPolicy = @($authorizationPolicy.value)[0] }
        $consentPolicies = @($authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
        $summary.externalIdentities = [ordered]@{ allowInvitesFrom = $authorizationPolicy.allowInvitesFrom }
        if ("$($authorizationPolicy.allowInvitesFrom)" -eq 'adminsGuestInvitersAndAllMembers') {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-22' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Every member can invite guests' `
                        -Evidence ([ordered]@{ allowInvitesFrom = $authorizationPolicy.allowInvitesFrom }) `
                        -Risk 'Any employee can bring outside accounts into the tenant without approval, so guest sprawl is hard to control.' `
                        -Recommendation 'Restrict invitations to administrators and the Guest Inviter role, and route requests through a short approval step.'))
        }
        $summary.userConsent = [ordered]@{ permissionGrantPoliciesAssigned = $consentPolicies }
        if ($consentPolicies -match 'user-default-low') {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-24' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Users can consent to verified-publisher applications with low-impact permissions' `
                        -Evidence ([ordered]@{ permissionGrantPoliciesAssigned = $consentPolicies }) `
                        -Risk 'This is the recommended middle ground; the residual risk is that low-impact permissions such as reading a profile can still be used for phishing lures.' `
                        -Recommendation 'Keep this setting, or disable user consent entirely and rely on the admin consent workflow if the business prefers full control.'))
        }
    }
    $flows = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/AuthenticationFlows' -Path '/policies/authenticationFlowsPolicy' -RawName 'entra-authentication-flows'
    if ($flows.Success) {
        $selfService = [bool]$flows.Body.selfServiceSignUp.isEnabled
        if ($summary.Contains('externalIdentities')) { $summary.externalIdentities.selfServiceSignUp = $selfService } else { $summary.externalIdentities = [ordered]@{ selfServiceSignUp = $selfService } }
        if ($selfService) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-22' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Self-service sign-up for external users is enabled' `
                        -Evidence ([ordered]@{ selfServiceSignUpEnabled = $true }) `
                        -Risk 'Outside users can create guest accounts through a sign-up flow without an invitation.' `
                        -Recommendation 'Disable self-service sign-up unless a specific application user flow needs it.'))
        }
    }

    #--- ENTRA-23 external collaboration domain restrictions (beta, unstable)
    $b2b = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/B2BManagementPolicy' -Path '/policies/b2bManagementPolicies' -ApiVersion beta -NoGap -RawName 'entra-b2b-management-policies'
    if ($b2b.Success) {
        $b2bPolicy = if ($b2b.Items) { $b2b.Items | Select-Object -First 1 } else { $b2b.Body }
        $domainPolicy = $b2bPolicy.invitationsAllowedAndBlockedDomainsPolicy
        $allowed = @($domainPolicy.allowedDomains)
        $blocked = @($domainPolicy.blockedDomains)
        $summary.collaborationDomains = [ordered]@{ allowedDomains = $allowed.Count; blockedDomains = $blocked.Count; source = 'beta endpoint' }
        if (-not $allowed.Count -and -not $blocked.Count -and $guests.Count -gt 20) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-23' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Guest invitations are allowed to any domain' `
                        -Evidence ([ordered]@{ guests = $guests.Count; allowedDomains = 0; blockedDomains = 0 }) `
                        -Risk 'Invitations can go to personal mail providers, where the account security is unknown and the person may not be who they claim.' `
                        -Recommendation 'Block consumer domains (for example gmail.com and outlook.com) or allow only known partner domains in the external collaboration settings.'))
        }
    }
    else {
        Add-SecOakGap -Context $Context -Area $area -Check 'Entra/B2BManagementPolicy' -EndpointOrCmdlet '/beta/policies/b2bManagementPolicies' -Result 'not assessed' `
            -Reason "Beta endpoint unavailable ($($b2b.StatusCode) $($b2b.ErrorCode)); treated as not assessed, never as a finding." -FillWith 'Check the external collaboration domain list in the Entra admin center manually.'
    }

    #--- ENTRA-25 permission grant policies
    $grantPolicies = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/PermissionGrantPolicies' -Path '/policies/permissionGrantPolicies' -RawName 'entra-permission-grant-policies'
    if ($grantPolicies.Success) {
        $customPolicies = @($grantPolicies.Items | Where-Object { "$($_.id)" -notlike 'microsoft-*' })
        $riskyCustom = [System.Collections.Generic.List[string]]::new()
        foreach ($customPolicy in $customPolicies) {
            $includes = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/PermissionGrantPolicies' -Path "/policies/permissionGrantPolicies/$($customPolicy.id)/includes"
            if (-not $includes.Success) { continue }
            $assigned = [bool]($consentPolicies | Where-Object { $_ -like "*$($customPolicy.id)" })
            $broad = @($includes.Items | Where-Object { "$($_.permissionType)" -eq 'delegated' -and "$($_.permissionClassification)" -eq 'all' -and "$($_.clientApplicationsFromVerifiedPublisherOnly)" -ne 'True' -and (@($_.permissions) -contains 'all') })
            if ($assigned -and $broad.Count) { $riskyCustom.Add("$($customPolicy.displayName)") }
        }
        $summary.permissionGrantPolicies = [ordered]@{ builtIn = @($grantPolicies.Items).Count - $customPolicies.Count; custom = $customPolicies.Count; customAssignedAndBroad = $riskyCustom.Count }
        if ($riskyCustom.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-25' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Custom consent policy lets users grant any permission to unverified applications' `
                        -Evidence ([ordered]@{ policies = $riskyCustom.Count; examples = (Select-SecOakExample $riskyCustom.ToArray()) }) `
                        -Risk 'A custom policy this wide is equivalent to the legacy "allow everything" user consent, so consent phishing succeeds.' `
                        -Recommendation 'Restrict the policy to verified publishers and low-impact permissions, or replace it with the built-in low-impact policy.'))
        }
    }

    #--- ENTRA-26 admin consent workflow
    $consentRequest = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/AdminConsentWorkflow' -Path '/policies/adminConsentRequestPolicy' -RawName 'entra-admin-consent-request-policy'
    if ($consentRequest.Success) {
        $workflow = $consentRequest.Body
        $summary.adminConsentWorkflow = [ordered]@{ isEnabled = [bool]$workflow.isEnabled; reviewers = @($workflow.reviewers).Count; requestDurationInDays = $workflow.requestDurationInDays }
        if ($authorization.Success -and -not $consentPolicies.Count -and -not $workflow.isEnabled) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-26' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'User consent is disabled but there is no admin consent workflow' `
                        -Evidence ([ordered]@{ userConsentPolicies = 0; adminConsentWorkflowEnabled = $false }) `
                        -Risk 'Users who need an application are blocked with no way to ask, which pushes them to personal accounts or shadow tools.' `
                        -Recommendation 'Enable the admin consent workflow with at least one reviewer so requests reach an administrator.'))
        }
        elseif ($workflow.isEnabled -and (-not @($workflow.reviewers).Count -or [int]$workflow.requestDurationInDays -eq 0)) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-26' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Admin consent workflow has no reviewers or no request duration' `
                        -Evidence ([ordered]@{ reviewers = @($workflow.reviewers).Count; requestDurationInDays = $workflow.requestDurationInDays }) `
                        -Risk 'Requests are created but nobody receives them, or they never expire.' `
                        -Recommendation 'Assign a reviewer (an administrator or a group) and a request duration of 7 to 30 days.'))
        }
    }

    #--- ENTRA-27 domains
    Write-Verbose 'Entra: domains and password protection'
    $domains = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/Domains' -Path '/domains?$select=id,isVerified,isInitial,authenticationType,passwordValidityPeriodInDays,passwordNotificationWindowInDays' -RawName 'entra-domains'
    if ($domains.Success) {
        $verified = @($domains.Items | Where-Object isVerified)
        $federated = @($verified | Where-Object authenticationType -eq 'Federated')
        $expiring = @($verified | Where-Object { $_.authenticationType -eq 'Managed' -and $null -ne $_.passwordValidityPeriodInDays -and [int64]$_.passwordValidityPeriodInDays -ne 2147483647 })
        $summary.domains = [ordered]@{ verified = $verified.Count; federated = $federated.Count; withPasswordExpiry = $expiring.Count }
        if ($federated.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-27' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Federated domains' `
                        -Evidence ([ordered]@{ federatedDomains = $federated.Count }) `
                        -Risk 'Sign-in for these domains is decided by an external identity server. If it is compromised or misconfigured, the attacker can mint sign-ins for any user in the domain.' `
                        -Recommendation 'Confirm the federation is still needed; otherwise convert the domain to managed with password hash synchronisation or cloud-only accounts.'))
        }
        if ($expiring.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-27' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Passwords expire periodically' `
                        -Evidence ([ordered]@{ domains = $expiring.Count; examples = (Select-SecOakExample @($expiring | ForEach-Object { '{0} days' -f $_.passwordValidityPeriodInDays })) }) `
                        -Risk 'Forced rotation leads to predictable passwords (adding a number) and more help desk resets, without stopping attackers who use a password immediately.' `
                        -Recommendation 'Set passwords to never expire once multifactor is enforced for everyone, and rely on banned-password checks and risk detection instead.'))
        }
    }

    #--- ENTRA-28 password protection and smart lockout
    $groupSettings = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/PasswordProtection' -Path '/groupSettings' -RawName 'entra-group-settings'
    $syncEnabled = $false
    $organization = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/DirectorySync' -Path '/organization?$select=id,displayName,onPremisesSyncEnabled,onPremisesLastSyncDateTime,onPremisesLastPasswordSyncDateTime' -RawName 'entra-organization'
    if ($organization.Success) { $syncEnabled = [bool](@($organization.Items) | Select-Object -First 1).onPremisesSyncEnabled }
    if ($groupSettings.Success) {
        $passwordRules = @($groupSettings.Items | Where-Object templateId -eq '5cf42378-d67d-4f36-ba46-e8b86229381d') | Select-Object -First 1
        if ($passwordRules) {
            $values = @{}
            foreach ($value in @($passwordRules.values)) { $values[$value.name] = "$($value.value)" }
            $summary.passwordProtection = [ordered]@{
                bannedPasswordCheck        = $values['EnableBannedPasswordCheck']
                customBannedListEntries    = @(($values['BannedPasswordList'] -split "`t") | Where-Object { $_ }).Count
                lockoutThreshold           = $values['LockoutThreshold']
                lockoutDurationSeconds     = $values['LockoutDurationInSeconds']
                onPremisesCheck            = $values['EnableBannedPasswordCheckOnPremises']
                onPremisesMode             = $values['BannedPasswordCheckOnPremisesMode']
            }
            if ($p1 -and ($values['EnableBannedPasswordCheck'] -eq 'False' -or -not $values['BannedPasswordList'])) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-28' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'No custom banned password list' `
                            -Evidence ([ordered]@{ enableBannedPasswordCheck = $values['EnableBannedPasswordCheck']; customEntries = $summary.passwordProtection.customBannedListEntries }) `
                            -Risk 'Users can still choose the company name, product names or the town as their password, which attackers guess first.' `
                            -Recommendation 'Add the company name, brands, local terms and seasons to the custom banned password list.'))
            }
            $threshold = 0
            if ([int]::TryParse($values['LockoutThreshold'], [ref]$threshold) -and $threshold -gt 10) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-28' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Smart lockout threshold is above 10 attempts' `
                            -Evidence ([ordered]@{ lockoutThreshold = $threshold }) `
                            -Risk 'More guesses per account before lockout make password spraying cheaper.' `
                            -Recommendation 'Set the lockout threshold to 10 or fewer failed attempts.'))
            }
            if ($syncEnabled -and ($values['EnableBannedPasswordCheckOnPremises'] -eq 'False' -or $values['BannedPasswordCheckOnPremisesMode'] -eq 'Audit')) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-28' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Password protection is not enforced for on-premises Active Directory' `
                            -Evidence ([ordered]@{ enableBannedPasswordCheckOnPremises = $values['EnableBannedPasswordCheckOnPremises']; mode = $values['BannedPasswordCheckOnPremisesMode'] }) `
                            -Risk 'Passwords set on the domain controllers bypass the banned list and synchronise to the cloud.' `
                            -Recommendation 'Deploy the password protection proxy and agent on the domain controllers and set the mode to Enforced.'))
            }
        }
        else {
            $summary.passwordProtection = [ordered]@{ note = 'No Password Rule Settings object: defaults apply (global banned list, lockout threshold 10, duration 60 seconds).' }
        }
    }

    #--- ENTRA-29 self-service password reset reach
    Write-Verbose 'Entra: self-service password reset registration'
    if ($p1) {
        $registration = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/SelfServicePasswordReset' -Path '/reports/authenticationMethods/userRegistrationDetails' -RawName 'entra-registration-details'
        if ($registration.Success) {
            $rows = @($registration.Items | Where-Object userType -ne 'guest')
            if ($Context.Cache.UsersAvailable) { $enabledIds = [System.Collections.Generic.HashSet[string]]::new([string[]]@($enabledMembers.id)); $rows = @($rows | Where-Object { $enabledIds.Contains([string]$_.id) }) }
            $ssprEnabled = @($rows | Where-Object isSsprEnabled)
            $notCapable = @($ssprEnabled | Where-Object { -not $_.isSsprCapable })
            $enabledPercent = if ($rows.Count) { [math]::Round(100 * $ssprEnabled.Count / $rows.Count, 1) } else { 0 }
            $notCapablePercent = if ($ssprEnabled.Count) { [math]::Round(100 * $notCapable.Count / $ssprEnabled.Count, 1) } else { 0 }
            $summary.selfServicePasswordReset = [ordered]@{ usersInScope = $rows.Count; ssprEnabled = $ssprEnabled.Count; ssprEnabledPercent = $enabledPercent; enabledButNotCapable = $notCapable.Count }
            if ($rows.Count -and $enabledPercent -lt 10) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-29' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Self-service password reset reaches few users' `
                            -Evidence ([ordered]@{ ssprEnabledPercent = $enabledPercent; usersInScope = $rows.Count; method = 'Inferred from registration details; the tenant setting itself has no Graph read.' }) `
                            -Risk 'Users must call someone to reset a password, which invites social engineering of the help desk and slows recovery.' `
                            -Recommendation 'Enable self-service password reset for all users with two methods required, and combine it with multifactor registration.'))
            }
            if ($ssprEnabled.Count -and $notCapablePercent -gt 25) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-29' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Many users enabled for self-service password reset have not registered enough methods' `
                            -Evidence ([ordered]@{ enabledButNotCapable = $notCapable.Count; percent = $notCapablePercent; examples = (Select-SecOakExample $notCapable.userPrincipalName) }) `
                            -Risk 'The feature is on but these users cannot use it when locked out.' `
                            -Recommendation 'Run a registration campaign and require registration at next sign-in through conditional access.'))
            }
        }
    }
    else { Add-SecOakEntraLicenceGap -Context $Context -Area $area -Check 'Entra/SelfServicePasswordReset' -What 'ENTRA-29 self-service password reset reach (userRegistrationDetails)' -Licence 'Microsoft Entra ID P1' }

    #--- ENTRA-31 disabled accounts with licences or roles
    Write-Verbose 'Entra: disabled accounts'
    if ($Context.Cache.UsersAvailable) {
        $disabled = @($users | Where-Object { -not $_.accountEnabled })
        $disabledIds = [System.Collections.Generic.HashSet[string]]::new([string[]]@($disabled.id))
        $disabledWithRoles = @($roles.Rows | Where-Object { $_.PrincipalType -eq 'user' -and $disabledIds.Contains([string]$_.PrincipalId) })
        $disabledPrivileged = @($disabledWithRoles | Where-Object Privileged)
        $disabledLicensed = @($disabled | Where-Object { @($_.assignedLicenses).Count -gt 0 })
        $summary.disabledAccounts = [ordered]@{ disabled = $disabled.Count; withDirectoryRoles = @($disabledWithRoles.PrincipalId | Select-Object -Unique).Count; withLicences = $disabledLicensed.Count }
        if ($disabledPrivileged.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-31' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                        -Title 'Disabled accounts still hold privileged directory roles' `
                        -Evidence ([ordered]@{ accounts = @($disabledPrivileged.PrincipalId | Select-Object -Unique).Count; examples = (Select-SecOakExample @($disabledPrivileged | ForEach-Object { '{0} ({1}, {2})' -f $_.Name, $_.Role, $_.Kind } | Select-Object -Unique)) }) `
                        -Risk 'If the account is re-enabled by mistake or by an attacker with user-management rights, it is instantly an administrator again.' `
                        -Recommendation 'Remove every role from disabled accounts as part of the leaver process, then delete the account after the retention period.'))
        }
        if ($disabledLicensed.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-31' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Disabled accounts still hold licences' `
                        -Evidence ([ordered]@{ accounts = $disabledLicensed.Count; examples = (Select-SecOakExample $disabledLicensed.userPrincipalName); note = 'The date the account was disabled is not readable, so the 30-day grace period is not applied.' }) `
                        -Risk 'The business pays for seats nobody uses, and the licensed mailbox and files stay live and reachable through delegates or rules.' `
                        -Recommendation 'Convert leaver mailboxes to shared mailboxes if needed, then remove the licences.'))
        }
    }

    #--- ENTRA-32 stale devices
    Write-Verbose 'Entra: directory devices'
    $devices = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/Devices' -Path '/devices?$select=id,deviceId,displayName,accountEnabled,operatingSystem,trustType,approximateLastSignInDateTime,isCompliant,isManaged,registrationDateTime&$top=999' -RawName 'entra-devices'
    $windowsDevices = @()
    $recentWindowsIds = [System.Collections.Generic.HashSet[string]]::new()
    if ($devices.Success) {
        $enabledDevices = @($devices.Items | Where-Object accountEnabled)
        $stale90 = @($enabledDevices | Where-Object { $d = ConvertTo-SecOakUtcDate $_.approximateLastSignInDateTime; $d -and $d -lt $now.AddDays(-90) })
        $silent180 = @($enabledDevices | Where-Object { -not (ConvertTo-SecOakUtcDate $_.approximateLastSignInDateTime) -and ($r = ConvertTo-SecOakUtcDate $_.registrationDateTime) -and $r -lt $now.AddDays(-180) })
        $windowsDevices = @($enabledDevices | Where-Object { $_.operatingSystem -eq 'Windows' -and $_.trustType -in 'AzureAd', 'ServerAd' })
        foreach ($device in $windowsDevices) { $d = ConvertTo-SecOakUtcDate $device.approximateLastSignInDateTime; if ($d -and $d -ge $now.AddDays(-7)) { [void]$recentWindowsIds.Add("$($device.deviceId)") } }
        $stalePercent = if ($enabledDevices.Count) { [math]::Round(100 * $stale90.Count / $enabledDevices.Count, 1) } else { 0 }
        $summary.devices = [ordered]@{ total = @($devices.Items).Count; enabled = $enabledDevices.Count; noSignIn90Days = $stale90.Count; noSignIn90DaysPercent = $stalePercent; neverActive180Days = $silent180.Count; windowsJoined = $windowsDevices.Count; byTrustType = @($enabledDevices | Group-Object trustType | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) }
        if ($stalePercent -gt 10) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-32' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'More than 10 percent of enabled devices have not signed in for 90 days' `
                        -Evidence ([ordered]@{ staleDevices = $stale90.Count; enabledDevices = $enabledDevices.Count; percent = $stalePercent; examples = (Select-SecOakExample $stale90.displayName) }) `
                        -Risk 'Stale device records clutter conditional access decisions and can keep a lost or resold device trusted.' `
                        -Recommendation 'Disable devices inactive for 90 days, delete them after a further 90, and automate the cleanup.'))
        }
        if ($silent180.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-32' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Devices registered over 180 days ago with no recorded activity' `
                        -Evidence ([ordered]@{ devices = $silent180.Count; examples = (Select-SecOakExample $silent180.displayName) }) `
                        -Risk 'These are probably failed enrolments or retired hardware still present in the directory.' `
                        -Recommendation 'Disable and then delete these device objects.'))
        }
    }

    #--- ENTRA-33 application registration credentials
    Write-Verbose 'Entra: application and service principal credentials'
    $applications = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/ApplicationCredentials' -Path '/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials,createdDateTime&$top=999' -RawName 'entra-applications'
    if ($applications.Success) {
        $credentials = foreach ($app in @($applications.Items)) {
            foreach ($secret in @($app.passwordCredentials)) { if ($secret) { [pscustomobject]@{ App = $app.displayName; Type = 'secret'; Start = ConvertTo-SecOakUtcDate $secret.startDateTime; End = ConvertTo-SecOakUtcDate $secret.endDateTime } } }
            foreach ($key in @($app.keyCredentials)) { if ($key) { [pscustomobject]@{ App = $app.displayName; Type = 'certificate'; Start = ConvertTo-SecOakUtcDate $key.startDateTime; End = ConvertTo-SecOakUtcDate $key.endDateTime } } }
        }
        $credentials = @($credentials)
        $longLived = @($credentials | Where-Object { $_.Type -eq 'secret' -and $_.Start -and $_.End -and ($_.End - $_.Start).TotalDays -gt 365 })
        $expiringSoon = @($credentials | Where-Object { $_.End -and $_.End -ge $now -and $_.End -lt $now.AddDays(30) })
        $expired = @($credentials | Where-Object { $_.End -and $_.End -lt $now })
        $summary.applicationCredentials = [ordered]@{ applications = @($applications.Items).Count; secrets = @($credentials | Where-Object Type -eq 'secret').Count; certificates = @($credentials | Where-Object Type -eq 'certificate').Count; longLivedSecrets = $longLived.Count; expiringWithin30Days = $expiringSoon.Count; expired = $expired.Count }
        if ($longLived.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-33' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Application secrets valid for more than a year' `
                        -Evidence ([ordered]@{ secrets = $longLived.Count; examples = (Select-SecOakExample @($longLived | ForEach-Object { '{0} (valid {1:yyyy-MM-dd} to {2:yyyy-MM-dd})' -f $_.App, $_.Start, $_.End })) }) `
                        -Risk 'A secret is a password for the application. One that lives for years stays valid long after it leaks into a script, a ticket or a former contractor''s notes.' `
                        -Recommendation 'Replace long-lived secrets with certificates or managed identities; where a secret is unavoidable, limit it to 6 to 12 months and rotate.'))
        }
        if ($expiringSoon.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-33' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Application credentials expiring within 30 days' `
                        -Evidence ([ordered]@{ credentials = $expiringSoon.Count; examples = (Select-SecOakExample @($expiringSoon | ForEach-Object { '{0} ({1}, expires {2:yyyy-MM-dd})' -f $_.App, $_.Type, $_.End })) }) `
                        -Risk 'The integration stops working when the credential expires, often with no warning to the business.' `
                        -Recommendation 'Renew the credential now and record its owner and next renewal date.'))
        }
        if ($expired.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-33' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Expired credentials left on application registrations' `
                        -Evidence ([ordered]@{ credentials = $expired.Count; examples = (Select-SecOakExample @($expired | ForEach-Object { '{0} ({1}, expired {2:yyyy-MM-dd})' -f $_.App, $_.Type, $_.End })) }) `
                        -Risk 'Clutter that hides which credential is really in use and suggests nobody owns the application.' `
                        -Recommendation 'Delete expired credentials and confirm an owner for each application.'))
        }
    }

    #--- ENTRA-34 service principal credentials
    $servicePrincipals = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/ServicePrincipalCredentials' -RawName 'entra-service-principals' `
        -Path "/servicePrincipals?`$select=id,appId,displayName,appOwnerOrganizationId,servicePrincipalType,passwordCredentials,keyCredentials&`$filter=servicePrincipalType eq 'Application'&`$top=999"
    if ($servicePrincipals.Success) {
        $withSecrets = @($servicePrincipals.Items | Where-Object { @($_.passwordCredentials).Count -gt 0 })
        $firstPartyWithSecrets = @($withSecrets | Where-Object { "$($_.appOwnerOrganizationId)" -eq $microsoftFirstPartyTenantId })
        $longLivedSp = @($withSecrets | Where-Object { "$($_.appOwnerOrganizationId)" -ne $microsoftFirstPartyTenantId -and (@($_.passwordCredentials | Where-Object { ($s = ConvertTo-SecOakUtcDate $_.startDateTime) -and ($e = ConvertTo-SecOakUtcDate $_.endDateTime) -and ($e - $s).TotalDays -gt 365 }).Count) })
        $signingExpiring = @($servicePrincipals.Items | Where-Object { @($_.keyCredentials | Where-Object { "$($_.usage)" -eq 'Verify' -and ($e = ConvertTo-SecOakUtcDate $_.endDateTime) -and $e -ge $now -and $e -lt $now.AddDays(30) }).Count })
        $summary.servicePrincipalCredentials = [ordered]@{ servicePrincipals = @($servicePrincipals.Items).Count; withSecrets = $withSecrets.Count; microsoftFirstPartyWithSecrets = $firstPartyWithSecrets.Count; longLivedSecrets = $longLivedSp.Count; signingCertificatesExpiring30Days = $signingExpiring.Count }
        if ($firstPartyWithSecrets.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-34' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Credentials added to Microsoft first-party service principals' `
                        -Evidence ([ordered]@{ servicePrincipals = $firstPartyWithSecrets.Count; examples = (Select-SecOakExample $firstPartyWithSecrets.displayName) }) `
                        -Risk 'Microsoft applications never need a credential in your tenant. A secret on one is a classic persistence trick: whoever holds it signs in as that application with all its permissions, invisibly.' `
                        -Recommendation 'Treat this as a possible compromise: identify who added the credential from the audit log, remove it, and review the application''s permissions and sign-ins.'))
        }
        if ($longLivedSp.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-34' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Enterprise applications with secrets valid for more than a year' `
                        -Evidence ([ordered]@{ servicePrincipals = $longLivedSp.Count; examples = (Select-SecOakExample $longLivedSp.displayName) }) `
                        -Risk 'Secrets added directly to the enterprise application do not show on the application registration, so they are easy to overlook and live for years.' `
                        -Recommendation 'Remove secrets from the enterprise application object; manage credentials on the application registration with short lifetimes or certificates.'))
        }
        if ($signingExpiring.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-34' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Single sign-on signing certificates expiring within 30 days' `
                        -Evidence ([ordered]@{ servicePrincipals = $signingExpiring.Count; examples = (Select-SecOakExample $signingExpiring.displayName) }) `
                        -Risk 'Single sign-on to these applications will fail when the certificate expires.' `
                        -Recommendation 'Roll the signing certificate in the enterprise application and update the partner application before expiry.'))
        }
    }

    #--- ENTRA-35 directory synchronisation status
    Write-Verbose 'Entra: directory synchronisation'
    if ($organization.Success) {
        $org = @($organization.Items) | Select-Object -First 1
        $lastSync = ConvertTo-SecOakUtcDate $org.onPremisesLastSyncDateTime
        $lastPasswordSync = ConvertTo-SecOakUtcDate $org.onPremisesLastPasswordSyncDateTime
        $orphaned = @($syncById.Values | Where-Object { -not $_.onPremisesSyncEnabled -and $_.onPremisesImmutableId })
        $summary.directorySync = [ordered]@{
            onPremisesSyncEnabled = $syncEnabled
            lastSync              = if ($lastSync) { $lastSync.ToString('yyyy-MM-dd HH:mm') } else { $null }
            lastPasswordSync      = if ($lastPasswordSync) { $lastPasswordSync.ToString('yyyy-MM-dd HH:mm') } else { $null }
            orphanedSyncedUsers   = $orphaned.Count
        }
        if ($syncEnabled -and (-not $lastSync -or $lastSync -lt $now.AddHours(-24))) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-35' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Directory synchronisation has not run in the last 24 hours' `
                        -Evidence ([ordered]@{ lastSync = $summary.directorySync.lastSync }) `
                        -Risk 'Leavers disabled on-premises stay enabled in the cloud, and password changes do not reach Microsoft 365.' `
                        -Recommendation 'Check the Entra Connect or Cloud Sync server, restart the scheduler, and set up Connect Health or a monitoring alert for stalled synchronisation.'))
        }
        elseif ($syncEnabled -and $lastPasswordSync -and $lastPasswordSync -lt $now.AddHours(-24)) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-35' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Password hash synchronisation is behind' `
                        -Evidence ([ordered]@{ lastSync = $summary.directorySync.lastSync; lastPasswordSync = $summary.directorySync.lastPasswordSync }) `
                        -Risk 'Users who changed their password on-premises keep the old password in the cloud, and leaked-credential detection is delayed.' `
                        -Recommendation 'Check the password hash synchronisation status on the Entra Connect server.'))
        }
        if (-not $syncEnabled -and $orphaned.Count) {
            $summary.directorySync.note = 'Synchronisation is off but some users still carry an on-premises immutable identifier (left over from a decommissioned server).'
        }
    }

    #--- ENTRA-36 synchronised privileged accounts
    if ($roles.Available -and $Context.Cache.EntraUserSyncAvailable) {
        $syncedPrivileged = @($roles.Rows | Where-Object { $_.Privileged -and $_.PrincipalType -eq 'user' -and $syncById[$_.PrincipalId] -and $syncById[$_.PrincipalId].onPremisesSyncEnabled })
        $syncedTop = @($syncedPrivileged | Where-Object { $_.Role -in 'Global Administrator', 'Privileged Role Administrator' })
        $summary.syncedPrivilegedAccounts = [ordered]@{ accounts = @($syncedPrivileged.PrincipalId | Select-Object -Unique).Count; globalOrPrivilegedRoleAdministrators = @($syncedTop.PrincipalId | Select-Object -Unique).Count }
        if ($syncedPrivileged.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-36' -Area $area -Severity $(if ($syncedTop.Count) { 'High' } else { 'Medium' }) -BaselineControl 'Separate admin accounts' `
                        -Title 'Administrator roles held by accounts synchronised from on-premises Active Directory' `
                        -Evidence ([ordered]@{ accounts = @($syncedPrivileged.PrincipalId | Select-Object -Unique).Count; globalOrPrivilegedRoleAdministrators = @($syncedTop.PrincipalId | Select-Object -Unique).Count; examples = (Select-SecOakExample @($syncedPrivileged | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Role } | Select-Object -Unique)) }) `
                        -Risk 'Whoever controls the on-premises domain controls these cloud administrators: a ransomware operator who owns the server also owns Microsoft 365.' `
                        -Recommendation 'Use cloud-only accounts for every administrator role, especially Global Administrator, and remove roles from synchronised accounts.'))
        }
    }

    #--- ENTRA-37 dynamic membership groups
    Write-Verbose 'Entra: groups and administrative units'
    $dynamicGroups = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/DynamicGroups' -ConsistencyLevelEventual -RawName 'entra-dynamic-groups' `
        -Path "/groups?`$filter=groupTypes/any(c:c eq 'DynamicMembership')&`$select=id,displayName,membershipRule,membershipRuleProcessingState,securityEnabled,isAssignableToRole&`$count=true"
    if ($dynamicGroups.Success) {
        $dynamic = @($dynamicGroups.Items)
        $referencedGroupIds = @($described | ForEach-Object { $_.includeGroups + $_.excludeGroups } | Select-Object -Unique)
        $riskyRule = '(?i)user\.(displayName|mail\b|otherMails|proxyAddresses|userPrincipalName\s+-(contains|match|startsWith|endsWith))'
        $userEditable = @($dynamic | Where-Object { "$($_.membershipRule)" -match $riskyRule -and ($_.securityEnabled -or $_.id -in $referencedGroupIds) })
        $paused = @($dynamic | Where-Object membershipRuleProcessingState -eq 'Paused')
        $allMembers = @($dynamic | Where-Object { "$($_.membershipRule)" -match '(?i)user\.userType\s+-eq\s+"Member"' -and "$($_.membershipRule)" -notmatch '(?i)accountEnabled' })
        $summary.dynamicGroups = [ordered]@{ groups = $dynamic.Count; rulesOnUserEditableAttributes = $userEditable.Count; paused = $paused.Count; allMembersWithoutEnabledFilter = $allMembers.Count }
        if ($userEditable.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-37' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Dynamic groups whose rules use attributes users or guests can influence' `
                        -Evidence ([ordered]@{ groups = $userEditable.Count; examples = (Select-SecOakExample $userEditable.displayName) }) `
                        -Risk 'A guest or user who can set their own display name, mail or job title can place themselves in the group and inherit whatever access or policy exclusion it carries.' `
                        -Recommendation 'Base membership rules on administrator-controlled attributes (for example extension attributes or userType) and review which groups are used in conditional access.'))
        }
        if ($paused.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-37' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Dynamic groups with paused membership processing' `
                        -Evidence ([ordered]@{ groups = $paused.Count; examples = (Select-SecOakExample $paused.displayName) }) `
                        -Risk 'Membership is frozen, so leavers stay in and joiners are missing, without any visible error.' `
                        -Recommendation 'Resume processing or convert the group to assigned membership.'))
        }
        if ($allMembers.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-37' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Dynamic "all members" groups that include disabled accounts' `
                        -Evidence ([ordered]@{ groups = $allMembers.Count; examples = (Select-SecOakExample $allMembers.displayName) }) `
                        -Risk 'Disabled leaver accounts stay licensed or in scope of policies through these groups.' `
                        -Recommendation 'Add "(user.accountEnabled -eq true)" to the membership rule.'))
        }
    }

    #--- ENTRA-38 role-assignable groups
    $roleGroups = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/RoleAssignableGroups' -ConsistencyLevelEventual -RawName 'entra-role-assignable-groups' `
        -Path '/groups?$filter=isAssignableToRole eq true&$select=id,displayName,isAssignableToRole,membershipRule&$count=true'
    if ($roleGroups.Success) {
        $groupList = @($roleGroups.Items)
        $praIds = @($roles.Rows | Where-Object { $_.Role -in 'Global Administrator', 'Privileged Role Administrator' -and $_.PrincipalType -eq 'user' } | Select-Object -ExpandProperty PrincipalId -Unique)
        $badOwners = [System.Collections.Generic.List[string]]::new()
        $riskyMembers = [System.Collections.Generic.List[string]]::new()
        $groupRoles = [System.Collections.Generic.List[string]]::new()
        foreach ($group in $groupList) {
            $heldRoles = @($roles.Rows | Where-Object PrincipalId -eq $group.id | Select-Object -ExpandProperty Role -Unique)
            $groupRoles.Add(('{0}: {1}' -f $group.displayName, $(if ($heldRoles) { $heldRoles -join ', ' } else { 'no role' })))
            $owners = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/RoleAssignableGroups' -Path "/groups/$($group.id)/owners?`$select=id,userPrincipalName,displayName"
            if ($owners.Success) {
                foreach ($owner in @($owners.Items | Where-Object { $_.id -notin $praIds })) { $badOwners.Add(('{0} owns {1}' -f $(if ($owner.userPrincipalName) { $owner.userPrincipalName } else { $owner.displayName }), $group.displayName)) }
            }
            $members = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/RoleAssignableGroups' -Path "/groups/$($group.id)/members?`$select=id,userPrincipalName,userType,accountEnabled"
            if ($members.Success) {
                foreach ($member in @($members.Items | Where-Object { $_.userType -eq 'Guest' -or ("$($_.accountEnabled)" -eq 'False') })) { $riskyMembers.Add(('{0} in {1} ({2})' -f $member.userPrincipalName, $group.displayName, $(if ($member.userType -eq 'Guest') { 'guest' } else { 'disabled' }))) }
            }
        }
        $summary.roleAssignableGroups = [ordered]@{ groups = $groupList.Count; groupRoles = $groupRoles.ToArray(); ownersOutsidePrivilegedRoleAdministrators = $badOwners.Count; guestOrDisabledMembers = $riskyMembers.Count }
        if ($badOwners.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-38' -Area $area -Severity High -BaselineControl 'Separate admin accounts' `
                        -Title 'Role-assignable groups owned by accounts that are not Global or Privileged Role Administrators' `
                        -Evidence ([ordered]@{ owners = $badOwners.Count; examples = (Select-SecOakExample $badOwners.ToArray()) }) `
                        -Risk 'A group owner can add anyone, including themselves, to the group and thereby hand out the directory role the group holds.' `
                        -Recommendation 'Remove owners from role-assignable groups or restrict ownership to Privileged Role Administrators.'))
        }
        if ($riskyMembers.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-38' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                        -Title 'Role-assignable groups contain guests or disabled accounts' `
                        -Evidence ([ordered]@{ members = $riskyMembers.Count; examples = (Select-SecOakExample $riskyMembers.ToArray()) }) `
                        -Risk 'Guests are governed by another organisation and disabled accounts can be re-enabled; either inherits the group''s role.' `
                        -Recommendation 'Remove guests and disabled accounts from role-assignable groups.'))
        }
    }

    #--- ENTRA-39 administrative units
    $units = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/AdministrativeUnits' -Path '/directory/administrativeUnits?$select=id,displayName,membershipType,membershipRule,isMemberManagementRestricted,visibility' -RawName 'entra-administrative-units'
    if ($units.Success) {
        $unitList = @($units.Items)
        $riskyScoped = [System.Collections.Generic.List[string]]::new()
        $scopedTotal = 0
        foreach ($unit in $unitList) {
            $scoped = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/AdministrativeUnits' -Path "/directory/administrativeUnits/$($unit.id)/scopedRoleMembers"
            if (-not $scoped.Success) { continue }
            $scopedTotal += @($scoped.Items).Count
            foreach ($member in @($scoped.Items)) {
                $id = "$($member.roleMemberInfo.id)"
                $user = if ($usersById) { $usersById[$id] } else { $null }
                if ($user -and ($user.userType -eq 'Guest' -or -not $user.accountEnabled)) { $riskyScoped.Add(('{0} in {1}' -f $user.userPrincipalName, $unit.displayName)) }
            }
        }
        $summary.administrativeUnits = [ordered]@{ units = $unitList.Count; restrictedManagementUnits = @($unitList | Where-Object isMemberManagementRestricted | Select-Object -ExpandProperty displayName); scopedRoleMembers = $scopedTotal; guestOrDisabledScopedAdministrators = $riskyScoped.Count }
        if ($riskyScoped.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-39' -Area $area -Severity Low -BaselineControl 'Separate admin accounts' `
                        -Title 'Administrative unit roles held by guests or disabled accounts' `
                        -Evidence ([ordered]@{ scopedAdministrators = $riskyScoped.Count; examples = (Select-SecOakExample $riskyScoped.ToArray()) }) `
                        -Risk 'Scoped administrators can reset passwords or change settings for the unit''s members; a guest or dormant account should not hold that.' `
                        -Recommendation 'Remove these scoped role assignments.'))
        }
    }

    #--- ENTRA-40 directory audit log, last 7 days
    Write-Verbose 'Entra: directory audit log'
    $since = $now.AddDays(-7).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $watchedActivities = @('Add member to role', 'Add eligible member to role', 'Add service principal credentials', 'Consent to application', 'Add delegated permission grant', 'Add app role assignment to service principal', 'Update conditional access policy', 'Delete conditional access policy', 'Set federation settings on domain', 'Set domain authentication', 'Update authorization policy')
    $nameFilter = ($watchedActivities | ForEach-Object { "activityDisplayName eq '$_'" }) -join ' or '
    $audits = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/DirectoryAudit' -NoGap -RawName 'entra-directory-audits' -Path "/auditLogs/directoryAudits?`$filter=activityDateTime ge $since and ($nameFilter)"
    $events = [System.Collections.Generic.List[object]]::new()
    $auditReadable = $audits.Success
    if ($audits.Success) { foreach ($e in $audits.Items) { $events.Add($e) } }
    else {
        $categories = @('RoleManagement', 'Policy', 'DirectoryManagement')
        $fallback = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/DirectoryAudit' -RawName 'entra-directory-audits-by-category' -Path ("/auditLogs/directoryAudits?`$filter=activityDateTime ge $since and (" + (($categories | ForEach-Object { "category eq '$_'" }) -join ' or ') + ')')
        $auditReadable = $fallback.Success
        if ($fallback.Success) { foreach ($e in @($fallback.Items | Where-Object { $_.activityDisplayName -in $watchedActivities })) { $events.Add($e) } }
    }
    $appEvents = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/DirectoryAudit' -NoGap -Path "/auditLogs/directoryAudits?`$filter=activityDateTime ge $since and category eq 'ApplicationManagement'"
    if ($appEvents.Success) {
        foreach ($e in @($appEvents.Items | Where-Object { ($_.activityDisplayName -in $watchedActivities) -or ("$($_.activityDisplayName)" -match '^Update application.*(secret|certificate)') })) {
            if (-not ($events | Where-Object id -eq $e.id)) { $events.Add($e) }
        }
    }
    if ($auditReadable) {
        $all = $events.ToArray()
        $federation = @($all | Where-Object { $_.activityDisplayName -in 'Set federation settings on domain', 'Set domain authentication' })
        $firstPartyCredentials = @($all | Where-Object { $_.activityDisplayName -eq 'Add service principal credentials' -and (@($_.targetResources | Where-Object { "$($_.displayName)" -match '^(Microsoft|Office 365|Azure|Windows Azure)' }).Count) })
        $appRoleAdds = @($all | Where-Object { $_.activityDisplayName -in 'Add member to role', 'Add eligible member to role' -and $_.initiatedBy.app -and ($_.initiatedBy.app.appId -or $_.initiatedBy.app.displayName) })
        $policyDeletes = @($all | Where-Object activityDisplayName -eq 'Delete conditional access policy')
        $other = @($all | Where-Object { $_ -notin $federation -and $_ -notin $firstPartyCredentials -and $_ -notin $appRoleAdds -and $_ -notin $policyDeletes })
        $summary.directoryAuditLast7Days = [ordered]@{ watchedEvents = $all.Count; byActivity = @($all | Group-Object activityDisplayName | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) }
        if ($federation.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-40' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Domain federation settings changed in the last 7 days' `
                        -Evidence ([ordered]@{ events = $federation.Count; examples = (Select-SecOakExample @($federation | ForEach-Object { '{0} by {1} on {2:yyyy-MM-dd}' -f $_.activityDisplayName, $(if ($_.initiatedBy.user.userPrincipalName) { $_.initiatedBy.user.userPrincipalName } else { $_.initiatedBy.app.displayName }), (ConvertTo-SecOakUtcDate $_.activityDateTime) })) }) `
                        -Risk 'Changing federation is how attackers add their own identity provider and sign in as any user without a password. It should be extremely rare.' `
                        -Recommendation 'Confirm each change with the administrator named; if unexplained, treat it as an incident and reset the domain to managed.'))
        }
        if ($firstPartyCredentials.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-40' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Credentials added to Microsoft service principals in the last 7 days' `
                        -Evidence ([ordered]@{ events = $firstPartyCredentials.Count; examples = (Select-SecOakExample @($firstPartyCredentials | ForEach-Object { '{0} on {1:yyyy-MM-dd}' -f (@($_.targetResources)[0].displayName), (ConvertTo-SecOakUtcDate $_.activityDateTime) })) }) `
                        -Risk 'A credential on a Microsoft application is a backdoor with that application''s permissions.' `
                        -Recommendation 'Remove the credential, identify who added it and review that account.'))
        }
        if ($appRoleAdds.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-40' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                        -Title 'Directory role assignments made by an application in the last 7 days' `
                        -Evidence ([ordered]@{ events = $appRoleAdds.Count; examples = (Select-SecOakExample @($appRoleAdds | ForEach-Object { '{0} by {1} on {2:yyyy-MM-dd}' -f $_.activityDisplayName, $_.initiatedBy.app.displayName, (ConvertTo-SecOakUtcDate $_.activityDateTime) })) }) `
                        -Risk 'An application granting roles is unusual outside automated provisioning and can be a sign of a compromised application credential.' `
                        -Recommendation 'Confirm the application and the assignment were expected; otherwise remove the role and rotate the application credential.'))
        }
        if ($policyDeletes.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-40' -Area $area -Severity Medium -BaselineControl 'Multifactor for every user' `
                        -Title 'Conditional access policies deleted in the last 7 days' `
                        -Evidence ([ordered]@{ events = $policyDeletes.Count; examples = (Select-SecOakExample @($policyDeletes | ForEach-Object { 'by {0} on {1:yyyy-MM-dd}' -f $(if ($_.initiatedBy.user.userPrincipalName) { $_.initiatedBy.user.userPrincipalName } else { $_.initiatedBy.app.displayName }), (ConvertTo-SecOakUtcDate $_.activityDateTime) })) }) `
                        -Risk 'Deleting a policy silently removes a protection; attackers do this to disable multifactor before moving further.' `
                        -Recommendation 'Confirm each deletion was intended and keep a backup of policies (for example exported JSON) so they can be restored.'))
        }
        if ($other.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-40' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Sensitive administrative events in the last 7 days for review' `
                        -Evidence ([ordered]@{ events = $other.Count; byActivity = @($other | Group-Object activityDisplayName | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) }) `
                        -Risk 'Role grants, consent grants, credential additions and policy changes are the events an attacker also produces. They need a quick human confirmation.' `
                        -Recommendation 'Review the listed events against change records; set up alerts on these activities so they are seen the same day.'))
        }
    }

    #--- ENTRA-41 and ENTRA-42 sign-in log summary, last 7 days
    Write-Verbose 'Entra: sign-in log summary'
    if ($p1) {
        $legacyClients = @('Exchange ActiveSync', 'IMAP4', 'POP3', 'Authenticated SMTP', 'Exchange Web Services', 'MAPI Over HTTP', 'Other clients')
        $legacyFilter = ($legacyClients | ForEach-Object { "clientAppUsed eq '$_'" }) -join ' or '
        $legacySignIns = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/SignInsLegacy' -RawName 'entra-sign-ins-legacy' -Path "/auditLogs/signIns?`$filter=createdDateTime ge $since and ($legacyFilter)&`$top=1000"
        if ($legacySignIns.Success) {
            $legacy = @($legacySignIns.Items)
            $legacySuccess = @($legacy | Where-Object { [int]$_.status.errorCode -eq 0 })
            $legacyFailed = @($legacy | Where-Object { [int]$_.status.errorCode -ne 0 })
            $summary.legacyAuthenticationLast7Days = [ordered]@{
                signIns    = $legacy.Count
                successful = $legacySuccess.Count
                failed     = $legacyFailed.Count
                byProtocol = @($legacy | Group-Object clientAppUsed | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
                usersWithSuccessfulLegacySignIn = @($legacySuccess.userPrincipalName | Select-Object -Unique).Count
                note       = 'Interactive sign-ins only; non-interactive legacy sign-ins are in the beta log and not read.'
            }
            if ($legacySuccess.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-41' -Area $area -Severity High -BaselineControl 'Legacy authentication blocked' `
                            -Title 'Successful legacy authentication sign-ins in the last 7 days' `
                            -Evidence ([ordered]@{ successfulSignIns = $legacySuccess.Count; users = @($legacySuccess.userPrincipalName | Select-Object -Unique).Count; byProtocol = @($legacySuccess | Group-Object clientAppUsed | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }); examples = (Select-SecOakExample @($legacySuccess | Group-Object userPrincipalName | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })) }) `
                            -Risk 'These sign-ins used protocols that cannot do multifactor, so the password alone was enough. Either the legacy block is missing or these accounts are excluded from it.' `
                            -Recommendation 'Find the device or application behind each account (usually an old mail client, scanner or line-of-business tool), move it to modern authentication, then close the exclusion.'))
            }
            elseif ($legacyFailed.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-41' -Area $area -Severity Medium -BaselineControl 'Legacy authentication blocked' `
                            -Title 'Failed legacy authentication attempts in the last 7 days' `
                            -Evidence ([ordered]@{ failedAttempts = $legacyFailed.Count; targetedAccounts = @($legacyFailed.userPrincipalName | Select-Object -Unique).Count; byProtocol = @($legacyFailed | Group-Object clientAppUsed | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) }) `
                            -Risk 'Attackers are trying passwords against legacy endpoints. The block is holding, but the accounts targeted are known to someone.' `
                            -Recommendation 'Keep the legacy block in place, confirm the targeted accounts have strong passwords and multifactor, and consider disabling basic authentication protocols in Exchange Online as well.'))
            }
        }
        $failures = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/SignInsFailed' -NoGap -RawName 'entra-sign-ins-failed' -Path "/auditLogs/signIns?`$filter=createdDateTime ge $since and status/errorCode ne 0&`$top=1000"
        $failurePartial = $false
        if (-not $failures.Success) {
            $failures = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/SignInsFailed' -NoPaging -RawName 'entra-sign-ins-recent' -Path "/auditLogs/signIns?`$filter=createdDateTime ge $since&`$top=1000"
            $failurePartial = $true
        }
        if ($failures.Success) {
            $failed = @($failures.Items | Where-Object { [int]$_.status.errorCode -ne 0 })
            $sprayBuckets = @($failed | Where-Object { [int]$_.status.errorCode -eq 50126 } | Group-Object { '{0}|{1:yyyy-MM-ddTHH}' -f $_.ipAddress, (ConvertTo-SecOakUtcDate $_.createdDateTime) } | Where-Object { @($_.Group.userId | Select-Object -Unique).Count -gt 10 })
            $adminFailures = @($failed | Where-Object { $_.userId -in $privilegedUserIds } | Group-Object userPrincipalName | Where-Object Count -gt 20)
            $locked = @($failed | Where-Object { [int]$_.status.errorCode -eq 50053 })
            $summary.failedSignInsLast7Days = [ordered]@{
                failedSignIns    = $failed.Count
                byErrorCode      = @($failed | Group-Object { $_.status.errorCode } | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
                sprayWindows     = $sprayBuckets.Count
                privilegedAccountsOver20Failures = $adminFailures.Count
                lockoutEvents    = $locked.Count
                partial          = $failurePartial
            }
            if ($sprayBuckets.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-42' -Area $area -Severity High -BaselineControl 'Multifactor for every user' `
                            -Title 'Password spray pattern in the last 7 days' `
                            -Evidence ([ordered]@{ sourceHourWindows = $sprayBuckets.Count; distinctSources = @($sprayBuckets | ForEach-Object { ($_.Name -split '\|')[0] } | Select-Object -Unique).Count; usersTargeted = @($sprayBuckets | ForEach-Object { $_.Group.userId } | Select-Object -Unique).Count; note = 'Source addresses are kept in the raw output only.' }) `
                            -Risk 'One source tried a password against many accounts within an hour. Any account with a weak or reused password and no multifactor will fall to this.' `
                            -Recommendation 'Enforce multifactor for all users, block legacy authentication, enable smart lockout and banned passwords, and consider blocking the source network in conditional access.'))
            }
            if ($adminFailures.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-42' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                            -Title 'Privileged accounts with more than 20 failed sign-ins in 7 days' `
                            -Evidence ([ordered]@{ accounts = $adminFailures.Count; examples = (Select-SecOakExample @($adminFailures | ForEach-Object { '{0}: {1} failures' -f $_.Name, $_.Count })) }) `
                            -Risk 'Administrator accounts are being guessed at, or a stale credential in a script is hammering them; both need attention.' `
                            -Recommendation 'Check each account for a misconfigured device or script, confirm multifactor and a strong password, and consider renaming administrator accounts away from guessable names.'))
            }
            if ($locked.Count) {
                $findings.Add((New-SecOakFinding -Id 'ENTRA-42' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Account lockouts in the last 7 days' `
                            -Evidence ([ordered]@{ lockoutEvents = $locked.Count; accounts = @($locked.userPrincipalName | Select-Object -Unique).Count }) `
                            -Risk 'Lockouts show repeated wrong passwords, either from an attacker or from a device still using an old password.' `
                            -Recommendation 'Ask the affected users about old devices or saved passwords and check for spray activity.'))
            }
        }
    }
    else { Add-SecOakEntraLicenceGap -Context $Context -Area $area -Check 'Entra/SignIns' -What 'ENTRA-41, 42 sign-in log summary' -Licence 'Microsoft Entra ID P1' }

    #--- ENTRA-43 token lifetime policies
    Write-Verbose 'Entra: token lifetime policies'
    $tokenPolicies = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/TokenLifetimePolicies' -Path '/policies/tokenLifetimePolicies' -RawName 'entra-token-lifetime-policies'
    if ($tokenPolicies.Success) {
        $policyList = @($tokenPolicies.Items)
        $longDefault = [System.Collections.Generic.List[string]]::new()
        $longApplied = [System.Collections.Generic.List[string]]::new()
        $descriptions = [System.Collections.Generic.List[string]]::new()
        foreach ($tokenPolicy in $policyList) {
            $lifetime = $null
            foreach ($definition in @($tokenPolicy.definition)) {
                try { $parsed = $definition | ConvertFrom-Json; $lifetime = $parsed.TokenLifetimePolicy.AccessTokenLifetime } catch { $lifetime = $null }
            }
            $span = $null
            if ($lifetime) { try { $span = [timespan]::Parse("$lifetime") } catch { $span = $null } }
            $appliesTo = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/TokenLifetimePolicies' -Path "/policies/tokenLifetimePolicies/$($tokenPolicy.id)/appliesTo"
            $applied = if ($appliesTo.Success) { @($appliesTo.Items).Count } else { 'unreadable' }
            $descriptions.Add(('{0}: access token lifetime {1}, organisation default {2}, applied to {3} objects' -f $tokenPolicy.displayName, $(if ($lifetime) { $lifetime } else { 'default' }), [bool]$tokenPolicy.isOrganizationDefault, $applied))
            if ($span -and $span -gt [timespan]::FromHours(1)) {
                if ($tokenPolicy.isOrganizationDefault) { $longDefault.Add("$($tokenPolicy.displayName) ($lifetime)") }
                elseif ($appliesTo.Success -and @($appliesTo.Items).Count) { $longApplied.Add("$($tokenPolicy.displayName) ($lifetime)") }
            }
        }
        $summary.tokenLifetimePolicies = [ordered]@{ policies = $policyList.Count; details = $descriptions.ToArray() }
        if ($longDefault.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-43' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Organisation-wide token lifetime policy extends access tokens beyond one hour' `
                        -Evidence ([ordered]@{ policies = $longDefault.ToArray() }) `
                        -Risk 'Longer access tokens keep working after a password reset, a disabled account or a revoked session, giving an attacker more time.' `
                        -Recommendation 'Remove the custom lifetime and rely on the default one hour with continuous access evaluation.'))
        }
        if ($longApplied.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-43' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Applications with extended access token lifetimes' `
                        -Evidence ([ordered]@{ policies = $longApplied.ToArray() }) `
                        -Risk 'Tokens for these applications stay valid longer than the default after a revocation.' `
                        -Recommendation 'Confirm each application still needs the longer lifetime; otherwise remove the policy assignment.'))
        }
    }

    #--- ENTRA-44 Windows LAPS (metadata only)
    Write-Verbose 'Entra: Windows LAPS and BitLocker escrow (metadata only)'
    $registrationPolicy = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/WindowsLaps' -Path '/policies/deviceRegistrationPolicy' -RawName 'entra-device-registration-policy'
    if ($registrationPolicy.Success) {
        $lapsEnabled = [bool]$registrationPolicy.Body.localAdminPassword.isEnabled
        $summary.windowsLaps = [ordered]@{ enabledInDeviceSettings = $lapsEnabled }
        if (-not $lapsEnabled) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-44' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Windows LAPS is not enabled in Entra device settings' `
                        -Evidence ([ordered]@{ localAdminPasswordEnabled = $false }) `
                        -Risk 'Every computer probably shares the same local administrator password, so one compromised laptop opens all of them.' `
                        -Recommendation 'Enable Windows LAPS in Entra device settings and deploy a LAPS policy through Intune so each device gets its own rotated local administrator password.'))
        }
    }
    $localCredentials = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/WindowsLaps' -Path '/directory/deviceLocalCredentials' -RawName 'entra-device-local-credentials'
    if ($localCredentials.Success) {
        $entries = @($localCredentials.Items)
        $entryIds = [System.Collections.Generic.HashSet[string]]::new([string[]]@($entries | ForEach-Object { "$($_.id)" }))
        $covered = @($windowsDevices | Where-Object { $entryIds.Contains("$($_.deviceId)") })
        $coveragePercent = if ($windowsDevices.Count) { [math]::Round(100 * $covered.Count / $windowsDevices.Count, 1) } else { $null }
        $oldBackup = @($entries | Where-Object { $recentWindowsIds.Contains("$($_.id)") -and ($b = ConvertTo-SecOakUtcDate $_.lastBackupDateTime) -and $b -lt $now.AddDays(-30) })
        if (-not $summary.Contains('windowsLaps')) { $summary.windowsLaps = [ordered]@{} }
        $summary.windowsLaps.devicesWithBackedUpPassword = $entries.Count
        $summary.windowsLaps.windowsJoinedDevices = $windowsDevices.Count
        $summary.windowsLaps.coveragePercent = $coveragePercent
        $summary.windowsLaps.activeDevicesWithBackupOlderThan30Days = $oldBackup.Count
        if ($windowsDevices.Count -and $coveragePercent -lt 80) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-44' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Fewer than 80 percent of Windows devices have a LAPS password backed up' `
                        -Evidence ([ordered]@{ windowsJoinedDevices = $windowsDevices.Count; devicesWithBackup = $covered.Count; coveragePercent = $coveragePercent }) `
                        -Risk 'Devices without an escrowed local administrator password either share a common password or cannot be recovered by the help desk.' `
                        -Recommendation 'Assign the Intune LAPS policy to all Windows devices and check the policy report for devices that fail to apply it.'))
        }
        if ($oldBackup.Count) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-44' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Active devices whose LAPS password backup is older than 30 days' `
                        -Evidence ([ordered]@{ devices = $oldBackup.Count; examples = (Select-SecOakExample $oldBackup.deviceName) }) `
                        -Risk 'The password is not rotating as intended, so a leaked password stays valid.' `
                        -Recommendation 'Check the LAPS policy rotation interval and the device policy status.'))
        }
    }

    #--- ENTRA-45 BitLocker recovery key escrow (metadata only)
    $bitlocker = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Entra/BitLockerKeys' -Path '/informationProtection/bitlocker/recoveryKeys' -RawName 'entra-bitlocker-keys'
    if ($bitlocker.Success) {
        $keys = @($bitlocker.Items | Select-Object id, deviceId, volumeType, createdDateTime)
        $keysByDevice = @($keys | Group-Object deviceId)
        $keyDeviceIds = [System.Collections.Generic.HashSet[string]]::new([string[]]@($keysByDevice | ForEach-Object { "$($_.Name)" }))
        $withKey = @($windowsDevices | Where-Object { $keyDeviceIds.Contains("$($_.deviceId)") })
        $keyPercent = if ($windowsDevices.Count) { [math]::Round(100 * $withKey.Count / $windowsDevices.Count, 1) } else { $null }
        $manyKeys = @($keysByDevice | Where-Object Count -gt 5)
        $summary.bitLocker = [ordered]@{ recoveryKeys = $keys.Count; devicesWithKeys = $keysByDevice.Count; windowsJoinedDevices = $windowsDevices.Count; coveragePercent = $keyPercent; devicesWithMoreThanFiveKeys = $manyKeys.Count; byVolumeType = @($keys | Group-Object volumeType | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) }
        if ($windowsDevices.Count -and $keyPercent -lt 80) {
            $findings.Add((New-SecOakFinding -Id 'ENTRA-45' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Fewer than 80 percent of Windows devices have a BitLocker recovery key in Entra ID' `
                        -Evidence ([ordered]@{ windowsJoinedDevices = $windowsDevices.Count; devicesWithKey = $withKey.Count; coveragePercent = $keyPercent }) `
                        -Risk 'Devices without an escrowed key are either not encrypted (data on a lost laptop is readable) or cannot be recovered when BitLocker asks for the key.' `
                        -Recommendation 'Deploy an Intune disk encryption policy that silently enables BitLocker and backs the key up to Entra ID, then follow up on non-compliant devices.'))
        }
    }

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
