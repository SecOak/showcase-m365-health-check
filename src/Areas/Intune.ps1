function ConvertTo-SecOakIntunePlatform {
    <#
    .SYNOPSIS
        Normalizes an Intune platform name (operating system, policy type, or platforms value) to Windows, iOS, Android, macOS, Linux, or Other.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()][AllowNull()][AllowEmptyString()][string]$Value)
    switch -Regex ("$Value") {
        'windows'      { return 'Windows' }
        'ios|ipad'     { return 'iOS' }
        'android|aosp' { return 'Android' }
        'mac'          { return 'macOS' }
        'linux'        { return 'Linux' }
        default        { return 'Other' }
    }
}

function Invoke-SecOakIntuneCheck {
    <#
    .SYNOPSIS
        Intune area: compliance and configuration policy coverage, endpoint security policies,
        Windows Update management, enrollment restrictions, Autopilot, app protection, scripts,
        Intune role assignments, Windows LAPS and BitLocker escrow metadata, and encryption state.
    .DESCRIPTION
        Implements INTUNE-01 to INTUNE-32. Managed device inventory, compliance state, operating
        system versions and sync age stay in the Devices area; this area reads the managed device
        list once more with a minimal select only to learn which platforms are present and which
        devices are personally owned.

        Beta endpoints are used only where v1.0 lacks the data (each call is marked in a comment).
        Passwords and recovery keys are never requested: the LAPS and BitLocker calls select
        metadata properties only.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakIntuneCheck -Context $context
    .NOTES
        Application permissions: DeviceManagementConfiguration.Read.All, DeviceManagementServiceConfig.Read.All,
        DeviceManagementApps.Read.All, DeviceManagementScripts.Read.All, DeviceManagementRBAC.Read.All,
        DeviceManagementManagedDevices.Read.All (platform presence only), Directory.Read.All (Windows device
        list for LAPS coverage), DeviceLocalCredential.ReadBasic.All (LAPS metadata, never the password),
        BitlockerKey.ReadBasic.All (recovery key metadata, never the key). Requires an Intune license.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Intune'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $now = [datetime]::UtcNow

    #region Managed device platforms (minimal overlap with the Devices area: platform presence and ownership only)
    $deviceResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/ManagedDevicePlatforms' `
        -Path '/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,managedDeviceOwnerType,azureADDeviceId,isEncrypted' -RawName 'intune-managed-device-platforms'
    $inventoryKnown = [bool]$deviceResult.Success
    $managedDevices = if ($inventoryKnown) { @($deviceResult.Items) } else { @() }
    $platformCounts = [ordered]@{ Windows = 0; iOS = 0; Android = 0; macOS = 0; Linux = 0; Other = 0 }
    $personalByPlatform = @{}
    foreach ($device in $managedDevices) {
        $platform = ConvertTo-SecOakIntunePlatform $device.operatingSystem
        $platformCounts[$platform]++
        if ($device.managedDeviceOwnerType -eq 'personal') { $personalByPlatform[$platform] = 1 + [int]$personalByPlatform[$platform] }
    }
    $platformsPresent = @($platformCounts.Keys | Where-Object { $_ -ne 'Other' -and $platformCounts[$_] -gt 0 })
    # When the inventory cannot be read, Windows checks still run (every small business has Windows devices).
    $windowsPresent = (-not $inventoryKnown) -or $platformCounts.Windows -gt 0
    $summary.managedDevicePlatforms = [ordered]@{
        inventoryRead     = $inventoryKnown
        byPlatform        = @($platformCounts.Keys | Where-Object { $platformCounts[$_] -gt 0 } | ForEach-Object { '{0}: {1}' -f $_, $platformCounts[$_] })
        personallyOwned   = ($personalByPlatform.Values | Measure-Object -Sum).Sum
    }
    #endregion

    #region INTUNE-01, 02, 03: legacy compliance policies (v1.0); also the Intune license gate
    $policyResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/CompliancePolicies' `
        -Path '/deviceManagement/deviceCompliancePolicies?$expand=assignments' -RawName 'intune-compliance-policies'
    if (-not $policyResult.Success -and $policyResult.StatusCode -eq 403 -and "$($policyResult.ErrorMessage)" -match 'licen[cs]e|MDM_Setting_UnAuthorized|not.*enabled') {
        # One tenant-level gap (already recorded by the wrapper) instead of thirty failures.
        $summary.intuneLicensed = $false
        $summary.note = 'Intune is not licensed or not enabled for this tenant; the remaining Intune checks were skipped.'
        foreach ($finding in $findings) { $Context.Findings.Add($finding) }
        $Context.AreaSummaries[$area] = $summary
        return [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
    }
    $summary.intuneLicensed = $true
    $legacyPolicies = if ($policyResult.Success) { @($policyResult.Items) } else { @() }

    # INTUNE-05 (beta: the settings catalog compliance engine has no v1.0 endpoint). Path verified live.
    $catalogResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/CompliancePoliciesSettingsCatalog' `
        -Path '/deviceManagement/compliancePolicies?$select=id,name,platforms,settingCount' -ApiVersion beta -RawName 'intune-compliance-policies-settings-catalog'
    $catalogPolicies = if ($catalogResult.Success) { @($catalogResult.Items) } else { @() }

    $coveredPlatforms = @{}
    foreach ($policy in $legacyPolicies) { $coveredPlatforms[(ConvertTo-SecOakIntunePlatform $policy.'@odata.type')] = $true }
    foreach ($policy in $catalogPolicies) { foreach ($p in @("$($policy.platforms)" -split ',')) { $coveredPlatforms[(ConvertTo-SecOakIntunePlatform $p.Trim())] = $true } }
    $unassignedPolicies = @($legacyPolicies | Where-Object { @($_.assignments).Count -eq 0 })
    $summary.compliancePolicies = [ordered]@{
        legacy            = $legacyPolicies.Count
        settingsCatalog   = $catalogPolicies.Count
        unassignedLegacy  = $unassignedPolicies.Count
        platformsCovered  = @($coveredPlatforms.Keys | Where-Object { $_ -ne 'Other' } | Sort-Object)
    }
    if ($policyResult.Success -or $catalogResult.Success) {
        $missing = @($platformsPresent | Where-Object { -not $coveredPlatforms[$_] })
        if ($missing.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-01' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Managed device platforms with no compliance policy' `
                        -Evidence ([ordered]@{ platformsWithoutPolicy = @($missing | ForEach-Object { '{0} ({1} devices)' -f $_, $platformCounts[$_] }); compliancePolicies = ($legacyPolicies.Count + $catalogPolicies.Count) }) `
                        -Risk 'Devices on these platforms are never checked for encryption, a screen lock, or an up-to-date operating system, yet they still count as trusted when reaching company data.' `
                        -Recommendation 'Create and assign a compliance policy for every platform in use (Windows, iOS, Android, macOS) and require a compliant device in conditional access.'))
        }
    }
    if ($unassignedPolicies.Count) {
        $findings.Add((New-SecOakFinding -Id 'INTUNE-02' -Area $area -Severity Medium -BaselineControl 'None' `
                    -Title 'Compliance policies that are not assigned to anyone' `
                    -Evidence ([ordered]@{ unassigned = $unassignedPolicies.Count; total = $legacyPolicies.Count; examples = (Select-SecOakExample $unassignedPolicies.displayName) }) `
                    -Risk 'An unassigned policy protects nothing: the devices it was meant to check are treated as if the policy did not exist.' `
                    -Recommendation 'Assign each compliance policy to the device or user groups it is meant for, or delete policies that are no longer needed.'))
    }

    # INTUNE-03: actions for noncompliance (v1.0 list-level expand verified live; no per-policy loop needed)
    if ($legacyPolicies.Count) {
        $actionResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/ComplianceActions' `
            -Path '/deviceManagement/deviceCompliancePolicies?$select=id,displayName&$expand=scheduledActionsForRule($expand=scheduledActionConfigurations)' -RawName 'intune-compliance-actions'
        if ($actionResult.Success) {
            $noFollowUp = @($actionResult.Items | Where-Object {
                    $configs = @($_.scheduledActionsForRule | ForEach-Object { @($_.scheduledActionConfigurations) })
                    # The implicit default is a single immediate "block" (mark noncompliant) with no grace period.
                    -not @($configs | Where-Object { $_.actionType -ne 'block' -or [int]$_.gracePeriodHours -gt 0 }).Count
                })
            $summary.compliancePolicies.withoutFollowUpAction = $noFollowUp.Count
            if ($noFollowUp.Count) {
                $findings.Add((New-SecOakFinding -Id 'INTUNE-03' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Compliance policies with no follow-up action for noncompliant devices' `
                            -Evidence ([ordered]@{ policies = $noFollowUp.Count; examples = (Select-SecOakExample $noFollowUp.displayName) }) `
                            -Risk 'Users are not told when their device falls out of compliance, so problems sit unnoticed until the device is blocked or, if conditional access is not enforced, are never fixed.' `
                            -Recommendation 'Add an email notification with a short grace period to each compliance policy, followed by blocking access or retiring the device.'))
            }
        }
    }

    # INTUNE-04: per-policy device status overview (v1.0 returns pending, notApplicable, success, error, failed counts only)
    if ($legacyPolicies.Count -and $legacyPolicies.Count -le 50) {
        $failingPolicies = [System.Collections.Generic.List[object]]::new()
        $overviewRead = 0
        foreach ($policy in $legacyPolicies) {
            $overview = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/CompliancePolicyStatus' `
                -Path "/deviceManagement/deviceCompliancePolicies/$($policy.id)/deviceStatusOverview" -NoPaging -NoGap:($overviewRead -gt 0)
            if (-not $overview.Success) { break }
            $overviewRead++
            $o = $overview.Body
            $problem = [int]$o.pendingCount + [int]$o.errorCount + [int]$o.failedCount
            $base = $problem + [int]$o.successCount
            if ($base -gt 0 -and $problem / $base -gt 0.25) {
                $failingPolicies.Add(('{0} ({1} of {2} devices pending, error, or failed)' -f $policy.displayName, $problem, $base))
            }
        }
        $summary.compliancePolicies.statusOverviewsRead = $overviewRead
        $summary.compliancePolicies.failingBroadly = $failingPolicies.Count
        if ($failingPolicies.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-04' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Compliance policies failing on a large share of devices' `
                        -Evidence ([ordered]@{ policies = $failingPolicies.Count; threshold = 'more than 25 percent pending, error, or failed'; examples = (Select-SecOakExample $failingPolicies.ToArray()) }) `
                        -Risk 'A policy that fails broadly usually points to a setting the devices cannot meet or a rollout that stalled, so the protection it promises is not in place.' `
                        -Recommendation 'Open each policy''s device status in Intune, fix the failing setting or the devices, and confirm the counts recover.'))
        }
    }
    #endregion

    #region INTUNE-06: tenant-wide compliance settings (v1.0 /deviceManagement/settings verified live; $select=settings on the singleton returns null)
    $settingsResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/ComplianceSettings' -Path '/deviceManagement/settings' -NoPaging -RawName 'intune-compliance-settings'
    if ($settingsResult.Success -and $settingsResult.Body) {
        $settings = $settingsResult.Body
        $summary.complianceSettings = [ordered]@{
            devicesWithNoPolicyAreCompliant = (-not [bool]$settings.secureByDefault)
            complianceCheckInThresholdDays  = $settings.deviceComplianceCheckinThresholdDays
        }
        if (-not [bool]$settings.secureByDefault) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-06' -Area $area -Severity $(if ($managedDevices.Count) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Devices with no compliance policy are treated as compliant' `
                        -Evidence ([ordered]@{ secureByDefault = $false; managedDevices = $managedDevices.Count }) `
                        -Risk 'Any device that has no compliance policy assigned passes as compliant, so conditional access rules that require a compliant device can be satisfied by an unchecked device.' `
                        -Recommendation 'In Intune compliance policy settings, set "Mark devices with no compliance policy assigned as" to Not compliant, after confirming every platform has an assigned policy.'))
        }
    }
    #endregion

    #region INTUNE-07 and INTUNE-17: legacy device configuration profiles and Windows Update rings (v1.0; isof filter fails live, so the type is filtered here)
    $configResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/DeviceConfigurations' `
        -Path '/deviceManagement/deviceConfigurations?$expand=assignments' -RawName 'intune-device-configurations'
    $profiles = if ($configResult.Success) { @($configResult.Items) } else { @() }
    $rings = @($profiles | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.windowsUpdateForBusinessConfiguration' })
    $unassignedProfiles = @($profiles | Where-Object { @($_.assignments).Count -eq 0 })
    $unassignedRings = @($rings | Where-Object { @($_.assignments).Count -eq 0 })
    #endregion

    #region INTUNE-08 to 16: settings catalog policies, endpoint security families, legacy intents, baselines (all beta: no v1.0 endpoints exist)
    $catalogConfigResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/ConfigurationPolicies' `
        -Path '/deviceManagement/configurationPolicies?$select=id,name,platforms,technologies,settingCount,isAssigned,templateReference' -ApiVersion beta -RawName 'intune-configuration-policies'
    $catalogConfigs = if ($catalogConfigResult.Success) { @($catalogConfigResult.Items) } else { @() }
    $plainCatalogConfigs = @($catalogConfigs | Where-Object { "$($_.templateReference.templateFamily)" -in 'none', '' })
    $unassignedCatalogConfigs = @($plainCatalogConfigs | Where-Object { -not $_.isAssigned })

    $intentResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/EndpointSecurityIntents' `
        -Path '/deviceManagement/intents?$select=id,displayName,isAssigned,isMigratingToConfigurationPolicy,templateId' -ApiVersion beta -RawName 'intune-endpoint-security-intents'
    $intents = if ($intentResult.Success) { @($intentResult.Items) } else { @() }
    $templateResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/Templates' `
        -Path '/deviceManagement/templates?$select=id,displayName,templateType,platformType,intentCount' -ApiVersion beta -RawName 'intune-templates'
    $templates = if ($templateResult.Success) { @($templateResult.Items) } else { @() }
    $templateById = @{}
    foreach ($template in $templates) { $templateById[$template.id] = $template }

    # Legacy intents carry no family; the family is inferred from the template name (Microsoft's own names such as "Antivirus", "Disk encryption").
    $familyPatterns = [ordered]@{
        endpointSecurityAntivirus                    = 'antivirus'
        endpointSecurityDiskEncryption               = 'encryption|bitlocker|filevault'
        endpointSecurityFirewall                     = 'firewall'
        endpointSecurityAttackSurfaceReduction       = 'attack surface'
        endpointSecurityAccountProtection            = 'account protection'
        endpointSecurityEndpointDetectionAndResponse = 'endpoint detection'
    }
    $familyCoverage = [ordered]@{}
    foreach ($family in $familyPatterns.Keys) {
        $catalogMatches = @($catalogConfigs | Where-Object { "$($_.templateReference.templateFamily)" -eq $family })
        $intentMatches = @($intents | Where-Object { $t = $templateById[$_.templateId]; $t -and "$($t.displayName)" -match $familyPatterns[$family] })
        $familyCoverage[$family] = [ordered]@{
            policies = $catalogMatches.Count + $intentMatches.Count
            assigned = @($catalogMatches | Where-Object isAssigned).Count + @($intentMatches | Where-Object isAssigned).Count
        }
    }
    $baselineTemplates = @($templates | Where-Object { "$($_.templateType)" -match 'baseline' })
    $baselineIntents = @($intents | Where-Object { $t = $templateById[$_.templateId]; $t -and "$($t.templateType)" -match 'baseline' })
    $baselineCatalog = @($catalogConfigs | Where-Object { "$($_.templateReference.templateFamily)" -eq 'baseline' })
    $baselineAssigned = @($baselineIntents | Where-Object isAssigned).Count + @($baselineCatalog | Where-Object isAssigned).Count

    $summary.configuration = [ordered]@{
        legacyProfiles            = $profiles.Count
        legacyProfilesUnassigned  = $unassignedProfiles.Count
        settingsCatalogPolicies   = $plainCatalogConfigs.Count
        settingsCatalogUnassigned = $unassignedCatalogConfigs.Count
        endpointSecurityPolicies  = @($catalogConfigs | Where-Object { "$($_.templateReference.templateFamily)" -like 'endpointSecurity*' }).Count
        legacyIntents             = $intents.Count
        intentsMigrating          = @($intents | Where-Object isMigratingToConfigurationPolicy).Count
        endpointSecurityByFamily  = @($familyCoverage.Keys | ForEach-Object { '{0}: {1} ({2} assigned)' -f ($_ -replace '^endpointSecurity', ''), $familyCoverage[$_].policies, $familyCoverage[$_].assigned })
        securityBaselineTemplates = $baselineTemplates.Count
        securityBaselinesAssigned = $baselineAssigned
    }

    if ($configResult.Success -and $catalogConfigResult.Success -and $profiles.Count -eq 0 -and $plainCatalogConfigs.Count -eq 0) {
        $findings.Add((New-SecOakFinding -Id 'INTUNE-07' -Area $area -Severity Medium -BaselineControl 'None' `
                    -Title 'No device configuration profiles exist' `
                    -Evidence ([ordered]@{ legacyProfiles = 0; settingsCatalogPolicies = 0; managedDevices = $managedDevices.Count }) `
                    -Risk 'Managed devices run on factory defaults: no enforced screen lock, password rules, or hardening settings, so each device is only as safe as its user makes it.' `
                    -Recommendation 'Create Settings Catalog profiles for the core device settings (screen lock, password, Defender, updates) and assign them to all devices.'))
    }
    elseif ($unassignedProfiles.Count) {
        $findings.Add((New-SecOakFinding -Id 'INTUNE-07' -Area $area -Severity Low -BaselineControl 'None' `
                    -Title 'Device configuration profiles that are not assigned' `
                    -Evidence ([ordered]@{ unassigned = $unassignedProfiles.Count; total = $profiles.Count; examples = (Select-SecOakExample $unassignedProfiles.displayName) }) `
                    -Risk 'These profiles apply to no device, so any setting they were meant to enforce is not in place.' `
                    -Recommendation 'Assign each profile to the intended device group or delete profiles that are no longer wanted.'))
    }
    if ($unassignedCatalogConfigs.Count) {
        $findings.Add((New-SecOakFinding -Id 'INTUNE-08' -Area $area -Severity Low -BaselineControl 'None' `
                    -Title 'Settings Catalog policies that are not assigned' `
                    -Evidence ([ordered]@{ unassigned = $unassignedCatalogConfigs.Count; total = $plainCatalogConfigs.Count; examples = (Select-SecOakExample $unassignedCatalogConfigs.name) }) `
                    -Risk 'These policies apply to no device, so any setting they were meant to enforce is not in place.' `
                    -Recommendation 'Assign each policy to the intended device group or delete policies that are no longer wanted.'))
    }

    if ($windowsPresent -and $catalogConfigResult.Success -and $intentResult.Success) {
        $familyChecks = @(
            @{ Id = 'INTUNE-09'; Family = 'endpointSecurityAntivirus'; Severity = 'High'; Title = 'No antivirus policy is assigned to Windows devices'
                Risk = 'Without a managed antivirus policy each device keeps whatever Defender settings its user leaves in place; real-time protection, cloud protection, and scans can be switched off without anyone noticing.'
                Recommendation = 'Create an Endpoint security Antivirus policy (Microsoft Defender Antivirus) and assign it to all Windows devices.' }
            @{ Id = 'INTUNE-10'; Family = 'endpointSecurityDiskEncryption'; Severity = 'High'; Title = 'No disk encryption policy is assigned to Windows devices'
                Risk = 'A lost or stolen laptop that is not encrypted exposes every file on it, and there is no recovery key on file for the ones that are.'
                Recommendation = 'Create an Endpoint security Disk encryption (BitLocker) policy that requires encryption and backs up recovery keys to Microsoft Entra ID, and assign it to all Windows devices.' }
            @{ Id = 'INTUNE-11'; Family = 'endpointSecurityFirewall'; Severity = 'Medium'; Title = 'No firewall policy is assigned to Windows devices'
                Risk = 'The Windows firewall can be turned off or opened up by users or software, leaving devices reachable from other machines on the same network.'
                Recommendation = 'Create an Endpoint security Firewall policy that keeps the firewall on for all network profiles and assign it to all Windows devices.' }
            @{ Id = 'INTUNE-12'; Family = 'endpointSecurityAttackSurfaceReduction'; Severity = 'Medium'; Title = 'No attack surface reduction policy is assigned to Windows devices'
                Risk = 'Common malware entry points such as Office macros that launch programs and scripts from email are not blocked at the device.'
                Recommendation = 'Create an Endpoint security Attack surface reduction rules policy in block mode for the standard rules and assign it to all Windows devices.' }
            @{ Id = 'INTUNE-13'; Family = 'endpointSecurityAccountProtection'; Severity = 'Medium'; Title = 'No account protection policy is assigned to Windows devices'
                Risk = 'Sign-in protections such as Windows Hello for Business and credential guard are left to each device, so stolen passwords work everywhere.'
                Recommendation = 'Create an Endpoint security Account protection policy that enables Windows Hello for Business and Credential Guard and assign it to all Windows devices.' }
            @{ Id = 'INTUNE-14'; Family = 'endpointSecurityEndpointDetectionAndResponse'; Severity = 'Medium'; Title = 'No endpoint detection and response onboarding policy is assigned'
                Risk = 'Windows devices are not connected to Microsoft Defender for Endpoint, so attacks on a device are not detected or investigated centrally. Note: an onboarding policy only works when Defender for Endpoint is licensed.'
                Recommendation = 'If Defender for Endpoint (included in Microsoft 365 Business Premium) is licensed, create an Endpoint security Endpoint detection and response policy and assign it to all Windows devices.' }
        )
        foreach ($check in $familyChecks) {
            $coverage = $familyCoverage[$check.Family]
            if ($coverage.assigned -eq 0) {
                $findings.Add((New-SecOakFinding -Id $check.Id -Area $area -Severity $check.Severity -BaselineControl 'None' `
                            -Title $check.Title `
                            -Evidence ([ordered]@{ policies = $coverage.policies; assigned = 0; windowsDevices = $platformCounts.Windows }) `
                            -Risk $check.Risk -Recommendation $check.Recommendation))
            }
        }
    }
    if ($windowsPresent -and $templateResult.Success -and $catalogConfigResult.Success -and $baselineAssigned -eq 0 -and $baselineTemplates.Count) {
        $findings.Add((New-SecOakFinding -Id 'INTUNE-16' -Area $area -Severity Medium -BaselineControl 'None' `
                    -Title 'No Microsoft security baseline is deployed' `
                    -Evidence ([ordered]@{ baselineTemplatesAvailable = $baselineTemplates.Count; baselinesAssigned = 0; examples = (Select-SecOakExample $baselineTemplates.displayName) }) `
                    -Risk 'Windows, Microsoft Edge, and Microsoft 365 Apps run with default settings instead of Microsoft''s hardened configuration, leaving well-known weaknesses open.' `
                    -Recommendation 'Deploy the Windows security baseline (and the Microsoft Edge and Microsoft 365 Apps baselines) to a pilot group, then to all Windows devices.'))
    }
    #endregion

    #region INTUNE-17 to 20: Windows Update rings and update profiles (rings v1.0; feature, quality, and driver profiles are beta-only)
    $featureResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/FeatureUpdateProfiles' `
        -Path '/deviceManagement/windowsFeatureUpdateProfiles?$select=id,displayName,featureUpdateVersion,endOfSupportDate&$expand=assignments' -ApiVersion beta -RawName 'intune-feature-update-profiles'
    $qualityResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/QualityUpdateProfiles' `
        -Path '/deviceManagement/windowsQualityUpdateProfiles?$select=id,displayName,releaseDateDisplayName&$expand=assignments' -ApiVersion beta -RawName 'intune-quality-update-profiles'
    $driverResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/DriverUpdateProfiles' `
        -Path '/deviceManagement/windowsDriverUpdateProfiles?$select=id,displayName,approvalType&$expand=assignments' -ApiVersion beta -RawName 'intune-driver-update-profiles'
    $featureProfiles = if ($featureResult.Success) { @($featureResult.Items) } else { @() }
    $qualityProfiles = if ($qualityResult.Success) { @($qualityResult.Items) } else { @() }
    $driverProfiles = if ($driverResult.Success) { @($driverResult.Items) } else { @() }
    $endOfSupportProfiles = @($featureProfiles | Where-Object { ($d = ConvertTo-SecOakUtcDate $_.endOfSupportDate) -and $d -lt $now })
    $unassignedFeature = @($featureProfiles | Where-Object { @($_.assignments).Count -eq 0 })
    $unassignedQuality = @($qualityProfiles | Where-Object { @($_.assignments).Count -eq 0 })
    $unassignedDriver = @($driverProfiles | Where-Object { @($_.assignments).Count -eq 0 })
    $summary.windowsUpdate = [ordered]@{
        updateRings              = $rings.Count
        updateRingsUnassigned    = $unassignedRings.Count
        featureUpdateProfiles    = $featureProfiles.Count
        featureUpdateEndOfSupport = $endOfSupportProfiles.Count
        qualityUpdateProfiles    = $qualityProfiles.Count
        driverUpdateProfiles     = $driverProfiles.Count
        profilesUnassigned       = $unassignedFeature.Count + $unassignedQuality.Count + $unassignedDriver.Count
    }
    if ($windowsPresent -and $configResult.Success) {
        if ($rings.Count -eq 0) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-17' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'No Windows Update rings exist' `
                        -Evidence ([ordered]@{ updateRings = 0; windowsDevices = $platformCounts.Windows }) `
                        -Risk 'Each Windows device installs updates on its own schedule and users can pause them, so security patches arrive late or not at all with no deadline.' `
                        -Recommendation 'Create a Windows Update ring with short deferrals and a deadline with grace period, and assign it to all Windows devices.'))
        }
        elseif ($unassignedRings.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-17' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Windows Update rings that are not assigned' `
                        -Evidence ([ordered]@{ unassigned = $unassignedRings.Count; total = $rings.Count; examples = (Select-SecOakExample $unassignedRings.displayName) }) `
                        -Risk 'The update schedule and deadlines in these rings apply to no device.' `
                        -Recommendation 'Assign each update ring to the intended device group or delete rings that are no longer wanted.'))
        }
    }
    if ($windowsPresent -and $featureResult.Success) {
        if ($endOfSupportProfiles.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-18' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Feature update profiles hold devices on a Windows version that is out of support' `
                        -Evidence ([ordered]@{ profiles = $endOfSupportProfiles.Count; examples = (Select-SecOakExample @($endOfSupportProfiles | ForEach-Object { '{0} ({1})' -f $_.displayName, $_.featureUpdateVersion })) }) `
                        -Risk 'Devices pinned to an unsupported Windows version stop receiving security updates while appearing fully managed.' `
                        -Recommendation 'Change each feature update profile to a supported Windows version and let devices upgrade.'))
        }
        elseif ($featureProfiles.Count -eq 0) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-18' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'No Windows feature update profile exists' `
                        -Evidence ([ordered]@{ featureUpdateProfiles = 0; updateRings = $rings.Count }) `
                        -Risk 'Which Windows version devices move to is left to the update ring and to Microsoft''s rollout, so version upgrades are not planned or tested first.' `
                        -Recommendation 'Optional for a small business: create a feature update profile that targets the Windows version you have tested, and update it when you are ready for the next one.'))
        }
        elseif ($unassignedFeature.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-18' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Feature update profiles that are not assigned' `
                        -Evidence ([ordered]@{ unassigned = $unassignedFeature.Count; total = $featureProfiles.Count; examples = (Select-SecOakExample $unassignedFeature.displayName) }) `
                        -Risk 'The target Windows version in these profiles applies to no device.' `
                        -Recommendation 'Assign each profile to the intended device group or delete profiles that are no longer wanted.'))
        }
    }
    # INTUNE-19 and INTUNE-20: absence is informational (recorded in the summary); only inert profiles are raised.
    if ($unassignedQuality.Count) {
        $findings.Add((New-SecOakFinding -Id 'INTUNE-19' -Area $area -Severity Low -BaselineControl 'None' `
                    -Title 'Windows quality update profiles that are not assigned' `
                    -Evidence ([ordered]@{ unassigned = $unassignedQuality.Count; total = $qualityProfiles.Count; examples = (Select-SecOakExample $unassignedQuality.displayName) }) `
                    -Risk 'The expedited security patch in these profiles reaches no device.' `
                    -Recommendation 'Assign each profile to the intended device group or delete profiles that are no longer wanted.'))
    }
    if ($unassignedDriver.Count) {
        $findings.Add((New-SecOakFinding -Id 'INTUNE-20' -Area $area -Severity Low -BaselineControl 'None' `
                    -Title 'Windows driver update profiles that are not assigned' `
                    -Evidence ([ordered]@{ unassigned = $unassignedDriver.Count; total = $driverProfiles.Count; examples = (Select-SecOakExample $unassignedDriver.displayName) }) `
                    -Risk 'Driver updates in these profiles reach no device.' `
                    -Recommendation 'Assign each profile to the intended device group or delete profiles that are no longer wanted.'))
    }
    #endregion

    #region INTUNE-21: enrollment restrictions (beta: v1.0 returns the newer per-platform restriction entries without a type, and the type filter fails live)
    $enrollmentResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/EnrollmentRestrictions' `
        -Path '/deviceManagement/deviceEnrollmentConfigurations' -ApiVersion beta -RawName 'intune-enrollment-configurations'
    if ($enrollmentResult.Success) {
        $enrollmentConfigs = @($enrollmentResult.Items)
        $defaultRestrictions = $enrollmentConfigs | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionsConfiguration' } | Sort-Object priority | Select-Object -First 1
        $singleRestrictions = @($enrollmentConfigs | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.deviceEnrollmentPlatformRestrictionConfiguration' })
        $defaultByPlatform = [ordered]@{ Windows = $defaultRestrictions.windowsRestriction; iOS = $defaultRestrictions.iosRestriction; Android = $defaultRestrictions.androidRestriction; macOS = $defaultRestrictions.macOSRestriction }
        $openPlatforms = [System.Collections.Generic.List[string]]::new()
        foreach ($platform in $defaultByPlatform.Keys) {
            $restriction = $defaultByPlatform[$platform]
            if (-not $restriction) { continue }
            $blockedByDefault = [bool]$restriction.platformBlocked -or [bool]$restriction.personalDeviceEnrollmentBlocked
            $blockedBySingle = @($singleRestrictions | Where-Object { (ConvertTo-SecOakIntunePlatform $_.platformType) -eq $platform -and ([bool]$_.platformRestriction.platformBlocked -or [bool]$_.platformRestriction.personalDeviceEnrollmentBlocked) }).Count -gt 0
            # A per-platform restriction only applies to its assigned groups, so it narrows the exposure without closing the default.
            if (-not $blockedByDefault -and -not $blockedBySingle) { $openPlatforms.Add($platform) }
        }
        $summary.enrollment = [ordered]@{
            configurations                  = $enrollmentConfigs.Count
            platformRestrictionOverrides    = $singleRestrictions.Count
            personalEnrollmentOpenByDefault = $openPlatforms.ToArray()
        }
        $relevantOpen = @($openPlatforms | Where-Object { (-not $inventoryKnown) -or $platformCounts[$_] -gt 0 })
        if ($relevantOpen.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-21' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Personally owned devices can enroll in Intune' `
                        -Evidence ([ordered]@{ platformsOpen = $relevantOpen; personallyOwnedEnrolled = @($relevantOpen | ForEach-Object { '{0}: {1}' -f $_, [int]$personalByPlatform[$_] }) }) `
                        -Risk 'Any user can enroll a home computer or phone and, once enrolled, that device can qualify for access that was meant for company-owned equipment.' `
                        -Recommendation 'In enrollment device platform restrictions, block personally owned devices for each platform unless bring-your-own-device is intended; for phones, use app protection policies instead of enrollment.'))
        }
    }
    #endregion

    #region INTUNE-22 and 23: Windows Autopilot (identities v1.0 without $select, which returns 500 live; profiles beta-only)
    $autopilotDevices = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/AutopilotDevices' -Path '/deviceManagement/windowsAutopilotDeviceIdentities' -RawName 'intune-autopilot-devices'
    $autopilotCount = if ($autopilotDevices.Success) { @($autopilotDevices.Items).Count } else { 0 }
    $autopilotProfiles = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/AutopilotProfiles' `
        -Path '/deviceManagement/windowsAutopilotDeploymentProfiles?$select=id,displayName,deviceType&$expand=assignments' -ApiVersion beta -RawName 'intune-autopilot-profiles'
    $profilesAssigned = if ($autopilotProfiles.Success) { @($autopilotProfiles.Items | Where-Object { @($_.assignments).Count -gt 0 }).Count } else { 0 }
    $summary.autopilot = [ordered]@{
        registeredDevices  = $autopilotCount
        deploymentProfiles = if ($autopilotProfiles.Success) { @($autopilotProfiles.Items).Count } else { $null }
        profilesAssigned   = $profilesAssigned
    }
    if ($autopilotDevices.Success -and $autopilotProfiles.Success -and $autopilotCount -gt 0 -and $profilesAssigned -eq 0) {
        $findings.Add((New-SecOakFinding -Id 'INTUNE-22' -Area $area -Severity Medium -BaselineControl 'None' `
                    -Title 'Autopilot devices are registered but no deployment profile is assigned' `
                    -Evidence ([ordered]@{ registeredDevices = $autopilotCount; deploymentProfiles = @($autopilotProfiles.Items).Count; assigned = 0 }) `
                    -Risk 'New or reset devices go through the standard Windows setup instead of the managed one, so they may end up as personal-style setups with local administrator users.' `
                    -Recommendation 'Create an Autopilot deployment profile (user-driven, standard user) and assign it to all Autopilot devices.'))
    }
    #endregion

    #region INTUNE-24 and 25: app protection policies and managed apps (v1.0)
    $iosResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/AppProtectionIos' `
        -Path '/deviceAppManagement/iosManagedAppProtections?$select=id,displayName,periodOfflineBeforeAccessCheck&$expand=assignments' -RawName 'intune-app-protection-ios'
    $androidResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/AppProtectionAndroid' `
        -Path '/deviceAppManagement/androidManagedAppProtections?$select=id,displayName,periodOfflineBeforeAccessCheck&$expand=assignments' -RawName 'intune-app-protection-android'
    $appsResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/ManagedApps' `
        -Path '/deviceAppManagement/mobileApps?$select=id,displayName,publisher,createdDateTime' -RawName 'intune-managed-apps'
    $mam = [ordered]@{ iOS = $iosResult; Android = $androidResult }
    $summary.appProtection = [ordered]@{}
    foreach ($platform in $mam.Keys) {
        $r = $mam[$platform]
        if (-not $r.Success) { continue }
        $policies = @($r.Items)
        $unassigned = @($policies | Where-Object { @($_.assignments).Count -eq 0 })
        $summary.appProtection[$platform] = '{0} policies ({1} unassigned)' -f $policies.Count, $unassigned.Count
        $platformDevices = $platformCounts[$platform]
        if ($policies.Count -eq 0 -and $platformDevices -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-24' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title "No app protection policy for $platform" `
                        -Evidence ([ordered]@{ platform = $platform; policies = 0; managedDevices = $platformDevices }) `
                        -Risk 'Company email and files inside Outlook, Teams, and Office on phones can be copied into personal apps or left on a phone that is lost, with no way to wipe only the company data.' `
                        -Recommendation "Create an app protection policy for $platform that requires a PIN, blocks copy to unmanaged apps, and allows a selective wipe, and assign it to all users."))
        }
        elseif ($unassigned.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-24' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title "App protection policies for $platform that are not assigned" `
                        -Evidence ([ordered]@{ platform = $platform; unassigned = $unassigned.Count; total = $policies.Count; examples = (Select-SecOakExample $unassigned.displayName) }) `
                        -Risk 'These policies protect no one until they are assigned.' `
                        -Recommendation 'Assign each app protection policy to all users or the intended groups.'))
        }
    }
    if ($appsResult.Success) {
        $apps = @($appsResult.Items)
        $summary.managedApps = [ordered]@{ total = $apps.Count; topPublishers = @($apps | Group-Object publisher | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }) }
    }
    #endregion

    #region INTUNE-26 and 27: scripts and remediations (beta-only endpoints)
    $scriptResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/DeviceScripts' `
        -Path '/deviceManagement/deviceManagementScripts?$select=id,displayName,runAsAccount,enforceSignatureCheck,runAs32Bit&$expand=assignments' -ApiVersion beta -RawName 'intune-device-scripts'
    $remediationResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/Remediations' `
        -Path '/deviceManagement/deviceHealthScripts?$select=id,displayName,publisher,isGlobalScript,runAsAccount&$expand=assignments' -ApiVersion beta -RawName 'intune-remediations'
    if ($scriptResult.Success) {
        $scripts = @($scriptResult.Items)
        $unsigned = @($scripts | Where-Object { -not $_.enforceSignatureCheck })
        $summary.scripts = [ordered]@{
            platformScripts        = $scripts.Count
            withoutSignatureCheck  = $unsigned.Count
            runAsSystem            = @($scripts | Where-Object runAsAccount -eq 'system').Count
            unassigned             = @($scripts | Where-Object { @($_.assignments).Count -eq 0 }).Count
        }
        if ($unsigned.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-26' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'PowerShell scripts deployed by Intune without a signature check' `
                        -Evidence ([ordered]@{ scripts = $unsigned.Count; total = $scripts.Count; runAsSystem = @($unsigned | Where-Object runAsAccount -eq 'system').Count; examples = (Select-SecOakExample $unsigned.displayName) }) `
                        -Risk 'Scripts run on every assigned device, usually as the system account. Anyone who can edit them in Intune can run anything on all devices, and there is no signature to catch a tampered script.' `
                        -Recommendation 'Review each script, remove ones no longer needed, run as the user where possible, and sign scripts and enable the signature check if the tooling allows.'))
        }
    }
    if ($remediationResult.Success) {
        $remediations = @($remediationResult.Items)
        $unassignedRemediations = @($remediations | Where-Object { -not $_.isGlobalScript -and @($_.assignments).Count -eq 0 })
        $summary.remediations = [ordered]@{ total = $remediations.Count; custom = @($remediations | Where-Object { -not $_.isGlobalScript }).Count; unassigned = $unassignedRemediations.Count }
        if ($unassignedRemediations.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-27' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Remediation scripts that are not assigned' `
                        -Evidence ([ordered]@{ unassigned = $unassignedRemediations.Count; total = $remediations.Count; examples = (Select-SecOakExample $unassignedRemediations.displayName) }) `
                        -Risk 'These detection and fix scripts run on no device, so whatever issue they were written for goes unchecked.' `
                        -Recommendation 'Assign each remediation to the intended device group or delete ones that are no longer wanted.'))
        }
    }
    #endregion

    #region INTUNE-28: Intune role assignments (v1.0). The Entra "Intune Administrator" role is covered by the Identity area.
    $roleResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/RoleDefinitions' `
        -Path '/deviceManagement/roleDefinitions?$select=id,displayName,isBuiltIn' -RawName 'intune-role-definitions'
    if ($roleResult.Success) {
        $roles = @($roleResult.Items)
        $assignmentsByRole = [ordered]@{}
        $broad = [System.Collections.Generic.List[string]]::new()
        $assignmentsRead = 0
        foreach ($role in $roles) {
            $assignmentResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/RoleAssignments' `
                -Path "/deviceManagement/roleDefinitions/$($role.id)/roleAssignments" -NoGap:($assignmentsRead -gt 0)
            if (-not $assignmentResult.Success) { break }
            $assignmentsRead++
            $assignments = @($assignmentResult.Items)
            if ($assignments.Count -eq 0) { continue }
            $memberGroups = @($assignments | ForEach-Object { @($_.members) } | Sort-Object -Unique).Count
            $assignmentsByRole[$role.displayName] = '{0} assignments, {1} member groups{2}' -f $assignments.Count, $memberGroups, $(if (-not $role.isBuiltIn) { ' (custom role)' } else { '' })
            # More than two assignments or member groups for one role is broader than a small business normally needs.
            if ($assignments.Count -gt 2 -or $memberGroups -gt 2) { $broad.Add($role.displayName) }
        }
        $summary.roleBasedAccess = [ordered]@{
            roleDefinitions   = $roles.Count
            customRoles       = @($roles | Where-Object { -not $_.isBuiltIn }).Count
            rolesRead         = $assignmentsRead
            assignmentsByRole = @($assignmentsByRole.Keys | ForEach-Object { '{0}: {1}' -f $_, $assignmentsByRole[$_] })
        }
        if ($broad.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-28' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Intune roles assigned more broadly than a small business needs' `
                        -Evidence ([ordered]@{ roles = $broad.Count; examples = (Select-SecOakExample @($broad | ForEach-Object { '{0}: {1}' -f $_, $assignmentsByRole[$_] })) }) `
                        -Risk 'Every person in these groups can change device policies, run scripts on all devices, or wipe them, and a compromised account among them inherits that reach.' `
                        -Recommendation 'Reduce each Intune role to the few named administrators who need it, use scope tags for helpdesk roles, and review the assignments quarterly.'))
        }
    }
    #endregion

    #region INTUNE-29: Windows LAPS coverage (metadata only; the credentials property is never selected)
    $windowsDeviceResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/WindowsDirectoryDevices' `
        -Path "/devices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceId,displayName,trustType,accountEnabled,approximateLastSignInDateTime" -RawName 'intune-windows-directory-devices'
    $lapsResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/LapsCoverage' `
        -Path '/directory/deviceLocalCredentials?$select=id,deviceName,lastBackupDateTime' -RawName 'intune-laps-metadata'
    if ($windowsDeviceResult.Success -and $lapsResult.Success) {
        $activeCutoff = $now.AddDays(-90)
        $backupCutoff = $now.AddDays(-30)
        $joined = @($windowsDeviceResult.Items | Where-Object {
                $_.trustType -in 'AzureAd', 'ServerAd' -and $_.accountEnabled -ne $false -and
                (($d = ConvertTo-SecOakUtcDate $_.approximateLastSignInDateTime) -and $d -ge $activeCutoff)
            })
        $recentBackup = @{}
        foreach ($credential in @($lapsResult.Items)) {
            $backup = ConvertTo-SecOakUtcDate $credential.lastBackupDateTime
            if ($backup -and $backup -ge $backupCutoff) { $recentBackup["$($credential.id)".ToLowerInvariant()] = $true }
        }
        $withoutLaps = @($joined | Where-Object { -not $recentBackup["$($_.deviceId)".ToLowerInvariant()] })
        $coverage = if ($joined.Count) { [math]::Round(100 * ($joined.Count - $withoutLaps.Count) / $joined.Count, 1) } else { $null }
        $summary.windowsLaps = [ordered]@{
            activeJoinedWindowsDevices = $joined.Count
            devicesWithRecentBackup    = $recentBackup.Count
            coveragePercent            = $coverage
        }
        if ($joined.Count -and $coverage -lt 90) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-29' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Windows devices without a managed local administrator password (LAPS)' `
                        -Evidence ([ordered]@{ devicesWithoutRecentBackup = $withoutLaps.Count; activeJoinedWindowsDevices = $joined.Count; coveragePercent = $coverage; window = 'password backed up within 30 days; devices active within 90 days'; examples = (Select-SecOakExample $withoutLaps.displayName) }) `
                        -Risk 'The built-in local administrator password on these devices is either shared across devices or unknown to IT. A shared password lets an attacker who takes one device sign in to all of them.' `
                        -Recommendation 'Deploy Windows LAPS through an Intune account protection policy so each device gets a unique, rotated local administrator password backed up to Microsoft Entra ID.'))
        }
    }
    #endregion

    #region INTUNE-31: device encryption state (beta-only collection)
    $encryptionResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/EncryptionState' `
        -Path '/deviceManagement/managedDeviceEncryptionStates?$select=id,deviceName,deviceType,encryptionState,encryptionReadinessState' -ApiVersion beta -RawName 'intune-encryption-states'
    $encryptedDeviceIds = @{}
    if ($encryptionResult.Success) {
        $states = @($encryptionResult.Items)
        $computers = @($states | Where-Object { "$($_.deviceType)" -match 'windows|mac' })
        $unencrypted = @($computers | Where-Object { $_.encryptionState -ne 'encrypted' })
        foreach ($state in $computers) { if ($state.encryptionState -eq 'encrypted') { $encryptedDeviceIds["$($state.id)".ToLowerInvariant()] = $state.deviceName } }
        $summary.encryption = [ordered]@{
            computersReported = $computers.Count
            encrypted         = $computers.Count - $unencrypted.Count
            notEncrypted      = $unencrypted.Count
            notReady          = @($unencrypted | Where-Object { $_.encryptionReadinessState -ne 'ready' }).Count
        }
        if ($unencrypted.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-31' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Managed computers that are not encrypted' `
                        -Evidence ([ordered]@{ notEncrypted = $unencrypted.Count; total = $computers.Count; examples = (Select-SecOakExample @($unencrypted | ForEach-Object { '{0} ({1}, readiness {2})' -f $_.deviceName, $_.encryptionState, $_.encryptionReadinessState })) }) `
                        -Risk 'If one of these laptops is lost or stolen, everything stored on it can be read by removing the disk, including cached email and files.' `
                        -Recommendation 'Assign a BitLocker (or FileVault) policy that requires encryption and fix the devices reported as not ready (usually a missing TPM setting or a pending restart).'))
        }
    }
    #endregion

    #region INTUNE-30: BitLocker recovery key escrow (metadata only; the key property is never selected). Expect a 403 gap until BitlockerKey.ReadBasic.All is granted.
    $keyResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/BitLockerKeyEscrow' `
        -Path '/informationProtection/bitlocker/recoveryKeys?$select=id,deviceId,createdDateTime,volumeType'
    if ($keyResult.Success) {
        $keyedDevices = @{}
        foreach ($key in @($keyResult.Items)) { $keyedDevices["$($key.deviceId)".ToLowerInvariant()] = $true }
        # Managed device id is not the directory device id; map through azureADDeviceId from the platform inventory.
        $entraIdByManagedId = @{}
        foreach ($device in $managedDevices) { if ($device.azureADDeviceId) { $entraIdByManagedId["$($device.id)".ToLowerInvariant()] = "$($device.azureADDeviceId)".ToLowerInvariant() } }
        $encryptedWithoutKey = [System.Collections.Generic.List[string]]::new()
        $encryptedChecked = 0
        foreach ($managedId in $encryptedDeviceIds.Keys) {
            $entraId = $entraIdByManagedId[$managedId]
            if (-not $entraId) { continue }
            $encryptedChecked++
            if (-not $keyedDevices[$entraId]) { $encryptedWithoutKey.Add($encryptedDeviceIds[$managedId]) }
        }
        $summary.bitLockerEscrow = [ordered]@{ recoveryKeys = @($keyResult.Items).Count; devicesWithKey = $keyedDevices.Count; encryptedDevicesChecked = $encryptedChecked; encryptedWithoutKey = $encryptedWithoutKey.Count }
        if ($encryptedWithoutKey.Count) {
            $findings.Add((New-SecOakFinding -Id 'INTUNE-30' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Encrypted devices with no BitLocker recovery key on file' `
                        -Evidence ([ordered]@{ devices = $encryptedWithoutKey.Count; encryptedDevicesChecked = $encryptedChecked; examples = (Select-SecOakExample $encryptedWithoutKey.ToArray()) }) `
                        -Risk 'If one of these devices asks for its recovery key after a hardware change or a failed update, nobody can unlock it and the data on it is lost.' `
                        -Recommendation 'Set the BitLocker policy to back up recovery keys to Microsoft Entra ID and confirm each existing device escrows its key (a policy refresh or re-encryption may be needed).'))
        }
    }
    #endregion

    #region INTUNE-32: Microsoft Tunnel (beta-only; informational)
    $tunnelResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Intune/MicrosoftTunnel' `
        -Path '/deviceManagement/microsoftTunnelConfigurations?$select=id,displayName' -ApiVersion beta -RawName 'intune-tunnel-configurations'
    if ($tunnelResult.Success) { $summary.microsoftTunnel = [ordered]@{ configurations = @($tunnelResult.Items).Count } }
    #endregion

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
