function Get-SecOakSubscribedSkuCache {
    <#
    .SYNOPSIS
        Reads /subscribedSkus once per run and caches the result for licence gating.
    .DESCRIPTION
        Returns $null when the licence list cannot be read, so callers treat licensing as
        unknown and run the check anyway instead of guessing.
    .NOTES
        Internal helper. Permission: Directory.Read.All.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check
    )
    if (-not $Context.Cache.ContainsKey('SubscribedSkus')) {
        $result = Invoke-SecOakGraphGet -Context $Context -Area $Area -Check $Check -Path '/subscribedSkus'
        # Direct assignment: an "if" expression would collapse an empty array to $null.
        $Context.Cache.SubscribedSkus = $null
        if ($result.Success) { $Context.Cache.SubscribedSkus = @($result.Items) }
    }
    if ($null -eq $Context.Cache.SubscribedSkus) { return $null }
    # The unary comma keeps an empty licence list distinct from "unreadable" ($null) when the array unrolls.
    return , @($Context.Cache.SubscribedSkus)
}

function Get-SecOakPurviewLicenseState {
    <#
    .SYNOPSIS
        Derives the Purview licence tiers from the tenant's enabled service plans.
    .DESCRIPTION
        Uses service plan names as a proxy (the catalogue notes the exact SKU lists are
        unverified): MIP_S_CLP1 marks the Microsoft 365 E3 and Business Premium tier
        (manual sensitivity labels, basic data loss prevention and retention, default alert
        policies); MIP_S_CLP2 marks the E5 or E5 Compliance tier (Teams data loss prevention,
        automatic labelling, advanced alerts); TEAMS* marks a Teams licence.
        When the licence list is unreadable every flag is $null (unknown).
    .NOTES
        Internal helper. Permission: Directory.Read.All.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Area
    )
    $skus = Get-SecOakSubscribedSkuCache -Context $Context -Area $Area -Check 'Purview/Licensing'
    if ($null -eq $skus) {
        return [pscustomobject]@{ Known = $false; Compliance = $null; ComplianceE5 = $null; SensitivityLabels = $null; Teams = $null }
    }
    $active = @($skus | Where-Object { $_.capabilityStatus -in 'Enabled', 'Warning' })
    $plans = @($active | ForEach-Object { @($_.servicePlans) } | Where-Object { $_.provisioningStatus -ne 'Disabled' } | ForEach-Object { $_.servicePlanName } | Sort-Object -Unique)
    $parts = @($active.skuPartNumber)
    $e3Tier = [bool]($plans -contains 'MIP_S_CLP1' -or $parts -match '^(SPB|SPE_E3|ENTERPRISEPACK)$')
    $e5Tier = [bool]($plans -contains 'MIP_S_CLP2' -or $parts -match '^(SPE_E5|ENTERPRISEPREMIUM|INFORMATION_PROTECTION_COMPLIANCE)$')
    [pscustomobject]@{
        Known             = $true
        Compliance        = ($e3Tier -or $e5Tier)
        ComplianceE5      = $e5Tier
        SensitivityLabels = [bool]($e3Tier -or $e5Tier -or $plans -match '^RMS_S_PREMIUM')
        Teams             = [bool]($plans -match '^TEAMS')
    }
}

function Test-SecOakLocationSet {
    <#
    .SYNOPSIS
        True when a policy object has the named location property and it holds at least one value.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Policy,
        [Parameter(Mandatory)][string]$Name
    )
    if ($null -eq $Policy) { return $false }
    $property = $Policy.PSObject.Properties[$Name]
    if (-not $property) { return $false }
    [bool](@($property.Value) | Where-Object { $null -ne $_ -and "$_" -ne '' })
}

function Invoke-SecOakPurviewCheck {
    <#
    .SYNOPSIS
        Purview area: data loss prevention, retention, sensitivity labels, alert policies, eDiscovery cases, and open Purview alerts.
    .DESCRIPTION
        Implements catalogue checks M365-32 to M365-37. The first four use Security and
        Compliance PowerShell (Get-* cmdlets only, through Invoke-SecOakComplianceGet); the
        last two use Microsoft Graph. A workload that is not licensed is reported as
        "Not licensed" (a gap with that result), never as a failure. Anything the app cannot
        read is a gap, not a finding.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakPurviewCheck -Context $context
    .NOTES
        Application permissions: Microsoft Exchange Online Protection > Exchange.ManageAsApp
        plus the Global Reader role on the service principal (Security and Compliance
        PowerShell); Directory.Read.All (licence gate); eDiscovery.Read.All (M365-36);
        SecurityAlert.Read.All (M365-37).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Purview'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $licence = Get-SecOakPurviewLicenseState -Context $Context -Area $area
    $summary.licensing = [ordered]@{
        known                = $licence.Known
        complianceTier       = if (-not $licence.Known) { 'unknown' } elseif ($licence.ComplianceE5) { 'E5 or E5 Compliance' } elseif ($licence.Compliance) { 'E3 or Business Premium' } else { 'none detected' }
        teamsLicensed        = $licence.Teams
        sensitivityLabels    = $licence.SensitivityLabels
    }
    # An unknown licence state never blocks a check; only a known "not licensed" does.
    $complianceLicensed = ($licence.Compliance -ne $false)
    $sccSession = 'not attempted'

    #region Security and Compliance PowerShell session
    $complianceReady = $false
    if (Get-Command -Name Invoke-SecOakComplianceGet -ErrorAction SilentlyContinue) {
        $complianceReady = $true
        if (Get-Command -Name Connect-SecOakCompliance -ErrorAction SilentlyContinue) {
            # Connect-SecOakCompliance records its own gap and returns 'none' on failure; the catch is a safety net only.
            try {
                $mode = Connect-SecOakCompliance -Context $Context
                if ("$mode" -eq 'none') { $complianceReady = $false; $sccSession = 'failed (see gaps)' }
                else { $sccSession = 'connected' }
            }
            catch {
                $complianceReady = $false
                $sccSession = 'failed'
                $reason = "$($_.Exception.Message)" -replace '\s+', ' '
                if (-not $reason) { $reason = 'Connect-SecOakCompliance threw without a message.' }
                Add-SecOakGap -Context $Context -Area $area -Check 'Purview/Connect' -EndpointOrCmdlet 'Connect-IPPSSession' -Result 'failed' `
                    -Reason $reason `
                    -FillWith 'Application permission Exchange.ManageAsApp on the Microsoft Exchange Online Protection resource plus the Global Reader role on the service principal.'
            }
        }
    }
    else {
        Add-SecOakGap -Context $Context -Area $area -Check 'Purview/Connect' -EndpointOrCmdlet 'Invoke-SecOakComplianceGet' -Result 'not checkable' `
            -Reason 'The Security and Compliance PowerShell helper is not loaded in this module build.' `
            -FillWith 'Load src\Core\Apis.ps1 (Connect-SecOakCompliance and Invoke-SecOakComplianceGet).'
    }
    $summary.securityAndCompliancePowerShell = $sccSession
    #endregion

    #region M365-32 Data loss prevention
    if (-not $complianceLicensed) {
        $summary.dataLossPrevention = 'Not licensed'
        Add-SecOakGap -Context $Context -Area $area -Check 'Purview/DataLossPrevention' -EndpointOrCmdlet 'Get-DlpCompliancePolicy' -Result 'not licensed' `
            -Reason 'No Microsoft 365 E3, Office 365 E3, Business Premium or E5 plan was found, so data loss prevention is not available.' `
            -FillWith 'Microsoft 365 Business Premium or E3 for Exchange, SharePoint and OneDrive; E5 or E5 Compliance for Teams.'
    }
    elseif ($complianceReady) {
        $policiesResult = Invoke-SecOakComplianceGet -Context $Context -Area $area -Check 'Purview/DataLossPrevention' -Cmdlet Get-DlpCompliancePolicy
        if ($policiesResult.Success) {
            $policies = @($policiesResult.Data)
            $rulesResult = Invoke-SecOakComplianceGet -Context $Context -Area $area -Check 'Purview/DataLossPrevention' -Cmdlet Get-DlpComplianceRule
            $rules = if ($rulesResult.Success) { @($rulesResult.Data) } else { @() }
            $enforced = @($policies | Where-Object { $_.Enabled -eq $true -and $_.Mode -eq 'Enable' })
            $testMode = @($policies | Where-Object { $_.Enabled -eq $true -and $_.Mode -in 'TestWithNotifications', 'TestWithoutNotifications' })
            $coverage = [ordered]@{
                exchange   = [bool]($enforced | Where-Object { Test-SecOakLocationSet -Policy $_ -Name 'ExchangeLocation' })
                sharePoint = [bool]($enforced | Where-Object { Test-SecOakLocationSet -Policy $_ -Name 'SharePointLocation' })
                oneDrive   = [bool]($enforced | Where-Object { Test-SecOakLocationSet -Policy $_ -Name 'OneDriveLocation' })
                teams      = [bool]($enforced | Where-Object { Test-SecOakLocationSet -Policy $_ -Name 'TeamsLocation' })
            }
            $summary.dataLossPrevention = [ordered]@{
                policies         = $policies.Count
                enforced         = $enforced.Count
                inTestMode       = $testMode.Count
                rules            = $rules.Count
                enforcedCoverage = $coverage
            }
            Save-SecOakRawData -Context $Context -Name 'purview-dlp-policies' -Data @($policies | Select-Object Name, Enabled, Mode, Priority, ExchangeLocation, SharePointLocation, OneDriveLocation, TeamsLocation, WhenChanged)
            if ($enforced.Count -eq 0) {
                $findings.Add((New-SecOakFinding -Id 'M365-32' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'No data loss prevention policy is enforced' `
                            -Evidence ([ordered]@{ policies = $policies.Count; enforced = 0; inTestMode = $testMode.Count }) `
                            -Risk 'Nothing stops staff from emailing or sharing bank details, personal data or customer records outside the company by mistake, and there is no record when it happens.' `
                            -Recommendation 'Create one data loss prevention policy from a built-in template (for example financial or personal data for your country) covering Exchange, SharePoint, OneDrive and Teams, run it in test mode for two weeks, then switch it to enforce.'))
            }
            else {
                $missing = @($coverage.GetEnumerator() | Where-Object { -not $_.Value -and -not ($_.Key -eq 'teams' -and $licence.Teams -eq $false) } | ForEach-Object { $_.Key })
                $teamsGapOnly = ($missing.Count -eq 1 -and $missing[0] -eq 'teams')
                if ($missing.Count -and -not ($teamsGapOnly -and $licence.ComplianceE5 -eq $false)) {
                    $findings.Add((New-SecOakFinding -Id 'M365-32' -Area $area -Severity Medium -BaselineControl 'None' `
                                -Title 'Data loss prevention does not cover every workload' `
                                -Evidence ([ordered]@{ enforcedPolicies = $enforced.Count; uncoveredWorkloads = $missing; enforcedCoverage = $coverage }) `
                                -Risk 'Sensitive data can still leave through the workloads that no enforced policy watches.' `
                                -Recommendation 'Extend an enforced policy to the uncovered workloads. Teams coverage needs an E5 or E5 Compliance licence.'))
                }
            }
            if ($testMode.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-32' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Data loss prevention policies left in test mode' `
                            -Evidence ([ordered]@{ inTestMode = $testMode.Count; examples = (Select-SecOakExample @($testMode | ForEach-Object { '{0} ({1})' -f $_.Name, $_.Mode })) }) `
                            -Risk 'A policy in test mode only reports matches; it never blocks anything, so the protection people believe is in place is not.' `
                            -Recommendation 'Review the test-mode reports and switch each policy to enforce, or remove it if it is not wanted.'))
            }
        }
        else { $summary.dataLossPrevention = 'Cannot read' }
    }
    else { $summary.dataLossPrevention = 'Cannot read' }
    #endregion

    #region M365-33 Retention
    if (-not $complianceLicensed) {
        $summary.retention = 'Not licensed'
        Add-SecOakGap -Context $Context -Area $area -Check 'Purview/Retention' -EndpointOrCmdlet 'Get-RetentionCompliancePolicy' -Result 'not licensed' `
            -Reason 'No Microsoft 365 E3, Business Premium or E5 plan was found, so retention policies are not available.' `
            -FillWith 'Microsoft 365 Business Premium or E3 for basic retention; E5 or E5 Compliance for automatic labelling and records management.'
    }
    elseif ($complianceReady) {
        # -DistributionDetail is needed for accurate location and DistributionStatus values; one call covers all policies.
        $retentionResult = Invoke-SecOakComplianceGet -Context $Context -Area $area -Check 'Purview/Retention' -Cmdlet Get-RetentionCompliancePolicy -Parameters @{ DistributionDetail = $true }
        if ($retentionResult.Success) {
            $retentionPolicies = @($retentionResult.Data)
            $retentionRules = Invoke-SecOakComplianceGet -Context $Context -Area $area -Check 'Purview/Retention' -Cmdlet Get-RetentionComplianceRule
            $labelsResult = Invoke-SecOakComplianceGet -Context $Context -Area $area -Check 'Purview/Retention' -Cmdlet Get-ComplianceTag
            $enabledPolicies = @($retentionPolicies | Where-Object { $_.Enabled -eq $true })
            $coverage = [ordered]@{
                exchange      = [bool]($enabledPolicies | Where-Object { (Test-SecOakLocationSet -Policy $_ -Name 'ExchangeLocation') -or (Test-SecOakLocationSet -Policy $_ -Name 'ModernGroupLocation') })
                sharePoint    = [bool]($enabledPolicies | Where-Object { Test-SecOakLocationSet -Policy $_ -Name 'SharePointLocation' })
                oneDrive      = [bool]($enabledPolicies | Where-Object { Test-SecOakLocationSet -Policy $_ -Name 'OneDriveLocation' })
                teamsChats    = [bool]($enabledPolicies | Where-Object { Test-SecOakLocationSet -Policy $_ -Name 'TeamsChatLocation' })
                teamsChannels = [bool]($enabledPolicies | Where-Object { Test-SecOakLocationSet -Policy $_ -Name 'TeamsChannelLocation' })
            }
            $notDistributed = @($enabledPolicies | Where-Object { $_.PSObject.Properties['DistributionStatus'] -and "$($_.DistributionStatus)" -notin 'Success', '' })
            $summary.retention = [ordered]@{
                policies        = $retentionPolicies.Count
                enabled         = $enabledPolicies.Count
                rules           = if ($retentionRules.Success) { @($retentionRules.Data).Count } else { 'Cannot read' }
                retentionLabels = if ($labelsResult.Success) { @($labelsResult.Data).Count } else { 'Cannot read' }
                coverage        = $coverage
                notDistributed  = $notDistributed.Count
            }
            Save-SecOakRawData -Context $Context -Name 'purview-retention-policies' -Data @($retentionPolicies | Select-Object Name, Enabled, Mode, DistributionStatus, ExchangeLocation, SharePointLocation, OneDriveLocation, ModernGroupLocation, TeamsChatLocation, TeamsChannelLocation)
            $missingCore = @($coverage.GetEnumerator() | Where-Object { $_.Key -in 'exchange', 'sharePoint', 'oneDrive' -and -not $_.Value } | ForEach-Object { $_.Key })
            if ($missingCore.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-33' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'No retention policy covers email or files' `
                            -Evidence ([ordered]@{ enabledPolicies = $enabledPolicies.Count; uncovered = $missingCore; coverage = $coverage }) `
                            -Risk 'Deleted email and files disappear for good after the default recycle period, so a mistake, a leaver or an attacker can destroy records the business may need for tax, contracts or a dispute.' `
                            -Recommendation 'Create one retention policy that keeps Exchange, SharePoint and OneDrive content for the period your legal and tax obligations require (commonly seven years), and apply it to all locations.'))
            }
            if ($licence.Teams -ne $false -and -not ($coverage.teamsChats -and $coverage.teamsChannels)) {
                $findings.Add((New-SecOakFinding -Id 'M365-33' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Teams chats or channel messages have no retention policy' `
                            -Evidence ([ordered]@{ teamsChats = $coverage.teamsChats; teamsChannels = $coverage.teamsChannels }) `
                            -Risk 'Teams conversations are increasingly where decisions are made; without a retention policy they cannot be relied on as records.' `
                            -Recommendation 'Add a Teams retention policy for chats and channel messages with the same period as email.'))
            }
            if ($notDistributed.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-33' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Retention policies that have not finished deploying' `
                            -Evidence ([ordered]@{ policies = $notDistributed.Count; examples = (Select-SecOakExample @($notDistributed | ForEach-Object { '{0} ({1})' -f $_.Name, $_.DistributionStatus })) }) `
                            -Risk 'A policy that is pending or in error is not protecting the locations it names.' `
                            -Recommendation 'Open each policy in the Purview portal, read the distribution error, and redeploy it.'))
            }
        }
        else { $summary.retention = 'Cannot read' }
    }
    else { $summary.retention = 'Cannot read' }
    #endregion

    #region M365-34 Sensitivity labels
    if ($licence.SensitivityLabels -eq $false) {
        $summary.sensitivityLabels = 'Not licensed'
        Add-SecOakGap -Context $Context -Area $area -Check 'Purview/SensitivityLabels' -EndpointOrCmdlet 'Get-Label' -Result 'not licensed' `
            -Reason 'No Azure Information Protection Plan 1 (included in Business Premium and E3) or higher plan was found.' `
            -FillWith 'Microsoft 365 Business Premium or E3 for manual labelling; E5 for automatic labelling.'
    }
    elseif ($complianceReady) {
        $labelResult = Invoke-SecOakComplianceGet -Context $Context -Area $area -Check 'Purview/SensitivityLabels' -Cmdlet Get-Label
        $labelPolicyResult = Invoke-SecOakComplianceGet -Context $Context -Area $area -Check 'Purview/SensitivityLabels' -Cmdlet Get-LabelPolicy
        if ($labelResult.Success -and $labelPolicyResult.Success) {
            $labels = @($labelResult.Data | Where-Object { -not ($_.PSObject.Properties['Disabled'] -and $_.Disabled -eq $true) })
            $labelPolicies = @($labelPolicyResult.Data)
            $publishing = @($labelPolicies | Where-Object { $_.Enabled -ne $false -and $_.PSObject.Properties['Labels'] -and @($_.Labels).Count -gt 0 })
            $settingsText = @($publishing | ForEach-Object { @($_.Settings) -join ';' }) -join ';'
            $hasDefaultLabel = [bool]($settingsText -match '(?i)defaultlabelid,\s*[0-9a-f-]{8,}')
            $requiresJustification = [bool]($settingsText -match '(?i)requiredowngradejustification,\s*true')
            $summary.sensitivityLabels = [ordered]@{
                labels                = $labels.Count
                labelPolicies         = $labelPolicies.Count
                publishingPolicies    = $publishing.Count
                defaultLabelSet       = $hasDefaultLabel
                downgradeJustification = $requiresJustification
            }
            Save-SecOakRawData -Context $Context -Name 'purview-label-policies' -Data @($labelPolicies | Select-Object Name, Enabled, Mode, Labels, Settings)
            if ($labels.Count -eq 0 -or $publishing.Count -eq 0) {
                $findings.Add((New-SecOakFinding -Id 'M365-34' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'No sensitivity labels are published to users' `
                            -Evidence ([ordered]@{ labels = $labels.Count; publishingPolicies = $publishing.Count }) `
                            -Risk 'Staff have no way to mark a document or email as confidential, so nothing can encrypt it or warn before it is shared outside the company.' `
                            -Recommendation 'Publish a small set of labels (for example Public, Internal, Confidential) with encryption on Confidential, and train staff to use them.'))
            }
            elseif (-not $hasDefaultLabel -or -not $requiresJustification) {
                $findings.Add((New-SecOakFinding -Id 'M365-34' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Sensitivity label policy has no default label or no downgrade justification' `
                            -Evidence ([ordered]@{ defaultLabelSet = $hasDefaultLabel; downgradeJustification = $requiresJustification; publishingPolicies = $publishing.Count }) `
                            -Risk 'Without a default label most documents stay unlabelled, and without justification a label can be quietly removed to bypass its protection.' `
                            -Recommendation 'Set a default label for documents and email in the label policy, and require users to give a reason when they lower or remove a label.'))
            }
        }
        else { $summary.sensitivityLabels = 'Cannot read' }
    }
    else { $summary.sensitivityLabels = 'Cannot read' }
    #endregion

    #region M365-35 Alert policies
    if (-not $complianceLicensed) {
        $summary.alertPolicies = 'Not licensed'
        Add-SecOakGap -Context $Context -Area $area -Check 'Purview/AlertPolicies' -EndpointOrCmdlet 'Get-ProtectionAlert' -Result 'not licensed' `
            -Reason 'The default alert policies need Microsoft 365 E3, Business Premium or higher.' `
            -FillWith 'Microsoft 365 Business Premium or E3; E5 for advanced and custom threshold alerts.'
    }
    elseif ($complianceReady) {
        $alertResult = Invoke-SecOakComplianceGet -Context $Context -Area $area -Check 'Purview/AlertPolicies' -Cmdlet Get-ProtectionAlert
        if ($alertResult.Success) {
            $alertPolicies = @($alertResult.Data)
            $defaults = @($alertPolicies | Where-Object { -not $_.PSObject.Properties['IsSystemRule'] -or $_.IsSystemRule -eq $true })
            $disabledHigh = @($defaults | Where-Object { $_.Disabled -eq $true -and "$($_.Severity)" -eq 'High' })
            $noRecipient = @($alertPolicies | Where-Object { $_.Disabled -ne $true -and -not (@($_.NotifyUser) | Where-Object { "$_" -ne '' }) })
            $summary.alertPolicies = [ordered]@{
                total               = $alertPolicies.Count
                defaultPolicies     = $defaults.Count
                disabled            = @($alertPolicies | Where-Object { $_.Disabled -eq $true }).Count
                disabledHighDefault = $disabledHigh.Count
                enabledNoRecipient  = $noRecipient.Count
                byCategory          = @($alertPolicies | Group-Object Category | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            }
            Save-SecOakRawData -Context $Context -Name 'purview-alert-policies' -Data @($alertPolicies | Select-Object Name, Disabled, Severity, Category, NotifyUser, IsSystemRule)
            if ($disabledHigh.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-35' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Default high-severity alert policies are switched off' `
                            -Evidence ([ordered]@{ disabled = $disabledHigh.Count; examples = (Select-SecOakExample @($disabledHigh.Name)) }) `
                            -Risk 'Microsoft would normally raise an alert for events such as an admin role being granted or email being forwarded outside; with these off, an account takeover can run unnoticed.' `
                            -Recommendation 'Turn the default high-severity alert policies back on in the Defender portal under Policies and rules, Alert policy.'))
            }
            if ($noRecipient.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-35' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Alert policies with no email recipient' `
                            -Evidence ([ordered]@{ policies = $noRecipient.Count; examples = (Select-SecOakExample @($noRecipient.Name)) }) `
                            -Risk 'Alerts only appear in the portal, so nobody is told when something suspicious happens unless they go looking.' `
                            -Recommendation 'Send alert notifications to a monitored mailbox or your IT provider, and check the Alerts page weekly.'))
            }
        }
        else { $summary.alertPolicies = 'Cannot read' }
    }
    else { $summary.alertPolicies = 'Cannot read' }
    #endregion

    #region M365-36 eDiscovery cases and legal holds (Graph)
    $casesResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Purview/EDiscoveryCases' -Path '/security/cases/ediscoveryCases?$select=id,displayName,status,createdDateTime,lastModifiedDateTime,closedDateTime' -RawName 'purview-ediscovery-cases'
    if ($casesResult.Success) {
        $cases = @($casesResult.Items)
        $activeCases = @($cases | Where-Object { "$($_.status)" -eq 'active' })
        $holdCount = 0
        $holdCasesRead = 0
        $holdCap = 25
        foreach ($case in ($activeCases | Select-Object -First $holdCap)) {
            $holds = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Purview/EDiscoveryHolds' -Path "/security/cases/ediscoveryCases/$($case.id)/legalHolds?`$select=id,displayName,status,isEnabled" -NoGap
            if ($holds.Success) { $holdCasesRead++; $holdCount += @($holds.Items).Count }
        }
        $staleCutoff = [datetime]::UtcNow.AddDays(-365)
        $staleCases = @($activeCases | Where-Object { ($d = ConvertTo-SecOakUtcDate $_.lastModifiedDateTime) -and $d -lt $staleCutoff })
        $summary.eDiscovery = [ordered]@{
            cases           = $cases.Count
            activeCases     = $activeCases.Count
            legalHolds      = $holdCount
            holdCasesRead   = $holdCasesRead
            holdCasesSkipped = [math]::Max(0, $activeCases.Count - $holdCap)
            activeOverOneYearIdle = $staleCases.Count
        }
        if ($staleCases.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-36' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'eDiscovery cases left active for more than a year without activity' `
                        -Evidence ([ordered]@{ cases = $staleCases.Count; examples = (Select-SecOakExample @($staleCases | ForEach-Object { '{0} (last change {1:yyyy-MM-dd})' -f $_.displayName, (ConvertTo-SecOakUtcDate $_.lastModifiedDateTime) })) }) `
                        -Risk 'Forgotten cases keep holds on mailboxes and sites, so data that should have been deleted is retained and storage keeps growing.' `
                        -Recommendation 'Review each idle case with whoever opened it; close it and release its holds if the matter is finished.'))
        }
    }
    else { $summary.eDiscovery = 'Cannot read' }
    #endregion

    #region M365-37 Open high-severity Purview alerts (Graph)
    $alertsPath = "/security/alerts_v2?`$filter=(status eq 'new' or status eq 'inProgress') and severity eq 'high'&`$select=id,title,severity,status,serviceSource,createdDateTime,lastUpdateDateTime&`$top=2000"
    $alertsResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Purview/OpenAlerts' -Path $alertsPath -RawName 'purview-open-high-alerts'
    if ($alertsResult.Success) {
        $alerts = @($alertsResult.Items)
        $purviewSources = 'microsoftDataLossPrevention', 'microsoftInsiderRiskManagement'
        $purviewAlerts = @($alerts | Where-Object { "$($_.serviceSource)" -in $purviewSources })
        $weekAgo = [datetime]::UtcNow.AddDays(-7)
        $purviewOld = @($purviewAlerts | Where-Object { ($d = ConvertTo-SecOakUtcDate $_.createdDateTime) -and $d -lt $weekAgo })
        $summary.openHighSeverityAlerts = [ordered]@{
            total          = $alerts.Count
            byServiceSource = @($alerts | Group-Object serviceSource | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            purview        = $purviewAlerts.Count
            purviewOlderThanSevenDays = $purviewOld.Count
            note           = 'Alerts from Defender products are counted here only; the Defender area assesses them.'
        }
        if ($purviewAlerts.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-37' -Area $area -Severity $(if ($purviewOld.Count) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Unresolved high-severity data loss prevention or insider risk alerts' `
                        -Evidence ([ordered]@{ open = $purviewAlerts.Count; olderThanSevenDays = $purviewOld.Count; examples = (Select-SecOakExample @($purviewAlerts | ForEach-Object { '{0} ({1}, {2:yyyy-MM-dd})' -f $_.title, $_.serviceSource, (ConvertTo-SecOakUtcDate $_.createdDateTime) })) }) `
                        -Risk 'Someone has probably already sent or shared sensitive data in a way the policy flags, and nobody has looked at it.' `
                        -Recommendation 'Assign each alert to a named person, investigate it within two working days, and tune the policy if it is a false positive.'))
        }
    }
    else { $summary.openHighSeverityAlerts = 'Cannot read' }
    #endregion

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
