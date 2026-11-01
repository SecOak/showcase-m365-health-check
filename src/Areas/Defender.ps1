#region Fixed advanced hunting queries (constants; never built from tenant data)
# Every query is bounded by a time window and a summarize, top, or take clause.
# Column names verified against the Microsoft Learn advanced hunting schema pages.
$script:DefenderHuntingQueries = [ordered]@{
    # HUNT-01: successful sign-ins with legacy (basic) authentication clients in the last 30 days.
    'HUNT-01' = @'
EntraIdSignInEvents
| where Timestamp > ago(30d)
| where ErrorCode == 0
| where ClientAppUsed in ("Other clients", "Exchange ActiveSync", "IMAP4", "POP3", "Authenticated SMTP", "Exchange Web Services", "Outlook Anywhere (RPC over HTTP)", "MAPI over HTTP", "Autodiscover", "Offline Address Book", "Exchange Online PowerShell", "Reporting Web Services")
| summarize SignIns = count(), LastSeen = max(Timestamp), Applications = make_set(Application, 5) by AccountUpn, ClientAppUsed
| top 200 by SignIns desc
'@
    # HUNT-02: devices not compliant with tamper-protection-related secure configuration.
    'HUNT-02' = @'
DeviceTvmSecureConfigurationAssessment
| where Timestamp > ago(7d)
| where ConfigurationCategory == "Security controls"
| where IsApplicable == true and IsCompliant == false
| join kind=inner (DeviceTvmSecureConfigurationAssessmentKB | project ConfigurationId, ConfigurationName, ConfigurationDescription) on ConfigurationId
| where ConfigurationName has "tamper" or ConfigurationDescription has "tamper"
| summarize LastAssessed = max(Timestamp) by DeviceId, DeviceName, ConfigurationName
| top 500 by LastAssessed desc
'@
    # HUNT-03: macro-enabled attachments delivered to mailboxes in the last 30 days.
    'HUNT-03' = @'
EmailAttachmentInfo
| where Timestamp > ago(30d)
| where FileType in ("docm", "xlsm", "pptm", "xlsb", "dotm", "xltm", "potm")
| join kind=inner (EmailEvents | where Timestamp > ago(30d) | where EmailDirection == "Inbound" | project NetworkMessageId, DeliveryAction, LatestDeliveryAction, ThreatTypes, Subject) on NetworkMessageId
| where DeliveryAction == "Delivered"
| summarize Messages = dcount(NetworkMessageId), Recipients = dcount(RecipientEmailAddress), LastSeen = max(Timestamp), ThreatTypes = make_set(ThreatTypes, 5), FileTypes = make_set(FileType, 7) by SenderFromAddress
| top 200 by Messages desc
'@
    # HUNT-04: inbox rules created or changed in the last 30 days that forward or redirect mail.
    'HUNT-04' = @'
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend RuleParameters = tostring(RawEventData.Parameters)
| where RuleParameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
| project Timestamp, AccountDisplayName, AccountObjectId, ActionType, RuleParameters, IPAddress, ISP, CountryCode
| top 200 by Timestamp desc
'@
    # HUNT-05: tampering attempts against the Defender for Endpoint sensor in the last 30 days.
    'HUNT-05' = @'
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "TamperingAttempt"
| summarize Attempts = count(), LastSeen = max(Timestamp), Processes = make_set(InitiatingProcessFileName, 5), Accounts = make_set(InitiatingProcessAccountName, 5) by DeviceId, DeviceName
| top 200 by Attempts desc
'@
}
#endregion

function Test-SecOakDefenderTrue {
    <#
    .SYNOPSIS
        True for a boolean-like value (True, 1, "true", "1"); handles hunting result booleans that arrive as text.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter()][AllowNull()][object]$Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [bool]) { return $Value }
    return ("$Value" -match '^(?i)(true|1)$')
}

function Get-SecOakDefenderAgeHours {
    <#
    .SYNOPSIS
        Hours elapsed since a Graph date value, or $null when the value cannot be parsed.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value)
    $date = ConvertTo-SecOakUtcDate $Value
    if ($null -eq $date) { return $null }
    [math]::Round(([datetime]::UtcNow - $date).TotalHours, 1)
}

function Get-SecOakDefenderExchangeData {
    <#
    .SYNOPSIS
        Runs one Exchange Online Get-* cmdlet for the Defender area and records a gap when it fails.
    .DESCRIPTION
        Returns the cmdlet output as an array, or $null when the cmdlet failed, was forbidden, or
        no Exchange Online session is open. Every failure is recorded as a gap so the caller
        only needs to test for $null.
    .PARAMETER Context
        The run context.
    .PARAMETER Check
        Check name for the endpoint log and gap list, for example Defender/AntiPhish.
    .PARAMETER Cmdlet
        The Get-* cmdlet name.
    .PARAMETER Parameters
        Splatted parameters.
    .PARAMETER RawName
        When set, the output is saved to raw\<RawName>.json.
    .PARAMETER LicenseHint
        Text appended to the gap reason when the cmdlet errors, typically the licence the feature needs.
    .NOTES
        Requires an Exchange Online session. Read-only Get-* cmdlets only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidatePattern('^Get-[A-Za-z0-9]+$')][string]$Cmdlet,
        [Parameter()][hashtable]$Parameters = @{},
        [Parameter()][ValidatePattern('^[a-z0-9\-]+$')][string]$RawName = '',
        [Parameter()][string]$LicenseHint = ''
    )
    $fill = 'Exchange.ManageAsApp on the reader app plus the Microsoft Entra role Global Reader on its service principal (certificate credential required).'
    if ($Context.ExchangeMode -eq 'none') {
        Add-SecOakGap -Context $Context -Area 'Defender' -Check $Check -EndpointOrCmdlet $Cmdlet -Result 'not collected' `
            -Reason 'No Exchange Online session could be opened.' -FillWith $fill
        return $null
    }
    try { $r = Invoke-SecOakExchangeGet -Context $Context -Check $Check -Cmdlet $Cmdlet -Parameters $Parameters }
    catch [System.Management.Automation.ParameterBindingException] {
        # The wrapper validates cmdlet names; a name it does not accept (for example one containing a digit) is a tooling gap.
        Add-SecOakGap -Context $Context -Area 'Defender' -Check $Check -EndpointOrCmdlet $Cmdlet -Result 'not collected' `
            -Reason "Invoke-SecOakExchangeGet did not accept the cmdlet name: $($_.Exception.Message)" -FillWith 'Widen the cmdlet name pattern in Invoke-SecOakExchangeGet to allow digits (Get-[A-Za-z0-9]+).'
        return $null
    }
    if ($r.Success) {
        $data = @($r.Data)
        if ($RawName) { Save-SecOakRawData -Context $Context -Name $RawName -Data $data }
        return , $data
    }
    $reason = if ($r.Forbidden) { "Forbidden: $($r.ErrorMessage)" } else { "Error: $($r.ErrorMessage)" }
    if ($LicenseHint -and -not $r.Forbidden) { $reason += " $LicenseHint" }
    Add-SecOakGap -Context $Context -Area 'Defender' -Check $Check -EndpointOrCmdlet $Cmdlet -Result $(if ($r.Forbidden) { 'forbidden' } else { 'error' }) `
        -Reason $reason -FillWith $fill
    return $null
}

function Get-SecOakDefenderForwardingTarget {
    <#
    .SYNOPSIS
        Extracts SMTP addresses from the ForwardTo, ForwardAsAttachmentTo, and RedirectTo entries
        of a serialised inbox rule parameter list from CloudAppEvents.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter()][AllowNull()][object]$RuleParameters)
    $text = "$RuleParameters"
    if (-not $text) { return , @() }
    $addresses = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($text, '(?i)"Name"\s*:\s*"(ForwardTo|ForwardAsAttachmentTo|RedirectTo)"\s*,\s*"Value"\s*:\s*"([^"]*)"')) {
        foreach ($a in [regex]::Matches($m.Groups[2].Value, '(?i)(?:smtp:)?([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})')) { $addresses.Add($a.Groups[1].Value.ToLowerInvariant()) }
    }
    , @($addresses | Select-Object -Unique)
}

function Invoke-SecOakDefenderCheck {
    <#
    .SYNOPSIS
        Defender area: Microsoft Defender XDR alerts and incidents, Secure Score trend and high-value
        controls, attack simulation history, Defender for Endpoint device coverage, exposure,
        vulnerabilities, recommendations and end-of-support software, Defender for Office 365 and
        Exchange Online Protection policy configuration, and five fixed advanced hunting queries.
    .DESCRIPTION
        Microsoft Graph (security alerts_v2, incidents, secureScores, secureScoreControlProfiles,
        attackSimulation) and the Defender for Endpoint API are read with app-only GET requests.
        Exchange Online Protection and Defender for Office 365 policies are read with Get-* cmdlets
        over an app-only Exchange Online session that this area opens and closes itself (an
        already-open session is reused and left open). The hunting queries are fixed constants in
        this file and run through the approved read-only POST to /security/runHuntingQuery; they are
        never built from tenant data. Every check records a gap and moves on when the API, licence,
        or permission is missing; nothing is guessed. Secure Score level is reported by the Posture
        area (POSTURE-01), so this area only reports the 30-day trend (DEFENDER-03). The Defender
        for Cloud Apps interface is not read directly; its alerts arrive through alerts_v2.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        Area result object with Area, Summary, and Findings.
    .EXAMPLE
        Invoke-SecOakDefenderCheck -Context $context
    .NOTES
        Application permissions (Microsoft Graph): SecurityAlert.Read.All, SecurityIncident.Read.All,
        SecurityEvents.Read.All, AttackSimulation.Read.All, ThreatHunting.Read.All.
        Application permissions (WindowsDefenderATP): Machine.Read.All, Score.Read.All,
        Vulnerability.Read.All, SecurityRecommendation.Read.All, Software.Read.All.
        Exchange Online: Exchange.ManageAsApp plus the Global Reader role on the reader app's
        service principal; requires ExchangeOnlineManagement 3.x.
        Licensing: Defender for Endpoint (Plan 1 or 2, or Business Premium) for the device checks;
        Defender Vulnerability Management (Plan 2 or add-on) for exposure, vulnerabilities,
        recommendations, software inventory and HUNT-02; Defender for Office 365 (Plan 1 or 2, or
        Business Premium) for Safe Links, Safe Attachments, impersonation protection, attack
        simulation and HUNT-03; Microsoft Entra ID P1 or P2 for HUNT-01 sign-in data.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Defender'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $nowUtc = [datetime]::UtcNow
    $cutoff30 = $nowUtc.AddDays(-30).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")

    #region Defender XDR through Microsoft Graph (DEFENDER-01 to 05)
    #--- DEFENDER-01: open alerts
    $alerts = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Defender/Alerts' -Path "/security/alerts_v2?`$filter=createdDateTime ge $cutoff30&`$top=100" -RawName 'defender-alerts'
    if ($alerts.Success) {
        $all = @($alerts.Items)
        $open = @($all | Where-Object { $_.status -in 'new', 'inProgress' })
        $staleHigh = @($open | Where-Object { $_.severity -eq 'high' -and (Get-SecOakDefenderAgeHours $_.createdDateTime) -gt 24 })
        $staleMedium = @($open | Where-Object { $_.severity -eq 'medium' -and (Get-SecOakDefenderAgeHours $_.createdDateTime) -gt 72 })
        $summary.alerts30Days = [ordered]@{
            total          = $all.Count
            open           = $open.Count
            openBySeverity = @($open | Group-Object severity | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            bySource       = @($all | Group-Object serviceSource | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            highOpenOver24Hours   = $staleHigh.Count
            mediumOpenOver72Hours = $staleMedium.Count
            note           = if ($all.Count -eq 0) { 'No alerts in 30 days. Verify that a Defender workload is licensed and onboarded; an empty result can also mean nothing is being monitored.' } else { '' }
        }
        if ($staleHigh.Count -or $staleMedium.Count) {
            $examples = @($staleHigh + $staleMedium | Sort-Object { $_.createdDateTime } | Select-Object -First 5 | ForEach-Object { '{0} ({1}, {2}, open {3} days)' -f $_.title, $_.severity, $_.serviceSource, [math]::Round((Get-SecOakDefenderAgeHours $_.createdDateTime) / 24, 1) })
            $findings.Add((New-SecOakFinding -Id 'DEFENDER-01' -Area $area -Severity $(if ($staleHigh.Count) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Defender alerts left open without triage' `
                        -Evidence ([ordered]@{ highOpenOver24Hours = $staleHigh.Count; mediumOpenOver72Hours = $staleMedium.Count; openAlerts = $open.Count; examples = $examples }) `
                        -Risk 'Nobody is acting on the security alerts Microsoft raises. A real intrusion (a stolen password, malware on a laptop, a phishing campaign) can sit unnoticed until data is lost.' `
                        -Recommendation 'Assign a person or partner to review the Defender portal alert queue daily, and set up email notifications for high and medium alerts. Resolve or classify every alert older than a day.'))
        }
    }

    #--- DEFENDER-02: open incidents
    $incidentRows = [System.Collections.Generic.List[object]]::new()
    $incidentsOk = $false
    foreach ($status in 'active', 'inProgress') {
        # The incidents endpoint caps $top at 50; the wrapper follows nextLink for the rest.
        $r = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Defender/Incidents' -Path "/security/incidents?`$filter=status eq '$status'&`$top=50" -RawName "defender-incidents-$($status.ToLowerInvariant())"
        if ($r.Success) { $incidentsOk = $true; foreach ($i in @($r.Items)) { $incidentRows.Add($i) } }
    }
    if ($incidentsOk) {
        $openIncidents = @($incidentRows)
        $criticalIncidents = @($openIncidents | Where-Object { $_.severity -eq 'high' -and (Get-SecOakDefenderAgeHours $_.createdDateTime) -gt 24 })
        $mediumIncidents = @($openIncidents | Where-Object { $_.severity -eq 'medium' -and (Get-SecOakDefenderAgeHours $_.createdDateTime) -gt 72 })
        $summary.openIncidents = [ordered]@{
            total      = $openIncidents.Count
            bySeverity = @($openIncidents | Group-Object severity | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            highOpenOver24Hours   = $criticalIncidents.Count
            mediumOpenOver72Hours = $mediumIncidents.Count
        }
        if ($criticalIncidents.Count -or $mediumIncidents.Count) {
            $examples = @($criticalIncidents + $mediumIncidents | Sort-Object { $_.createdDateTime } | Select-Object -First 5 | ForEach-Object { '{0} ({1}, open {2} days)' -f $_.displayName, $_.severity, [math]::Round((Get-SecOakDefenderAgeHours $_.createdDateTime) / 24, 1) })
            $findings.Add((New-SecOakFinding -Id 'DEFENDER-02' -Area $area -Severity $(if ($criticalIncidents.Count) { 'Critical' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Defender incidents open without a response' `
                        -Evidence ([ordered]@{ highOpenOver24Hours = $criticalIncidents.Count; mediumOpenOver72Hours = $mediumIncidents.Count; openIncidents = $openIncidents.Count; examples = $examples }) `
                        -Risk 'An incident groups related alerts into one attack story. A high-severity incident left open for more than a day usually means an active compromise is not being contained.' `
                        -Recommendation 'Open each incident in the Defender portal, follow the recommended actions (reset passwords, isolate the device, remove the mailbox rule), then mark it resolved with a classification.'))
        }
    }

    #--- DEFENDER-03 and DEFENDER-04: Secure Score trend and high-value controls
    $scores = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Defender/SecureScoreTrend' -Path '/security/secureScores?$top=30' -NoPaging -RawName 'defender-secure-score-history'
    $profiles = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Defender/SecureScoreControls' -Path '/security/secureScoreControlProfiles'
    if ($scores.Success -and @($scores.Items).Count) {
        $history = @($scores.Items | Where-Object { $null -ne (ConvertTo-SecOakUtcDate $_.createdDateTime) } | Sort-Object { ConvertTo-SecOakUtcDate $_.createdDateTime } -Descending)
        $latest = $history | Select-Object -First 1
        $oldest = $history | Select-Object -Last 1
        $change = [math]::Round([double]$latest.currentScore - [double]$oldest.currentScore, 2)
        $spanDays = [math]::Round(((ConvertTo-SecOakUtcDate $latest.createdDateTime) - (ConvertTo-SecOakUtcDate $oldest.createdDateTime)).TotalDays)
        $summary.secureScoreTrend = [ordered]@{
            latestDate   = (ConvertTo-SecOakUtcDate $latest.createdDateTime).ToString('yyyy-MM-dd')
            latestScore  = $latest.currentScore
            maxScore     = $latest.maxScore
            comparedWith = (ConvertTo-SecOakUtcDate $oldest.createdDateTime).ToString('yyyy-MM-dd')
            changePoints = $change
            daysCovered  = $spanDays
        }
        if ($change -lt -5 -and $spanDays -ge 7) {
            $findings.Add((New-SecOakFinding -Id 'DEFENDER-03' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Microsoft Secure Score has dropped over the last month' `
                        -Evidence ([ordered]@{ changePoints = $change; daysCovered = $spanDays; from = $oldest.currentScore; to = $latest.currentScore; maxScore = $latest.maxScore }) `
                        -Risk 'A falling score means a protection was switched off, an exception was added, or new users and devices arrived without the usual safeguards.' `
                        -Recommendation 'Open Secure Score history in the Defender portal, find the actions that lost points, and restore them or record why the change was made.'))
        }

        if ($profiles.Success -and @($profiles.Items).Count) {
            $active = @($profiles.Items | Where-Object { -not (Test-SecOakDefenderTrue $_.deprecated) -and [double]$_.maxScore -gt 0 })
            $weights = @($active | ForEach-Object { [double]$_.maxScore } | Sort-Object -Descending)
            $decileWeight = if ($weights.Count) { $weights[[math]::Max(0, [math]::Ceiling($weights.Count * 0.10) - 1)] } else { 0 }
            $quartileWeight = if ($weights.Count) { $weights[[math]::Max(0, [math]::Ceiling($weights.Count * 0.25) - 1)] } else { 0 }
            $profileMap = @{}
            foreach ($p in $active) { $profileMap[$p.id] = $p }
            $notImplemented = foreach ($control in @($latest.controlScores)) {
                $p = $profileMap[$control.controlName]
                if (-not $p) { continue }
                $gap = [double]$p.maxScore - [double]$control.score
                if ($gap -le 0) { continue }
                $state = @($p.controlStateUpdates | Sort-Object { ConvertTo-SecOakUtcDate $_.updatedDateTime } -Descending | Select-Object -First 1).state
                [pscustomobject]@{ Title = $p.title; MaxScore = [double]$p.maxScore; PointsAvailable = [math]::Round($gap, 2); State = "$state"; Category = $p.controlCategory }
            }
            $notImplemented = @($notImplemented)
            $topDecile = @($notImplemented | Where-Object { $_.MaxScore -ge $decileWeight -and $_.State -ne 'Ignored' -and $_.State -ne 'ThirdParty' })
            $topQuartile = @($notImplemented | Where-Object { $_.MaxScore -ge $quartileWeight -and $_.MaxScore -lt $decileWeight -and $_.State -ne 'Ignored' -and $_.State -ne 'ThirdParty' })
            $ignored = @($notImplemented | Where-Object { $_.State -eq 'Ignored' })
            $summary.secureScoreControls = [ordered]@{
                controlsAvailable    = $active.Count
                notImplemented       = $notImplemented.Count
                topDecileNotImplemented   = $topDecile.Count
                topQuartileNotImplemented = $topQuartile.Count
                markedIgnored        = $ignored.Count
                markedThirdParty     = @($notImplemented | Where-Object State -eq 'ThirdParty').Count
            }
            if ($topDecile.Count -or $topQuartile.Count) {
                $examples = @($topDecile + $topQuartile | Sort-Object MaxScore -Descending | Select-Object -First 6 | ForEach-Object { '{0} ({1} of {2} points available)' -f $_.Title, $_.PointsAvailable, $_.MaxScore })
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-04' -Area $area -Severity $(if ($topDecile.Count) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                            -Title 'Highest-value Secure Score protections are not in place' `
                            -Evidence ([ordered]@{ topDecileNotImplemented = $topDecile.Count; topQuartileNotImplemented = $topQuartile.Count; markedIgnored = $ignored.Count; examples = $examples }) `
                            -Risk 'Microsoft weights each improvement action by how much attack risk it removes. The heaviest actions that are still open are the protections attackers most often exploit, typically multifactor authentication, admin account hygiene, and mail filtering.' `
                            -Recommendation 'Work through the listed actions first; each is a guided change in the Defender portal. If an action is covered by another product, mark it as resolved through a third party rather than ignoring it.'))
            }
        }
    }

    #--- DEFENDER-05: attack simulation training
    $simulations = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Defender/AttackSimulation' -Path '/security/attackSimulation/simulations?$top=50' -RawName 'defender-attack-simulations'
    if ($simulations.Success) {
        $sims = @($simulations.Items)
        $completed = @($sims | Where-Object { $_.status -in 'succeeded', 'running' })
        $recent = @($completed | Where-Object { ($d = ConvertTo-SecOakUtcDate $_.launchDateTime) -and $d -gt $nowUtc.AddDays(-365) })
        $summary.attackSimulations = [ordered]@{
            total            = $sims.Count
            byStatus         = @($sims | Group-Object status | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            launchedLast12Months = $recent.Count
            note             = if ($sims.Count -eq 0) { 'No simulations found. This endpoint cannot tell an unlicensed tenant from a licensed one that never ran a simulation; Attack simulation training needs Defender for Office 365 Plan 2.' } else { '' }
        }
        if ($recent.Count -eq 0) {
            $findings.Add((New-SecOakFinding -Id 'DEFENDER-05' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'No phishing simulation has been run in the last 12 months' `
                        -Evidence ([ordered]@{ simulationsFound = $sims.Count; launchedLast12Months = 0; licenceNote = 'Requires Defender for Office 365 Plan 2 (included in Microsoft 365 E5); not included in Business Premium.' }) `
                        -Risk 'There is no measure of how many staff would click a convincing phishing email, so the biggest human risk is unknown and untrained.' `
                        -Recommendation 'If Defender for Office 365 Plan 2 is licensed, schedule a quarterly simulation with automatic training assignment. Otherwise run a third-party phishing simulation or short awareness sessions at least twice a year.'))
        }
        else {
            $withReport = @($recent | Where-Object { $_.report -and $_.report.overview -and [int]$_.report.overview.resolvedTargetsCount -gt 0 })
            $lowCompletion = foreach ($s in $withReport) {
                $o = $s.report.overview
                $trained = [int]$o.trainingEventsContent.trainingsAssignedUserCount
                if ($trained -le 0) { continue }
                $rate = [math]::Round(100 * [int]$o.trainingEventsContent.trainingsCompletedUserCount / $trained, 1)
                if ($rate -lt 70) { '{0} ({1} percent completed training)' -f $s.displayName, $rate }
            }
            $lowCompletion = @($lowCompletion)
            if ($lowCompletion.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-05' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Phishing simulation training completion is below 70 percent' `
                            -Evidence ([ordered]@{ simulationsBelow70Percent = $lowCompletion.Count; examples = (Select-SecOakExample $lowCompletion) }) `
                            -Risk 'Staff who clicked the simulated phishing email but did not finish the assigned training remain the most likely to click a real one.' `
                            -Recommendation 'Send reminders for the outstanding training and ask managers to follow up; consider a shorter training module.'))
            }
        }
    }
    #endregion

    #region Defender for Endpoint API (DEFENDER-06 to 12)
    $machinesResult = Invoke-SecOakApiGet -Context $Context -Api DefenderEndpoint -Area $area -Check 'Defender/Machines' -Path '/api/machines?$top=10000' -RawName 'defender-machines'
    $mdeReachable = [bool]$machinesResult.Success
    if (-not $mdeReachable) {
        $summary.defenderForEndpoint = if ($machinesResult.StatusCode -in 401, 403) { 'Not reachable (401/403): Defender for Endpoint is not licensed, not provisioned, or the Machine.Read.All permission is not granted.' } else { "Not reachable ($($machinesResult.ErrorCode))." }
    }
    else {
        $machines = @($machinesResult.Items)
        $onboarded = @($machines | Where-Object onboardingStatus -eq 'Onboarded')
        $activeDevices = @($onboarded | Where-Object healthStatus -eq 'Active')
        $unhealthy = @($onboarded | Where-Object { $_.healthStatus -in 'Inactive', 'ImpairedCommunication', 'NoSensorData' })
        $canOnboard = @($machines | Where-Object { $_.onboardingStatus -eq 'CanBeOnboarded' -and ($d = ConvertTo-SecOakUtcDate $_.firstSeen) -and $d -lt $nowUtc.AddDays(-14) })
        $coverage = if ($onboarded.Count) { [math]::Round(100 * $activeDevices.Count / $onboarded.Count, 1) } else { $null }
        $highExposure = @($onboarded | Where-Object exposureLevel -eq 'High')
        $summary.defenderForEndpoint = [ordered]@{
            devicesKnown       = $machines.Count
            onboarded          = $onboarded.Count
            activeSensor       = $activeDevices.Count
            activePercent      = $coverage
            byHealthStatus     = @($onboarded | Group-Object healthStatus | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            byOnboardingStatus = @($machines | Group-Object onboardingStatus | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            byOsPlatform       = @($onboarded | Group-Object osPlatform | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            byExposureLevel    = @($onboarded | Group-Object exposureLevel | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            canBeOnboardedOver14Days = $canOnboard.Count
        }
        #--- DEFENDER-06: coverage and sensor health
        $lowCoverage = ($null -ne $coverage -and $coverage -lt 90)
        if ($machines.Count -eq 0) {
            $findings.Add((New-SecOakFinding -Id 'DEFENDER-06' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'No devices are onboarded to Defender for Endpoint' `
                        -Evidence ([ordered]@{ devicesKnown = 0 }) `
                        -Risk 'Laptops and servers have no endpoint detection and response. Malware, ransomware, and credential theft on a device are not seen or stopped centrally.' `
                        -Recommendation 'Onboard every company Windows, macOS, and mobile device to Defender for Endpoint, ideally automatically through Intune.'))
        }
        elseif ($lowCoverage -or $canOnboard.Count) {
            $examples = @($unhealthy | Sort-Object { $_.lastSeen } | Select-Object -First 5 | ForEach-Object { '{0} ({1}, last seen {2:yyyy-MM-dd})' -f $_.computerDnsName, $_.healthStatus, (ConvertTo-SecOakUtcDate $_.lastSeen) })
            $examples += @($canOnboard | Select-Object -First 3 | ForEach-Object { '{0} (can be onboarded, first seen {1:yyyy-MM-dd})' -f $_.computerDnsName, (ConvertTo-SecOakUtcDate $_.firstSeen) })
            $findings.Add((New-SecOakFinding -Id 'DEFENDER-06' -Area $area -Severity $(if ($lowCoverage) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Defender for Endpoint coverage gaps: unhealthy sensors or devices never onboarded' `
                        -Evidence ([ordered]@{ activePercent = $coverage; onboarded = $onboarded.Count; unhealthySensors = $unhealthy.Count; canBeOnboardedOver14Days = $canOnboard.Count; examples = (Select-SecOakExample $examples -Count 8) }) `
                        -Risk 'A device whose sensor is inactive or impaired sends no telemetry, so an attack on it is invisible. Devices discovered on the network but never onboarded have no protection at all.' `
                        -Recommendation 'Onboard the discovered devices, fix or retire the devices with inactive sensors (often laptops that were replaced but never offboarded), and check that the sensor is not blocked by a proxy or firewall.'))
        }
        #--- DEFENDER-08: high exposure devices
        if ($highExposure.Count) {
            $findings.Add((New-SecOakFinding -Id 'DEFENDER-08' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Devices with a High exposure level' `
                        -Evidence ([ordered]@{ highExposure = $highExposure.Count; onboarded = $onboarded.Count; examples = (Select-SecOakExample @($highExposure | ForEach-Object { '{0} ({1}, risk {2})' -f $_.computerDnsName, $_.osPlatform, $_.riskScore })) }) `
                        -Risk 'These devices carry the most unpatched, exploitable weaknesses in the fleet. One is enough for ransomware to gain a foothold.' `
                        -Recommendation 'Open each device in the Defender portal, apply the pending updates and security recommendations, and enable automatic Windows and application updates.'))
        }
    }

    if ($mdeReachable) {
        #--- DEFENDER-07: exposure score
        $exposure = Invoke-SecOakApiGet -Context $Context -Api DefenderEndpoint -Area $area -Check 'Defender/ExposureScore' -Path '/api/exposureScore' -NoPaging -RawName 'defender-exposure-score'
        if ($exposure.Success) {
            $body = if ($null -ne $exposure.Body) { $exposure.Body } else { @($exposure.Items) | Select-Object -First 1 }
            $score = if ($null -ne $body -and $null -ne $body.score) { [math]::Round([double]$body.score, 1) } else { $null }
            $summary.exposureScore = [ordered]@{ score = $score; band = $(if ($null -eq $score) { 'unknown' } elseif ($score -ge 70) { 'High' } elseif ($score -ge 30) { 'Medium' } else { 'Low' }) }
            if ($null -eq $score -or $score -eq 0) {
                Add-SecOakGap -Context $Context -Area $area -Check 'Defender/ExposureScore' -EndpointOrCmdlet '/api/exposureScore' -Result 'no data' `
                    -Reason 'The exposure score is missing or zero, which usually means Defender Vulnerability Management is not licensed or has not assessed any device yet.' `
                    -FillWith 'Defender for Endpoint Plan 2 or the Defender Vulnerability Management add-on, with at least one onboarded device.'
            }
            elseif ($score -ge 30) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-07' -Area $area -Severity $(if ($score -ge 70) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                            -Title 'Organisation exposure score is in the medium or high band' `
                            -Evidence ([ordered]@{ score = $score; band = $summary.exposureScore.band; scale = '0 to 100; Microsoft bands 0 to 29 low, 30 to 69 medium, 70 to 100 high' }) `
                            -Risk 'The exposure score summarises how many known weaknesses exist across all devices and how exploitable they are. A medium or high score means attackers have many usable ways in.' `
                            -Recommendation 'Use the Defender Vulnerability Management dashboard to fix the top recommendations, starting with those marked as having a public exploit, and keep operating systems and browsers on automatic updates.'))
            }
        }

        #--- DEFENDER-09 and DEFENDER-10: critical vulnerabilities and affected devices
        $vulnerabilities = Invoke-SecOakApiGet -Context $Context -Api DefenderEndpoint -Area $area -Check 'Defender/Vulnerabilities' -Path '/api/vulnerabilities?$filter=severity%20eq%20''Critical''&$top=8000'
        if ($vulnerabilities.Success) {
            $present = @($vulnerabilities.Items | Where-Object { [int]$_.exposedMachines -gt 0 })
            $exploitable = @($present | Where-Object { Test-SecOakDefenderTrue $_.publicExploit })
            Save-SecOakRawData -Context $Context -Name 'defender-critical-vulnerabilities' -Data @($present | Select-Object id, name, severity, cvssV3, exposedMachines, publicExploit, exploitVerified, publishedOn)
            $summary.criticalVulnerabilities = [ordered]@{
                criticalCvesAffectingDevices = $present.Count
                withPublicExploit            = $exploitable.Count
                devicesExposedMax            = @($present | ForEach-Object { [int]$_.exposedMachines } | Measure-Object -Maximum).Maximum
            }
            if ($present.Count) {
                $deviceExamples = [System.Collections.Generic.List[string]]::new()
                foreach ($cve in @($exploitable + $present | Sort-Object { [int]$_.exposedMachines } -Descending | Select-Object -First 3)) {
                    if ("$($cve.id)" -notmatch '^CVE-\d{4}-\d{4,}$') { continue }
                    $refs = Invoke-SecOakApiGet -Context $Context -Api DefenderEndpoint -Area $area -Check 'Defender/VulnerabilityDevices' -Path "/api/vulnerabilities/$($cve.id)/machineReferences" -NoGap
                    if ($refs.Success) { foreach ($m in @($refs.Items | Select-Object -First 3)) { $deviceExamples.Add(('{0}: {1}' -f $cve.id, $m.computerDnsName)) } }
                }
                $examples = @($exploitable + $present | Select-Object -Unique -First 5 | ForEach-Object { '{0} ({1} devices{2})' -f $_.id, $_.exposedMachines, $(if (Test-SecOakDefenderTrue $_.publicExploit) { ', public exploit' } else { '' }) })
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-09' -Area $area -Severity $(if ($exploitable.Count) { 'Critical' } else { 'High' }) -BaselineControl 'None' `
                            -Title 'Critical vulnerabilities present on company devices' `
                            -Evidence ([ordered]@{ criticalCves = $present.Count; withPublicExploit = $exploitable.Count; examples = $examples; affectedDeviceExamples = (Select-SecOakExample $deviceExamples.ToArray() -Count 6) }) `
                            -Risk 'Critical-rated weaknesses, especially those with a public exploit, are what ransomware groups scan for. A single unpatched browser, Office, or VPN client can hand over the whole network.' `
                            -Recommendation 'Patch the listed products on the affected devices this week. Turn on automatic updates for Windows, browsers, and Office, and use Intune update rings with deadlines so patches are not deferred.'))
            }
        }

        #--- DEFENDER-11: security recommendations
        $recommendations = Invoke-SecOakApiGet -Context $Context -Api DefenderEndpoint -Area $area -Check 'Defender/Recommendations' -Path '/api/recommendations?$top=10000'
        if ($recommendations.Success) {
            $activeRecs = @($recommendations.Items | Where-Object { $_.status -eq 'Active' -and [int]$_.exposedMachinesCount -gt 0 })
            $urgent = @($activeRecs | Where-Object { [double]$_.severityScore -ge 7 })
            $urgentExploit = @($urgent | Where-Object { (Test-SecOakDefenderTrue $_.publicExploit) -or (Test-SecOakDefenderTrue $_.activeAlert) })
            Save-SecOakRawData -Context $Context -Name 'defender-recommendations-urgent' -Data @($urgent | Select-Object id, recommendationName, productName, severityScore, exposedMachinesCount, publicExploit, activeAlert, remediationType, recommendationCategory)
            $summary.securityRecommendations = [ordered]@{
                activeWithExposedDevices = $activeRecs.Count
                severityScore7OrMore     = $urgent.Count
                withPublicExploitOrActiveAlert = $urgentExploit.Count
                byCategory               = @($activeRecs | Group-Object recommendationCategory | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            }
            if ($urgent.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-11' -Area $area -Severity $(if ($urgentExploit.Count) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                            -Title 'High-severity security recommendations outstanding' `
                            -Evidence ([ordered]@{ severityScore7OrMore = $urgent.Count; withPublicExploitOrActiveAlert = $urgentExploit.Count; examples = (Select-SecOakExample @($urgentExploit + $urgent | Sort-Object { [double]$_.severityScore } -Descending | Select-Object -Unique -First 6 | ForEach-Object { '{0} (score {1}, {2} devices)' -f $_.recommendationName, $_.severityScore, $_.exposedMachinesCount })) }) `
                            -Risk 'Each recommendation is a specific patch or setting Microsoft rates as a serious weakness on devices you own. Those tied to a public exploit or an active alert are being used by attackers now.' `
                            -Recommendation 'Work the recommendations page in the Defender portal from the top: apply the update or configuration change, or request remediation through Intune. Aim to clear everything with a score of 7 or more within 30 days.'))
            }
        }

        #--- DEFENDER-12: end-of-support software
        $software = Invoke-SecOakApiGet -Context $Context -Api DefenderEndpoint -Area $area -Check 'Defender/SoftwareInventory' -Path '/api/machines/SoftwareInventoryByMachine?pageSize=10000'
        if ($software.Success) {
            $rows = @($software.Items)
            $eos = @($rows | Where-Object { "$($_.endOfSupportStatus)" -match '^(?i)(EOS|EOS Version|End of support|EndOfSupport|Upcoming EOS|Upcoming EOS Version)$' -or ("$($_.endOfSupportStatus)" -and "$($_.endOfSupportStatus)" -notmatch '^(?i)(None|Supported|NotEos)?$') })
            $reachedEos = @($eos | Where-Object { "$($_.endOfSupportStatus)" -notmatch '(?i)upcoming' })
            $byProduct = @($reachedEos | Group-Object { '{0} {1}' -f $_.softwareVendor, $_.softwareName } | Sort-Object Count -Descending)
            Save-SecOakRawData -Context $Context -Name 'defender-end-of-support-software' -Data @($byProduct | ForEach-Object { [ordered]@{ product = $_.Name; devices = $_.Count; status = @($_.Group.endOfSupportStatus | Select-Object -Unique) } })
            $summary.softwareInventory = [ordered]@{
                rows                  = $rows.Count
                devicesWithInventory  = @($rows | Select-Object -ExpandProperty deviceId -Unique).Count
                endOfSupportProducts  = $byProduct.Count
                endOfSupportDevices   = @($reachedEos | Select-Object -ExpandProperty deviceId -Unique).Count
                upcomingEndOfSupportRows = ($eos.Count - $reachedEos.Count)
            }
            if ($byProduct.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-12' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Software past end of support installed on devices' `
                            -Evidence ([ordered]@{ products = $byProduct.Count; devices = $summary.softwareInventory.endOfSupportDevices; examples = (Select-SecOakExample @($byProduct | Select-Object -First 6 | ForEach-Object { '{0} ({1} devices)' -f $_.Name, $_.Count })) }) `
                            -Risk 'Software that no longer receives security updates stays vulnerable forever; attackers keep exploits for old versions of Office, Java, Adobe Reader, and Windows components ready to use.' `
                            -Recommendation 'Upgrade or uninstall the listed products. Where a business application depends on an old version, isolate that device from email and web browsing until it can be replaced.'))
            }
        }
    }
    #endregion

    #region Exchange Online Protection and Defender for Office 365 policies (DEFENDER-14 to 25)
    $openedExchange = $false
    try {
        if ($Context.ExchangeMode -eq 'none' -and $Context.CredentialType -eq 'Certificate') {
            try { $null = Connect-SecOakExchange -Context $Context -Mode App; $openedExchange = $true }
            catch { Write-Warning $_.Exception.Message }
        }
        $mdoHint = 'Defender for Office 365 (Plan 1 or 2, or Microsoft 365 Business Premium) is required for this policy type.'
        $summary.exchangeSession = $Context.ExchangeMode

        $acceptedDomains = @()
        if ($Context.Cache.ContainsKey('Exchange') -and $Context.Cache.Exchange.AcceptedDomains) { $acceptedDomains = @($Context.Cache.Exchange.AcceptedDomains.DomainName | ForEach-Object { "$_".ToLowerInvariant() }) }
        elseif ($Context.ExchangeMode -ne 'none') {
            $d = Invoke-SecOakExchangeGet -Context $Context -Check 'Defender/AcceptedDomains' -Cmdlet Get-AcceptedDomain
            if ($d.Success) { $acceptedDomains = @($d.Data.DomainName | ForEach-Object { "$_".ToLowerInvariant() }) }
        }
        if (-not $acceptedDomains -and $Context.InitialDomain) { $acceptedDomains = @($Context.InitialDomain.ToLowerInvariant()) }

        #--- DEFENDER-14: anti-phishing policies
        $antiPhish = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/AntiPhish' -Cmdlet Get-AntiPhishPolicy -RawName 'defender-antiphish-policies'
        if ($null -ne $antiPhish) {
            $enabledPolicies = @($antiPhish | Where-Object { Test-SecOakDefenderTrue $_.Enabled })
            $default = $antiPhish | Where-Object { Test-SecOakDefenderTrue $_.IsDefault } | Select-Object -First 1
            $impersonationOn = { param($p) (Test-SecOakDefenderTrue $p.EnableTargetedUserProtection) -or (Test-SecOakDefenderTrue $p.EnableTargetedDomainsProtection) -or (Test-SecOakDefenderTrue $p.EnableOrganizationDomainsProtection) -or (Test-SecOakDefenderTrue $p.EnableMailboxIntelligenceProtection) }
            $withImpersonation = @($enabledPolicies | Where-Object { & $impersonationOn $_ })
            $defaultHasImpersonation = ($null -ne $default) -and (& $impersonationOn $default)
            $spoofOffDefault = ($null -ne $default) -and -not (Test-SecOakDefenderTrue $default.EnableSpoofIntelligence)
            $summary.antiPhishing = [ordered]@{
                policies                 = $antiPhish.Count
                enabled                  = $enabledPolicies.Count
                withImpersonationProtection = $withImpersonation.Count
                defaultPolicyImpersonation  = $defaultHasImpersonation
                defaultPhishThresholdLevel  = $(if ($default) { $default.PhishThresholdLevel } else { $null })
                defaultSpoofIntelligence    = $(if ($default) { [bool](Test-SecOakDefenderTrue $default.EnableSpoofIntelligence) } else { $null })
            }
            if ($withImpersonation.Count -eq 0) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-14' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'Impersonation protection is not enabled in any anti-phishing policy' `
                            -Evidence ([ordered]@{ enabledPolicies = $enabledPolicies.Count; withImpersonationProtection = 0; defaultPhishThresholdLevel = $summary.antiPhishing.defaultPhishThresholdLevel; licenceNote = 'Impersonation settings need Defender for Office 365; if it is not licensed this is a licensing gap rather than a misconfiguration.' }) `
                            -Risk 'Emails pretending to be the owner, the accountant, or a supplier (business email compromise) are not detected. This is the most common way small businesses lose money to fraudulent invoices and payment changes.' `
                            -Recommendation 'Enable the Standard preset security policy, or edit the default anti-phishing policy: turn on user impersonation for the owners and finance staff, domain impersonation for your own domains, mailbox intelligence protection, and set the phishing threshold to 3 (more aggressive).'))
            }
            elseif (-not $defaultHasImpersonation) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-14' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Default anti-phishing policy has no impersonation protection; only custom or preset policies provide it' `
                            -Evidence ([ordered]@{ policiesWithImpersonation = (Select-SecOakExample @($withImpersonation.Name)); defaultPolicyImpersonation = $false }) `
                            -Risk 'Anyone not included in the custom or preset policy scope falls back to the default policy and receives no impersonation protection.' `
                            -Recommendation 'Confirm the custom or preset policy includes every user and domain, or enable impersonation protection on the default policy as a safety net.'))
            }
            if ($spoofOffDefault) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-14' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Spoof intelligence is disabled in the default anti-phishing policy' `
                            -Evidence ([ordered]@{ policy = "$($default.Name)"; enableSpoofIntelligence = $false }) `
                            -Risk 'Messages that forge your own domain or a trusted sender address are not analysed, so spoofed emails reach staff inboxes.' `
                            -Recommendation 'Turn spoof intelligence back on in the default anti-phishing policy and keep the unauthenticated sender indicators enabled.'))
            }
        }

        #--- DEFENDER-15: Safe Links
        $safeLinks = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/SafeLinks' -Cmdlet Get-SafeLinksPolicy -RawName 'defender-safe-links-policies' -LicenseHint $mdoHint
        $safeLinksRules = if ($null -ne $safeLinks) { Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/SafeLinks' -Cmdlet Get-SafeLinksRule } else { $null }
        if ($null -ne $safeLinks) {
            $inUse = @($safeLinks | Where-Object { $p = $_; (Test-SecOakDefenderTrue $p.IsBuiltInProtection) -or ($null -eq $safeLinksRules) -or @($safeLinksRules | Where-Object { $_.SafeLinksPolicy -eq $p.Name -and $_.State -eq 'Enabled' }).Count -gt 0 })
            $weak = @($inUse | Where-Object { -not (Test-SecOakDefenderTrue $_.EnableSafeLinksForEmail) -or -not (Test-SecOakDefenderTrue $_.ScanUrls) })
            $clickThrough = @($inUse | Where-Object { Test-SecOakDefenderTrue $_.AllowClickThrough })
            $summary.safeLinks = [ordered]@{
                policies         = $safeLinks.Count
                inUse            = $inUse.Count
                emailScanningOff = $weak.Count
                allowClickThrough = $clickThrough.Count
                note             = if ($safeLinks.Count -eq 0) { 'No Safe Links policy returned; Defender for Office 365 is probably not licensed.' } else { '' }
            }
            if ($safeLinks.Count -eq 0) {
                Add-SecOakGap -Context $Context -Area $area -Check 'Defender/SafeLinks' -EndpointOrCmdlet 'Get-SafeLinksPolicy' -Result 'not licensed' `
                    -Reason 'No Safe Links policies exist, which normally means Defender for Office 365 is not licensed in this tenant.' -FillWith $mdoHint
            }
            elseif ($weak.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-15' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'Safe Links policies in use do not scan links in email' `
                            -Evidence ([ordered]@{ policiesInUse = $inUse.Count; withEmailScanningOff = $weak.Count; examples = (Select-SecOakExample @($weak | ForEach-Object { '{0} (email {1}, scan URLs {2})' -f $_.Name, $_.EnableSafeLinksForEmail, $_.ScanUrls })) }) `
                            -Risk 'Links in email are not checked at click time, so a link that was harmless when delivered and turned malicious later opens the phishing page directly.' `
                            -Recommendation 'Edit each listed Safe Links policy: enable Safe Links for email, turn on real-time URL scanning, and enable it for Teams and Office apps too. The Standard preset security policy sets all of these.'))
            }
            elseif ($clickThrough.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-15' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Safe Links lets users click through to blocked sites' `
                            -Evidence ([ordered]@{ policiesAllowingClickThrough = $clickThrough.Count; examples = (Select-SecOakExample @($clickThrough.Name)) }) `
                            -Risk 'A warning page that can be bypassed with one click is often ignored under pressure.' `
                            -Recommendation 'Disable "let users click through to the original URL" in the listed Safe Links policies.'))
            }
        }

        #--- DEFENDER-16: Safe Attachments
        $safeAttachments = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/SafeAttachments' -Cmdlet Get-SafeAttachmentPolicy -RawName 'defender-safe-attachment-policies' -LicenseHint $mdoHint
        $safeAttachmentRules = if ($null -ne $safeAttachments) { Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/SafeAttachments' -Cmdlet Get-SafeAttachmentRule } else { $null }
        if ($null -ne $safeAttachments) {
            $inUse = @($safeAttachments | Where-Object { $p = $_; (Test-SecOakDefenderTrue $p.IsBuiltInProtection) -or ($null -eq $safeAttachmentRules) -or @($safeAttachmentRules | Where-Object { $_.SafeAttachmentPolicy -eq $p.Name -and $_.State -eq 'Enabled' }).Count -gt 0 })
            $weak = @($inUse | Where-Object { -not (Test-SecOakDefenderTrue $_.Enable) -or "$($_.Action)" -notin 'Block', 'DynamicDelivery', 'Replace' })
            $summary.safeAttachments = [ordered]@{
                policies  = $safeAttachments.Count
                inUse     = $inUse.Count
                notBlocking = $weak.Count
                byAction  = @($inUse | Group-Object Action | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
                note      = if ($safeAttachments.Count -eq 0) { 'No Safe Attachments policy returned; Defender for Office 365 is probably not licensed.' } else { '' }
            }
            if ($safeAttachments.Count -eq 0) {
                Add-SecOakGap -Context $Context -Area $area -Check 'Defender/SafeAttachments' -EndpointOrCmdlet 'Get-SafeAttachmentPolicy' -Result 'not licensed' `
                    -Reason 'No Safe Attachments policies exist, which normally means Defender for Office 365 is not licensed in this tenant.' -FillWith $mdoHint
            }
            elseif ($weak.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-16' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'Safe Attachments policies in use do not block malicious attachments' `
                            -Evidence ([ordered]@{ policiesInUse = $inUse.Count; notBlocking = $weak.Count; examples = (Select-SecOakExample @($weak | ForEach-Object { '{0} (enabled {1}, action {2})' -f $_.Name, $_.Enable, $_.Action })) }) `
                            -Risk 'Attachments are either not detonated in the sandbox or only monitored, so a booby-trapped invoice or CV is delivered to the inbox.' `
                            -Recommendation 'Set the action to Block (or Dynamic Delivery if staff need instant access to the message body) in each listed policy, or enable the Standard preset security policy.'))
            }
        }

        #--- DEFENDER-17: anti-malware policies
        $malware = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/AntiMalware' -Cmdlet Get-MalwareFilterPolicy -RawName 'defender-malware-policies'
        if ($null -ne $malware) {
            $expected = @('exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'hta', 'jar', 'vbs', 'vbe', 'wsf', 'wsh', 'iso', 'lnk', 'msi', 'reg')
            $filterOff = @($malware | Where-Object { -not (Test-SecOakDefenderTrue $_.EnableFileFilter) })
            $defaultPolicy = $malware | Where-Object { Test-SecOakDefenderTrue $_.IsDefault } | Select-Object -First 1
            $missingTypes = @()
            if ($defaultPolicy -and (Test-SecOakDefenderTrue $defaultPolicy.EnableFileFilter)) {
                $types = @($defaultPolicy.FileTypes | ForEach-Object { "$_".ToLowerInvariant() })
                $missingTypes = @($expected | Where-Object { $_ -notin $types })
            }
            $summary.antiMalware = [ordered]@{
                policies              = $malware.Count
                commonAttachmentFilterOff = $filterOff.Count
                defaultBlockedFileTypes   = $(if ($defaultPolicy) { @($defaultPolicy.FileTypes).Count } else { $null })
                defaultMissingCommonTypes = $missingTypes
            }
            if ($filterOff.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-17' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Common attachment filter is disabled in an anti-malware policy' `
                            -Evidence ([ordered]@{ policiesWithFilterOff = $filterOff.Count; examples = (Select-SecOakExample @($filterOff.Name)) }) `
                            -Risk 'Executable and script attachments (.exe, .bat, .vbs, .iso and similar) are delivered instead of being blocked outright, relying entirely on antivirus detection.' `
                            -Recommendation 'Enable the common attachment filter in each listed anti-malware policy and keep the default blocked file type list.'))
            }
            elseif ($missingTypes.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-17' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Default anti-malware policy does not block some common risky file types' `
                            -Evidence ([ordered]@{ missingTypes = $missingTypes; blockedTypes = @($defaultPolicy.FileTypes).Count }) `
                            -Risk 'Attackers pick whichever executable or script format is not on the block list.' `
                            -Recommendation 'Add the missing file types to the common attachment filter, or reset the list to Microsoft''s default set.'))
            }
        }

        #--- DEFENDER-18: inbound anti-spam policies
        $contentFilter = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/AntiSpam' -Cmdlet Get-HostedContentFilterPolicy -RawName 'defender-antispam-policies'
        if ($null -ne $contentFilter) {
            $consumerDomains = @('gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com', 'ymail.com', 'aol.com', 'icloud.com', 'me.com', 'mail.com', 'protonmail.com', 'proton.me', 'gmx.com', 'zoho.com')
            $riskyAllow = foreach ($p in $contentFilter) {
                foreach ($d in @($p.AllowedSenderDomains)) {
                    $name = "$d".ToLowerInvariant() -replace '^.*?:', ''
                    if ($name -match '\*' -or $name -in $consumerDomains -or $name -in $acceptedDomains) { '{0}: {1}' -f $p.Name, $name }
                }
            }
            $riskyAllow = @($riskyAllow)
            $deliverToInbox = @($contentFilter | Where-Object { "$($_.HighConfidenceSpamAction)" -in 'AddXHeader', 'ModifySubject' -or "$($_.PhishSpamAction)" -in 'AddXHeader', 'ModifySubject' })
            $junkNotQuarantine = @($contentFilter | Where-Object { "$($_.HighConfidenceSpamAction)" -eq 'MoveToJmf' -or "$($_.PhishSpamAction)" -eq 'MoveToJmf' })
            $summary.antiSpam = [ordered]@{
                policies               = $contentFilter.Count
                allowedSenderDomainsTotal = @($contentFilter | ForEach-Object { @($_.AllowedSenderDomains).Count } | Measure-Object -Sum).Sum
                allowedSendersTotal    = @($contentFilter | ForEach-Object { @($_.AllowedSenders).Count } | Measure-Object -Sum).Sum
                riskyAllowedDomains    = $riskyAllow.Count
                highConfidenceSpamOrPhishDeliveredToInbox = $deliverToInbox.Count
                highConfidenceSpamOrPhishToJunkOnly = $junkNotQuarantine.Count
            }
            if ($riskyAllow.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-18' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'Anti-spam policy allow-lists a consumer, wildcard, or own domain' `
                            -Evidence ([ordered]@{ riskyEntries = $riskyAllow.Count; examples = (Select-SecOakExample $riskyAllow) }) `
                            -Risk 'Every message claiming to come from that domain skips spam and phishing filtering. Allow-listing gmail.com or your own domain is a common way phishing and spoofed invoices get through.' `
                            -Recommendation 'Remove these domains from the allowed sender domains list. If a specific partner needs an exception, allow their individual address or use the Tenant Allow/Block List with an expiry date.'))
            }
            if ($deliverToInbox.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-18' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'High-confidence spam or phishing is delivered to the inbox' `
                            -Evidence ([ordered]@{ policies = $deliverToInbox.Count; examples = (Select-SecOakExample @($deliverToInbox | ForEach-Object { '{0} (high confidence spam {1}, phish {2})' -f $_.Name, $_.HighConfidenceSpamAction, $_.PhishSpamAction })) }) `
                            -Risk 'Messages the filter is sure are spam or phishing are only tagged, so users still see and click them.' `
                            -Recommendation 'Set the high confidence spam and phishing actions to Quarantine in the listed anti-spam policies (the Standard preset does this).'))
            }
            elseif ($junkNotQuarantine.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-18' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'High-confidence spam or phishing goes to the Junk folder instead of quarantine' `
                            -Evidence ([ordered]@{ policies = $junkNotQuarantine.Count; examples = (Select-SecOakExample @($junkNotQuarantine | ForEach-Object { '{0} (high confidence spam {1}, phish {2})' -f $_.Name, $_.HighConfidenceSpamAction, $_.PhishSpamAction })) }) `
                            -Risk 'Users browse the Junk folder and release convincing phishing messages; quarantine keeps them out of reach until an administrator reviews them.' `
                            -Recommendation 'Change the high confidence spam and phishing actions to Quarantine, as Microsoft''s Standard and Strict settings recommend.'))
            }
        }

        #--- DEFENDER-19: connection filter IP allow list
        $connectionFilter = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/ConnectionFilter' -Cmdlet Get-HostedConnectionFilterPolicy -RawName 'defender-connection-filter'
        if ($null -ne $connectionFilter) {
            $allowEntries = @($connectionFilter | ForEach-Object { @($_.IPAllowList) } | ForEach-Object { "$_" } | Where-Object { $_ })
            $broad = @($allowEntries | Where-Object { $_ -match '/(\d{1,2})$' -and [int]$Matches[1] -le 23 })
            $safeListOn = @($connectionFilter | Where-Object { Test-SecOakDefenderTrue $_.EnableSafeList })
            $summary.connectionFilter = [ordered]@{ ipAllowListEntries = $allowEntries.Count; broadRanges = $broad.Count; safeListEnabled = ($safeListOn.Count -gt 0) }
            if ($broad.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-19' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'Connection filter allows a broad IP address range' `
                            -Evidence ([ordered]@{ broadRanges = $broad.Count; examples = (Select-SecOakExample $broad) }) `
                            -Risk 'Mail from every server in that range bypasses spam filtering completely. A /23 or wider range covers hundreds of addresses, most of them not the intended sender.' `
                            -Recommendation 'Replace the range with the specific sending addresses (a /32 each), or remove it and use an inbound connector with certificate authentication.'))
            }
            elseif ($allowEntries.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-19' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Connection filter IP allow list contains entries to review' `
                            -Evidence ([ordered]@{ entries = $allowEntries.Count; examples = (Select-SecOakExample $allowEntries) }) `
                            -Risk 'Mail from allow-listed addresses skips spam filtering. Entries added for an old scanner, application, or partner are often forgotten and can be abused if the address changes hands.' `
                            -Recommendation 'Confirm each address is still needed and document why; remove the rest.'))
            }
            if ($safeListOn.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-19' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Connection filter safe list is enabled' `
                            -Evidence ([ordered]@{ enableSafeList = $true }) `
                            -Risk 'The safe list trusts third-party sender reputation sources and skips filtering for them, which Microsoft recommends leaving off.' `
                            -Recommendation 'Turn off "Turn on safe list" in the connection filter policy.'))
            }
        }

        #--- DEFENDER-20: Tenant Allow/Block List allow entries without expiry
        $tablAllow = [System.Collections.Generic.List[object]]::new()
        $tablOk = $false
        foreach ($listType in 'Sender', 'Url', 'FileHash') {
            $items = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/TenantAllowBlockList' -Cmdlet Get-TenantAllowBlockListItems -Parameters @{ ListType = $listType; Allow = $true }
            if ($null -ne $items) { $tablOk = $true; foreach ($i in $items) { $tablAllow.Add([pscustomobject]@{ ListType = $listType; Value = "$($i.Value)"; ListSubType = "$($i.ListSubType)"; ExpirationDate = $i.ExpirationDate; LastUsedDate = $i.LastUsedDate }) } }
        }
        if ($tablOk) {
            $tenantAllows = @($tablAllow | Where-Object { $_.ListSubType -ne 'AdvancedDelivery' })
            $noExpiry = @($tenantAllows | Where-Object { $null -eq (ConvertTo-SecOakUtcDate $_.ExpirationDate) })
            Save-SecOakRawData -Context $Context -Name 'defender-tenant-allow-entries' -Data @($tablAllow | Select-Object ListType, ListSubType, ExpirationDate, LastUsedDate)
            $summary.tenantAllowList = [ordered]@{
                allowEntries      = $tablAllow.Count
                byListType        = @($tablAllow | Group-Object ListType | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
                phishingSimulationEntries = ($tablAllow.Count - $tenantAllows.Count)
                allowWithoutExpiry = $noExpiry.Count
            }
            if ($noExpiry.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-20' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Tenant Allow/Block List allow entries that never expire' `
                            -Evidence ([ordered]@{ allowWithoutExpiry = $noExpiry.Count; examples = (Select-SecOakExample @($noExpiry | ForEach-Object { '{0}: {1}' -f $_.ListType, $_.Value })) }) `
                            -Risk 'A permanent allow for a sender, link, or file overrides the filters for good. If that sender is later compromised or the domain changes hands, their mail is trusted.' `
                            -Recommendation 'Set an expiry (45 days or less) or "remove after last use" on each allow entry, and remove entries that are no longer needed.'))
            }
        }

        #--- DEFENDER-21: quarantine policies and user notifications
        $quarantinePolicies = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/Quarantine' -Cmdlet Get-QuarantinePolicy -RawName 'defender-quarantine-policies'
        if ($null -ne $quarantinePolicies -and $null -ne $contentFilter) {
            $notifyMap = @{}
            foreach ($q in $quarantinePolicies) { $notifyMap["$($q.Name)"] = (Test-SecOakDefenderTrue $q.ESNEnabled) }
            $silent = foreach ($p in $contentFilter) {
                foreach ($tag in 'SpamQuarantineTag', 'BulkQuarantineTag', 'PhishQuarantineTag') {
                    $name = "$($p.$tag)"
                    if ($name -and $notifyMap.ContainsKey($name) -and -not $notifyMap[$name]) { '{0}: {1} uses {2}' -f $p.Name, $tag, $name }
                }
            }
            $silent = @($silent)
            $summary.quarantine = [ordered]@{
                policies                  = $quarantinePolicies.Count
                withUserNotifications     = @($quarantinePolicies | Where-Object { Test-SecOakDefenderTrue $_.ESNEnabled }).Count
                spamCategoriesWithoutNotification = $silent.Count
            }
            if ($silent.Count -and $silent.Count -eq @($contentFilter).Count * 3) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-21' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Users are never notified about quarantined mail' `
                            -Evidence ([ordered]@{ spamCategoriesWithoutNotification = $silent.Count; examples = (Select-SecOakExample $silent) }) `
                            -Risk 'Legitimate mail caught by the spam filter sits unseen in quarantine; staff assume it never arrived, and the administrator becomes the bottleneck for every release.' `
                            -Recommendation 'Assign the DefaultFullAccessWithNotificationPolicy (or a custom quarantine policy with notifications) to the spam and bulk categories in the anti-spam policy so users receive a digest of held mail.'))
            }
        }

        #--- DEFENDER-22: Safe Attachments for SharePoint, OneDrive and Teams; Safe Documents
        $atpPolicy = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/AtpPolicy' -Cmdlet Get-AtpPolicyForO365 -RawName 'defender-atp-policy' -LicenseHint $mdoHint
        if ($null -ne $atpPolicy -and $atpPolicy.Count) {
            $policy = $atpPolicy[0]
            $summary.defenderForOffice365Global = [ordered]@{
                safeAttachmentsForSharePointOneDriveTeams = [bool](Test-SecOakDefenderTrue $policy.EnableATPForSPOTeamsODB)
                safeDocuments        = [bool](Test-SecOakDefenderTrue $policy.EnableSafeDocs)
                allowSafeDocsOpen    = [bool](Test-SecOakDefenderTrue $policy.AllowSafeDocsOpen)
            }
            if (-not (Test-SecOakDefenderTrue $policy.EnableATPForSPOTeamsODB)) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-22' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'Safe Attachments for SharePoint, OneDrive and Teams is turned off' `
                            -Evidence ([ordered]@{ enableATPForSPOTeamsODB = $false; licenceNote = 'Needs Defender for Office 365 Plan 1 or 2 (included in Business Premium).' }) `
                            -Risk 'Files uploaded to SharePoint, OneDrive, or Teams are not scanned in the sandbox, so a malicious document shared internally or by a guest spreads without warning.' `
                            -Recommendation 'Turn on Safe Attachments for SharePoint, OneDrive and Microsoft Teams in the Defender portal (Policies, Safe Attachments, Global settings).'))
            }
            elseif (-not (Test-SecOakDefenderTrue $policy.EnableSafeDocs)) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-22' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Safe Documents is turned off' `
                            -Evidence ([ordered]@{ enableSafeDocs = $false; licenceNote = 'Safe Documents needs Microsoft 365 E5 or E5 Security; ignore this item if the tenant is not licensed for it.' }) `
                            -Risk 'Office files opened in Protected View are not checked against Defender for Endpoint before the user clicks Enable Editing.' `
                            -Recommendation 'If Microsoft 365 E5 or E5 Security is licensed, enable Safe Documents in the Safe Attachments global settings and do not allow users to open files before the scan completes.'))
            }
        }

        #--- DEFENDER-23: Built-in protection
        $builtIn = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/BuiltInProtection' -Cmdlet Get-ATPBuiltInProtectionRule -RawName 'defender-builtin-protection-rule' -LicenseHint $mdoHint
        if ($null -ne $builtIn -and $builtIn.Count) {
            $rule = $builtIn[0]
            $summary.builtInProtection = [ordered]@{ state = "$($rule.State)"; exceptions = (@($rule.ExceptIfSentTo).Count + @($rule.ExceptIfSentToMemberOf).Count + @($rule.ExceptIfRecipientDomainIs).Count) }
            if ("$($rule.State)" -ne 'Enabled') {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-23' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'Built-in protection preset policy is disabled' `
                            -Evidence ([ordered]@{ state = "$($rule.State)" }) `
                            -Risk 'Built-in protection is the safety net that gives every mailbox Safe Links and Safe Attachments even when no other policy applies. With it off, anyone outside a custom or preset policy has neither.' `
                            -Recommendation 'Re-enable the Built-in protection preset security policy in the Defender portal. It has no user-visible impact and is on by default.'))
            }
        }

        #--- DEFENDER-24 and DEFENDER-25: Standard and Strict preset adoption, both layers
        $eopRules = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/PresetPolicies' -Cmdlet Get-EOPProtectionPolicyRule -RawName 'defender-eop-preset-rules'
        $atpRules = Get-SecOakDefenderExchangeData -Context $Context -Check 'Defender/PresetPolicies' -Cmdlet Get-ATPProtectionPolicyRule -RawName 'defender-atp-preset-rules' -LicenseHint $mdoHint
        if ($null -ne $eopRules) {
            $presets = [ordered]@{}
            foreach ($name in 'Standard Preset Security Policy', 'Strict Preset Security Policy') {
                $e = $eopRules | Where-Object { $_.Name -eq $name } | Select-Object -First 1
                $a = if ($null -ne $atpRules) { $atpRules | Where-Object { $_.Name -eq $name } | Select-Object -First 1 } else { $null }
                $presets[$name] = [ordered]@{
                    eopLayer = $(if ($e) { "$($e.State)" } else { 'not created' })
                    defenderLayer = $(if ($null -eq $atpRules) { 'not readable' } elseif ($a) { "$($a.State)" } else { 'not created' })
                }
            }
            $summary.presetSecurityPolicies = $presets
            $anyEopEnabled = @($presets.Values | Where-Object { $_.eopLayer -eq 'Enabled' }).Count -gt 0
            $partial = @($presets.Keys | Where-Object { $p = $presets[$_]; ($p.eopLayer -eq 'Enabled') -xor ($p.defenderLayer -eq 'Enabled') -and $p.defenderLayer -ne 'not readable' })
            if ($partial.Count -and $null -ne $atpRules -and $atpRules.Count) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-25' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'Preset security policy is only partially enabled (one of its two layers is off)' `
                            -Evidence ([ordered]@{ presets = @($partial | ForEach-Object { '{0}: EOP {1}, Defender for Office 365 {2}' -f $_, $presets[$_].eopLayer, $presets[$_].defenderLayer }) }) `
                            -Risk 'A preset policy has an Exchange Online Protection layer (spam, malware, spoofing) and a Defender for Office 365 layer (Safe Links, Safe Attachments, impersonation). With one layer off, the users assigned to the preset are missing half of the intended protection, and the portal makes this easy to miss.' `
                            -Recommendation 'Open the preset security policy in the Defender portal and enable both layers for the same set of users, or turn the preset off completely and rely on reviewed custom policies.'))
            }
            elseif (-not $anyEopEnabled) {
                $findings.Add((New-SecOakFinding -Id 'DEFENDER-24' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Neither the Standard nor the Strict preset security policy is enabled' `
                            -Evidence ([ordered]@{ presets = @($presets.Keys | ForEach-Object { '{0}: EOP {1}, Defender for Office 365 {2}' -f $_, $presets[$_].eopLayer, $presets[$_].defenderLayer }) }) `
                            -Risk 'The tenant relies entirely on the default and custom policies. Microsoft updates the preset policies as threats change; custom policies drift and are rarely reviewed.' `
                            -Recommendation 'Enable the Standard preset security policy for all users unless there is a documented reason to keep custom policies, and review any custom policy against Microsoft''s recommended settings.'))
            }
        }
    }
    finally {
        if ($openedExchange) { Disconnect-SecOakExchange -Context $Context }
    }
    #endregion

    #region Advanced hunting (HUNT-01 to 05), fixed queries through the approved read-only POST
    $hunting = [ordered]@{}
    $huntResults = @{}
    $huntingTables = @{
        'HUNT-01' = 'EntraIdSignInEvents (Microsoft Entra ID P1 or P2 with Defender XDR)'
        'HUNT-02' = 'DeviceTvmSecureConfigurationAssessment (Defender for Endpoint Plan 2 or Defender Vulnerability Management)'
        'HUNT-03' = 'EmailAttachmentInfo and EmailEvents (Defender for Office 365 Plan 2)'
        'HUNT-04' = 'CloudAppEvents (Defender for Cloud Apps with the Office 365 connector)'
        'HUNT-05' = 'DeviceEvents (Defender for Endpoint Plan 2)'
    }
    foreach ($id in $script:DefenderHuntingQueries.Keys) {
        $r = Invoke-SecOakReadOnlyPost -Context $Context -Api Graph -Area $area -Check "Defender/$id" -Path '/security/runHuntingQuery' -Body @{ Query = $script:DefenderHuntingQueries[$id] } -NoGap
        $huntResults[$id] = $r
        if ($r.Success) { $hunting[$id] = "ok ($(@($r.Items).Count) rows)"; continue }
        # A 400 "Failed to resolve table" means the tenant has no data for that workload: a licensing or
        # onboarding gap, not a permission failure and not a finding.
        $noData = ($r.StatusCode -eq 400 -and "$($r.ErrorMessage)" -match '(?i)failed to resolve (table|column|scalar)|semantic error')
        $hunting[$id] = if ($noData) { 'no data (table not available in this tenant)' } elseif ($r.StatusCode -in 401, 403) { 'forbidden' } else { "not run ($($r.ErrorCode))" }
        if ($noData) {
            Add-SecOakGap -Context $Context -Area $area -Check "Defender/$id" -EndpointOrCmdlet 'Graph POST /security/runHuntingQuery' -Result 'no data' `
                -Reason "The hunting table is not available in this tenant ($($r.ErrorMessage)). Advanced hunting only exposes tables for workloads that are licensed and onboarded." `
                -FillWith "Licence and onboard the workload that populates $($huntingTables[$id]); at least one device or mailbox must have reported data."
        }
        else {
            Add-SecOakGap -Context $Context -Area $area -Check "Defender/$id" -EndpointOrCmdlet 'Graph POST /security/runHuntingQuery' -Result "$($r.StatusCode)" `
                -Reason "$($r.ErrorCode): $($r.ErrorMessage)" -FillWith 'Application permission ThreatHunting.Read.All on the reader app, and a Defender XDR workload (Defender for Endpoint, Office 365, Identity, or Cloud Apps) licensed in the tenant.'
        }
    }
    $summary.hunting = $hunting

    #--- HUNT-01: successful legacy authentication sign-ins
    $r = $huntResults['HUNT-01']
    if ($r.Success) {
        $rows = @($r.Items)
        Save-SecOakRawData -Context $Context -Name 'defender-hunt-legacy-auth' -Data @($rows | Select-Object ClientAppUsed, SignIns, LastSeen)
        $summary.legacyAuthenticationSignIns30Days = [ordered]@{
            accounts    = @($rows | Select-Object -ExpandProperty AccountUpn -Unique).Count
            signIns     = @($rows | ForEach-Object { [int]$_.SignIns } | Measure-Object -Sum).Sum
            byClient    = @($rows | Group-Object ClientAppUsed | Sort-Object Count -Descending | ForEach-Object { '{0}: {1} accounts' -f $_.Name, $_.Count })
            note        = if ($rows.Count -eq 0) { 'No rows. Either no legacy sign-ins occurred, or sign-in data is not in advanced hunting (needs Microsoft Entra ID P1 or P2).' } else { '' }
        }
        if ($rows.Count) {
            $findings.Add((New-SecOakFinding -Id 'HUNT-01' -Area $area -Severity High -BaselineControl 'Legacy authentication blocked' `
                        -Title 'Successful sign-ins with legacy authentication in the last 30 days' `
                        -Evidence ([ordered]@{ accounts = $summary.legacyAuthenticationSignIns30Days.accounts; signIns = $summary.legacyAuthenticationSignIns30Days.signIns; examples = (Select-SecOakExample @($rows | Sort-Object { [int]$_.SignIns } -Descending | ForEach-Object { '{0} via {1} ({2} sign-ins)' -f $_.AccountUpn, $_.ClientAppUsed, $_.SignIns })) }) `
                        -Risk 'Legacy protocols (IMAP, POP, SMTP AUTH, ActiveSync basic) accept a password alone and ignore multifactor authentication and most conditional access rules, so one leaked password is enough to read the mailbox.' `
                        -Recommendation 'Move the listed accounts and devices (usually scanners, old phones, or line-of-business apps) to modern authentication, then block legacy authentication for everyone with a conditional access policy.'))
        }
    }

    #--- HUNT-02: tamper-protection secure configuration not compliant
    $r = $huntResults['HUNT-02']
    if ($r.Success) {
        $rows = @($r.Items)
        $devices = @($rows | Select-Object -ExpandProperty DeviceName -Unique)
        $summary.tamperProtectionNonCompliant = [ordered]@{
            devices = $devices.Count
            note    = if ($rows.Count -eq 0) { 'No rows. Either every assessed device is compliant, or Defender Vulnerability Management is not licensed (the table is empty without it).' } else { '' }
        }
        if ($rows.Count) {
            $findings.Add((New-SecOakFinding -Id 'HUNT-02' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Devices without tamper protection or related security controls' `
                        -Evidence ([ordered]@{ devices = $devices.Count; controls = @($rows | Select-Object -ExpandProperty ConfigurationName -Unique); examples = (Select-SecOakExample $devices) }) `
                        -Risk 'Without tamper protection, malware or an attacker with admin rights can switch off Defender antivirus and real-time protection with one command, then operate unseen.' `
                        -Recommendation 'Enable tamper protection tenant-wide in the Defender portal (Settings, Endpoints, Advanced features) or through an Intune antivirus policy, and confirm the listed devices become compliant.'))
        }
    }

    #--- HUNT-03: macro-enabled attachments delivered
    $r = $huntResults['HUNT-03']
    if ($r.Success) {
        $rows = @($r.Items)
        $withThreat = @($rows | Where-Object { "$($_.ThreatTypes)" -match '(?i)malware|phish' })
        $summary.macroAttachmentsDelivered30Days = [ordered]@{
            senders   = $rows.Count
            messages  = @($rows | ForEach-Object { [int]$_.Messages } | Measure-Object -Sum).Sum
            sendersWithThreatVerdict = $withThreat.Count
            note      = if ($rows.Count -eq 0) { 'No rows. Either no macro-enabled files were delivered, or email tables are not populated (needs Defender for Office 365).' } else { '' }
        }
        if ($rows.Count) {
            $findings.Add((New-SecOakFinding -Id 'HUNT-03' -Area $area -Severity $(if ($withThreat.Count) { 'Critical' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Macro-enabled Office attachments delivered to mailboxes in the last 30 days' `
                        -Evidence ([ordered]@{ senders = $rows.Count; messages = $summary.macroAttachmentsDelivered30Days.messages; sendersWithThreatVerdict = $withThreat.Count; examples = (Select-SecOakExample @($withThreat + $rows | Select-Object -Unique -First 5 | ForEach-Object { '{0} ({1} messages, types {2}{3})' -f $_.SenderFromAddress, $_.Messages, (@($_.FileTypes) -join '/'), $(if ("$($_.ThreatTypes)" -match '(?i)malware|phish') { ', threat verdict' } else { '' }) })) }) `
                        -Risk 'Macro-enabled files (.docm, .xlsm) are the classic ransomware delivery method. Any that arrived with a malware or phishing verdict were delivered before the verdict and may have been opened.' `
                        -Recommendation 'Add macro-enabled file types to the common attachment filter unless a partner genuinely needs to send them, keep Office set to block macros from the internet, and check with the recipients whether the flagged messages were opened.'))
        }
    }

    #--- HUNT-04: inbox rules that forward or redirect mail
    $r = $huntResults['HUNT-04']
    if ($r.Success) {
        $rows = @($r.Items)
        $classified = foreach ($row in $rows) {
            $targets = @(Get-SecOakDefenderForwardingTarget $row.RuleParameters)
            $external = @($targets | Where-Object { $t = $_; -not @($acceptedDomains | Where-Object { $t.EndsWith("@$_") -or $t.EndsWith(".$_") }).Count })
            [pscustomobject]@{ Account = "$($row.AccountDisplayName)"; ActionType = "$($row.ActionType)"; Timestamp = $row.Timestamp; Targets = $targets; External = $external; Country = "$($row.CountryCode)" }
        }
        $classified = @($classified)
        $externalRules = @($classified | Where-Object { $_.External.Count -gt 0 })
        $summary.inboxRuleForwardingEvents30Days = [ordered]@{
            events         = $rows.Count
            withExternalTarget = $externalRules.Count
            acceptedDomainsKnown = $acceptedDomains.Count
            note           = if ($rows.Count -eq 0) { 'No rows. Either no forwarding rules were created, or Exchange Online audit events are not flowing into advanced hunting (needs the Office 365 connector in Defender for Cloud Apps).' } else { '' }
        }
        if ($externalRules.Count) {
            $findings.Add((New-SecOakFinding -Id 'HUNT-04' -Area $area -Severity High -BaselineControl 'No automatic external forwarding' `
                        -Title 'Inbox rules forwarding mail outside the organisation were created in the last 30 days' `
                        -Evidence ([ordered]@{ events = $externalRules.Count; examples = (Select-SecOakExample @($externalRules | ForEach-Object { '{0} ({1}, to {2}, from {3})' -f $_.Account, $_.ActionType, ($_.External -join ', '), $_.Country })) }) `
                        -Risk 'A rule that quietly forwards or redirects mail to an outside address is the standard sign of a compromised mailbox: the attacker reads everything, including password resets and invoices, even after the password is changed.' `
                        -Recommendation 'Check each listed account now: remove the rule, reset the password, revoke sessions, and review recent sign-ins. Then block automatic external forwarding in the outbound spam policy.'))
        }
        elseif ($classified.Count -and $acceptedDomains.Count -eq 0) {
            $findings.Add((New-SecOakFinding -Id 'HUNT-04' -Area $area -Severity Medium -BaselineControl 'No automatic external forwarding' `
                        -Title 'Inbox rules that forward or redirect mail were created in the last 30 days (destination not classified)' `
                        -Evidence ([ordered]@{ events = $classified.Count; examples = (Select-SecOakExample @($classified | ForEach-Object { '{0} ({1}, to {2})' -f $_.Account, $_.ActionType, ($_.Targets -join ', ') })) }) `
                        -Risk 'The accepted domains could not be read, so it is unknown whether these rules send mail outside the organisation.' `
                        -Recommendation 'Review each rule with the account owner and remove any that forward to an address outside the company.'))
        }
    }

    #--- HUNT-05: tampering attempts against the sensor
    $r = $huntResults['HUNT-05']
    if ($r.Success) {
        $rows = @($r.Items)
        $summary.tamperingAttempts30Days = [ordered]@{
            devices  = $rows.Count
            attempts = @($rows | ForEach-Object { [int]$_.Attempts } | Measure-Object -Sum).Sum
            note     = if ($rows.Count -eq 0) { 'No rows. No tampering attempts were recorded; devices without tamper protection generate no such events.' } else { '' }
        }
        if ($rows.Count) {
            $findings.Add((New-SecOakFinding -Id 'HUNT-05' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Attempts to tamper with Defender for Endpoint in the last 30 days' `
                        -Evidence ([ordered]@{ devices = $rows.Count; attempts = $summary.tamperingAttempts30Days.attempts; examples = (Select-SecOakExample @($rows | ForEach-Object { '{0} ({1} attempts, {2})' -f $_.DeviceName, $_.Attempts, (@($_.Processes) -join ', ') })) }) `
                        -Risk 'Something on these devices tried to disable antivirus or the sensor. Whether it was malware, a remote-access tool, or a user with admin rights, it is the step that comes right before ransomware runs.' `
                        -Recommendation 'Investigate each device in the Defender portal timeline, remove the process responsible, and make sure tamper protection is in block mode rather than audit mode.'))
        }
    }
    #endregion

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
