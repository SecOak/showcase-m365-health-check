function Invoke-SecOakServiceHealthCheck {
    <#
    .SYNOPSIS
        ServiceHealth area: degraded services, open incidents, message-centre actions due, licence errors, and subscription state.
    .DESCRIPTION
        Implements catalogue checks M365-38 to M365-42. Service health (M365-38 to M365-40)
        reads the Graph service announcement endpoints. M365-41 (licence assignment errors)
        and the subscription-state half of M365-42 live here because they describe tenant
        health rather than seat usage; the unused-seat half of M365-42 is already covered by
        LICENSING-01. Anything the app cannot read is a gap, not a finding.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakServiceHealthCheck -Context $context
    .NOTES
        Application permissions: ServiceHealth.Read.All (M365-38, M365-39),
        ServiceMessage.Read.All (M365-40), Directory.Read.All or User.Read.All plus
        Group.Read.All (M365-41, M365-42).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'ServiceHealth'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $now = [datetime]::UtcNow

    #region M365-38 Service health overview
    $overviews = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'ServiceHealth/Overview' -Path '/admin/serviceAnnouncement/healthOverviews' -RawName 'servicehealth-overviews'
    if ($overviews.Success) {
        $services = @($overviews.Items)
        $degradedStates = 'serviceDegradation', 'serviceInterruption', 'extendedRecovery'
        $degraded = @($services | Where-Object { "$($_.status)" -in $degradedStates })
        $summary.services = [ordered]@{
            total    = $services.Count
            healthy  = @($services | Where-Object { "$($_.status)" -eq 'serviceOperational' }).Count
            degraded = $degraded.Count
            byStatus = @($services | Group-Object status | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
        }
        if ($degraded.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-38' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Microsoft 365 services currently degraded or interrupted' `
                        -Evidence ([ordered]@{ services = $degraded.Count; examples = (Select-SecOakExample @($degraded | ForEach-Object { '{0} ({1})' -f $_.service, $_.status })) }) `
                        -Risk 'Staff may be unable to send email, join meetings or open files until Microsoft resolves the problem, and security features that rely on the affected service may not run.' `
                        -Recommendation 'Check the Service health page in the admin centre for the current status and expected resolution, and tell staff what is affected. This is a point-in-time observation, not a configuration fault.'))
        }
    }
    else { $summary.services = 'Cannot read' }
    #endregion

    #region M365-39 Open service issues
    $issues = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'ServiceHealth/Issues' -Path '/admin/serviceAnnouncement/issues?$filter=isResolved eq false' -RawName 'servicehealth-open-issues'
    if ($issues.Success) {
        $open = @($issues.Items)
        $incidents = @($open | Where-Object { "$($_.classification)" -eq 'incident' })
        $advisoryCutoff = $now.AddDays(-14)
        $oldAdvisories = @($open | Where-Object { "$($_.classification)" -eq 'advisory' -and ($d = ConvertTo-SecOakUtcDate $_.startDateTime) -and $d -lt $advisoryCutoff })
        $summary.openIssues = [ordered]@{
            total                  = $open.Count
            incidents              = $incidents.Count
            advisories             = @($open | Where-Object { "$($_.classification)" -eq 'advisory' }).Count
            advisoriesOverTwoWeeks = $oldAdvisories.Count
            services               = @($open | ForEach-Object { $_.service } | Sort-Object -Unique)
        }
        if ($incidents.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-39' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Open Microsoft 365 incidents affecting this tenant' `
                        -Evidence ([ordered]@{ incidents = $incidents.Count; examples = (Select-SecOakExample @($incidents | ForEach-Object { '{0}: {1} (since {2:yyyy-MM-dd})' -f $_.id, $_.title, (ConvertTo-SecOakUtcDate $_.startDateTime) })) }) `
                        -Risk 'An incident means a Microsoft service this tenant uses is failing or partly failing right now; some incidents involve security features not running.' `
                        -Recommendation 'Read each incident in the admin centre, note any user action Microsoft asks for, and confirm the incident is closed at the next check.'))
        }
        if ($oldAdvisories.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-39' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Service advisories open for more than two weeks' `
                        -Evidence ([ordered]@{ advisories = $oldAdvisories.Count; examples = (Select-SecOakExample @($oldAdvisories | ForEach-Object { '{0}: {1} (since {2:yyyy-MM-dd})' -f $_.id, $_.title, (ConvertTo-SecOakUtcDate $_.startDateTime) })) }) `
                        -Risk 'Long-running advisories usually describe a known limitation or a change the tenant must adapt to; ignoring them can leave a feature partly broken.' `
                        -Recommendation 'Review each advisory and record whether it needs action or can be dismissed.'))
        }
    }
    else { $summary.openIssues = 'Cannot read' }
    #endregion

    #region M365-40 Message centre posts requiring action
    $today = $now.ToString('yyyy-MM-ddT00:00:00Z')
    $messagesPath = "/admin/serviceAnnouncement/messages?`$filter=actionRequiredByDateTime ge $today&`$select=id,title,category,severity,isMajorChange,actionRequiredByDateTime,services,lastModifiedDateTime"
    $messages = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'ServiceHealth/Messages' -Path $messagesPath -NoGap
    if (-not $messages.Success -and $messages.StatusCode -eq 400) {
        # Some tenants reject the date filter; fall back to a full read filtered locally.
        $messages = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'ServiceHealth/Messages' -Path '/admin/serviceAnnouncement/messages?$select=id,title,category,severity,isMajorChange,actionRequiredByDateTime,services,lastModifiedDateTime'
    }
    elseif (-not $messages.Success) {
        $reason = "$($messages.ErrorMessage)" -replace '\s+', ' '
        if (-not $reason) { $reason = "HTTP $($messages.StatusCode) $($messages.ErrorCode)".Trim() }
        Add-SecOakGap -Context $Context -Area $area -Check 'ServiceHealth/Messages' -EndpointOrCmdlet '/admin/serviceAnnouncement/messages' -Result "$($messages.StatusCode)" `
            -Reason $reason -FillWith 'Application permission ServiceMessage.Read.All.'
    }
    if ($messages.Success) {
        $actionable = @($messages.Items | Where-Object {
                $due = ConvertTo-SecOakUtcDate $_.actionRequiredByDateTime
                $due -and $due -ge $now.Date
            })
        $urgent = @($actionable | Where-Object {
                ($_.isMajorChange -eq $true -or "$($_.category)" -eq 'planForChange') -and (ConvertTo-SecOakUtcDate $_.actionRequiredByDateTime) -le $now.AddDays(30)
            })
        $urgentIds = @($urgent.id)
        $soon = @($actionable | Where-Object { $_.id -notin $urgentIds -and (ConvertTo-SecOakUtcDate $_.actionRequiredByDateTime) -le $now.AddDays(90) })
        $summary.messageCentre = [ordered]@{
            postsWithActionDue = $actionable.Count
            dueWithinThirtyDays = $urgent.Count
            dueWithinNinetyDays = $soon.Count
            majorChanges       = @($actionable | Where-Object { $_.isMajorChange -eq $true }).Count
        }
        Save-SecOakRawData -Context $Context -Name 'servicehealth-messages-action-due' -Data $actionable
        if ($urgent.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-40' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Major Microsoft changes that need action within 30 days' `
                        -Evidence ([ordered]@{ posts = $urgent.Count; examples = (Select-SecOakExample @($urgent | ForEach-Object { '{0}: {1} (due {2:yyyy-MM-dd})' -f $_.id, $_.title, (ConvertTo-SecOakUtcDate $_.actionRequiredByDateTime) })) }) `
                        -Risk 'Microsoft is retiring or changing something the tenant uses; if nobody acts before the date, a feature, integration or sign-in method can stop working without warning.' `
                        -Recommendation 'Open each post in the Message centre, decide who owns the action, and complete it before the due date.'))
        }
        if ($soon.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-40' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Message centre posts with action due within 90 days' `
                        -Evidence ([ordered]@{ posts = $soon.Count; examples = (Select-SecOakExample @($soon | ForEach-Object { '{0}: {1} (due {2:yyyy-MM-dd})' -f $_.id, $_.title, (ConvertTo-SecOakUtcDate $_.actionRequiredByDateTime) })) }) `
                        -Risk 'These changes are further out but still need someone to read and plan for them.' `
                        -Recommendation 'Add the due dates to the IT calendar and review the Message centre monthly.'))
        }
    }
    else { $summary.messageCentre = 'Cannot read' }
    #endregion

    #region M365-41 Licence assignment errors
    $usersWithErrors = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'ServiceHealth/LicenseErrors' -Path '/users?$select=id,userPrincipalName,licenseAssignmentStates&$top=999' -RawName 'servicehealth-user-license-states'
    $groupsWithErrors = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'ServiceHealth/LicenseErrors' -Path '/groups?$filter=hasMembersWithLicenseErrors eq true&$select=id,displayName' -RawName 'servicehealth-group-license-errors'
    if ($usersWithErrors.Success -or $groupsWithErrors.Success) {
        $userErrors = @()
        if ($usersWithErrors.Success) {
            $userErrors = @($usersWithErrors.Items | Where-Object { @($_.licenseAssignmentStates | Where-Object { "$($_.state)" -eq 'Error' }).Count -gt 0 })
        }
        $groupErrors = if ($groupsWithErrors.Success) { @($groupsWithErrors.Items) } else { @() }
        $errorCodes = @($userErrors | ForEach-Object { @($_.licenseAssignmentStates | Where-Object { "$($_.state)" -eq 'Error' }).error } | Where-Object { $_ } | Group-Object | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
        $summary.licenseErrors = [ordered]@{
            usersScanned     = if ($usersWithErrors.Success) { @($usersWithErrors.Items).Count } else { 'Cannot read' }
            usersWithErrors  = if ($usersWithErrors.Success) { $userErrors.Count } else { 'Cannot read' }
            groupsWithErrors = if ($groupsWithErrors.Success) { $groupErrors.Count } else { 'Cannot read' }
            errorTypes       = $errorCodes
        }
        if ($userErrors.Count -or $groupErrors.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-41' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Licence assignments in an error state' `
                        -Evidence ([ordered]@{ users = $userErrors.Count; groups = $groupErrors.Count; errorTypes = $errorCodes; examples = (Select-SecOakExample @(@($userErrors.userPrincipalName) + @($groupErrors | ForEach-Object { 'group: ' + $_.displayName }))) }) `
                        -Risk 'A user whose licence failed to apply is missing services the business thinks they have, often including Defender, Intune or mailbox features, so they are less protected than their colleagues.' `
                        -Recommendation 'Open Billing, Licenses in the admin centre, fix the cause shown for each error (usually not enough seats or a conflicting plan), and reprocess the group assignment.'))
        }
    }
    else { $summary.licenseErrors = 'Cannot read' }
    #endregion

    #region M365-42 Subscription state
    if (-not $Context.Cache.ContainsKey('SubscribedSkus')) {
        $skuResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'ServiceHealth/Subscriptions' -Path '/subscribedSkus'
        $Context.Cache.SubscribedSkus = $null
        if ($skuResult.Success) { $Context.Cache.SubscribedSkus = @($skuResult.Items) }
    }
    if ($null -ne $Context.Cache.SubscribedSkus) {
        $skus = @($Context.Cache.SubscribedSkus)
        $securityPattern = '^(SPB|SPE_E3|SPE_E5|ENTERPRISEPREMIUM|EMS|EMSPREMIUM|AAD_PREMIUM|AAD_PREMIUM_P2|INTUNE_A|ATP_ENTERPRISE|THREAT_INTELLIGENCE|DEFENDER_ENDPOINT|MDATP|WIN_DEF_ATP|Microsoft_Defender|M365_SECURITY|IDENTITY_THREAT_PROTECTION)'
        $unhealthy = @($skus | Where-Object { "$($_.capabilityStatus)" -in 'Warning', 'Suspended', 'LockedOut' })
        $securityUnhealthy = @($unhealthy | Where-Object { "$($_.skuPartNumber)" -match $securityPattern })
        $suspended = @($securityUnhealthy | Where-Object { "$($_.capabilityStatus)" -in 'Suspended', 'LockedOut' })
        $summary.subscriptions = [ordered]@{
            total           = $skus.Count
            byStatus        = @($skus | Group-Object capabilityStatus | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            notHealthy      = $unhealthy.Count
            securityRelated = $securityUnhealthy.Count
            note            = 'Unassigned seats are assessed in the Licensing area (LICENSING-01).'
        }
        if ($unhealthy.Count) {
            $severity = if ($suspended.Count) { 'High' } elseif ($securityUnhealthy.Count) { 'Medium' } else { 'Low' }
            $findings.Add((New-SecOakFinding -Id 'M365-42' -Area $area -Severity $severity -BaselineControl 'None' `
                        -Title 'Subscriptions in warning, suspended or locked state' `
                        -Evidence ([ordered]@{ subscriptions = $unhealthy.Count; securityRelated = $securityUnhealthy.Count; examples = (Select-SecOakExample @($unhealthy | ForEach-Object { '{0} ({1})' -f $_.skuPartNumber, $_.capabilityStatus })) }) `
                        -Risk 'A subscription in warning has lapsed or has a payment problem and will be suspended; once suspended, its services (including security features) stop and the data is deleted after the grace period.' `
                        -Recommendation 'Check Billing, Your products in the admin centre, renew or fix payment for the affected subscription, and confirm it returns to Active.'))
        }
    }
    else { $summary.subscriptions = 'Cannot read' }
    #endregion

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
