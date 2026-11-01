function Invoke-SecOakBackupCheck {
    <#
    .SYNOPSIS
        Backup area: whether Microsoft 365 Backup is enabled and which workloads have an active protection policy.
    .DESCRIPTION
        Implements catalogue checks M365-44 and M365-45 against the Graph Microsoft 365 Backup
        endpoints. The summary states plainly whether any Microsoft 365 Backup protection
        exists ("None detected", "Present: ..." or "Cannot read"). The endpoints answer only
        to a registered backup controller app, so a 403 from a plain reporting app is a gap
        and the backup state must then be confirmed manually with the client. A third-party
        backup product is not visible through these endpoints at all.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakBackupCheck -Context $context
    .NOTES
        Application permissions: BackupRestore-Control.Read.All (M365-44),
        BackupRestore-Configuration.Read.All (M365-45).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Backup'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $recommendedService = 'a Microsoft 365 backup service (Microsoft 365 Backup or a third-party product)'

    #region M365-44 Backup service status
    $statusResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Backup/ServiceStatus' -Path '/solutions/backupRestore/serviceStatus' -NoPaging -NoGap
    $serviceStatus = $null
    $serviceReadable = $false
    if ($statusResult.Success) {
        $serviceReadable = $true
        $serviceStatus = $statusResult.Body
        $summary.serviceStatus = [ordered]@{
            status                    = "$($serviceStatus.status)"
            disableReason             = "$($serviceStatus.disableReason)"
            gracePeriodEnds           = if ($serviceStatus.gracePeriodDateTime) { (ConvertTo-SecOakUtcDate $serviceStatus.gracePeriodDateTime).ToString('yyyy-MM-dd') } else { $null }
            restoreAllowedUntil       = if ($serviceStatus.restoreAllowedTillDateTime) { (ConvertTo-SecOakUtcDate $serviceStatus.restoreAllowedTillDateTime).ToString('yyyy-MM-dd') } else { $null }
        }
        Save-SecOakRawData -Context $Context -Name 'backup-service-status' -Data @($serviceStatus | Select-Object status, disableReason, gracePeriodDateTime, restoreAllowedTillDateTime)
    }
    elseif ($statusResult.StatusCode -eq 404) {
        # The backup service has never been set up in this tenant.
        $serviceReadable = $true
        $summary.serviceStatus = [ordered]@{ status = 'notSetUp'; disableReason = 'never enabled' }
    }
    else {
        $summary.serviceStatus = 'Cannot read'
        $reason = "$($statusResult.ErrorMessage)" -replace '\s+', ' '
        if (-not $reason) { $reason = "HTTP $($statusResult.StatusCode) $($statusResult.ErrorCode)".Trim() }
        Add-SecOakGap -Context $Context -Area $area -Check 'Backup/ServiceStatus' -EndpointOrCmdlet '/solutions/backupRestore/serviceStatus' -Result "$($statusResult.StatusCode)" `
            -Reason $reason `
            -FillWith 'Application permission BackupRestore-Control.Read.All. Only a registered backup controller app can read this; otherwise confirm the backup state manually in the admin centre under Settings, Microsoft 365 Backup.'
    }
    #endregion

    #region M365-45 Protection policies
    $policiesResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Backup/ProtectionPolicies' -Path '/solutions/backupRestore/protectionPolicies' -RawName 'backup-protection-policies' -NoGap
    $policiesReadable = $false
    $policies = @()
    $active = @()
    $troubled = @()
    $coveredWorkloads = @()
    $uncovered = @()
    if ($policiesResult.Success) {
        $policiesReadable = $true
        $policies = @($policiesResult.Items)
    }
    elseif ($policiesResult.StatusCode -eq 404) {
        $policiesReadable = $true
    }
    else {
        $reason = "$($policiesResult.ErrorMessage)" -replace '\s+', ' '
        if (-not $reason) { $reason = "HTTP $($policiesResult.StatusCode) $($policiesResult.ErrorCode)".Trim() }
        Add-SecOakGap -Context $Context -Area $area -Check 'Backup/ProtectionPolicies' -EndpointOrCmdlet '/solutions/backupRestore/protectionPolicies' -Result "$($policiesResult.StatusCode)" `
            -Reason $reason `
            -FillWith 'Application permission BackupRestore-Configuration.Read.All. Only a registered backup controller app can read this; otherwise confirm which workloads are backed up manually.'
    }

    $workloadOf = {
        param($policy)
        switch -Regex ("$($policy.'@odata.type')") {
            'exchange' { 'Exchange'; break }
            'sharePoint' { 'SharePoint'; break }
            'oneDrive' { 'OneDrive'; break }
            default { 'Unknown' }
        }
    }
    if ($policiesReadable) {
        $active = @($policies | Where-Object { "$($_.status)" -eq 'active' })
        $troubled = @($policies | Where-Object { "$($_.status)" -in 'activeWithErrors', 'updating', 'inactive' })
        $coveredWorkloads = @($active | ForEach-Object { & $workloadOf $_ } | Sort-Object -Unique)
        $allWorkloads = 'Exchange', 'SharePoint', 'OneDrive'
        $uncovered = @($allWorkloads | Where-Object { $_ -notin $coveredWorkloads })
        $summary.protectionPolicies = [ordered]@{
            total            = $policies.Count
            active           = $active.Count
            withErrorsOrPending = $troubled.Count
            coveredWorkloads = $coveredWorkloads
            uncoveredWorkloads = $uncovered
        }
    }
    else { $summary.protectionPolicies = 'Cannot read' }
    #endregion

    #region Plain statement of backup protection
    $serviceEnabled = $serviceReadable -and $serviceStatus -and "$($serviceStatus.status)" -in 'enabled', 'protectionChangeLocked', 'restoreLocked'
    if ($policiesReadable -and $coveredWorkloads.Count) {
        $summary.backupProtection = 'Present: Microsoft 365 Backup covers ' + ($coveredWorkloads -join ', ') + $(if ($uncovered.Count) { '; not ' + ($uncovered -join ', ') } else { '' })
    }
    elseif ($serviceReadable -and $policiesReadable) {
        $summary.backupProtection = 'None detected (Microsoft 365 Backup ' + $(if ($serviceEnabled) { 'is enabled but has no active protection policy' } else { 'is not enabled' }) + '; a third-party backup would not show here)'
    }
    else {
        $summary.backupProtection = 'Cannot read (permission not granted); confirm with the client whether Microsoft 365 Backup or a third-party backup is in place'
    }
    #endregion

    #region Findings
    if ($serviceReadable -and $serviceStatus) {
        $status = "$($serviceStatus.status)"
        $reason = "$($serviceStatus.disableReason)"
        if ($status -eq 'disabled' -and $reason -in 'invalidBillingProfile', 'controllerServiceAppDeleted') {
            $findings.Add((New-SecOakFinding -Id 'M365-44' -Area $area -Severity High -BaselineControl 'Tested backups' `
                        -Title 'Microsoft 365 Backup has stopped because of a billing or controller problem' `
                        -Evidence ([ordered]@{ status = $status; disableReason = $reason; gracePeriodEnds = $summary.serviceStatus.gracePeriodEnds; restoreAllowedUntil = $summary.serviceStatus.restoreAllowedUntil }) `
                        -Risk 'Backups are no longer being taken, and once the grace period ends the existing restore points are deleted, so the business could lose the ability to recover email and files after a ransomware attack or an accidental deletion.' `
                        -Recommendation 'Fix the Azure billing profile (or re-register the backup app) before the grace period ends, then confirm in the admin centre that the status is back to Enabled and run a test restore.'))
        }
        elseif ($status -eq 'disabled' -and $serviceReadable -and $policiesReadable -and $coveredWorkloads.Count -eq 0) {
            $findings.Add((New-SecOakFinding -Id 'M365-44' -Area $area -Severity Medium -BaselineControl 'Tested backups' `
                        -Title 'Microsoft 365 Backup is not enabled' `
                        -Evidence ([ordered]@{ status = $status; disableReason = $reason; thirdPartyBackupVisible = $false }) `
                        -Risk 'Unless a separate backup product is in place, deleted or encrypted email and files can only be recovered within the standard retention windows, which is not enough after a ransomware attack or a leaver clearing out their files.' `
                        -Recommendation ('Confirm whether the business already runs {0}. If not, put one in place covering Exchange, SharePoint and OneDrive, and test a restore once a quarter.' -f $recommendedService)))
        }
    }
    elseif ($serviceReadable -and -not $serviceStatus -and $policiesReadable) {
        $findings.Add((New-SecOakFinding -Id 'M365-44' -Area $area -Severity Medium -BaselineControl 'Tested backups' `
                    -Title 'Microsoft 365 Backup has never been set up' `
                    -Evidence ([ordered]@{ status = 'notSetUp'; thirdPartyBackupVisible = $false }) `
                    -Risk 'Unless a separate backup product is in place, deleted or encrypted email and files can only be recovered within the standard retention windows, which is not enough after a ransomware attack or a leaver clearing out their files.' `
                    -Recommendation ('Confirm whether the business already runs {0}. If not, put one in place covering Exchange, SharePoint and OneDrive, and test a restore once a quarter.' -f $recommendedService)))
    }

    if ($policiesReadable -and $serviceEnabled -and $uncovered.Count) {
        $findings.Add((New-SecOakFinding -Id 'M365-45' -Area $area -Severity Medium -BaselineControl 'Tested backups' `
                    -Title 'Workloads without an active Microsoft 365 Backup policy' `
                    -Evidence ([ordered]@{ uncoveredWorkloads = $uncovered; coveredWorkloads = $coveredWorkloads; activePolicies = $active.Count }) `
                    -Risk 'The workloads listed are not being backed up, so their data cannot be restored after deletion or ransomware.' `
                    -Recommendation ('Add a protection policy for each uncovered workload, or cover it with {0}, and test a restore.' -f $recommendedService)))
    }
    if ($policiesReadable -and $troubled.Count) {
        $findings.Add((New-SecOakFinding -Id 'M365-45' -Area $area -Severity Low -BaselineControl 'Tested backups' `
                    -Title 'Backup protection policies with errors or still deploying' `
                    -Evidence ([ordered]@{ policies = $troubled.Count; examples = (Select-SecOakExample @($troubled | ForEach-Object { '{0} ({1}, {2})' -f $_.displayName, (& $workloadOf $_), $_.status })) }) `
                    -Risk 'A policy with errors may be skipping some mailboxes or sites, so a restore could come up short.' `
                    -Recommendation 'Open each policy in the admin centre, read the per-item errors, and fix or remove the failing items.'))
    }
    #endregion

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
