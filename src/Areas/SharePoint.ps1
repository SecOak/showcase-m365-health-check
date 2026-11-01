function Invoke-SecOakSharePointCheck {
    <#
    .SYNOPSIS
        SharePoint area: idle session sign-out, unmanaged device sync, deleted-user OneDrive
        retention, conditional access policy state, site ownership, orphaned OneDrives and
        report anonymization.
    .DESCRIPTION
        Implements catalogue checks M365-15 to M365-21. Sharing links, legacy authentication
        (M365-14), resharing and invitation matching are checked by the Sharing area and are
        not repeated here. Uses the Graph SharePoint tenant settings and the SharePoint and
        OneDrive usage reports only; no site content or Sites.Read.All.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        Area result object with Area, Summary, and Findings.
    .EXAMPLE
        Invoke-SecOakSharePointCheck -Context $context
    .NOTES
        Application permissions: SharePointTenantSettings.Read.All (tenant settings),
        Reports.Read.All (site and OneDrive usage reports), ReportSettings.Read.All
        (report anonymization state), Directory.Read.All (user inventory for owner lookups).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'SharePoint'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}

    #--- Licence gate (result state, not a failure)
    if (-not $Context.Cache.ContainsKey('ServicePlans')) {
        $skuResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check "$area/Licensing" -Path '/subscribedSkus' -NoGap
        $Context.Cache.ServicePlans = if ($skuResult.Success) { @($skuResult.Items | Where-Object capabilityStatus -eq 'Enabled' | ForEach-Object { $_.servicePlans } | ForEach-Object { "$($_.servicePlanName)" } | Select-Object -Unique) } else { $null }
    }
    $plans = $Context.Cache.ServicePlans
    $licensed = if ($null -eq $plans) { 'unknown' } elseif (@($plans | Where-Object { $_ -match '^(SHAREPOINT|ONEDRIVE)' }).Count) { 'yes' } else { 'no' }
    $summary.licensing = [ordered]@{ sharePointOrOneDrive = $licensed }
    if ($licensed -eq 'no') {
        $summary.result = 'Not licensed: no SharePoint or OneDrive service plan is enabled in this tenant, so the SharePoint checks were not run.'
        $Context.AreaSummaries[$area] = $summary
        return [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
    }

    #--- Tenant settings: M365-15, M365-16, M365-17, M365-18
    $settings = Invoke-SecOakGraphGet -Context $Context -Area $area -Check "$area/TenantSettings" -Path '/admin/sharepoint/settings' -RawName 'sharepoint-tenant-settings'
    if ($settings.Success) {
        $s = $settings.Body
        $idle = $s.idleSessionSignOut
        $summary.tenantSettings = [ordered]@{
            idleSessionSignOutEnabled              = [bool]$idle.isEnabled
            idleSessionWarnAfterSeconds            = $idle.warnAfterInSeconds
            idleSessionSignOutAfterSeconds         = $idle.signOutAfterInSeconds
            isUnmanagedSyncAppForTenantRestricted  = [bool]$s.isUnmanagedSyncAppForTenantRestricted
            allowedDomainGuidsForSyncApp           = @($s.allowedDomainGuidsForSyncApp).Count
            deletedUserPersonalSiteRetentionPeriodInDays = $s.deletedUserPersonalSiteRetentionPeriodInDays
            isMacSyncAppEnabled                    = $s.isMacSyncAppEnabled
            isSyncButtonHiddenOnPersonalSite       = $s.isSyncButtonHiddenOnPersonalSite
            isSitePagesCreationEnabled             = $s.isSitePagesCreationEnabled
            isCommentingOnSitePagesEnabled         = $s.isCommentingOnSitePagesEnabled
            isSiteCreationEnabled                  = $s.isSiteCreationEnabled
            isSiteCreationUIEnabled                = $s.isSiteCreationUIEnabled
            isLoopEnabled                          = $s.isLoopEnabled
            imageTaggingOption                     = $s.imageTaggingOption
            note                                   = 'Unmanaged device access policy state (M365-18) is not exposed through Graph; the Access area reports the Conditional Access policies that enforce it.'
        }
        if (-not $idle.isEnabled) {
            $findings.Add((New-SecOakFinding -Id 'M365-15' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Idle session sign-out for SharePoint and OneDrive is off' `
                        -Evidence ([ordered]@{ idleSessionSignOutEnabled = $false }) `
                        -Risk 'A browser session left open on a shared or unmanaged computer stays signed in to company files indefinitely. Anyone who sits at that computer next can open them.' `
                        -Recommendation 'Turn on idle session sign-out in the SharePoint admin center (Policies, Access control) with a warning after about 30 minutes and sign-out after 1 hour.'))
        }
        elseif ([int]$idle.signOutAfterInSeconds -gt 28800) {
            $findings.Add((New-SecOakFinding -Id 'M365-15' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Idle session sign-out waits longer than 8 hours' `
                        -Evidence ([ordered]@{ signOutAfterInSeconds = $idle.signOutAfterInSeconds }) `
                        -Risk 'The sign-out is on but so late that a session left open at the end of a day is still active the next morning.' `
                        -Recommendation 'Reduce the idle sign-out to 1 or 2 hours.'))
        }
        if (-not $s.isUnmanagedSyncAppForTenantRestricted) {
            $findings.Add((New-SecOakFinding -Id 'M365-16' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'OneDrive sync is allowed from computers outside the company' `
                        -Evidence ([ordered]@{ isUnmanagedSyncAppForTenantRestricted = $false; allowedDomainGuidsForSyncApp = @($s.allowedDomainGuidsForSyncApp).Count }) `
                        -Risk 'Staff can sync entire document libraries to a home or personal computer that the company does not manage, back up or wipe. Files then leave with the device.' `
                        -Recommendation 'Restrict the sync client to computers joined to the company domain or managed by Intune (SharePoint admin center, Settings, OneDrive sync, or an Intune device compliance policy with Conditional Access).'))
        }
        $retentionDays = $s.deletedUserPersonalSiteRetentionPeriodInDays
        if ($null -ne $retentionDays -and [int]$retentionDays -lt 90) {
            $findings.Add((New-SecOakFinding -Id 'M365-17' -Area $area -Severity Low -BaselineControl 'Tested backups' `
                        -Title 'OneDrive files of leavers are deleted in under 90 days' `
                        -Evidence ([ordered]@{ deletedUserPersonalSiteRetentionPeriodInDays = $retentionDays }) `
                        -Risk 'When someone leaves, their OneDrive is removed after this period. If nobody claims the files in time, work is lost with no way back.' `
                        -Recommendation 'Set the retention for deleted users OneDrive to at least 90 days (SharePoint admin center, Settings, OneDrive retention) and make handover of files part of the leaver process.'))
        }
    }

    #--- Report anonymization: M365-21
    $reportSettings = Invoke-SecOakGraphGet -Context $Context -Area $area -Check "$area/ReportSettings" -Path '/admin/reportSettings' -NoGap
    $namesHidden = $null
    if ($reportSettings.Success) {
        $namesHidden = [bool]$reportSettings.Body.displayConcealedNames
        $summary.reportSettings = [ordered]@{ displayConcealedNames = $namesHidden; source = '/admin/reportSettings' }
    }
    else {
        Add-SecOakGap -Context $Context -Area $area -Check "$area/ReportSettings" -EndpointOrCmdlet '/v1.0/admin/reportSettings' -Result "$($reportSettings.StatusCode)" `
            -Reason $(if ($reportSettings.ErrorMessage) { $reportSettings.ErrorMessage } else { 'The report settings could not be read.' }) `
            -FillWith 'Application permission ReportSettings.Read.All. Until then the report data itself is inspected for hashed names.'
    }

    #--- Usage reports: M365-19, M365-20
    Get-SecOakUserInventory -Context $Context
    $usersAvailable = $Context.Cache.ContainsKey('UsersAvailable') -and $Context.Cache.UsersAvailable
    $usersByAddress = @{}
    if ($usersAvailable) {
        foreach ($user in @($Context.Cache.Users)) {
            foreach ($address in @($user.userPrincipalName, $user.mail)) { if ($address) { $usersByAddress["$address".ToLowerInvariant()] = $user } }
        }
    }
    $reportFill = 'Application permission Reports.Read.All.'
    $hashedSeen = $false

    function ConvertFrom-SecOakReportCsv {
        param([AllowNull()]$Body)
        if ($null -eq $Body) { return @() }
        $text = if ($Body -is [string]) { $Body } elseif ($Body -is [byte[]]) { [System.Text.Encoding]::UTF8.GetString($Body) } else { "$Body" }
        $text = $text.TrimStart([char]0xFEFF)
        if (-not $text.Trim()) { return @() }
        @($text | ConvertFrom-Csv)
    }

    $sites = Invoke-SecOakGraphGet -Context $Context -Area $area -Check "$area/SiteOwnership" -Path "/reports/getSharePointSiteUsageDetail(period='D180')" -NoPaging -NoGap
    if ($sites.Success) {
        $rows = @(ConvertFrom-SecOakReportCsv -Body $sites.Body | Where-Object { "$($_.'Is Deleted')" -notmatch '^(True|1)$' })
        $reduced = @($rows | ForEach-Object {
                [pscustomobject][ordered]@{
                    SiteId            = "$($_.'Site Id')"
                    OwnerDisplayName  = "$($_.'Owner Display Name')"
                    OwnerPrincipalName = "$($_.'Owner Principal Name')"
                    LastActivityDate  = "$($_.'Last Activity Date')"
                    FileCount         = "$($_.'File Count')"
                    ActiveFileCount   = "$($_.'Active File Count')"
                    StorageUsedBytes  = "$($_.'Storage Used (Byte)')"
                    RootWebTemplate   = "$($_.'Root Web Template')"
                    ExternalSharing   = "$($_.'External Sharing')"
                }
            })
        Save-SecOakRawData -Context $Context -Name 'sharepoint-site-usage-detail' -Data $reduced
        $hashedOwners = @($reduced | Where-Object { $_.OwnerPrincipalName -and $_.OwnerPrincipalName -notmatch '@' -and $_.OwnerPrincipalName -match '^[0-9A-Fa-f]{16,}$' })
        if ($hashedOwners.Count) { $hashedSeen = $true }
        # Built-in system sites have no owner by design and are excluded from the ownership and inactivity evaluation.
        $systemTemplates = @('Basic Search Center', 'Compliance Policy Center', 'My Site Host', 'SharePoint Online Tenant Fundamental Site', 'Tenant Admin Site', 'Project Web App Site', 'App Catalog Site', 'Redirect Site', 'Point Publishing Hub', 'Point Publishing Topic', 'Content Center')
        $systemSites = @($reduced | Where-Object { $_.RootWebTemplate -in $systemTemplates })
        $reduced = @($reduced | Where-Object { $_.RootWebTemplate -notin $systemTemplates })
        $cutoff = [datetime]::UtcNow.AddDays(-180)
        $inactive = @($reduced | Where-Object {
                $d = $null
                if ($_.LastActivityDate) { try { $d = ConvertTo-SecOakUtcDate $_.LastActivityDate } catch { $d = $null } }
                ($null -eq $d) -or ($d -lt $cutoff)
            })
        $ownerless = @($reduced | Where-Object { -not $_.OwnerPrincipalName -and -not $_.OwnerDisplayName })
        $disabledOwner = @()
        if ($usersAvailable -and -not $hashedSeen) {
            $disabledOwner = @($reduced | Where-Object {
                    $_.OwnerPrincipalName -and $_.RootWebTemplate -ne 'Group' -and $_.RootWebTemplate -notmatch 'Group#0' -and
                    ($u = $usersByAddress["$($_.OwnerPrincipalName)".ToLowerInvariant()]) -and -not $u.accountEnabled
                })
        }
        $summary.sites = [ordered]@{
            sitesInReport         = $reduced.Count
            systemSitesExcluded   = $systemSites.Count
            byTemplate            = @($reduced | Group-Object RootWebTemplate | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            inactive180Days       = $inactive.Count
            ownerless             = $ownerless.Count
            disabledOwner         = $disabledOwner.Count
            externalSharingEnabled = @($reduced | Where-Object { $_.ExternalSharing -match '^(True|1)$' }).Count
            ownerLookup           = $(if ($hashedSeen) { 'not possible (report names are hashed)' } elseif ($usersAvailable) { 'user inventory' } else { 'user inventory unavailable' })
        }
        if (-not $usersAvailable) {
            Add-SecOakGap -Context $Context -Area $area -Check "$area/SiteOwnership" -EndpointOrCmdlet '/v1.0/users (accountEnabled)' -Result 'not collected' `
                -Reason 'The Graph user inventory is unavailable, so site owners could not be checked against account state.' -FillWith 'Application permission Directory.Read.All.'
        }
        if ($ownerless.Count -or $disabledOwner.Count) {
            $affected = @($ownerless + $disabledOwner)
            $findings.Add((New-SecOakFinding -Id 'M365-19' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'SharePoint sites with no owner or a disabled owner' `
                        -Evidence ([ordered]@{ ownerless = $ownerless.Count; disabledOwner = $disabledOwner.Count; total = $reduced.Count; examples = (Select-SecOakExample @($affected | ForEach-Object { if ($_.OwnerPrincipalName) { $_.OwnerPrincipalName } else { $_.SiteId } })) }) `
                        -Risk 'Nobody is responsible for who can see these sites or whether their files are still needed. Access reviews and clean-up never happen, and the files stay reachable by whoever was once added.' `
                        -Recommendation 'Assign an active owner to each site (SharePoint admin center, Active sites) and include site ownership in the leaver process.'))
        }
        if ($inactive.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-19' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'SharePoint sites with no activity for 180 days' `
                        -Evidence ([ordered]@{ sites = $inactive.Count; total = $reduced.Count }) `
                        -Risk 'Forgotten sites keep old data, and old sharing, alive. They add to what an attacker can reach and to what must be searched in a data request.' `
                        -Recommendation 'Review the inactive sites with their owners; archive or delete the ones no longer needed and set a site lifecycle policy in the SharePoint admin center.'))
        }
    }
    else {
        Add-SecOakGap -Context $Context -Area $area -Check "$area/SiteOwnership" -EndpointOrCmdlet "/v1.0/reports/getSharePointSiteUsageDetail(period='D180')" -Result "$($sites.StatusCode)" `
            -Reason $(if ($sites.ErrorMessage) { $sites.ErrorMessage } else { 'The site usage report could not be read.' }) -FillWith $reportFill
    }

    $drives = Invoke-SecOakGraphGet -Context $Context -Area $area -Check "$area/OrphanedOneDrive" -Path "/reports/getOneDriveUsageAccountDetail(period='D30')" -NoPaging -NoGap
    if ($drives.Success) {
        $rows = @(ConvertFrom-SecOakReportCsv -Body $drives.Body | Where-Object { "$($_.'Is Deleted')" -notmatch '^(True|1)$' })
        $reduced = @($rows | ForEach-Object {
                [pscustomobject][ordered]@{
                    OwnerPrincipalName = "$($_.'Owner Principal Name')"
                    LastActivityDate   = "$($_.'Last Activity Date')"
                    FileCount          = "$($_.'File Count')"
                    StorageUsedBytes   = "$($_.'Storage Used (Byte)')"
                }
            })
        Save-SecOakRawData -Context $Context -Name 'sharepoint-onedrive-usage-detail' -Data $reduced
        $hashedDrives = @($reduced | Where-Object { $_.OwnerPrincipalName -and $_.OwnerPrincipalName -notmatch '@' -and $_.OwnerPrincipalName -match '^[0-9A-Fa-f]{16,}$' })
        if ($hashedDrives.Count) { $hashedSeen = $true }
        $withStorage = @($reduced | Where-Object { [int64]"$(if ($_.StorageUsedBytes) { $_.StorageUsedBytes } else { 0 })" -gt 0 })
        $orphaned = @()
        $matchedState = 'not checked'
        if ($hashedSeen) { $matchedState = 'not possible (report names are hashed)' }
        elseif ($usersAvailable) {
            $matchedState = 'user inventory'
            $orphaned = @($withStorage | Where-Object {
                    $u = $usersByAddress["$($_.OwnerPrincipalName)".ToLowerInvariant()]
                    ($null -eq $u) -or (-not $u.accountEnabled)
                })
        }
        else {
            Add-SecOakGap -Context $Context -Area $area -Check "$area/OrphanedOneDrive" -EndpointOrCmdlet '/v1.0/users (accountEnabled)' -Result 'not collected' `
                -Reason 'The Graph user inventory is unavailable, so OneDrive owners could not be checked against account state.' -FillWith 'Application permission Directory.Read.All.'
        }
        $summary.oneDrive = [ordered]@{ accountsInReport = $reduced.Count; withStorage = $withStorage.Count; orphaned = $orphaned.Count; ownerLookup = $matchedState }
        if ($orphaned.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-20' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'OneDrive storage belonging to disabled or missing accounts' `
                        -Evidence ([ordered]@{ oneDrives = $orphaned.Count; total = $withStorage.Count; examples = (Select-SecOakExample $orphaned.OwnerPrincipalName) }) `
                        -Risk 'Files of people who have left still sit in their OneDrive. Anyone they shared with keeps access, and the files disappear for good once the retention period ends.' `
                        -Recommendation 'For each leaver, assign a manager access to the OneDrive, move the files that matter to a team site, and let the account be removed after handover.'))
        }
    }
    else {
        Add-SecOakGap -Context $Context -Area $area -Check "$area/OrphanedOneDrive" -EndpointOrCmdlet "/v1.0/reports/getOneDriveUsageAccountDetail(period='D30')" -Result "$($drives.StatusCode)" `
            -Reason $(if ($drives.ErrorMessage) { $drives.ErrorMessage } else { 'The OneDrive usage report could not be read.' }) -FillWith $reportFill
    }

    #--- M365-21 evaluation
    if ($null -eq $namesHidden -and ($sites.Success -or $drives.Success)) {
        $namesHidden = $hashedSeen
        $summary.reportSettings = [ordered]@{ displayConcealedNames = $namesHidden; source = 'inferred from report data' }
    }
    if ($true -eq $namesHidden) {
        $findings.Add((New-SecOakFinding -Id 'M365-21' -Area $area -Severity Low -BaselineControl 'None' `
                    -Title 'Usage reports hide user and site names' `
                    -Evidence ([ordered]@{ displayConcealedNames = $true; source = $summary.reportSettings.source }) `
                    -Risk 'With names hashed in the usage reports, nobody can tell which person or site an inactive OneDrive, a large site or unusual activity belongs to. The site ownership and orphaned OneDrive checks above could not name the owners.' `
                    -Recommendation 'In the Microsoft 365 admin center (Settings, Org settings, Reports) turn off "Display concealed user, group, and site names in all reports", or agree that privacy takes precedence and accept that report-based checks stay anonymous.'))
    }

    $summary.coveredElsewhere = 'Sharing links, legacy authentication (M365-14), resharing and invitation matching: Sharing area (SHARING-01 to SHARING-04).'
    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
