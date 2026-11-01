function Invoke-SecOakDeviceCheck {
    <#
    .SYNOPSIS
        Devices area: Intune managed device compliance, operating system versions, and sync age.
    .DESCRIPTION
        Patch age is estimated without external data: for Windows, each device's build
        revision is compared with the newest revision seen in the tenant for the same build.
        Windows 10 devices are flagged because Windows 10 support ended on 14 October 2025.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakDeviceCheck -Context $context
    .NOTES
        Application permission: DeviceManagementManagedDevices.Read.All. Requires Intune.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Devices'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $select = 'id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,managementAgent,managedDeviceOwnerType,userPrincipalName,enrolledDateTime,model'
    $result = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Devices/ManagedDevices' -Path "/deviceManagement/managedDevices?`$select=$select" -RawName 'devices-managed'
    if ($result.Success) {
        $devices = @($result.Items)
        $cutoff = [datetime]::UtcNow.AddDays(-30)
        $staleSync = @($devices | Where-Object { ($d = ConvertTo-SecOakUtcDate $_.lastSyncDateTime) -and $d -lt $cutoff })
        $nonCompliant = @($devices | Where-Object complianceState -in 'noncompliant', 'error', 'conflict')
        $windows = @($devices | Where-Object { $_.operatingSystem -eq 'Windows' -and $_.osVersion -match '^\d+\.\d+\.\d+\.\d+$' })
        $behind = [System.Collections.Generic.List[object]]::new()
        foreach ($group in ($windows | Group-Object { ($_.osVersion -split '\.')[0..2] -join '.' })) {
            $newest = ($group.Group | ForEach-Object { [int](($_.osVersion -split '\.')[3]) } | Measure-Object -Maximum).Maximum
            foreach ($device in $group.Group) {
                if ([int](($device.osVersion -split '\.')[3]) -lt $newest) { $behind.Add($device) }
            }
        }
        $windows10 = @($windows | Where-Object { [int](($_.osVersion -split '\.')[2]) -lt 22000 })
        $summary.devices = [ordered]@{
            total                = $devices.Count
            byOperatingSystem    = @($devices | Group-Object operatingSystem | Sort-Object Count -Descending | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            byCompliance         = @($devices | Group-Object complianceState | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            notSynced30Days      = $staleSync.Count
            windowsBehindNewestPatchInTenant = $behind.Count
            windows10            = $windows10.Count
            topWindowsVersions   = @($windows | Group-Object osVersion | Sort-Object Count -Descending | Select-Object -First 6 | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
        }
        if ($devices.Count -eq 0) {
            $findings.Add((New-SecOakFinding -Id 'DEVICES-01' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'No devices are managed by Intune' `
                        -Evidence ([ordered]@{ managedDevices = 0 }) `
                        -Risk 'There is no central view of whether company devices are encrypted, patched, or protected, and no way to wipe a lost device.' `
                        -Recommendation 'Enroll company Windows and mobile devices in Intune and assign compliance policies.'))
        }
        if ($nonCompliant.Count) {
            $findings.Add((New-SecOakFinding -Id 'DEVICES-02' -Area $area -Severity $(if ($nonCompliant.Count / [math]::Max(1, $devices.Count) -ge 0.2) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Devices not meeting compliance policy' `
                        -Evidence ([ordered]@{ nonCompliant = $nonCompliant.Count; total = $devices.Count; examples = (Select-SecOakExample @($nonCompliant | ForEach-Object { '{0} ({1} {2})' -f $_.deviceName, $_.operatingSystem, $_.complianceState })) }) `
                        -Risk 'Non-compliant devices may be missing encryption, updates, or protection while still reaching company data.' `
                        -Recommendation 'Fix or retire each device and require a compliant device in conditional access for company data.'))
        }
        if ($staleSync.Count) {
            $findings.Add((New-SecOakFinding -Id 'DEVICES-03' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Devices that have not synced with Intune in 30 days or more' `
                        -Evidence ([ordered]@{ devices = $staleSync.Count; examples = (Select-SecOakExample @($staleSync | ForEach-Object { '{0} (last sync {1:yyyy-MM-dd})' -f $_.deviceName, (ConvertTo-SecOakUtcDate $_.lastSyncDateTime) })) }) `
                        -Risk 'These devices are not receiving policy or updates, or are lost or retired but still registered.' `
                        -Recommendation 'Locate each device; retire or wipe those no longer in use and set up an automatic device cleanup rule.'))
        }
        if ($windows10.Count) {
            $findings.Add((New-SecOakFinding -Id 'DEVICES-04' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Windows 10 devices past end of support' `
                        -Evidence ([ordered]@{ devices = $windows10.Count; examples = (Select-SecOakExample @($windows10 | ForEach-Object { '{0} ({1})' -f $_.deviceName, $_.osVersion })) }) `
                        -Risk 'Windows 10 stopped receiving security updates on 14 October 2025 unless enrolled in Extended Security Updates, so new vulnerabilities stay open.' `
                        -Recommendation 'Upgrade to Windows 11 or confirm Extended Security Updates enrollment for each device.'))
        }
        if ($behind.Count) {
            # A proxy only; when every device passes compliance (which usually includes an OS version rule) keep it Low.
            $findings.Add((New-SecOakFinding -Id 'DEVICES-05' -Area $area -Severity $(if ($nonCompliant.Count) { 'Medium' } else { 'Low' }) -BaselineControl 'None' `
                        -Title 'Windows devices behind the newest patch level seen in the tenant' `
                        -Evidence ([ordered]@{ devices = $behind.Count; method = 'Build revision compared with the newest revision of the same build in this tenant (proxy for patch age).'; examples = (Select-SecOakExample @($behind | ForEach-Object { '{0} ({1})' -f $_.deviceName, $_.osVersion })) }) `
                        -Risk 'Devices missing monthly cumulative updates are exposed to vulnerabilities that are already public.' `
                        -Recommendation 'Use Windows Update for Business rings with deadlines and check the Intune update reports for failures.'))
        }
    }

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
