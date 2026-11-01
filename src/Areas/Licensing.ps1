function Invoke-SecOakLicensingCheck {
    <#
    .SYNOPSIS
        Licensing area: purchased versus assigned licenses and licensed users with no sign-in in 90 days.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakLicensingCheck -Context $context
    .NOTES
        Application permissions: Directory.Read.All (subscribed licenses and users),
        AuditLog.Read.All.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Licensing'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $result = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Licensing/SubscribedSkus' -Path '/subscribedSkus' -RawName 'licensing-subscribed-skus'
    if ($result.Success) {
        $skus = @($result.Items | ForEach-Object {
                [pscustomobject][ordered]@{
                    Sku        = $_.skuPartNumber
                    Status     = $_.capabilityStatus
                    Purchased  = [int]$_.prepaidUnits.enabled
                    Assigned   = [int]$_.consumedUnits
                    Unassigned = [int]$_.prepaidUnits.enabled - [int]$_.consumedUnits
                    Plans      = @($_.servicePlans.servicePlanName)
                }
            })
        $plans = @($skus.Plans)
        $Context.Cache.Premium = [ordered]@{
            EntraIdP1 = [bool]($plans -contains 'AAD_PREMIUM')
            EntraIdP2 = [bool]($plans -contains 'AAD_PREMIUM_P2')
            Intune    = [bool]($plans -match '^INTUNE_A')
            DefenderForOffice = [bool]($plans -match '^ATP_ENTERPRISE|THREAT_INTELLIGENCE')
        }
        # Very large pools are free or viral offers, not purchased seats.
        $paidUnused = @($skus | Where-Object { $_.Status -eq 'Enabled' -and $_.Purchased -gt 0 -and $_.Purchased -lt 10000 -and $_.Unassigned -gt 0 })
        $summary.subscriptions = @($skus | Where-Object Purchased -lt 10000 | Select-Object Sku, Status, Purchased, Assigned, Unassigned)
        $summary.premiumFeatures = $Context.Cache.Premium
        if ($paidUnused.Count) {
            $findings.Add((New-SecOakFinding -Id 'LICENSING-01' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Purchased licenses not assigned' `
                        -Evidence ([ordered]@{ skus = $paidUnused.Count; unassignedSeats = ($paidUnused | Measure-Object Unassigned -Sum).Sum; examples = (Select-SecOakExample @($paidUnused | ForEach-Object { '{0}: {1} of {2} unassigned' -f $_.Sku, $_.Unassigned, $_.Purchased })) }) `
                        -Risk 'Cost only: the company pays for seats nobody uses.' `
                        -Recommendation 'Reduce the seat count at the next renewal or reassign the seats.'))
        }
    }

    Get-SecOakUserInventory -Context $Context
    if ($Context.Cache.SignInActivityAvailable) {
        $cutoff = [datetime]::UtcNow.AddDays(-90)
        $idle = @($Context.Cache.Users | Where-Object {
                @($_.assignedLicenses).Count -gt 0 -and (ConvertTo-SecOakUtcDate $_.createdDateTime) -lt $cutoff -and
                ($null -eq ($last = Get-SecOakLastSignIn -User $_) -or $last -lt $cutoff)
            })
        $disabledLicensed = @($idle | Where-Object { -not $_.accountEnabled })
        $summary.licensedUsersNoSignIn90Days = $idle.Count
        if ($idle.Count) {
            $findings.Add((New-SecOakFinding -Id 'LICENSING-02' -Area $area -Severity $(if ($idle.Count -gt 5) { 'Medium' } else { 'Low' }) -BaselineControl 'None' `
                        -Title 'Licensed users with no sign-in for 90 days or more' `
                        -Evidence ([ordered]@{ users = $idle.Count; disabledButLicensed = $disabledLicensed.Count; examples = (Select-SecOakExample $idle.userPrincipalName) }) `
                        -Risk 'Paid licenses on unused accounts cost money, and the enabled ones are unwatched accounts an attacker could use.' `
                        -Recommendation 'Confirm with the business owner, then convert shared use to shared mailboxes, remove licenses, and disable leavers.'))
        }
    }
    else { $summary.licensedUsersNoSignIn90Days = 'unavailable (sign-in activity not readable)' }

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
