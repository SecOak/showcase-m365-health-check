function Invoke-SecOakPostureCheck {
    <#
    .SYNOPSIS
        Posture area: latest Microsoft Secure Score and the top improvement actions.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakPostureCheck -Context $context
    .NOTES
        Application permission: SecurityEvents.Read.All.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Posture'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $scores = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Posture/SecureScore' -Path '/security/secureScores?$top=1' -NoPaging -RawName 'posture-secure-score'
    $profiles = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Posture/SecureScore' -Path '/security/secureScoreControlProfiles' -RawName 'posture-control-profiles'
    if ($scores.Success -and $scores.Items) {
        $latest = $scores.Items | Sort-Object { ConvertTo-SecOakUtcDate $_.createdDateTime } -Descending | Select-Object -First 1
        $percent = if ($latest.maxScore) { [math]::Round(100 * $latest.currentScore / $latest.maxScore, 1) } else { $null }
        $profileMap = @{}
        if ($profiles.Success) { foreach ($p in $profiles.Items) { $profileMap[$p.id] = $p } }
        $actions = foreach ($control in @($latest.controlScores)) {
            $p = $profileMap[$control.controlName]
            if (-not $p -or $p.deprecated) { continue }
            $gap = [double]$p.maxScore - [double]$control.score
            if ($gap -le 0) { continue }
            [pscustomobject][ordered]@{ Action = $p.title; PointsAvailable = [math]::Round($gap, 2); Category = $p.controlCategory; UserImpact = $p.userImpact; ImplementationCost = $p.implementationCost; Rank = $p.rank }
        }
        $top = @($actions | Sort-Object @{ Expression = 'PointsAvailable'; Descending = $true }, Rank | Select-Object -First 10)
        $summary.secureScore = [ordered]@{
            date            = (ConvertTo-SecOakUtcDate $latest.createdDateTime).ToString('yyyy-MM-dd')
            currentScore    = $latest.currentScore
            maxScore        = $latest.maxScore
            percent         = $percent
            comparativeAllTenants = @($latest.averageComparativeScores | Where-Object basis -eq 'AllTenants').averageScore
            topImprovementActions = $top
        }
        if ($null -ne $percent -and $percent -lt 60) {
            $findings.Add((New-SecOakFinding -Id 'POSTURE-01' -Area $area -Severity $(if ($percent -lt 40) { 'High' } else { 'Medium' }) -BaselineControl 'None' `
                        -Title 'Microsoft Secure Score is low' `
                        -Evidence ([ordered]@{ percent = $percent; currentScore = $latest.currentScore; maxScore = $latest.maxScore; topActions = (Select-SecOakExample $top.Action) }) `
                        -Risk 'Many of Microsoft''s recommended protections are not in place. The score is a broad indicator, not a measure of risk by itself.' `
                        -Recommendation 'Work through the top improvement actions, starting with identity protections, and track the score monthly.'))
        }
    }

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
