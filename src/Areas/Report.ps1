function Export-SecOakRunReport {
    <#
    .SYNOPSIS
        Writes endpoint-log.csv, token-scopes.txt, findings.json, gaps.md, and run-summary.json.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        A summary object with counts per area and severity, and the output path.
    .EXAMPLE
        Export-SecOakRunReport -Context $context
    .NOTES
        No permissions required. Writes only under the run's output folder.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $out = $Context.OutputPath
    $script:EndpointLog | Export-Csv -Path (Join-Path $out 'endpoint-log.csv') -NoTypeInformation -Encoding utf8

    # A tenantless run (public domain checks only) acquires no tokens, so it has no token-scopes.txt.
    if (-not $Context.Tenantless) {
        $scopeLines = [System.Collections.Generic.List[string]]::new()
        $scopeLines.Add('Token permission names recorded for this run. Tokens themselves are never stored.')
        $scopeLines.Add('')
        foreach ($record in $script:TokenClaimRecords) {
            $label = if ($record.Kind -eq 'App') { 'App-only token (Microsoft Graph), roles claim' } else { 'Azure CLI delegated token (Microsoft Graph), scp claim' }
            $scopeLines.Add("$label, acquired $($record.AcquiredAt)")
            $names = if ($record.Kind -eq 'App') { $record.Roles } else { $record.Scopes }
            if (-not $names) { $scopeLines.Add('  (none)') } else { foreach ($n in $names) { $scopeLines.Add("  $n") } }
            $scopeLines.Add('')
        }
        if (-not ($script:TokenClaimRecords | Where-Object Kind -eq 'AzureCli')) { $scopeLines.Add("Azure CLI delegated token: $($Context.AzureCliTokenState)"); $scopeLines.Add('') }
        $scopeLines | Set-Content -Path (Join-Path $out 'token-scopes.txt') -Encoding utf8
    }

    $sorted = @($Context.Findings | Sort-Object { $script:SeverityRank[$_.severity] }, id)
    ConvertTo-Json -InputObject $sorted -Depth 10 | Set-Content -Path (Join-Path $out 'findings.json') -Encoding utf8

    $gapLines = [System.Collections.Generic.List[string]]::new()
    $gapLines.Add("# Gaps: $($Context.ClientName), $($Context.StartedUtc.ToString('yyyy-MM-dd'))")
    $gapLines.Add('')
    $gapLines.Add('Checks that failed, were forbidden, or were limited, and what would fill each one.')
    $gapLines.Add('')
    if ($Context.Gaps.Count) {
        $gapLines.Add('| Area | Check | Endpoint or cmdlet | Result | Why | What would fill it |')
        $gapLines.Add('|---|---|---|---|---|---|')
        foreach ($gap in $Context.Gaps) {
            $cells = @($gap.Area, $gap.Check, $gap.EndpointOrCmdlet, $gap.Result, $gap.Reason, $gap.FillWith) | ForEach-Object { ("$_" -replace '\|', '\|' -replace '\r?\n', ' ') }
            $gapLines.Add('| ' + ($cells -join ' | ') + ' |')
        }
    }
    else { $gapLines.Add('No gaps recorded.') }
    if (-not $Context.Tenantless) {
        $gapLines.Add('')
        $gapLines.Add('## Open questions (cannot be checked from the tenant)')
        $gapLines.Add('')
        $gapLines.Add('- Backups: is Microsoft 365 data (Exchange, OneDrive, SharePoint, Teams) backed up by a third-party or Microsoft 365 Backup service, how long is it retained, and when was a restore last tested? Maps to baseline control "Tested backups".')
    }
    $gapLines | Set-Content -Path (Join-Path $out 'gaps.md') -Encoding utf8

    $bySeverity = [ordered]@{}
    foreach ($level in 'Critical', 'High', 'Medium', 'Low') { $bySeverity[$level] = @($sorted | Where-Object severity -eq $level).Count }
    $byArea = [ordered]@{}
    foreach ($group in ($sorted | Group-Object area)) { $byArea[$group.Name] = $group.Count }
    $summary = [pscustomobject][ordered]@{
        ClientName       = $Context.ClientName
        TenantId         = $Context.TenantId
        StartedUtc       = $Context.StartedUtc.ToString('yyyy-MM-ddTHH:mm:ssZ')
        FinishedUtc      = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        OutputPath       = $out
        FindingsBySeverity = $bySeverity
        FindingsByArea   = $byArea
        Gaps             = $Context.Gaps.Count
        EndpointCalls    = $script:EndpointLog.Count
        AppOnlyForbidden = @($script:EndpointLog | Where-Object AppOnlyResult -eq 'forbidden').Count
        AreaSummaries    = $Context.AreaSummaries
    }
    ConvertTo-Json -InputObject $summary -Depth 12 | Set-Content -Path (Join-Path $out 'run-summary.json') -Encoding utf8
    $summary
}
