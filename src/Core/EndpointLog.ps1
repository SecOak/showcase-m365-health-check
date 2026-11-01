function Get-SecOakPermissionHint {
    <#
    .SYNOPSIS
        Returns the least-privilege permission hint for a Graph path or Exchange cmdlet.
    .PARAMETER Tool
        Graph, Exchange, DNS, HTTPS (public sources), DefenderEndpoint, AzureResourceManager,
        Compliance (Security and Compliance PowerShell), or Teams (MicrosoftTeams module).
    .PARAMETER EndpointOrCmdlet
        The Graph path (without version prefix), API path, or cmdlet name.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateSet('Graph', 'Exchange', 'DNS', 'HTTPS', 'DefenderEndpoint', 'AzureResourceManager', 'Compliance', 'Teams')][string]$Tool,
        [Parameter(Mandatory)][string]$EndpointOrCmdlet
    )
    switch ($Tool) {
        { $_ -in 'DNS', 'HTTPS' } { return [pscustomobject]@{ Permission = 'None (public OSINT)'; Note = '' } }
        'Exchange' {
            $hint = $script:ExchangePermissionHints[$EndpointOrCmdlet]
            if (-not $hint) { $hint = 'Exchange.ManageAsApp + Global Reader (unverified for this cmdlet)' }
            return [pscustomobject]@{ Permission = $hint; Note = '' }
        }
        { $_ -in 'DefenderEndpoint', 'AzureResourceManager' } { return Get-SecOakApiPermissionHint -Api $Tool -Path $EndpointOrCmdlet }
        'Compliance' { return [pscustomobject]@{ Permission = $script:CompliancePermissionHintDefault; Note = '' } }
        'Teams' { return [pscustomobject]@{ Permission = $script:TeamsPermissionHintDefault; Note = '' } }
        'Graph' {
            foreach ($entry in $script:GraphPermissionHints) {
                if ($EndpointOrCmdlet -match $entry.Pattern) {
                    $permission = $entry.Permission
                    if ($entry.Confidence -ne 'documented') { $permission += ' (unsure: ' + $entry.Confidence + ')' }
                    return [pscustomobject]@{ Permission = $permission; Note = [string]$entry.Note }
                }
            }
            return [pscustomobject]@{ Permission = 'Unknown (not mapped; check Microsoft Learn)'; Note = '' }
        }
    }
}

function Add-SecOakEndpointLogEntry {
    <#
    .SYNOPSIS
        Appends one row to the in-memory endpoint log.
    .NOTES
        Internal helper. No permissions required. Never pass tokens or secrets in Notes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidateSet('Graph', 'Exchange', 'DNS', 'HTTPS', 'DefenderEndpoint', 'AzureResourceManager', 'Compliance', 'Teams')][string]$Tool,
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$EndpointOrCmdlet,
        [Parameter(Mandatory)][string]$HttpStatusOrResult,
        [Parameter(Mandatory)][ValidateSet('app-only', 'azcli-delegated', 'exo-app', 'exo-interactive', 'scc-app', 'teams-app', 'none')][string]$AuthUsed,
        [Parameter(Mandatory)][ValidateSet('success', 'forbidden', 'error', 'not attempted')][string]$AppOnlyResult,
        [Parameter()][string]$Notes = ''
    )
    $hintKey = if ($Tool -eq 'Graph') { $EndpointOrCmdlet -replace '^/(v1\.0|beta)', '' } else { $EndpointOrCmdlet }
    $hint = Get-SecOakPermissionHint -Tool $Tool -EndpointOrCmdlet $hintKey
    $allNotes = (@($Notes, $hint.Note) | Where-Object { $_ }) -join ' '
    $script:EndpointLog.Add([pscustomobject][ordered]@{
            Timestamp                   = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            Check                       = $Check
            Tool                        = $Tool
            Method                      = $Method
            EndpointOrCmdlet            = $EndpointOrCmdlet
            HttpStatusOrResult          = $HttpStatusOrResult
            AuthUsed                    = $AuthUsed
            AppOnlyResult               = $AppOnlyResult
            LeastPrivilegeAppPermission = $hint.Permission
            Notes                       = $allNotes
        })
}

function Get-SecOakEndpointLog {
    <#
    .SYNOPSIS
        Returns the endpoint log rows recorded so far in this session.
    .EXAMPLE
        Get-SecOakEndpointLog | Where-Object AppOnlyResult -eq 'forbidden'
    .NOTES
        No permissions required.
    #>
    [CmdletBinding()]
    param()
    $script:EndpointLog.ToArray()
}
