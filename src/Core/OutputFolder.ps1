function Initialize-SecOakOutputFolder {
    <#
    .SYNOPSIS
        Creates the output and raw folders for a run. Call only after the tenant is confirmed.
    .PARAMETER Context
        The run context.
    .NOTES
        No permissions required.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    try {
        $raw = Join-Path $Context.OutputPath 'raw'
        $null = New-Item -ItemType Directory -Path $raw -Force -ErrorAction Stop
        $Context.RawPath = $raw
    }
    catch {
        throw "Could not create output folder '$($Context.OutputPath)': $($_.Exception.Message)"
    }
}

function Save-SecOakRawData {
    <#
    .SYNOPSIS
        Writes a raw JSON export for a check into the run's raw folder.
    .PARAMETER Context
        The run context.
    .PARAMETER Name
        File name without extension, for example identity-users.
    .PARAMETER Data
        The data to serialize.
    .NOTES
        No permissions required. Output stays under the client-data folder.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidatePattern('^[a-z0-9\-]+$')][string]$Name,
        [Parameter(Mandatory)][AllowNull()][object]$Data
    )
    if (-not $Context.RawPath) { return }
    $path = Join-Path $Context.RawPath "$Name.json"
    try {
        ConvertTo-Json -InputObject $Data -Depth 30 | Set-Content -Path $path -Encoding utf8 -ErrorAction Stop
    }
    catch {
        Write-Warning "Could not write raw export ${Name}: $($_.Exception.Message)"
    }
}
