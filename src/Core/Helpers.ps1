function ConvertTo-SecOakBase64Url {
    <#
    .SYNOPSIS
        Encodes bytes or a string as base64url without padding.
    .PARAMETER Bytes
        Raw bytes to encode.
    .PARAMETER Text
        A string to encode as UTF-8 first.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Bytes')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Bytes')][byte[]]$Bytes,
        [Parameter(Mandatory, ParameterSetName = 'Text')][string]$Text
    )
    if ($PSCmdlet.ParameterSetName -eq 'Text') { $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Text) }
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-SecOakJwtPayload {
    <#
    .SYNOPSIS
        Decodes the claims of a JSON Web Token without validating it.
    .DESCRIPTION
        Used only to read tid, roles, scp, and exp so the run can verify the tenant and
        record permission names. The token itself is never returned.
    .PARAMETER Token
        The access token to decode.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Token)

    $segment = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    switch ($segment.Length % 4) { 2 { $segment += '==' } 3 { $segment += '=' } }
    [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($segment)) | ConvertFrom-Json
}

function ConvertTo-SecOakUtcDate {
    <#
    .SYNOPSIS
        Converts a Graph or Exchange date value to a UTC DateTime, or $null.
    .PARAMETER Value
        A DateTime, an ISO 8601 string, or $null.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    param([Parameter()][AllowNull()][object]$Value)

    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $parsed = [datetime]::MinValue
    if ([datetime]::TryParse("$Value", [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$parsed)) {
        if ($parsed.Year -le 1601) { return $null }
        return $parsed
    }
    return $null
}

function Get-SecOakLastSignIn {
    <#
    .SYNOPSIS
        Returns the most recent sign-in time (interactive, non-interactive, or successful) for a user.
    .PARAMETER User
        A user object from Graph that may carry signInActivity.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$User)

    $activity = $User.signInActivity
    if ($null -eq $activity) { return $null }
    $dates = @(
        ConvertTo-SecOakUtcDate $activity.lastSignInDateTime
        ConvertTo-SecOakUtcDate $activity.lastNonInteractiveSignInDateTime
        ConvertTo-SecOakUtcDate $activity.lastSuccessfulSignInDateTime
    ) | Where-Object { $null -ne $_ }
    if (-not $dates) { return $null }
    ($dates | Sort-Object -Descending | Select-Object -First 1)
}

function Select-SecOakExample {
    <#
    .SYNOPSIS
        Returns up to a few short example values for finding evidence.
    .PARAMETER InputObject
        The values to sample.
    .PARAMETER Count
        Maximum number of examples. Defaults to 5.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    param(
        [Parameter()][AllowNull()][AllowEmptyCollection()][object[]]$InputObject,
        [Parameter()][ValidateRange(1, 20)][int]$Count = 5
    )
    if (-not $InputObject) { return , @() }
    , @($InputObject | Where-Object { $null -ne $_ } | Select-Object -First $Count)
}
