function New-SecOakFinding {
    <#
    .SYNOPSIS
        Builds a finding object with the fields the client report needs.
    .PARAMETER Id
        Stable identifier such as IDENTITY-03.
    .PARAMETER Area
        Area name (Identity, Email, Domain, Devices, Sharing, Licensing, Posture, Access,
        plus planned Defender, Intune, Azure, Purview, Teams, ServiceHealth, Backup).
    .PARAMETER Title
        One-line title.
    .PARAMETER Severity
        Critical, High, Medium, or Low.
    .PARAMETER Evidence
        Counts and brief examples (an ordered dictionary).
    .PARAMETER Risk
        Plain-language risk statement.
    .PARAMETER Recommendation
        Recommended fix.
    .PARAMETER BaselineControl
        The baseline control this maps to, or None.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidatePattern('^[A-Z][A-Z0-9]*-\d{2}$')][string]$Id,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Area,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low')][string]$Severity,
        [Parameter(Mandatory)][System.Collections.IDictionary]$Evidence,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Risk,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Recommendation,
        [Parameter(Mandatory)][ValidateScript({ $_ -in $script:BaselineControls })][string]$BaselineControl
    )
    [pscustomobject][ordered]@{
        id              = $Id
        area            = $Area
        title           = $Title
        severity        = $Severity
        evidence        = $Evidence
        risk            = $Risk
        recommendedFix  = $Recommendation
        baselineControl = $BaselineControl
    }
}

function Add-SecOakGap {
    <#
    .SYNOPSIS
        Records a check that could not be completed and what would fill it.
    .PARAMETER Context
        The run context.
    .PARAMETER Area
        Area name.
    .PARAMETER Check
        Check name.
    .PARAMETER EndpointOrCmdlet
        The Graph path, cmdlet, or description of what could not be read.
    .PARAMETER Result
        Short result such as 403, not licensed, or not checkable.
    .PARAMETER Reason
        Why it failed.
    .PARAMETER FillWith
        The permission, license, or access that would fill the gap.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$EndpointOrCmdlet,
        [Parameter(Mandatory)][string]$Result,
        [Parameter(Mandatory)][string]$Reason,
        [Parameter(Mandatory)][string]$FillWith
    )
    $Context.Gaps.Add([pscustomobject][ordered]@{
            Area             = $Area
            Check            = $Check
            EndpointOrCmdlet = $EndpointOrCmdlet
            Result           = $Result
            Reason           = $Reason
            FillWith         = $FillWith
        })
}
