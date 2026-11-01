function Invoke-SecOakSharingCheck {
    <#
    .SYNOPSIS
        Sharing area: SharePoint and OneDrive tenant sharing settings.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakSharingCheck -Context $context
    .NOTES
        Application permission: SharePointTenantSettings.Read.All.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Sharing'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $result = Invoke-SecOakGraphGet -Context $Context -Area $area -Check 'Sharing/TenantSettings' -Path '/admin/sharepoint/settings' -RawName 'sharing-sharepoint-settings'
    if ($result.Success) {
        $s = $result.Body
        $summary.sharePoint = [ordered]@{
            sharingCapability                   = $s.sharingCapability
            sharingDomainRestrictionMode        = $s.sharingDomainRestrictionMode
            isResharingByExternalUsersEnabled   = $s.isResharingByExternalUsersEnabled
            isLegacyAuthProtocolsEnabled        = $s.isLegacyAuthProtocolsEnabled
            isUnmanagedSyncAppForTenantRestricted = $s.isUnmanagedSyncAppForTenantRestricted
            idleSessionSignOutEnabled           = $s.idleSessionSignOut.isEnabled
            isRequireAcceptingUserToMatchInvitedUserEnabled = $s.isRequireAcceptingUserToMatchInvitedUserEnabled
            note                                = 'OneDrive can be set more restrictive than this tenant level; Graph does not expose the separate OneDrive setting.'
        }
        if ($s.sharingCapability -eq 'externalUserAndGuestSharing') {
            $findings.Add((New-SecOakFinding -Id 'SHARING-01' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Anyone (anonymous) links are allowed' `
                        -Evidence ([ordered]@{ sharingCapability = $s.sharingCapability; domainRestriction = $s.sharingDomainRestrictionMode }) `
                        -Risk 'Files can be shared with links that work for anyone who has them, with no sign-in. Forwarded or leaked links expose the data.' `
                        -Recommendation 'Limit sharing to "New and existing guests", or if Anyone links are needed, set expiry and view-only defaults.'))
        }
        if ($s.isLegacyAuthProtocolsEnabled) {
            $findings.Add((New-SecOakFinding -Id 'SHARING-02' -Area $area -Severity Medium -BaselineControl 'Legacy authentication blocked' `
                        -Title 'SharePoint accepts legacy authentication protocols' `
                        -Evidence ([ordered]@{ isLegacyAuthProtocolsEnabled = $true }) `
                        -Risk 'Apps that do not support modern authentication can reach SharePoint with only a password, bypassing multifactor.' `
                        -Recommendation 'Turn off "Apps that don''t use modern authentication" in the SharePoint admin center.'))
        }
        if ($s.isResharingByExternalUsersEnabled) {
            $findings.Add((New-SecOakFinding -Id 'SHARING-03' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Guests can reshare items they do not own' `
                        -Evidence ([ordered]@{ isResharingByExternalUsersEnabled = $true }) `
                        -Risk 'Content can spread to people the owner never approved.' `
                        -Recommendation 'Turn off "Allow guests to share items they don''t own".'))
        }
        if ($s.sharingCapability -ne 'disabled' -and -not $s.isRequireAcceptingUserToMatchInvitedUserEnabled) {
            $findings.Add((New-SecOakFinding -Id 'SHARING-04' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Sharing invitations can be accepted by a different account' `
                        -Evidence ([ordered]@{ isRequireAcceptingUserToMatchInvitedUserEnabled = $false }) `
                        -Risk 'A forwarded invitation can be redeemed by someone other than the intended guest.' `
                        -Recommendation 'Require guests to sign in with the same account the invitation was sent to.'))
        }
    }

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
