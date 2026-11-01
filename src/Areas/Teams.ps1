function Invoke-SecOakTeamsCheck {
    <#
    .SYNOPSIS
        Teams area: external access, consumer chat, trial tenants, meeting lobby and control,
        cloud storage providers, channel email, app permission policy, guest access
        governance, and end-user security reporting.
    .DESCRIPTION
        Implements catalogue checks M365-22 to M365-31 through the MicrosoftTeams module
        (app-only, Get-Cs* cmdlets only) plus one Graph read of the Group.Unified directory
        setting. Guest invitation restrictions are covered by the Identity area, so M365-30
        is reported as information. Org-wide app settings and the app catalogue are not
        readable app-only and are always recorded as a gap. Always disconnects the Teams
        session in a finally block.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        Area result object with Area, Summary, and Findings.
    .EXAMPLE
        Invoke-SecOakTeamsCheck -Context $context
    .NOTES
        Requires the MicrosoftTeams module. App-only: Graph application permission
        Organization.Read.All on the reader app plus the directory role Global Reader (or
        Teams Reader where available) on its service principal (certificate credential
        required). Graph application permission Directory.Read.All for the Group.Unified
        setting.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Teams'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $store = @{}

    #--- Licence gate (result state, not a failure)
    if (-not $Context.Cache.ContainsKey('ServicePlans')) {
        $skuResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check "$area/Licensing" -Path '/subscribedSkus' -NoGap
        $Context.Cache.ServicePlans = if ($skuResult.Success) { @($skuResult.Items | Where-Object capabilityStatus -eq 'Enabled' | ForEach-Object { $_.servicePlans } | ForEach-Object { "$($_.servicePlanName)" } | Select-Object -Unique) } else { $null }
    }
    $plans = $Context.Cache.ServicePlans
    $licensed = if ($null -eq $plans) { 'unknown' } elseif (@($plans | Where-Object { $_ -match '^TEAMS' }).Count) { 'yes' } else { 'no' }
    $summary.licensing = [ordered]@{ teams = $licensed; defenderForOffice = [bool]($null -ne $plans -and @($plans | Where-Object { $_ -match '^ATP_ENTERPRISE|THREAT_INTELLIGENCE' }).Count) }
    if ($licensed -eq 'no') {
        $summary.result = 'Not licensed: no Teams service plan is enabled in this tenant, so the Teams checks were not run.'
        $Context.AreaSummaries[$area] = $summary
        return [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
    }

    #--- Always a gap: org-wide app settings and the app catalogue are not readable app-only
    Add-SecOakGap -Context $Context -Area $area -Check "$area/AppSettings" -EndpointOrCmdlet 'Get-M365UnifiedTenantSettings, Get-AllM365TeamsApps, Get-M365TeamsApp' -Result 'not supported app-only' `
        -Reason 'Org-wide Teams app settings, app-centric management assignments and the app catalogue cannot be read with application authentication. Only the classic app permission policy (M365-29) is read.' `
        -FillWith 'A delegated (interactive) Teams admin session, or a screenshot of Teams admin center, Teams apps, Manage apps and Org-wide app settings.'

    #--- Collect (Teams module cmdlets one after another; session always closed)
    $mode = 'none'
    try {
        $mode = Connect-SecOakTeams -Context $Context
        if ($mode -ne 'none') {
            $r = Invoke-SecOakTeamsGet -Context $Context -Area $area -Check "$area/ExternalAccess" -Cmdlet Get-CsTenantFederationConfiguration
            if ($r.Success -and $r.Data) {
                $f = @($r.Data)[0]
                $allowedRaw = $f.AllowedDomains
                $allowedText = "$allowedRaw"
                $allowedList = @()
                if ($null -ne $allowedRaw -and $allowedRaw.PSObject.Properties['AllowedDomain']) { $allowedList = @($allowedRaw.AllowedDomain | ForEach-Object { "$($_.Domain)" }) }
                elseif ($allowedRaw -is [System.Collections.IEnumerable] -and $allowedRaw -isnot [string]) { $allowedList = @($allowedRaw | ForEach-Object { if ($_.PSObject.Properties['Domain']) { "$($_.Domain)" } else { "$_" } }) }
                $allowsAll = ($allowedText -match 'AllowAllKnownDomains') -or (-not $allowedList.Count -and $allowedText -notmatch 'Domain')
                $store.Federation = [pscustomobject][ordered]@{
                    AllowFederatedUsers          = [bool]$f.AllowFederatedUsers
                    AllowsAllDomains             = [bool]$allowsAll
                    AllowedDomainCount           = $allowedList.Count
                    BlockedDomainCount           = @($f.BlockedDomains | ForEach-Object { if ($_.PSObject.Properties['Domain']) { $_.Domain } else { $_ } }).Count
                    AllowTeamsConsumer           = [bool]$f.AllowTeamsConsumer
                    AllowTeamsConsumerInbound    = [bool]$f.AllowTeamsConsumerInbound
                    ExternalAccessWithTrialTenants = "$($f.ExternalAccessWithTrialTenants)"
                    AllowedTrialTenantDomains    = @($f.AllowedTrialTenantDomains).Count
                }
                Save-SecOakRawData -Context $Context -Name 'teams-federation-configuration' -Data $store.Federation
            }

            $r = Invoke-SecOakTeamsGet -Context $Context -Area $area -Check "$area/MeetingPolicy" -Cmdlet Get-CsTeamsMeetingPolicy
            if ($r.Success) {
                $store.MeetingPolicies = @($r.Data | ForEach-Object {
                        [pscustomobject][ordered]@{
                            Identity                                 = "$($_.Identity)"
                            AllowAnonymousUsersToJoinMeeting         = [bool]$_.AllowAnonymousUsersToJoinMeeting
                            AllowAnonymousUsersToStartMeeting        = [bool]$_.AllowAnonymousUsersToStartMeeting
                            AutoAdmittedUsers                        = "$($_.AutoAdmittedUsers)"
                            AllowPSTNUsersToBypassLobby              = [bool]$_.AllowPSTNUsersToBypassLobby
                            AllowExternalParticipantGiveRequestControl = [bool]$_.AllowExternalParticipantGiveRequestControl
                        }
                    })
                Save-SecOakRawData -Context $Context -Name 'teams-meeting-policies' -Data $store.MeetingPolicies
            }

            $r = Invoke-SecOakTeamsGet -Context $Context -Area $area -Check "$area/ClientConfiguration" -Cmdlet Get-CsTeamsClientConfiguration
            if ($r.Success -and $r.Data) {
                $c = @($r.Data)[0]
                $store.ClientConfiguration = [pscustomobject][ordered]@{
                    AllowDropBox          = [bool]$c.AllowDropBox
                    AllowBox              = [bool]$c.AllowBox
                    AllowGoogleDrive      = [bool]$c.AllowGoogleDrive
                    AllowShareFile        = [bool]$c.AllowShareFile
                    AllowEgnyte           = [bool]$c.AllowEgnyte
                    AllowEmailIntoChannel = [bool]$c.AllowEmailIntoChannel
                    AllowGuestUser        = [bool]$c.AllowGuestUser
                }
                Save-SecOakRawData -Context $Context -Name 'teams-client-configuration' -Data $store.ClientConfiguration
            }

            $r = Invoke-SecOakTeamsGet -Context $Context -Area $area -Check "$area/AppPermissionPolicy" -Cmdlet Get-CsTeamsAppPermissionPolicy
            if ($r.Success) {
                $store.AppPermissionPolicies = @($r.Data | ForEach-Object {
                        [pscustomobject][ordered]@{
                            Identity               = "$($_.Identity)"
                            GlobalCatalogAppsType  = "$($_.GlobalCatalogAppsType)"
                            GlobalCatalogAppCount  = @($_.GlobalCatalogApps).Count
                            PrivateCatalogAppsType = "$($_.PrivateCatalogAppsType)"
                            PrivateCatalogAppCount = @($_.PrivateCatalogApps).Count
                            DefaultCatalogAppsType = "$($_.DefaultCatalogAppsType)"
                            DefaultCatalogAppCount = @($_.DefaultCatalogApps).Count
                        }
                    })
                Save-SecOakRawData -Context $Context -Name 'teams-app-permission-policies' -Data $store.AppPermissionPolicies
            }

            $r = Invoke-SecOakTeamsGet -Context $Context -Area $area -Check "$area/MessagingPolicy" -Cmdlet Get-CsTeamsMessagingPolicy
            if ($r.Success) {
                $store.MessagingPolicies = @($r.Data | ForEach-Object { [pscustomobject]@{ Identity = "$($_.Identity)"; AllowSecurityEndUserReporting = [bool]$_.AllowSecurityEndUserReporting } })
                Save-SecOakRawData -Context $Context -Name 'teams-messaging-policies' -Data $store.MessagingPolicies
            }
        }
        else {
            $summary.teamsModule = 'Not connected; checks M365-22 to M365-29 and M365-31 were not run (see gaps).'
        }
    }
    finally {
        if ($mode -ne 'none') { Disconnect-SecOakTeams -Context $Context }
    }

    #--- Graph: Group.Unified directory setting (M365-30)
    $groupSettings = Invoke-SecOakGraphGet -Context $Context -Area $area -Check "$area/GuestAccess" -Path '/groupSettings' -NoGap
    if ($groupSettings.Success) {
        $unified = @($groupSettings.Items | Where-Object { $_.displayName -eq 'Group.Unified' }) | Select-Object -First 1
        $valueOf = { param($name) $v = @($unified.values | Where-Object name -eq $name) | Select-Object -First 1; if ($v) { "$($v.value)" } else { $null } }
        $store.GroupUnified = [pscustomobject][ordered]@{
            SettingsObjectExists       = [bool]$unified
            AllowToAddGuests           = $(if ($unified) { $t = & $valueOf 'AllowToAddGuests'; if ($null -eq $t) { 'default (true)' } else { $t } } else { 'default (true)' })
            AllowGuestsToAccessGroups  = $(if ($unified) { $t = & $valueOf 'AllowGuestsToAccessGroups'; if ($null -eq $t) { 'default (true)' } else { $t } } else { 'default (true)' })
        }
    }
    else {
        Add-SecOakGap -Context $Context -Area $area -Check "$area/GuestAccess" -EndpointOrCmdlet '/v1.0/groupSettings' -Result "$($groupSettings.StatusCode)" `
            -Reason $(if ($groupSettings.ErrorMessage) { $groupSettings.ErrorMessage } else { 'The directory group settings could not be read.' }) -FillWith 'Application permission Directory.Read.All.'
    }

    #--- M365-22, 23, 24 external access
    if ($store.ContainsKey('Federation')) {
        $f = $store.Federation
        $summary.externalAccess = [ordered]@{
            allowFederatedUsers            = $f.AllowFederatedUsers
            allowedDomains                 = $(if ($f.AllowsAllDomains) { 'all known domains' } else { "$($f.AllowedDomainCount) listed" })
            blockedDomains                 = $f.BlockedDomainCount
            allowTeamsConsumer             = $f.AllowTeamsConsumer
            allowTeamsConsumerInbound      = $f.AllowTeamsConsumerInbound
            externalAccessWithTrialTenants = $f.ExternalAccessWithTrialTenants
        }
        if ($f.AllowFederatedUsers -and $f.AllowsAllDomains) {
            $findings.Add((New-SecOakFinding -Id 'M365-22' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Teams external access is open to every organization' `
                        -Evidence ([ordered]@{ allowFederatedUsers = $true; allowedDomains = 'all known domains'; blockedDomains = $f.BlockedDomainCount }) `
                        -Risk 'Anyone with a Teams account at any company can message and call your staff directly. Attackers use this to send links and fake IT support chats that land inside Teams, where people trust them more than email.' `
                        -Recommendation 'In the Teams admin center (Users, External access) allow only the specific partner domains the business works with, or block all and add domains on request.'))
        }
        if ($f.AllowTeamsConsumer) {
            $findings.Add((New-SecOakFinding -Id 'M365-23' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Staff can chat with personal (consumer) Teams accounts' `
                        -Evidence ([ordered]@{ allowTeamsConsumer = $true; allowTeamsConsumerInbound = $f.AllowTeamsConsumerInbound }) `
                        -Risk 'Personal Teams accounts are free and anonymous. Allowing chat with them gives phishing and social engineering a direct line to staff inside a trusted app.' `
                        -Recommendation 'Turn off "People in my organization can communicate with Teams users whose accounts aren''t managed by an organization" in the Teams admin center, External access.'))
        }
        elseif ($f.AllowTeamsConsumerInbound) {
            $findings.Add((New-SecOakFinding -Id 'M365-23' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Personal (consumer) Teams accounts can start chats with staff' `
                        -Evidence ([ordered]@{ allowTeamsConsumer = $false; allowTeamsConsumerInbound = $true }) `
                        -Risk 'Unmanaged personal accounts can open a conversation with anyone in the company, which is the usual first step of a Teams phishing attempt.' `
                        -Recommendation 'Turn off inbound communication from unmanaged Teams accounts in the Teams admin center, External access.'))
        }
        if ($f.ExternalAccessWithTrialTenants -eq 'Allowed') {
            $findings.Add((New-SecOakFinding -Id 'M365-24' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Teams accepts communication from trial-only tenants' `
                        -Evidence ([ordered]@{ externalAccessWithTrialTenants = 'Allowed'; allowedTrialTenantDomains = $f.AllowedTrialTenantDomains }) `
                        -Risk 'Trial tenants are free to create and are routinely used for phishing campaigns because they look like a real company.' `
                        -Recommendation 'Set external access with trial-only tenants to Blocked (Set-CsTenantFederationConfiguration -ExternalAccessWithTrialTenants Blocked), listing any genuine trial partner explicitly.'))
        }
    }

    #--- M365-25, 26 meeting policy (Global evaluated; custom policies reported for information)
    if ($store.ContainsKey('MeetingPolicies')) {
        $policies = @($store.MeetingPolicies)
        $global = @($policies | Where-Object { $_.Identity -in 'Global', 'Tag:Global' }) | Select-Object -First 1
        $custom = @($policies | Where-Object { $_.Identity -notin 'Global', 'Tag:Global' })
        $summary.meetings = [ordered]@{
            policies                           = $policies.Count
            customPoliciesAllowingAnonymousJoin = @($custom | Where-Object { $_.AllowAnonymousUsersToJoinMeeting -or $_.AllowAnonymousUsersToStartMeeting }).Count
            note                               = 'Custom policy assignments to users are not read; the Global policy applies to everyone without an assignment.'
        }
        if ($global) {
            $summary.meetings.global = [ordered]@{
                allowAnonymousUsersToJoinMeeting  = $global.AllowAnonymousUsersToJoinMeeting
                allowAnonymousUsersToStartMeeting = $global.AllowAnonymousUsersToStartMeeting
                autoAdmittedUsers                 = $global.AutoAdmittedUsers
                allowPSTNUsersToBypassLobby       = $global.AllowPSTNUsersToBypassLobby
                allowExternalParticipantGiveRequestControl = $global.AllowExternalParticipantGiveRequestControl
            }
            if ($global.AllowAnonymousUsersToJoinMeeting -or $global.AllowAnonymousUsersToStartMeeting) {
                $findings.Add((New-SecOakFinding -Id 'M365-25' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Anonymous users can join or start Teams meetings' `
                            -Evidence ([ordered]@{ allowAnonymousUsersToJoinMeeting = $global.AllowAnonymousUsersToJoinMeeting; allowAnonymousUsersToStartMeeting = $global.AllowAnonymousUsersToStartMeeting; policy = 'Global' }) `
                            -Risk 'Anyone with a meeting link can join without an account, and can even start the meeting before the organizer is present. Leaked links then give strangers a seat in internal meetings.' `
                            -Recommendation 'On the Global meeting policy, turn off anonymous users can join a meeting and anonymous users can start a meeting. Where customers must join without an account, keep them in the lobby.'))
            }
            if ($global.AutoAdmittedUsers -eq 'Everyone') {
                $findings.Add((New-SecOakFinding -Id 'M365-25' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Everyone bypasses the meeting lobby' `
                            -Evidence ([ordered]@{ autoAdmittedUsers = 'Everyone'; policy = 'Global' }) `
                            -Risk 'External and anonymous attendees enter meetings straight away, without the organizer admitting them, so an uninvited participant can listen in unnoticed.' `
                            -Recommendation 'Set "Who can bypass the lobby" to people in my organization (or people in my organization and guests) on the Global meeting policy.'))
            }
            if ($global.AllowPSTNUsersToBypassLobby) {
                $findings.Add((New-SecOakFinding -Id 'M365-25' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Dial-in callers bypass the meeting lobby' `
                            -Evidence ([ordered]@{ allowPSTNUsersToBypassLobby = $true; policy = 'Global' }) `
                            -Risk 'Anyone with the conference number and ID joins directly by phone, with no name shown, so an outsider can sit in a meeting unnoticed.' `
                            -Recommendation 'Turn off "Dial-in users can bypass the lobby" on the Global meeting policy.'))
            }
            if ($global.AllowExternalParticipantGiveRequestControl) {
                $findings.Add((New-SecOakFinding -Id 'M365-26' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'External participants can take control of shared screens' `
                            -Evidence ([ordered]@{ allowExternalParticipantGiveRequestControl = $true; policy = 'Global' }) `
                            -Risk 'A guest or anonymous attendee can request, and be given, control of a presenter''s screen, which allows actions on the presenter''s computer during a meeting.' `
                            -Recommendation 'Turn off "External participants can give or request control" on the Global meeting policy.'))
            }
        }
    }

    #--- M365-27, 28 client configuration; M365-30 information
    if ($store.ContainsKey('ClientConfiguration')) {
        $c = $store.ClientConfiguration
        $allowedProviders = @(@('DropBox', 'Box', 'GoogleDrive', 'ShareFile', 'Egnyte') | Where-Object { $c."Allow$_" })
        $summary.clientConfiguration = [ordered]@{ thirdPartyStorageAllowed = $allowedProviders; allowEmailIntoChannel = $c.AllowEmailIntoChannel; allowGuestUser = $c.AllowGuestUser }
        if ($allowedProviders.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-27' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Teams allows third-party cloud storage providers' `
                        -Evidence ([ordered]@{ providers = $allowedProviders }) `
                        -Risk 'Staff can attach and store company files through personal Dropbox, Box, Google Drive, ShareFile or Egnyte accounts from inside Teams, outside company backup and control.' `
                        -Recommendation 'Turn off each storage provider the business has not approved (Teams admin center, Teams settings, Files), keeping only OneDrive and SharePoint.'))
        }
        if ($c.AllowEmailIntoChannel) {
            $findings.Add((New-SecOakFinding -Id 'M365-28' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Email can be sent into Teams channels' `
                        -Evidence ([ordered]@{ allowEmailIntoChannel = $true }) `
                        -Risk 'Every channel can get an email address. Messages sent to it bypass the mailbox protections and land in the channel, attachments included, where anyone in the team opens them.' `
                        -Recommendation 'Turn off "Users can send emails to a channel email address" unless a team relies on it; if it is needed, restrict the accepted sender domains.'))
        }
    }
    if ($store.ContainsKey('GroupUnified') -or $store.ContainsKey('ClientConfiguration')) {
        $summary.guestAccess = [ordered]@{
            groupUnifiedSettingsObject = $(if ($store.ContainsKey('GroupUnified')) { $store.GroupUnified.SettingsObjectExists } else { 'unknown' })
            allowToAddGuests           = $(if ($store.ContainsKey('GroupUnified')) { $store.GroupUnified.AllowToAddGuests } else { 'unknown' })
            allowGuestsToAccessGroups  = $(if ($store.ContainsKey('GroupUnified')) { $store.GroupUnified.AllowGuestsToAccessGroups } else { 'unknown' })
            teamsAllowGuestUser        = $(if ($store.ContainsKey('ClientConfiguration')) { $store.ClientConfiguration.AllowGuestUser } else { 'unknown' })
            note                       = 'Information only (M365-30): guest invitation restrictions and stale guests are reported by the Identity area (IDENTITY-12 to IDENTITY-14).'
        }
    }

    #--- M365-29 app permission policy
    if ($store.ContainsKey('AppPermissionPolicies')) {
        $policies = @($store.AppPermissionPolicies)
        $global = @($policies | Where-Object { $_.Identity -in 'Global', 'Tag:Global' }) | Select-Object -First 1
        $summary.appPermissionPolicy = [ordered]@{
            policies = $policies.Count
            note     = 'Classic app permission policy only. If the tenant uses app-centric management this policy is no longer applied; the org-wide app settings are a recorded gap.'
        }
        if ($global) {
            $summary.appPermissionPolicy.global = [ordered]@{ globalCatalogAppsType = $global.GlobalCatalogAppsType; globalCatalogApps = $global.GlobalCatalogAppCount; privateCatalogAppsType = $global.PrivateCatalogAppsType; defaultCatalogAppsType = $global.DefaultCatalogAppsType }
            if ($global.GlobalCatalogAppsType -eq 'BlockedAppList' -and $global.GlobalCatalogAppCount -eq 0) {
                $findings.Add((New-SecOakFinding -Id 'M365-29' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'All third-party Teams apps are allowed' `
                            -Evidence ([ordered]@{ globalCatalogAppsType = 'BlockedAppList'; blockedApps = 0; policy = 'Global' }) `
                            -Risk 'Any user can add any app from the public Teams store. Some apps request access to chats, files and calendars, and the company has no list of what has been added.' `
                            -Recommendation 'Change the Global app permission policy (or the app-centric management settings) to allow specific third-party apps only, with an approval step for new requests.'))
            }
        }
    }

    #--- M365-31 end-user security reporting
    if ($store.ContainsKey('MessagingPolicies')) {
        $policies = @($store.MessagingPolicies)
        $global = @($policies | Where-Object { $_.Identity -in 'Global', 'Tag:Global' }) | Select-Object -First 1
        $summary.messaging = [ordered]@{ policies = $policies.Count; globalAllowSecurityEndUserReporting = $(if ($global) { $global.AllowSecurityEndUserReporting } else { 'unknown' }); defenderForOffice = $summary.licensing.defenderForOffice }
        if ($global -and -not $global.AllowSecurityEndUserReporting) {
            $findings.Add((New-SecOakFinding -Id 'M365-31' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Users cannot report suspicious Teams messages' `
                        -Evidence ([ordered]@{ allowSecurityEndUserReporting = $false; policy = 'Global'; defenderForOffice = $summary.licensing.defenderForOffice }) `
                        -Risk 'Staff have no report button for a phishing message received in Teams, so attacks that arrive by chat go unreported and unlearned from.' `
                        -Recommendation 'Turn on "Report a security concern" in the Global messaging policy. With Defender for Office 365 the reports also reach Microsoft; without it they go to the reporting mailbox configured in the Defender portal.'))
        }
    }

    $summary.coveredElsewhere = 'Guest invitation restrictions, guest role and stale guests: Identity area (IDENTITY-12 to IDENTITY-14).'
    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
