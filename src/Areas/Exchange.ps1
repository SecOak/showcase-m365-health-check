function Read-SecOakExchangeStep {
    <#
    .SYNOPSIS
        Runs one Exchange Online Get-* cmdlet for the Exchange area and records a gap when it fails.
    .NOTES
        Internal helper. Requires an Exchange Online session opened by Connect-SecOakExchange.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Cmdlet,
        [Parameter()][hashtable]$Parameters = @{}
    )
    $r = Invoke-SecOakExchangeGet -Context $Context -Check $Check -Cmdlet $Cmdlet -Parameters $Parameters
    if (-not $r.Success) {
        Add-SecOakGap -Context $Context -Area $Area -Check $Check -EndpointOrCmdlet $Cmdlet -Result $(if ($r.Forbidden) { 'forbidden' } else { 'error' }) `
            -Reason $(if ($r.ErrorMessage) { $r.ErrorMessage } else { 'The cmdlet failed or was not available to this session.' }) `
            -FillWith 'Exchange.ManageAsApp on the reader app plus the Microsoft Entra role Global Reader on its service principal (certificate credential required).'
    }
    $r
}

function Resolve-SecOakExchangePrincipal {
    <#
    .SYNOPSIS
        Looks up a mailbox permission trustee or role group member in the cached user inventory.
    .DESCRIPTION
        Returns the Graph user when the value is an object ID, a user principal name, or a
        primary SMTP address of a known user; otherwise $null.
    .NOTES
        Internal helper. No permissions required (uses the cache filled by Get-SecOakUserInventory).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter()][AllowNull()][AllowEmptyString()][string]$Value
    )
    if (-not $Value -or -not $Context.Cache.ContainsKey('Users')) { return $null }
    $key = $Value.Trim().ToLowerInvariant()
    if ($Context.Cache.UsersById.ContainsKey($key)) { return $Context.Cache.UsersById[$key] }
    if (-not $Context.Cache.ContainsKey('UsersByAddress')) {
        $map = @{}
        foreach ($user in @($Context.Cache.Users)) {
            foreach ($address in @($user.userPrincipalName, $user.mail)) {
                if ($address) { $map["$address".ToLowerInvariant()] = $user }
            }
        }
        $Context.Cache.UsersByAddress = $map
    }
    if ($Context.Cache.UsersByAddress.ContainsKey($key)) { return $Context.Cache.UsersByAddress[$key] }
    $null
}

function Invoke-SecOakExchangeCheck {
    <#
    .SYNOPSIS
        Exchange area: mailbox auditing depth, audit bypass, shared mailbox sign-in, legacy
        protocols, authentication policies, external sender tagging, connectors, mailbox
        delegations, Outlook on the web storage providers, calendar sharing, Exchange role
        groups, and litigation hold state.
    .DESCRIPTION
        Implements catalogue checks M365-01 to M365-13. Forwarding, inbox rules, transport
        rules, auto-forward controls, audit log ingestion, organization-wide mailbox auditing
        and DKIM are checked by the Email area and are not repeated here. Opens its own
        Exchange Online session (app-only first, interactive only when the run allows it)
        and always disconnects in a finally block. Get-* cmdlets only.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        Area result object with Area, Summary, and Findings.
    .EXAMPLE
        Invoke-SecOakExchangeCheck -Context $context
    .NOTES
        Requires ExchangeOnlineManagement 3.x. App-only: Exchange.ManageAsApp (Office 365
        Exchange Online) plus the Global Reader role on the reader app's service principal.
        Graph application permission Directory.Read.All for the user inventory used to
        resolve shared mailbox accounts, delegates and role group members.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Exchange'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $store = @{}
    $fill = 'Exchange.ManageAsApp on the reader app plus the Microsoft Entra role Global Reader on its service principal (certificate credential required).'
    $permissionMailboxCap = 250

    #--- Licence gate (result state, not a failure)
    if (-not $Context.Cache.ContainsKey('ServicePlans')) {
        $skuResult = Invoke-SecOakGraphGet -Context $Context -Area $area -Check "$area/Licensing" -Path '/subscribedSkus' -NoGap
        $Context.Cache.ServicePlans = if ($skuResult.Success) { @($skuResult.Items | Where-Object capabilityStatus -eq 'Enabled' | ForEach-Object { $_.servicePlans } | ForEach-Object { "$($_.servicePlanName)" } | Select-Object -Unique) } else { $null }
    }
    $plans = $Context.Cache.ServicePlans
    $exchangeLicensed = if ($null -eq $plans) { 'unknown' } elseif (@($plans | Where-Object { $_ -match '^EXCHANGE_S_(STANDARD|ENTERPRISE|DESKLESS|ESSENTIALS|ARCHIVE)' }).Count) { 'yes' } else { 'no' }
    $premiumAudit = $null -ne $plans -and ($plans -contains 'M365_ADVANCED_AUDITING')
    $summary.licensing = [ordered]@{ exchangeOnline = $exchangeLicensed; auditPremium = $premiumAudit }
    if ($exchangeLicensed -eq 'no') {
        $summary.result = 'Not licensed: no Exchange Online service plan is enabled in this tenant, so the Exchange checks were not run.'
        $Context.AreaSummaries[$area] = $summary
        return [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
    }

    #--- Collect (own session, always disconnected)
    $connected = $false
    try {
        if ($Context.CredentialType -eq 'Certificate') {
            try { $null = Connect-SecOakExchange -Context $Context -Mode App; $connected = $true }
            catch { Write-Warning $_.Exception.Message }
        }
        if (-not $connected -and $Context.ExchangeInteractiveFallback) {
            try { $null = Connect-SecOakExchange -Context $Context -Mode Interactive; $connected = $true }
            catch { Write-Warning $_.Exception.Message }
        }
        if (-not $connected) {
            Add-SecOakGap -Context $Context -Area $area -Check "$area/Connect" -EndpointOrCmdlet 'Connect-ExchangeOnline' -Result 'not connected' `
                -Reason 'No Exchange Online session could be opened, so checks M365-01 to M365-13 were not run.' -FillWith $fill
        }
        else {
            Write-Verbose 'Exchange: mailboxes (audit and hold properties)'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/MailboxAudit" -Cmdlet Get-EXOMailbox -Parameters @{
                ResultSize = 'Unlimited'; RecipientTypeDetails = 'UserMailbox', 'SharedMailbox'
                Properties = 'AuditEnabled', 'AuditLogAgeLimit', 'AuditOwner', 'AuditDelegate', 'AuditAdmin', 'DefaultAuditSet',
                'LitigationHoldEnabled', 'LitigationHoldDuration', 'ArchiveStatus', 'RetentionHoldEnabled', 'InPlaceHolds',
                'ExternalDirectoryObjectId', 'RecipientTypeDetails', 'PrimarySmtpAddress', 'DisplayName'
            }
            if ($r.Success) {
                $store.Mailboxes = @($r.Data | ForEach-Object {
                        [pscustomobject][ordered]@{
                            DisplayName               = "$($_.DisplayName)"
                            PrimarySmtpAddress        = "$($_.PrimarySmtpAddress)"
                            RecipientTypeDetails      = "$($_.RecipientTypeDetails)"
                            ExternalDirectoryObjectId = "$($_.ExternalDirectoryObjectId)"
                            AuditEnabled              = [bool]$_.AuditEnabled
                            AuditLogAgeLimit          = "$($_.AuditLogAgeLimit)"
                            DefaultAuditSet           = @($_.DefaultAuditSet | ForEach-Object { "$_" })
                            AuditOwner                = @($_.AuditOwner | ForEach-Object { "$_" })
                            AuditDelegate             = @($_.AuditDelegate | ForEach-Object { "$_" })
                            AuditAdmin                = @($_.AuditAdmin | ForEach-Object { "$_" })
                            LitigationHoldEnabled     = [bool]$_.LitigationHoldEnabled
                            LitigationHoldDuration    = "$($_.LitigationHoldDuration)"
                            ArchiveStatus             = "$($_.ArchiveStatus)"
                            RetentionHoldEnabled      = [bool]$_.RetentionHoldEnabled
                            InPlaceHoldCount          = @($_.InPlaceHolds).Count
                        }
                    })
                Save-SecOakRawData -Context $Context -Name 'exchange-mailboxes-audit-hold' -Data $store.Mailboxes
            }

            Write-Verbose 'Exchange: audit bypass associations'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/AuditBypass" -Cmdlet Get-MailboxAuditBypassAssociation -Parameters @{ ResultSize = 'Unlimited' }
            if ($r.Success) {
                $store.AuditBypass = @($r.Data | Where-Object { $_.AuditBypassEnabled -eq $true } | ForEach-Object { "$($_.Name)" })
                $store.AuditBypassTotal = @($r.Data).Count
                Save-SecOakRawData -Context $Context -Name 'exchange-audit-bypass' -Data $store.AuditBypass
            }

            Write-Verbose 'Exchange: transport configuration'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/SmtpAuth" -Cmdlet Get-TransportConfig
            if ($r.Success -and $r.Data) { $store.TransportConfig = [pscustomobject]@{ SmtpClientAuthenticationDisabled = $r.Data[0].SmtpClientAuthenticationDisabled } }

            Write-Verbose 'Exchange: client access settings per mailbox'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/ClientProtocols" -Cmdlet Get-EXOCasMailbox -Parameters @{
                ResultSize = 'Unlimited'
                Properties = 'SmtpClientAuthenticationDisabled', 'PopEnabled', 'ImapEnabled', 'ActiveSyncEnabled', 'EwsEnabled', 'OwaMailboxPolicy', 'PrimarySmtpAddress'
            }
            if ($r.Success) {
                $store.CasMailboxes = @($r.Data | ForEach-Object {
                        [pscustomobject][ordered]@{
                            PrimarySmtpAddress               = "$($_.PrimarySmtpAddress)"
                            SmtpClientAuthenticationDisabled = $_.SmtpClientAuthenticationDisabled
                            PopEnabled                       = [bool]$_.PopEnabled
                            ImapEnabled                      = [bool]$_.ImapEnabled
                            ActiveSyncEnabled                = [bool]$_.ActiveSyncEnabled
                            EwsEnabled                       = $_.EwsEnabled
                            OwaMailboxPolicy                 = "$($_.OwaMailboxPolicy)"
                        }
                    })
                Save-SecOakRawData -Context $Context -Name 'exchange-cas-mailboxes' -Data $store.CasMailboxes
            }

            Write-Verbose 'Exchange: authentication policies'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/AuthenticationPolicy" -Cmdlet Get-AuthenticationPolicy
            if ($r.Success) {
                $store.AuthenticationPolicies = @($r.Data | Select-Object Name, AllowBasicAuthSmtp, AllowBasicAuthPop, AllowBasicAuthImap, AllowBasicAuthActiveSync, AllowBasicAuthWebServices, AllowBasicAuthOutlookService, AllowBasicAuthReportingWebServices, AllowBasicAuthAutodiscover, AllowBasicAuthMapi, AllowBasicAuthOfflineAddressBook, AllowBasicAuthRpc, AllowBasicAuthPowershell)
                Save-SecOakRawData -Context $Context -Name 'exchange-authentication-policies' -Data $store.AuthenticationPolicies
            }
            # The Email area caches only two fields of the organization configuration and closes its
            # session, so the default authentication policy is read here with one extra call.
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/AuthenticationPolicy" -Cmdlet Get-OrganizationConfig
            if ($r.Success -and $r.Data) { $store.DefaultAuthenticationPolicy = "$($r.Data[0].DefaultAuthenticationPolicy)" }

            Write-Verbose 'Exchange: external sender tagging'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/ExternalTag" -Cmdlet Get-ExternalInOutlook
            if ($r.Success -and $r.Data) { $store.ExternalInOutlook = [pscustomobject]@{ Enabled = [bool]$r.Data[0].Enabled; AllowListCount = @($r.Data[0].AllowList).Count } }

            Write-Verbose 'Exchange: connectors'
            $inbound = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/Connectors" -Cmdlet Get-InboundConnector
            $outbound = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/Connectors" -Cmdlet Get-OutboundConnector
            if ($inbound.Success) { $store.InboundConnectors = @($inbound.Data | Select-Object Name, Enabled, ConnectorType, RequireTls, RestrictDomainsToCertificate, RestrictDomainsToIPAddresses, SenderIPAddresses, SenderDomains, TlsSenderCertificateName) }
            if ($outbound.Success) { $store.OutboundConnectors = @($outbound.Data | Select-Object Name, Enabled, ConnectorType, TlsSettings, RecipientDomains, SmartHosts, UseMXRecord) }
            if ($inbound.Success -or $outbound.Success) { Save-SecOakRawData -Context $Context -Name 'exchange-connectors' -Data @{ inbound = $store.InboundConnectors; outbound = $store.OutboundConnectors } }

            Write-Verbose 'Exchange: Outlook on the web policies'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/OwaPolicy" -Cmdlet Get-OwaMailboxPolicy
            if ($r.Success) { $store.OwaPolicies = @($r.Data | Select-Object Name, IsDefault, AdditionalStorageProvidersAvailable) }

            Write-Verbose 'Exchange: calendar sharing policies'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/CalendarSharing" -Cmdlet Get-SharingPolicy
            if ($r.Success) {
                $store.SharingPolicies = @($r.Data | ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; Enabled = [bool]$_.Enabled; Default = [bool]$_.Default; Domains = @($_.Domains | ForEach-Object { "$_" }) } })
                Save-SecOakRawData -Context $Context -Name 'exchange-sharing-policies' -Data $store.SharingPolicies
            }

            Write-Verbose 'Exchange: privileged role groups'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/RoleGroups" -Cmdlet Get-RoleGroup
            if ($r.Success) {
                $store.RoleGroups = @($r.Data | ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; MemberCount = @($_.Members).Count } })
                $store.RoleGroupMembers = @{}
                foreach ($groupName in 'Organization Management', 'Recipient Management', 'Discovery Management', 'Compliance Management') {
                    if (-not ($store.RoleGroups | Where-Object Name -eq $groupName)) { continue }
                    $m = Invoke-SecOakExchangeGet -Context $Context -Check "$area/RoleGroups" -Cmdlet Get-RoleGroupMember -Parameters @{ Identity = $groupName } -LogLabel $groupName
                    if ($m.Success) {
                        $store.RoleGroupMembers[$groupName] = @($m.Data | ForEach-Object {
                                [pscustomobject][ordered]@{
                                    Name                      = "$($_.Name)"
                                    DisplayName               = "$($_.DisplayName)"
                                    RecipientTypeDetails      = "$($_.RecipientTypeDetails)"
                                    PrimarySmtpAddress        = "$($_.PrimarySmtpAddress)"
                                    WindowsLiveID             = "$($_.WindowsLiveID)"
                                    ExternalDirectoryObjectId = "$($_.ExternalDirectoryObjectId)"
                                }
                            })
                    }
                    else {
                        Add-SecOakGap -Context $Context -Area $area -Check "$area/RoleGroups" -EndpointOrCmdlet "Get-RoleGroupMember ($groupName)" -Result $(if ($m.Forbidden) { 'forbidden' } else { 'error' }) `
                            -Reason "$($m.ErrorMessage)" -FillWith $fill
                    }
                }
                Save-SecOakRawData -Context $Context -Name 'exchange-role-group-members' -Data $store.RoleGroupMembers
            }
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/RoleGroups" -Cmdlet Get-ManagementRoleAssignment -Parameters @{ RoleAssigneeType = 'ServicePrincipal' }
            if ($r.Success) {
                $store.ServicePrincipalAssignments = @($r.Data | ForEach-Object { [pscustomobject]@{ Name = "$($_.Name)"; Role = "$($_.Role)"; RoleAssignee = "$($_.RoleAssigneeName)"; Enabled = [bool]$_.Enabled } })
                Save-SecOakRawData -Context $Context -Name 'exchange-service-principal-roles' -Data $store.ServicePrincipalAssignments
            }

            Write-Verbose 'Exchange: mailbox delegations'
            $r = Read-SecOakExchangeStep -Context $Context -Area $area -Check "$area/Delegations" -Cmdlet Get-EXORecipientPermission -Parameters @{ ResultSize = 'Unlimited' }
            if ($r.Success) {
                $store.SendAs = @($r.Data | Where-Object { "$($_.Trustee)" -ne 'NT AUTHORITY\SELF' -and "$($_.AccessControlType)" -ne 'Deny' } | ForEach-Object {
                        [pscustomobject]@{ Mailbox = "$($_.Identity)"; Trustee = "$($_.Trustee)"; AccessRights = 'SendAs' }
                    })
            }
            if ($store.ContainsKey('Mailboxes')) {
                $targets = @($store.Mailboxes)
                $store.PermissionMailboxesSkipped = [math]::Max(0, $targets.Count - $permissionMailboxCap)
                $targets = @($targets | Select-Object -First $permissionMailboxCap)
                $fullAccess = [System.Collections.Generic.List[object]]::new()
                $failures = 0
                $consecutiveForbidden = 0
                $index = 0
                foreach ($mailbox in $targets) {
                    $index++
                    Write-Progress -Activity 'Reading mailbox permissions' -Status "Mailbox $index of $($targets.Count)" -PercentComplete ([int](100 * $index / $targets.Count))
                    $identity = if ($mailbox.ExternalDirectoryObjectId) { $mailbox.ExternalDirectoryObjectId } else { $mailbox.PrimarySmtpAddress }
                    $p = Invoke-SecOakExchangeGet -Context $Context -Check "$area/Delegations" -Cmdlet Get-EXOMailboxPermission -Parameters @{ Identity = $identity } -LogLabel "mailbox $index of $($targets.Count)"
                    if ($p.Success) {
                        $consecutiveForbidden = 0
                        foreach ($entry in @($p.Data | Where-Object { "$($_.User)" -ne 'NT AUTHORITY\SELF' -and -not $_.IsInherited -and "$($_.AccessControlType)" -ne 'Deny' -and (@($_.AccessRights) -join ',') -match 'FullAccess' })) {
                            $fullAccess.Add([pscustomobject]@{ Mailbox = $mailbox.PrimarySmtpAddress; Trustee = "$($entry.User)"; AccessRights = 'FullAccess' })
                        }
                    }
                    else {
                        $failures++
                        if ($p.Forbidden) { $consecutiveForbidden++ } else { $consecutiveForbidden = 0 }
                        if ($consecutiveForbidden -ge 3) {
                            Write-Warning 'Get-EXOMailboxPermission is forbidden for this session; stopping the mailbox loop.'
                            Add-SecOakGap -Context $Context -Area $area -Check "$area/Delegations" -EndpointOrCmdlet 'Get-EXOMailboxPermission' -Result 'forbidden' -Reason "$($p.ErrorMessage)" -FillWith $fill
                            break
                        }
                    }
                }
                Write-Progress -Activity 'Reading mailbox permissions' -Completed
                if ($consecutiveForbidden -lt 3) {
                    $store.FullAccess = $fullAccess.ToArray()
                    $store.PermissionMailboxesRead = $targets.Count - $failures
                    $store.PermissionFailures = $failures
                }
            }
            if ($store.ContainsKey('FullAccess') -or $store.ContainsKey('SendAs')) {
                Save-SecOakRawData -Context $Context -Name 'exchange-delegations' -Data @{ fullAccess = $store.FullAccess; sendAs = $store.SendAs }
            }
        }
    }
    finally {
        Disconnect-SecOakExchange -Context $Context
    }

    #--- Graph user inventory (cached, shared with other areas) for account state lookups
    if ($connected) { Get-SecOakUserInventory -Context $Context }
    $usersAvailable = $Context.Cache.ContainsKey('UsersAvailable') -and $Context.Cache.UsersAvailable

    #--- M365-01 mailbox auditing per mailbox, M365-13 holds
    if ($store.ContainsKey('Mailboxes')) {
        $mailboxes = @($store.Mailboxes)
        $requiredOwner = @('Update', 'MoveToDeletedItems', 'SoftDelete', 'HardDelete', 'UpdateFolderPermissions', 'UpdateInboxRules', 'UpdateCalendarDelegation')
        $requiredDelegate = @('Update', 'MoveToDeletedItems', 'SoftDelete', 'HardDelete', 'SendAs', 'SendOnBehalf', 'Create', 'UpdateFolderPermissions', 'UpdateInboxRules')
        $requiredAdmin = @('Update', 'MoveToDeletedItems', 'SoftDelete', 'HardDelete', 'SendAs', 'SendOnBehalf', 'Create', 'UpdateFolderPermissions', 'UpdateInboxRules', 'UpdateCalendarDelegation')
        if ($premiumAudit) {
            $requiredOwner += 'MailItemsAccessed', 'Send'
            $requiredDelegate += 'MailItemsAccessed'
            $requiredAdmin += 'MailItemsAccessed', 'Send'
        }
        $auditOff = @($mailboxes | Where-Object { -not $_.AuditEnabled })
        $missingActions = @($mailboxes | Where-Object {
                if (-not $_.AuditEnabled) { return $false }
                $owner = @($_.AuditOwner); $delegate = @($_.AuditDelegate); $admin = @($_.AuditAdmin)
                (@($requiredOwner | Where-Object { $_ -notin $owner }).Count -gt 0) -or
                (@($requiredDelegate | Where-Object { $_ -notin $delegate }).Count -gt 0) -or
                (@($requiredAdmin | Where-Object { $_ -notin $admin }).Count -gt 0)
            })
        $summary.mailboxAuditing = [ordered]@{
            mailboxes            = $mailboxes.Count
            byType               = @($mailboxes | Group-Object RecipientTypeDetails | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            auditDisabled        = $auditOff.Count
            missingRecommendedActions = $missingActions.Count
            recommendedActionsBasis = $(if ($premiumAudit) { 'Microsoft defaults plus MailItemsAccessed and Send (Audit Premium licensed)' } else { 'Microsoft default actions (Audit Premium not licensed)' })
        }
        if ($auditOff.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-01' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Mailboxes with auditing turned off' `
                        -Evidence ([ordered]@{ mailboxes = $auditOff.Count; total = $mailboxes.Count; examples = (Select-SecOakExample $auditOff.PrimarySmtpAddress) }) `
                        -Risk 'When a mailbox is not audited there is no record of who read, deleted or sent mail from it. If the account is compromised, the extent of the breach cannot be established.' `
                        -Recommendation 'Turn mailbox auditing back on for each mailbox (Set-Mailbox -AuditEnabled $true) and keep the organization default enabled.'))
        }
        elseif ($missingActions.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-01' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Mailboxes missing recommended audit actions' `
                        -Evidence ([ordered]@{ mailboxes = $missingActions.Count; total = $mailboxes.Count; basis = $summary.mailboxAuditing.recommendedActionsBasis; examples = (Select-SecOakExample $missingActions.PrimarySmtpAddress) }) `
                        -Risk 'Some owner, delegate or admin actions on these mailboxes are not logged, so an investigation after a phishing incident would have blind spots.' `
                        -Recommendation 'Reset the audit actions on these mailboxes to the Microsoft defaults (Set-Mailbox -DefaultAuditSet Admin,Delegate,Owner) so new recommended actions are picked up automatically.'))
        }

        $retentionHold = @($mailboxes | Where-Object RetentionHoldEnabled)
        $summary.holds = [ordered]@{
            litigationHold       = @($mailboxes | Where-Object LitigationHoldEnabled).Count
            archiveActive        = @($mailboxes | Where-Object { $_.ArchiveStatus -eq 'Active' }).Count
            inPlaceHolds         = @($mailboxes | Where-Object { $_.InPlaceHoldCount -gt 0 }).Count
            retentionHoldEnabled = $retentionHold.Count
            note                 = 'Information only. No designated mailbox list was supplied, so the absence of a hold is not a finding.'
        }
        if ($retentionHold.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-13' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Mailboxes with retention hold left on' `
                        -Evidence ([ordered]@{ mailboxes = $retentionHold.Count; examples = (Select-SecOakExample $retentionHold.PrimarySmtpAddress) }) `
                        -Risk 'Retention hold pauses the retention policy, so old mail is never cleaned up and the mailbox grows without limit. It is meant for temporary use, such as a long absence.' `
                        -Recommendation 'Confirm why each hold was set; remove it when the reason has passed (Set-Mailbox -RetentionHoldEnabled $false).'))
        }

        #--- M365-03 shared mailbox direct sign-in
        $shared = @($mailboxes | Where-Object RecipientTypeDetails -eq 'SharedMailbox')
        if (-not $shared.Count) { $summary.sharedMailboxSignIn = 'Not applicable: no shared mailboxes.' }
        elseif (-not $usersAvailable) {
            $summary.sharedMailboxSignIn = 'unknown (user inventory not readable)'
            Add-SecOakGap -Context $Context -Area $area -Check "$area/SharedMailboxSignIn" -EndpointOrCmdlet '/v1.0/users (accountEnabled)' -Result 'not collected' `
                -Reason 'The Graph user inventory is unavailable, so the sign-in state of shared mailbox accounts could not be checked.' -FillWith 'Application permission Directory.Read.All.'
        }
        else {
            $enabledShared = @($shared | Where-Object { $u = Resolve-SecOakExchangePrincipal -Context $Context -Value $_.ExternalDirectoryObjectId; $u -and $u.accountEnabled })
            $summary.sharedMailboxSignIn = [ordered]@{ sharedMailboxes = $shared.Count; accountEnabled = $enabledShared.Count }
            if ($enabledShared.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-03' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Shared mailboxes whose account can sign in directly' `
                            -Evidence ([ordered]@{ sharedMailboxes = $enabledShared.Count; total = $shared.Count; examples = (Select-SecOakExample $enabledShared.PrimarySmtpAddress) }) `
                            -Risk 'A shared mailbox account with sign-in enabled is a user account nobody owns. It often has no multifactor and a password that was never changed, which makes it an easy way in.' `
                            -Recommendation 'Block sign-in for each shared mailbox account in Microsoft Entra (staff open shared mailboxes through their own account, so nothing breaks).'))
            }
        }
    }

    #--- M365-02 audit bypass
    if ($store.ContainsKey('AuditBypass')) {
        $summary.auditBypass = [ordered]@{ recipientsChecked = $store.AuditBypassTotal; bypassEnabled = @($store.AuditBypass).Count }
        if (@($store.AuditBypass).Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-02' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Accounts excluded from mailbox audit logging' `
                        -Evidence ([ordered]@{ accounts = @($store.AuditBypass).Count; examples = (Select-SecOakExample $store.AuditBypass) }) `
                        -Risk 'Anything these accounts do in any mailbox is never logged. An attacker who obtains one of them, or a service account, can read and delete mail invisibly.' `
                        -Recommendation 'Remove the audit bypass from each account (Set-MailboxAuditBypassAssociation -AuditBypassEnabled $false) unless there is a documented reason to keep it.'))
        }
    }

    #--- M365-04 SMTP AUTH organization-wide
    if ($store.ContainsKey('TransportConfig')) {
        $summary.smtpClientAuthenticationDisabledOrgWide = $store.TransportConfig.SmtpClientAuthenticationDisabled
        if (-not $store.TransportConfig.SmtpClientAuthenticationDisabled) {
            $findings.Add((New-SecOakFinding -Id 'M365-04' -Area $area -Severity High -BaselineControl 'Legacy authentication blocked' `
                        -Title 'SMTP AUTH client submission is enabled for the organization' `
                        -Evidence ([ordered]@{ smtpClientAuthenticationDisabled = $false }) `
                        -Risk 'Any mailbox can be used to send mail with just a username and password from anywhere, which bypasses multifactor and is the usual route for spam sent from a stolen account.' `
                        -Recommendation 'Turn off SMTP AUTH for the organization (Set-TransportConfig -SmtpClientAuthenticationDisabled $true) and enable it only on the individual mailboxes that printers or applications really need.'))
        }
    }

    #--- M365-05 per-mailbox protocols, M365-10 Outlook on the web storage providers
    if ($store.ContainsKey('CasMailboxes')) {
        $cas = @($store.CasMailboxes)
        $smtpOverride = @($cas | Where-Object { $_.SmtpClientAuthenticationDisabled -eq $false })
        $popImap = @($cas | Where-Object { $_.PopEnabled -or $_.ImapEnabled })
        $summary.clientProtocols = [ordered]@{
            mailboxes               = $cas.Count
            smtpAuthEnabledPerMailbox = $smtpOverride.Count
            popEnabled              = @($cas | Where-Object PopEnabled).Count
            imapEnabled             = @($cas | Where-Object ImapEnabled).Count
            activeSyncEnabled       = @($cas | Where-Object ActiveSyncEnabled).Count
            ewsEnabled              = @($cas | Where-Object { $_.EwsEnabled -ne $false }).Count
            note                    = 'ActiveSync and Exchange Web Services are reported for information only.'
        }
        if ($smtpOverride.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-05' -Area $area -Severity Medium -BaselineControl 'Legacy authentication blocked' `
                        -Title 'Mailboxes with SMTP AUTH enabled individually' `
                        -Evidence ([ordered]@{ mailboxes = $smtpOverride.Count; total = $cas.Count; examples = (Select-SecOakExample $smtpOverride.PrimarySmtpAddress) }) `
                        -Risk 'These mailboxes accept username-and-password mail sending even when it is switched off for the organization, so a stolen password is enough to send mail as them.' `
                        -Recommendation 'Confirm which mailboxes genuinely feed a printer or application; clear the per-mailbox override on the rest (Set-CASMailbox -SmtpClientAuthenticationDisabled $null).'))
        }
        if ($popImap.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-05' -Area $area -Severity Low -BaselineControl 'Legacy authentication blocked' `
                        -Title 'Mailboxes with POP or IMAP enabled' `
                        -Evidence ([ordered]@{ mailboxes = $popImap.Count; total = $cas.Count; examples = (Select-SecOakExample $popImap.PrimarySmtpAddress) }) `
                        -Risk 'POP and IMAP let old mail programs download the whole mailbox. They are rarely needed in a modern setup and widen the attack surface.' `
                        -Recommendation 'Disable POP and IMAP on all mailboxes (Set-CASMailbox -PopEnabled $false -ImapEnabled $false) unless a specific application needs one of them.'))
        }
        if ($store.ContainsKey('OwaPolicies')) {
            $assignedNames = @($cas.OwaMailboxPolicy | Where-Object { $_ } | Select-Object -Unique)
            $risky = @($store.OwaPolicies | Where-Object { $_.AdditionalStorageProvidersAvailable -and ($_.IsDefault -or $_.Name -in $assignedNames) })
            $summary.outlookWebStorageProviders = [ordered]@{ policies = @($store.OwaPolicies).Count; allowingThirdPartyStorage = $risky.Count }
            if ($risky.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-10' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Outlook on the web offers third-party storage providers' `
                            -Evidence ([ordered]@{ policies = @($risky | ForEach-Object Name) }) `
                            -Risk 'Users can attach and save company files through personal Dropbox, Google Drive or Box accounts from the web mail interface, outside company control.' `
                            -Recommendation 'Turn off additional storage providers on the Outlook on the web policy (Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $false).'))
            }
        }
    }
    elseif ($store.ContainsKey('OwaPolicies')) {
        $risky = @($store.OwaPolicies | Where-Object { $_.AdditionalStorageProvidersAvailable -and $_.IsDefault })
        $summary.outlookWebStorageProviders = [ordered]@{ policies = @($store.OwaPolicies).Count; allowingThirdPartyStorage = $risky.Count; note = 'Policy assignments unknown; the default policy only was evaluated.' }
        if ($risky.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-10' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Outlook on the web offers third-party storage providers' `
                        -Evidence ([ordered]@{ policies = @($risky | ForEach-Object Name) }) `
                        -Risk 'Users can attach and save company files through personal Dropbox, Google Drive or Box accounts from the web mail interface, outside company control.' `
                        -Recommendation 'Turn off additional storage providers on the Outlook on the web policy (Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $false).'))
        }
    }

    #--- M365-06 authentication policies
    if ($store.ContainsKey('AuthenticationPolicies')) {
        $policies = @($store.AuthenticationPolicies)
        $allowingBasic = @($policies | Where-Object { $_.AllowBasicAuthSmtp -or $_.AllowBasicAuthPop -or $_.AllowBasicAuthImap })
        $defaultPolicy = if ($store.ContainsKey('DefaultAuthenticationPolicy')) { $store.DefaultAuthenticationPolicy } else { '' }
        $summary.authenticationPolicies = [ordered]@{ policies = $policies.Count; defaultPolicy = $(if ($defaultPolicy) { $defaultPolicy } else { 'none' }); allowingBasicSmtpPopOrImap = $allowingBasic.Count }
        if (-not $policies.Count) { $summary.authenticationPolicies.result = 'No policy' }
        if ($allowingBasic.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-06' -Area $area -Severity Medium -BaselineControl 'Legacy authentication blocked' `
                        -Title 'Authentication policies still allow basic authentication' `
                        -Evidence ([ordered]@{ policies = @($allowingBasic | ForEach-Object Name) }) `
                        -Risk 'Basic authentication sends a plain username and password and cannot use multifactor. A policy that allows it for SMTP, POP or IMAP leaves that door open should Microsoft re-enable the protocol for the tenant.' `
                        -Recommendation 'Set AllowBasicAuthSmtp, AllowBasicAuthPop and AllowBasicAuthImap to false on each policy (Set-AuthenticationPolicy).'))
        }
        elseif (-not $defaultPolicy -or -not $policies.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-06' -Area $area -Severity Medium -BaselineControl 'Legacy authentication blocked' `
                        -Title 'No default authentication policy blocks basic authentication' `
                        -Evidence ([ordered]@{ policies = $policies.Count; defaultPolicy = 'none' }) `
                        -Risk 'Microsoft has switched basic authentication off for the tenant, but without a policy of your own that state depends on Microsoft. A policy that blocks it is the control you own and can show an insurer or auditor.' `
                        -Recommendation 'Create an authentication policy that blocks every basic authentication protocol (New-AuthenticationPolicy) and set it as the organization default (Set-OrganizationConfig -DefaultAuthenticationPolicy).'))
        }
    }

    #--- M365-07 external sender tagging
    if ($store.ContainsKey('ExternalInOutlook')) {
        $summary.externalSenderTag = [ordered]@{ enabled = $store.ExternalInOutlook.Enabled; allowListEntries = $store.ExternalInOutlook.AllowListCount }
        if (-not $store.ExternalInOutlook.Enabled) {
            $findings.Add((New-SecOakFinding -Id 'M365-07' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'External sender tag in Outlook is off' `
                        -Evidence ([ordered]@{ enabled = $false }) `
                        -Risk 'Staff get no visual cue when a message really comes from outside the company, which makes impersonation of a colleague or the boss harder to spot.' `
                        -Recommendation 'Turn on the external sender tag (Set-ExternalInOutlook -Enabled $true); it applies to Outlook, Outlook on the web and the mobile apps.'))
        }
        elseif ($store.ExternalInOutlook.AllowListCount -gt 20) {
            $findings.Add((New-SecOakFinding -Id 'M365-07' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Many senders are exempt from the external sender tag' `
                        -Evidence ([ordered]@{ allowListEntries = $store.ExternalInOutlook.AllowListCount }) `
                        -Risk 'Every exempt domain or address looks internal to staff, so a spoofed message from one of them is more convincing.' `
                        -Recommendation 'Trim the allow list to the few partner addresses that genuinely need it.'))
        }
    }

    #--- M365-08 connectors
    if ($store.ContainsKey('InboundConnectors') -or $store.ContainsKey('OutboundConnectors')) {
        $inboundList = @($store.InboundConnectors)
        $outboundList = @($store.OutboundConnectors)
        if (-not $inboundList.Count -and -not $outboundList.Count) { $summary.connectors = 'Not applicable: no connectors.' }
        else {
            $weakInbound = @($inboundList | Where-Object {
                    $_.Enabled -and "$($_.ConnectorType)" -eq 'Partner' -and (
                        -not $_.RequireTls -or (
                            (@($_.SenderDomains | ForEach-Object { "$_" }) -match '^(smtp:)?\*') -and
                            -not $_.RestrictDomainsToCertificate -and -not $_.RestrictDomainsToIPAddresses -and -not @($_.SenderIPAddresses).Count))
                })
            $weakOutbound = @($outboundList | Where-Object { $_.Enabled -and @($_.SmartHosts).Count -and "$($_.TlsSettings)" -notin 'CertificateValidation', 'DomainValidation' })
            $disabled = @(@($inboundList | Where-Object { -not $_.Enabled }) + @($outboundList | Where-Object { -not $_.Enabled }))
            $summary.connectors = [ordered]@{ inbound = $inboundList.Count; outbound = $outboundList.Count; weakInbound = $weakInbound.Count; weakOutbound = $weakOutbound.Count; disabled = $disabled.Count }
            if ($weakInbound.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-08' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Inbound partner connectors without TLS or sender restriction' `
                            -Evidence ([ordered]@{ connectors = @($weakInbound | ForEach-Object Name) }) `
                            -Risk 'Mail through these connectors is trusted as coming from a partner, but anyone can use the path because it is not tied to a certificate or IP address, or it accepts unencrypted connections.' `
                            -Recommendation 'Require TLS and restrict each partner connector to the partner certificate name or IP addresses.'))
            }
            if ($weakOutbound.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-08' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Outbound connectors to a smart host without certificate or domain validation' `
                            -Evidence ([ordered]@{ connectors = @($weakOutbound | ForEach-Object { '{0} ({1})' -f $_.Name, $_.TlsSettings }) }) `
                            -Risk 'Outgoing mail sent through these connectors could be intercepted or redirected because the receiving server is not verified.' `
                            -Recommendation 'Set the connector TLS setting to certificate validation or domain validation for the smart host.'))
            }
            if ($disabled.Count) {
                $findings.Add((New-SecOakFinding -Id 'M365-08' -Area $area -Severity Low -BaselineControl 'None' `
                            -Title 'Disabled connectors that were never removed' `
                            -Evidence ([ordered]@{ connectors = @($disabled | ForEach-Object Name) }) `
                            -Risk 'A leftover connector can be re-enabled by mistake or by an attacker with admin access and re-open an old mail route.' `
                            -Recommendation 'Remove connectors that are no longer used.'))
            }
        }
    }

    #--- M365-09 delegations
    if ($store.ContainsKey('FullAccess') -or $store.ContainsKey('SendAs')) {
        $grants = @(@($store.FullAccess) + @($store.SendAs))
        $everyone = @($grants | Where-Object { $_.Trustee -match '^(Default|Anonymous|Everyone|Authenticated Users|(NT AUTHORITY|S-1-1-0|[^\\]+)\\(Everyone|Authenticated Users))$' })
        $weakTrustees = @($grants | Where-Object {
                $_ -notin $everyone -and ($u = Resolve-SecOakExchangePrincipal -Context $Context -Value $_.Trustee) -and (-not $u.accountEnabled -or $u.userType -eq 'Guest')
            })
        $summary.delegations = [ordered]@{
            mailboxesReadForFullAccess = $(if ($store.ContainsKey('PermissionMailboxesRead')) { $store.PermissionMailboxesRead } else { 0 })
            mailboxesSkippedByCap      = $(if ($store.ContainsKey('PermissionMailboxesSkipped')) { $store.PermissionMailboxesSkipped } else { 0 })
            fullAccessGrants           = @($store.FullAccess).Count
            sendAsGrants               = @($store.SendAs).Count
            grantsToEveryone           = $everyone.Count
            grantsToDisabledOrGuest    = $weakTrustees.Count
            examples                   = (Select-SecOakExample @($grants | ForEach-Object { '{0}: {1} -> {2}' -f $_.AccessRights, $_.Trustee, $_.Mailbox }))
        }
        if ($store.ContainsKey('PermissionMailboxesSkipped') -and $store.PermissionMailboxesSkipped -gt 0) {
            Add-SecOakGap -Context $Context -Area $area -Check "$area/Delegations" -EndpointOrCmdlet 'Get-EXOMailboxPermission' -Result 'partial' `
                -Reason "Full Access was read for the first $permissionMailboxCap mailboxes only; $($store.PermissionMailboxesSkipped) mailboxes were skipped to limit run time." `
                -FillWith 'Rerun with a higher cap or against the skipped mailboxes.'
        }
        if ($store.ContainsKey('PermissionFailures') -and $store.PermissionFailures -gt 0) {
            Add-SecOakGap -Context $Context -Area $area -Check "$area/Delegations" -EndpointOrCmdlet 'Get-EXOMailboxPermission' -Result 'partial' `
                -Reason "$($store.PermissionFailures) mailboxes could not be read." -FillWith 'Usually transient; rerun for the affected mailboxes.'
        }
        if ($everyone.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-09' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Mailbox access granted to everyone or anonymous' `
                        -Evidence ([ordered]@{ grants = $everyone.Count; examples = (Select-SecOakExample @($everyone | ForEach-Object { '{0}: {1} -> {2}' -f $_.AccessRights, $_.Trustee, $_.Mailbox })) }) `
                        -Risk 'Any account in the tenant, or anyone at all, can open or send as these mailboxes.' `
                        -Recommendation 'Remove the grants to Default, Anonymous, Everyone or Authenticated Users and give access to named people or a mail-enabled security group only.'))
        }
        if ($weakTrustees.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-09' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Mailbox access held by disabled or guest accounts' `
                        -Evidence ([ordered]@{ grants = $weakTrustees.Count; examples = (Select-SecOakExample @($weakTrustees | ForEach-Object { '{0}: {1} -> {2}' -f $_.AccessRights, $_.Trustee, $_.Mailbox })) }) `
                        -Risk 'Leavers and outside accounts still hold Full Access or Send As on company mailboxes. If a disabled account is re-enabled or a guest is compromised, the mailbox is exposed.' `
                        -Recommendation 'Remove mailbox permissions when an account is disabled, and do not grant mailbox access to guest accounts.'))
        }
    }

    #--- M365-11 calendar sharing
    if ($store.ContainsKey('SharingPolicies')) {
        $policies = @($store.SharingPolicies | Where-Object Enabled)
        $detailToAll = @($policies | Where-Object { @($_.Domains | Where-Object { $_ -match '^\*:CalendarSharingFreeBusy(Detail|Reviewer)$' }).Count })
        $anonymous = @($policies | Where-Object { @($_.Domains | Where-Object { $_ -match '^Anonymous:' }).Count })
        $summary.calendarSharing = [ordered]@{ policies = @($store.SharingPolicies).Count; enabled = $policies.Count; fullDetailToAllDomains = $detailToAll.Count; anonymousSharing = $anonymous.Count; domains = @($policies | ForEach-Object { '{0}: {1}' -f $_.Name, ($_.Domains -join '; ') }) }
        if ($detailToAll.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-11' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Calendars can be shared with full details to any external domain' `
                        -Evidence ([ordered]@{ policies = @($detailToAll | ForEach-Object Name) }) `
                        -Risk 'Users can share meeting subjects, attendees and locations with anyone outside the company, which reveals customers, deals and travel.' `
                        -Recommendation 'Limit the default sharing policy to free/busy time only for external domains, and allow full details only for named partner domains.'))
        }
        if ($anonymous.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-11' -Area $area -Severity Low -BaselineControl 'None' `
                        -Title 'Anonymous calendar sharing is enabled' `
                        -Evidence ([ordered]@{ policies = @($anonymous | ForEach-Object Name) }) `
                        -Risk 'Users can publish calendar links that anyone with the link can open without signing in.' `
                        -Recommendation 'Remove the Anonymous entry from the sharing policy unless public calendars are a business requirement.'))
        }
    }

    #--- M365-12 privileged role groups
    if ($store.ContainsKey('RoleGroupMembers')) {
        $weakMembers = [System.Collections.Generic.List[object]]::new()
        $membership = [ordered]@{}
        foreach ($groupName in @($store.RoleGroupMembers.Keys)) {
            $members = @($store.RoleGroupMembers[$groupName])
            $membership[$groupName] = $members.Count
            foreach ($member in $members) {
                $user = Resolve-SecOakExchangePrincipal -Context $Context -Value $member.ExternalDirectoryObjectId
                if (-not $user -and $member.WindowsLiveID) { $user = Resolve-SecOakExchangePrincipal -Context $Context -Value $member.WindowsLiveID }
                if (-not $user -and $member.PrimarySmtpAddress) { $user = Resolve-SecOakExchangePrincipal -Context $Context -Value $member.PrimarySmtpAddress }
                $isGuest = $member.RecipientTypeDetails -eq 'GuestMailUser' -or ($user -and $user.userType -eq 'Guest')
                $isDisabled = $user -and -not $user.accountEnabled
                if ($isGuest -or $isDisabled) { $weakMembers.Add([pscustomobject]@{ Group = $groupName; Member = $member.Name; State = $(if ($isGuest) { 'guest' } else { 'disabled' }) }) }
            }
        }
        $orgManagement = @($store.RoleGroupMembers['Organization Management'])
        $spWrite = @($store.ServicePrincipalAssignments | Where-Object { $_.Enabled -and $_.Role -notmatch '^View-Only' })
        $summary.roleGroups = [ordered]@{
            membership                     = $membership
            guestOrDisabledMembers         = $weakMembers.Count
            servicePrincipalAssignments    = @($store.ServicePrincipalAssignments).Count
            servicePrincipalsWithWriteRoles = @($spWrite.RoleAssignee | Select-Object -Unique).Count
            userInventoryAvailable         = $usersAvailable
        }
        if ($weakMembers.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-12' -Area $area -Severity High -BaselineControl 'Separate admin accounts' `
                        -Title 'Exchange admin role groups contain guest or disabled accounts' `
                        -Evidence ([ordered]@{ members = $weakMembers.Count; examples = (Select-SecOakExample @($weakMembers | ForEach-Object { '{0}: {1} ({2})' -f $_.Group, $_.Member, $_.State })) }) `
                        -Risk 'Accounts that have left, or that belong to another organization, still hold Exchange admin rights. Re-enabling or compromising one of them gives control over all mail.' `
                        -Recommendation 'Remove these members from the role groups and review the membership whenever someone leaves.'))
        }
        if ($orgManagement.Count -gt 5) {
            $findings.Add((New-SecOakFinding -Id 'M365-12' -Area $area -Severity Medium -BaselineControl 'Separate admin accounts' `
                        -Title 'Organization Management has more than five direct members' `
                        -Evidence ([ordered]@{ members = $orgManagement.Count; examples = (Select-SecOakExample $orgManagement.Name) }) `
                        -Risk 'Every member can change any mail setting, read any mailbox through permissions, and create forwarding. More admins means more accounts an attacker can target.' `
                        -Recommendation 'Reduce Organization Management to the two or three people who administer Exchange; give others a narrower role group such as Recipient Management.'))
        }
        if ($spWrite.Count) {
            $findings.Add((New-SecOakFinding -Id 'M365-12' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Applications hold Exchange roles beyond view-only' `
                        -Evidence ([ordered]@{ applications = @($spWrite.RoleAssignee | Select-Object -Unique).Count; examples = (Select-SecOakExample @($spWrite | ForEach-Object { '{0}: {1}' -f $_.RoleAssignee, $_.Role } | Select-Object -Unique)) }) `
                        -Risk 'An application with a write role in Exchange can change mailboxes and mail flow without a person signing in. If its certificate or secret leaks, so does that power.' `
                        -Recommendation 'Confirm each application is known and documented; remove assignments for tools no longer in use and prefer view-only roles where the tool only reads.'))
        }
    }

    $summary.coveredElsewhere = 'Forwarding, inbox rules, transport rules, auto-forward controls, audit log ingestion, organization-wide mailbox auditing and DKIM: Email area (EMAIL-01 to EMAIL-07, EMAIL-11).'
    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
