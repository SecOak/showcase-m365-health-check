function Get-SecOakSmtpAddress {
    <#
    .SYNOPSIS
        Extracts SMTP addresses from Exchange recipient strings such as "Name [SMTP:a@b.com]".
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter()][AllowNull()][object[]]$Value)
    $addresses = foreach ($entry in @($Value)) {
        if (-not $entry) { continue }
        $text = "$entry"
        $matches2 = [regex]::Matches($text, '(?i)smtp:([^\]\s"]+@[^\]\s"]+)')
        if ($matches2.Count) { foreach ($m in $matches2) { $m.Groups[1].Value } }
        elseif ($text -match '^[^\s@"]+@[^\s@"]+$') { $text }
    }
    @($addresses | Where-Object { $_ } | Select-Object -Unique)
}

function Test-SecOakExternalAddress {
    <#
    .SYNOPSIS
        True when an SMTP address is outside the tenant's accepted domains.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Address,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$AcceptedDomains
    )
    $domain = ($Address -split '@')[-1].ToLowerInvariant()
    foreach ($accepted in $AcceptedDomains) {
        $a = $accepted.ToLowerInvariant()
        if ($domain -eq $a -or $domain.EndsWith(".$a")) { return $false }
    }
    $true
}

function Invoke-SecOakEmailCollection {
    <#
    .SYNOPSIS
        Collects Exchange Online data for the email checks into the context cache.
    .PARAMETER Context
        The run context. An Exchange session must be open.
    .PARAMETER Step
        The collection steps to run.
    .PARAMETER AppOnlyResult
        Passed through to the endpoint log when replaying steps interactively.
    .OUTPUTS
        The names of steps that were forbidden.
    .NOTES
        Requires an Exchange Online session. Read-only Get-* cmdlets only.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidateSet('AcceptedDomains', 'Mailboxes', 'InboxRules', 'TransportRules', 'RemoteDomains', 'OutboundSpam', 'AuditConfig', 'Dkim')][string[]]$Step,
        [Parameter()][ValidateSet('', 'forbidden')][string]$AppOnlyResult = ''
    )
    if (-not $Context.Cache.ContainsKey('Exchange')) { $Context.Cache.Exchange = @{} }
    $store = $Context.Cache.Exchange
    $forbiddenSteps = [System.Collections.Generic.List[string]]::new()
    $common = @{ Context = $Context; AppOnlyResult = $AppOnlyResult }

    foreach ($name in $Step) {
        Write-Verbose "Email: collecting $name"
        switch ($name) {
            'AcceptedDomains' {
                $r = Invoke-SecOakExchangeGet @common -Check 'Email/AcceptedDomains' -Cmdlet Get-AcceptedDomain
                if ($r.Success) { $store.AcceptedDomains = @($r.Data | Select-Object Name, DomainName, DomainType, Default); Save-SecOakRawData -Context $Context -Name 'email-accepted-domains' -Data $store.AcceptedDomains }
                elseif ($r.Forbidden) { $forbiddenSteps.Add($name) }
            }
            'Mailboxes' {
                $r = Invoke-SecOakExchangeGet @common -Check 'Email/Forwarding' -Cmdlet Get-EXOMailbox -Parameters @{
                    ResultSize = 'Unlimited'
                    Properties = 'ForwardingSmtpAddress', 'ForwardingAddress', 'DeliverToMailboxAndForward', 'RecipientTypeDetails', 'ExternalDirectoryObjectId'
                }
                if ($r.Success) {
                    $mailboxes = @($r.Data | Select-Object DisplayName, UserPrincipalName, PrimarySmtpAddress, RecipientTypeDetails, ExternalDirectoryObjectId, ForwardingSmtpAddress, ForwardingAddress, DeliverToMailboxAndForward)
                    # Resolve ForwardingAddress targets (a mail contact means external forwarding).
                    foreach ($mailbox in @($mailboxes | Where-Object ForwardingAddress)) {
                        $target = Invoke-SecOakExchangeGet @common -Check 'Email/Forwarding' -Cmdlet Get-EXORecipient -Parameters @{ Identity = "$($mailbox.ForwardingAddress)"; Properties = 'ExternalEmailAddress' } -LogLabel 'forwarding target'
                        $resolved = if ($target.Success -and $target.Data) { $target.Data[0] } else { $null }
                        $mailbox | Add-Member -NotePropertyName ForwardingTargetType -NotePropertyValue $(if ($resolved) { "$($resolved.RecipientTypeDetails)" } else { 'unresolved' })
                        $mailbox | Add-Member -NotePropertyName ForwardingTargetAddress -NotePropertyValue $(if ($resolved.ExternalEmailAddress) { "$($resolved.ExternalEmailAddress)" -replace '^(?i)smtp:', '' } elseif ($resolved) { "$($resolved.PrimarySmtpAddress)" } else { '' })
                    }
                    $store.Mailboxes = $mailboxes
                    Save-SecOakRawData -Context $Context -Name 'email-mailboxes' -Data $mailboxes
                }
                elseif ($r.Forbidden) { $forbiddenSteps.Add($name) }
            }
            'InboxRules' {
                $targets = @($store.Mailboxes | Where-Object RecipientTypeDetails -in 'UserMailbox', 'SharedMailbox')
                if (-not $targets) { Write-Verbose 'Email: no mailbox list, skipping inbox rules'; break }
                $rules = [System.Collections.Generic.List[object]]::new()
                $failures = [System.Collections.Generic.List[object]]::new()
                $consecutiveForbidden = 0
                $index = 0
                foreach ($mailbox in $targets) {
                    $index++
                    Write-Progress -Activity 'Reading inbox rules' -Status "Mailbox $index of $($targets.Count)" -PercentComplete ([int](100 * $index / $targets.Count))
                    $identity = if ($mailbox.ExternalDirectoryObjectId) { "$($mailbox.ExternalDirectoryObjectId)" } else { "$($mailbox.PrimarySmtpAddress)" }
                    $r = Invoke-SecOakExchangeGet @common -Check 'Email/InboxRules' -Cmdlet Get-InboxRule -Parameters @{ Mailbox = $identity; WarningAction = 'SilentlyContinue' } -LogLabel "mailbox $index of $($targets.Count)"
                    if ($r.Success) {
                        $consecutiveForbidden = 0
                        foreach ($rule in @($r.Data)) {
                            $rules.Add([pscustomobject][ordered]@{
                                    Mailbox               = "$($mailbox.PrimarySmtpAddress)"
                                    Name                  = $rule.Name
                                    Enabled               = $rule.Enabled
                                    ForwardTo             = @(Get-SecOakSmtpAddress $rule.ForwardTo)
                                    ForwardAsAttachmentTo = @(Get-SecOakSmtpAddress $rule.ForwardAsAttachmentTo)
                                    RedirectTo            = @(Get-SecOakSmtpAddress $rule.RedirectTo)
                                    DeleteMessage         = $rule.DeleteMessage
                                    MoveToFolder          = "$($rule.MoveToFolder)"
                                })
                        }
                    }
                    else {
                        $failures.Add([pscustomobject]@{ Mailbox = "$($mailbox.PrimarySmtpAddress)"; Error = $r.ErrorMessage })
                        Write-Warning "Inbox rules unreadable for mailbox $index of $($targets.Count): $($r.ErrorMessage)"
                        if ($r.Forbidden) { $consecutiveForbidden++ } else { $consecutiveForbidden = 0 }
                        if ($consecutiveForbidden -ge 3) {
                            Write-Warning 'Get-InboxRule is forbidden for this session; stopping the mailbox loop.'
                            $forbiddenSteps.Add($name)
                            break
                        }
                    }
                }
                Write-Progress -Activity 'Reading inbox rules' -Completed
                if ($name -notin $forbiddenSteps) {
                    $store.InboxRules = $rules.ToArray()
                    $store.InboxRuleFailures = $failures.ToArray()
                    $store.InboxRuleMailboxesRead = $targets.Count - $failures.Count
                    Save-SecOakRawData -Context $Context -Name 'email-inbox-rules' -Data $store.InboxRules
                    Save-SecOakRawData -Context $Context -Name 'email-inbox-rule-failures' -Data $store.InboxRuleFailures
                }
            }
            'TransportRules' {
                $r = Invoke-SecOakExchangeGet @common -Check 'Email/TransportRules' -Cmdlet Get-TransportRule -Parameters @{ ResultSize = 'Unlimited' }
                if ($r.Success) {
                    $store.TransportRules = @($r.Data | Select-Object Name, State, Mode, Priority, RedirectMessageTo, BlindCopyTo, CopyTo, AddToRecipients, SetSCL, SentToScope, FromScope)
                    Save-SecOakRawData -Context $Context -Name 'email-transport-rules' -Data $store.TransportRules
                }
                elseif ($r.Forbidden) { $forbiddenSteps.Add($name) }
            }
            'RemoteDomains' {
                $r = Invoke-SecOakExchangeGet @common -Check 'Email/AutoForwarding' -Cmdlet Get-RemoteDomain
                if ($r.Success) {
                    $store.RemoteDomains = @($r.Data | Select-Object Name, DomainName, AutoForwardEnabled, AutoReplyEnabled)
                    Save-SecOakRawData -Context $Context -Name 'email-remote-domains' -Data $store.RemoteDomains
                }
                elseif ($r.Forbidden) { $forbiddenSteps.Add($name) }
            }
            'OutboundSpam' {
                $p = Invoke-SecOakExchangeGet @common -Check 'Email/AutoForwarding' -Cmdlet Get-HostedOutboundSpamFilterPolicy
                $q = Invoke-SecOakExchangeGet @common -Check 'Email/AutoForwarding' -Cmdlet Get-HostedOutboundSpamFilterRule
                if ($p.Success) {
                    $store.OutboundPolicies = @($p.Data | Select-Object Name, IsDefault, AutoForwardingMode, Enabled)
                    $store.OutboundRules = if ($q.Success) { @($q.Data | Select-Object Name, HostedOutboundSpamFilterPolicy, State, Priority, From, FromMemberOf, SenderDomainIs) } else { @() }
                    Save-SecOakRawData -Context $Context -Name 'email-outbound-spam' -Data @{ policies = $store.OutboundPolicies; rules = $store.OutboundRules }
                }
                elseif ($p.Forbidden) { $forbiddenSteps.Add($name) }
            }
            'AuditConfig' {
                $a = Invoke-SecOakExchangeGet @common -Check 'Email/AuditLog' -Cmdlet Get-AdminAuditLogConfig
                $o = Invoke-SecOakExchangeGet @common -Check 'Email/AuditLog' -Cmdlet Get-OrganizationConfig
                if ($a.Success) {
                    $store.AuditConfig = [pscustomobject]@{
                        UnifiedAuditLogIngestionEnabled = $a.Data[0].UnifiedAuditLogIngestionEnabled
                        MailboxAuditingDisabled         = if ($o.Success) { $o.Data[0].AuditDisabled } else { $null }
                    }
                    Save-SecOakRawData -Context $Context -Name 'email-audit-config' -Data $store.AuditConfig
                }
                elseif ($a.Forbidden) { $forbiddenSteps.Add($name) }
            }
            'Dkim' {
                $r = Invoke-SecOakExchangeGet @common -Check 'Email/Dkim' -Cmdlet Get-DkimSigningConfig
                if ($r.Success) {
                    $store.Dkim = @($r.Data | Select-Object Domain, Enabled, Status, Selector1CNAME, Selector2CNAME)
                    Save-SecOakRawData -Context $Context -Name 'email-dkim' -Data $store.Dkim
                }
                elseif ($r.Forbidden) { $forbiddenSteps.Add($name) }
            }
        }
    }
    $forbiddenSteps.ToArray()
}

function Invoke-SecOakEmailCheck {
    <#
    .SYNOPSIS
        Email area: forwarding, inbox rules, transport rules, auto-forward controls, audit
        log ingestion, and DKIM signing configuration for every accepted domain.
    .DESCRIPTION
        Connects to Exchange Online app-only first. Steps that are forbidden app-only are
        replayed through an interactive sign-in when the run allows it, and both attempts
        are logged. Exchange is always disconnected in a finally block. Public DNS records
        (SPF, DMARC, DKIM selector CNAMEs) are checked by the Domain area, not here, so this
        area makes no DNS lookups and works whether or not the Domain area runs.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        Area result object with Area, Summary, and Findings.
    .EXAMPLE
        Invoke-SecOakEmailCheck -Context $context
    .NOTES
        Requires ExchangeOnlineManagement 3.x. App-only: Exchange.ManageAsApp plus the
        Global Reader role on the reader app's service principal.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Email'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $allSteps = @('AcceptedDomains', 'Mailboxes', 'InboxRules', 'TransportRules', 'RemoteDomains', 'OutboundSpam', 'AuditConfig', 'Dkim')
    $Context.Cache.Exchange = @{}
    $pending = $allSteps
    $appOnlyForbidden = @()

    try {
        $connected = $false
        if ($Context.CredentialType -eq 'Certificate') {
            try { $null = Connect-SecOakExchange -Context $Context -Mode App; $connected = $true }
            catch { Write-Warning $_.Exception.Message }
        }
        if ($connected) {
            $appOnlyForbidden = @(Invoke-SecOakEmailCollection -Context $Context -Step $pending)
            $pending = $appOnlyForbidden
        }
        if ($pending.Count -gt 0 -and $Context.ExchangeInteractiveFallback) {
            Disconnect-SecOakExchange -Context $Context
            try {
                $null = Connect-SecOakExchange -Context $Context -Mode Interactive
                $marker = if ($connected) { 'forbidden' } else { '' }
                # InboxRules depends on the mailbox list, so replay it with its dependency.
                $replay = @($pending)
                if ('InboxRules' -in $replay -and -not $Context.Cache.Exchange.Mailboxes -and 'Mailboxes' -notin $replay) { $replay = @('Mailboxes') + $replay }
                $pending = @(Invoke-SecOakEmailCollection -Context $Context -Step $replay -AppOnlyResult $marker)
            }
            catch { Write-Warning $_.Exception.Message }
        }
    }
    finally {
        Disconnect-SecOakExchange -Context $Context
    }

    $store = $Context.Cache.Exchange
    foreach ($missing in @($allSteps | Where-Object { -not $store.ContainsKey($_) -and -not ($_ -eq 'OutboundSpam' -and $store.ContainsKey('OutboundPolicies')) })) {
        Add-SecOakGap -Context $Context -Area $area -Check "Email/$missing" -EndpointOrCmdlet $missing -Result $(if ($missing -in $appOnlyForbidden) { 'forbidden' } else { 'not collected' }) `
            -Reason $(if ($Context.ExchangeMode -eq 'none' -and -not $store.Count) { 'No Exchange Online session could be opened.' } else { 'The cmdlet failed or was not available to this session.' }) `
            -FillWith 'Exchange.ManageAsApp on the reader app plus the Microsoft Entra role Global Reader on its service principal (certificate credential required).'
    }
    $summary.exchangeAppOnlyForbiddenSteps = $appOnlyForbidden

    $acceptedDomains = @($store.AcceptedDomains.DomainName | ForEach-Object { "$_" })
    if (-not $acceptedDomains -and $Context.InitialDomain) { $acceptedDomains = @($Context.InitialDomain) }

    #--- Mailbox forwarding
    if ($store.Mailboxes) {
        $forwarding = foreach ($mailbox in @($store.Mailboxes | Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress })) {
            $address = if ($mailbox.ForwardingSmtpAddress) { "$($mailbox.ForwardingSmtpAddress)" -replace '^(?i)smtp:', '' } else { $mailbox.ForwardingTargetAddress }
            $external = ($mailbox.ForwardingTargetType -eq 'MailContact' -or $mailbox.ForwardingTargetType -eq 'MailUser') -or ($address -and (Test-SecOakExternalAddress -Address $address -AcceptedDomains $acceptedDomains))
            [pscustomobject]@{ Mailbox = "$($mailbox.PrimarySmtpAddress)"; Target = $address; External = [bool]$external }
        }
        $forwarding = @($forwarding)
        $externalForwarding = @($forwarding | Where-Object External)
        $summary.mailboxes = [ordered]@{
            total                   = @($store.Mailboxes).Count
            byType                  = @($store.Mailboxes | Group-Object RecipientTypeDetails | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count })
            forwardingConfigured    = $forwarding.Count
            forwardingExternal      = $externalForwarding.Count
        }
        if ($externalForwarding.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'EMAIL-01' -Area $area -Severity High -BaselineControl 'No automatic external forwarding' `
                        -Title 'Mailboxes forwarding to external addresses' `
                        -Evidence ([ordered]@{ mailboxes = $externalForwarding.Count; examples = (Select-SecOakExample @($externalForwarding | ForEach-Object { '{0} -> {1}' -f $_.Mailbox, $_.Target })) }) `
                        -Risk 'Every message these mailboxes receive is copied outside the company. This is a common way attackers keep reading mail after a compromise, and a data-leak path.' `
                        -Recommendation 'Confirm each forward with the mailbox owner, remove any that are not approved, and block automatic external forwarding in the outbound spam policy.'))
        }
    }

    #--- Inbox rules
    if ($store.ContainsKey('InboxRules')) {
        $externalRules = @($store.InboxRules | Where-Object {
                $targets = @($_.ForwardTo) + @($_.ForwardAsAttachmentTo) + @($_.RedirectTo)
                @($targets | Where-Object { $_ -and (Test-SecOakExternalAddress -Address $_ -AcceptedDomains $acceptedDomains) }).Count -gt 0
            })
        $summary.inboxRules = [ordered]@{
            mailboxesRead         = $store.InboxRuleMailboxesRead
            mailboxFailures       = @($store.InboxRuleFailures).Count
            rulesTotal            = @($store.InboxRules).Count
            externalForwardRules  = $externalRules.Count
        }
        if ($externalRules.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'EMAIL-02' -Area $area -Severity High -BaselineControl 'No automatic external forwarding' `
                        -Title 'Inbox rules that forward or redirect mail externally' `
                        -Evidence ([ordered]@{ rules = $externalRules.Count; mailboxes = @($externalRules.Mailbox | Select-Object -Unique).Count; examples = (Select-SecOakExample @($externalRules | ForEach-Object { '{0}: "{1}"{2}' -f $_.Mailbox, $_.Name, $(if ($_.Enabled) { '' } else { ' (disabled)' }) })) }) `
                        -Risk 'Attackers who get into a mailbox often add a hidden forwarding rule so they keep receiving mail after the password is changed.' `
                        -Recommendation 'Review each rule with the mailbox owner, delete unapproved rules, and investigate the sign-in history of affected mailboxes.'))
        }
        if (@($store.InboxRuleFailures).Count -gt 0) {
            Add-SecOakGap -Context $Context -Area $area -Check 'Email/InboxRules' -EndpointOrCmdlet 'Get-InboxRule' -Result 'partial' `
                -Reason "$(@($store.InboxRuleFailures).Count) mailboxes could not be read (see raw\email-inbox-rule-failures.json)." `
                -FillWith 'Usually transient or mailbox-specific; rerun for the listed mailboxes.'
        }
    }

    #--- Transport rules
    if ($store.ContainsKey('TransportRules')) {
        $redirecting = @($store.TransportRules | Where-Object {
                $targets = @(Get-SecOakSmtpAddress (@($_.RedirectMessageTo) + @($_.BlindCopyTo) + @($_.CopyTo) + @($_.AddToRecipients)))
                $_.State -eq 'Enabled' -and @($targets | Where-Object { Test-SecOakExternalAddress -Address $_ -AcceptedDomains $acceptedDomains }).Count
            })
        $spamBypass = @($store.TransportRules | Where-Object { $_.State -eq 'Enabled' -and "$($_.SetSCL)" -eq '-1' })
        $summary.transportRules = [ordered]@{ total = @($store.TransportRules).Count; externalCopyOrRedirect = $redirecting.Count; spamFilterBypass = $spamBypass.Count }
        if ($redirecting.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'EMAIL-03' -Area $area -Severity High -BaselineControl 'No automatic external forwarding' `
                        -Title 'Transport rules that copy or redirect mail to external addresses' `
                        -Evidence ([ordered]@{ rules = $redirecting.Count; examples = (Select-SecOakExample $redirecting.Name) }) `
                        -Risk 'An organization-wide rule can silently copy large volumes of mail outside the company.' `
                        -Recommendation 'Confirm the business purpose and owner of each rule and remove any that are not approved.'))
        }
        if ($spamBypass.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'EMAIL-04' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Transport rules that bypass spam filtering' `
                        -Evidence ([ordered]@{ rules = $spamBypass.Count; examples = (Select-SecOakExample $spamBypass.Name) }) `
                        -Risk 'Mail matching these rules skips spam and phishing filtering. Attackers who spoof an allowed sender reach inboxes unchecked.' `
                        -Recommendation 'Replace spam-bypass rules with Tenant Allow/Block List entries or advanced delivery settings, scoped as tightly as possible.'))
        }
    }

    #--- Automatic external forwarding controls
    if ($store.ContainsKey('OutboundPolicies')) {
        $default = @($store.OutboundPolicies | Where-Object IsDefault) | Select-Object -First 1
        $allowingPolicies = @($store.OutboundPolicies | Where-Object AutoForwardingMode -eq 'On')
        $defaultRemote = @($store.RemoteDomains | Where-Object { $_.DomainName -eq '*' }) | Select-Object -First 1
        $summary.autoForwarding = [ordered]@{
            defaultOutboundPolicyMode = $default.AutoForwardingMode
            policiesAllowingForwarding = @($allowingPolicies | ForEach-Object Name)
            defaultRemoteDomainAutoForward = if ($defaultRemote) { $defaultRemote.AutoForwardEnabled } else { 'unknown' }
        }
        if ($default.AutoForwardingMode -eq 'On') {
            $findings.Add((New-SecOakFinding -Id 'EMAIL-05' -Area $area -Severity High -BaselineControl 'No automatic external forwarding' `
                        -Title 'Automatic external forwarding is allowed for everyone' `
                        -Evidence ([ordered]@{ defaultOutboundPolicyMode = $default.AutoForwardingMode; defaultRemoteDomainAutoForward = $summary.autoForwarding.defaultRemoteDomainAutoForward }) `
                        -Risk 'Any user, or an attacker in their mailbox, can set up forwarding that sends company mail outside without review.' `
                        -Recommendation 'Set the default outbound spam policy automatic forwarding to Off, and create a scoped policy only for approved exceptions.'))
        }
        elseif ($allowingPolicies.Count -gt 0) {
            $findings.Add((New-SecOakFinding -Id 'EMAIL-05' -Area $area -Severity Medium -BaselineControl 'No automatic external forwarding' `
                        -Title 'Custom policies allow automatic external forwarding' `
                        -Evidence ([ordered]@{ policies = @($allowingPolicies | ForEach-Object Name); defaultOutboundPolicyMode = $default.AutoForwardingMode }) `
                        -Risk 'Users in scope of these policies can forward mail outside automatically.' `
                        -Recommendation 'Confirm each exception is approved and scoped to named users, and review it at least yearly.'))
        }
    }

    #--- Audit log
    if ($store.ContainsKey('AuditConfig')) {
        $summary.auditLog = [ordered]@{ unifiedAuditLogIngestionEnabled = $store.AuditConfig.UnifiedAuditLogIngestionEnabled; mailboxAuditingDisabledOrgWide = $store.AuditConfig.MailboxAuditingDisabled }
        if (-not $store.AuditConfig.UnifiedAuditLogIngestionEnabled) {
            $findings.Add((New-SecOakFinding -Id 'EMAIL-06' -Area $area -Severity High -BaselineControl 'None' `
                        -Title 'Unified audit logging is turned off' `
                        -Evidence ([ordered]@{ unifiedAuditLogIngestionEnabled = $false }) `
                        -Risk 'Without the audit log there is no record of who read, changed, or deleted mail and files. An incident cannot be investigated.' `
                        -Recommendation 'Turn on audit log ingestion (Microsoft Purview portal, Audit) and confirm events appear within 24 hours.'))
        }
        if ($store.AuditConfig.MailboxAuditingDisabled -eq $true) {
            $findings.Add((New-SecOakFinding -Id 'EMAIL-07' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Mailbox auditing is disabled for the organization' `
                        -Evidence ([ordered]@{ auditDisabled = $true }) `
                        -Risk 'Mailbox access by owners, delegates, and admins is not recorded.' `
                        -Recommendation 'Re-enable mailbox auditing by default for the organization.'))
        }
    }

    #--- DKIM signing configuration per accepted domain (Exchange side). The public DNS records
    #--- for SPF, DMARC, and the DKIM selector CNAMEs are checked in the Domain area.
    $summary.domainAuthenticationRecords = 'Checked in the Domain area (public DNS), not here.'
    if ($store.ContainsKey('Dkim') -and $store.ContainsKey('AcceptedDomains')) {
        $dkimRows = foreach ($domain in @($store.AcceptedDomains | Where-Object { "$($_.DomainName)" -notmatch '\.onmicrosoft\.com$' })) {
            $name = "$($domain.DomainName)".ToLowerInvariant()
            $dkimConfig = @($store.Dkim | Where-Object { "$($_.Domain)" -eq $name }) | Select-Object -First 1
            [pscustomobject][ordered]@{
                Domain      = $name
                DkimEnabled = if ($dkimConfig) { [bool]$dkimConfig.Enabled } else { $null }
                DkimStatus  = if ($dkimConfig) { "$($dkimConfig.Status)" } else { 'no signing configuration' }
            }
        }
        $dkimRows = @($dkimRows)
        $dkimBad = @($dkimRows | Where-Object { $_.DkimEnabled -ne $true })
        $summary.dkimSigning = [ordered]@{ domainsChecked = $dkimRows.Count; signingNotEnabled = $dkimBad.Count }
        if ($dkimBad.Count) {
            $findings.Add((New-SecOakFinding -Id 'EMAIL-11' -Area $area -Severity Medium -BaselineControl 'None' `
                        -Title 'Domains without DKIM signing enabled' `
                        -Evidence ([ordered]@{ domains = $dkimBad.Count; examples = (Select-SecOakExample @($dkimBad | ForEach-Object { '{0} (enabled {1}, status {2})' -f $_.Domain, $_.DkimEnabled, $_.DkimStatus })) }) `
                        -Risk 'Outgoing mail is not cryptographically signed, which weakens DMARC and deliverability and makes spoofing harder to detect.' `
                        -Recommendation 'Publish the two selector CNAME records from the Defender portal (the Domain area reports whether they exist), then enable DKIM signing for each domain.'))
        }
    }

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
