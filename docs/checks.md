# Checks

Every finding below is produced by one of the `Invoke-SecOak*Check` functions (or
`Invoke-SecOakAccessAudit` for the Access area), one file per area in `src\Areas\`,
through a call to the internal `New-SecOakFinding` helper. Severity is `Critical`, `High`, `Medium`, or `Low`. Baseline control is one of the
values in the module's `$script:BaselineControls` list, or `None` when a finding does not
map to one of the named baseline controls. Data sources are Microsoft Graph GET requests
(version is `v1.0` unless noted), Exchange Online, Security and Compliance, and Microsoft Teams
`Get-*` cmdlets, Defender for Endpoint and Azure Resource Manager GET requests, three
approved read-only POST requests (advanced hunting and the Azure Policy summary), and
public DNS and HTTPS lookups.
This document describes what the code checks and how it decides severity; it does not
restate the exact risk or recommendation text, which is in `findings.json` from a run.

Each finding ID is stable (for example `IDENTITY-03`) and some IDs are reused across two
mutually exclusive conditions in the same check (for example `IDENTITY-07`, `EMAIL-05`);
those are listed as one entry with both branches.

The sections below describe the original areas in detail. The "Check index" at the end
lists every finding ID the code can produce, in all eighteen areas, with its title,
severity, and baseline control; it is generated from the area files, so it is the
authoritative list.

## Identity

Function: `Invoke-SecOakIdentityCheck`. Application permissions: `User.Read.All`,
`AuditLog.Read.All`, `Policy.Read.All`, `RoleManagement.Read.Directory`,
`RoleEligibilitySchedule.Read.Directory`, `Application.Read.All`,
`IdentityRiskyUser.Read.All`, `IdentityRiskEvent.Read.All`. Several items need Microsoft
Entra ID P1 or P2 (multifactor registration detail, sign-in activity, conditional access,
Privileged Identity Management eligibility, full risky-user and risk-detection detail).

Data collected first and reused by later findings in this area: the user inventory
(`GET /users?$select=id,displayName,userPrincipalName,mail,accountEnabled,userType,
createdDateTime,assignedLicenses,assignedPlans,signInActivity&$top=500`, with a fallback
request that drops `signInActivity` if that call fails, in which case stale-account and
stale-guest findings are skipped for the run).

### IDENTITY-01: Administrators without multifactor registered
- Checks: administrators (`isAdmin`) returned by the authentication methods registration
  report who are not `isMfaRegistered`.
- Severity: Critical (fixed).
- Data source: `GET /reports/authenticationMethods/userRegistrationDetails`.
- Baseline control: Multifactor for every user.

### IDENTITY-02: Users who cannot complete multifactor sign-in
- Checks: users in scope (enabled members, or all non-guest rows if the user inventory
  could not be read) who are not `isMfaCapable`.
- Severity: High when the not-capable percentage of users in scope is 10% or more,
  otherwise Medium.
- Data source: `GET /reports/authenticationMethods/userRegistrationDetails`.
- Baseline control: Multifactor for every user.

### IDENTITY-03: Legacy authentication is not blocked
- Checks: security defaults are off, and no enabled conditional access policy blocks all
  users, all apps, for client app types including both `exchangeActiveSync` and `other`.
- Severity: High (fixed).
- Data source: `GET /policies/identitySecurityDefaultsEnforcementPolicy`,
  `GET /identity/conditionalAccess/policies`.
- Baseline control: Legacy authentication blocked.

### IDENTITY-04: Administrators are not required to use multifactor
- Checks: security defaults are off, and no enabled conditional access policy requires
  multifactor (built-in control `mfa` or an authentication strength) for all users or for
  the Global Administrator role.
- Severity: Critical (fixed).
- Data source: same as IDENTITY-03.
- Baseline control: Multifactor for every user.

### IDENTITY-05: No policy requires multifactor for all users
- Checks: security defaults are off, and no enabled conditional access policy requires
  multifactor for all users and all cloud apps.
- Severity: High (fixed).
- Data source: same as IDENTITY-03.
- Baseline control: Multifactor for every user.

### IDENTITY-06: Conditional access policies with broad exclusions
- Checks: enabled policies that require multifactor or block, and exclude more than two
  users, or exclude any group, role, or guests.
- Severity: Medium (fixed).
- Data source: `GET /identity/conditionalAccess/policies`.
- Baseline control: Multifactor for every user.

### IDENTITY-07: Global Administrator count out of range
Two mutually exclusive branches on the same finding ID:
- "Too many Global Administrators": more than 4 distinct principals hold the role.
  Severity High.
- "Fewer than two Global Administrators": fewer than 2. Severity Medium.
- Data source: `GET /roleManagement/directory/roleDefinitions?$select=id,displayName,
  templateId,isBuiltIn`, `GET /roleManagement/directory/roleAssignments?$expand=principal`,
  `GET /roleManagement/directory/roleEligibilitySchedules?$expand=principal`.
- Baseline control: Separate admin accounts.

### IDENTITY-08: Admin roles held by everyday accounts with licensed mailboxes
- Checks: user principals holding any directory role who also have an enabled Exchange
  Online service plan (a licensed mailbox).
- Severity: High if any of those admins hold a role in the privileged-role list
  (`$script:PrivilegedRoleNames`), otherwise Medium.
- Data source: same role endpoints as IDENTITY-07, plus the user inventory for mailbox
  presence (`assignedPlans`).
- Baseline control: Separate admin accounts.

### IDENTITY-09: Guest accounts hold admin roles
- Checks: role assignments where the principal is a guest user (`userType -eq 'Guest'`
  or a `#EXT#` user principal name).
- Severity: High (fixed).
- Data source: same role endpoints as IDENTITY-07.
- Baseline control: Separate admin accounts.

### IDENTITY-10: Applications (service principals) hold directory roles
- Checks: role assignments whose principal type is `servicePrincipal`, excluding the
  Security Oak reader app itself.
- Severity: High if any of those service principals hold a privileged role, otherwise
  Medium.
- Data source: same role endpoints as IDENTITY-07.
- Baseline control: None.

### IDENTITY-11: Enabled accounts with no sign-in for 90 days or more
- Checks: enabled member accounts created more than 90 days ago whose last interactive or
  non-interactive sign-in (whichever is later) is more than 90 days ago, or who have never
  signed in. Skipped entirely if sign-in activity could not be read.
- Severity: High if any stale account also holds a directory role, otherwise Medium.
- Data source: `GET /users?...&signInActivity` (user inventory).
- Baseline control: None.

### IDENTITY-12: Guest accounts unused for 90 days or more
- Checks: enabled guest accounts with no sign-in in the last 90 days (or never signed in).
  Skipped entirely if sign-in activity could not be read.
- Severity: Medium if more than 10 stale guests, otherwise Low.
- Data source: user inventory (`userType -eq 'Guest'`).
- Baseline control: None.

### IDENTITY-13: Anyone, including guests, can invite new guests
- Checks: the authorization policy's `allowInvitesFrom` equals `everyone`.
- Severity: Medium (fixed).
- Data source: `GET /policies/authorizationPolicy`.
- Baseline control: None.

### IDENTITY-14: Guests have the same directory access as members
- Checks: the authorization policy's `guestUserRoleId` equals the "same access as
  members" role template ID (`a0b1b346-4d3e-4e8b-98f8-753987be4970`).
- Severity: High (fixed).
- Data source: `GET /policies/authorizationPolicy`.
- Baseline control: None.

### IDENTITY-15: Users can consent to any application
- Checks: the authorization policy's assigned permission grant policies include
  `user-default-legacy`.
- Severity: High (fixed).
- Data source: `GET /policies/authorizationPolicy`.
- Baseline control: None.

### IDENTITY-16: Enterprise apps with high-privilege application permissions
- Checks: service principals (other than the Security Oak reader app) with an application
  permission on Microsoft Graph or Exchange Online classified `Write` or `Elevated` by
  `Get-SecOakPermissionRisk` (permission segments matching ReadWrite/Write/Manage/
  FullControl/Send/Create/Delete/Grant/Invite, or `Exchange.ManageAsApp`, or
  `full_access_as_app`).
- Severity: High (fixed).
- Data source: `GET /servicePrincipals?$filter=appId eq '<Graph or Exchange resource app
  ID>'`, `GET /servicePrincipals/{id}/appRoleAssignedTo?$top=999`, and
  `GET /servicePrincipals/{id}?$select=id,appId,displayName,appRoles` to resolve role
  names.
- Baseline control: None.

### IDENTITY-17: Enterprise apps that can read sensitive data tenant-wide
- Checks: service principals (other than the reader app, and not already counted in
  IDENTITY-16) with a permission classified `SensitiveRead` (a fixed list including
  `Mail.Read`, `Files.Read.All`, `Sites.Read.All`, `Chat.Read.All`,
  `UserAuthenticationMethod.Read.All`, `AuditLog.Read.All`, `Directory.Read.All`, and
  similar).
- Severity: Medium (fixed).
- Data source: same as IDENTITY-16.
- Baseline control: None.

### IDENTITY-18: Users currently flagged at risk
- Checks: users with `riskState` of `atRisk` or `confirmedCompromised`.
- Severity: High if any of those are `riskLevel -eq 'high'` or `riskState -eq
  'confirmedCompromised'`, otherwise Medium.
- Data source: `GET /identityProtection/riskyUsers`,
  `GET /identityProtection/riskDetections?$filter=detectedDateTime ge <30 days ago>`
  (used for summary detail, not for this finding's severity).
- Baseline control: None.

### Identity summary data (not findings)
Users (total, enabled members, guests); multifactor (users in scope, registered, capable,
not capable, admins in report, admins not registered); conditional access (security
defaults on/off, policy counts by state, whether legacy authentication is blocked,
multifactor required for all users, multifactor required for admins, the full policy
list); admin roles (active and eligible assignment counts, distinct admins, Global
Administrator count, admins with a mailbox, guest admins, service principal admins, group
assignments, a role-name breakdown); stale accounts (count with no sign-in in 90 days,
never signed in, stale admins), reported as `unavailable` when sign-in activity could not
be read; guests (total, enabled, stale, invite and guest-role settings); user consent
(assigned permission grant policies, whether users can register apps or create tenants);
application permissions (apps with any application permission, with write-level access,
with sensitive read access); risk (users at risk by level, note when risk level is hidden
because the tenant lacks Entra ID P2, detections in the last 30 days by type).

## Email

Function: `Invoke-SecOakEmailCheck`, backed by `Invoke-SecOakEmailCollection`. Requires
ExchangeOnlineManagement 3.x. App-only needs `Exchange.ManageAsApp` (Office 365 Exchange
Online) plus the Global Reader Microsoft Entra role on the reader app's service principal,
and a certificate credential (Exchange app-only rejects a client secret). Steps that come
back forbidden app-only are replayed through an interactive Exchange sign-in when
`-ExchangeInteractiveFallback` is used; each attempt is logged separately in
`endpoint-log.csv`.

Collection steps, each a read-only `Get-*` cmdlet: `Get-AcceptedDomain`, `Get-EXOMailbox`
(forwarding properties, with `Get-EXORecipient` used to resolve the target of a mail
contact forward), `Get-InboxRule` (per mailbox, for user and shared mailboxes; the loop
stops after three consecutive forbidden results and records that step as forbidden),
`Get-TransportRule`, `Get-RemoteDomain`, `Get-HostedOutboundSpamFilterPolicy` and
`Get-HostedOutboundSpamFilterRule`, `Get-AdminAuditLogConfig` and `Get-OrganizationConfig`,
`Get-DkimSigningConfig`. Any step not collected (not attempted, forbidden, or failed) is
recorded as a gap with the reason and the permission that would fill it.

### EMAIL-01: Mailboxes forwarding to external addresses
- Checks: mailboxes with `ForwardingSmtpAddress` or `ForwardingAddress` set, where the
  resolved target address is outside the tenant's accepted domains, or the target
  recipient type is a mail contact or mail user.
- Severity: High (fixed).
- Data source: `Get-EXOMailbox` (forwarding properties), `Get-EXORecipient` (target
  resolution), `Get-AcceptedDomain` (domain comparison).
- Baseline control: No automatic external forwarding.

### EMAIL-02: Inbox rules that forward or redirect mail externally
- Checks: inbox rules whose forward, forward-as-attachment, or redirect targets include
  an address outside the tenant's accepted domains.
- Severity: High (fixed).
- Data source: `Get-InboxRule` per mailbox.
- Baseline control: No automatic external forwarding.

### EMAIL-03: Transport rules that copy or redirect mail to external addresses
- Checks: enabled transport rules whose redirect, blind-copy, copy, or add-recipient
  targets include an address outside the tenant's accepted domains.
- Severity: High (fixed).
- Data source: `Get-TransportRule`.
- Baseline control: No automatic external forwarding.

### EMAIL-04: Transport rules that bypass spam filtering
- Checks: enabled transport rules that set the spam confidence level (`SetSCL`) to `-1`.
- Severity: Medium (fixed).
- Data source: `Get-TransportRule`.
- Baseline control: None.

### EMAIL-05: Automatic external forwarding is allowed
Two mutually exclusive branches on the same finding ID:
- "...allowed for everyone": the default outbound spam policy's `AutoForwardingMode` is
  `On`. Severity High.
- "Custom policies allow automatic external forwarding": the default policy is not `On`,
  but at least one non-default outbound spam policy has `AutoForwardingMode -eq 'On'`.
  Severity Medium.
- Data source: `Get-HostedOutboundSpamFilterPolicy`, `Get-RemoteDomain` (for summary
  detail).
- Baseline control: No automatic external forwarding.

### EMAIL-06: Unified audit logging is turned off
- Checks: `Get-AdminAuditLogConfig` reports `UnifiedAuditLogIngestionEnabled -eq $false`.
- Severity: High (fixed).
- Data source: `Get-AdminAuditLogConfig`.
- Baseline control: None.

### EMAIL-07: Mailbox auditing is disabled for the organization
- Checks: `Get-OrganizationConfig` reports `AuditDisabled -eq $true`.
- Severity: Medium (fixed).
- Data source: `Get-OrganizationConfig`.
- Baseline control: None.

### EMAIL-08: Domains with a missing, duplicate, or permissive SPF record
- Checks, per accepted domain that is not the `.onmicrosoft.com` domain: the domain does
  not have exactly one `v=spf1` TXT record, or its record ends in `+all`, `?all`, or has
  no `all` mechanism (`none`).
- Severity: High (fixed).
- Data source: DNS TXT lookup on the domain (`Resolve-DnsName`).
- Baseline control: None.

### EMAIL-09: Domains without an enforcing DMARC policy
- Checks: the domain has no DMARC record, or its policy (`p=`) is `none`.
- Severity: High if any domain has no DMARC record at all, otherwise Medium (only
  `p=none` domains present).
- Data source: DNS TXT lookup on `_dmarc.<domain>`.
- Baseline control: None.

### EMAIL-10: DMARC records without aggregate reporting
- Checks: the domain has a DMARC record but no `rua=` reporting address.
- Severity: Low (fixed).
- Data source: DNS TXT lookup on `_dmarc.<domain>`.
- Baseline control: None.

### EMAIL-11: Domains without DKIM signing enabled
- Checks: `Get-DkimSigningConfig` does not report `Enabled -eq $true` for the domain (also
  true when no DKIM configuration entry is found for it).
- Severity: Medium (fixed).
- Data source: `Get-DkimSigningConfig`, plus DNS CNAME lookups on
  `selector1._domainkey.<domain>` and `selector2._domainkey.<domain>` for the summary
  evidence.
- Baseline control: None.

### Email summary data (not findings)
Whether app-only access was forbidden for any collection step; mailboxes (total, by
recipient type, forwarding configured, forwarding external); inbox rules (mailboxes read,
mailbox read failures, total rules, external forward rules); transport rules (total,
external copy or redirect, spam filter bypass); automatic forwarding (default outbound
policy mode, policies allowing forwarding, default remote domain auto-forward setting);
audit log (unified audit log ingestion enabled, organization-wide mailbox auditing
disabled); per-domain SPF/DMARC/DKIM detail is written to
`raw\email-domain-authentication.json` and rolled up as domains checked, SPF missing,
DMARC missing, DMARC policy `none`, DKIM disabled.

## Devices

Function: `Invoke-SecOakDeviceCheck`. Application permission:
`DeviceManagementManagedDevices.Read.All`. Requires an Intune license in the tenant.

Data source for every finding in this area:
`GET /deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,osVersion,
complianceState,lastSyncDateTime,managementAgent,managedDeviceOwnerType,
userPrincipalName,enrolledDateTime,model`.

### DEVICES-01: No devices are managed by Intune
- Checks: zero managed devices returned.
- Severity: Medium (fixed).
- Baseline control: None.

### DEVICES-02: Devices not meeting compliance policy
- Checks: devices with `complianceState` of `noncompliant`, `error`, or `conflict`.
- Severity: High if non-compliant devices are 20% or more of all managed devices,
  otherwise Medium.
- Baseline control: None.

### DEVICES-03: Devices that have not synced with Intune in 30 days or more
- Checks: `lastSyncDateTime` older than 30 days.
- Severity: Medium (fixed).
- Baseline control: None.

### DEVICES-04: Windows 10 devices past end of support
- Checks: Windows devices whose OS version's build number (third component of the
  4-part version) is below 22000 (Windows 11's build floor). Windows 10 support ended 14
  October 2025.
- Severity: High (fixed).
- Baseline control: None.

### DEVICES-05: Windows devices behind the newest patch level seen in the tenant
- Checks: for each Windows build (major.minor.build grouping of the 4-part OS version),
  devices whose revision (4th version component) is lower than the highest revision seen
  for that same build elsewhere in the tenant.
- Severity: Medium if any device is also non-compliant tenant-wide, otherwise Low.
- Baseline control: None.
- This is a proxy estimate, not a measurement against Microsoft's published patch
  catalog: the code has no external source of "latest available build" and instead
  compares each device's build revision with the newest revision of the same build number
  already observed among the tenant's own devices. A device is only flagged if a newer
  revision of its own build exists somewhere in the tenant; a tenant where every device is
  already on the same (possibly outdated) revision produces no DEVICES-05 finding at all.

### Devices summary data (not findings)
Total device count; devices by operating system; devices by compliance state; count not
synced in 30 days; count of Windows devices behind the newest revision seen in the tenant;
Windows 10 count; the six most common Windows OS versions.

## Sharing

Function: `Invoke-SecOakSharingCheck`. Application permission:
`SharePointTenantSettings.Read.All`. Data source for every finding in this area:
`GET /admin/sharepoint/settings`.

### SHARING-01: Anyone (anonymous) links are allowed
- Checks: `sharingCapability -eq 'externalUserAndGuestSharing'`.
- Severity: Medium (fixed).
- Baseline control: None.

### SHARING-02: SharePoint accepts legacy authentication protocols
- Checks: `isLegacyAuthProtocolsEnabled -eq $true`.
- Severity: Medium (fixed).
- Baseline control: Legacy authentication blocked.

### SHARING-03: Guests can reshare items they do not own
- Checks: `isResharingByExternalUsersEnabled -eq $true`.
- Severity: Low (fixed).
- Baseline control: None.

### SHARING-04: Sharing invitations can be accepted by a different account
- Checks: sharing is not disabled (`sharingCapability -ne 'disabled'`) and
  `isRequireAcceptingUserToMatchInvitedUserEnabled -eq $false`.
- Severity: Low (fixed).
- Baseline control: None.

### Sharing summary data (not findings)
Sharing capability, sharing domain restriction mode, external resharing setting, legacy
authentication setting, unmanaged sync app restriction, idle session sign-out setting,
require-matching-invited-user setting, plus a note that OneDrive can be configured more
restrictively than the tenant-level SharePoint setting, which Graph does not separately
expose.

## Licensing

Function: `Invoke-SecOakLicensingCheck`. Application permissions:
`LicenseAssignment.Read.All` (or `Organization.Read.All`), `User.Read.All`,
`AuditLog.Read.All`.

### LICENSING-01: Purchased licenses not assigned
- Checks: SKUs with `capabilityStatus -eq 'Enabled'`, purchased seats between 1 and
  9,999 (larger pools are treated as free or viral offers, not purchased seats, and
  excluded), and at least one unassigned seat.
- Severity: Low (fixed).
- Data source: `GET /subscribedSkus`.
- Baseline control: None.

### LICENSING-02: Licensed users with no sign-in for 90 days or more
- Checks: users with at least one assigned license, created more than 90 days ago, whose
  last sign-in (interactive or non-interactive) is more than 90 days ago or who have never
  signed in. Skipped entirely if sign-in activity could not be read.
- Severity: Medium if more than 5 such users, otherwise Low.
- Data source: user inventory (`GET /users?...&signInActivity`, shared with Identity).
- Baseline control: None.

### Licensing summary data (not findings)
Subscriptions under the 10,000-seat cutoff (SKU, status, purchased, assigned,
unassigned); premium feature flags cached for reuse elsewhere in the run (Entra ID P1,
Entra ID P2, Intune, Defender for Office, detected from the SKUs' service plan names);
licensed users with no sign-in in 90 days, or `unavailable` when sign-in activity could
not be read.

## Posture

Function: `Invoke-SecOakPostureCheck`. Application permission:
`SecurityEvents.Read.All`.

### POSTURE-01: Microsoft Secure Score is low
- Checks: the most recent secure score record's percentage (`currentScore / maxScore *
  100`, rounded to one decimal) is below 60.
- Severity: High if the percentage is below 40, otherwise Medium.
- Data source: `GET /security/secureScores?$top=1` (not paged; only the newest record is
  used), `GET /security/secureScoreControlProfiles` (to resolve each control's title,
  category, and point gap, skipping deprecated controls).
- Baseline control: None.

### Posture summary data (not findings)
Date of the latest score, current score, max score, percentage, the all-tenants
comparative average score (when Microsoft supplies it), and the top ten improvement
actions by points available (action title, points available, category, user impact,
implementation cost, Microsoft's rank).

## Access

Function: `Invoke-SecOakAccessAudit`, run for the `Access` area (internally labelled
"Security Oak access" in the report). This is a self-audit of the Security Oak reader app
and its service principal: it never changes the app and only reads it. Application
permissions: `Application.Read.All`, `RoleManagement.Read.Directory`,
`DelegatedPermissionGrant.Read.All`, `AuditLog.Read.All` (service principal sign-ins,
needs Entra ID P1).

### ACCESS-01: Security Oak app is not single tenant
- Checks: the application's `signInAudience` is not `AzureADMyOrg`.
- Severity: High (fixed).
- Data source: `GET /applications?$filter=appId eq '<reader app ID>'&$select=id,appId,
  displayName,signInAudience,keyCredentials,passwordCredentials,requiredResourceAccess`.
- Baseline control: None.

### ACCESS-02: Security Oak app holds write or manage permissions
- Checks: application permissions granted to the reader app's service principal that
  `Get-SecOakPermissionRisk` classifies as `Write` (the same classification used in
  IDENTITY-16/17, without an `Elevated` exception here since `Exchange.ManageAsApp` is a
  designed part of the app).
- Severity: High (fixed).
- Data source: `GET /servicePrincipals?$filter=appId eq '<reader app ID>'` (own service
  principal), `GET /servicePrincipals/{id}/appRoleAssignments`, and
  `GET /servicePrincipals/{resourceId}?$select=...appRoles` to resolve permission names.
- Baseline control: None.

### ACCESS-03: Security Oak app holds directory roles beyond Global Reader
- Checks: directory roles assigned to the reader app's service principal other than
  Global Reader.
- Severity: Critical if Global Administrator is one of the extra roles, otherwise High.
- Data source: `GET /roleManagement/directory/roleAssignments?$filter=principalId eq
  '<service principal id>'&$expand=roleDefinition`.
- Baseline control: None.

### ACCESS-04: Security Oak app has client secrets
- Checks: any `passwordCredentials` entry present on the application or service
  principal object.
- Severity: Medium (fixed).
- Data source: `keyCredentials`/`passwordCredentials` from the ACCESS-01 application read
  and the own-service-principal read.
- Baseline control: None.

### ACCESS-05: Security Oak app has expired credentials
- Checks: any certificate or secret whose `endDateTime` is in the past.
- Severity: Low (fixed).
- Data source: same credential collections as ACCESS-04.
- Baseline control: None.

### ACCESS-06: Security Oak app credential expires within 60 days
- Checks: any certificate or secret whose `endDateTime` is in the future but within 60
  days.
- Severity: Medium (fixed).
- Data source: same credential collections as ACCESS-04.
- Baseline control: None.

### ACCESS-07: Security Oak app has no owners
- Checks: the application object exists but neither the application nor its service
  principal has any owner returned.
- Severity: Low (fixed).
- Data source: `GET /applications/{id}/owners?$select=id,displayName,
  userPrincipalName`, `GET /servicePrincipals/{id}/owners?$select=id,displayName,
  userPrincipalName`.
- Baseline control: None.

### ACCESS-08: Security Oak app has delegated permission grants
- Checks: any OAuth2 permission grant where the reader app's service principal is the
  client.
- Severity: Medium (fixed).
- Data source: `GET /oauth2PermissionGrants?$filter=clientId eq '<service principal
  id>'`.
- Baseline control: None.

### Access summary data (not findings)
Application display name and sign-in audience; granted permissions (resource and
permission name for every Microsoft Graph and Exchange Online application role assigned
to the reader app); token roles claimed by the most recent app-only token that are not
found in the current grants (a drift check between what the token actually carries and
what the directory currently shows as granted); directory roles held by the service
principal; a human-readable credential list (type, owner object, expiry); owners of the
application and service principal objects; delegated (OAuth2) permission grant scopes;
service principal sign-ins in the last 30 days (count returned, failure count, up to five
distinct source IP addresses), read from
`GET (beta) /auditLogs/signIns?$filter=appId eq '<reader app ID>' and createdDateTime ge
<30 days ago> and signInEventTypes/any(t: t eq 'servicePrincipal')&$top=50`.

## Backups

The Backup area (`Invoke-SecOakBackupCheck`, findings M365-44 and M365-45) reads the
Microsoft 365 Backup endpoints in Microsoft Graph. Those endpoints answer only to a
registered backup controller app, so a 403 is recorded as a gap, and a third-party backup
product is never visible through them. For that reason `Export-SecOakRunReport` still
writes a fixed "Open questions (cannot be checked from the tenant)" section at the end of
`gaps.md` on every run, asking whether Microsoft 365 data is backed up, how long it is
retained, and when a restore was last tested (baseline control "Tested backups").

## Check index

Generated from the area files. Titles shown as `<value>` are filled in at run time. A
row marked "No finding of its own" is an ID from the research catalogue that the code
covers elsewhere or deliberately does not report.

### Identity

Function: `Invoke-SecOakIdentityCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakIdentityCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| IDENTITY-01 | Administrators without multifactor registered | Critical | Multifactor for every user |
| IDENTITY-02 | Users who cannot complete multifactor sign-in | High or Medium | Multifactor for every user |
| IDENTITY-03 | Legacy authentication is not blocked | High | Legacy authentication blocked |
| IDENTITY-04 | Administrators are not required to use multifactor | Critical | Multifactor for every user |
| IDENTITY-05 | No policy requires multifactor for all users | High | Multifactor for every user |
| IDENTITY-06 | Conditional access policies with broad exclusions | Medium | Multifactor for every user |
| IDENTITY-07 | Too many Global Administrators; or Fewer than two Global Administrators | High or Medium | Separate admin accounts |
| IDENTITY-08 | Admin roles held by everyday accounts with licensed mailboxes | High or Medium | Separate admin accounts |
| IDENTITY-09 | Guest accounts hold admin roles | High | Separate admin accounts |
| IDENTITY-10 | Applications (service principals) hold directory roles | High or Medium | None |
| IDENTITY-11 | Enabled accounts with no sign-in for 90 days or more | High or Medium | None |
| IDENTITY-12 | Guest accounts unused for 90 days or more | Medium or Low | None |
| IDENTITY-13 | Anyone, including guests, can invite new guests | Medium | None |
| IDENTITY-14 | Guests have the same directory access as members | High | None |
| IDENTITY-15 | Users can consent to any application | High | None |
| IDENTITY-16 | Enterprise apps with high-privilege application permissions | High | None |
| IDENTITY-17 | Enterprise apps that can read sensitive data tenant-wide | Medium | None |
| IDENTITY-18 | Users currently flagged at risk | High or Medium | None |

### Email

Function: `Invoke-SecOakEmailCollection`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakEmailCollection -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| EMAIL-01 | Mailboxes forwarding to external addresses | High | No automatic external forwarding |
| EMAIL-02 | Inbox rules that forward or redirect mail externally | High | No automatic external forwarding |
| EMAIL-03 | Transport rules that copy or redirect mail to external addresses | High | No automatic external forwarding |
| EMAIL-04 | Transport rules that bypass spam filtering | Medium | None |
| EMAIL-05 | Automatic external forwarding is allowed for everyone; or Custom policies allow automatic external forwarding | High or Medium | No automatic external forwarding |
| EMAIL-06 | Unified audit logging is turned off | High | None |
| EMAIL-07 | Mailbox auditing is disabled for the organization | Medium | None |
| EMAIL-11 | Domains without DKIM signing enabled | Medium | None |

### Domain

Function: `Invoke-SecOakDomainCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakDomainCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| DOMAIN-01 | Inbound mail routes through a third-party gateway | Low | None |
| DOMAIN-02 | SPF record missing | High | None |
| DOMAIN-03 | More than one SPF record | High | None |
| DOMAIN-04 | SPF record causes a permanent error (more than 10 DNS lookups or a broken include) | High | None |
| DOMAIN-05 | SPF record does not fail unauthorized senders | High, Medium, or Low (by the SPF all qualifier and DMARC enforcement) | None |
| DOMAIN-06 | SPF record uses the ptr mechanism | Low | None |
| DOMAIN-07 | DMARC record missing; or DMARC record invalid (more than one record) | High | None |
| DOMAIN-08 | DMARC policy is monitor-only (p=none) | Medium | None |
| DOMAIN-09 | DMARC policy applies to only part of the mail (pct under 100) | Low | None |
| DOMAIN-10 | DMARC subdomain policy is weaker than the domain policy | Low | None |
| DOMAIN-11 | DMARC record without aggregate reporting | Low | None |
| DOMAIN-12 | Microsoft 365 DKIM selector records missing | Medium | None |
| DOMAIN-13 | Domain that does not send mail is not locked against spoofing | Medium | None |
| DOMAIN-14 | MTA-STS not published | Low | None |
| DOMAIN-15 | MTA-STS policy is not enforcing | Low | None |
| DOMAIN-16 | SMTP TLS reporting record does not resolve; or SMTP TLS reporting not published | Low | None |
| DOMAIN-17 | DNSSEC not enabled | Low | None |
| DOMAIN-18 | No CAA record | Low | None |
| DOMAIN-19 | Domain registration expires soon | High under 30 days, otherwise Medium | None |
| DOMAIN-20 | Registrar transfer lock not set | Medium | None |
| DOMAIN-21 | Subdomains point to cloud resources that no longer exist (subdomain takeover) | High | None |
| DOMAIN-22 | Sign-in for this domain is federated to an external identity provider | Low | None |
| DOMAIN-23 | Registered lookalike domains that can send and receive mail | Medium | None |
| DOMAIN-24 | Registered lookalike domains | Low | None |

### Devices

Function: `Invoke-SecOakDeviceCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakDeviceCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| DEVICES-01 | No devices are managed by Intune | Medium | None |
| DEVICES-02 | Devices not meeting compliance policy | High or Medium | None |
| DEVICES-03 | Devices that have not synced with Intune in 30 days or more | Medium | None |
| DEVICES-04 | Windows 10 devices past end of support | High | None |
| DEVICES-05 | Windows devices behind the newest patch level seen in the tenant | Medium or Low | None |

### Sharing

Function: `Invoke-SecOakSharingCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakSharingCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| SHARING-01 | Anyone (anonymous) links are allowed | Medium | None |
| SHARING-02 | SharePoint accepts legacy authentication protocols | Medium | Legacy authentication blocked |
| SHARING-03 | Guests can reshare items they do not own | Low | None |
| SHARING-04 | Sharing invitations can be accepted by a different account | Low | None |

### Licensing

Function: `Invoke-SecOakLicensingCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakLicensingCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| LICENSING-01 | Purchased licenses not assigned | Low | None |
| LICENSING-02 | Licensed users with no sign-in for 90 days or more | Medium or Low | None |

### Posture

Function: `Invoke-SecOakPostureCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakPostureCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| POSTURE-01 | Microsoft Secure Score is low | High or Medium | None |

### Entra

Function: `Invoke-SecOakEntraCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakEntraCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| ENTRA-02 | Authentication methods policy migration not completed; or Authenticator registration campaign is disabled; or Users cannot report suspicious multifactor prompts | Medium or Low | Multifactor for every user, None |
| ENTRA-03 | Text message or voice call authentication is enabled for all users; or Email one-time passcode is enabled for member users | Medium or Low | Multifactor for every user, None |
| ENTRA-04 | Microsoft Authenticator is disabled and no phishing-resistant method is enabled; or Authenticator prompts do not show the application name or sign-in location | Medium or Low | Multifactor for every user |
| ENTRA-05 | Passkeys (FIDO2) are not enabled; or Passkeys accept any key without attestation or model restrictions; or Temporary Access Pass can be reused for a long lifetime | Low | Multifactor for every user, None |
| ENTRA-06 | No conditional access policy requires phishing-resistant sign-in for administrators; or Custom authentication strengths allow text message or voice call | Medium or Low | Multifactor for every user |
| ENTRA-07 | Trusted named locations contain very wide IP ranges; or Multifactor policies covering administrators skip trusted locations | Medium or Low | Multifactor for every user |
| ENTRA-11 | No conditional access policy requires a compliant or joined device | Medium or Low | None |
| ENTRA-12 | No user risk policy forces a password change for high-risk users; or No sign-in risk policy challenges risky sign-ins | High | None |
| ENTRA-13 | No cloud-only emergency access account is excluded from every blocking or multifactor policy; or Accounts excluded from every protective policy that are not cloud-only Global Administrators; or More than two accounts are excluded from every protective policy; or Emergency access accounts not signed in for over a year | Medium or Low | Separate admin accounts, Multifactor for every user |
| ENTRA-14 | Report-only conditional access policies left unchanged for over 30 days; or No sign-in frequency or non-persistent browser session for administrators; or Registering security information is not protected by conditional access | Low | None, Separate admin accounts, Multifactor for every user |
| ENTRA-15 | Activating <value> does not require multifactor authentication; or <value> activations can last longer than 8 hours; or Activating <value> does not require a justification | High or Medium or Low | Multifactor for every user, Separate admin accounts, None |
| ENTRA-16 | Permanent <value> assignments are allowed; or Global Administrator activation needs no approval | Medium or Low | Separate admin accounts |
| ENTRA-17 | Nobody is notified when Global Administrator is activated | Low | None |
| ENTRA-18 | No recurring access review for guest users; or No recurring access review for privileged role assignments; or Access reviews that run only once | Medium or Low | None, Separate admin accounts |
| ENTRA-19 | Access reviews do not apply their results automatically; or Guest access reviews keep access when reviewers do not respond; or Recurring access reviews with no completed instance in 120 days | Low | None |
| ENTRA-20 | B2B direct connect is open to all external users and applications by default; or Multifactor from any external tenant is trusted by default; or Automatic invitation redemption is enabled for all tenants by default | Medium or Low | None, Multifactor for every user |
| ENTRA-21 | Partner organisations with B2B direct connect open to all users and applications; or Partner device compliance is trusted while the tenant does not use device compliance itself; or Partner organisations with automatic invitation redemption | Medium or Low | None |
| ENTRA-22 | Every member can invite guests; or Self-service sign-up for external users is enabled | Low | None |
| ENTRA-23 | Guest invitations are allowed to any domain | Low | None |
| ENTRA-24 | Users can consent to verified-publisher applications with low-impact permissions | Low | None |
| ENTRA-25 | Custom consent policy lets users grant any permission to unverified applications | Medium | None |
| ENTRA-26 | User consent is disabled but there is no admin consent workflow; or Admin consent workflow has no reviewers or no request duration | Medium or Low | None |
| ENTRA-27 | Federated domains; or Passwords expire periodically | Medium or Low | None |
| ENTRA-28 | No custom banned password list; or Smart lockout threshold is above 10 attempts; or Password protection is not enforced for on-premises Active Directory | Low | None |
| ENTRA-29 | Self-service password reset reaches few users; or Many users enabled for self-service password reset have not registered enough methods | Low | None |
| ENTRA-31 | Disabled accounts still hold privileged directory roles; or Disabled accounts still hold licences | Medium or Low | Separate admin accounts, None |
| ENTRA-32 | More than 10 percent of enabled devices have not signed in for 90 days; or Devices registered over 180 days ago with no recorded activity | Low | None |
| ENTRA-33 | Application secrets valid for more than a year; or Application credentials expiring within 30 days; or Expired credentials left on application registrations | Medium or Low | None |
| ENTRA-34 | Credentials added to Microsoft first-party service principals; or Enterprise applications with secrets valid for more than a year; or Single sign-on signing certificates expiring within 30 days | High or Medium or Low | None |
| ENTRA-35 | Directory synchronisation has not run in the last 24 hours; or Password hash synchronisation is behind | High or Medium | None |
| ENTRA-36 | Administrator roles held by accounts synchronised from on-premises Active Directory | High or Medium | Separate admin accounts |
| ENTRA-37 | Dynamic groups whose rules use attributes users or guests can influence; or Dynamic groups with paused membership processing; or Dynamic "all members" groups that include disabled accounts | Medium or Low | None |
| ENTRA-38 | Role-assignable groups owned by accounts that are not Global or Privileged Role Administrators; or Role-assignable groups contain guests or disabled accounts | High or Medium | Separate admin accounts |
| ENTRA-39 | Administrative unit roles held by guests or disabled accounts | Low | Separate admin accounts |
| ENTRA-40 | Domain federation settings changed in the last 7 days; or Credentials added to Microsoft service principals in the last 7 days; or Directory role assignments made by an application in the last 7 days; or Conditional access policies deleted in the last 7 days; or Sensitive administrative events in the last 7 days for review | High or Medium or Low | None, Separate admin accounts, Multifactor for every user |
| ENTRA-41 | Successful legacy authentication sign-ins in the last 7 days; or Failed legacy authentication attempts in the last 7 days | High or Medium | Legacy authentication blocked |
| ENTRA-42 | Password spray pattern in the last 7 days; or Privileged accounts with more than 20 failed sign-ins in 7 days; or Account lockouts in the last 7 days | High or Medium or Low | Multifactor for every user, Separate admin accounts, None |
| ENTRA-43 | Organisation-wide token lifetime policy extends access tokens beyond one hour; or Applications with extended access token lifetimes | Medium or Low | None |
| ENTRA-44 | Windows LAPS is not enabled in Entra device settings; or Fewer than 80 percent of Windows devices have a LAPS password backed up; or Active devices whose LAPS password backup is older than 30 days | Medium or Low | None |
| ENTRA-45 | Fewer than 80 percent of Windows devices have a BitLocker recovery key in Entra ID | Medium | None |

### Intune

Function: `Invoke-SecOakIntuneCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakIntuneCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| INTUNE-01 | Managed device platforms with no compliance policy | High | None |
| INTUNE-02 | Compliance policies that are not assigned to anyone | Medium | None |
| INTUNE-03 | Compliance policies with no follow-up action for noncompliant devices | Low | None |
| INTUNE-04 | Compliance policies failing on a large share of devices | Medium | None |
| INTUNE-06 | Devices with no compliance policy are treated as compliant | High or Medium | None |
| INTUNE-07 | No device configuration profiles exist; or Device configuration profiles that are not assigned | Medium or Low | None |
| INTUNE-08 | Settings Catalog policies that are not assigned | Low | None |
| INTUNE-09 | No antivirus policy is assigned to Windows devices | High | None |
| INTUNE-10 | No disk encryption policy is assigned to Windows devices | High | None |
| INTUNE-11 | No firewall policy is assigned to Windows devices | Medium | None |
| INTUNE-12 | No attack surface reduction policy is assigned to Windows devices | Medium | None |
| INTUNE-13 | No account protection policy is assigned to Windows devices | Medium | None |
| INTUNE-14 | No endpoint detection and response onboarding policy is assigned | Medium | None |
| INTUNE-16 | No Microsoft security baseline is deployed | Medium | None |
| INTUNE-17 | No Windows Update rings exist; or Windows Update rings that are not assigned | Medium or Low | None |
| INTUNE-18 | Feature update profiles hold devices on a Windows version that is out of support; or No Windows feature update profile exists; or Feature update profiles that are not assigned | Medium or Low | None |
| INTUNE-19 | Windows quality update profiles that are not assigned | Low | None |
| INTUNE-20 | Windows driver update profiles that are not assigned | Low | None |
| INTUNE-21 | Personally owned devices can enroll in Intune | Medium | None |
| INTUNE-22 | Autopilot devices are registered but no deployment profile is assigned | Medium | None |
| INTUNE-24 | No app protection policy for <value>; or App protection policies for <value> that are not assigned | Medium or Low | None |
| INTUNE-26 | PowerShell scripts deployed by Intune without a signature check | Low | None |
| INTUNE-27 | Remediation scripts that are not assigned | Low | None |
| INTUNE-28 | Intune roles assigned more broadly than a small business needs | Medium | None |
| INTUNE-29 | Windows devices without a managed local administrator password (LAPS) | High | None |
| INTUNE-30 | Encrypted devices with no BitLocker recovery key on file | High | None |
| INTUNE-31 | Managed computers that are not encrypted | High | None |

### Defender

Function: `Invoke-SecOakDefenderCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakDefenderCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| DEFENDER-01 | Defender alerts left open without triage | High or Medium | None |
| DEFENDER-02 | Defender incidents open without a response | Critical or Medium | None |
| DEFENDER-03 | Microsoft Secure Score has dropped over the last month | Medium | None |
| DEFENDER-04 | Highest-value Secure Score protections are not in place | High or Medium | None |
| DEFENDER-05 | No phishing simulation has been run in the last 12 months; or Phishing simulation training completion is below 70 percent | Medium or Low | None |
| DEFENDER-06 | No devices are onboarded to Defender for Endpoint; or Defender for Endpoint coverage gaps: unhealthy sensors or devices never onboarded | High or Medium | None |
| DEFENDER-07 | Organisation exposure score is in the medium or high band | High or Medium | None |
| DEFENDER-08 | Devices with a High exposure level | High | None |
| DEFENDER-09 | Critical vulnerabilities present on company devices | Critical or High | None |
| DEFENDER-11 | High-severity security recommendations outstanding | High or Medium | None |
| DEFENDER-12 | Software past end of support installed on devices | Medium | None |
| DEFENDER-14 | Impersonation protection is not enabled in any anti-phishing policy; or Default anti-phishing policy has no impersonation protection; only custom or preset policies provide it; or Spoof intelligence is disabled in the default anti-phishing policy | High or Medium | None |
| DEFENDER-15 | Safe Links policies in use do not scan links in email; or Safe Links lets users click through to blocked sites | High or Low | None |
| DEFENDER-16 | Safe Attachments policies in use do not block malicious attachments | High | None |
| DEFENDER-17 | Common attachment filter is disabled in an anti-malware policy; or Default anti-malware policy does not block some common risky file types | Medium or Low | None |
| DEFENDER-18 | Anti-spam policy allow-lists a consumer, wildcard, or own domain; or High-confidence spam or phishing is delivered to the inbox; or High-confidence spam or phishing goes to the Junk folder instead of quarantine | High or Medium | None |
| DEFENDER-19 | Connection filter allows a broad IP address range; or Connection filter IP allow list contains entries to review; or Connection filter safe list is enabled | High or Medium or Low | None |
| DEFENDER-20 | Tenant Allow/Block List allow entries that never expire | Medium | None |
| DEFENDER-21 | Users are never notified about quarantined mail | Medium | None |
| DEFENDER-22 | Safe Attachments for SharePoint, OneDrive and Teams is turned off; or Safe Documents is turned off | High or Low | None |
| DEFENDER-23 | Built-in protection preset policy is disabled | High | None |
| DEFENDER-24 | Neither the Standard nor the Strict preset security policy is enabled | Medium | None |
| DEFENDER-25 | Preset security policy is only partially enabled (one of its two layers is off) | High | None |
| HUNT-01 | Successful sign-ins with legacy authentication in the last 30 days | High | Legacy authentication blocked |
| HUNT-02 | Devices without tamper protection or related security controls | High | None |
| HUNT-03 | Macro-enabled Office attachments delivered to mailboxes in the last 30 days | Critical or Medium | None |
| HUNT-04 | Inbox rules forwarding mail outside the organisation were created in the last 30 days; or Inbox rules that forward or redirect mail were created in the last 30 days (destination not classified) | High or Medium | No automatic external forwarding |
| HUNT-05 | Attempts to tamper with Defender for Endpoint in the last 30 days | High | None |

### Exchange

Function: `Invoke-SecOakExchangeCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakExchangeCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| M365-01 | Mailboxes with auditing turned off; or Mailboxes missing recommended audit actions | High or Medium | None |
| M365-02 | Accounts excluded from mailbox audit logging | High | None |
| M365-03 | Shared mailboxes whose account can sign in directly | Medium | None |
| M365-04 | SMTP AUTH client submission is enabled for the organization | High | Legacy authentication blocked |
| M365-05 | Mailboxes with SMTP AUTH enabled individually; or Mailboxes with POP or IMAP enabled | Medium or Low | Legacy authentication blocked |
| M365-06 | Authentication policies still allow basic authentication; or No default authentication policy blocks basic authentication | Medium | Legacy authentication blocked |
| M365-07 | External sender tag in Outlook is off; or Many senders are exempt from the external sender tag | Medium or Low | None |
| M365-08 | Inbound partner connectors without TLS or sender restriction; or Outbound connectors to a smart host without certificate or domain validation; or Disabled connectors that were never removed | Medium or Low | None |
| M365-09 | Mailbox access granted to everyone or anonymous; or Mailbox access held by disabled or guest accounts | High or Medium | None |
| M365-10 | Outlook on the web offers third-party storage providers | Medium | None |
| M365-11 | Calendars can be shared with full details to any external domain; or Anonymous calendar sharing is enabled | Medium or Low | None |
| M365-12 | Exchange admin role groups contain guest or disabled accounts; or Organization Management has more than five direct members; or Applications hold Exchange roles beyond view-only | High or Medium | Separate admin accounts, None |
| M365-13 | Mailboxes with retention hold left on | Low | None |

### SharePoint

Function: `Invoke-SecOakSharePointCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakSharePointCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| M365-15 | Idle session sign-out for SharePoint and OneDrive is off; or Idle session sign-out waits longer than 8 hours | Medium or Low | None |
| M365-16 | OneDrive sync is allowed from computers outside the company | Medium | None |
| M365-17 | OneDrive files of leavers are deleted in under 90 days | Low | Tested backups |
| M365-19 | SharePoint sites with no owner or a disabled owner; or SharePoint sites with no activity for 180 days | Medium or Low | None |
| M365-20 | OneDrive storage belonging to disabled or missing accounts | Low | None |
| M365-21 | Usage reports hide user and site names | Low | None |

### Teams

Function: `Invoke-SecOakTeamsCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakTeamsCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| M365-22 | Teams external access is open to every organization | Medium | None |
| M365-23 | Staff can chat with personal (consumer) Teams accounts; or Personal (consumer) Teams accounts can start chats with staff | Medium | None |
| M365-24 | Teams accepts communication from trial-only tenants | Low | None |
| M365-25 | Anonymous users can join or start Teams meetings; or Everyone bypasses the meeting lobby; or Dial-in callers bypass the meeting lobby | Medium or Low | None |
| M365-26 | External participants can take control of shared screens | Low | None |
| M365-27 | Teams allows third-party cloud storage providers | Medium | None |
| M365-28 | Email can be sent into Teams channels | Low | None |
| M365-29 | All third-party Teams apps are allowed | Medium | None |
| M365-31 | Users cannot report suspicious Teams messages | Low | None |

### Purview

Function: `Invoke-SecOakPurviewCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakPurviewCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| M365-32 | No data loss prevention policy is enforced; or Data loss prevention does not cover every workload; or Data loss prevention policies left in test mode | High or Medium | None |
| M365-33 | No retention policy covers email or files; or Teams chats or channel messages have no retention policy; or Retention policies that have not finished deploying | Medium or Low | None |
| M365-34 | No sensitivity labels are published to users; or Sensitivity label policy has no default label or no downgrade justification | Medium or Low | None |
| M365-35 | Default high-severity alert policies are switched off; or Alert policies with no email recipient | Medium or Low | None |
| M365-36 | eDiscovery cases left active for more than a year without activity | Low | None |
| M365-37 | Unresolved high-severity data loss prevention or insider risk alerts | High or Medium | None |

### ServiceHealth

Function: `Invoke-SecOakServiceHealthCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakServiceHealthCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| M365-38 | Microsoft 365 services currently degraded or interrupted | Medium | None |
| M365-39 | Open Microsoft 365 incidents affecting this tenant; or Service advisories open for more than two weeks | Medium or Low | None |
| M365-40 | Major Microsoft changes that need action within 30 days; or Message centre posts with action due within 90 days | Medium or Low | None |
| M365-41 | Licence assignments in an error state | Medium | None |
| M365-42 | Subscriptions in warning, suspended or locked state | High, Medium, or Low (suspended, security service unhealthy, other) | None |

### Backup

Function: `Invoke-SecOakBackupCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakBackupCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| M365-44 | Microsoft 365 Backup has stopped because of a billing or controller problem; or Microsoft 365 Backup is not enabled; or Microsoft 365 Backup has never been set up | High or Medium | Tested backups |
| M365-45 | Workloads without an active Microsoft 365 Backup policy; or Backup protection policies with errors or still deploying | Medium or Low | Tested backups |

### Azure

Function: `Invoke-SecOakAzureCheck`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakAzureCheck -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| AZURE-03 | Broad privileged access at the tenant root management group | Critical, High, or Medium (guest, service principal, other) | Separate admin accounts |
| AZURE-04 | Guests, applications, or too many Owners hold privileged access to a subscription | Critical or High or Medium | Separate admin accounts |
| AZURE-05 | Custom roles grant broad write or permission-management rights | Low | None |
| AZURE-06 | No finding of its own: Classic administrators were retired in 2025; any holdover appears as an Owner assignment in AZURE-04. | - | - |
| AZURE-07 | Defender for Cloud plans are off for resources that exist | High or Medium | None |
| AZURE-08 | Defender for Cloud secure score is low | Medium or Low | None |
| AZURE-09 | Open Defender for Cloud recommendations | High or Medium or Low | None |
| AZURE-10 | Nobody is emailed when Defender for Cloud raises an alert | Medium or Low | None |
| AZURE-11 | No finding of its own: Log Analytics agent auto-provisioning was retired in November 2024; coverage comes from AZURE-09 assessments. | - | - |
| AZURE-12 | Resources are not compliant with assigned Azure policies | Medium or Low | None |
| AZURE-13 | Azure activity log is not exported for long-term retention | Medium or Low | None |
| AZURE-14 | No resource locks protect against accidental deletion | Low | None |
| AZURE-15 | No finding of its own: Public IP inventory is reported under inventory.publicIps and feeds AZURE-16 and AZURE-18; it produces no finding of its own. | - | - |
| AZURE-16 | Network security groups allow management ports from the internet | Low | None |
| AZURE-17 | Virtual machines rely on default platform encryption only | High or Medium | None |
| AZURE-18 | Virtual machines reachable directly from the internet | High or Medium | None |
| AZURE-19 | Virtual machines not protected by Azure Backup | Medium | Tested backups |
| AZURE-20 | VPN gateways on a retired SKU or policy-based configuration | Medium | None |
| AZURE-21 | Microsoft Entra Domain Services allows weak protocols or exposes LDAP | High or Medium or Low | None |
| AZURE-22 | Storage accounts with anonymous access, weak transport security, or open networks | High, Medium, or Low (worst item found) | None |
| AZURE-23 | Key vaults without deletion protection or open to the internet | High, Medium, or Low (worst item found) | None |
| AZURE-24 | SQL servers reachable from the internet or accepting old TLS | Medium | None |
| AZURE-25 | SQL servers still allow SQL password logins | High | Multifactor for every user |
| AZURE-26 | SQL server auditing is disabled | Medium | None |
| AZURE-27 | Web apps accept unencrypted HTTP | High | None |
| AZURE-28 | Web apps allow plain FTP or old TLS versions | High or Medium | None |
| AZURE-29 | Recovery Services vaults without soft delete, immutability, or network restriction | Medium or Low | Tested backups |
| AZURE-30 | No finding of its own: Microsoft 365 Backup has no Azure Resource Manager resource; it is a Microsoft Graph and admin center feature. | - | - |

### Access

Function: `Invoke-SecOakAccessAudit`. Permissions and licensing are listed in the function's help (`Get-Help Invoke-SecOakAccessAudit -Full`, NOTES section).

| ID | Finding | Severity | Baseline control |
|---|---|---|---|
| ACCESS-01 | Security Oak app is not single tenant | High | None |
| ACCESS-02 | Security Oak app holds write or manage permissions | High | None |
| ACCESS-03 | Security Oak app holds directory roles beyond Global Reader | Critical or High | None |
| ACCESS-04 | Security Oak app has client secrets | Medium | None |
| ACCESS-05 | Security Oak app has expired credentials | Low | None |
| ACCESS-06 | Security Oak app credential expires within 60 days | Medium | None |
| ACCESS-07 | Security Oak app has no owners | Low | None |
| ACCESS-08 | Security Oak app has delegated permission grants | Medium | None |
