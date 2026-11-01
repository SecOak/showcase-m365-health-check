# Permissions

The approved least-privilege permission set for the Security Oak reader app, used against
the pilot tenant.

## Summary

- Read-only. Every permission in the approved set is a read permission; no write
  permission is ever requested. Microsoft Graph, Defender for Endpoint, and Azure Resource
  Manager calls are HTTP GET (`Invoke-SecOakGraphGet` and `Invoke-SecOakApiGet` cannot
  issue anything else). Exchange Online and Security and Compliance calls are `Get-*`
  cmdlets and Microsoft Teams calls are `Get-Cs*` cmdlets; the wrappers reject any other
  cmdlet name. The only POST requests are the exceptions listed under "Read-only
  exceptions" below.
- Application permissions only. The reader app authenticates with client credentials
  (app-only). There are no delegated permission grants and no signed-in user.
- Certificate credential. The app authenticates with a certificate, not a client secret.
  For the Exchange Online calls specifically, the certificate's private key must be in a
  CryptoAPI (CSP) provider, not a CNG provider; Exchange Online app-only authentication
  does not accept a CNG key.
- Single tenant. The app registration's supported account type is "Accounts in this
  organizational directory only," and every acquired token is checked against the
  configured tenant ID before use.
- Owners are optional. The app registration and its service principal do not need an
  owner for the health check to run. If neither has one, the health check reports that as
  a finding (`ACCESS-07`) rather than treating it as a hard requirement.

## Application permissions

The approved set is `config\reader-app-permissions.json`: 42 application permissions
across four resources (Microsoft Graph, Office 365 Exchange Online, WindowsDefenderATP for
Defender for Endpoint, and Microsoft Exchange Online Protection for Security and Compliance
PowerShell). `setup\New-SecurityOakReaderApp.ps1` applies exactly this set. The table is
generated from that file; "Used by" combines the areas named in the file with the areas
whose function help names the permission.

| Permission | Resource | Used by | Reason |
|---|---|---|---|
| `Directory.Read.All` | Microsoft Graph | Identity, Domain, Devices, Licensing, Entra, Intune, Defender, Exchange, SharePoint, Teams, Purview, ServiceHealth, Azure, Access | Users, groups, devices, applications, service principals, licenses, and delegated permission grants. |
| `Policy.Read.All` | Microsoft Graph | Identity, Posture, Entra | Conditional Access, security defaults, authorization, and authentication method policies. |
| `RoleManagement.Read.Directory` | Microsoft Graph | Identity, Entra, Access | Directory role assignments and eligibility, including the reader app's own roles. |
| `AuditLog.Read.All` | Microsoft Graph | Identity, Licensing, Entra, Access | Sign-in activity for stale accounts and license use, and the reader app's own sign-ins. |
| `IdentityRiskyUser.Read.All` | Microsoft Graph | Identity | Users flagged at risk by Microsoft Entra ID Protection. |
| `IdentityRiskEvent.Read.All` | Microsoft Graph | Identity | Risk detections behind risky users. |
| `DeviceManagementManagedDevices.Read.All` | Microsoft Graph | Devices, Intune | Intune managed devices, compliance state, and encryption. |
| `SharePointTenantSettings.Read.All` | Microsoft Graph | Sharing, SharePoint | SharePoint and OneDrive external sharing settings. |
| `SecurityEvents.Read.All` | Microsoft Graph | Posture, Defender | Microsoft Secure Score and improvement actions. |
| `Reports.Read.All` | Microsoft Graph | Sharing, Licensing, SharePoint | Usage reports for sharing activity and license use. |
| `AccessReview.Read.All` | Microsoft Graph | Identity, Entra | Access reviews, reviewers, decisions, and settings, for reviewing standing access. |
| `AttackSimulation.Read.All` | Microsoft Graph | Defender | Attack simulation training campaigns and results. |
| `DeviceLocalCredential.ReadBasic.All` | Microsoft Graph | Identity, Entra, Intune | Local administrator (LAPS) credential metadata managed by Intune, excluding the password itself. |
| `DeviceManagementApps.Read.All` | Microsoft Graph | Intune | Intune-managed app properties, assignments, and protection policies. |
| `DeviceManagementConfiguration.Read.All` | Microsoft Graph | Intune | Intune device configuration profiles and their assignment status. |
| `DeviceManagementRBAC.Read.All` | Microsoft Graph | Intune | Intune role-based access control role definitions and assignments. |
| `DeviceManagementScripts.Read.All` | Microsoft Graph | Intune | Intune PowerShell and remediation scripts and their assignments. |
| `DeviceManagementServiceConfig.Read.All` | Microsoft Graph | Intune | Intune enrollment and device configuration service settings. |
| `Domain.Read.All` | Microsoft Graph | Identity, Domain | Verified domains, DNS records used for verification, and federation configuration. |
| `Organization.Read.All` | Microsoft Graph | Identity, Teams | Tenant organization information, including verified domains and directory settings Teams depends on. |
| `RoleManagementPolicy.Read.Directory` | Microsoft Graph | Identity | Privileged Identity Management policies for Microsoft Entra directory role assignments. |
| `SecurityAlert.Read.All` | Microsoft Graph | Defender, Purview | Microsoft 365 Defender and Purview security alerts. |
| `SecurityIncident.Read.All` | Microsoft Graph | Defender | Microsoft 365 Defender security incidents, correlated from alerts. |
| `ThreatHunting.Read.All` | Microsoft Graph | Defender | Advanced hunting with a fixed set of read-only KQL queries. Advanced hunting is called through a POST; this is a logged, documented read-only exception. |
| `UserAuthenticationMethod.Read.All` | Microsoft Graph | Identity | Registered authentication methods per user, for MFA and passwordless coverage checks. |
| `Policy.Read.PermissionGrant` | Microsoft Graph | Identity, Entra | Delegated and application permission grant policies, to review consent governance. |
| `Policy.Read.DeviceConfiguration` | Microsoft Graph | Identity, Entra, Intune | Device configuration policy read access, complementing Intune configuration profiles. |
| `BitlockerKey.ReadBasic.All` | Microsoft Graph | Identity, Intune | BitLocker recovery key metadata only (key IDs and timestamps), never the recovery key itself. |
| `ServiceHealth.Read.All` | Microsoft Graph | ServiceHealth | Microsoft 365 service health status and incidents. |
| `ServiceMessage.Read.All` | Microsoft Graph | ServiceHealth | Microsoft 365 message center announcements and advisories. |
| `eDiscovery.Read.All` | Microsoft Graph | Purview | eDiscovery cases, holds, and search configuration in Purview. |
| `BackupRestore-Control.Read.All` | Microsoft Graph | Backup | Microsoft 365 Backup protection policies and job status. |
| `BackupRestore-Configuration.Read.All` | Microsoft Graph | Backup | Microsoft 365 Backup service configuration. |
| `ReportSettings.Read.All` | Microsoft Graph | Sharing, Licensing, SharePoint | Tenant-level usage report display settings, which affect the sharing and licensing report output. |
| `RoleManagementPolicy.Read.AzureADGroup` | Microsoft Graph | Identity | Privileged Identity Management policies for group-based role assignments. |
| `Exchange.ManageAsApp` | Office 365 Exchange Online | Email, Defender, Exchange, Purview | App-only Exchange Online PowerShell. Only Get cmdlets are used; the Global Reader role limits it to reading. |
| `Machine.Read.All` | WindowsDefenderATP | Defender | Defender for Endpoint device inventory, onboarding health, sensor state and exposure level. |
| `Vulnerability.Read.All` | WindowsDefenderATP | Defender | Vulnerability and exposed-device counts from Defender Vulnerability Management. |
| `SecurityRecommendation.Read.All` | WindowsDefenderATP | Defender | Security recommendations from Defender Vulnerability Management. |
| `Software.Read.All` | WindowsDefenderATP | Defender | Software inventory, end-of-support and vulnerable software. |
| `Score.Read.All` | WindowsDefenderATP | Defender | Exposure score and device secure score. |
| `Exchange.ManageAsApp` | Microsoft Exchange Online Protection | Email, Defender, Exchange, Purview | App-only Security and Compliance PowerShell (Connect-IPPSSession). Only Get cmdlets are used; the Global Reader role limits it to reading. Separate from the Office 365 Exchange Online grant. |
### Why no narrower permission works for `Directory.Read.All`

`/oauth2PermissionGrants` (read during the Security Oak self-audit, to see what the app's
own service principal has been delegated) has no narrower application permission at all;
`Directory.Read.All` is the only application permission that grants it. Since the app
already needs `Directory.Read.All` for that one call, using it for the other directory
reads (users, applications, service principals, subscribed SKUs, organization) as well
adds no extra access beyond what a narrower, single-purpose permission would grant:

- `Application.Read.All` (applications and service principals) is a strict subset of
  `Directory.Read.All`.
- `User.Read.All` (users) is a strict subset of `Directory.Read.All`.
- `LicenseAssignment.Read.All` (subscribed SKUs) is a strict subset of `Directory.Read.All`.
- `Organization.Read.All` (organization) is a strict subset of `Directory.Read.All`.

Granting all four narrower permissions alongside `Directory.Read.All` would not reduce
what the app can read; it would only add rows to the app registration's permission list.
Granting `Directory.Read.All` alone therefore covers the same endpoints with one
permission instead of five. The one exception in the approved set is `Organization.Read.All`,
which is kept because Microsoft lists it for Teams PowerShell application authentication;
it adds no access beyond `Directory.Read.All`.

## Exchange Online

| Permission / role | Resource | Used by (area / check) | Cmdlets |
|---|---|---|---|
| `Exchange.ManageAsApp` (Office 365 Exchange Online) + Microsoft Entra role **Global Reader** | Exchange Online configuration: accepted domains, mailboxes, mail forwarding, inbox rules, transport rules, remote domains, anti-spam policy, admin audit log configuration, organization configuration, DKIM signing configuration | Email/Domains; Email/Forwarding; Email/InboxRules; Email/TransportRules; Email/AutoForwarding; Email/AuditLog; Email/Dkim | `Get-AcceptedDomain`, `Get-EXOMailbox`, `Get-EXORecipient`, `Get-InboxRule`, `Get-TransportRule`, `Get-RemoteDomain`, `Get-HostedOutboundSpamFilterPolicy`, `Get-HostedOutboundSpamFilterRule`, `Get-AdminAuditLogConfig`, `Get-OrganizationConfig`, `Get-DkimSigningConfig` |

Exchange Online app-only access needs two things together, not one:

- The `Exchange.ManageAsApp` API permission (under "Office 365 Exchange Online"), which
  lets the app authenticate to Exchange Online at all.
- A Microsoft Entra directory role assigned to the app's service principal, because
  Exchange Online authorizes app-only sessions by directory role rather than by a
  per-cmdlet API permission. **Global Reader** is the least-privileged built-in role that
  is read-only and still unlocks every `Get-*` cmdlet this health check calls, including
  `Get-InboxRule`, which was confirmed working app-only with Global Reader during the
  pilot.

The certificate used for this connection must have its private key in a CryptoAPI (CSP)
key storage provider. Exchange Online's app-only (certificate-based) authentication does
not accept a certificate whose private key is in a CNG provider.

## Security and Compliance PowerShell

The Purview area connects to Security and Compliance PowerShell app-only with
`Exchange.ManageAsApp` on the Microsoft Exchange Online Protection resource, authorized
by the same Global Reader directory role. Only `Get-*` cmdlets are called.

## Microsoft Teams PowerShell

The Teams area connects with the MicrosoftTeams module (4.7.1-preview or later) using the
same certificate. Authorization comes from the directory role on the service principal
(Global Reader); no separate API permission is needed. Only `Get-Cs*` cmdlets are called.
Microsoft does not support some cmdlets with application authentication, including the
Teams app settings; those are recorded as gaps ("not readable app-only") rather than
guessed.

## Defender for Endpoint

The five WindowsDefenderATP permissions in the table are read permissions on the Defender
for Endpoint API. Tokens are requested for `https://api.securitycenter.microsoft.com` and
requests go to `https://api.security.microsoft.com`. Advanced hunting uses fixed queries
through the approved read-only POST below.

## Azure

Azure access is not an app registration permission. The reader app's service principal
needs two Azure role assignments at the tenant root management group, made by a tenant
administrator outside the setup script:

- **Reader**: read Azure resources and configuration across every subscription.
- **Security Reader**: read Microsoft Defender for Cloud recommendations, secure score, and
  alerts.

Without them the Azure area records gaps and produces no Azure findings.

## Read-only exceptions

These are the only requests that are not GET or `Get-*`. Each has a fixed shape
(`Invoke-SecOakReadOnlyPost` refuses anything else before sending) and each is written to
the endpoint log with the note "approved read-only POST exception":

- The OAuth token request (client credentials with the certificate) for each API.
- Microsoft Graph `POST /security/runHuntingQuery` with a fixed query.
- Defender for Endpoint `POST /api/advancedqueries/run` with a fixed query.
- Azure Resource Manager `POST .../providers/Microsoft.PolicyInsights/policyStates/latest/summarize`
  on a subscription or management group scope, with an empty body.
## How to verify

Run the setup script in report-only mode to compare what is currently granted against
this approved set, without changing anything:

```
setup\New-SecurityOakReaderApp.ps1
```

Add `-Apply` only when a consultant is aligning the app registration to the approved set;
that is a state-changing run and should not be run casually.

Run the health check's own self-audit to confirm, from inside the pilot tenant, what the
app currently holds:

```
Invoke-SecurityOakHealthCheck.ps1 -PermissionAudit
```

This runs only the Security Oak access area (`Invoke-SecOakAccessAudit`), which reports
the app's granted permissions, directory roles, credentials, owners, sign-in audience, and
recent sign-ins.

Public DNS lookups made elsewhere in the health check (for example, mail authentication
records) are ordinary DNS queries against public resolvers and need no Microsoft Graph or
Exchange Online permission at all.
