Set-StrictMode -Version 1.0
$script:GraphBaseUri          = 'https://graph.microsoft.com'
$script:GraphResourceAppId    = '00000003-0000-0000-c000-000000000000'
$script:ExchangeResourceAppId = '00000002-0000-0ff1-ce00-000000000000'
$script:GlobalAdminTemplateId = '62e90394-69f5-4237-9190-012177145e10'
$script:GlobalReaderTemplateId = 'f2ef992c-3afb-46b9-b7cf-a126ee74c451'
$script:BaselineControls = @(
    'Multifactor for every user'
    'Separate admin accounts'
    'Legacy authentication blocked'
    'No automatic external forwarding'
    'Tested backups'
    'None'
)
$script:SeverityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
$script:PrivilegedRoleNames = @(
    'Global Administrator', 'Privileged Role Administrator', 'Privileged Authentication Administrator',
    'Security Administrator', 'Exchange Administrator', 'SharePoint Administrator', 'User Administrator',
    'Application Administrator', 'Cloud Application Administrator', 'Authentication Administrator',
    'Conditional Access Administrator', 'Intune Administrator', 'Helpdesk Administrator',
    'Billing Administrator', 'Teams Administrator', 'Hybrid Identity Administrator',
    'Authentication Policy Administrator', 'Compliance Administrator', 'Groups Administrator',
    'Password Administrator', 'Azure DevOps Administrator', 'Domain Name Administrator',
    'External Identity Provider Administrator', 'Directory Writers', 'Partner Tier2 Support',
    'Partner Tier1 Support'
)
$script:SensitiveReadPermissions = @(
    'Mail.Read', 'Mail.ReadBasic.All', 'Mail.ReadBasic', 'MailboxSettings.Read', 'Calendars.Read',
    'Contacts.Read', 'Files.Read.All', 'Sites.Read.All', 'Chat.Read.All', 'ChannelMessage.Read.All',
    'Notes.Read.All', 'OnlineMeetingTranscript.Read.All', 'OnlineMeetingRecording.Read.All',
    'UserAuthenticationMethod.Read.All', 'AuditLog.Read.All', 'Directory.Read.All',
    'IdentityRiskyUser.Read.All', 'SecurityEvents.Read.All'
)
$script:GraphPermissionHints = @(
    @{ Pattern = '^/organization';                                   Permission = 'Directory.Read.All';                             Confidence = 'documented' }
    @{ Pattern = '^/domains';                                        Permission = 'Directory.Read.All';                             Confidence = 'documented' }
    @{ Pattern = '^/reports/authenticationMethods/userRegistrationDetails'; Permission = 'AuditLog.Read.All';                       Confidence = 'documented'; Note = 'Requires Microsoft Entra ID P1 or P2.' }
    @{ Pattern = '^/policies/identitySecurityDefaultsEnforcementPolicy'; Permission = 'Policy.Read.All';                            Confidence = 'documented' }
    @{ Pattern = '^/identity/conditionalAccess/policies';            Permission = 'Policy.Read.All';                                Confidence = 'documented' }
    @{ Pattern = '^/policies/authorizationPolicy';                   Permission = 'Policy.Read.All';                                Confidence = 'documented' }
    @{ Pattern = '^/roleManagement/directory/roleEligibilitySchedules'; Permission = 'RoleManagement.Read.Directory';              Confidence = 'documented'; Note = 'Privileged Identity Management requires Microsoft Entra ID P2.' }
    @{ Pattern = '^/roleManagement/directory/role';                  Permission = 'RoleManagement.Read.Directory';                  Confidence = 'documented' }
    @{ Pattern = '^/users.*signInActivity';                          Permission = 'Directory.Read.All + AuditLog.Read.All';         Confidence = 'documented'; Note = 'signInActivity requires Microsoft Entra ID P1 or P2.' }
    @{ Pattern = '^/users';                                          Permission = 'Directory.Read.All';                             Confidence = 'documented' }
    @{ Pattern = '^/oauth2PermissionGrants';                         Permission = 'Directory.Read.All';                             Confidence = 'documented' }
    @{ Pattern = '^/servicePrincipals/[^/]+/owners';                 Permission = 'Directory.Read.All';                             Confidence = 'documented' }
    @{ Pattern = '^/servicePrincipals';                              Permission = 'Directory.Read.All';                             Confidence = 'documented' }
    @{ Pattern = '^/applications';                                   Permission = 'Directory.Read.All';                             Confidence = 'documented' }
    @{ Pattern = '^/identityProtection/riskyUsers';                  Permission = 'IdentityRiskyUser.Read.All';                     Confidence = 'documented'; Note = 'Full detail requires Microsoft Entra ID P2.' }
    @{ Pattern = '^/identityProtection/riskDetections';              Permission = 'IdentityRiskEvent.Read.All';                     Confidence = 'documented'; Note = 'Requires Microsoft Entra ID P2.' }
    @{ Pattern = '^/deviceManagement/managedDevices';                Permission = 'DeviceManagementManagedDevices.Read.All';        Confidence = 'documented'; Note = 'Requires an Intune license in the tenant.' }
    @{ Pattern = '^/admin/sharepoint/settings';                      Permission = 'SharePointTenantSettings.Read.All';              Confidence = 'documented' }
    @{ Pattern = '^/subscribedSkus';                                 Permission = 'Directory.Read.All';                             Confidence = 'documented' }
    @{ Pattern = '^/security/runHuntingQuery';                      Permission = 'ThreatHunting.Read.All';                         Confidence = 'documented'; Note = 'Approved read-only POST exception. Returns 400 when a table has no data in the tenant.' }
    @{ Pattern = '^/security/secureScore';                           Permission = 'SecurityEvents.Read.All';                        Confidence = 'documented' }
    @{ Pattern = '^/auditLogs/signIns';                              Permission = 'AuditLog.Read.All';                              Confidence = 'documented'; Note = 'Requires Microsoft Entra ID P1 or P2.' }
    @{ Pattern = '^/security/alerts_v2';                           Permission = 'SecurityAlert.Read.All';                       Confidence = 'documented' }
    @{ Pattern = '^/security/incidents';                           Permission = 'SecurityIncident.Read.All';                    Confidence = 'documented' }
    @{ Pattern = '^/security/attackSimulation';                    Permission = 'AttackSimulation.Read.All';                    Confidence = 'documented'; Note = 'Requires Microsoft Defender for Office 365 Plan 2.' }
    @{ Pattern = '^/security/cases';                               Permission = 'eDiscovery.Read.All';                          Confidence = 'documented'; Note = 'App-only access also requires Microsoft Purview premium eDiscovery (E5 or add-on) and the app in the eDiscoveryManager role group, which can manage cases; not read-only, so not granted. Review eDiscovery cases in the Purview portal instead.' }
    @{ Pattern = '^/admin/serviceAnnouncement/messages';           Permission = 'ServiceMessage.Read.All';                      Confidence = 'documented' }
    @{ Pattern = '^/admin/serviceAnnouncement';                    Permission = 'ServiceHealth.Read.All';                       Confidence = 'documented' }
    @{ Pattern = '^/admin/reportSettings';                         Permission = 'ReportSettings.Read.All';                      Confidence = 'documented' }
    @{ Pattern = '^/solutions/backupRestore';                      Permission = 'BackupRestore-Configuration.Read.All';         Confidence = 'documented'; Note = 'Requires Microsoft 365 Backup to be set up.' }
    @{ Pattern = '^/informationProtection/bitlocker';              Permission = 'BitlockerKey.ReadBasic.All';                   Confidence = 'documented' }
    @{ Pattern = '^/directory/deviceLocalCredentials';             Permission = 'DeviceLocalCredential.ReadBasic.All';          Confidence = 'documented' }
    @{ Pattern = '^/directory/administrativeUnits';                Permission = 'Directory.Read.All';                           Confidence = 'documented' }
    @{ Pattern = '^/deviceManagement/(deviceEnrollmentConfigurations|windowsAutopilot)'; Permission = 'DeviceManagementServiceConfig.Read.All';       Confidence = 'documented'; Note = 'Requires an Intune license in the tenant.' }
    @{ Pattern = '^/deviceManagement/(roleDefinitions|roleAssignments)'; Permission = 'DeviceManagementRBAC.Read.All';                Confidence = 'documented' }
    @{ Pattern = '^/deviceManagement/(deviceHealthScripts|deviceManagementScripts)'; Permission = 'DeviceManagementScripts.Read.All';             Confidence = 'documented'; Note = 'Requires an Intune license in the tenant.' }
    @{ Pattern = '^/deviceManagement/';                            Permission = 'DeviceManagementConfiguration.Read.All';       Confidence = 'documented'; Note = 'Requires an Intune license in the tenant.' }
    @{ Pattern = '^/deviceAppManagement';                          Permission = 'DeviceManagementApps.Read.All';                Confidence = 'documented'; Note = 'Requires an Intune license in the tenant.' }
    @{ Pattern = '^/devices(\?|/|$)';                              Permission = 'Directory.Read.All';                           Confidence = 'documented' }
    @{ Pattern = '^/groups';                                       Permission = 'Directory.Read.All';                           Confidence = 'documented' }
    @{ Pattern = '^/groupSettings';                                Permission = 'Directory.Read.All';                           Confidence = 'documented' }
    @{ Pattern = '^/identity/conditionalAccess';                   Permission = 'Policy.Read.All';                              Confidence = 'documented' }
    @{ Pattern = '^/identityGovernance/accessReviews';             Permission = 'AccessReview.Read.All';                        Confidence = 'documented' }
    @{ Pattern = '^/policies/permissionGrantPolicies';             Permission = 'Policy.Read.PermissionGrant';                  Confidence = 'documented' }
    @{ Pattern = '^/policies/deviceRegistrationPolicy';            Permission = 'Policy.Read.DeviceConfiguration';              Confidence = 'documented' }
    @{ Pattern = '^/policies';                                     Permission = 'Policy.Read.All';                              Confidence = 'documented' }
    @{ Pattern = '^/reports/authenticationMethods';                Permission = 'AuditLog.Read.All';                            Confidence = 'documented'; Note = 'Requires Microsoft Entra ID P1 or P2.' }
)
$script:ExchangePermissionHints = @{
    'Connect-ExchangeOnline'             = 'Exchange.ManageAsApp (Office 365 Exchange Online) + Microsoft Entra role Global Reader on the service principal'
    'Get-ConnectionInformation'          = 'None (local module state)'
    'Get-AcceptedDomain'                 = 'Exchange.ManageAsApp + Global Reader'
    'Get-EXOMailbox'                     = 'Exchange.ManageAsApp + Global Reader'
    'Get-EXORecipient'                   = 'Exchange.ManageAsApp + Global Reader'
    'Get-InboxRule'                      = 'Exchange.ManageAsApp + Global Reader'
    'Get-TransportRule'                  = 'Exchange.ManageAsApp + Global Reader'
    'Get-RemoteDomain'                   = 'Exchange.ManageAsApp + Global Reader'
    'Get-HostedOutboundSpamFilterPolicy' = 'Exchange.ManageAsApp + Global Reader'
    'Get-HostedOutboundSpamFilterRule'   = 'Exchange.ManageAsApp + Global Reader'
    'Get-AdminAuditLogConfig'            = 'Exchange.ManageAsApp + Global Reader'
    'Get-OrganizationConfig'             = 'Exchange.ManageAsApp + Global Reader'
    'Get-DkimSigningConfig'              = 'Exchange.ManageAsApp + Global Reader'
}
$script:PublicHttpsHosts = @('crt.sh', 'rdap.org', 'login.microsoftonline.com', 'cloudflare-dns.com')
$script:PublicUserAgent = 'SecurityOak-HealthCheck/0.1 (read-only domain posture check)'
$script:HostnamePattern = '^(?=.{4,253}$)([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+([A-Za-z]{2,63}|xn--[A-Za-z0-9\-]{1,59})$'
$script:DnsTypeNumbers = @{ A = 1; NS = 2; CNAME = 5; MX = 15; TXT = 16; AAAA = 28; DS = 43; CAA = 257 }
$script:TakeoverSuffixPatterns = @(
    '\.azurewebsites\.net$', '\.cloudapp\.net$', '\.cloudapp\.azure\.com$', '\.trafficmanager\.net$',
    '\.blob\.core\.windows\.net$', '\.web\.core\.windows\.net$', '\.azureedge\.net$', '\.azurefd\.net$',
    '\.azure-api\.net$', '\.azurecontainer\.io$', '\.azurestaticapps\.net$', '\.azurehdinsight\.net$',
    '\.database\.windows\.net$', '\.servicebus\.windows\.net$', '\.search\.windows\.net$', '\.redis\.cache\.windows\.net$',
    '(^|\.)s3\.amazonaws\.com$', '\.s3[\.\-][a-z0-9\-\.]*amazonaws\.com$', '\.s3-website[\.\-][a-z0-9\-\.]*amazonaws\.com$',
    '\.elasticbeanstalk\.com$', '\.cloudfront\.net$', '\.github\.io$', '\.herokuapp\.com$', '\.herokudns\.com$',
    '\.netlify\.app$', '\.pantheonsite\.io$', '\.ghost\.io$', '\.surge\.sh$', '\.bitbucket\.io$', '\.fastly\.net$'
)
$script:Tokens = @{}
$script:TokenClaimRecords = [System.Collections.Generic.List[object]]::new()
$script:EndpointLog = [System.Collections.Generic.List[object]]::new()
