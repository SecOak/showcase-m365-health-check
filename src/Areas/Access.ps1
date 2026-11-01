function Invoke-SecOakAccessAudit {
    <#
    .SYNOPSIS
        Self-audit of the Security Oak reader app: permissions, roles, credentials, owners,
        audience, sign-ins, and delegated grants. Report only; never changes the app.
    .PARAMETER Context
        The run context.
    .EXAMPLE
        Invoke-SecOakAccessAudit -Context $context
    .NOTES
        Application permissions: Directory.Read.All, RoleManagement.Read.Directory,
        AuditLog.Read.All (sign-ins, Entra ID P1).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $area = 'Security Oak access'
    $findings = [System.Collections.Generic.List[object]]::new()
    $summary = [ordered]@{}
    $check = 'Access/SelfAudit'
    $now = [datetime]::UtcNow

    $application = Invoke-SecOakGraphGet -Context $Context -Area $area -Check $check `
        -Path ("/applications?`$filter=appId eq '{0}'&`$select=id,appId,displayName,signInAudience,keyCredentials,passwordCredentials,requiredResourceAccess" -f $Context.AppId) -RawName 'access-application'
    $app = if ($application.Success) { $application.Items | Select-Object -First 1 } else { $null }
    $sp = Get-SecOakOwnServicePrincipal -Context $Context -Check $check

    if ($app) { $summary.displayName = $app.displayName; $summary.signInAudience = $app.signInAudience }
    if ($app -and $app.signInAudience -ne 'AzureADMyOrg') {
        $findings.Add((New-SecOakFinding -Id 'ACCESS-01' -Area $area -Severity High -BaselineControl 'None' `
                    -Title 'Security Oak app is not single tenant' `
                    -Evidence ([ordered]@{ signInAudience = $app.signInAudience }) `
                    -Risk 'A multi-tenant registration can be consented into other tenants, widening where its credential works.' `
                    -Recommendation 'Change the supported account types to "Accounts in this organizational directory only".'))
    }

    #--- Granted application permissions
    $tokenRoles = @(($script:TokenClaimRecords | Where-Object Kind -eq 'App' | Select-Object -First 1).Roles)
    if ($sp) {
        $assignments = Invoke-SecOakGraphGet -Context $Context -Area $area -Check $check -Path "/servicePrincipals/$($sp.id)/appRoleAssignments" -RawName 'access-app-role-assignments'
        if ($assignments.Success) {
            $granted = foreach ($assignment in $assignments.Items) {
                $map = Get-SecOakResourceAppRoleMap -Context $Context -Area $area -Check $check -ResourceServicePrincipalId $assignment.resourceId
                $name = $map.Roles[$assignment.appRoleId]
                [pscustomobject]@{ Resource = $assignment.resourceDisplayName; Permission = $name; Risk = Get-SecOakPermissionRisk -Permission "$name" }
            }
            $granted = @($granted)
            $summary.grantedPermissions = @($granted | ForEach-Object { '{0}: {1}' -f $_.Resource, $_.Permission } | Sort-Object)
            $flagged = @($granted | Where-Object Risk -eq 'Write')
            if ($flagged.Count) {
                $findings.Add((New-SecOakFinding -Id 'ACCESS-02' -Area $area -Severity High -BaselineControl 'None' `
                            -Title 'Security Oak app holds write or manage permissions' `
                            -Evidence ([ordered]@{ permissions = @($flagged | ForEach-Object { '{0}: {1}' -f $_.Resource, $_.Permission }) }) `
                            -Risk 'The health check only reads. Any write permission is unnecessary access that would be abused if the certificate leaked.' `
                            -Recommendation 'Remove these permissions from the app registration and revoke their admin consent.'))
            }
            $graphGranted = @($granted | Where-Object Resource -eq 'Microsoft Graph' | Select-Object -ExpandProperty Permission)
            $summary.tokenRolesNotInGrants = @($tokenRoles | Where-Object { $_ -notin $graphGranted })
        }
    }
    else {
        $summary.servicePrincipal = 'not found or unreadable'
    }

    #--- Directory roles
    if ($sp) {
        $roles = Invoke-SecOakGraphGet -Context $Context -Area $area -Check $check -Path ("/roleManagement/directory/roleAssignments?`$filter=principalId eq '{0}'&`$expand=roleDefinition" -f $sp.id) -RawName 'access-directory-roles'
        if ($roles.Success) {
            $roleNames = @($roles.Items | ForEach-Object { $_.roleDefinition.displayName })
            $summary.directoryRoles = $roleNames
            $extra = @($roleNames | Where-Object { $_ -ne 'Global Reader' })
            if ($extra.Count) {
                $findings.Add((New-SecOakFinding -Id 'ACCESS-03' -Area $area -Severity $(if ($extra -contains 'Global Administrator') { 'Critical' } else { 'High' }) -BaselineControl 'None' `
                            -Title 'Security Oak app holds directory roles beyond Global Reader' `
                            -Evidence ([ordered]@{ roles = $extra }) `
                            -Risk 'A role beyond read-only lets the app change the tenant, which the health check never needs.' `
                            -Recommendation 'Remove every directory role from the service principal except Global Reader.'))
            }
        }
    }

    #--- Credentials
    $credentials = [System.Collections.Generic.List[object]]::new()
    foreach ($owner in @(@{ Name = 'application'; Object = $app }, @{ Name = 'servicePrincipal'; Object = $sp })) {
        if (-not $owner.Object) { continue }
        foreach ($key in @($owner.Object.keyCredentials)) { if ($key) { $credentials.Add([pscustomobject]@{ On = $owner.Name; Type = 'certificate'; Name = $key.displayName; Expires = ConvertTo-SecOakUtcDate $key.endDateTime }) } }
        foreach ($secret in @($owner.Object.passwordCredentials)) { if ($secret) { $credentials.Add([pscustomobject]@{ On = $owner.Name; Type = 'secret'; Name = $secret.displayName; Expires = ConvertTo-SecOakUtcDate $secret.endDateTime }) } }
    }
    $summary.credentials = @($credentials | ForEach-Object { '{0} on {1}, expires {2:yyyy-MM-dd}' -f $_.Type, $_.On, $_.Expires })
    $secrets = @($credentials | Where-Object Type -eq 'secret')
    $expired = @($credentials | Where-Object { $_.Expires -and $_.Expires -lt $now })
    $expiring = @($credentials | Where-Object { $_.Expires -and $_.Expires -ge $now -and $_.Expires -lt $now.AddDays(60) })
    if ($secrets.Count) {
        $findings.Add((New-SecOakFinding -Id 'ACCESS-04' -Area $area -Severity Medium -BaselineControl 'None' `
                    -Title 'Security Oak app has client secrets' `
                    -Evidence ([ordered]@{ secrets = $secrets.Count; on = @($secrets.On | Select-Object -Unique) }) `
                    -Risk 'A secret is a password that can be copied and used from anywhere. Certificates with non-exportable keys are much harder to steal.' `
                    -Recommendation 'Switch to certificate authentication and remove the secrets.'))
    }
    if ($expired.Count) {
        $findings.Add((New-SecOakFinding -Id 'ACCESS-05' -Area $area -Severity Low -BaselineControl 'None' `
                    -Title 'Security Oak app has expired credentials' `
                    -Evidence ([ordered]@{ expired = $expired.Count; examples = (Select-SecOakExample @($expired | ForEach-Object { '{0} on {1}, expired {2:yyyy-MM-dd}' -f $_.Type, $_.On, $_.Expires })) }) `
                    -Risk 'Expired credentials are clutter that hides which credential is actually in use.' `
                    -Recommendation 'Remove expired credentials from the app registration.'))
    }
    if ($expiring.Count) {
        $findings.Add((New-SecOakFinding -Id 'ACCESS-06' -Area $area -Severity Medium -BaselineControl 'None' `
                    -Title 'Security Oak app credential expires within 60 days' `
                    -Evidence ([ordered]@{ expiring = $expiring.Count; examples = (Select-SecOakExample @($expiring | ForEach-Object { '{0} on {1}, expires {2:yyyy-MM-dd}' -f $_.Type, $_.On, $_.Expires })) }) `
                    -Risk 'Health checks will stop working when the credential expires.' `
                    -Recommendation 'Create a new certificate, add it to the app, confirm a run works, then remove the old one.'))
    }

    #--- Owners
    $ownerNames = @()
    if ($app) {
        $appOwners = Invoke-SecOakGraphGet -Context $Context -Area $area -Check $check -Path "/applications/$($app.id)/owners?`$select=id,displayName,userPrincipalName"
        if ($appOwners.Success) { $ownerNames += @($appOwners.Items | ForEach-Object { "application: $(if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName })" }) }
    }
    if ($sp) {
        $spOwners = Invoke-SecOakGraphGet -Context $Context -Area $area -Check $check -Path "/servicePrincipals/$($sp.id)/owners?`$select=id,displayName,userPrincipalName"
        if ($spOwners.Success) { $ownerNames += @($spOwners.Items | ForEach-Object { "servicePrincipal: $(if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName })" }) }
    }
    $summary.owners = $ownerNames
    if ($app -and -not $ownerNames) {
        $findings.Add((New-SecOakFinding -Id 'ACCESS-07' -Area $area -Severity Low -BaselineControl 'None' `
                    -Title 'Security Oak app has no owners' `
                    -Evidence ([ordered]@{ owners = 0 }) `
                    -Risk 'Nobody in the tenant is on record as accountable for the app.' `
                    -Recommendation 'Add a named administrator as owner of the application object (admin account, not an everyday account).'))
    }

    #--- Delegated permission grants
    if ($sp) {
        $grants = Invoke-SecOakGraphGet -Context $Context -Area $area -Check $check -Path ("/oauth2PermissionGrants?`$filter=clientId eq '{0}'" -f $sp.id) -RawName 'access-delegated-grants'
        if ($grants.Success) {
            $summary.delegatedGrants = @($grants.Items | ForEach-Object { '{0}: {1}' -f $_.consentType, $_.scope.Trim() })
            if (@($grants.Items).Count) {
                $findings.Add((New-SecOakFinding -Id 'ACCESS-08' -Area $area -Severity Medium -BaselineControl 'None' `
                            -Title 'Security Oak app has delegated permission grants' `
                            -Evidence ([ordered]@{ grants = @($grants.Items).Count; scopes = $summary.delegatedGrants }) `
                            -Risk 'The reader app is designed for app-only use. Delegated grants let it act as signed-in users, which it does not need.' `
                            -Recommendation 'Revoke the delegated grants and remove delegated permissions from the app registration.'))
            }
        }
    }

    #--- Recent service principal sign-ins
    $since = $now.AddDays(-30).ToString('yyyy-MM-ddTHH:mm:ssZ')
    $signIns = Invoke-SecOakGraphGet -Context $Context -Area $area -Check $check -ApiVersion beta -NoPaging -RawName 'access-service-principal-sign-ins' `
        -Path ("/auditLogs/signIns?`$filter=appId eq '{0}' and createdDateTime ge {1} and signInEventTypes/any(t: t eq 'servicePrincipal')&`$top=50" -f $Context.AppId, $since)
    if ($signIns.Success) {
        $summary.servicePrincipalSignInsLast30Days = [ordered]@{
            returned  = @($signIns.Items).Count
            failures  = @($signIns.Items | Where-Object { $_.status.errorCode -ne 0 }).Count
            ipAddresses = @($signIns.Items.ipAddress | Select-Object -Unique | Select-Object -First 5)
        }
    }

    foreach ($finding in $findings) { $Context.Findings.Add($finding) }
    $Context.AreaSummaries[$area] = $summary
    [pscustomobject]@{ Area = $area; Summary = $summary; Findings = $findings.ToArray() }
}
