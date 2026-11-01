#region API definitions and permission hints
# Read-only wrappers for the APIs beyond Microsoft Graph and Exchange Online:
# Microsoft Defender for Endpoint, Azure Resource Manager, Security and Compliance PowerShell,
# and the MicrosoftTeams module. The same structural read-only guarantee applies:
#   * Invoke-SecOakApiGet issues HTTP GET only.
#   * Invoke-SecOakReadOnlyPost issues HTTP POST to three allow-listed read-only endpoints only
#     and rejects everything else before any network call.
#   * Invoke-SecOakComplianceGet accepts Get-* cmdlets only; Invoke-SecOakTeamsGet accepts Get-Cs* only.
#
# Facts verified on Microsoft Learn (URLs are cited next to the code that relies on them).

# Token audience and request host per API.
# Defender for Endpoint: the token is requested for https://api.securitycenter.microsoft.com/.default and the
#   requests go to https://api.security.microsoft.com. A token with another audience yields 403.
#   https://learn.microsoft.com/defender-endpoint/api/exposed-apis-create-app-webapp#get-an-access-token
#   https://learn.microsoft.com/defender-endpoint/api/get-machines
# Azure Resource Manager: base https://management.azure.com, every request needs an api-version query string;
#   the client credentials scope is the resource identifier plus /.default.
#   https://learn.microsoft.com/rest/api/azure/#create-the-request
#   https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow#get-a-token
#   https://learn.microsoft.com/entra/identity-platform/scopes-oidc#the-%60default%60-scope
$script:ApiDefinitions = @{
    Graph                = @{ BaseUri = $script:GraphBaseUri; Scope = "$script:GraphBaseUri/.default"; Tool = 'Graph' }
    DefenderEndpoint     = @{ BaseUri = 'https://api.security.microsoft.com'; Scope = 'https://api.securitycenter.microsoft.com/.default'; Tool = 'DefenderEndpoint' }
    AzureResourceManager = @{ BaseUri = 'https://management.azure.com'; Scope = 'https://management.azure.com/.default'; Tool = 'AzureResourceManager' }
}

# Least-privilege application permission hints for Defender for Endpoint paths (first match wins).
# Machine.Read.All: https://learn.microsoft.com/defender-endpoint/api/get-machines
# AdvancedQuery.Read.All: https://learn.microsoft.com/defender-endpoint/api/run-advanced-query-api
$script:DefenderEndpointPermissionHints = @(
    @{ Pattern = '^/api/machines'; Permission = 'Machine.Read.All'; Confidence = 'documented'; Note = '' }
    @{ Pattern = '^/api/advancedqueries/run'; Permission = 'AdvancedQuery.Read.All'; Confidence = 'documented'; Note = 'Defender advanced hunting API retires on 1 February 2027; Graph runHuntingQuery replaces it.' }
    @{ Pattern = '^/api/alerts'; Permission = 'Alert.Read.All'; Confidence = 'likely'; Note = '' }
    @{ Pattern = '^/api/vulnerabilities'; Permission = 'Vulnerability.Read.All'; Confidence = 'likely'; Note = '' }
    @{ Pattern = '^/api/recommendations'; Permission = 'SecurityRecommendation.Read.All'; Confidence = 'likely'; Note = '' }
    @{ Pattern = '^/api/(exposureScore|configurationScore)'; Permission = 'Score.Read.All'; Confidence = 'likely'; Note = '' }
    @{ Pattern = '^/api/software'; Permission = 'Software.Read.All'; Confidence = 'likely'; Note = '' }
)

# Azure Resource Manager authorizes with Azure role-based access control, not application permissions.
$script:AzureResourceManagerPermissionHints = @(
    @{ Pattern = '/providers/Microsoft\.Security/'; Permission = 'Azure RBAC Security Reader (or Reader) role on the subscription'; Confidence = 'likely'; Note = '' }
    @{ Pattern = '/providers/Microsoft\.PolicyInsights/'; Permission = 'Azure RBAC Reader role on the subscription or management group'; Confidence = 'likely'; Note = '' }
    @{ Pattern = '^/subscriptions'; Permission = 'Azure RBAC Reader role on each subscription'; Confidence = 'documented'; Note = 'A service principal without any role assignment sees an empty subscription list.' }
    @{ Pattern = '^/providers/Microsoft\.Management/managementGroups'; Permission = 'Azure RBAC Reader role on the management group'; Confidence = 'likely'; Note = '' }
)

# Cmdlet prefix for the Security and Compliance connection (Get-Label runs as Get-SecOakSccLabel), so its
# cmdlets never shadow Exchange Online cmdlets of the same name in the same session.
$script:CompliancePrefix = 'SecOakScc'

# Security and Compliance PowerShell app-only needs Exchange.ManageAsApp on the Microsoft Exchange Online
# Protection resource (a different resource than Office 365 Exchange Online) plus a directory role on the
# service principal. https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps
$script:CompliancePermissionHintDefault = 'Exchange.ManageAsApp (Microsoft Exchange Online Protection) + Global Reader or Compliance Administrator role (unverified for this cmdlet)'

# MicrosoftTeams app-only authorizes through the directory role assigned to the service principal.
# https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication
$script:TeamsPermissionHintDefault = 'Directory role on the service principal (Global Reader or Teams Administrator; unverified for this cmdlet)'

# Read-only POST allow-list. Anything that does not match one entry exactly is rejected before any network call.
# Graph:    POST /security/runHuntingQuery on v1.0, body { Query } (ThreatHunting.Read.All).
#           https://learn.microsoft.com/graph/api/security-security-runhuntingquery?view=graph-rest-1.0
# Defender: POST /api/advancedqueries/run, body { Query } (AdvancedQuery.Read.All).
#           https://learn.microsoft.com/defender-endpoint/api/run-advanced-query-api
# Azure:    POST {scope}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=... with an
#           empty body, on a subscription or a management group scope. 'latest' is the only allowed value.
#           https://learn.microsoft.com/azure/governance/policy/how-to/get-compliance-data#command-line
$script:ReadOnlyPostAllowList = @(
    @{
        Api        = 'Graph'
        Pattern    = '^/security/runHuntingQuery$'
        BodyKeys   = @('Query')
        Permission = 'ThreatHunting.Read.All'
        Prefix     = '/v1.0'
    }
    @{
        Api        = 'DefenderEndpoint'
        Pattern    = '^/api/advancedqueries/run$'
        BodyKeys   = @('Query')
        Permission = 'AdvancedQuery.Read.All'
        Prefix     = ''
    }
    @{
        Api        = 'AzureResourceManager'
        Pattern    = '^/(subscriptions/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|providers/Microsoft\.Management/managementGroups/[A-Za-z0-9\-_\.\(\)]{1,90})/providers/Microsoft\.PolicyInsights/policyStates/latest/summarize\?api-version=\d{4}-\d{2}-\d{2}$'
        BodyKeys   = @()
        Permission = 'Azure RBAC Reader role on the subscription or management group'
        Prefix     = ''
    }
)
#endregion

function Get-SecOakApiPermissionHint {
    <#
    .SYNOPSIS
        Returns the least-privilege hint for a Defender for Endpoint or Azure Resource Manager path.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][ValidateSet('DefenderEndpoint', 'AzureResourceManager')][string]$Api,
        [Parameter(Mandatory)][string]$Path
    )
    $table = if ($Api -eq 'DefenderEndpoint') { $script:DefenderEndpointPermissionHints } else { $script:AzureResourceManagerPermissionHints }
    foreach ($entry in $table) {
        if ($Path -match $entry.Pattern) {
            $permission = $entry.Permission
            if ($entry.Confidence -ne 'documented') { $permission += ' (unsure: ' + $entry.Confidence + ')' }
            return [pscustomobject]@{ Permission = $permission; Note = [string]$entry.Note }
        }
    }
    [pscustomobject]@{ Permission = 'Unknown (not mapped; check Microsoft Learn)'; Note = '' }
}

function Get-SecOakApiToken {
    <#
    .SYNOPSIS
        Returns a cached or newly acquired app-only token for one API, for internal use only.
    .DESCRIPTION
        Graph reuses the Graph token cache. Defender for Endpoint and Azure Resource Manager use the
        same certificate assertion as Graph with their own scope. Tokens are cached in the module's
        token store (cleared by Disconnect-SecOakSession), never on the context object, so the context
        can be written to disk safely. A token for the wrong tenant is rejected. When the token
        request fails with an Entra error, the API is marked unavailable on the context so later
        calls fail fast without repeating the request.
    .PARAMETER Context
        The run context.
    .PARAMETER Api
        Graph, DefenderEndpoint, or AzureResourceManager.
    .NOTES
        Internal helper. Requires the reader app's certificate in Cert:\CurrentUser\My.
        Client credentials grant: https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow#get-a-token
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidateSet('Graph', 'DefenderEndpoint', 'AzureResourceManager')][string]$Api
    )
    if ($Api -eq 'Graph') { return Get-SecOakAccessToken -Context $Context -Kind App }

    $kind = "App:$Api"
    $cached = $script:Tokens[$kind]
    if ($cached -and $cached.ExpiresOn -gt [datetime]::UtcNow.AddMinutes(5)) { return $cached.Value }

    $state = $Context.ApiState[$Api]
    if ($state -and $state.State -eq 'unavailable') { throw "The $Api token is unavailable: $($state.Reason)" }

    try {
        $issued = Request-SecOakAppToken -Context $Context -Scope $script:ApiDefinitions[$Api].Scope
    }
    catch {
        $message = $_.Exception.Message
        if ($message -match 'AADSTS\d+') {
            $Context.ApiState[$Api] = [pscustomobject]@{ State = 'unavailable'; Reason = $message }
        }
        throw
    }
    $claims = ConvertFrom-SecOakJwtPayload -Token $issued.Value
    if ("$($claims.tid)".ToLowerInvariant() -ne $Context.TenantId) {
        throw "The $Api token was issued for a different tenant than the one configured. Stopping to avoid a wrong-tenant run."
    }
    $script:Tokens[$kind] = @{ Value = $issued.Value; ExpiresOn = $issued.ExpiresOn }
    $Context.ApiState[$Api] = [pscustomobject]@{ State = 'available'; Reason = '' }
    if (-not ($script:TokenClaimRecords | Where-Object Kind -eq $kind)) {
        Register-SecOakTokenClaim -Kind $kind -Claims $claims
    }
    $issued.Value
}

function Invoke-SecOakHttpPost {
    <#
    .SYNOPSIS
        Issues one HTTP POST to an already allow-listed URI with retries on 429, 503, and 504.
    .DESCRIPTION
        Only Invoke-SecOakReadOnlyPost calls this, after the allow-list check. Honors Retry-After,
        otherwise exponential backoff with jitter, maximum 4 retries.
    .NOTES
        Internal helper. POST to allow-listed read-only endpoints only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Token,
        [Parameter()][AllowNull()][string]$JsonBody
    )
    $headers = @{ Authorization = "Bearer $Token" }
    $requestParameters = @{ Method = 'Post'; Uri = $Uri; Headers = $headers; ContentType = 'application/json'; SkipHttpErrorCheck = $true; ErrorAction = 'Stop' }
    if ($JsonBody) { $requestParameters.Body = $JsonBody }
    $maxRetries = 4
    $attempt = 0
    while ($true) {
        $statusCode = 0
        $responseHeaders = $null
        try {
            $body = Invoke-RestMethod @requestParameters -StatusCodeVariable statusCode -ResponseHeadersVariable responseHeaders
        }
        catch {
            return [pscustomobject]@{ StatusCode = 0; Body = $null; Retries = $attempt; ErrorCode = 'NetworkError'; ErrorMessage = $_.Exception.Message }
        }
        if ($statusCode -in 429, 503, 504 -and $attempt -lt $maxRetries) {
            $attempt++
            $delay = 0
            if ($responseHeaders -and $responseHeaders['Retry-After']) { [int]::TryParse("$($responseHeaders['Retry-After'][0])", [ref]$delay) | Out-Null }
            if ($delay -le 0) { $delay = [math]::Pow(2, $attempt) + (Get-Random -Minimum 0 -Maximum 1000) / 1000 }
            Write-Warning "The service returned $statusCode; retry $attempt of $maxRetries in $([math]::Round($delay, 1)) seconds."
            Start-Sleep -Milliseconds ([int]($delay * 1000))
            continue
        }
        $errorCode = $null
        $errorMessage = $null
        if ($statusCode -ge 400) {
            if ($body -and $body.PSObject.Properties['error'] -and $body.error) { $errorCode = $body.error.code; $errorMessage = $body.error.message }
            else { $errorMessage = "$body" }
            if ($errorMessage -and $errorMessage.Length -gt 240) { $errorMessage = $errorMessage.Substring(0, 240) + '...' }
            if (-not $errorMessage) { $errorMessage = "HTTP $statusCode" }
        }
        return [pscustomobject]@{ StatusCode = [int]$statusCode; Body = $body; Retries = $attempt; ErrorCode = $errorCode; ErrorMessage = $errorMessage }
    }
}

function Invoke-SecOakApiGetAttempt {
    <#
    .SYNOPSIS
        Performs a paged GET against one API host and returns the combined result.
    .DESCRIPTION
        Follows @odata.nextLink (Defender for Endpoint, Graph) or nextLink and @nextLink (Azure Resource Manager)
        only when the link points at the same host as the first request.
        Azure Resource Manager paging: https://learn.microsoft.com/rest/api/resources/subscriptions/list
    .NOTES
        Internal helper. GET only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Token,
        [Parameter()][switch]$NoPaging
    )
    $allowedHost = ([uri]$Uri).Host
    $items = [System.Collections.Generic.List[object]]::new()
    $pages = 0
    $retries = 0
    $next = $Uri
    $first = $null
    $partial = $false
    while ($next) {
        $response = Invoke-SecOakHttpGet -Uri $next -Token $Token
        $retries += $response.Retries
        if ($response.StatusCode -lt 200 -or $response.StatusCode -ge 300) {
            if ($pages -eq 0) {
                return [pscustomobject]@{ Success = $false; StatusCode = $response.StatusCode; Items = @(); Body = $null; Pages = 0; Retries = $retries; ErrorCode = $response.ErrorCode; ErrorMessage = $response.ErrorMessage; Partial = $false }
            }
            $partial = $true
            Write-Warning "Paging stopped after $pages pages: $($response.StatusCode) $($response.ErrorMessage)"
            break
        }
        $pages++
        if (-not $first) { $first = $response }
        $body = $response.Body
        $next = $null
        if ($body -and $body.PSObject.Properties['value']) {
            foreach ($item in @($body.value)) { $items.Add($item) }
            if (-not $NoPaging) {
                $link = $null
                foreach ($name in '@odata.nextLink', 'nextLink', '@nextLink') {
                    if ($body.PSObject.Properties[$name] -and $body.$name) { $link = "$($body.$name)"; break }
                }
                if ($link) {
                    $linkHost = try { ([uri]$link).Host } catch { '' }
                    if ($linkHost -eq $allowedHost -and $link -like 'https://*') { $next = $link }
                    else { Write-Warning "Ignored a next link that points at another host."; $partial = $true }
                }
            }
        }
    }
    $isCollection = $first.Body -and $first.Body.PSObject.Properties['value']
    [pscustomobject]@{
        Success      = $true
        StatusCode   = $first.StatusCode
        Items        = if ($isCollection) { $items.ToArray() } else { @() }
        Body         = if ($isCollection) { $null } else { $first.Body }
        Pages        = $pages
        Retries      = $retries
        ErrorCode    = $null
        ErrorMessage = if ($partial) { 'Partial result: paging stopped early.' } else { $null }
        Partial      = $partial
    }
}

function Invoke-SecOakApiGet {
    <#
    .SYNOPSIS
        Read-only GET against Defender for Endpoint or Azure Resource Manager with paging, retries, and logging.
    .DESCRIPTION
        App-only token only (no delegated fallback). Every attempt is written to the endpoint log.
        Failures are recorded as gaps unless -NoGap is set. This function can only issue GET requests.
        When the token for the API is unavailable the call returns Success = $false without throwing.
    .PARAMETER Context
        The run context.
    .PARAMETER Api
        DefenderEndpoint or AzureResourceManager.
    .PARAMETER Area
        Area name for gaps.
    .PARAMETER Check
        Check name for the endpoint log.
    .PARAMETER Path
        Path starting with a slash, including the query string. Defender for Endpoint example:
        /api/machines?$top=100. Azure Resource Manager example (api-version is mandatory):
        /subscriptions?api-version=2022-12-01.
    .PARAMETER NoPaging
        Return the first page only.
    .PARAMETER RawName
        When set, the result is saved to raw\<RawName>.json.
    .PARAMETER NoGap
        Do not record a gap on failure (the caller handles it).
    .OUTPUTS
        Object with Success, StatusCode, Items, Body, Pages, Retries, ErrorCode, ErrorMessage, Partial, AuthUsed, AppOnlyResult.
    .EXAMPLE
        Invoke-SecOakApiGet -Context $context -Api DefenderEndpoint -Area Defender -Check 'Defender/Machines' -Path '/api/machines?$top=100'
    .EXAMPLE
        Invoke-SecOakApiGet -Context $context -Api AzureResourceManager -Area Azure -Check 'Azure/Subscriptions' -Path '/subscriptions?api-version=2022-12-01'
    .NOTES
        Defender for Endpoint: https://learn.microsoft.com/defender-endpoint/api/get-machines
        Azure Resource Manager: https://learn.microsoft.com/rest/api/azure/#create-the-request
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidateSet('DefenderEndpoint', 'AzureResourceManager')][string]$Api,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidatePattern('^/[^\s]*$')][string]$Path,
        [Parameter()][switch]$NoPaging,
        [Parameter()][ValidatePattern('^[a-z0-9\-]+$')][string]$RawName,
        [Parameter()][switch]$NoGap
    )
    $definition = $script:ApiDefinitions[$Api]
    if ($Api -eq 'AzureResourceManager' -and $Path -notmatch '[?&]api-version=') {
        throw 'Azure Resource Manager paths must include the api-version query string.'
    }
    $uri = "$($definition.BaseUri)$Path"
    $result = $null
    try {
        $token = Get-SecOakApiToken -Context $Context -Api $Api
        $result = Invoke-SecOakApiGetAttempt -Uri $uri -Token $token -NoPaging:$NoPaging
    }
    catch {
        $result = [pscustomobject]@{ Success = $false; StatusCode = 0; Items = @(); Body = $null; Pages = 0; Retries = 0; ErrorCode = 'TokenError'; ErrorMessage = $_.Exception.Message; Partial = $false }
    }
    finally { $token = $null }

    $appResult = if ($result.Success) { 'success' } elseif ($result.StatusCode -in 401, 403) { 'forbidden' } else { 'error' }
    $notes = if ($result.Success) { "pages=$($result.Pages); items=$(@($result.Items).Count); retries=$($result.Retries)" } else { "$($result.ErrorCode): $($result.ErrorMessage)" }
    if ($result.Partial) { $notes += '; partial' }
    Add-SecOakEndpointLogEntry -Check $Check -Tool $definition.Tool -Method GET -EndpointOrCmdlet $Path -HttpStatusOrResult "$($result.StatusCode)" `
        -AuthUsed 'app-only' -AppOnlyResult $appResult -Notes $notes
    $result | Add-Member -NotePropertyName AuthUsed -NotePropertyValue 'app-only' -Force
    $result | Add-Member -NotePropertyName AppOnlyResult -NotePropertyValue $appResult -Force

    if ($result.Success -and $RawName) {
        $data = if ($null -ne $result.Body) { $result.Body } else { $result.Items }
        Save-SecOakRawData -Context $Context -Name $RawName -Data $data
    }
    if (-not $result.Success -and -not $NoGap) {
        $hint = Get-SecOakApiPermissionHint -Api $Api -Path $Path
        $fill = if ($Api -eq 'DefenderEndpoint') { "Application permission $($hint.Permission) (Defender for Endpoint API)." } else { "$($hint.Permission)." }
        Add-SecOakGap -Context $Context -Area $Area -Check $Check -EndpointOrCmdlet "$Api $Path" -Result "$($result.StatusCode)" `
            -Reason "$($result.ErrorCode): $($result.ErrorMessage)" -FillWith "$fill $($hint.Note)".Trim()
    }
    $result
}

function Test-SecOakReadOnlyPostRequest {
    <#
    .SYNOPSIS
        Validates a POST request against the allow-list and returns the matching entry.
    .DESCRIPTION
        Throws when the API and path do not match one allow-list entry exactly, when the body has
        keys outside the entry's allowed keys, when a required body key is missing or not a
        non-empty string, or when an entry that expects an empty body receives one. No network call.
    .NOTES
        Internal helper. No permissions required.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][ValidateSet('Graph', 'DefenderEndpoint', 'AzureResourceManager')][string]$Api,
        [Parameter(Mandatory)][string]$Path,
        [Parameter()][AllowNull()][hashtable]$Body
    )
    if ($Path -match '\s|\.\./|//|[\r\n]' -or $Path -notmatch '^/') {
        throw "Read-only POST rejected: the path is malformed."
    }
    $entry = $script:ReadOnlyPostAllowList | Where-Object { $_.Api -eq $Api -and $Path -cmatch $_.Pattern } | Select-Object -First 1
    if (-not $entry) {
        throw "Read-only POST rejected: $Api $Path is not on the allow-list (runHuntingQuery, advancedqueries/run, policyStates/latest/summarize only)."
    }
    $bodyKeys = if ($Body) { @($Body.Keys) } else { @() }
    if ($entry.BodyKeys.Count -eq 0) {
        if ($bodyKeys.Count -gt 0) { throw "Read-only POST rejected: $Api $Path takes an empty body." }
        return $entry
    }
    foreach ($key in $bodyKeys) {
        if ($key -notin $entry.BodyKeys) { throw "Read-only POST rejected: body key '$key' is not allowed for $Api $Path." }
        $value = $Body[$key]
        if ($value -isnot [string] -or [string]::IsNullOrWhiteSpace($value)) { throw "Read-only POST rejected: body key '$key' must be a non-empty string." }
    }
    foreach ($required in $entry.BodyKeys) {
        if ($required -notin $bodyKeys) { throw "Read-only POST rejected: body key '$required' is required for $Api $Path." }
    }
    $entry
}

function Invoke-SecOakReadOnlyPost {
    <#
    .SYNOPSIS
        Approved read-only POST to one of three allow-listed query endpoints, with retries and logging.
    .DESCRIPTION
        The only POST wrapper in the module. It accepts exactly:
          Graph                POST /security/runHuntingQuery (v1.0) with body @{ Query = '<KQL>' }
          DefenderEndpoint     POST /api/advancedqueries/run with body @{ Query = '<KQL>' }
          AzureResourceManager POST /subscriptions/<id>/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=<date>
                               or the same under /providers/Microsoft.Management/managementGroups/<name>, with an empty body
        Everything else throws before any network call. These endpoints run a query and change
        nothing; the endpoint log records each call with Method POST and the note
        "approved read-only POST exception". Items holds the result rows (results, Results, or value).
    .PARAMETER Context
        The run context.
    .PARAMETER Api
        Graph, DefenderEndpoint, or AzureResourceManager.
    .PARAMETER Area
        Area name for gaps.
    .PARAMETER Check
        Check name for the endpoint log.
    .PARAMETER Path
        The allow-listed path (without the Graph version prefix).
    .PARAMETER Body
        Hashtable with the fixed query (Graph and Defender), or $null (Azure Resource Manager).
    .PARAMETER RawName
        When set, the result rows are saved to raw\<RawName>.json.
    .PARAMETER NoGap
        Do not record a gap on failure (the caller handles it).
    .OUTPUTS
        Object with Success, StatusCode, Items, Body, Pages, Retries, ErrorCode, ErrorMessage, Partial, AuthUsed, AppOnlyResult.
    .EXAMPLE
        Invoke-SecOakReadOnlyPost -Context $context -Api Graph -Area Defender -Check 'Defender/Hunt' -Path '/security/runHuntingQuery' -Body @{ Query = 'DeviceInfo | take 1 | project Timestamp' }
    .NOTES
        Graph runHuntingQuery (ThreatHunting.Read.All; 45 calls per minute, 100,000 rows, 3 minute timeout):
          https://learn.microsoft.com/graph/api/security-security-runhuntingquery?view=graph-rest-1.0
        Defender advanced query (AdvancedQuery.Read.All; 45 calls per minute, 1,500 per hour, 100,000 rows):
          https://learn.microsoft.com/defender-endpoint/api/run-advanced-query-api#limitations
        Azure Policy summarize:
          https://learn.microsoft.com/azure/governance/policy/how-to/get-compliance-data#command-line
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidateSet('Graph', 'DefenderEndpoint', 'AzureResourceManager')][string]$Api,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidatePattern('^/')][string]$Path,
        [Parameter()][AllowNull()][hashtable]$Body,
        [Parameter()][ValidatePattern('^[a-z0-9\-]+$')][string]$RawName,
        [Parameter()][switch]$NoGap
    )
    $entry = Test-SecOakReadOnlyPostRequest -Api $Api -Path $Path -Body $Body
    $definition = $script:ApiDefinitions[$Api]
    $logPath = "$($entry.Prefix)$Path"
    $uri = "$($definition.BaseUri)$logPath"
    $jsonBody = if ($entry.BodyKeys.Count -gt 0) { [ordered]@{ Query = $Body['Query'] } | ConvertTo-Json -Compress } else { $null }

    $result = $null
    try {
        $token = Get-SecOakApiToken -Context $Context -Api $Api
        $response = Invoke-SecOakHttpPost -Uri $uri -Token $token -JsonBody $jsonBody
        if ($response.StatusCode -ge 200 -and $response.StatusCode -lt 300) {
            $rows = $null
            $responseBody = $response.Body
            if ($responseBody) {
                foreach ($name in 'results', 'Results', 'value') {
                    $property = $responseBody.PSObject.Properties | Where-Object Name -ceq $name | Select-Object -First 1
                    if ($property) { $rows = @($property.Value); break }
                }
            }
            $result = [pscustomobject]@{
                Success      = $true
                StatusCode   = $response.StatusCode
                Items        = if ($null -ne $rows) { $rows } else { @() }
                Body         = if ($null -eq $rows) { $responseBody } else { $null }
                Pages        = 1
                Retries      = $response.Retries
                ErrorCode    = $null
                ErrorMessage = $null
                Partial      = $false
            }
        }
        else {
            $result = [pscustomobject]@{ Success = $false; StatusCode = $response.StatusCode; Items = @(); Body = $null; Pages = 0; Retries = $response.Retries; ErrorCode = $response.ErrorCode; ErrorMessage = $response.ErrorMessage; Partial = $false }
        }
    }
    catch {
        $result = [pscustomobject]@{ Success = $false; StatusCode = 0; Items = @(); Body = $null; Pages = 0; Retries = 0; ErrorCode = 'TokenError'; ErrorMessage = $_.Exception.Message; Partial = $false }
    }
    finally { $token = $null }

    $appResult = if ($result.Success) { 'success' } elseif ($result.StatusCode -in 401, 403) { 'forbidden' } else { 'error' }
    $notes = if ($result.Success) { "rows=$(@($result.Items).Count); retries=$($result.Retries)" } else { "$($result.ErrorCode): $($result.ErrorMessage)" }
    Add-SecOakEndpointLogEntry -Check $Check -Tool $definition.Tool -Method POST -EndpointOrCmdlet $logPath -HttpStatusOrResult "$($result.StatusCode)" `
        -AuthUsed 'app-only' -AppOnlyResult $appResult -Notes "approved read-only POST exception; $notes"
    $result | Add-Member -NotePropertyName AuthUsed -NotePropertyValue 'app-only' -Force
    $result | Add-Member -NotePropertyName AppOnlyResult -NotePropertyValue $appResult -Force

    if ($result.Success -and $RawName) {
        $data = if ($null -ne $result.Body) { $result.Body } else { $result.Items }
        Save-SecOakRawData -Context $Context -Name $RawName -Data $data
    }
    if (-not $result.Success -and -not $NoGap) {
        $fill = if ($Api -eq 'AzureResourceManager') { "$($entry.Permission)." } else { "Application permission $($entry.Permission)." }
        Add-SecOakGap -Context $Context -Area $Area -Check $Check -EndpointOrCmdlet "$Api POST $logPath" -Result "$($result.StatusCode)" `
            -Reason "$($result.ErrorCode): $($result.ErrorMessage)" -FillWith $fill
    }
    $result
}

function Connect-SecOakCompliance {
    <#
    .SYNOPSIS
        Opens an app-only Security and Compliance PowerShell connection next to any Exchange Online one.
    .DESCRIPTION
        Uses Connect-IPPSSession with the certificate thumbprint and a cmdlet prefix, so the
        compliance cmdlets never collide with Exchange Online cmdlets of the same name in this
        session. The connected tenant is verified against the configured tenant ID. On any failure
        (module missing, no certificate, sign-in refused, wrong tenant) a gap is recorded, the API is
        marked unavailable, and the function returns 'none' without throwing.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        The connection mode string: scc-app or none.
    .EXAMPLE
        Connect-SecOakCompliance -Context $context
    .NOTES
        Requires ExchangeOnlineManagement 3.x. App-only needs Exchange.ManageAsApp on the Microsoft
        Exchange Online Protection resource plus a directory role on the service principal.
        https://learn.microsoft.com/powershell/exchange/app-only-auth-powershell-v2?view=exchange-ps
        https://learn.microsoft.com/powershell/module/exchangepowershell/connect-ippssession?view=exchange-ps
        Coexistence with Connect-ExchangeOnline (Get-ConnectionInformation, IsEopSession, ConnectionId):
        https://learn.microsoft.com/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#rest-api-connections-in-the-exo-v3-module
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    if ($Context.ComplianceMode -ne 'none') { return $Context.ComplianceMode }
    $area = 'Purview'
    $check = 'Purview/Connect'
    $failure = $null
    try {
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) { throw 'The ExchangeOnlineManagement module is not installed.' }
        Import-Module ExchangeOnlineManagement -ErrorAction Stop -Verbose:$false
        if ($Context.CredentialType -ne 'Certificate') { throw 'Security and Compliance app-only access requires a certificate; the app is configured with a secret.' }
        if (-not $Context.InitialDomain) { throw 'The initial domain is unknown; run Get-SecOakTenantIdentity first or set InitialDomain in the config.' }

        $connectParameters = @{
            AppId                 = $Context.AppId
            CertificateThumbprint = $Context.CertificateThumbprint
            Organization          = $Context.InitialDomain
            Prefix                = $script:CompliancePrefix
            ShowBanner            = $false
            ErrorAction           = 'Stop'
        }
        Connect-IPPSSession @connectParameters | Out-Null
        $connection = Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' -and $_.ModulePrefix -eq $script:CompliancePrefix } | Select-Object -Last 1
        if (-not $connection) { throw 'Connect-IPPSSession returned without a connected session.' }
        if ("$($connection.TenantID)".ToLowerInvariant() -ne $Context.TenantId) {
            Disconnect-ExchangeOnline -ConnectionId $connection.ConnectionId -Confirm:$false -ErrorAction SilentlyContinue
            throw 'Security and Compliance PowerShell connected to a different tenant than the one configured. Disconnected.'
        }
        $Context.ComplianceConnectionId = "$($connection.ConnectionId)"
        $Context.ComplianceMode = 'scc-app'
        $Context.ApiState['Compliance'] = [pscustomobject]@{ State = 'available'; Reason = '' }
        Add-SecOakEndpointLogEntry -Check $check -Tool Compliance -Method Connect -EndpointOrCmdlet 'Connect-IPPSSession' -HttpStatusOrResult 'connected' `
            -AuthUsed 'scc-app' -AppOnlyResult 'success'
        return 'scc-app'
    }
    catch {
        $failure = ($_.Exception.Message -replace '\s+', ' ')
    }
    if ($failure.Length -gt 240) { $failure = $failure.Substring(0, 240) + '...' }
    $Context.ApiState['Compliance'] = [pscustomobject]@{ State = 'unavailable'; Reason = $failure }
    Add-SecOakEndpointLogEntry -Check $check -Tool Compliance -Method Connect -EndpointOrCmdlet 'Connect-IPPSSession' -HttpStatusOrResult 'failed' `
        -AuthUsed 'scc-app' -AppOnlyResult 'forbidden' -Notes $failure
    Add-SecOakGap -Context $Context -Area $area -Check $check -EndpointOrCmdlet 'Connect-IPPSSession' -Result 'failed' -Reason $failure `
        -FillWith $script:CompliancePermissionHintDefault
    'none'
}

function Disconnect-SecOakCompliance {
    <#
    .SYNOPSIS
        Disconnects the Security and Compliance PowerShell connection this module opened, and only that one.
    .PARAMETER Context
        The run context.
    .NOTES
        Requires ExchangeOnlineManagement. Disconnect-ExchangeOnline -ConnectionId:
        https://learn.microsoft.com/powershell/module/exchangepowershell/disconnect-exchangeonline?view=exchange-ps
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    if ($Context.ComplianceMode -ne 'none') {
        try {
            if ($Context.ComplianceConnectionId) { Disconnect-ExchangeOnline -ConnectionId $Context.ComplianceConnectionId -Confirm:$false -ErrorAction Stop | Out-Null }
            else { Disconnect-ExchangeOnline -ModulePrefix $script:CompliancePrefix -Confirm:$false -ErrorAction Stop | Out-Null }
        }
        catch { Write-Warning "Security and Compliance disconnect reported: $($_.Exception.Message)" }
        $Context.ComplianceMode = 'none'
        $Context.ComplianceConnectionId = ''
    }
}

function Invoke-SecOakComplianceGet {
    <#
    .SYNOPSIS
        Runs one read-only Security and Compliance PowerShell Get-* cmdlet and logs it.
    .DESCRIPTION
        Rejects any cmdlet not named Get-*. The cmdlet is resolved through the connection's prefix
        (Get-Label runs as Get-<prefix>Label), so it always targets the compliance connection. A
        cmdlet missing from the session (role-based access control hides cmdlets the caller cannot
        run) or an access-denied error is classified as forbidden. Without a connection the call
        returns Success = $false and records a gap; it never throws.
    .PARAMETER Context
        The run context.
    .PARAMETER Area
        Area name for gaps.
    .PARAMETER Check
        Check name for the endpoint log.
    .PARAMETER Cmdlet
        The Get-* cmdlet name as documented (without the prefix), for example Get-Label.
    .PARAMETER Parameters
        Splatted parameters.
    .PARAMETER NoGap
        Do not record a gap on failure (the caller handles it).
    .OUTPUTS
        Object with Success, Forbidden, Data, ErrorMessage.
    .EXAMPLE
        Invoke-SecOakComplianceGet -Context $context -Area Purview -Check 'Purview/Labels' -Cmdlet Get-Label
    .NOTES
        Requires a connection opened by Connect-SecOakCompliance.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidatePattern('^Get-[A-Za-z0-9]+$')][string]$Cmdlet,
        [Parameter()][hashtable]$Parameters = @{},
        [Parameter()][switch]$NoGap
    )
    $success = $false
    $forbidden = $false
    $data = $null
    $message = $null
    if ($Context.ComplianceMode -ne 'scc-app') {
        $state = $Context.ApiState['Compliance']
        $message = if ($state -and $state.Reason) { "No Security and Compliance connection: $($state.Reason)" } else { 'No Security and Compliance connection (Connect-SecOakCompliance was not run).' }
        $forbidden = $true
    }
    else {
        $prefixed = $Cmdlet -replace '^Get-', "Get-$script:CompliancePrefix"
        try {
            if (-not (Get-Command -Name $prefixed -ErrorAction SilentlyContinue)) {
                throw [System.Management.Automation.CommandNotFoundException]::new("$Cmdlet is not available in this session (not granted by role-based access control).")
            }
            $data = @(& $prefixed @Parameters -ErrorAction Stop)
            $success = $true
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            $forbidden = $true
            $message = $_.Exception.Message
        }
        catch {
            $message = ($_.Exception.Message -replace '\s+', ' ')
            if ($message -match 'access ?denied|not authorized|unauthorized|forbidden|permission|isn''t within your current write scope|RBAC|role assignment') { $forbidden = $true }
        }
    }
    if ($message -and $message.Length -gt 240) { $message = $message.Substring(0, 240) + '...' }

    $appColumn = if ($success) { 'success' } elseif ($forbidden) { 'forbidden' } else { 'error' }
    $resultText = if ($success) { "ok ($(@($data).Count) objects)" } elseif ($forbidden) { 'forbidden' } else { 'error' }
    Add-SecOakEndpointLogEntry -Check $Check -Tool Compliance -Method 'Invoke' -EndpointOrCmdlet $Cmdlet -HttpStatusOrResult $resultText `
        -AuthUsed $(if ($Context.ComplianceMode -eq 'none') { 'none' } else { 'scc-app' }) -AppOnlyResult $appColumn -Notes "$message"
    if (-not $success -and -not $NoGap) {
        Add-SecOakGap -Context $Context -Area $Area -Check $Check -EndpointOrCmdlet $Cmdlet -Result $resultText -Reason "$message" `
            -FillWith $script:CompliancePermissionHintDefault
    }
    [pscustomobject]@{ Success = $success; Forbidden = $forbidden; Data = $data; ErrorMessage = $message }
}

function Connect-SecOakTeams {
    <#
    .SYNOPSIS
        Opens an app-only MicrosoftTeams PowerShell connection.
    .DESCRIPTION
        Uses Connect-MicrosoftTeams with the certificate (thumbprint when the installed module still
        offers that parameter, otherwise the certificate object from Cert:\CurrentUser\My; the
        private key stays in the store). The connected tenant is verified against the configured
        tenant ID. On any failure a gap is recorded, the API is marked unavailable, and the function
        returns 'none' without throwing.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        The connection mode string: teams-app or none.
    .EXAMPLE
        Connect-SecOakTeams -Context $context
    .NOTES
        Requires the MicrosoftTeams module (4.7.1-preview or later for application authentication).
        Authorization comes from the directory role assigned to the service principal.
        https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication
        https://learn.microsoft.com/powershell/module/microsoftteams/connect-microsoftteams?view=teams-ps
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    if ($Context.TeamsMode -ne 'none') { return $Context.TeamsMode }
    $area = 'Teams'
    $check = 'Teams/Connect'
    $failure = $null
    try {
        if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) { throw 'The MicrosoftTeams module is not installed. Install-PSResource MicrosoftTeams -Scope CurrentUser' }
        Import-Module MicrosoftTeams -ErrorAction Stop -Verbose:$false
        if ($Context.CredentialType -ne 'Certificate') { throw 'Teams app-only access requires a certificate; the app is configured with a secret.' }

        $connectParameters = @{ ApplicationId = $Context.AppId; TenantId = $Context.TenantId; ErrorAction = 'Stop' }
        $command = Get-Command -Name Connect-MicrosoftTeams -ErrorAction Stop
        if ($command.Parameters.ContainsKey('CertificateThumbprint')) {
            $connectParameters.CertificateThumbprint = $Context.CertificateThumbprint
        }
        else {
            $certificate = Get-Item -Path "Cert:\CurrentUser\My\$($Context.CertificateThumbprint)" -ErrorAction SilentlyContinue
            if (-not $certificate) { throw 'Certificate with the configured thumbprint was not found in Cert:\CurrentUser\My.' }
            $connectParameters.Certificate = $certificate
        }
        $account = Connect-MicrosoftTeams @connectParameters
        $connectedTenant = if ($account -and $account.PSObject.Properties['TenantId']) { "$($account.TenantId)".ToLowerInvariant() } else { '' }
        if ($connectedTenant -ne $Context.TenantId) {
            Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction SilentlyContinue
            throw 'Teams connected to a different tenant than the one configured (or reported none). Disconnected.'
        }
        $Context.TeamsMode = 'teams-app'
        $Context.ApiState['Teams'] = [pscustomobject]@{ State = 'available'; Reason = '' }
        Add-SecOakEndpointLogEntry -Check $check -Tool Teams -Method Connect -EndpointOrCmdlet 'Connect-MicrosoftTeams' -HttpStatusOrResult 'connected' `
            -AuthUsed 'teams-app' -AppOnlyResult 'success'
        return 'teams-app'
    }
    catch {
        $failure = ($_.Exception.Message -replace '\s+', ' ')
    }
    if ($failure.Length -gt 240) { $failure = $failure.Substring(0, 240) + '...' }
    $Context.ApiState['Teams'] = [pscustomobject]@{ State = 'unavailable'; Reason = $failure }
    Add-SecOakEndpointLogEntry -Check $check -Tool Teams -Method Connect -EndpointOrCmdlet 'Connect-MicrosoftTeams' -HttpStatusOrResult 'failed' `
        -AuthUsed 'teams-app' -AppOnlyResult 'forbidden' -Notes $failure
    Add-SecOakGap -Context $Context -Area $area -Check $check -EndpointOrCmdlet 'Connect-MicrosoftTeams' -Result 'failed' -Reason $failure `
        -FillWith $script:TeamsPermissionHintDefault
    'none'
}

function Disconnect-SecOakTeams {
    <#
    .SYNOPSIS
        Disconnects the MicrosoftTeams session if this module connected it.
    .PARAMETER Context
        The run context.
    .NOTES
        Requires the MicrosoftTeams module.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][pscustomobject]$Context)
    if ($Context.TeamsMode -ne 'none') {
        try { Disconnect-MicrosoftTeams -Confirm:$false -ErrorAction Stop | Out-Null }
        catch { Write-Warning "Teams disconnect reported: $($_.Exception.Message)" }
        $Context.TeamsMode = 'none'
    }
}

function Invoke-SecOakTeamsGet {
    <#
    .SYNOPSIS
        Runs one read-only MicrosoftTeams Get-Cs* cmdlet and logs it.
    .DESCRIPTION
        Rejects any cmdlet not named Get-Cs*. A cmdlet missing from the module or an access-denied
        error is classified as forbidden. Without a connection the call returns Success = $false and
        records a gap; it never throws.
    .PARAMETER Context
        The run context.
    .PARAMETER Area
        Area name for gaps.
    .PARAMETER Check
        Check name for the endpoint log.
    .PARAMETER Cmdlet
        The Get-Cs* cmdlet name, for example Get-CsTenant.
    .PARAMETER Parameters
        Splatted parameters.
    .PARAMETER NoGap
        Do not record a gap on failure (the caller handles it).
    .OUTPUTS
        Object with Success, Forbidden, Data, ErrorMessage.
    .EXAMPLE
        Invoke-SecOakTeamsGet -Context $context -Area Teams -Check 'Teams/Tenant' -Cmdlet Get-CsTenant
    .NOTES
        Requires a connection opened by Connect-SecOakTeams. Cmdlets not supported with application
        authentication are listed at
        https://learn.microsoft.com/microsoftteams/teams-powershell-application-authentication
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidatePattern('^Get-Cs[A-Za-z]+$')][string]$Cmdlet,
        [Parameter()][hashtable]$Parameters = @{},
        [Parameter()][switch]$NoGap
    )
    $success = $false
    $forbidden = $false
    $data = $null
    $message = $null
    if ($Context.TeamsMode -ne 'teams-app') {
        $state = $Context.ApiState['Teams']
        $message = if ($state -and $state.Reason) { "No Teams connection: $($state.Reason)" } else { 'No Teams connection (Connect-SecOakTeams was not run).' }
        $forbidden = $true
    }
    else {
        try {
            $command = Get-Command -Name $Cmdlet -Module MicrosoftTeams -ErrorAction SilentlyContinue
            if (-not $command) {
                throw [System.Management.Automation.CommandNotFoundException]::new("$Cmdlet is not available in the MicrosoftTeams module.")
            }
            $data = @(& $command @Parameters -ErrorAction Stop)
            $success = $true
        }
        catch [System.Management.Automation.CommandNotFoundException] {
            $forbidden = $true
            $message = $_.Exception.Message
        }
        catch {
            $message = ($_.Exception.Message -replace '\s+', ' ')
            if ($message -match 'access ?denied|not authorized|unauthorized|forbidden|permission|insufficient|not supported|RBAC|role') { $forbidden = $true }
        }
    }
    if ($message -and $message.Length -gt 240) { $message = $message.Substring(0, 240) + '...' }

    $appColumn = if ($success) { 'success' } elseif ($forbidden) { 'forbidden' } else { 'error' }
    $resultText = if ($success) { "ok ($(@($data).Count) objects)" } elseif ($forbidden) { 'forbidden' } else { 'error' }
    Add-SecOakEndpointLogEntry -Check $Check -Tool Teams -Method 'Invoke' -EndpointOrCmdlet $Cmdlet -HttpStatusOrResult $resultText `
        -AuthUsed $(if ($Context.TeamsMode -eq 'none') { 'none' } else { 'teams-app' }) -AppOnlyResult $appColumn -Notes "$message"
    if (-not $success -and -not $NoGap) {
        Add-SecOakGap -Context $Context -Area $Area -Check $Check -EndpointOrCmdlet $Cmdlet -Result $resultText -Reason "$message" `
            -FillWith $script:TeamsPermissionHintDefault
    }
    [pscustomobject]@{ Success = $success; Forbidden = $forbidden; Data = $data; ErrorMessage = $message }
}
