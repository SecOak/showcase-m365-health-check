function Invoke-SecOakHttpGet {
    <#
    .SYNOPSIS
        Issues one HTTP GET with retries on 429, 503, and 504.
    .DESCRIPTION
        Honors Retry-After, otherwise exponential backoff with jitter, maximum 4 retries.
    .NOTES
        Internal helper. GET only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Token,
        [Parameter()][switch]$ConsistencyLevelEventual
    )
    $headers = @{ Authorization = "Bearer $Token" }
    if ($ConsistencyLevelEventual) { $headers.ConsistencyLevel = 'eventual' }
    $maxRetries = 4
    $attempt = 0
    while ($true) {
        $statusCode = 0
        $responseHeaders = $null
        try {
            $body = Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers -SkipHttpErrorCheck `
                -StatusCodeVariable statusCode -ResponseHeadersVariable responseHeaders -ErrorAction Stop
        }
        catch {
            return [pscustomobject]@{ StatusCode = 0; Body = $null; Retries = $attempt; ErrorCode = 'NetworkError'; ErrorMessage = $_.Exception.Message }
        }
        if ($statusCode -in 429, 503, 504 -and $attempt -lt $maxRetries) {
            $attempt++
            $delay = 0
            if ($responseHeaders -and $responseHeaders['Retry-After']) { [int]::TryParse("$($responseHeaders['Retry-After'][0])", [ref]$delay) | Out-Null }
            if ($delay -le 0) { $delay = [math]::Pow(2, $attempt) + (Get-Random -Minimum 0 -Maximum 1000) / 1000 }
            Write-Warning "Graph returned $statusCode; retry $attempt of $maxRetries in $([math]::Round($delay, 1)) seconds."
            Start-Sleep -Milliseconds ([int]($delay * 1000))
            continue
        }
        $errorCode = $null
        $errorMessage = $null
        if ($statusCode -ge 400) {
            if ($body -and $body.error) { $errorCode = $body.error.code; $errorMessage = $body.error.message }
            else { $errorMessage = "$body" }
            if ($errorMessage -and $errorMessage.Length -gt 240) { $errorMessage = $errorMessage.Substring(0, 240) + '...' }
            if (-not $errorMessage) { $errorMessage = "HTTP $statusCode" }
        }
        return [pscustomobject]@{ StatusCode = [int]$statusCode; Body = $body; Retries = $attempt; ErrorCode = $errorCode; ErrorMessage = $errorMessage }
    }
}

function Invoke-SecOakGraphGetAttempt {
    <#
    .SYNOPSIS
        Performs a paged GET with one token and returns the combined result.
    .NOTES
        Internal helper. GET only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Token,
        [Parameter()][switch]$ConsistencyLevelEventual,
        [Parameter()][switch]$NoPaging
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $pages = 0
    $retries = 0
    $next = $Uri
    $first = $null
    $partial = $false
    while ($next) {
        $response = Invoke-SecOakHttpGet -Uri $next -Token $Token -ConsistencyLevelEventual:$ConsistencyLevelEventual
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
        if ($body -and $body.PSObject.Properties['value']) {
            foreach ($item in @($body.value)) { $items.Add($item) }
            $next = if ($NoPaging) { $null } else { $body.'@odata.nextLink' }
        }
        else { $next = $null }
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

function Invoke-SecOakGraphGet {
    <#
    .SYNOPSIS
        Read-only Microsoft Graph GET with paging, throttling retries, app-first auth, and logging.
    .DESCRIPTION
        Tries the app-only token first. On 401 or 403, and when the run allows it, retries
        with the Azure CLI delegated token. Every attempt is written to the endpoint log.
        Final failures are recorded as gaps. This function can only issue GET requests.
    .PARAMETER Context
        The run context.
    .PARAMETER Area
        Area name for gaps.
    .PARAMETER Check
        Check name for the endpoint log.
    .PARAMETER Path
        Graph path starting with a slash, including any query string, for example
        /users?$select=id.
    .PARAMETER ApiVersion
        v1.0 (default) or beta.
    .PARAMETER ConsistencyLevelEventual
        Adds the ConsistencyLevel: eventual header for advanced queries.
    .PARAMETER NoPaging
        Return the first page only.
    .PARAMETER RawName
        When set, the result is saved to raw\<RawName>.json.
    .PARAMETER NoGap
        Do not record a gap on failure (the caller handles it).
    .OUTPUTS
        Object with Success, StatusCode, AuthUsed, AppOnlyResult, Items, Body, ErrorCode, ErrorMessage.
    .EXAMPLE
        Invoke-SecOakGraphGet -Context $context -Area Identity -Check 'Identity/Guests' -Path '/policies/authorizationPolicy'
    .NOTES
        Permissions: depends on the endpoint; see the LeastPrivilegeAppPermission column.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][ValidatePattern('^/')][string]$Path,
        [Parameter()][ValidateSet('v1.0', 'beta')][string]$ApiVersion = 'v1.0',
        [Parameter()][switch]$ConsistencyLevelEventual,
        [Parameter()][switch]$NoPaging,
        [Parameter()][ValidatePattern('^[a-z0-9\-]+$')][string]$RawName,
        [Parameter()][switch]$NoGap
    )
    $uri = "$script:GraphBaseUri/$ApiVersion$Path"
    $logPath = "/$ApiVersion$Path"
    $appResult = 'not attempted'
    $result = $null

    if ($Context.AppTokenAvailable) {
        try {
            $token = Get-SecOakAccessToken -Context $Context -Kind App
            $result = Invoke-SecOakGraphGetAttempt -Uri $uri -Token $token -ConsistencyLevelEventual:$ConsistencyLevelEventual -NoPaging:$NoPaging
        }
        catch {
            $result = [pscustomobject]@{ Success = $false; StatusCode = 0; Items = @(); Body = $null; Pages = 0; Retries = 0; ErrorCode = 'TokenError'; ErrorMessage = $_.Exception.Message; Partial = $false }
        }
        finally { $token = $null }
        $appResult = if ($result.Success) { 'success' } elseif ($result.StatusCode -in 401, 403) { 'forbidden' } else { 'error' }
        $notes = if ($result.Success) { "pages=$($result.Pages); items=$(@($result.Items).Count); retries=$($result.Retries)" } else { "$($result.ErrorCode): $($result.ErrorMessage)" }
        if ($result.Partial) { $notes += '; partial' }
        Add-SecOakEndpointLogEntry -Check $Check -Tool Graph -Method GET -EndpointOrCmdlet $logPath -HttpStatusOrResult "$($result.StatusCode)" `
            -AuthUsed 'app-only' -AppOnlyResult $appResult -Notes $notes
        $result | Add-Member -NotePropertyName AuthUsed -NotePropertyValue 'app-only' -Force
    }

    $shouldFallback = $Context.AzureCliFallback -and ($null -eq $result -or $result.StatusCode -in 401, 403 -or $result.ErrorCode -eq 'TokenError')
    if ($shouldFallback -and $Context.AzureCliTokenState -ne 'unavailable') {
        $azureResult = $null
        try {
            $token = Get-SecOakAccessToken -Context $Context -Kind AzureCli
            $Context.AzureCliTokenState = 'available'
            $azureResult = Invoke-SecOakGraphGetAttempt -Uri $uri -Token $token -ConsistencyLevelEventual:$ConsistencyLevelEventual -NoPaging:$NoPaging
        }
        catch {
            if ($_.Exception.Message -like '*different tenant*') { throw }
            $Context.AzureCliTokenState = 'unavailable'
            Write-Warning "Azure CLI fallback unavailable: $($_.Exception.Message)"
        }
        finally { $token = $null }
        if ($azureResult) {
            $notes = if ($azureResult.Success) { "pages=$($azureResult.Pages); items=$(@($azureResult.Items).Count); retries=$($azureResult.Retries)" } else { "$($azureResult.ErrorCode): $($azureResult.ErrorMessage)" }
            Add-SecOakEndpointLogEntry -Check $Check -Tool Graph -Method GET -EndpointOrCmdlet $logPath -HttpStatusOrResult "$($azureResult.StatusCode)" `
                -AuthUsed 'azcli-delegated' -AppOnlyResult $appResult -Notes $notes
            $azureResult | Add-Member -NotePropertyName AuthUsed -NotePropertyValue 'azcli-delegated' -Force
            if ($azureResult.Success -or -not $result) { $result = $azureResult }
        }
    }

    if (-not $result) {
        $result = [pscustomobject]@{ Success = $false; StatusCode = 0; Items = @(); Body = $null; Pages = 0; Retries = 0; ErrorCode = 'NoToken'; ErrorMessage = 'No usable token for this call.'; Partial = $false; AuthUsed = 'none' }
        Add-SecOakEndpointLogEntry -Check $Check -Tool Graph -Method GET -EndpointOrCmdlet $logPath -HttpStatusOrResult 'not run' -AuthUsed none -AppOnlyResult 'not attempted' -Notes 'No usable token.'
    }
    $result | Add-Member -NotePropertyName AppOnlyResult -NotePropertyValue $appResult -Force

    if ($result.Success -and $RawName) {
        $data = if ($null -ne $result.Body) { $result.Body } else { $result.Items }
        Save-SecOakRawData -Context $Context -Name $RawName -Data $data
    }
    if (-not $result.Success -and -not $NoGap) {
        $hint = Get-SecOakPermissionHint -Tool Graph -EndpointOrCmdlet $Path
        $reason = "$($result.ErrorCode): $($result.ErrorMessage)"
        if ($result.ErrorMessage -match 'licen[cs]e|premium|P1|P2|not.*subscri') { $reason = "Likely a license limit. $reason" }
        Add-SecOakGap -Context $Context -Area $Area -Check $Check -EndpointOrCmdlet $logPath -Result "$($result.StatusCode)" -Reason $reason `
            -FillWith "Application permission $($hint.Permission). $($hint.Note)".Trim()
    }
    $result
}
