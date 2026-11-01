function New-SecOakClientAssertion {
    <#
    .SYNOPSIS
        Builds a signed client assertion from a certificate in Cert:\CurrentUser\My.
    .DESCRIPTION
        The private key never leaves the certificate store; only the signature is used.
    .NOTES
        Internal helper. Requires the certificate with its private key in CurrentUser\My.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$AppId,
        [Parameter(Mandatory)][ValidatePattern('^[0-9A-F]{40}$')][string]$Thumbprint
    )
    $certificate = Get-Item -Path "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
    if (-not $certificate) { throw "Certificate with the configured thumbprint was not found in Cert:\CurrentUser\My." }
    if (-not $certificate.HasPrivateKey) { throw 'The configured certificate has no private key in Cert:\CurrentUser\My.' }
    if ($certificate.NotAfter -lt [datetime]::Now) { throw "The configured certificate expired on $($certificate.NotAfter.ToString('yyyy-MM-dd'))." }

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $header = [ordered]@{ alg = 'RS256'; typ = 'JWT'; x5t = (ConvertTo-SecOakBase64Url -Bytes $certificate.GetCertHash()) } | ConvertTo-Json -Compress
    $payload = [ordered]@{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        iss = $AppId
        sub = $AppId
        jti = [guid]::NewGuid().Guid
        nbf = $now
        iat = $now
        exp = $now + 600
    } | ConvertTo-Json -Compress
    $unsigned = (ConvertTo-SecOakBase64Url -Text $header) + '.' + (ConvertTo-SecOakBase64Url -Text $payload)

    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
    if (-not $rsa) { throw 'The configured certificate does not have an RSA private key.' }
    try {
        $signature = $rsa.SignData([System.Text.Encoding]::UTF8.GetBytes($unsigned),
            [System.Security.Cryptography.HashAlgorithmName]::SHA256,
            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
    }
    finally { $rsa.Dispose() }
    "$unsigned." + (ConvertTo-SecOakBase64Url -Bytes $signature)
}

function Register-SecOakTokenClaim {
    <#
    .SYNOPSIS
        Stores the non-secret claims of a token for token-scopes.txt.
    .NOTES
        Internal helper. Records names only, never the token.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Kind,
        [Parameter(Mandatory)][pscustomobject]$Claims
    )
    $script:TokenClaimRecords.Add([pscustomobject][ordered]@{
            Kind       = $Kind
            AcquiredAt = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
            TenantId   = $Claims.tid
            Roles      = @($Claims.roles | Sort-Object)
            Scopes     = @(("$($Claims.scp)" -split ' ') | Where-Object { $_ } | Sort-Object)
        })
}

function Request-SecOakAppToken {
    <#
    .SYNOPSIS
        Requests one app-only token for the given scope with the client credentials grant.
    .DESCRIPTION
        Certificate assertion (New-SecOakClientAssertion) or the secret in SECOAK_APP_SECRET.
        Shared by the Graph token (Get-SecOakAccessToken) and the other APIs (Get-SecOakApiToken).
        The token request is the only non-GET HTTP call outside the allow-listed read-only POSTs;
        it reads and changes nothing in the tenant.
    .PARAMETER Context
        The run context.
    .PARAMETER Scope
        The resource scope, for example https://graph.microsoft.com/.default.
    .OUTPUTS
        Object with Value (the token) and ExpiresOn (UTC). Returned only to other module functions.
    .NOTES
        Internal helper. https://learn.microsoft.com/entra/identity-platform/v2-oauth2-client-creds-grant-flow#get-a-token
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidatePattern('^https://[a-z0-9\.\-]+/\.default$')][string]$Scope
    )
    $body = @{
        client_id  = $Context.AppId
        scope      = $Scope
        grant_type = 'client_credentials'
    }
    if ($Context.CredentialType -eq 'Certificate') {
        $body.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        $body.client_assertion = New-SecOakClientAssertion -TenantId $Context.TenantId -AppId $Context.AppId -Thumbprint $Context.CertificateThumbprint
    }
    else {
        if (-not $env:SECOAK_APP_SECRET) { throw 'No certificate thumbprint configured and the SECOAK_APP_SECRET environment variable is empty.' }
        $body.client_secret = $env:SECOAK_APP_SECRET
    }
    try {
        $response = Invoke-RestMethod -Method Post -Uri "https://login.microsoftonline.com/$($Context.TenantId)/oauth2/v2.0/token" `
            -Body $body -ContentType 'application/x-www-form-urlencoded' -ErrorAction Stop
    }
    catch {
        $detail = $_.ErrorDetails.Message
        $code = if ($detail) { try { ($detail | ConvertFrom-Json).error_description.Split([Environment]::NewLine)[0] } catch { $detail } } else { $_.Exception.Message }
        throw "App-only token request failed: $code"
    }
    finally { $body.Remove('client_assertion'); $body.Remove('client_secret') }
    [pscustomobject]@{ Value = $response.access_token; ExpiresOn = [datetime]::UtcNow.AddSeconds([int]$response.expires_in) }
}

function Get-SecOakAccessToken {
    <#
    .SYNOPSIS
        Returns a cached or newly acquired Microsoft Graph token for internal use.
    .DESCRIPTION
        App: client credentials with a certificate assertion, or with the secret in the
        SECOAK_APP_SECRET environment variable. AzureCli: az account get-access-token for
        the signed-in delegated account. Tokens for the wrong tenant are rejected.
        The token is returned only to other functions in this module.
    .PARAMETER Context
        The run context.
    .PARAMETER Kind
        App or AzureCli.
    .NOTES
        Internal helper. App needs the reader app registration; AzureCli needs a prior
        "az login --tenant <tenant> --allow-no-subscriptions".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][pscustomobject]$Context,
        [Parameter(Mandatory)][ValidateSet('App', 'AzureCli')][string]$Kind
    )
    $cached = $script:Tokens[$Kind]
    if ($cached -and $cached.ExpiresOn -gt [datetime]::UtcNow.AddMinutes(5)) { return $cached.Value }

    if ($Kind -eq 'App') {
        $issued = Request-SecOakAppToken -Context $Context -Scope "$script:GraphBaseUri/.default"
        $value = $issued.Value
        $expires = $issued.ExpiresOn
    }
    else {
        if (-not (Get-Command az -ErrorAction SilentlyContinue)) { throw 'Azure CLI (az) is not installed.' }
        $raw = & az account get-access-token --resource-type ms-graph --tenant $Context.TenantId --query '{t:accessToken,e:expires_on}' -o json 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) {
            throw "Azure CLI could not issue a Graph token. Run: az login --tenant $($Context.TenantId) --allow-no-subscriptions"
        }
        $parsed = ($raw -join '') | ConvertFrom-Json
        $value = $parsed.t
        $expires = [DateTimeOffset]::FromUnixTimeSeconds([long]$parsed.e).UtcDateTime
    }

    $claims = ConvertFrom-SecOakJwtPayload -Token $value
    if ("$($claims.tid)".ToLowerInvariant() -ne $Context.TenantId) {
        throw "The $Kind token was issued for a different tenant than the one configured. Stopping to avoid a wrong-tenant run."
    }
    $script:Tokens[$Kind] = @{ Value = $value; ExpiresOn = $expires }
    if (-not ($script:TokenClaimRecords | Where-Object Kind -eq $Kind)) {
        Register-SecOakTokenClaim -Kind $Kind -Claims $claims
    }
    $value
}

function Connect-SecOakGraph {
    <#
    .SYNOPSIS
        Acquires the app-only Graph token and returns the permission names it carries.
    .PARAMETER Context
        The run context.
    .OUTPUTS
        An object with TenantId, AppId, and Roles. Never the token.
    .EXAMPLE
        Connect-SecOakGraph -Context $context
    .NOTES
        Requires the reader app registration with a certificate in Cert:\CurrentUser\My
        or a secret in SECOAK_APP_SECRET.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][pscustomobject]$Context)

    $null = Get-SecOakAccessToken -Context $Context -Kind App
    $Context.AppTokenAvailable = $true
    $record = $script:TokenClaimRecords | Where-Object Kind -eq 'App' | Select-Object -First 1
    [pscustomobject]@{ TenantId = $record.TenantId; AppId = $Context.AppId; Roles = $record.Roles }
}
