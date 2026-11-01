# Security Oak Microsoft 365 health check

> **Showcase copy.** This is a sanitized example of my work, published for portfolio purposes.
> It is a snapshot, not an actively maintained project, and it has never been pointed at a real
> tenant from this repository. Issues and pull requests are welcome but may not get a reply.
> Contact: zachanger@outlook.com · [zachanger.com](https://zachanger.com)

A read-only Microsoft 365 security health check, and the least-privilege reader app
setup that supports it, built for small-business Microsoft 365 tenants.

## Hard guarantees

- Microsoft Graph access is GET only. `Invoke-SecOakGraphGet` is the only function in the
  module that calls Graph, and it has no parameter that changes the HTTP method.
- Exchange Online access is `Get-*` cmdlets only. `Invoke-SecOakExchangeGet` is the only
  function that runs Exchange cmdlets, and it rejects any cmdlet whose name does not start
  with `Get-`.
- The only non-GET request the tool makes is the OAuth token request to
  `login.microsoftonline.com`, which reads nothing from and changes nothing in the client
  tenant.
- The tenant display name and ID are read and shown before anything else is collected.
  A run either stops there (`-ShowTenant`) or requires confirmation, either interactively
  (typing `yes`) or with `-ConfirmedTenantId`, which must match the tenant the token was
  actually issued for.
- Client data never belongs in this repository. Client configuration lives outside it
  (`$HOME\SecurityOak\clients\<client>.json`), and run output is written outside it
  (`$HOME\SecurityOak\client-data\...`), with `.gitignore` as a second line of defence.

## Requirements

- PowerShell 7.2 or later.
- `ExchangeOnlineManagement` 3.x, for the Email area.
- `Microsoft.Graph.Authentication`, for the reader app setup script only
  (`setup\New-SecurityOakReaderApp.ps1`); the health check itself does not use the Graph
  PowerShell SDK.
- Azure CLI, optional, only needed for `-AzureCliFallback` (a delegated fallback for
  calls the app-only credential cannot make).

## Setting up a client

1. Read `docs\permissions.md` for the full list of Microsoft Graph application
   permissions, the `Exchange.ManageAsApp` role, and the Global Reader Microsoft Entra
   role the reader app needs, and why.
2. Create the reader app in the client tenant with `setup\New-SecurityOakReaderApp.ps1
   -TenantId <tenant-id>` first, in report-only mode, to see what it would create without
   changing anything. Only after review, the consultant runs it again with `-Apply`, from
   a session that has the Global Administrator or Privileged Role Administrator role
   active through Privileged Identity Management.
3. Create the app's certificate locally, before running the setup script, as a
   non-exportable certificate in `Cert:\CurrentUser\My` using the CryptoAPI provider
   `"Microsoft Enhanced RSA and AES Cryptographic Provider"`. Exchange app-only
   authentication fails against a certificate created with a CNG key, which is the
   default provider for `New-SelfSignedCertificate` on most systems, so the provider must
   be set explicitly:

   ```powershell
   $cert = New-SelfSignedCertificate `
       -Subject "CN=SecurityOak-Reader-Contoso" `
       -CertStoreLocation Cert:\CurrentUser\My `
       -KeyExportPolicy NonExportable `
       -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
       -KeySpec Signature `
       -KeyAlgorithm RSA `
       -KeyLength 2048 `
       -NotAfter (Get-Date).AddYears(1)
   Export-Certificate -Cert $cert -FilePath "$HOME\SecurityOak\contoso-reader.cer"
   ```

   Only the public `.cer` file is exported (with `Export-Certificate`, not
   `Export-PfxCertificate`); the private key stays non-exportable in the certificate
   store. The `.cer` is uploaded to the app registration; it is not a secret and is not
   itself sufficient to authenticate, but it still identifies the client and should stay
   out of the repository (`.gitignore` blocks `*.cer`).

## Client configuration

Copy `config\tenant.example.json` to `$HOME\SecurityOak\clients\<client>.json`, outside
the repository, and fill in the real `ClientName`, `TenantId`, `AppId`,
`CertificateThumbprint`, and `InitialDomain`. Never commit a filled-in copy; `.gitignore`
blocks every `*.json` file in the repository except `config\*.example.json`, and blocks
everything else under `config\` as a second line of defence.

## Running

Always confirm the tenant before collecting anything:

```powershell
./Invoke-SecurityOakHealthCheck.ps1 -ConfigPath $HOME\SecurityOak\clients\contoso.json -ShowTenant
```

Then run for real, either non-interactively with the confirmed tenant ID, or
interactively and type `yes` when prompted:

```powershell
./Invoke-SecurityOakHealthCheck.ps1 -ConfigPath $HOME\SecurityOak\clients\contoso.json -ConfirmedTenantId <tenant-id>
```

Other parameters:

- `-Area Identity, Email` — run only the named areas (`Identity`, `Email`, `Domain`, `Devices`,
  `Sharing`, `Licensing`, `Posture`, `Entra`, `Intune`, `Defender`, `Exchange`, `SharePoint`,
  `Teams`, `Purview`, `ServiceHealth`, `Backup`, `Azure`, `Access`). Defaults to all eighteen.
- `-PermissionAudit` — run only the Access self-audit, to review what the reader app
  actually holds against what the health check uses.
- `-AzureCliFallback` — retry Graph calls that come back 401 or 403 using an Azure CLI
  delegated token. Requires `az login --tenant <tenant-id> --allow-no-subscriptions`
  first.
- `-ExchangeInteractiveFallback` — replay Exchange steps that fail app-only through an
  interactive sign-in; `-ExchangeUserPrincipalName <user@contoso.com>` pre-fills the
  account for that sign-in.

Example running every area with both fallbacks available:

```powershell
az login --tenant <tenant-id> --allow-no-subscriptions
./Invoke-SecurityOakHealthCheck.ps1 -ConfigPath $HOME\SecurityOak\clients\contoso.json `
    -ConfirmedTenantId <tenant-id> -AzureCliFallback -ExchangeInteractiveFallback `
    -ExchangeUserPrincipalName consultant@contoso.onmicrosoft.com
```

## Output

Each run writes to `$HOME\SecurityOak\client-data\<client>\<yyyyMMdd>\`, outside the
repository:

| File | Contents |
|---|---|
| `raw\*.json` | Raw data exported per check (one file per collection step). |
| `endpoint-log.csv` | One row per Graph call, Exchange cmdlet, and DNS lookup. Columns: `Timestamp`, `Check`, `Tool`, `Method`, `EndpointOrCmdlet`, `HttpStatusOrResult`, `AuthUsed`, `AppOnlyResult`, `LeastPrivilegeAppPermission`, `Notes`. |
| `token-scopes.txt` | Permission names carried by each token acquired during the run. The tokens themselves are never written. |
| `findings.json` | Findings with severity, evidence, risk, recommended fix, and baseline control. See `docs\checks.md` for what produces each one. |
| `gaps.md` | What could not be checked, why, and what permission or license would fill it, plus a fixed "open questions" section for what these APIs cannot answer at all (currently backups; see `docs\checks.md`). |
| `run-summary.json` | Counts per area and severity, plus the per-area summary data described in `docs\checks.md`. |
| `run-log.txt` | Full run transcript. |

## Repository hygiene

`.gitignore` blocks: run output and client data (`output/`, `client-data/`, `raw/`,
`*.csv`, `*.log`, `token-scopes.txt`, `run-log.txt`, `gaps.md`, `findings.json`,
`endpoint-log.*`); every `*.json` file except `config\*.example.json`; everything else
under `config\`, plus `*.local.json`, `*.local.psd1`, and `*.tenant.json` wherever they
appear; certificates, keys, and secrets (`*.pfx`, `*.p12`, `*.cer`, `*.crt`, `*.pem`,
`*.key`, `*.snk`, `.env`, `.env.*`, `*.secret`, `*.secrets`); and editor and operating
system noise.

Before every commit, review `git status` and the staged diff. Never commit a real
tenant ID, domain, user name, app ID, certificate thumbprint, or anything from an
output folder. Use `contoso` and clearly fake placeholders in anything checked in,
including examples in documentation and commit messages.

## Layout

| Path | Purpose |
|---|---|
| `Invoke-SecurityOakHealthCheck.ps1` | Orchestrator: signs in, shows and confirms the tenant, runs the selected areas, writes the run report. |
| `src\SecurityOak.HealthCheck.psd1` | Module manifest. |
| `src\SecurityOak.HealthCheck.psm1` | Loader: dot-sources `src\Core` then `src\Areas` in a fixed order and exports the public functions. |
| `src\Core\` | Token acquisition, the read-only wrappers (Graph, Defender for Endpoint, Azure Resource Manager, Exchange Online, Security and Compliance, Teams, public DNS and HTTPS), endpoint logging, findings, and gaps. |
| `src\Areas\` | One file per area, each with one check function, plus the run report writer. |
| `config\reader-app-permissions.json` | The approved read-only permission set the setup script applies. |
| `config\tenant.example.json` | Placeholder client configuration to copy outside the repository. |
| `docs\checks.md` | Every finding: what it checks, its severity rule, its data source, and its baseline control. |
| `docs\permissions.md` | The reader app's application permissions, directory role, Azure roles, and read-only exceptions, and why each is needed. |
| `setup\New-SecurityOakReaderApp.ps1` | Creates and configures the reader app in a client tenant; report-only by default, `-Apply` to make changes. |
| `.gitignore` | Keeps client data and secrets out of the repository. |

## Licence

Released under the [MIT License](LICENSE).
