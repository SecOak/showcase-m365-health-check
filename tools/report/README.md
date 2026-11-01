# Security Oak client report generator

Turns a completed health check run folder into a polished, client-facing
Word (`.docx`) report. This tool is read-only against its input: it never
modifies the run folder, `findings.json`, `gaps.md`, or `run-summary.json`.
It writes exactly one new file, the report, into the run folder you point it
at.

No client data lives in this repository. The generator only reads a run
folder that you supply on the command line, and that folder is expected to
live outside the repository (for example under `%USERPROFILE%\SecurityOak\client-data\<client>\<run>`).

## Requirements

- Node.js (any recent LTS version; developed against Node 24)
- Run `npm install` once in this folder to fetch the `docx` package (this
  installs into `tools\report\node_modules`, which is not committed)

## Usage

From this folder (`tools\report`):

```powershell
npm install
node generate-report.js --run "C:\Users\<you>\SecurityOak\client-data\<client>\<run-folder>" --client "Client Display Name" --date 2026-09-24
```

Arguments:

| Flag | Description |
|---|---|
| `--run`, `-r` | Path to the completed run folder. Must contain `findings.json`, `gaps.md`, and `run-summary.json`. |
| `--client`, `-c` | Client display name used on the cover page and in the output file name, e.g. `"Contoso Limited"`. |
| `--date`, `-d` | Report date in `yyyy-MM-dd` format, e.g. `2026-09-24`. |

Example:

```powershell
node generate-report.js --run "$HOME\SecurityOak\client-data\contoso\20260924" --client "Contoso Limited" --date 2026-09-24
```

## Output

`<run folder>\Security-Oak-Health-Check-<Client-Name>-<yyyyMMdd>.docx`

The report has:

1. Cover page — title, client name, date, "Prepared by Security Oak", "Confidential".
2. Executive summary — posture paragraph, a findings-by-severity table, and a numbered "Top priorities" list (every Critical and High finding).
3. Scope and method — read-only assessment statement, areas covered, and licensing context.
4. Findings — grouped by severity (Critical first) then by area, each with why it matters, what to do, and evidence rendered in plain language.
5. What we could not check — one entry per row in `gaps.md`, written in plain language (no raw URLs or PowerShell cmdlet names), plus the open questions.
6. Recommended roadmap — This week / Next 30 days / Next 90 days / Ongoing, grouped by severity.
7. Appendix — an index table of every finding (ID, area, title, severity).

Every page carries a "Security Oak — Confidential" header and a page-number
footer, in a single accent color.

## Safeguards

- Any GUID-shaped string encountered anywhere in the finding data (tenant
  IDs, application IDs, certificate thumbprints, etc.) is stripped and
  replaced with `[redacted]` before it reaches the document, as a
  defence-in-depth safeguard on top of clean source data.
- The "What we could not check" section rewrites raw URLs, Graph/REST API
  paths, PowerShell cmdlet names, and bare third-party hostnames (e.g.
  `crt.sh`) into plain descriptions, so no technical endpoint or command
  names appear in that client-facing section. (The "What to do" remediation
  text in the Findings section may legitimately reference specific
  PowerShell cmdlets, since that is actionable guidance for the client's IT
  administrator.)

## Verifying a generated report

The `docx` file is a zip of XML. To spot-check one without Word:

```bash
# Render to PDF and inspect pages (requires LibreOffice's soffice on PATH,
# or call the full path to soffice.exe on Windows)
soffice --headless --convert-to pdf "Security-Oak-Health-Check-<Client>-<date>.docx"
```

Then open the PDF, or rasterize individual pages to images for a quick
visual check (with Poppler's `pdftoppm`, or PyMuPDF/`fitz` if Poppler is not
installed).

To check text content programmatically, unzip the `.docx` and read
`word/document.xml` — the visible text lives in `<w:t>` elements. This is
useful for asserting things like finding counts or the absence of any
GUID-shaped string.

## Notes for maintainers

- The script (`generate-report.js`) is self-contained: it parses
  `findings.json` and the `gaps.md` pipe table itself, with no dependency on
  the PowerShell side of this repository.
- Severity order is always Critical, High, Medium, Low.
- Evidence objects are rendered generically: camelCase keys become plain
  words, arrays become bulleted lists capped at 10 items (with "and N more"),
  nested objects become indented sub-bullets, and booleans render as
  Yes/No. `baselineControl` is omitted from a finding's write-up when its
  value is `"None"`.
