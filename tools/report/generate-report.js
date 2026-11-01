#!/usr/bin/env node
"use strict";

/**
 * Security Oak — Microsoft 365 Health Check client report generator.
 *
 * Reads a completed run folder (findings.json, gaps.md, run-summary.json)
 * and produces a polished, client-facing Word (.docx) report.
 *
 * This tool is READ-ONLY against its input: it never modifies the run
 * folder or anything in it. It writes exactly one new file, the report,
 * into the same run folder.
 *
 * No client data is read, written, or embedded anywhere in this repository.
 * Everything client-specific lives in the run folder the caller points at,
 * which is outside the repository by convention.
 *
 * Usage:
 *   node generate-report.js --run "<run folder>" --client "<Client Display Name>" --date <yyyy-MM-dd>
 *
 * See README.md in this folder for details.
 */

const fs = require("fs");
const path = require("path");
const {
  Document,
  Packer,
  Paragraph,
  TextRun,
  HeadingLevel,
  Table,
  TableRow,
  TableCell,
  WidthType,
  BorderStyle,
  ShadingType,
  AlignmentType,
  Header,
  Footer,
  PageNumber,
  PageBreak,
  LevelFormat,
  convertInchesToTwip,
  VerticalAlign,
} = require("docx");

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { run: null, client: null, date: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--run" || a === "-r") args.run = argv[++i];
    else if (a === "--client" || a === "-c") args.client = argv[++i];
    else if (a === "--date" || a === "-d") args.date = argv[++i];
    else if (a === "--help" || a === "-h") args.help = true;
  }
  return args;
}

function printUsageAndExit(code) {
  console.log(
    [
      "Security Oak M365 Health Check — report generator",
      "",
      "Usage:",
      '  node generate-report.js --run "<run folder>" --client "<Client Display Name>" --date <yyyy-MM-dd>',
      "",
      "Options:",
      "  --run, -r      Path to the completed run folder (must contain findings.json, gaps.md, run-summary.json)",
      "  --client, -c   Client display name for the cover page and file name, e.g. \"Contoso Limited\"",
      "  --date, -d     Report date in yyyy-MM-dd, e.g. 2026-09-24",
      "",
      "Output:",
      "  <run folder>\\Security-Oak-Health-Check-<client>-<yyyyMMdd>.docx",
    ].join("\n")
  );
  process.exit(code);
}

// ---------------------------------------------------------------------------
// Safety: strip anything GUID-shaped out of any text before it reaches the
// document. Findings should not contain tenant IDs, application IDs, or
// certificate thumbprints, but this is a defence-in-depth safeguard.
// ---------------------------------------------------------------------------

const GUID_RE = /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g;

function scrub(text) {
  if (text === null || text === undefined) return text;
  return String(text).replace(GUID_RE, "[redacted]");
}

// PowerShell verb prefixes recognised by the approved-verb list (the common
// subset actually seen in this tool's cmdlet names).
const POWERSHELL_VERBS =
  "Get|Set|New|Remove|Add|Enable|Disable|Update|Invoke|Register|Unregister|" +
  "Connect|Disconnect|Import|Export|Test|Find|Search|Start|Stop|Grant|Revoke|" +
  "Request|Resolve|Restore|Backup|Sync|Install|Uninstall";

// Bare hostnames of third-party lookup services that may appear in raw
// technical error text, e.g. "crt.sh".
const HOSTNAME_RE = /\b[a-z0-9][a-z0-9-]*\.(?:sh|com|net|org|io|gov|co)\b/gi;

// Strip raw URLs and PowerShell-cmdlet-looking or Graph-path-looking tokens
// out of text destined for the "what we could not check" section, per the
// requirement that no raw URLs or cmdlet names appear in client-facing text.
// This intentionally does NOT touch generic Capitalized-Hyphenated tokens
// (e.g. permission scope names like "BackupRestore-Configuration.Read.All"),
// only recognised PowerShell verb-noun cmdlet shapes.
function toPlainLanguage(text) {
  if (!text) return "";
  let out = scrub(text);
  // Raw URLs
  out = out.replace(/https?:\/\/\S+/g, "a technical lookup");
  // Graph / REST style paths, e.g. /v1.0/security/cases or /solutions/backupRestore/...
  out = out.replace(/\/[a-zA-Z0-9_\-./${}]*\/[a-zA-Z0-9_\-./${}]+/g, "a technical lookup");
  // PowerShell cmdlet-style tokens, e.g. Get-ExternalInOutlook, Get-M365UnifiedTenantSettings
  out = out.replace(new RegExp(`\\b(?:${POWERSHELL_VERBS})-[A-Z][a-zA-Z0-9]*\\b`, "g"), "a technical command");
  // Bare third-party lookup hostnames, e.g. crt.sh
  out = out.replace(HOSTNAME_RE, "an external lookup service");
  // Collapse any doubled-up replacement text and tidy whitespace
  out = out.replace(/\s{2,}/g, " ").trim();
  return out;
}

// ---------------------------------------------------------------------------
// Small text helpers
// ---------------------------------------------------------------------------

function camelCaseToWords(key) {
  const withSpaces = String(key)
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .replace(/[_-]+/g, " ")
    .trim();
  const lower = withSpaces.toLowerCase();
  return lower.charAt(0).toUpperCase() + lower.slice(1);
}

function formatDisplayDate(isoDate) {
  const [y, m, d] = isoDate.split("-").map((n) => parseInt(n, 10));
  const dt = new Date(Date.UTC(y, m - 1, d));
  const months = [
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
  ];
  return `${months[dt.getUTCMonth()]} ${dt.getUTCDate()}, ${dt.getUTCFullYear()}`;
}

function formatCompactDate(isoDate) {
  return isoDate.replace(/-/g, "");
}

function slugForFileName(text) {
  return String(text).trim().replace(/\s+/g, "-").replace(/[^a-zA-Z0-9-]/g, "");
}

function firstSentence(text) {
  if (!text) return "";
  const match = String(text).match(/^.*?[.!?](?:\s|$)/);
  return (match ? match[0] : text).trim();
}

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];
const SEVERITY_COLOR = {
  Critical: "C00000",
  High: "E36C09",
  Medium: "BF9000",
  Low: "2E7D32",
};
const ACCENT_COLOR = "1F4E5F"; // one accent color used throughout
const ACCENT_COLOR_LIGHT = "DCE9EC";
const TEXT_DARK = "222222";
const RULE_GRAY = "BFBFBF";

// ---------------------------------------------------------------------------
// Input loading
// ---------------------------------------------------------------------------

function loadInputs(runFolder) {
  const findingsPath = path.join(runFolder, "findings.json");
  const gapsPath = path.join(runFolder, "gaps.md");
  const summaryPath = path.join(runFolder, "run-summary.json");

  for (const [label, p] of [
    ["findings.json", findingsPath],
    ["gaps.md", gapsPath],
    ["run-summary.json", summaryPath],
  ]) {
    if (!fs.existsSync(p)) {
      throw new Error(`Required input "${label}" was not found in the run folder: ${p}`);
    }
  }

  const findings = JSON.parse(fs.readFileSync(findingsPath, "utf-8"));
  const gapsMarkdown = fs.readFileSync(gapsPath, "utf-8");
  let runSummary = {};
  try {
    runSummary = JSON.parse(fs.readFileSync(summaryPath, "utf-8"));
  } catch (e) {
    runSummary = {};
  }

  if (!Array.isArray(findings)) {
    throw new Error("findings.json did not parse to an array");
  }

  return { findings, gapsMarkdown, runSummary };
}

// Parses the gaps.md pipe table (Area | Check | Endpoint or cmdlet | Result | Why | What would fill it)
// and the "Open questions" section beneath it.
function parseGaps(markdown) {
  const lines = markdown.split(/\r?\n/);
  const rows = [];
  let openQuestions = [];

  let inTable = false;
  let headerSeen = false;
  let inOpenQuestions = false;

  for (const line of lines) {
    if (/^##\s*Open questions/i.test(line.trim())) {
      inOpenQuestions = true;
      inTable = false;
      continue;
    }
    if (inOpenQuestions) {
      const bulletMatch = line.match(/^\s*[-*]\s+(.*)$/);
      if (bulletMatch) openQuestions.push(bulletMatch[1].trim());
      continue;
    }
    if (line.trim().startsWith("|")) {
      inTable = true;
      const cells = line
        .trim()
        .replace(/^\|/, "")
        .replace(/\|$/, "")
        .split("|")
        .map((c) => c.trim());
      if (!headerSeen) {
        headerSeen = true; // header row
        continue;
      }
      if (cells.every((c) => /^:?-+:?$/.test(c))) continue; // separator row
      if (cells.length >= 6) {
        rows.push({
          area: cells[0],
          check: cells[1],
          endpoint: cells[2],
          result: cells[3],
          why: cells[4],
          whatWouldFillIt: cells[5],
        });
      }
    } else if (inTable && line.trim() === "") {
      inTable = false;
    }
  }

  return { rows, openQuestions };
}

// ---------------------------------------------------------------------------
// Document building blocks
// ---------------------------------------------------------------------------

function heading1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    spacing: { before: 360, after: 160 },
    children: [new TextRun({ text: scrub(text), bold: true, color: ACCENT_COLOR })],
  });
}

function heading2(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_2,
    spacing: { before: 260, after: 120 },
    children: [new TextRun({ text: scrub(text), bold: true, color: ACCENT_COLOR })],
  });
}

function heading3(text, extraRuns) {
  const children = [new TextRun({ text: scrub(text), bold: true, color: TEXT_DARK })];
  if (extraRuns) children.push(...extraRuns);
  return new Paragraph({
    heading: HeadingLevel.HEADING_3,
    spacing: { before: 220, after: 80 },
    children,
  });
}

function bodyParagraph(text, opts) {
  opts = opts || {};
  return new Paragraph({
    spacing: { after: 160 },
    children: [new TextRun({ text: scrub(text), italics: !!opts.italics, bold: !!opts.bold })],
  });
}

function labelledParagraph(label, text) {
  return new Paragraph({
    spacing: { after: 120 },
    children: [
      new TextRun({ text: `${label}: `, bold: true }),
      new TextRun({ text: scrub(text) }),
    ],
  });
}

function bulletParagraph(text, level) {
  return new Paragraph({
    numbering: { reference: "bullet-list", level: level || 0 },
    spacing: { after: 60 },
    children: [new TextRun({ text: scrub(text) })],
  });
}

function numberedParagraph(text, ref) {
  return new Paragraph({
    numbering: { reference: ref, level: 0 },
    spacing: { after: 100 },
    children: [new TextRun({ text: scrub(text) })],
  });
}

function pageBreakParagraph() {
  return new Paragraph({ children: [new PageBreak()] });
}

function thinRule() {
  return new Paragraph({
    spacing: { before: 80, after: 240 },
    border: { bottom: { color: RULE_GRAY, space: 1, style: BorderStyle.SINGLE, size: 6 } },
    children: [],
  });
}

function makeCell(text, opts) {
  opts = opts || {};
  return new TableCell({
    width: { size: opts.width || 2000, type: WidthType.DXA },
    shading: opts.shade ? { type: ShadingType.CLEAR, fill: opts.shade } : undefined,
    verticalAlign: VerticalAlign.CENTER,
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    children: [
      new Paragraph({
        alignment: opts.align || AlignmentType.LEFT,
        children: [
          new TextRun({
            text: scrub(text),
            bold: !!opts.bold,
            color: opts.color || TEXT_DARK,
          }),
        ],
      }),
    ],
  });
}

// ---------------------------------------------------------------------------
// Evidence rendering
// ---------------------------------------------------------------------------

function renderEvidenceValue(key, value) {
  const paragraphs = [];
  const label = camelCaseToWords(key);

  if (Array.isArray(value)) {
    if (value.length === 0) {
      paragraphs.push(labelledParagraph(label, "None"));
      return paragraphs;
    }
    paragraphs.push(
      new Paragraph({
        spacing: { after: 40 },
        children: [new TextRun({ text: `${label}:`, bold: true })],
      })
    );
    const cap = 10;
    const shown = value.slice(0, cap);
    shown.forEach((item) => {
      const text = typeof item === "object" && item !== null ? flattenObjectInline(item) : String(item);
      paragraphs.push(bulletParagraph(text, 0));
    });
    if (value.length > cap) {
      paragraphs.push(bulletParagraph(`and ${value.length - cap} more`, 0));
    }
    return paragraphs;
  }

  if (value !== null && typeof value === "object") {
    paragraphs.push(
      new Paragraph({
        spacing: { after: 40 },
        children: [new TextRun({ text: `${label}:`, bold: true })],
      })
    );
    Object.entries(value).forEach(([subKey, subValue]) => {
      const subLabel = camelCaseToWords(subKey);
      const subText = typeof subValue === "boolean" ? (subValue ? "Yes" : "No") : String(subValue);
      paragraphs.push(bulletParagraph(`${subLabel}: ${subText}`, 0));
    });
    return paragraphs;
  }

  if (typeof value === "boolean") {
    paragraphs.push(labelledParagraph(label, value ? "Yes" : "No"));
    return paragraphs;
  }

  paragraphs.push(labelledParagraph(label, String(value)));
  return paragraphs;
}

function flattenObjectInline(obj) {
  return Object.entries(obj)
    .map(([k, v]) => `${camelCaseToWords(k)}: ${typeof v === "boolean" ? (v ? "Yes" : "No") : v}`)
    .join(", ");
}

function renderEvidence(evidence) {
  const paragraphs = [];
  if (!evidence || typeof evidence !== "object" || Object.keys(evidence).length === 0) {
    return [bodyParagraph("No supporting detail was recorded for this finding.")];
  }
  paragraphs.push(
    new Paragraph({
      spacing: { before: 80, after: 60 },
      children: [new TextRun({ text: "Evidence", bold: true, italics: true })],
    })
  );
  Object.entries(evidence).forEach(([key, value]) => {
    paragraphs.push(...renderEvidenceValue(key, value));
  });
  return paragraphs;
}

// ---------------------------------------------------------------------------
// Section builders
// ---------------------------------------------------------------------------

function buildCoverPage(clientName, displayDate) {
  return [
    new Paragraph({ spacing: { before: 2000 }, children: [] }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 400 },
      children: [
        new TextRun({
          text: "Microsoft 365 Security Health Check",
          bold: true,
          size: 56,
          color: ACCENT_COLOR,
        }),
      ],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 240 },
      children: [new TextRun({ text: scrub(clientName), bold: true, size: 36 })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 800 },
      children: [new TextRun({ text: displayDate, size: 28 })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { before: 1400, after: 80 },
      children: [new TextRun({ text: "Prepared by Security Oak", size: 24, color: ACCENT_COLOR })],
    }),
    new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 80 },
      children: [new TextRun({ text: "Confidential", bold: true, size: 24 })],
    }),
    pageBreakParagraph(),
  ];
}

function buildExecutiveSummary(findings, severityCounts, total) {
  const paragraphs = [];
  paragraphs.push(heading1("Executive summary"));

  const critical = severityCounts.Critical || 0;
  const high = severityCounts.High || 0;
  const medium = severityCounts.Medium || 0;
  const low = severityCounts.Low || 0;

  const posture =
    `This assessment reviewed the Microsoft 365 tenant and identified ${total} findings in total. ` +
    `${critical} ${critical === 1 ? "is" : "are"} rated Critical and ${high} ${high === 1 ? "is" : "are"} rated High, ` +
    `meaning ${critical + high} issue${critical + high === 1 ? "" : "s"} need attention in the near term to reduce the ` +
    `chance of account compromise, data loss, or a successful ransomware attack. The remaining findings — ` +
    `${medium} Medium and ${low} Low — represent smaller gaps and hardening opportunities that further reduce risk ` +
    `once the urgent items are addressed. None of the findings below required any change to the tenant to identify; ` +
    `this was a read-only review.`;
  paragraphs.push(bodyParagraph(posture));

  // Findings-by-severity table
  paragraphs.push(heading2("Findings by severity"));
  const headerRow = new TableRow({
    tableHeader: true,
    children: [
      makeCell("Severity", { width: 4000, bold: true, shade: ACCENT_COLOR, color: "FFFFFF" }),
      makeCell("Count", { width: 2000, bold: true, shade: ACCENT_COLOR, color: "FFFFFF", align: AlignmentType.CENTER }),
    ],
  });
  const rows = [headerRow];
  SEVERITY_ORDER.forEach((sev) => {
    rows.push(
      new TableRow({
        children: [
          makeCell(sev, { width: 4000, color: SEVERITY_COLOR[sev], bold: true }),
          makeCell(String(severityCounts[sev] || 0), { width: 2000, align: AlignmentType.CENTER }),
        ],
      })
    );
  });
  rows.push(
    new TableRow({
      children: [
        makeCell("Total", { width: 4000, bold: true, shade: ACCENT_COLOR_LIGHT }),
        makeCell(String(total), { width: 2000, align: AlignmentType.CENTER, bold: true, shade: ACCENT_COLOR_LIGHT }),
      ],
    })
  );
  paragraphs.push(
    new Table({
      width: { size: 6000, type: WidthType.DXA },
      columnWidths: [4000, 2000],
      rows,
    })
  );
  paragraphs.push(new Paragraph({ spacing: { after: 240 }, children: [] }));

  // Top priorities
  paragraphs.push(heading2("Top priorities"));
  const topPriority = findings.filter((f) => f.severity === "Critical" || f.severity === "High");
  if (topPriority.length === 0) {
    paragraphs.push(bodyParagraph("There are no Critical or High findings in this assessment."));
  } else {
    topPriority
      .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
      .forEach((f) => {
        const fix = firstSentence(f.recommendedFix);
        paragraphs.push(numberedParagraph(`${f.title} — ${fix}`, "top-priorities"));
      });
  }

  return paragraphs;
}

function buildScopeAndMethod(findings, gapRows) {
  const paragraphs = [];
  paragraphs.push(pageBreakParagraph());
  paragraphs.push(heading1("Scope and method"));

  paragraphs.push(
    bodyParagraph(
      "This was a read-only assessment. Security Oak reviewed the tenant using a dedicated, read-only " +
        "application registered in Microsoft Entra ID and authenticated with a certificate rather than a " +
        "password. That application can only read configuration and reporting data; it cannot make changes. " +
        "No settings, policies, or data in the tenant were changed as part of this review."
    )
  );

  const areas = Array.from(
    new Set([...findings.map((f) => f.area), ...gapRows.map((g) => g.area)])
  ).sort((a, b) => a.localeCompare(b));

  paragraphs.push(heading2("Areas covered"));
  areas.forEach((area) => paragraphs.push(bulletParagraph(area, 0)));
  paragraphs.push(new Paragraph({ spacing: { after: 160 }, children: [] }));

  paragraphs.push(heading2("Licensing context"));
  paragraphs.push(
    bodyParagraph(
      "Findings and recommendations below take the following licensing into account:"
    )
  );
  [
    "Microsoft 365 Business Premium",
    "Microsoft Defender for Office 365 Plan 2",
    "Microsoft Entra ID P2",
    "Microsoft 365 Copilot Business",
  ].forEach((lic) => paragraphs.push(bulletParagraph(lic, 0)));
  paragraphs.push(
    bodyParagraph("The tenant has no Azure subscriptions, so Azure infrastructure controls are out of scope for this review.")
  );

  return paragraphs;
}

function severityLabelRun(severity) {
  return new TextRun({
    text: ` ${severity.toUpperCase()} `,
    bold: true,
    color: "FFFFFF",
    shading: { type: ShadingType.CLEAR, fill: SEVERITY_COLOR[severity] || "808080" },
  });
}

function buildFindingsSection(findings) {
  const paragraphs = [];
  paragraphs.push(pageBreakParagraph());
  paragraphs.push(heading1("Findings"));
  paragraphs.push(
    bodyParagraph(
      "Findings are grouped by severity, with Critical first, then by the area of Microsoft 365 they affect."
    )
  );

  SEVERITY_ORDER.forEach((severity) => {
    const inSeverity = findings.filter((f) => f.severity === severity);
    if (inSeverity.length === 0) return;

    paragraphs.push(heading2(`${severity} (${inSeverity.length})`));

    const areas = Array.from(new Set(inSeverity.map((f) => f.area))).sort((a, b) => a.localeCompare(b));
    areas.forEach((area) => {
      const inArea = inSeverity.filter((f) => f.area === area).sort((a, b) => a.id.localeCompare(b.id));
      paragraphs.push(
        new Paragraph({
          heading: HeadingLevel.HEADING_3,
          spacing: { before: 200, after: 80 },
          children: [new TextRun({ text: area, bold: true, italics: true, color: ACCENT_COLOR })],
        })
      );

      inArea.forEach((f) => {
        paragraphs.push(
          new Paragraph({
            spacing: { before: 160, after: 60 },
            children: [
              new TextRun({ text: `${f.id} — ${scrub(f.title)}`, bold: true, size: 24 }),
            ],
          })
        );
        paragraphs.push(
          new Paragraph({
            spacing: { after: 100 },
            children: [severityLabelRun(f.severity)],
          })
        );
        paragraphs.push(
          new Paragraph({
            spacing: { after: 60 },
            children: [new TextRun({ text: "Why it matters", bold: true, italics: true })],
          })
        );
        paragraphs.push(bodyParagraph(f.risk || ""));
        paragraphs.push(
          new Paragraph({
            spacing: { after: 60 },
            children: [new TextRun({ text: "What to do", bold: true, italics: true })],
          })
        );
        paragraphs.push(bodyParagraph(f.recommendedFix || ""));
        paragraphs.push(...renderEvidence(f.evidence));
        if (f.baselineControl && f.baselineControl !== "None") {
          paragraphs.push(labelledParagraph("Baseline control", f.baselineControl));
        }
        paragraphs.push(thinRule());
      });
    });
  });

  return paragraphs;
}

function buildCouldNotCheckSection(gapRows, openQuestions) {
  const paragraphs = [];
  paragraphs.push(pageBreakParagraph());
  paragraphs.push(heading1("What we could not check"));
  paragraphs.push(
    bodyParagraph(
      "A small number of checks could not be completed during this assessment, either because the review " +
        "application does not have permission for that area, the data was not available from Microsoft, or the " +
        "check depends on an interactive administrator session. Each is listed below in plain language, along " +
        "with what would need to change to complete it."
    )
  );

  if (gapRows.length === 0) {
    paragraphs.push(bodyParagraph("There were no incomplete checks in this assessment."));
  } else {
    gapRows.forEach((g) => {
      const checkLabel = plainLanguageCheckLabel(g.check);
      paragraphs.push(
        new Paragraph({
          spacing: { before: 160, after: 40 },
          children: [new TextRun({ text: `${g.area} — ${checkLabel}`, bold: true })],
        })
      );
      paragraphs.push(labelledParagraph("Why", toPlainLanguage(g.why)));
      paragraphs.push(labelledParagraph("What would fill it", toPlainLanguage(g.whatWouldFillIt)));
    });
  }

  if (openQuestions.length > 0) {
    paragraphs.push(heading2("Open questions"));
    paragraphs.push(
      bodyParagraph("These cannot be answered from the tenant alone and are best discussed directly:")
    );
    openQuestions.forEach((q) => paragraphs.push(bulletParagraph(toPlainLanguage(q), 0)));
  }

  return paragraphs;
}

// Turns a "Area/CheckId" style identifier into a short, readable label
// without exposing the raw endpoint, cmdlet, or query syntax.
function plainLanguageCheckLabel(rawCheck) {
  if (!rawCheck) return "A configuration check";
  const afterSlash = rawCheck.includes("/") ? rawCheck.split("/").slice(1).join(" ") : rawCheck;
  const words = camelCaseToWords(afterSlash.replace(/-/g, " "));
  return words || "A configuration check";
}

function buildRoadmapSection(findings) {
  const paragraphs = [];
  paragraphs.push(pageBreakParagraph());
  paragraphs.push(heading1("Recommended roadmap"));
  paragraphs.push(
    bodyParagraph(
      "A suggested order of work, grouped by urgency. Critical items first, then High, then Medium, with Low " +
        "items folded into ongoing operations."
    )
  );

  const groups = [
    { label: "This week", severity: "Critical" },
    { label: "Next 30 days", severity: "High" },
    { label: "Next 90 days", severity: "Medium" },
    { label: "Ongoing", severity: "Low" },
  ];

  groups.forEach((g) => {
    const items = findings.filter((f) => f.severity === g.severity);
    paragraphs.push(heading2(`${g.label} (${items.length})`));
    if (items.length === 0) {
      paragraphs.push(bodyParagraph("Nothing in this category."));
    } else {
      items.forEach((f) => paragraphs.push(bulletParagraph(f.title, 0)));
    }
  });

  return paragraphs;
}

function buildAppendix(findings) {
  const paragraphs = [];
  paragraphs.push(pageBreakParagraph());
  paragraphs.push(heading1("Appendix: index of all findings"));

  const sorted = [...findings].sort((a, b) => {
    const areaCmp = a.area.localeCompare(b.area);
    if (areaCmp !== 0) return areaCmp;
    return a.id.localeCompare(b.id);
  });

  const headerRow = new TableRow({
    tableHeader: true,
    children: [
      makeCell("ID", { width: 1400, bold: true, shade: ACCENT_COLOR, color: "FFFFFF" }),
      makeCell("Area", { width: 1600, bold: true, shade: ACCENT_COLOR, color: "FFFFFF" }),
      makeCell("Title", { width: 4600, bold: true, shade: ACCENT_COLOR, color: "FFFFFF" }),
      makeCell("Severity", { width: 1400, bold: true, shade: ACCENT_COLOR, color: "FFFFFF" }),
    ],
  });
  const rows = [headerRow];
  sorted.forEach((f) => {
    rows.push(
      new TableRow({
        children: [
          makeCell(f.id, { width: 1400 }),
          makeCell(f.area, { width: 1600 }),
          makeCell(f.title, { width: 4600 }),
          makeCell(f.severity, { width: 1400, color: SEVERITY_COLOR[f.severity], bold: true }),
        ],
      })
    );
  });

  paragraphs.push(
    new Table({
      width: { size: 9000, type: WidthType.DXA },
      columnWidths: [1400, 1600, 4600, 1400],
      rows,
    })
  );

  return paragraphs;
}

// ---------------------------------------------------------------------------
// Header / footer
// ---------------------------------------------------------------------------

function buildHeader() {
  return new Header({
    children: [
      new Paragraph({
        alignment: AlignmentType.RIGHT,
        border: { bottom: { color: RULE_GRAY, space: 4, style: BorderStyle.SINGLE, size: 4 } },
        children: [new TextRun({ text: "Security Oak — Confidential", size: 18, color: "666666" })],
      }),
    ],
  });
}

function buildFooter() {
  return new Footer({
    children: [
      new Paragraph({
        alignment: AlignmentType.CENTER,
        children: [
          new TextRun({ text: "Security Oak — Confidential   |   Page ", size: 18, color: "666666" }),
          new TextRun({ children: [PageNumber.CURRENT], size: 18, color: "666666" }),
          new TextRun({ text: " of ", size: 18, color: "666666" }),
          new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 18, color: "666666" }),
        ],
      }),
    ],
  });
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help || !args.run || !args.client || !args.date) {
    printUsageAndExit(args.help ? 0 : 1);
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(args.date)) {
    console.error('Error: --date must be in yyyy-MM-dd format, e.g. 2026-09-24');
    process.exit(1);
  }

  const runFolder = path.resolve(args.run);
  if (!fs.existsSync(runFolder) || !fs.statSync(runFolder).isDirectory()) {
    console.error(`Error: run folder not found: ${runFolder}`);
    process.exit(1);
  }

  const { findings, gapsMarkdown } = loadInputs(runFolder);
  const { rows: gapRows, openQuestions } = parseGaps(gapsMarkdown);

  const severityCounts = {};
  findings.forEach((f) => {
    severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
  });
  const total = findings.length;

  const displayDate = formatDisplayDate(args.date);
  const compactDate = formatCompactDate(args.date);

  const bodyChildren = [
    ...buildCoverPage(args.client, displayDate),
    ...buildExecutiveSummary(findings, severityCounts, total),
    ...buildScopeAndMethod(findings, gapRows),
    ...buildFindingsSection(findings),
    ...buildCouldNotCheckSection(gapRows, openQuestions),
    ...buildRoadmapSection(findings),
    ...buildAppendix(findings),
  ];

  const doc = new Document({
    creator: "Security Oak",
    title: `Microsoft 365 Security Health Check — ${args.client}`,
    description: "Security Oak Microsoft 365 security health check report",
    numbering: {
      config: [
        {
          reference: "bullet-list",
          levels: [
            {
              level: 0,
              format: LevelFormat.BULLET,
              text: "•",
              alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: convertInchesToTwip(0.35), hanging: convertInchesToTwip(0.2) } } },
            },
          ],
        },
        {
          reference: "top-priorities",
          levels: [
            {
              level: 0,
              format: LevelFormat.DECIMAL,
              text: "%1.",
              alignment: AlignmentType.LEFT,
              style: { paragraph: { indent: { left: convertInchesToTwip(0.35), hanging: convertInchesToTwip(0.25) } } },
            },
          ],
        },
      ],
    },
    sections: [
      {
        properties: {
          page: {
            size: { width: 12240, height: 15840 }, // US Letter, in DXA
            margin: {
              top: convertInchesToTwip(1),
              bottom: convertInchesToTwip(1),
              left: convertInchesToTwip(1),
              right: convertInchesToTwip(1),
            },
          },
        },
        headers: { default: buildHeader() },
        footers: { default: buildFooter() },
        children: bodyChildren,
      },
    ],
  });

  const fileName = `Security-Oak-Health-Check-${slugForFileName(args.client)}-${compactDate}.docx`;
  const outputPath = path.join(runFolder, fileName);

  Packer.toBuffer(doc).then((buffer) => {
    fs.writeFileSync(outputPath, buffer);
    console.log(`Report written to: ${outputPath}`);
    console.log(`Findings: ${total} (Critical ${severityCounts.Critical || 0}, High ${severityCounts.High || 0}, Medium ${severityCounts.Medium || 0}, Low ${severityCounts.Low || 0})`);
    console.log(`Gaps: ${gapRows.length}, Open questions: ${openQuestions.length}`);
  }).catch((err) => {
    console.error("Failed to generate report:", err);
    process.exit(1);
  });
}

main();
