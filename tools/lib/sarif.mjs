// Convert dsh-redblue findings.json into SARIF 2.1.0 (design §8.4).

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

function norm(value) {
  return String(value ?? "").toLowerCase().replace(/\s+/g, " ").trim();
}

function slugify(value) {
  const text = norm(value).replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return text || "unknown";
}

function levelOf(severity) {
  const value = norm(severity);
  if (value === "critical" || value === "high") return "error";
  if (value === "medium") return "warning";
  return "note";
}

function rankOf(severity) {
  return SEVERITY_RANK[norm(severity)] ?? 0;
}

function findingsOf(document) {
  if (Array.isArray(document)) return document;
  if (document && Array.isArray(document.findings)) return document.findings;
  return [];
}

function locationOf(finding) {
  const target = finding && finding.target && typeof finding.target === "object" ? finding.target : null;
  const location = finding && finding.location && typeof finding.location === "object" ? finding.location : null;
  if (target && target.kind === "url") {
    return [{ physicalLocation: { artifactLocation: { uri: String(target.value) } } }];
  }
  if (target && target.kind === "source") {
    const uri = String(target.value).replace(/\\/g, "/");
    const region = location && Number.isInteger(location.line) ? { startLine: Number(location.line) } : undefined;
    return [{ physicalLocation: { artifactLocation: { uri }, ...(region ? { region } : {}) } }];
  }
  if (target) {
    return [{ logicalLocations: [{ name: String(target.value), kind: "resource" }] }];
  }
  return [];
}

export function convertFindingsToSarif(document) {
  const all = findingsOf(document);
  const reportable = all.filter((finding) => finding && (finding.disposition === undefined || norm(finding.disposition) === "reportable"));
  const categories = [];
  for (const finding of reportable) {
    const category = String((finding && finding.category) || "uncategorized");
    if (!categories.includes(category)) categories.push(category);
  }
  categories.sort();
  const rules = categories.map((category) => ({
    id: slugify(category),
    name: category,
    shortDescription: { text: category },
    properties: { tags: ["security"] },
  }));
  const results = reportable
    .slice()
    .sort((a, b) => (rankOf(b.severity) - rankOf(a.severity)) || (String(a.id || "") < String(b.id || "") ? -1 : 1))
    .map((finding) => ({
      ruleId: slugify(finding.category || "uncategorized"),
      level: levelOf(finding.severity),
      message: { text: [finding.title, finding.claim].filter(Boolean).join(" — ") },
      locations: locationOf(finding),
      partialFingerprints: { dshRedblueFingerprint: String(finding.fingerprint || "") },
      properties: {
        severity: String(finding.severity || ""),
        domain: String(finding.domain || ""),
        kind: String(finding.kind || ""),
        disposition: String(finding.disposition || ""),
        runId: String(finding.runId || ""),
      },
    }));
  return {
    version: "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "dsh-redblue",
            version: "0.1.0",
            informationUri: "https://dsh.local/dsh-redblue",
            rules,
          },
        },
        results,
        properties: {
          workflow: document && typeof document === "object" ? String(document.workflow || "") : "",
          runId: document && typeof document === "object" ? String(document.runId || "") : "",
        },
      },
    ],
  };
}