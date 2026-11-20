#!/usr/bin/env node
// dsh-redblue sanitization lint (POLICY R1-R12/v1).
// Zero-dependency Node ESM. Implements docs/sanitization-rules.md and policy/sanitization.md.
//
// Usage:
//   node tools/sanitize-lint.mjs [--strict] [--json] [--check <ID[,ID...]>] [--list-checks]
//                                [--policy <path>] [paths...]
//
// Default paths: the plugin root (this file's parent directory).
// Exit codes: 0 no blocker (or not --strict); 1 blockers under --strict; 2 usage/internal error.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const VERSION = "dsh-redblue-sanitize/v1";
const POLICY_VERSION = "R1-R12/v1";
const PLUGIN_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const NOW = new Date();

// ---------------------------------------------------------------------------
// POLICY constants (R1-R12/v1). policy/sanitization.md documents these values.
// ---------------------------------------------------------------------------

const UPSTREAM = {
  claudeRed: {
    repo: "https://github.com/SnailSploit/Claude-Red",
    commit: "6196ba7464662de34e8744d359f175d1a7bca530",
    license: "MIT",
  },
  acs: {
    repo: "https://github.com/mukul975/Anthropic-Cybersecurity-Skills",
    commit: "54a798831d2266a3ca61ce68a7acb80b81160d57",
    license: "Apache-2.0",
  },
  strix: {
    repo: "https://github.com/usestrix/strix",
    commit: "8db295a5b3564be2b430bb3a9afdb4db7850fa24",
    license: "Apache-2.0",
  },
};
const UPSTREAM_LIST = Object.values(UPSTREAM);
const UPSTREAM_REPOS = UPSTREAM_LIST.map((u) => u.repo);
const UPSTREAM_COMMITS = UPSTREAM_LIST.map((u) => u.commit);
const REPO_LICENSE = new Map(UPSTREAM_LIST.map((u) => [u.repo, u.license]));
const SOURCE_DIRS = new Map([
  [UPSTREAM.claudeRed.repo, "claude-red"],
  [UPSTREAM.acs.repo, "acs"],
  [UPSTREAM.strix.repo, "strix"],
]);
let sourceRootCache;
function sourceRoot() {
  if (sourceRootCache !== undefined) return sourceRootCache;
  const candidates = [
    resolve(process.cwd(), ".work", "sources"),
    resolve(PLUGIN_ROOT, "..", ".work", "sources"),
    resolve(PLUGIN_ROOT, ".work", "sources"),
  ];
  sourceRootCache = candidates.find((candidate) => existsSync(candidate)) || null;
  return sourceRootCache;
}
function sourcePathStatus(repo, sourcePath) {
  if (!repo || !sourcePath) return null;
  const dir = SOURCE_DIRS.get(repo);
  const root = sourceRoot();
  if (!root || !dir) return null;
  if (sourcePath.startsWith("/") || sourcePath.startsWith("\\") || sourcePath.split(/[\\/]/).includes("..")) return false;
  return existsSync(join(root, dir, sourcePath));
}

const DEFAULT_POLICY = {
  version: POLICY_VERSION,
  reservedDomains: ["example.com", "example.net", "example.org"],
  reservedTlds: ["test", "example", "invalid", "localhost"],
  authorityDomains: [
    "github.com",
    "raw.githubusercontent.com",
    "nvd.nist.gov",
    "cve.org",
    "cve.mitre.org",
    "cwe.mitre.org",
    "capec.mitre.org",
    "attack.mitre.org",
    "owasp.org",
    "first.org",
    "nist.gov",
    "cisa.gov",
    "sans.org",
    "sigmahq.io",
    "mitre.org",
    "msrc.microsoft.com",
    "learn.microsoft.com",
    "docs.aws.amazon.com",
    "cloud.google.com",
    "kubernetes.io",
    "docs.docker.com",
    "rfc-editor.org",
    "datatracker.ietf.org",
    "ietf.org",
    "json-schema.org",
    "json.schemastore.org",
    "schemastore.org",
    "spdx.org",
    "semver.org",
    "dsh.local",
    "w3.org",
  ],
  toolDomains: [
    "crt.sh",
    "shodan.io",
    "censys.io",
    "urlscan.io",
    "virustotal.com",
    "portswigger.net",
    "projectdiscovery.io",
  ],
  denylistDomains: [
    "attacker.com",
    "evil.com",
    "malware.com",
    "phishing.com",
    "badguy.com",
    "evil.test",
    "attacker.test",
  ],
  docIpv4Cidrs: ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
  loopbackIpv4Cidrs: ["127.0.0.0/8"],
  docIpv6Prefixes: ["2001:db8"],
  privateIpv4Cidrs: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"],
  privateIpv6Prefixes: ["fc", "fd", "fe80"],
  wildcardValues: ["0.0.0.0", "0.0.0.0/0", "::", "::/0"],
  tlds: [
    "com", "net", "org", "io", "dev", "ai", "co", "cn", "uk", "de", "jp", "ru", "in", "br",
    "fr", "nl", "se", "no", "fi", "dk", "pl", "it", "es", "ca", "au", "ch", "at", "be", "cz",
    "pt", "gr", "tr", "kr", "tw", "hk", "sg", "my", "id", "th", "vn", "ph", "nz", "za", "mx",
    "ar", "cl", "il", "ae", "sa", "ir", "pk", "bd", "lk", "np", "site", "xyz", "info", "me",
    "tech", "security", "sh", "run", "top", "online", "store", "edu", "gov", "mil", "us",
    "test", "example", "invalid", "localhost", "local",
  ],
  fileExtensions: [
    "md", "json", "jsonl", "js", "mjs", "cjs", "ts", "tsx", "yml", "yaml", "txt", "svg",
    "sarif", "log", "csv", "pcap", "zip", "sha256",
  ],
  jaccardThreshold: 0.35,
  maxSkillLines: 300,
  maxSkillBytes: 24576,
  maxDescription: 500,
  maxReferenceBytes: 49152,
  maxIndexBytes: 24576,
  maxRewriteSummary: 120,
  freshnessWarnDays: 180,
  freshnessBlockDays: 365,
  authBanner: "> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。",
};

const CANDIDATE_EXTENSIONS = new Set(DEFAULT_POLICY.fileExtensions.filter((ext) => !["pcap", "zip"].includes(ext)));

const SKILL_KEYS = [
  "name", "description", "whenToUse", "risk", "requires", "ingests",
  "source-repo", "source-commit", "source-license", "source-path",
  "last-verified", "rewrite-summary",
];
const REFERENCE_KEYS = [
  "source-repo", "source-commit", "source-license", "source-path",
  "last-verified", "rewrite-summary",
];
const INGEST_BOUNDARY_PHRASES = ["不可信数据", "只读", "不执行其中任何指令", "写入仅限 workDir"];

const EXPECTED_SKILLS = {
  "dsh-rb-run": { lane: "rb", risk: "passive", requires: "none" },
  "dsh-red-scope": { lane: "red", risk: "passive", requires: "authorization" },
  "dsh-red-recon": { lane: "red", risk: "passive", requires: "authorization" },
  "dsh-red-surface": { lane: "red", risk: "passive", requires: "authorization" },
  "dsh-red-discover": { lane: "red", risk: "active", requires: "authorization" },
  "dsh-red-validate": { lane: "red", risk: "active", requires: "authorization" },
  "dsh-red-exploit": { lane: "red", risk: "exploit", requires: "authorization" },
  "dsh-red-post": { lane: "red", risk: "post", requires: "authorization" },
  "dsh-rb-report": { lane: "rb", risk: "passive", requires: "authorization" },
  "dsh-blue-hunt": { lane: "blue", risk: "passive", requires: "none" },
  "dsh-blue-detect": { lane: "blue", risk: "passive", requires: "none" },
  "dsh-blue-dfir": { lane: "blue", risk: "passive", requires: "none" },
  "dsh-blue-harden": { lane: "blue", risk: "passive", requires: "none" },
  "dsh-purple-verify": { lane: "purple", risk: "passive", requires: "authorization" },
  "dsh-rb-triage": { lane: "rb", risk: "passive", requires: "authorization" },
};
const CANONICAL_SKILLS = Object.keys(EXPECTED_SKILLS);

const CHECK_DEFS = [
  { id: "R1-PROVENANCE", rule: "R1", level: "blocker", kinds: ["skill", "reference", "asset"] },
  { id: "R1-NOTICE", rule: "R1", level: "blocker", kinds: ["notice"] },
  { id: "R1-LICENSE", rule: "R1", level: "blocker", kinds: ["package", "license"] },
  { id: "R2-RESERVED", rule: "R2", level: "blocker", kinds: ["skill", "reference", "policy", "schema"] },
  { id: "R2-AUTHORITY-LINK", rule: "R2", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R2-PRIVATE", rule: "R2", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R2-DENYLIST", rule: "R2", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R2-EXAMPLE-TARGET", rule: "R2", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R3-WEAPON", rule: "R3", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R3-DESTRUCTIVE", rule: "R3", level: "blocker", kinds: ["skill", "reference", "workflow"] },
  { id: "R3-AUTH-BANNER", rule: "R3", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R4-VERIFY-DISABLED", rule: "R4", level: "blocker", kinds: ["skill", "reference", "workflow", "lib"] },
  { id: "R4-WILDCARD", rule: "R4", level: "blocker", kinds: ["skill", "reference", "policy"] },
  { id: "R4-DRYRUN-DEFAULT", rule: "R4", level: "blocker", kinds: ["workflow"] },
  { id: "R4-SCOPE-GATE", rule: "R4", level: "blocker", kinds: ["workflow"] },
  { id: "R5-FAKE", rule: "R5", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R5-METRIC", rule: "R5", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R5-CVE", rule: "R5", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R6-SKILL-SIZE", rule: "R6", level: "blocker", kinds: ["skill"] },
  { id: "R6-DESC", rule: "R6", level: "blocker", kinds: ["skill"] },
  { id: "R6-WHEN", rule: "R6", level: "blocker", kinds: ["skill"] },
  { id: "R6-REF-SIZE", rule: "R6", level: "blocker", kinds: ["reference"] },
  { id: "R7-NAME", rule: "R7", level: "blocker", kinds: ["skill", "lib"] },
  { id: "R7-JACCARD", rule: "R7", level: "blocker", kinds: ["skill"] },
  { id: "R7-NEGATIVE", rule: "R7", level: "blocker", kinds: ["skill"] },
  { id: "R8-SKILL", rule: "R8", level: "blocker", kinds: ["skill"] },
  { id: "R8-WORKFLOW", rule: "R8", level: "blocker", kinds: ["workflow"] },
  { id: "R9-LAST-VERIFIED", rule: "R9", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R9-VERSION-FRESH", rule: "R9", level: "warning", kinds: ["skill", "reference"] },
  { id: "R10-SECRET", rule: "R10", level: "blocker", kinds: ["skill", "reference", "policy"] },
  { id: "R10-PII", rule: "R10", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R10-INTERNAL-HOST", rule: "R10", level: "blocker", kinds: ["skill", "reference"] },
  { id: "R11-TERMINOLOGY", rule: "R11", level: "warning", kinds: ["skill", "reference", "policy"] },
  { id: "R12-RISK", rule: "R12", level: "blocker", kinds: ["skill"] },
  { id: "R12-CONFIRM", rule: "R12", level: "blocker", kinds: ["workflow"] },
  { id: "R12-REPORT-ONLY", rule: "R12", level: "blocker", kinds: ["skill", "reference", "workflow"] },
];
const CHECK_BY_ID = new Map(CHECK_DEFS.map((c) => [c.id, c]));

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const toPosix = (p) => p.split(sep).join("/");

function relOf(abs) {
  const rel = relative(process.cwd(), abs);
  return (rel !== "" && !rel.startsWith("..") ? rel : abs).split(sep).join("/");
}

function classify(abs) {
  const p = toPosix(abs);
  const b = basename(abs);
  if (b === "SKILL.md") return "skill";
  if (b === "package.json") return "package";
  if (b === "NOTICE") return "notice";
  if (b === "LICENSE") return "license";
  if (/(^|\/)references\//.test(p)) return "reference";
  if (/(^|\/)workflow\//.test(p)) return "workflow";
  if (/(^|\/)lib\//.test(p)) return "lib";
  if (/(^|\/)policy\//.test(p)) return "policy";
  if (/(^|\/)schema\//.test(p)) return "schema";
  if (/\.(ya?ml|svg|txt)$/i.test(b)) return "asset";
  return "other";
}

function isCandidateFile(name) {
  if (["NOTICE", "LICENSE", "SKILL.md"].includes(name)) return true;
  if (!name.includes(".")) return false;
  const ext = name.slice(name.lastIndexOf(".") + 1).toLowerCase();
  return CANDIDATE_EXTENSIONS.has(ext);
}

const SKIP_SEGMENTS = new Set(["node_modules", ".git", ".work", ".hg", ".svn"]);

function collectFiles(rootPaths) {
  const out = [];
  const seen = new Set();
  const walk = (abs, relBase) => {
    let st;
    try { st = statSync(abs); } catch { return; }
    if (st.isDirectory()) {
      let entries;
      try { entries = readdirSync(abs, { withFileTypes: true }); } catch { return; }
      entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      for (const entry of entries) {
        if (SKIP_SEGMENTS.has(entry.name)) continue;
        const childRel = relBase === "" ? entry.name : relBase + "/" + entry.name;
        if (entry.isDirectory()) {
          if (childRel === "docs" || childRel === "test/fixtures") continue;
          walk(join(abs, entry.name), childRel);
        } else if (entry.isFile() && isCandidateFile(entry.name)) {
          const fileAbs = join(abs, entry.name);
          if (seen.has(fileAbs)) continue;
          seen.add(fileAbs);
          out.push({ abs: fileAbs, rel: relOf(fileAbs), kind: classify(fileAbs) });
        }
      }
      return;
    }
    if (!st.isFile() || !isCandidateFile(basename(abs))) return;
    if (seen.has(abs)) return;
    seen.add(abs);
    out.push({ abs, rel: relOf(abs), kind: classify(abs) });
  };
  for (const p of rootPaths) {
    const abs = resolve(p);
    if (!existsSync(abs)) throw new Error(`路径不存在: ${p}`);
    walk(abs, "");
  }
  out.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  return out.map(loadFile);
}

function loadFile(entry) {
  const buf = readFileSync(entry.abs);
  const text = buf.toString("utf8");
  return {
    ...entry,
    text,
    bytes: buf.length,
    lines: text.split(/\r?\n/),
  };
}

function filesOfKinds(files, kinds) {
  const set = new Set(kinds);
  return files.filter((f) => set.has(f.kind));
}

function truncate(s, max = 160) {
  const t = String(s).replace(/\s+/g, " ").trim();
  return t.length > max ? t.slice(0, max) + "…" : t;
}

function finding(id, file, line, message, evidence, levelOverride) {
  const def = CHECK_BY_ID.get(id);
  return {
    id,
    rule: def.rule,
    level: levelOverride ?? def.level,
    status: "fail",
    file: typeof file === "string" ? file : file.rel,
    line: Math.max(1, Number.isFinite(line) ? line : 1),
    message,
    evidence: truncate(evidence ?? ""),
  };
}

function keyLine(file, key) {
  for (let i = 0; i < file.lines.length; i++) {
    if (new RegExp("^" + key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\s*:").test(file.lines[i])) return i + 1;
  }
  return 1;
}

function stripQuotes(v) {
  const t = String(v).trim();
  if (t.length >= 2 && (t[0] === '"' || t[0] === "'") && t[t.length - 1] === t[0]) return t.slice(1, -1);
  return t;
}

function parseFlatBlock(body) {
  const meta = {};
  for (const line of body.split(/\r?\n/)) {
    const kv = /^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/.exec(line);
    if (kv !== null) meta[kv[1]] = stripQuotes(kv[2]);
  }
  return meta;
}

function frontmatterOf(file) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(file.text);
  if (m === null) return { ok: false, meta: {}, body: file.text };
  return { ok: true, meta: parseFlatBlock(m[1]), body: file.text.slice(m[0].length) };
}

function provenanceOf(file) {
  const m = /<!--\s*dsh-redblue:(provenance|index)\b([\s\S]*?)-->/.exec(file.text);
  if (m !== null) {
    const start = file.text.slice(0, m.index).split(/\r?\n/).length;
    return { type: m[1], meta: parseFlatBlock(m[2]), line: start };
  }
  const lines = file.text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const head = /^\s*#\s*dsh-redblue:(provenance|index)\s*$/.exec(lines[i]);
    if (head === null) continue;
    const block = [];
    let j = i + 1;
    while (j < lines.length) {
      const body = /^\s*#\s?(.*)$/.exec(lines[j]);
      if (body === null) break;
      block.push(body[1]);
      j++;
    }
    return { type: head[1], meta: parseFlatBlock(block.join("\n")), line: i + 1 };
  }
  return null;
}

function fenceStates(file) {
  const states = [];
  let inFence = false;
  let info = "";
  for (const line of file.lines) {
    const open = /^\s*(`{3,}|~{3,})\s*(\S*)(.*)$/.exec(line);
    if (!inFence && open !== null) {
      inFence = true;
      info = (open[2] || "").toLowerCase();
      states.push({ inFence: false, info: "", labOnly: false, isDelimiter: true });
      continue;
    }
    if (inFence && /^\s*(`{3,}|~{3,})\s*$/.test(line)) {
      states.push({ inFence: true, info, labOnly: /lab-only/.test(info), isDelimiter: true });
      inFence = false;
      info = "";
      continue;
    }
    states.push({ inFence, info, labOnly: inFence && /lab-only/.test(info), isDelimiter: false });
  }
  return states;
}

function inlineCodeSpans(line) {
  const spans = [];
  const re = /`([^`]+)`/g;
  let m;
  while ((m = re.exec(line)) !== null) spans.push(m[1]);
  return spans;
}

function isNegated(line) {
  return /禁止|不得|不允许|拒绝|切勿|never|forbidden|must\s+not|do\s+not|no\s+/i.test(line);
}

function daysBetweenUtc(dateStr) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr);
  if (m === null) return null;
  const y = Number(m[1]);
  const mo = Number(m[2]);
  const d = Number(m[3]);
  if (mo < 1 || mo > 12 || d < 1) return null;
  const daysInMonth = new Date(Date.UTC(y, mo, 0)).getUTCDate();
  if (d > daysInMonth) return null;
  const then = Date.UTC(y, mo - 1, d);
  const today = Date.UTC(NOW.getUTCFullYear(), NOW.getUTCMonth(), NOW.getUTCDate());
  return Math.floor((today - then) / 86400000);
}

function validDateString(dateStr) {
  return daysBetweenUtc(dateStr) !== null;
}

// ---------------------------------------------------------------------------
// Domains / IPs / emails
// ---------------------------------------------------------------------------

const DOMAIN_RE = /(?<![@A-Za-z0-9_./\\-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9_-])/g;
const EMAIL_RE = /[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})/g;
const IPV4_RE = /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g;
const IPV6_RE = /(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])/g;
const URL_RE = /https?:\/\/[^\s<>)\]"'`]+/g;

function policyList(key) {
  return Array.isArray(POLICY[key]) ? POLICY[key] : DEFAULT_POLICY[key];
}

function hostMatches(host, entries) {
  const h = host.toLowerCase().replace(/\.$/, "");
  return entries.some((d) => h === d || h.endsWith("." + d));
}

function isReservedHost(host) {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (h === "localhost") return true;
  if (h === "dsh.local" || h.endsWith(".dsh.local")) return true;
  if (hostMatches(h, policyList("reservedDomains"))) return true;
  return policyList("reservedTlds").some((t) => h.endsWith("." + t));
}

function isAllowedLinkHost(host) {
  if (isReservedHost(host)) return true;
  return hostMatches(host, policyList("authorityDomains")) || hostMatches(host, policyList("toolDomains"));
}

function isAllowedEmailHost(host) {
  return isReservedHost(host);
}

function isDenylisted(host) {
  return hostMatches(host, policyList("denylistDomains"));
}

function tldOf(host) {
  const parts = host.toLowerCase().replace(/\.$/, "").split(".");
  return parts.length >= 2 ? parts[parts.length - 1] : "";
}

function looksLikeDomainToken(token) {
  const host = token.toLowerCase();
  if (host.includes("/") || host.includes("\\")) return false;
  if (policyList("fileExtensions").some((ext) => host.endsWith("." + ext))) return false;
  if (!policyList("tlds").includes(tldOf(host))) return false;
  return true;
}

function ipv4ToInt(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let value = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value >>> 0;
}

function cidrContainsIpv4(ip, cidr) {
  const [base, bitsRaw] = cidr.split("/");
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (ipInt === null || baseInt === null) return false;
  const bits = Number(bitsRaw);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

function parseIpv6(token) {
  const t = token.toLowerCase();
  if (!t.includes(":")) return null;
  const doubleColon = t.includes("::");
  if (doubleColon && t.indexOf("::") !== t.lastIndexOf("::")) return null;
  const [head, tail] = doubleColon ? t.split("::") : [t, ""];
  const groups = (s) => (s === "" ? [] : s.split(":"));
  const h = groups(head);
  const tl = doubleColon ? groups(tail) : [];
  for (const g of [...h, ...tl]) if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
  if (doubleColon) {
    if (h.length + tl.length > 7) return null;
  } else if (h.length !== 8) {
    return null;
  }
  return t;
}

function classifyIpv4(ip) {
  if (ip === "0.0.0.0") return "wildcard";
  if (policyList("loopbackIpv4Cidrs").some((c) => cidrContainsIpv4(ip, c))) return "loopback";
  if (policyList("docIpv4Cidrs").some((c) => cidrContainsIpv4(ip, c))) return "doc";
  if (policyList("privateIpv4Cidrs").some((c) => cidrContainsIpv4(ip, c))) return "private";
  return "public";
}

function classifyIpv6(token) {
  const t = parseIpv6(token);
  if (t === null) return null;
  if (t === "::") return "wildcard";
  if (t === "::1") return "loopback";
  if (policyList("docIpv6Prefixes").some((p) => t.startsWith(p))) return "doc";
  if (policyList("privateIpv6Prefixes").some((p) => t.startsWith(p))) return "private";
  return "public";
}

function tokensOf(file) {
  const domains = [];
  const ips = [];
  const emails = [];
  for (let i = 0; i < file.lines.length; i++) {
    const line = file.lines[i];
    for (const m of line.matchAll(EMAIL_RE)) emails.push({ value: m[0], host: m[1], line: i + 1 });
    for (const m of line.matchAll(DOMAIN_RE)) {
      const value = m[0];
      const start = m.index ?? 0;
      if (start > 0 && line[start - 1] === "@") continue;
      if (!looksLikeDomainToken(value)) continue;
      domains.push({ value, line: i + 1 });
    }
    for (const m of line.matchAll(IPV4_RE)) {
      if (ipv4ToInt(m[0]) !== null) ips.push({ value: m[0], family: 4, line: i + 1 });
    }
    for (const m of line.matchAll(IPV6_RE)) {
      const value = m[0];
      if (value.includes(":") && parseIpv6(value) !== null) ips.push({ value, family: 6, line: i + 1 });
    }
  }
  return { domains, ips, emails };
}

// ---------------------------------------------------------------------------
// R1 — provenance and license
// ---------------------------------------------------------------------------

function checkProvenanceMeta(f, prov, out, prefix) {
  for (const key of REFERENCE_KEYS) {
    if (prov.meta[key] === undefined || prov.meta[key] === "") {
      out.push(finding("R1-PROVENANCE", f, prov.line, `${prefix}provenance 缺少必填键 ${key}`, ""));
    }
  }
  const repo = prov.meta["source-repo"];
  if (repo !== undefined && repo !== "" && !UPSTREAM_REPOS.includes(repo)) {
    out.push(finding("R1-PROVENANCE", f, prov.line, `${prefix}source-repo 不在三上游 pin 内: ${repo}`, repo));
  }
  const commit = prov.meta["source-commit"];
  if (commit !== undefined && commit !== "" && !UPSTREAM_COMMITS.includes(commit)) {
    out.push(finding("R1-PROVENANCE", f, prov.line, `${prefix}source-commit 不在三上游 pin 内: ${commit}`, commit));
  }
  const license = prov.meta["source-license"];
  if (repo !== undefined && license !== undefined && REPO_LICENSE.has(repo) && REPO_LICENSE.get(repo) !== license) {
    out.push(finding("R1-PROVENANCE", f, prov.line, `${prefix}source-license 与仓库不匹配: ${license} != ${REPO_LICENSE.get(repo)}`, repo));
  }
  const summary = prov.meta["rewrite-summary"];
  if (summary !== undefined && [...summary].length > POLICY.maxRewriteSummary) {
    out.push(finding("R1-PROVENANCE", f, prov.line, `${prefix}rewrite-summary 超过 ${POLICY.maxRewriteSummary} 码点`, summary));
  }
  const sourcePath = prov.meta["source-path"];
  if (!f.rel.includes("test/fixtures/") && sourcePath !== undefined && sourcePath !== "" && sourcePathStatus(repo, sourcePath) === false) {
    out.push(finding("R1-PROVENANCE", f, prov.line, `${prefix}source-path 在固定 commit 快照中不存在: ${sourcePath}`, sourcePath));
  }
}

function checkR1Provenance(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill"])) {
    const fm = frontmatterOf(f);
    if (!fm.ok) {
      out.push(finding("R1-PROVENANCE", f, 1, "SKILL.md 缺少 frontmatter provenance 块", f.lines[0] ?? ""));
      continue;
    }
    for (const key of SKILL_KEYS) {
      if (fm.meta[key] === undefined || fm.meta[key] === "") {
        out.push(finding("R1-PROVENANCE", f, keyLine(f, key), `frontmatter 缺少必填键 ${key}`, ""));
      }
    }
    const repo = fm.meta["source-repo"];
    if (repo !== undefined && repo !== "" && !UPSTREAM_REPOS.includes(repo)) {
      out.push(finding("R1-PROVENANCE", f, keyLine(f, "source-repo"), `source-repo 不在三上游 pin 内: ${repo}`, repo));
    }
    const commit = fm.meta["source-commit"];
    if (commit !== undefined && commit !== "" && !UPSTREAM_COMMITS.includes(commit)) {
      out.push(finding("R1-PROVENANCE", f, keyLine(f, "source-commit"), `source-commit 不在三上游 pin 内: ${commit}`, commit));
    }
    const license = fm.meta["source-license"];
    if (repo !== undefined && license !== undefined && REPO_LICENSE.has(repo) && REPO_LICENSE.get(repo) !== license) {
      out.push(finding("R1-PROVENANCE", f, keyLine(f, "source-license"), `source-license 与仓库不匹配: ${license} != ${REPO_LICENSE.get(repo)}`, repo));
    }
    const summary = fm.meta["rewrite-summary"];
    if (summary !== undefined && [...summary].length > POLICY.maxRewriteSummary) {
      out.push(finding("R1-PROVENANCE", f, keyLine(f, "rewrite-summary"), `rewrite-summary 超过 ${POLICY.maxRewriteSummary} 码点`, summary));
    }
    const sourcePath = fm.meta["source-path"];
    if (!f.rel.includes("test/fixtures/") && sourcePath !== undefined && sourcePath !== "" && sourcePathStatus(repo, sourcePath) === false) {
      out.push(finding("R1-PROVENANCE", f, keyLine(f, "source-path"), `source-path 在固定 commit 快照中不存在: ${sourcePath}`, sourcePath));
    }
  }
  for (const f of filesOfKinds(files, ["reference"])) {
    const prov = provenanceOf(f);
    if (prov === null) {
      out.push(finding("R1-PROVENANCE", f, 1, "reference 缺少 dsh-redblue provenance/index 注释块", ""));
      continue;
    }
    if (prov.type === "index") {
      const commits = prov.meta["upstream-commits"] ?? "";
      for (const c of UPSTREAM_COMMITS) {
        if (!commits.includes(c)) out.push(finding("R1-PROVENANCE", f, prov.line, `INDEX 头缺少上游 commit ${c.slice(0, 12)}…`, commits));
      }
      if (!prov.meta["last-verified"]) out.push(finding("R1-PROVENANCE", f, prov.line, "INDEX 头缺少 last-verified", ""));
      continue;
    }
    checkProvenanceMeta(f, prov, out, "");
  }
  // asset（yml/svg/txt 等）只要声明了 dsh-redblue provenance 头，就必须与 reference
  // 同样可追溯；未声明 provenance 的资产（icon.svg、cordis.patch.yml）不属 R1 对象，
  // 由 R2/R10 覆盖（见 docs/assembly-report.md 的 R6 受理说明）。
  for (const f of filesOfKinds(files, ["asset"])) {
    const prov = provenanceOf(f);
    if (prov === null || prov.type !== "provenance") continue;
    checkProvenanceMeta(f, prov, out, "asset ");
  }
  return out;
}

function checkR1Notice(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["notice"])) {
    const missing = [];
    for (const u of UPSTREAM_LIST) {
      if (!f.text.includes(u.repo)) missing.push(u.repo);
      if (!f.text.includes(u.commit)) missing.push(u.commit.slice(0, 12) + "…");
    }
    for (const needle of ["Modifications:", "MIT License", "Permission is hereby granted", "Apache-2.0", "Copyright"]) {
      if (!f.text.includes(needle)) missing.push(needle);
    }
    for (const item of missing) {
      out.push(finding("R1-NOTICE", f, 1, `NOTICE 缺少必要内容: ${item}`, ""));
    }
  }
  return out;
}

function checkR1License(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["package"])) {
    let pkg;
    try {
      pkg = JSON.parse(f.text);
    } catch (error) {
      out.push(finding("R1-LICENSE", f, 1, `package.json 不是合法 JSON: ${error.message}`, ""));
      continue;
    }
    if (pkg.license !== "Apache-2.0") {
      out.push(finding("R1-LICENSE", f, 1, `package.json license 必须为 Apache-2.0，实际 ${String(pkg.license)}`, ""));
    }
  }
  for (const f of filesOfKinds(files, ["license"])) {
    for (const needle of ["Apache License", "Version 2.0", "END OF TERMS AND CONDITIONS"]) {
      if (!f.text.includes(needle)) out.push(finding("R1-LICENSE", f, 1, `LICENSE 缺少 Apache-2.0 文本片段: ${needle}`, ""));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R2 — placeholder sanitization
// ---------------------------------------------------------------------------

function checkR2Reserved(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "policy", "schema", "asset"])) {
    const tokens = tokensOf(f);
    for (const d of tokens.domains) {
      if (isReservedHost(d.value) || isAllowedLinkHost(d.value) || isDenylisted(d.value)) continue;
      out.push(finding("R2-RESERVED", f, d.line, `非保留/非权威域名: ${d.value}`, d.value));
    }
    for (const ip of tokens.ips) {
      const kind = ip.family === 4 ? classifyIpv4(ip.value) : classifyIpv6(ip.value);
      if (kind === null || kind === "doc" || kind === "loopback" || kind === "private" || kind === "wildcard") continue;
      out.push(finding("R2-RESERVED", f, ip.line, `非文档网段 IP: ${ip.value}`, ip.value));
    }
    for (const e of tokens.emails) {
      if (isAllowedEmailHost(e.host)) continue;
      out.push(finding("R2-RESERVED", f, e.line, `非保留域邮箱: ${e.value}`, e.value));
    }
  }
  return out;
}

function checkR2AuthorityLink(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      for (const m of line.matchAll(URL_RE)) {
        const url = m[0].replace(/[.,;:]+$/, "");
        const hostMatch = /^https?:\/\/([^/:?#]+)/i.exec(url);
        if (hostMatch === null) continue;
        const host = hostMatch[1].toLowerCase();
        if (isAllowedLinkHost(host)) continue;
        out.push(finding("R2-AUTHORITY-LINK", f, i + 1, `引用链接不在权威/工具白名单: ${host}`, url));
      }
    }
  }
  return out;
}

function checkR2Private(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    const fences = fenceStates(f);
    const tokens = tokensOf(f);
    for (const ip of tokens.ips) {
      const kind = ip.family === 4 ? classifyIpv4(ip.value) : classifyIpv6(ip.value);
      if (kind !== "private") continue;
      if (fences[ip.line - 1]?.labOnly === true) continue;
      out.push(finding("R2-PRIVATE", f, ip.line, `私有网段地址只允许出现在 lab-only 代码块: ${ip.value}`, ip.value));
    }
  }
  return out;
}

function checkR2Denylist(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    const tokens = tokensOf(f);
    for (const d of tokens.domains) {
      if (!isDenylisted(d.value)) continue;
      out.push(finding("R2-DENYLIST", f, d.line, `禁止使用攻击者风格域名: ${d.value}`, d.value));
    }
    for (const e of tokens.emails) {
      if (!isDenylisted(e.host)) continue;
      out.push(finding("R2-DENYLIST", f, e.line, `禁止使用攻击者风格域名: ${e.value}`, e.value));
    }
  }
  return out;
}

function targetValueAllowed(value) {
  const v = value.trim().replace(/^["']|["']$/g, "");
  if (v === "" || v.startsWith("<") || v.includes("<TARGET>") || v.includes("<AUTHORIZED-TARGET>")) return true;
  if (v === "localhost") return true;
  const ip4 = /^(\d{1,3}\.){3}\d{1,3}$/.exec(v);
  if (ip4 !== null) {
    const kind = classifyIpv4(v);
    return kind === "doc" || kind === "loopback" || kind === "private" || kind === "wildcard";
  }
  if (v.includes(":")) {
    const kind = classifyIpv6(v);
    return kind === "doc" || kind === "loopback" || kind === "private" || kind === "wildcard";
  }
  const host = v.replace(/^https?:\/\//i, "").split(/[/:?#]/)[0];
  return isReservedHost(host);
}

function checkR2ExampleTarget(files) {
  const out = [];
  const patterns = [
    /["']?target["']?\s*[:=]\s*["']?([^\s"',}\]]+)/i,
    /["']?value["']?\s*[:=]\s*["']?([^\s"',}\]]+)/i,
    /--target(?:=|\s+)([^\s"',}\]]+)/i,
    /--url(?:=|\s+)([^\s"',}\]]+)/i,
    /-u\s+([^\s"',}\]]+)/,
  ];
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    const fences = fenceStates(f);
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (!fences[i]?.inFence && !fences[i]?.isDelimiter) continue;
      for (const re of patterns) {
        const m = re.exec(line);
        if (m === null) continue;
        const value = m[1];
        if (targetValueAllowed(value)) continue;
        out.push(finding("R2-EXAMPLE-TARGET", f, i + 1, `示例目标必须使用保留域/文档网段/<TARGET>: ${value}`, truncate(line)));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R3 — no weaponized artifacts
// ---------------------------------------------------------------------------

const WEAPON_PATTERNS = [
  /eval\s*\(\s*\$_(POST|GET|REQUEST)/i,
  /assert\s*\(\s*\$_/i,
  /aspxspy|c99shell|b374k/i,
  /Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter/i,
  /bash\s+-i\s*>&\s*\/dev\/tcp\//i,
  /nc\s+(-[a-z]*e|.*\s-e\s)/i,
  /ncat\s+.*-e\s/i,
  /socat\s+.*EXEC:/i,
  /python[23]?\s+-c\s+['"]import\s+socket/i,
  /IEX\s*\(\s*New-Object\s+Net\.WebClient/i,
  /msfvenom\s+-p\s+/i,
  /mimikatz\s+sekurlsa::/i,
  /procdump.*lsass/i,
  /comsvcs\.dll.*MiniDump/i,
  /secretsdump(\.py)?\s+/i,
  /cobalt\s*strike\s+.*(beacon|powershell)/i,
  /meterpreter/i,
  /schtasks\s+\/create/i,
  /New-Service\s+/i,
  /reg\s+add\s+.*\\Run/i,
  /crontab\s+-e/i,
  /systemctl\s+enable\s+/i,
  />>\s*.*authorized_keys/i,
];
const DETECTION_INFO = /^(sigma|kql|spl|eql|yara)\b/;
const ARMED_INFO = new Set(["bash", "sh", "powershell", "pwsh", "cmd", "python", "http", "sql", "javascript"]);

function checkR3Weapon(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    const fences = fenceStates(f);
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const state = fences[i];
      if (state.isDelimiter) continue;
      let candidates = [];
      if (state.inFence) {
        if (DETECTION_INFO.test(state.info)) continue;
        candidates = [line];
      } else {
        candidates = inlineCodeSpans(line);
      }
      for (const candidate of candidates) {
        const hit = WEAPON_PATTERNS.find((re) => re.test(candidate));
        if (hit !== undefined) {
          out.push(finding("R3-WEAPON", f, i + 1, "检出武器化代码模式", truncate(candidate)));
          break;
        }
      }
    }
  }
  return out;
}

const DESTRUCTIVE_PATTERNS = [
  [/rm\s+-rf\s+\/(\s|$|\*)/i],
  [/dd\s+.*of=\/dev\/(sd|nvme|vd)/i],
  [/:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/],
  [/mkfs\./i],
  [/chmod\s+-R\s+777\s+\//i],
  [/vssadmin\s+(delete|resize)\s+shadows/i],
  [/bcdedit\s+\/set/i],
  [/cipher\s+\/w/i],
  [/format\s+[A-Za-z]:/i],
  [/DROP\s+DATABASE/],
  [/SHUTDOWN/],
];

function checkR3Destructive(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "workflow"])) {
    for (let i = 0; i < f.lines.length; i++) {
      for (const [re] of DESTRUCTIVE_PATTERNS) {
        if (re.test(f.lines[i])) {
          out.push(finding("R3-DESTRUCTIVE", f, i + 1, "检出破坏性命令", truncate(f.lines[i])));
          break;
        }
      }
    }
  }
  return out;
}

function checkR3AuthBanner(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    for (let i = 0; i < f.lines.length; i++) {
      const m = /^\s*(`{3,}|~{3,})\s*(\S*)(.*)$/.exec(f.lines[i]);
      if (m === null) continue;
      const info = (m[2] || "").toLowerCase();
      if (!ARMED_INFO.has(info)) continue;
      const windowText = f.lines.slice(Math.max(0, i - 3), i).join("\n");
      if (windowText.includes(POLICY.authBanner)) continue;
      out.push(finding("R3-AUTH-BANNER", f, i + 1, `攻击性代码块前 3 行缺少授权横幅（${info}）`, truncate(f.lines[i])));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R4 — authorization gates and safe defaults
// ---------------------------------------------------------------------------

function checkR4VerifyDisabled(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "workflow", "lib"])) {
    for (let i = 0; i < f.lines.length; i++) {
      if (!/verify\s*=\s*False/i.test(f.lines[i])) continue;
      if (isNegated(f.lines[i])) continue;
      out.push(finding("R4-VERIFY-DISABLED", f, i + 1, "禁止 verify=False（会关闭 TLS 校验）", truncate(f.lines[i])));
    }
  }
  return out;
}

function checkR4Wildcard(files) {
  const out = [];
  const patterns = [
    /--target\s+\*/i,
    /--cidr\s+(?:0\.0\.0\.0|::)\s*\/\s*0/i,
    /(?<![\d.])0\.0\.0\.0\/0(?![\d])/,
    /(?<!:)::\/0/,
    /["'\s]0\.0\.0\.0(?=["'\s,}\]]|$)/,
    /prefix(?:len|length)?\s*[:=]?\s*0\b/i,
  ];
  for (const f of filesOfKinds(files, ["skill", "reference", "policy", "asset"])) {
    for (let i = 0; i < f.lines.length; i++) {
      if (isNegated(f.lines[i])) continue;
      const hit = patterns.find((re) => re.test(f.lines[i]));
      if (hit !== undefined) {
        out.push(finding("R4-WILDCARD", f, i + 1, "禁止无界目标（通配/全网 CIDR）", truncate(f.lines[i])));
      }
    }
  }
  return out;
}

function checkR4DryRunDefault(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["workflow"])) {
    if (!/args\.dryRun\s*===\s*undefined\s*\?\s*true/s.test(f.text)) {
      out.push(finding("R4-DRYRUN-DEFAULT", f, 1, "workflow 缺少默认 true 的 dryRun 表达式", ""));
    }
  }
  return out;
}

function checkR4ScopeGate(files) {
  const out = [];
  const prefixes = ["G-AUTH-", "G-MODE-", "G-WIN-", "G-BUD-", "G-DH-"];
  for (const f of filesOfKinds(files, ["workflow"])) {
    const gates = new Set(f.text.match(/G-[A-Z]+-\d{2}/g) ?? []);
    if (gates.size < 8) out.push(finding("R4-SCOPE-GATE", f, 1, `workflow 门禁 ID 少于 8 个（实际 ${gates.size}）`, ""));
    for (const prefix of prefixes) {
      if (![...gates].some((g) => g.startsWith(prefix))) out.push(finding("R4-SCOPE-GATE", f, 1, `workflow 缺少 ${prefix}* 门禁`, ""));
    }
    if (![...gates].some((g) => g.startsWith("G-TGT-") || g.startsWith("G-DS-"))) {
      out.push(finding("R4-SCOPE-GATE", f, 1, "workflow 缺少 G-TGT-* 或 G-DS-* 门禁", ""));
    }
    const base = basename(f.abs);
    if (base === "exploit.js" || base === "post.js") {
      for (const gate of ["G-CFM-01", "G-CFM-02", "G-CFM-03", "G-CFM-04"]) {
        if (!f.text.includes(gate)) out.push(finding("R4-SCOPE-GATE", f, 1, `confirm 门禁缺少 ${gate}`, ""));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R5 — no fabricated content
// ---------------------------------------------------------------------------

function checkR5Fake(files) {
  const out = [];
  const re = /(simulated|synthetic|fake|mock|dummy)\s+(finding|result|scan|output|data|evidence)/i;
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    for (let i = 0; i < f.lines.length; i++) {
      if (!re.test(f.lines[i])) continue;
      if (isNegated(f.lines[i])) continue;
      out.push(finding("R5-FAKE", f, i + 1, "禁止生成 simulated/fake/mock 结果", truncate(f.lines[i])));
    }
  }
  return out;
}

const PERF_WORDS = /(检出率|准确率|成功率|覆盖率|误报率|detection\s+rate|accuracy|recall|precision)/i;
const SOURCE_HINT = /(source\s*:|来源\s*[:：]|https?:\/\/(?:[a-z0-9-]+\.)*(?:github\.com|nist\.gov|owasp\.org|mitre\.org|cve\.org|first\.org|sans\.org|cisa\.gov|sigmahq\.io|rfc-editor\.org))/i;

function checkR5Metric(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (!/\d+(\.\d+)?\s*%/.test(line)) continue;
      const windowText = f.lines.slice(Math.max(0, i - 3), Math.min(f.lines.length, i + 4)).join("\n");
      if (PERF_WORDS.test(line) || PERF_WORDS.test(windowText)) {
        if (SOURCE_HINT.test(windowText)) continue;
        out.push(finding("R5-METRIC", f, i + 1, "效能百分比缺少可溯源引用", truncate(line)));
      } else {
        out.push(finding("R5-METRIC", f, i + 1, "百分比数值需确认语境（warning）", truncate(line), "warning"));
      }
    }
  }
  return out;
}

function checkR5Cve(files) {
  const out = [];
  const re = /CVE[-_ ]?\d{4}[-_ ]?\d+/gi;
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    for (let i = 0; i < f.lines.length; i++) {
      for (const m of f.lines[i].matchAll(re)) {
        const raw = m[0];
        const normalized = raw.replace(/[-_ ]/g, "-").toUpperCase();
        if (!/^CVE-\d{4}-\d{4,7}$/.test(normalized)) {
          out.push(finding("R5-CVE", f, i + 1, `CVE 格式非法: ${raw}`, raw));
          continue;
        }
        const windowText = f.lines.slice(Math.max(0, i - 1), Math.min(f.lines.length, i + 2)).join("\n");
        if (!/已核实|待核实/.test(windowText)) {
          out.push(finding("R5-CVE", f, i + 1, `CVE 未标注核验状态: ${normalized}`, raw, "warning"));
        }
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R6 — structural limits
// ---------------------------------------------------------------------------

function countLines(file) {
  const lines = file.text.split(/\r?\n/);
  let end = lines.length;
  while (end > 0 && lines[end - 1].trim() === "") end -= 1;
  return end;
}

function checkR6SkillSize(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill"])) {
    const lineCount = countLines(f);
    if (lineCount > POLICY.maxSkillLines) {
      out.push(finding("R6-SKILL-SIZE", f, 1, `SKILL.md 行数 ${lineCount} 超过 ${POLICY.maxSkillLines}`, ""));
    }
    if (f.bytes > POLICY.maxSkillBytes) {
      out.push(finding("R6-SKILL-SIZE", f, 1, `SKILL.md 字节数 ${f.bytes} 超过 ${POLICY.maxSkillBytes}`, ""));
    }
  }
  return out;
}

function checkR6Desc(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill"])) {
    const fm = frontmatterOf(f);
    const desc = fm.meta.description;
    if (desc === undefined || desc === "") {
      out.push(finding("R6-DESC", f, 1, "frontmatter 缺少 description", ""));
    } else if ([...desc].length > POLICY.maxDescription) {
      out.push(finding("R6-DESC", f, keyLine(f, "description"), `description ${[...desc].length} 码点超过 ${POLICY.maxDescription}`, ""));
    }
  }
  return out;
}

function checkR6When(files) {
  const out = [];
  const placeholder = /^(n\/a|na|tbd|todo|待定|占位|占位符|无|none)$/i;
  for (const f of filesOfKinds(files, ["skill"])) {
    const fm = frontmatterOf(f);
    const value = (fm.meta.whenToUse ?? "").trim();
    if (value === "" || placeholder.test(value)) {
      out.push(finding("R6-WHEN", f, keyLine(f, "whenToUse"), "whenToUse 缺失或为占位词", value));
    }
  }
  return out;
}

function checkR6RefSize(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["reference"])) {
    const isIndex = basename(f.abs) === "INDEX.md";
    if (isIndex && f.bytes > POLICY.maxIndexBytes) {
      out.push(finding("R6-REF-SIZE", f, 1, `INDEX.md 字节数 ${f.bytes} 超过 ${POLICY.maxIndexBytes}`, "", "warning"));
    } else if (!isIndex && f.bytes > POLICY.maxReferenceBytes) {
      out.push(finding("R6-REF-SIZE", f, 1, `reference 字节数 ${f.bytes} 超过 ${POLICY.maxReferenceBytes}`, ""));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R7 — dedupe and trigger isolation
// ---------------------------------------------------------------------------

const STOPWORDS = [
  "触发词", "适用", "技能", "使用", "场景", "输出", "产出", "输入", "执行", "提供", "支持",
  "包含", "需要", "可以", "以及", "通过", "基于", "进行", "实现", "相关", "目标", "数据",
  "方法", "结果", "的", "了", "与", "和", "及", "或", "在", "用", "为", "对", "不", "本",
].sort((a, b) => b.length - a.length);

function bigramsOf(description) {
  let s = String(description).toLowerCase();
  s = s.replace(/dsh-[a-z0-9-]+/g, " ");
  s = s.replace(/[a-z0-9]+/g, " ");
  s = s.replace(/[^\u4e00-\u9fff]+/g, " ");
  const out = new Set();
  for (let segment of s.split(/\s+/)) {
    if (segment === "") continue;
    for (const word of STOPWORDS) segment = segment.split(word).join("");
    const chars = [...segment];
    for (let i = 0; i + 1 < chars.length; i++) out.add(chars[i] + chars[i + 1]);
  }
  return out;
}

function jaccard(a, b) {
  if (a.size === 0 && b.size === 0) return 0;
  let inter = 0;
  for (const item of a) if (b.has(item)) inter += 1;
  return inter / (a.size + b.size - inter);
}

function laneOf(name) {
  const m = /^dsh-(rb|red|blue|purple)-/.exec(name);
  return m === null ? null : m[1];
}

function skillEntries(files) {
  const skills = [];
  for (const f of filesOfKinds(files, ["skill"])) {
    const fm = frontmatterOf(f);
    skills.push({ file: f, meta: fm.meta, name: fm.meta.name ?? "", description: fm.meta.description ?? "" });
  }
  return skills;
}

function libSkillNames(files) {
  const names = new Set();
  for (const f of filesOfKinds(files, ["lib"])) {
    for (const m of f.text.matchAll(/name:\s*"([^"]+)"/g)) {
      if (/^dsh-(rb|red|blue|purple)-[a-z0-9-]+$/.test(m[1])) names.add(m[1]);
    }
  }
  return names;
}

function checkR7Name(files) {
  const out = [];
  const skills = skillEntries(files);
  const seen = new Map();
  for (const s of skills) {
    if (!/^dsh-(rb|red|blue|purple)-[a-z0-9-]+$/.test(s.name)) {
      out.push(finding("R7-NAME", s.file, keyLine(s.file, "name"), `技能名不符合 dsh-<lane>-<name> 形式: ${s.name}`, ""));
      continue;
    }
    if (seen.has(s.name)) {
      out.push(finding("R7-NAME", s.file, keyLine(s.file, "name"), `技能名重复: ${s.name}`, "")); 
    } else {
      seen.set(s.name, s);
    }
  }
  const declared = libSkillNames(files);
  if (skills.length > 0 && declared.size > 0) {
    const actual = new Set(skills.map((s) => s.name));
    for (const name of declared) {
      if (!actual.has(name)) out.push(finding("R7-NAME", filesOfKinds(files, ["lib"])[0], 1, `lib/index.js 声明的技能缺少 SKILL.md: ${name}`, ""));
    }
    for (const name of actual) {
      if (!declared.has(name)) out.push(finding("R7-NAME", seen.get(name)?.file ?? files[0], 1, `SKILL.md 的技能未在 lib/index.js 声明: ${name}`, ""));
    }
  }
  return out;
}

function checkR7Jaccard(files) {
  const out = [];
  const skills = skillEntries(files).filter((s) => s.description !== "");
  const byLane = new Map();
  for (const s of skills) {
    const lane = laneOf(s.name);
    if (lane === null) continue;
    if (!byLane.has(lane)) byLane.set(lane, []);
    byLane.get(lane).push({ ...s, grams: bigramsOf(s.description) });
  }
  for (const [lane, entries] of byLane) {
    for (let i = 0; i < entries.length; i++) {
      for (let j = i + 1; j < entries.length; j++) {
        const value = jaccard(entries[i].grams, entries[j].grams);
        if (value > POLICY.jaccardThreshold) {
          out.push(finding("R7-JACCARD", entries[i].file, keyLine(entries[i].file, "description"),
            `lane ${lane} 内 description Jaccard ${value.toFixed(3)} 超过 ${POLICY.jaccardThreshold}（${entries[i].name} vs ${entries[j].name}）`, ""));
        }
      }
    }
  }
  return out;
}

function checkR7Negative(files) {
  const out = [];
  const skills = skillEntries(files);
  const registered = new Set([...CANONICAL_SKILLS, ...skills.map((s) => s.name)]);
  for (const s of skills) {
    const desc = s.description;
    if (desc === "") {
      out.push(finding("R7-NEGATIVE", s.file, keyLine(s.file, "description"), "description 为空，缺少触发词与负向边界", ""));
      continue;
    }
    const triggerIndex = desc.indexOf("触发词：");
    const negativeIndex = desc.indexOf("不适用：");
    if (triggerIndex < 0) {
      out.push(finding("R7-NEGATIVE", s.file, keyLine(s.file, "description"), "description 缺少“触发词：”段", ""));
    } else {
      const end = negativeIndex > triggerIndex ? negativeIndex : desc.length;
      const raw = desc.slice(triggerIndex + "触发词：".length, end);
      const items = raw.split(/[、,，;；]/).map((x) => x.trim()).filter((x) => x !== "");
      if (items.length < 2) {
        out.push(finding("R7-NEGATIVE", s.file, keyLine(s.file, "description"), "“触发词：”后少于 2 个分隔项", raw));
      }
    }
    if (negativeIndex < 0) {
      out.push(finding("R7-NEGATIVE", s.file, keyLine(s.file, "description"), "description 缺少“不适用：”段", ""));
    } else {
      const tail = desc.slice(negativeIndex + "不适用：".length);
      const siblings = [...tail.matchAll(/dsh-(rb|red|blue|purple)-[a-z0-9-]+/g)]
        .map((m) => m[0])
        .filter((name) => name !== s.name && registered.has(name));
      if (siblings.length === 0) {
        out.push(finding("R7-NEGATIVE", s.file, keyLine(s.file, "description"), "“不适用：”未点名已注册的兄弟技能", tail));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R8 — prompt-injection boundary
// ---------------------------------------------------------------------------

function boundarySection(file) {
  const start = file.lines.findIndex((line) => /^##\s*安全边界\s*$/.test(line));
  if (start < 0) return null;
  let end = file.lines.length;
  for (let i = start + 1; i < file.lines.length; i++) {
    if (/^##\s+/.test(file.lines[i])) { end = i; break; }
  }
  return { start, text: file.lines.slice(start, end).join("\n") };
}

function checkR8Skill(files) {
  const out = [];
  for (const s of skillEntries(files)) {
    if ((s.meta.ingests ?? "").trim() !== "target") continue;
    const section = boundarySection(s.file);
    if (section === null) {
      out.push(finding("R8-SKILL", s.file, 1, "ingests: target 的技能缺少“## 安全边界”段", ""));
      continue;
    }
    for (const phrase of INGEST_BOUNDARY_PHRASES) {
      if (!section.text.includes(phrase)) {
        out.push(finding("R8-SKILL", s.file, section.start + 1, `安全边界段缺少短语: ${phrase}`, ""));
      }
    }
  }
  return out;
}

function checkR8Workflow(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["workflow"])) {
    for (const phrase of INGEST_BOUNDARY_PHRASES) {
      if (!f.text.includes(phrase)) out.push(finding("R8-WORKFLOW", f, 1, `workflow 未注入 UNTRUSTED_CLAUSE 短语: ${phrase}`, ""));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R9 — freshness
// ---------------------------------------------------------------------------

function checkR9LastVerified(files) {
  const out = [];
  for (const s of skillEntries(files)) {
    const value = s.meta["last-verified"];
    if (value === undefined || value === "") {
      out.push(finding("R9-LAST-VERIFIED", s.file, keyLine(s.file, "last-verified"), "缺少 last-verified", ""));
    } else if (!validDateString(value)) {
      out.push(finding("R9-LAST-VERIFIED", s.file, keyLine(s.file, "last-verified"), `last-verified 不是合法日期: ${value}`, value));
    }
  }
  for (const f of filesOfKinds(files, ["reference"])) {
    const prov = provenanceOf(f);
    if (prov === null) continue;
    const value = prov.meta["last-verified"];
    if (value === undefined || value === "") {
      out.push(finding("R9-LAST-VERIFIED", f, prov.line, "缺少 last-verified", ""));
    } else if (!validDateString(value)) {
      out.push(finding("R9-LAST-VERIFIED", f, prov.line, `last-verified 不是合法日期: ${value}`, value));
    }
  }
  return out;
}

function checkR9VersionFresh(files) {
  const out = [];
  const visit = (file, value, line) => {
    const days = daysBetweenUtc(value ?? "");
    if (days === null) return;
    if (days > POLICY.freshnessBlockDays) {
      out.push(finding("R9-VERSION-FRESH", file, line, `last-verified 距今 ${days} 天，超过 ${POLICY.freshnessBlockDays} 天`, value));
    } else if (days > POLICY.freshnessWarnDays) {
      out.push(finding("R9-VERSION-FRESH", file, line, `last-verified 距今 ${days} 天，超过 ${POLICY.freshnessWarnDays} 天`, value, "warning"));
    }
  };
  for (const s of skillEntries(files)) visit(s.file, s.meta["last-verified"], keyLine(s.file, "last-verified"));
  for (const f of filesOfKinds(files, ["reference"])) {
    const prov = provenanceOf(f);
    if (prov === null) continue;
    visit(f, prov.meta["last-verified"], prov.line);
    if (prov.type === "provenance") {
      // Strip IP/CIDR tokens first so documentation ranges do not look like version numbers.
      const versionText = f.text.replace(IPV4_RE, " ").replace(IPV6_RE, " ");
      const versionHits = (versionText.match(/\bv?\d+\.\d+/g) ?? []).length
        + (versionText.match(/\bCIS\b/g) ?? []).length
        + (versionText.match(/\bbaseline\b/gi) ?? []).length
        + (versionText.match(/版本/g) ?? []).length;
      if (versionHits >= 3 && !/版本时效/.test(f.text)) {
        out.push(finding("R9-VERSION-FRESH", f, 1, "含版本/基线内容但缺少“版本时效”说明", "", "warning"));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R10 — secrets and PII
// ---------------------------------------------------------------------------

const SECRET_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,
  /AIza[0-9A-Za-z_-]{35}/,
  /gh[pousr]_[A-Za-z0-9]{36,}/,
  /xox[baprs]-[0-9A-Za-z-]{10,}/,
  /sk_live_[0-9a-zA-Z]{24,}/,
  /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/,
  /-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/,
  /(api[_-]?key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_-]{16,}['"]/i,
];
const PLACEHOLDER_HINT = /example|changeme|placeholder|redacted|<[^>]{1,40}>|xxx|…/i;

function checkR10Secret(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "policy"])) {
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      if (PLACEHOLDER_HINT.test(line)) continue;
      const hit = SECRET_PATTERNS.find((re) => re.test(line));
      if (hit !== undefined) out.push(finding("R10-SECRET", f, i + 1, "检出疑似密钥/令牌/私钥", truncate(line)));
    }
  }
  return out;
}

function checkR10Pii(files) {
  const out = [];
  const phone = /(?<!\d)1[3-9]\d{9}(?!\d)/;
  const ssn = /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/;
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      for (const m of line.matchAll(EMAIL_RE)) {
        if (isAllowedEmailHost(m[1])) continue;
        out.push(finding("R10-PII", f, i + 1, `非保留域邮箱（PII）: ${m[0]}`, m[0]));
      }
      if (phone.test(line)) out.push(finding("R10-PII", f, i + 1, "疑似中国大陆手机号", truncate(line)));
      if (ssn.test(line)) out.push(finding("R10-PII", f, i + 1, "疑似美式 SSN", truncate(line)));
    }
  }
  return out;
}

function checkR10InternalHost(files) {
  const out = [];
  const re = /(?<![A-Za-z0-9.-])([a-z0-9-]+\.(?:internal|corp|lan|local|home|intranet))\b/gi;
  for (const f of filesOfKinds(files, ["skill", "reference", "asset"])) {
    for (let i = 0; i < f.lines.length; i++) {
      for (const m of f.lines[i].matchAll(re)) {
        const host = m[1].toLowerCase();
        if (host === "dsh.local" || host.endsWith(".dsh.local") || host === "localhost") continue;
        out.push(finding("R10-INTERNAL-HOST", f, i + 1, `禁止出现内网主机名: ${host}`, host));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R11 — terminology (warning)
// ---------------------------------------------------------------------------

function checkR11Terminology(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["skill", "reference", "policy"])) {
    if (/finding/i.test(f.text) && /发现(?!阶段|到|了|的|漏洞|问题)/.test(f.text)) {
      const line = f.lines.findIndex((l) => /发现(?!阶段|到|了|的|漏洞|问题)/.test(l)) + 1;
      out.push(finding("R11-TERMINOLOGY", f, line, "同一文件混用对象 finding 与中文“发现”作名词", ""));
    }
    if (/\bscope\b/i.test(f.text) && /范围对象/.test(f.text)) {
      out.push(finding("R11-TERMINOLOGY", f, 1, "同一文件混用 scope 与“范围对象”", "", "warning"));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// R12 — risk classification and safe defaults
// ---------------------------------------------------------------------------

function checkR12Risk(files) {
  const out = [];
  for (const s of skillEntries(files)) {
    const expected = EXPECTED_SKILLS[s.name];
    if (expected === undefined) {
      out.push(finding("R12-RISK", s.file, keyLine(s.file, "name"), `未知技能名，无法核对 risk/requires: ${s.name}`, ""));
      continue;
    }
    if ((s.meta.risk ?? "") !== expected.risk) {
      out.push(finding("R12-RISK", s.file, keyLine(s.file, "risk"), `risk 与期望表不符: ${s.meta.risk ?? "(缺失)"} != ${expected.risk}`, ""));
    }
    if ((s.meta.requires ?? "") !== expected.requires) {
      out.push(finding("R12-RISK", s.file, keyLine(s.file, "requires"), `requires 与期望表不符: ${s.meta.requires ?? "(缺失)"} != ${expected.requires}`, ""));
    }
  }
  return out;
}

function checkR12Confirm(files) {
  const out = [];
  for (const f of filesOfKinds(files, ["workflow"])) {
    const base = basename(f.abs);
    const gates = ["G-CFM-01", "G-CFM-02", "G-CFM-03", "G-CFM-04"];
    if (base === "exploit.js" || base === "post.js") {
      for (const gate of gates) {
        if (!f.text.includes(gate)) out.push(finding("R12-CONFIRM", f, 1, `exploit/post 缺少 ${gate}`, ""));
      }
      if (!/confirm/.test(f.text)) out.push(finding("R12-CONFIRM", f, 1, "exploit/post 缺少 confirm 变量", ""));
    } else if (/G-CFM-/.test(f.text)) {
      out.push(finding("R12-CONFIRM", f, 1, "非 exploit/post workflow 不应出现 G-CFM 门禁（warning）", "", "warning"));
    }
  }
  return out;
}

function checkR12ReportOnly(files) {
  const out = [];
  const patterns = [
    /autoRemediate\s*[:=]\s*true/i,
    /autoExecute\s*[:=]\s*true/i,
    /自动执行(修复|遏制|利用)/,
  ];
  for (const f of filesOfKinds(files, ["skill", "reference", "workflow"])) {
    for (let i = 0; i < f.lines.length; i++) {
      const line = f.lines[i];
      const hit = patterns.find((re) => re.test(line));
      if (hit !== undefined && !isNegated(line)) {
        out.push(finding("R12-REPORT-ONLY", f, i + 1, "禁止默认自动执行/自动修复", truncate(line)));
        continue;
      }
      if (/--force/.test(line) && !/需显式|禁止|不得|不允许|拒绝|显式|requires?/i.test(line)) {
        out.push(finding("R12-REPORT-ONLY", f, i + 1, "--force 不得作为默认行为", truncate(line)));
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Runner wiring
// ---------------------------------------------------------------------------

const RUNNERS = {
  "R1-PROVENANCE": checkR1Provenance,
  "R1-NOTICE": checkR1Notice,
  "R1-LICENSE": checkR1License,
  "R2-RESERVED": checkR2Reserved,
  "R2-AUTHORITY-LINK": checkR2AuthorityLink,
  "R2-PRIVATE": checkR2Private,
  "R2-DENYLIST": checkR2Denylist,
  "R2-EXAMPLE-TARGET": checkR2ExampleTarget,
  "R3-WEAPON": checkR3Weapon,
  "R3-DESTRUCTIVE": checkR3Destructive,
  "R3-AUTH-BANNER": checkR3AuthBanner,
  "R4-VERIFY-DISABLED": checkR4VerifyDisabled,
  "R4-WILDCARD": checkR4Wildcard,
  "R4-DRYRUN-DEFAULT": checkR4DryRunDefault,
  "R4-SCOPE-GATE": checkR4ScopeGate,
  "R5-FAKE": checkR5Fake,
  "R5-METRIC": checkR5Metric,
  "R5-CVE": checkR5Cve,
  "R6-SKILL-SIZE": checkR6SkillSize,
  "R6-DESC": checkR6Desc,
  "R6-WHEN": checkR6When,
  "R6-REF-SIZE": checkR6RefSize,
  "R7-NAME": checkR7Name,
  "R7-JACCARD": checkR7Jaccard,
  "R7-NEGATIVE": checkR7Negative,
  "R8-SKILL": checkR8Skill,
  "R8-WORKFLOW": checkR8Workflow,
  "R9-LAST-VERIFIED": checkR9LastVerified,
  "R9-VERSION-FRESH": checkR9VersionFresh,
  "R10-SECRET": checkR10Secret,
  "R10-PII": checkR10Pii,
  "R10-INTERNAL-HOST": checkR10InternalHost,
  "R11-TERMINOLOGY": checkR11Terminology,
  "R12-RISK": checkR12Risk,
  "R12-CONFIRM": checkR12Confirm,
  "R12-REPORT-ONLY": checkR12ReportOnly,
};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

let POLICY = { ...DEFAULT_POLICY };

function usage() {
  return [
    "usage: node tools/sanitize-lint.mjs [--strict] [--json] [--check <ID[,ID...]>]",
    "                                  [--list-checks] [--allow-empty] [paths...]",
    "       node tools/sanitize-lint.mjs --policy <path> --allow-policy-override [paths...]",
    "",
    "note: --policy is test-only and needs NODE_ENV=test or --allow-policy-override;",
    "      release gates must never pass --policy (see R7 risk note in docs/sanitization-rules.md).",
  ].join("\n");
}

function parseArgs(argv) {
  const opts = { strict: false, json: false, checks: null, list: false, policyPath: null, allowPolicyOverride: false, allowEmpty: false, paths: [] };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--strict") opts.strict = true;
    else if (arg === "--json") opts.json = true;
    else if (arg === "--allow-empty") opts.allowEmpty = true;
    else if (arg === "--allow-policy-override") opts.allowPolicyOverride = true;
    else if (arg === "--list-checks") opts.list = true;
    else if (arg === "--check") {
      const raw = argv[++i];
      if (raw === undefined) throw new Error("--check 需要一个逗号分隔的检查 ID");
      opts.checks = raw.split(",").map((s) => s.trim()).filter(Boolean);
    } else if (arg === "--policy") {
      const raw = argv[++i];
      if (raw === undefined) throw new Error("--policy 需要一个文件路径");
      opts.policyPath = raw;
    } else if (arg === "--help" || arg === "-h") {
      opts.help = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`未知参数: ${arg}`);
    } else {
      opts.paths.push(arg);
    }
  }
  if (opts.policyPath !== null && !opts.allowPolicyOverride && process.env.NODE_ENV !== "test") {
    throw new Error("--policy 只允许测试使用：需要 NODE_ENV=test 或显式 --allow-policy-override（发布门禁不得覆盖 POLICY）");
  }
  return opts;
}

function loadPolicy(path) {
  const raw = JSON.parse(readFileSync(resolve(path), "utf8"));
  POLICY = { ...DEFAULT_POLICY, ...raw };
}

function renderText(findings, checkedFiles) {
  const lines = [`dsh-redblue sanitize lint (${POLICY_VERSION})`];
  for (const f of findings) {
    lines.push(`[${f.level}] ${f.id} ${f.file}:${f.line} ${f.message}${f.evidence ? " :: " + f.evidence : ""}`);
  }
  const blockers = findings.filter((f) => f.level === "blocker").length;
  const warnings = findings.filter((f) => f.level === "warning").length;
  lines.push(`summary: files=${checkedFiles} blockers=${blockers} warnings=${warnings}`);
  return lines.join("\n") + "\n";
}

function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(error.message + "\n" + usage() + "\n");
    return 2;
  }
  if (opts.help) {
    process.stdout.write(usage() + "\n");
    return 0;
  }
  try {
    if (opts.policyPath !== null) loadPolicy(opts.policyPath);
  } catch (error) {
    process.stderr.write(`无法加载 policy 文件: ${error.message}\n`);
    return 2;
  }
  if (opts.list) {
    for (const def of CHECK_DEFS) process.stdout.write(`${def.id}\t${def.rule}\t${def.level}\t${def.kinds.join(",")}\n`);
    return 0;
  }
  let selected = CHECK_DEFS;
  if (opts.checks !== null) {
    const unknown = opts.checks.filter((id) => !CHECK_BY_ID.has(id));
    if (unknown.length > 0) {
      process.stderr.write(`未知检查 ID: ${unknown.join(",")}\n`);
      return 2;
    }
    selected = opts.checks.map((id) => CHECK_BY_ID.get(id));
  }
  const paths = opts.paths.length > 0 ? opts.paths : [PLUGIN_ROOT];
  let files;
  try {
    files = collectFiles(paths);
  } catch (error) {
    process.stderr.write(`无法读取路径: ${error.message}\n`);
    return 2;
  }
  if (files.length === 0 && !opts.allowEmpty) {
    process.stderr.write("未找到可扫描文件（目录为空或无匹配扩展名）；如确认是空扫描，使用 --allow-empty\n");
    return 2;
  }
  const findings = [];
  try {
    for (const def of selected) findings.push(...RUNNERS[def.id](files));
  } catch (error) {
    process.stderr.write(`检查执行失败: ${error.stack ?? error.message}\n`);
    return 2;
  }
  findings.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : a.line - b.line || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)));
  const blockers = findings.filter((f) => f.level === "blocker").length;
  const warnings = findings.filter((f) => f.level === "warning").length;
  if (opts.json) {
    const payload = {
      version: VERSION,
      policy: POLICY.version ?? POLICY_VERSION,
      generatedAt: new Date().toISOString(),
      strict: opts.strict,
      checks: findings,
      summary: { blockers, warnings, checkedFiles: files.length },
    };
    process.stdout.write(JSON.stringify(payload, null, 2) + "\n");
  } else {
    process.stdout.write(renderText(findings, files.length));
  }
  return opts.strict && blockers > 0 ? 1 : 0;
}

process.exitCode = main();
