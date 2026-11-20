import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import { checkScope } from "../tools/lib/gate.mjs";
import { runGuard } from "../tools/lib/guard.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const workflowDir = resolve(root, "workflow");
const skillDir = "C:/dsh-workspace/branch1/dsh-redblue/skills";

const WORKFLOWS = ["assess", "recon", "exploit", "post", "hunt", "ir", "purple", "triage", "harden", "reverse"];
// skills/run/SKILL.md 的路由表属于 t36 的 outOfScope；v0.2 的 reverse 路由由文档同步任务补齐。
const ENTRY_ROUTED_WORKFLOWS = WORKFLOWS.filter((workflow) => workflow !== "reverse");

function loadWorkflow(name) {
  const source = readFileSync(resolve(workflowDir, name + ".js"), "utf8");
  return vm.runInNewContext(
    "(async function(args, phase, log, agent, parallel, pipeline) {\n" + source + "\n})",
    { console },
  );
}

const NOW = Date.now();
const isoDate = (ms) => new Date(ms).toISOString().slice(0, 10);
const isoTime = (ms) => new Date(ms).toISOString();

function baseScope(overrides = {}) {
  return Object.assign({
    authorization: {
      type: "written",
      reference: "ROE-TEST-001",
      grantedBy: "Security Office",
      validFrom: isoDate(NOW - 86400000),
      validTo: isoDate(NOW + 86400000),
    },
    targets: [
      { kind: "url", value: "https://app.example.com/login" },
      { kind: "domain", value: "app.example.com" },
    ],
    exclusions: [],
    mode: "passive",
    window: { start: isoTime(NOW - 3600000), end: isoTime(NOW + 3600000) },
    budget: { maxRequests: 100, maxMinutes: 60 },
    dataHandling: { retain: "findings-only", secrets: "mask-and-redact", destruction: "none" },
    dataSources: [],
  }, overrides);
}

function dataSource(kind, value, extra = {}) {
  return Object.assign({ kind, value }, extra);
}

function argsFor(workflow, overrides = {}) {
  const scope = baseScope();
  const workDir = "C:/work/rb-" + workflow;
  const base = { scope, workDir, skillDir, maxConcurrency: 2, dryRun: true };
  if (workflow === "recon") return Object.assign(base, { activeScan: false }, overrides);
  if (workflow === "exploit") {
    scope.mode = "exploit";
    scope.dataSources = [dataSource("findings", "C:/work/findings.json")];
    return Object.assign(base, { confirm: "app.example.com" }, overrides);
  }
  if (workflow === "post") {
    scope.mode = "post";
    return Object.assign(base, { confirm: "app.example.com" }, overrides);
  }
  if (workflow === "hunt") {
    scope.dataSources = [dataSource("logs", "C:/work/telemetry.jsonl")];
    return Object.assign(base, overrides);
  }
  if (workflow === "ir") {
    scope.dataSources = [dataSource("evidence", "C:/work/evidence")];
    return Object.assign(base, overrides);
  }
  if (workflow === "purple") {
    scope.dataSources = [dataSource("findings", "C:/work/findings.json"), dataSource("detections", "C:/work/rules")];
    return Object.assign(base, overrides);
  }
  if (workflow === "triage") {
    scope.dataSources = [dataSource("finding", "C:/work/finding.json")];
    return Object.assign(base, overrides);
  }
  if (workflow === "harden") {
    scope.dataSources = [dataSource("baseline", "C:/work/baseline.json", { version: "1.0", lastVerified: isoDate(NOW) })];
    return Object.assign(base, overrides);
  }
  if (workflow === "reverse") {
    scope.targets = [{ kind: "source", value: REVERSE_TARGET }];
    return Object.assign(base, { runtime: false }, overrides);
  }
  return Object.assign(base, overrides);
}

function sha256Of(text) {
  return createHash("sha256").update(text).digest("hex");
}

function contentOfPrompt(prompt) {
  const match = /文件开始 >>>\n([\s\S]*?)\n<<< 文件结束/.exec(prompt);
  return match === null ? null : match[1];
}

function reportWriteReply(prompt) {
  const content = contentOfPrompt(prompt);
  if (content === null) return { ok: false, error: "prompt lacks content markers", sha256: "unknown", bytes: null };
  return { ok: true, sha256: sha256Of(content), bytes: Buffer.byteLength(content, "utf8") };
}

function tamperedReply(prompt, path) {
  const content = contentOfPrompt(prompt);
  if (content === null) return { ok: false, error: "prompt lacks content markers", sha256: "unknown", bytes: null };
  const tampered = content.length > 0 ? (content[0] === "{" ? "[" : "x") + content.slice(1) : "x";
  return { ok: true, path: path, sha256: sha256Of(tampered), bytes: Buffer.byteLength(tampered, "utf8") };
}

const REVERSE_TARGET = "C:/samples/app.exe";
const REVERSE_SHA = "a".repeat(64);
const REVERSE_BUNDLE = JSON.stringify({ schemaVersion: "rea-evidence/v1", records: [] });

const DEFAULT_REPLIES = [
  [/^scope$/, () => ({ ok: true, notes: "scope ok" })],
  [/^recon$/, () => ({ assets: [{ kind: "domain", value: "app.example.com", source: "ct", confidence: "high", passive: true }], exposures: [], limitations: [] })],
  [/^surface$/, () => ({ hypotheses: [{ id: "H1", title: "public login", entryPoint: "https://app.example.com/login", trustBoundary: "internet", attackIds: ["T1190"], priority: "high", rationale: "x" }], limitations: [] })],
  [/^discover:/, () => ({ candidates: [{ title: "Reflected XSS", category: "cross-site scripting", target: { kind: "url", value: "https://app.example.com/login?q=x" }, claim: "c", evidence: "e", confidence: "medium", attack: [{ id: "T1059.007" }] }], limitations: [] })],
  [/^validate:/, () => ({ title: "Reflected XSS", category: "cross-site scripting", target: { kind: "url", value: "https://app.example.com/login?q=x" }, severity: "medium", disposition: "suppressed", confidence: "high", claim: "c", evidence: "e", remediation: "r" })],
  [/^validate$/, () => ({ findings: [] })],
  [/^exploit$/, () => ({ actions: [], findings: [] })],
  [/^post$/, () => ({ paths: [] })],
  [/^hunt:plan$/, () => ({ hypotheses: [{ id: "H1", attackId: "T1071", hypothesis: "dns beacon", telemetryRequired: ["dns"], successCriteria: "x" }] })],
  [/^hunt:/, () => ({ hypothesisId: "H1", status: "refuted", evidenceRefs: [] })],
  [/^intake$/, () => ({ files: [] })],
  [/^triage$/, () => ({ severity: "low", scope: "host", confidence: "medium", findings: [] })],
  [/^timeline$/, () => ({ events: [] })],
  [/^containment$/, () => ({ recommendations: [] })],
  [/^redActions$/, () => ({ actions: [] })],
  [/^detectCoverage$/, () => ({ detections: [], limitations: [] })],
  [/^gaps$/, () => ({ matrix: [], summary: {}, gaps: [], limitations: [] })],
  [/^finding$/, () => ({ id: "EXT-1", title: "External XSS", severity: "medium", source: "scanner", category: "xss", target: { kind: "url", value: "https://app.example.com/x" }, claim: "c", evidence: "e", confidence: "medium" })],
  [/^review$/, () => ({ reviewNotes: "ok", evidenceRefs: [] })],
  [/^disposition$/, () => ({ disposition: "suppressed", severity: "medium", confidence: "high", claim: "c", evidence: "e", remediation: "r", evidenceRefs: [] })],
  [/^write$/, () => ({ written: true, count: 1 })],
  [/^baseline$/, () => ({ baseline: [{ framework: "CIS", version: "1.0", lastVerified: isoDate(NOW), sourceRef: "x" }], controls: [{ controlId: "C1", title: "t", expected: "e", severity: "medium" }] })],
  [/^check:/, () => ({ controlId: "C1", status: "pass", observed: "o", evidenceRefs: [] })],
  [/^remediation$/, () => ({ items: [] })],
  [/^verify$/, () => ({ verified: [] })],
  [/^reverse-scope$/, () => ({
    reaAvailable: true,
    server: { package: "rea-agents", version: "6.9.0", skillVersion: 62, protocol: "2026-07-28", catalog: { mcpTools: 3, cliCommands: 2, prompts: 1 } },
    providers: [{ id: "ghidra", kind: "static-engine", available: true, version: "12.1.4", reason: null, remediation: null }, { id: "jadx", kind: "parser", available: false, version: null, reason: "provider_missing", remediation: "set REA_JADX_MCP_JAR" }],
    runtimeProviders: [{ id: "frida", kind: "runtime", available: "unknown", reason: null, remediation: "probe list_frida_devices" }],
    toolAvailability: { immediate: 1, targetRequired: 1, hardUnavailable: 1, byReason: { provider_missing: 1 } },
    targetKind: "pe",
    target: { path: REVERSE_TARGET, sha256: REVERSE_SHA, bytes: 118256, format: "pe", architecture: "x86_64" },
    suggestedTools: ["open_binary", "inspect_pe_imports"],
    degraded: [],
    limitations: [],
  })],
  [/^reverse-inventory$/, () => ({
    ok: true,
    target: { path: REVERSE_TARGET, sha256: REVERSE_SHA, bytes: 118256, format: "pe" },
    members: [],
    evidenceIds: ["ev_" + "b".repeat(64)],
    sideEffects: [{ kind: "engine-start", provider: "ghidra", targetExecuted: false, closed: true }],
    unknowns: [],
    degraded: [],
    limitations: [],
  })],
  [/^reverse-static$/, () => ({
    candidates: [{ title: "unsigned binary", category: "hardening-gap", target: { kind: "source", value: REVERSE_TARGET }, claim: "no signature", evidence: "e", confidence: "derived", authority: "shipped-artifact", evidenceId: "ev_" + "c".repeat(64), operation: "inspect_pe_certificates", disposition: "deferred", limitations: ["static only"] }],
    evidence: [{ evidenceId: "ev_" + "c".repeat(64), operation: "inspect_pe_certificates" }],
    techniques: [],
    degraded: [{ capability: "inspect_binary_hardening", reason: "client_schema_error", remediation: "use inspect_pe_load_config", effect: "hardening_not_assessed" }],
    limitations: ["static only"],
  })],
  [/^reverse-runtime$/, () => ({
    executed: false,
    providers: [],
    actions: [],
    cleanup: [],
    candidates: [],
    evidence: [],
    degraded: [{ capability: "frida", reason: "provider_unavailable", effect: "runtime_not_executed" }],
    limitations: [],
  })],
  [/^reverse-report-export$/, () => ({
    ok: true,
    path: "evidence/rea-evidence.json",
    bytes: Buffer.byteLength(REVERSE_BUNDLE, "utf8"),
    sha256: sha256Of(REVERSE_BUNDLE),
    records: 1,
    evidenceIds: ["ev_" + "b".repeat(64)],
    content: REVERSE_BUNDLE,
    fallback: false,
    cleanup: [],
    limitations: [],
  })],
  [/^report-write:/, (label, prompt) => reportWriteReply(prompt)],
  [/^seal$/, () => ({ ok: true, checks: [{ name: "hash-match", pass: true }], mismatches: [] })],
  [/^seal-write$/, () => ({ ok: true, path: "scan-manifest.json" })],
];

function replyFor(custom) {
  return (label, prompt) => {
    if (custom) {
      const value = custom(label, prompt);
      if (value !== undefined) return typeof value === "string" ? value : JSON.stringify(value);
    }
    for (const [pattern, make] of DEFAULT_REPLIES) if (pattern.test(label)) return JSON.stringify(make(label, prompt));
    return JSON.stringify({ ok: true });
  };
}

function makeHarness(custom) {
  const calls = [];
  const batchSizes = [];
  const reply = replyFor(custom);
  const agent = async (prompt, options = {}) => {
    const label = String(options.label ?? "");
    calls.push({ label, phase: options.phase, prompt });
    return reply(label, prompt);
  };
  const phase = (name) => calls.push({ phase: name });
  const parallel = async (thunks) => {
    batchSizes.push(thunks.length);
    return Promise.all(thunks.map(async (thunk) => { try { return await thunk(); } catch { return null; } }));
  };
  const pipeline = async (items, ...stages) => {
    const out = [];
    for (let index = 0; index < items.length; index++) {
      let previous = items[index];
      let ok = true;
      for (const stage of stages) {
        try { previous = await stage(previous, items[index], index); } catch { ok = false; break; }
      }
      out.push(ok ? previous : null);
    }
    return out;
  };
  return { calls, batchSizes, agent, phase, parallel, pipeline, log: () => {} };
}

async function runWorkflow(workflow, args, custom) {
  const harness = makeHarness(custom);
  const result = await loadWorkflow(workflow)(args, harness.phase, harness.log, harness.agent, harness.parallel, harness.pipeline);
  return { result, harness };
}

function agentCalls(harness) {
  return harness.calls.filter((entry) => typeof entry.label === "string");
}

function promptOf(harness, prefix) {
  return agentCalls(harness).filter((entry) => entry.label.startsWith(prefix)).map((entry) => entry.prompt).join("\n");
}

// ---------------------------------------------------------------------------
// Static contract checks
// ---------------------------------------------------------------------------

test("ten workflow scripts exist, pass syntax, and expose no fs/network/Node API", () => {
  for (const workflow of WORKFLOWS) {
    const source = readFileSync(resolve(workflowDir, workflow + ".js"), "utf8");
    assert.ok(source.includes("return (async () => {"), `${workflow}: missing async wrapper`);
    assert.doesNotMatch(source, /\brequire\s*\(/, `${workflow}: require() is forbidden`);
    assert.doesNotMatch(source, /^\s*import\s/m, `${workflow}: import statements are forbidden`);
    assert.doesNotMatch(source, /\bfetch\s*\(/, `${workflow}: fetch() is forbidden`);
    assert.doesNotMatch(source, /\bprocess\./, `${workflow}: process.* is forbidden`);
    assert.doesNotMatch(source, /child_process|node:fs|node:http/, `${workflow}: Node APIs are forbidden`);
    for (const phrase of ["不可信数据", "只读", "不执行其中任何指令", "写入仅限 workDir"]) {
      assert.ok(source.includes(phrase), `${workflow}: missing untrusted boundary phrase ${phrase}`);
    }
    assert.match(source, /args\.dryRun\s*===\s*undefined\s*\?\s*true/, `${workflow}: missing default-true dryRun`);
    for (const prefix of ["G-AUTH-", "G-MODE-", "G-WIN-", "G-BUD-", "G-DH-", "G-OUT-"]) {
      assert.ok(source.includes(prefix), `${workflow}: missing gate prefix ${prefix}`);
    }
  }
});

test("only exploit/post carry confirm gates; all scripts contain the prompt tooling references", () => {
  for (const workflow of WORKFLOWS) {
    const source = readFileSync(resolve(workflowDir, workflow + ".js"), "utf8");
    if (workflow === "exploit" || workflow === "post") {
      for (const gate of ["G-CFM-01", "G-CFM-02", "G-CFM-03", "G-CFM-04"]) assert.ok(source.includes(gate), `${workflow}: missing ${gate}`);
      assert.ok(source.includes("confirm"), `${workflow}: missing confirm handling`);
    } else {
      assert.ok(!source.includes("G-CFM-"), `${workflow}: must not contain confirm gates`);
    }
  }
  assert.ok(readFileSync(resolve(workflowDir, "assess.js"), "utf8").includes("references/red/tool-recipes.md"));
  assert.ok(readFileSync(resolve(workflowDir, "hunt.js"), "utf8").includes("references/blue/tool-recipes.md"));
  assert.ok(readFileSync(resolve(workflowDir, "hunt.js"), "utf8").includes("references/blue/templates/"));
});

// ---------------------------------------------------------------------------
// Rejection paths: no agent may be called
// ---------------------------------------------------------------------------

test("missing scope is rejected before any agent call", async () => {
  for (const workflow of WORKFLOWS) {
    const args = argsFor(workflow);
    delete args.scope;
    const { result, harness } = await runWorkflow(workflow, args);
    assert.equal(result.ok, false, workflow);
    assert.equal(result.status, "rejected", workflow);
    assert.equal(result.exitCode, 1, workflow);
    assert.equal(result.code, 1, workflow);
    assert.ok(result.rejectedBy.includes("G-ARG-01"), workflow + ": " + JSON.stringify(result.rejectedBy));
    assert.equal(agentCalls(harness).length, 0, workflow + ": agent must not run");
  }
});

test("relative workDir or skillDir is rejected without agent calls", async () => {
  for (const workflow of WORKFLOWS) {
    const relativeWork = await runWorkflow(workflow, Object.assign(argsFor(workflow), { workDir: "work/out" }));
    assert.equal(relativeWork.result.status, "rejected", workflow);
    assert.ok(relativeWork.result.rejectedBy.includes("G-PATH-01"), workflow);
    assert.equal(agentCalls(relativeWork.harness).length, 0, workflow);

    const traversal = await runWorkflow(workflow, Object.assign(argsFor(workflow), { workDir: "C:/work/../escape" }));
    assert.ok(traversal.result.rejectedBy.includes("G-PATH-01"), workflow);

    const relativeSkill = await runWorkflow(workflow, Object.assign(argsFor(workflow), { skillDir: "dsh-redblue/skills" }));
    assert.ok(relativeSkill.result.rejectedBy.includes("G-PATH-02"), workflow);
    assert.equal(agentCalls(relativeSkill.harness).length, 0, workflow);
  }
});

test("expired authorization is rejected without agent calls", async () => {
  for (const workflow of WORKFLOWS) {
    const args = argsFor(workflow);
    args.scope = baseScope({
      authorization: {
        type: "written",
        reference: "ROE-OLD",
        grantedBy: "Office",
        validFrom: "2020-01-01",
        validTo: "2020-12-31",
      },
    });
    if (workflow === "exploit") args.scope.dataSources = [dataSource("findings", "C:/work/findings.json")];
    if (workflow === "post") args.scope.mode = "post";
    if (workflow === "hunt") args.scope.dataSources = [dataSource("logs", "C:/work/telemetry.jsonl")];
    if (workflow === "ir") args.scope.dataSources = [dataSource("evidence", "C:/work/evidence")];
    if (workflow === "purple") args.scope.dataSources = [dataSource("findings", "C:/work/findings.json"), dataSource("detections", "C:/work/rules")];
    if (workflow === "triage") args.scope.dataSources = [dataSource("finding", "C:/work/finding.json")];
    if (workflow === "harden") args.scope.dataSources = [dataSource("baseline", "C:/work/baseline.json", { version: "1.0", lastVerified: isoDate(NOW) })];
    const { result, harness } = await runWorkflow(workflow, args);
    assert.equal(result.status, "rejected", workflow);
    assert.ok(result.rejectedBy.includes("G-AUTH-07"), workflow + ": " + JSON.stringify(result.rejectedBy));
    assert.equal(agentCalls(harness).length, 0, workflow);
  }
});

test("wildcard target and exclusion hit are rejected without agent calls", async () => {
  for (const workflow of WORKFLOWS) {
    const wildcard = argsFor(workflow);
    wildcard.scope = baseScope({ targets: [{ kind: "cidr", value: "0.0.0.0/0" }] });
    if (workflow === "exploit") wildcard.scope.dataSources = [dataSource("findings", "C:/work/findings.json")];
    if (workflow === "hunt") wildcard.scope.dataSources = [dataSource("logs", "C:/work/telemetry.jsonl")];
    if (workflow === "ir") wildcard.scope.dataSources = [dataSource("evidence", "C:/work/evidence")];
    if (workflow === "purple") wildcard.scope.dataSources = [dataSource("findings", "C:/work/findings.json"), dataSource("detections", "C:/work/rules")];
    if (workflow === "triage") wildcard.scope.dataSources = [dataSource("finding", "C:/work/finding.json")];
    if (workflow === "harden") wildcard.scope.dataSources = [dataSource("baseline", "C:/work/baseline.json", { version: "1.0", lastVerified: isoDate(NOW) })];
    const wild = await runWorkflow(workflow, wildcard);
    assert.ok(wild.result.rejectedBy.includes("G-TGT-02"), workflow + ": " + JSON.stringify(wild.result.rejectedBy));
    assert.equal(agentCalls(wild.harness).length, 0, workflow);

    const excluded = argsFor(workflow);
    excluded.scope = baseScope({ exclusions: ["app.example.com"] });
    if (workflow === "exploit") excluded.scope.dataSources = [dataSource("findings", "C:/work/findings.json")];
    if (workflow === "hunt") excluded.scope.dataSources = [dataSource("logs", "C:/work/telemetry.jsonl")];
    if (workflow === "ir") excluded.scope.dataSources = [dataSource("evidence", "C:/work/evidence")];
    if (workflow === "purple") excluded.scope.dataSources = [dataSource("findings", "C:/work/findings.json"), dataSource("detections", "C:/work/rules")];
    if (workflow === "triage") excluded.scope.dataSources = [dataSource("finding", "C:/work/finding.json")];
    if (workflow === "harden") excluded.scope.dataSources = [dataSource("baseline", "C:/work/baseline.json", { version: "1.0", lastVerified: isoDate(NOW) })];
    const hit = await runWorkflow(workflow, excluded);
    assert.ok(hit.result.rejectedBy.includes("G-TGT-04"), workflow + ": " + JSON.stringify(hit.result.rejectedBy));
    assert.equal(agentCalls(hit.harness).length, 0, workflow);
  }
});

test("mode below minimum or invalid is rejected without agent calls", async () => {
  const perWorkflowMode = {
    assess: "bogus",
    recon: "passive",
    exploit: "passive",
    post: "exploit",
    hunt: "bogus",
    ir: "bogus",
    purple: "bogus",
    triage: "bogus",
    harden: "bogus",
    reverse: "bogus",
  };
  for (const workflow of WORKFLOWS) {
    const args = argsFor(workflow);
    args.scope = baseScope({ mode: perWorkflowMode[workflow] });
    if (workflow === "recon") args.activeScan = true;
    if (workflow === "exploit") args.scope.dataSources = [dataSource("findings", "C:/work/findings.json")];
    if (workflow === "hunt") args.scope.dataSources = [dataSource("logs", "C:/work/telemetry.jsonl")];
    if (workflow === "ir") args.scope.dataSources = [dataSource("evidence", "C:/work/evidence")];
    if (workflow === "purple") args.scope.dataSources = [dataSource("findings", "C:/work/findings.json"), dataSource("detections", "C:/work/rules")];
    if (workflow === "triage") args.scope.dataSources = [dataSource("finding", "C:/work/finding.json")];
    if (workflow === "harden") args.scope.dataSources = [dataSource("baseline", "C:/work/baseline.json", { version: "1.0", lastVerified: isoDate(NOW) })];
    const { result, harness } = await runWorkflow(workflow, args);
    assert.equal(result.status, "rejected", workflow);
    const expected = workflow === "recon" ? "G-MODE-03" : (workflow === "assess" || workflow === "hunt" || workflow === "ir" || workflow === "purple" || workflow === "triage" || workflow === "harden" || workflow === "reverse" ? "G-MODE-01" : "G-MODE-02");
    assert.ok(result.rejectedBy.includes(expected), workflow + ": expected " + expected + " got " + JSON.stringify(result.rejectedBy));
    assert.equal(agentCalls(harness).length, 0, workflow);
  }
});

test("exploit/post enforce confirm presence, exact match and mode", async () => {
  const missing = await runWorkflow("exploit", Object.assign(argsFor("exploit"), { confirm: undefined }));
  assert.ok(missing.result.rejectedBy.includes("G-CFM-01"));

  const mismatch = await runWorkflow("exploit", Object.assign(argsFor("exploit"), { confirm: "other.example.com" }));
  assert.ok(mismatch.result.rejectedBy.includes("G-CFM-02"), JSON.stringify(mismatch.result.rejectedBy));

  const postWrongMode = await runWorkflow("post", Object.assign(argsFor("post"), { scope: baseScope({ mode: "exploit" }) }));
  assert.ok(postWrongMode.result.rejectedBy.includes("G-CFM-03"), JSON.stringify(postWrongMode.result.rejectedBy));

  const exploitNoPrecise = await runWorkflow("exploit", Object.assign(argsFor("exploit"), {
    scope: baseScope({ mode: "exploit", targets: [{ kind: "cidr", value: "192.0.2.0/24" }], dataSources: [dataSource("findings", "C:/work/findings.json")] }),
  }));
  assert.ok(exploitNoPrecise.result.rejectedBy.includes("G-CFM-04"), JSON.stringify(exploitNoPrecise.result.rejectedBy));

  for (const workflow of ["exploit", "post"]) {
    const { result } = await runWorkflow(workflow, argsFor(workflow));
    assert.equal(result.ok, true, workflow);
  }
});

test("data-source gates reject before any agent call", async () => {
  const cases = [
    ["hunt", { dataSources: [] }, "G-DS-01"],
    ["ir", { dataSources: [] }, "G-DS-02"],
    ["purple", { dataSources: [dataSource("findings", "C:/work/findings.json")] }, "G-DS-03"],
    ["triage", { dataSources: [] }, "G-DS-06"],
    ["harden", { dataSources: [] }, "G-DS-04"],
  ];
  for (const [workflow, overrides, gate] of cases) {
    const args = argsFor(workflow);
    args.scope = baseScope(overrides);
    const { result, harness } = await runWorkflow(workflow, args);
    assert.equal(result.status, "rejected", workflow);
    assert.ok(result.rejectedBy.includes(gate), workflow + ": " + JSON.stringify(result.rejectedBy));
    assert.equal(agentCalls(harness).length, 0, workflow);
  }

  const stale = argsFor("harden");
  stale.scope = baseScope({ dataSources: [dataSource("baseline", "C:/work/baseline.json", { version: "1.0", lastVerified: "2020-01-01" })] });
  const staleResult = await runWorkflow("harden", stale);
  assert.ok(staleResult.result.rejectedBy.includes("G-DS-05"), JSON.stringify(staleResult.result.rejectedBy));

  const noVersion = argsFor("harden");
  noVersion.scope = baseScope({ dataSources: [dataSource("baseline", "C:/work/baseline.json", { lastVerified: isoDate(NOW) })] });
  const noVersionResult = await runWorkflow("harden", noVersion);
  assert.ok(noVersionResult.result.rejectedBy.includes("G-DS-04"), JSON.stringify(noVersionResult.result.rejectedBy));
});

test("invalid maxConcurrency and unknown args keys are rejected", async () => {
  const badConcurrency = await runWorkflow("assess", Object.assign(argsFor("assess"), { maxConcurrency: 9 }));
  assert.ok(badConcurrency.result.rejectedBy.includes("G-CONC-01"));
  const unknownKey = await runWorkflow("assess", Object.assign(argsFor("assess"), { unexpected: true }));
  assert.ok(unknownKey.result.rejectedBy.includes("G-ARG-01"));
});

// ---------------------------------------------------------------------------
// Dry-run success paths
// ---------------------------------------------------------------------------

test("all ten workflows complete a dry-run path with sealed deterministic products", async () => {
  for (const workflow of WORKFLOWS) {
    const { result, harness } = await runWorkflow(workflow, argsFor(workflow));
    assert.equal(result.ok, true, workflow + ": " + JSON.stringify(result));
    assert.equal(result.sealed, true, workflow);
    assert.equal(result.exitCode, 0, workflow);
    assert.ok(["clean", "plan"].includes(result.status), workflow + ": " + result.status);
    if (workflow === "exploit" || workflow === "post") assert.equal(result.status, "plan", workflow);
    const paths = result.artifacts.map((artifact) => artifact.path);
    for (const required of ["findings.json", "coverage.json", "report.md", "exports/results.sarif"]) {
      assert.ok(paths.includes(required), workflow + ": missing product " + required + " in " + paths.join(","));
    }
    if (workflow === "reverse") {
      for (const required of ["scope.json", "reverse.json", "evidence/rea-evidence.json"]) {
        assert.ok(paths.includes(required), "reverse: missing product " + required + " in " + paths.join(","));
      }
      assert.equal(result.written.length, 8, "reverse: expected 8 written products (7 artifacts + manifest)");
      assert.equal(result.runtime, false);
    }
    assert.ok(result.written.includes("scan-manifest.json"), workflow + ": manifest must be written");
    for (const artifact of result.artifacts) {
      assert.match(artifact.sha256, /^[0-9a-f]{64}$/, workflow + ": invalid sha256 for " + artifact.path);
      assert.ok(artifact.bytes >= 0, workflow);
    }
    assert.ok(agentCalls(harness).some((entry) => entry.label.startsWith("report-write:")), workflow + ": no report write");
    assert.ok(agentCalls(harness).some((entry) => entry.label === "seal"), workflow + ": no seal verify");
    assert.ok(agentCalls(harness).some((entry) => entry.label === "seal-write"), workflow + ": no manifest write");
    assert.match(promptOf(harness, "seal"), /scan-manifest\.json/);
    assert.match(promptOf(harness, "seal"), /sha256/);
  }
});

test("assess candidates count is independent of deduplication", async () => {
  const { result } = await runWorkflow("assess", argsFor("assess"));
  assert.equal(result.counts.candidates, 8);
  assert.equal(result.counts.reportable, 0);
});

test("reportable findings produce status findings and exitCode 2", async () => {
  const custom = (label, prompt) => {
    if (label.startsWith("validate:")) {
      return { title: "Reflected XSS", category: "cross-site scripting", target: { kind: "url", value: "https://app.example.com/login?q=x" }, severity: "high", disposition: "reportable", confidence: "high", claim: "c", evidence: "e", remediation: "r", attack: [{ id: "T1059.007" }] };
    }
    if (label === "hunt:plan") return undefined;
    if (label.startsWith("hunt:")) return { hypothesisId: "H1", status: "confirmed", evidenceRefs: [] };
    if (label === "gaps") {
      if (prompt.includes("workflow=harden")) {
        return { matrix: [], summary: {}, gaps: [{ controlId: "C1", title: "t", framework: "CIS", baselineVersion: "1.0", expected: "e", observed: "o", status: "fail", severity: "high", verified: false, evidenceRefs: [] }], limitations: [] };
      }
      return { matrix: [{ attackId: "T1190", redObserved: true, detections: [], status: "gap", gapSeverity: "high", evidenceRefs: [] }], summary: {}, gaps: [], limitations: [] };
    }
    if (label === "disposition") return { disposition: "reportable", severity: "high", confidence: "high", claim: "c", evidence: "e", remediation: "r", evidenceRefs: [] };
    if (label === "check:C1") return { controlId: "C1", status: "fail", observed: "o", evidenceRefs: [] };
    return undefined;
  };
  for (const workflow of ["assess", "hunt", "purple", "triage", "harden"]) {
    const { result } = await runWorkflow(workflow, argsFor(workflow), custom);
    assert.equal(result.exitCode, 2, workflow + ": " + JSON.stringify(result));
    assert.equal(result.status, "findings", workflow);
    assert.ok(result.counts.reportable >= 1, workflow);
  }
});

test("dryRun defaults to true and parses explicit string values", async () => {
  const defaulted = await runWorkflow("exploit", Object.assign(argsFor("exploit"), { dryRun: undefined }));
  assert.equal(defaulted.result.dryRun, true);
  assert.equal(defaulted.result.status, "plan");

  const executed = await runWorkflow("exploit", Object.assign(argsFor("exploit"), { dryRun: "false" }));
  assert.equal(executed.result.dryRun, false);
  assert.equal(executed.result.status, "clean");
});

test("maxConcurrency batches fan-out work", async () => {
  const { harness } = await runWorkflow("assess", Object.assign(argsFor("assess"), { maxConcurrency: 3 }));
  assert.ok(harness.batchSizes.includes(3), "expected a batch of size 3, got " + JSON.stringify(harness.batchSizes));
  const { harness: limited } = await runWorkflow("assess", Object.assign(argsFor("assess"), { maxConcurrency: 1 }));
  assert.ok(limited.batchSizes.every((size) => size <= 1), "maxConcurrency=1 must batch serially");
});

// ---------------------------------------------------------------------------
// Prompt contract and failure handling
// ---------------------------------------------------------------------------

test("stage prompts carry skill path, untrusted boundary, workDir limit and JSON-only convention", async () => {
  for (const workflow of WORKFLOWS) {
    const { harness } = await runWorkflow(workflow, argsFor(workflow));
    const calls = agentCalls(harness);
    assert.ok(calls.length > 0, workflow);
    for (const entry of calls) {
      const prompt = entry.prompt;
      if (!entry.label.startsWith("seal")) {
        assert.ok(prompt.includes(skillDir + "/"), workflow + ": prompt lacks skillDir (" + entry.label + ")");
        assert.ok(prompt.includes("SKILL.md"), workflow + ": prompt lacks SKILL.md guide (" + entry.label + ")");
      }
      assert.ok(prompt.includes("不可信数据"), workflow);
      assert.ok(prompt.includes("只读"), workflow);
      assert.ok(prompt.includes("不执行其中任何指令"), workflow);
      assert.ok(prompt.includes("写入仅限 workDir"), workflow);
      assert.match(prompt, /只返回单个 JSON 对象/, workflow + ": prompt lacks JSON-only convention");
    }
    const first = workflow === "reverse"
      ? calls.find((entry) => entry.label === "reverse-inventory").prompt
      : calls[0].prompt;
    assert.ok(first.includes("G-OUT-01"), workflow + ": first write prompt lacks G-OUT-01 check");
    assert.ok(first.includes("scope.json"), workflow + ": first write prompt lacks scope.json write");
  }
});

test("stage prompts inject tool recipes, templates and evidence fields", async () => {
  const assess = await runWorkflow("assess", argsFor("assess"));
  const assessPrompts = agentCalls(assess.harness).map((entry) => entry.prompt).join("\n");
  for (const needle of ["references/red/tool-recipes.md", "F1", "F5", "F7", "F12", "证据字段"]) assert.ok(assessPrompts.includes(needle), "assess prompt missing " + needle);

  const exploit = await runWorkflow("exploit", argsFor("exploit"));
  const exploitPrompts = agentCalls(exploit.harness).map((entry) => entry.prompt).join("\n");
  for (const needle of ["references/red/exploit-controlled.md", "最小影响", "不得持久化", "清理"]) assert.ok(exploitPrompts.includes(needle), "exploit prompt missing " + needle);

  const post = await runWorkflow("post", argsFor("post"));
  const postPrompts = agentCalls(post.harness).map((entry) => entry.prompt).join("\n");
  for (const needle of ["references/red/post-readonly.md", "不得持久化", "只读"]) assert.ok(postPrompts.includes(needle), "post prompt missing " + needle);

  const hunt = await runWorkflow("hunt", argsFor("hunt"));
  const huntPrompts = agentCalls(hunt.harness).map((entry) => entry.prompt).join("\n");
  for (const needle of ["references/blue/tool-recipes.md", "references/blue/templates/kql.md", "B2", "证据字段"]) assert.ok(huntPrompts.includes(needle), "hunt prompt missing " + needle);

  const purple = await runWorkflow("purple", argsFor("purple"));
  const purplePrompts = agentCalls(purple.harness).map((entry) => entry.prompt).join("\n");
  for (const needle of ["references/blue/tool-recipes.md", "references/blue/templates/sigma.yml", "references/blue/detect-engineering.md"]) assert.ok(purplePrompts.includes(needle), "purple prompt missing " + needle);

  const ir = await runWorkflow("ir", argsFor("ir"));
  const irPrompts = agentCalls(ir.harness).map((entry) => entry.prompt).join("\n");
  for (const needle of ["references/blue/tool-recipes.md", "references/blue/templates/kql.md", "sha256"]) assert.ok(irPrompts.includes(needle), "ir prompt missing " + needle);

  const harden = await runWorkflow("harden", argsFor("harden"));
  const hardenPrompts = agentCalls(harden.harness).map((entry) => entry.prompt).join("\n");
  for (const needle of ["references/blue/tool-recipes.md", "references/blue/templates/sigma.yml", "版本时效"]) assert.ok(hardenPrompts.includes(needle), "harden prompt missing " + needle);
});

test("agent stage returning non-JSON yields a stage error with stage name", async () => {
  const custom = (label) => label === "recon" ? "not json at all" : undefined;
  const { result, harness } = await runWorkflow("assess", argsFor("assess"), custom);
  assert.equal(result.ok, false);
  assert.equal(result.status, "error");
  assert.equal(result.exitCode, 1);
  assert.equal(result.failedStage, "recon");
  assert.match(result.error, /recon/);
  assert.ok(agentCalls(harness).some((entry) => entry.label === "recon"));
});

test("G-OUT-01 from the first phase rejects without report writes", async () => {
  for (const workflow of WORKFLOWS) {
    const firstLabel = {
      assess: "scope", recon: "scope", exploit: "scope", post: "scope", hunt: "scope",
      ir: "intake", purple: "redActions", triage: "finding", harden: "baseline", reverse: "reverse-inventory",
    }[workflow];
    const custom = (label) => label === firstLabel ? { gate: "G-OUT-01" } : undefined;
    const { result, harness } = await runWorkflow(workflow, argsFor(workflow), custom);
    assert.equal(result.status, "rejected", workflow);
    assert.equal(result.exitCode, 1, workflow);
    assert.ok(result.rejectedBy.includes("G-OUT-01"), workflow + ": " + JSON.stringify(result.rejectedBy));
    assert.ok(!agentCalls(harness).some((entry) => entry.label.startsWith("report-write:")), workflow + ": must not write products");
    assert.ok(!agentCalls(harness).some((entry) => entry.label === "seal"), workflow + ": must not seal");
  }
});

test("seal failure turns the run into a stage error", async () => {
  const custom = (label) => label === "seal" ? { ok: false, checks: [{ name: "hash-match", pass: false, detail: "mismatch" }] } : undefined;
  const { result } = await runWorkflow("assess", argsFor("assess"), custom);
  assert.equal(result.ok, false);
  assert.equal(result.status, "error");
  assert.equal(result.exitCode, 1);
  assert.equal(result.sealed, false);
  assert.equal(result.failedStage, "seal");
});

test("report write failure is reported as a report stage error", async () => {
  const custom = (label) => label.startsWith("report-write:findings") ? { ok: false, error: "disk full" } : undefined;
  const { result } = await runWorkflow("assess", argsFor("assess"), custom);
  assert.equal(result.status, "error");
  assert.equal(result.exitCode, 1);
  assert.equal(result.failedStage, "report");
  assert.match(result.error, /findings\.json/);
});
// ---------------------------------------------------------------------------
// Artifact/schema consistency and entry-skill contract
// ---------------------------------------------------------------------------

function fileContentFrom(harness, path) {
  const slug = path.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  const entry = agentCalls(harness).find((call) => call.label === "report-write:" + slug);
  assert.ok(entry, "missing report-write for " + path);
  const match = /文件开始 >>>\n([\s\S]*?)\n<<< 文件结束/.exec(entry.prompt);
  assert.ok(match, "missing verbatim content markers for " + path);
  return match[1];
}

test("generated findings/coverage/manifest match the draft-07 schemas", async () => {
  const { result, harness } = await runWorkflow("assess", argsFor("assess"));
  const findings = JSON.parse(fileContentFrom(harness, "findings.json"));
  assert.equal(findings.schemaVersion, "dsh-redblue-findings/v1");
  assert.equal(findings.workflow, "assess");
  assert.equal(findings.scopeDigest, result.artifacts.find((item) => item.path === "findings.json") ? findings.scopeDigest : "");
  assert.ok(Array.isArray(findings.findings));
  assert.equal(findings.summary.candidates, 8);

  const coverage = JSON.parse(fileContentFrom(harness, "coverage.json"));
  const coverageSchema = JSON.parse(readFileSync(resolve(root, "schema/coverage.schema.json"), "utf8"));
  assert.equal(coverageSchema.$schema, "http://json-schema.org/draft-07/schema#");
  for (const key of coverageSchema.required) assert.ok(key in coverage, "coverage missing " + key);
  assert.equal(coverage.schemaVersion, "dsh-redblue-coverage/v1");
  assert.ok(["assess", "recon", "exploit", "post", "hunt", "ir", "purple", "triage", "harden"].includes(coverage.workflow));
  assert.match(coverage.snapshotDigest, /^dsh-redblue-snapshot\/v1:sha256:[0-9a-f]{64}$/);
  for (const phase of coverage.phases) assert.ok(["completed", "failed", "skipped"].includes(phase.status));

  const sealWritePrompt = promptOf(harness, "seal-write");
  const manifestMatch = /文件开始 >>>\n(\{.*\})\n<<< 文件结束/.exec(sealWritePrompt);
  assert.ok(manifestMatch, "seal-write prompt lacks completed manifest");
  const manifest = JSON.parse(manifestMatch[1]);
  const manifestSchema = JSON.parse(readFileSync(resolve(root, "schema/manifest.schema.json"), "utf8"));
  assert.equal(manifestSchema.$schema, "http://json-schema.org/draft-07/schema#");
  for (const key of manifestSchema.required) assert.ok(key in manifest, "manifest missing " + key);
  assert.equal(manifest.manifestVersion, "dsh-redblue-manifest/v1");
  assert.equal(manifest.plugin.name, "dsh-redblue");
  assert.equal(manifest.status, "completed");
  assert.equal(manifest.exitCode, 0);
  for (const artifact of manifest.artifacts) {
    assert.match(artifact.path, /^[^/].*$/);
    assert.match(artifact.sha256, /^[0-9a-f]{64}$/);
  }
  assert.ok(manifest.artifacts.some((artifact) => artifact.path === "report.md"));
  assert.ok(manifest.artifacts.every((artifact) => artifact.path !== "scan-manifest.json"));
});

test("entry skill routes intents to all nine scripts and documents gates", () => {
  const skill = readFileSync(resolve(root, "skills", "run", "SKILL.md"), "utf8");
  for (const workflow of ENTRY_ROUTED_WORKFLOWS) assert.ok(skill.includes("`" + workflow + ".js`"), "run skill missing " + workflow);
  assert.ok(readFileSync(resolve(workflowDir, "reverse.js"), "utf8").length > 0, "reverse workflow must exist");
  for (const needle of ["意图 → 脚本路由表", "工具面自检", "默认 `dryRun=true`", "二次确认", "退出码", "产物位置", "workDir"]) {
    assert.ok(skill.includes(needle), "run skill missing " + needle);
  }
  assert.ok(skill.includes("standard") && skill.includes("ptc"), "run skill missing preset fallback guidance");
  assert.match(skill, /`0` 干净\/计划完成/);
  assert.match(skill, /`1` 门禁拒绝或执行错误/);
  assert.match(skill, /`2` 存在 reportable finding/);
});

test("default maxConcurrency is 2", async () => {
  const args = argsFor("assess");
  delete args.maxConcurrency;
  const { harness } = await runWorkflow("assess", args);
  assert.ok(harness.batchSizes.length > 0);
  assert.ok(harness.batchSizes.every((size) => size <= 2), JSON.stringify(harness.batchSizes));
  assert.ok(harness.batchSizes.includes(2), JSON.stringify(harness.batchSizes));
});

test("authorization, window, budget, dataHandling, config and path gates", async () => {
  const cases = [
    ["missing authorization reference", "assess", (scope) => { scope.authorization.reference = ""; }, "G-AUTH-01"],
    ["invalid authorization type", "assess", (scope) => { scope.authorization.type = "verbal"; }, "G-AUTH-02"],
    ["internal mandate on written-only workflow", "assess", (scope) => { scope.authorization.type = "internal-mandate"; }, "G-AUTH-03"],
    ["missing grantedBy", "assess", (scope) => { scope.authorization.grantedBy = ""; }, "G-AUTH-04"],
    ["inverted authorization window", "assess", (scope) => { scope.authorization.validFrom = isoDate(NOW + 2 * 86400000); scope.authorization.validTo = isoDate(NOW - 86400000); }, "G-AUTH-05"],
    ["future authorization", "assess", (scope) => { scope.authorization.validFrom = isoDate(NOW + 2 * 86400000); scope.authorization.validTo = isoDate(NOW + 3 * 86400000); }, "G-AUTH-06"],
    ["window outside current time", "assess", (scope) => { scope.window.start = isoTime(NOW + 3600000); scope.window.end = isoTime(NOW + 7200000); }, "G-WIN-03"],
    ["window end before start", "assess", (scope) => { scope.window.start = isoTime(NOW + 3600000); scope.window.end = isoTime(NOW); }, "G-WIN-02"],
    ["budget out of range", "assess", (scope) => { scope.budget.maxRequests = 0; }, "G-BUD-01"],
    ["destruction not none", "assess", (scope) => { scope.dataHandling.destruction = "delete"; }, "G-DH-03"],
    ["secrets not masked", "assess", (scope) => { scope.dataHandling.secrets = "plain"; }, "G-DH-02"],
    ["unknown scope field", "assess", (scope) => { scope.shadowAuthorization = true; }, "G-CONF-01"],
    ["invalid target kind", "assess", (scope) => { scope.targets = [{ kind: "email", value: "a@example.com" }]; }, "G-TGT-03"],
  ];
  for (const [label, workflow, mutate, gate] of cases) {
    const args = argsFor(workflow);
    args.scope = baseScope();
    if (workflow === "exploit") args.scope.dataSources = [dataSource("findings", "C:/work/findings.json")];
    mutate(args.scope);
    const { result, harness } = await runWorkflow(workflow, args);
    assert.equal(result.status, "rejected", label);
    assert.ok(result.rejectedBy.includes(gate), label + ": expected " + gate + " got " + JSON.stringify(result.rejectedBy));
    assert.equal(agentCalls(harness).length, 0, label);
  }

  const relativeSource = argsFor("hunt");
  relativeSource.scope = baseScope({ dataSources: [dataSource("logs", "logs/telemetry.jsonl")] });
  const relative = await runWorkflow("hunt", relativeSource);
  assert.ok(relative.result.rejectedBy.includes("G-PATH-03"), JSON.stringify(relative.result.rejectedBy));
  assert.equal(agentCalls(relative.harness).length, 0);
});

// ---------------------------------------------------------------------------
// t16 regression: report readback/retry, failed manifest mismatches, annotated scope
// ---------------------------------------------------------------------------

function manifestFromSealWrite(harness) {
  const entry = agentCalls(harness).filter((call) => call.label === "seal-write").pop();
  assert.ok(entry, "missing seal-write call");
  const match = /文件开始 >>>\n(\{.*\})\n<<< 文件结束/.exec(entry.prompt);
  assert.ok(match, "seal-write prompt lacks manifest content");
  return JSON.parse(match[1]);
}

test("report write tamper is detected by readback and retried successfully", async () => {
  let findingsAttempts = 0;
  const custom = (label, prompt) => {
    if (label !== "report-write:findings-json") return undefined;
    findingsAttempts++;
    if (findingsAttempts === 1) return tamperedReply(prompt, "findings.json");
    return undefined;
  };
  const { result, harness } = await runWorkflow("assess", argsFor("assess"), custom);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.sealed, true);
  assert.equal(result.exitCode, 0);
  assert.equal(findingsAttempts, 2, "tampered first write must trigger exactly one retry");
  const writes = agentCalls(harness).filter((call) => call.label === "report-write:findings-json");
  assert.equal(writes.length, 2);
  assert.match(writes[1].prompt, /上一次回读校验不一致/);
  assert.match(writes[1].prompt, /expected sha256=/);
});

test("persistent report tamper fails and failed manifest lists precise mismatches", async () => {
  let findingsAttempts = 0;
  const custom = (label, prompt) => {
    if (label !== "report-write:findings-json") return undefined;
    findingsAttempts++;
    return tamperedReply(prompt, "findings.json");
  };
  const { result, harness } = await runWorkflow("assess", argsFor("assess"), custom);
  assert.equal(result.ok, false);
  assert.equal(result.status, "error");
  assert.equal(result.exitCode, 1);
  assert.equal(result.failedStage, "report");
  assert.equal(findingsAttempts, 3, "initial write + at most two retries");
  assert.match(result.error, /findings\.json/);
  assert.match(result.error, /expected=/);
  assert.match(result.error, /actual=/);
  const manifest = manifestFromSealWrite(harness);
  assert.equal(manifest.status, "failed");
  assert.equal(manifest.exitCode, 1);
  assert.equal(manifest.mismatches.length, 1);
  const mismatch = manifest.mismatches[0];
  assert.equal(mismatch.path, "findings.json");
  assert.match(mismatch.expectedSha256, /^[0-9a-f]{64}$/);
  assert.match(mismatch.actualSha256, /^[0-9a-f]{64}$/);
  assert.notEqual(mismatch.expectedSha256, mismatch.actualSha256);
  assert.ok(Number.isInteger(mismatch.bytes) && mismatch.bytes > 0, "bytes must be an integer");
});

test("workflow scope projection passes gate/guard while hard gates remain strict", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dsh-redblue-scope-"));
  try {
    const { harness } = await runWorkflow("assess", argsFor("assess"));
    const scopeContent = fileContentFrom(harness, "scope.json");
    const projected = JSON.parse(scopeContent);
    for (const key of ["scopeDigest", "validatedAt", "confirmedTarget"]) {
      assert.ok(!(key in projected), "scope.json must not carry archival/derived field " + key);
    }
    assert.equal(projected.mode, "passive");
    assert.ok(Array.isArray(projected.targets) && projected.targets.length > 0);

    const firstPrompt = promptOf(harness, "scope");
    assert.match(firstPrompt, /scope\.archive\.json/);
    assert.match(firstPrompt, /scopeDigest/);
    assert.match(firstPrompt, /validatedAt/);

    const check = checkScope(projected, { now: new Date(NOW) });
    assert.equal(check.ok, true, JSON.stringify(check.rejectedBy));
    assert.deepEqual(check.rejectedBy, []);

    const scopePath = join(dir, "scope.json");
    writeFileSync(scopePath, scopeContent, "utf8");
    const guarded = await runGuard({
      recipeId: "runtime_probe",
      target: "app.example.com",
      scopePath,
      execute: false,
      workdir: dir,
      now: new Date(NOW),
    });
    assert.equal(guarded.exitCode, 0, JSON.stringify(guarded.output));
    assert.equal(guarded.output.ok, true);
    assert.equal(guarded.output.dryRun, true);

    const missingAuth = checkScope(Object.assign({}, projected, { authorization: undefined }), { now: new Date(NOW) });
    assert.equal(missingAuth.ok, false);
    assert.ok(missingAuth.rejectedBy.includes("G-AUTH-01"), JSON.stringify(missingAuth.rejectedBy));

    const expired = checkScope(Object.assign({}, projected, {
      authorization: Object.assign({}, projected.authorization, { validFrom: "2020-01-01", validTo: "2020-12-31" }),
    }), { now: new Date(NOW) });
    assert.ok(expired.rejectedBy.includes("G-AUTH-07"), JSON.stringify(expired.rejectedBy));

    const wildcard = checkScope(Object.assign({}, projected, { targets: [{ kind: "cidr", value: "0.0.0.0/0" }] }), { now: new Date(NOW) });
    assert.ok(wildcard.rejectedBy.includes("G-TGT-02"), JSON.stringify(wildcard.rejectedBy));

    const annotated = Object.assign({}, projected, {
      scopeDigest: "dsh-redblue-scope/v1:sha256:" + "a".repeat(64),
      validatedAt: new Date(NOW).toISOString(),
    });
    const annotatedCheck = checkScope(annotated, { now: new Date(NOW) });
    assert.equal(annotatedCheck.ok, false, "the strict gate must still reject annotated objects");
    assert.ok(annotatedCheck.rejectedBy.includes("G-CONF-01"), JSON.stringify(annotatedCheck.rejectedBy));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ten capsules share the same finalize core and pure scope projection", () => {
  let coreHash = null;
  for (const workflow of WORKFLOWS) {
    const source = readFileSync(resolve(workflowDir, workflow + ".js"), "utf8");
    const start = source.indexOf("async function finalize(ctx, state) {");
    const end = source.indexOf("function explainError(error) {");
    assert.ok(start >= 0 && end > start, `${workflow}: finalize core anchors missing`);
    const segment = source.slice(start, end);
    const hash = sha256Of(segment);
    if (coreHash === null) coreHash = hash;
    else assert.equal(hash, coreHash, `${workflow}: finalize core drifted from assess`);
    assert.match(segment, /expectedSha256/, workflow);
    assert.match(segment, /actualSha256/, workflow);
    assert.match(segment, /seal-write/, workflow);
    assert.match(segment, /mismatches/, workflow);
    assert.match(source, /ctx\.scopeContent = stableStringify\(pre\.scope\)/, workflow);
    assert.match(source, /ctx\.scopeArchiveContent = stableStringify\(scopeDoc\)/, workflow);
    assert.match(source, /scope\.archive\.json/, workflow);
  }
  assert.match(readFileSync(resolve(workflowDir, "assess.js"), "utf8"), /async function finalize\(ctx, state\) \{/);
});

test("every workflow stage skill directory exists under skills/", () => {
  const skillsRoot = resolve(root, "skills");
  const skillDirs = new Set(readdirSync(skillsRoot));
  const stageDirs = new Set();
  const promptDirs = new Set();
  const usedBy = new Map();
  const track = (set, dir, workflow, kind) => {
    set.add(dir);
    if (!usedBy.has(dir)) usedBy.set(dir, []);
    usedBy.get(dir).push(workflow + kind);
  };
  for (const workflow of WORKFLOWS) {
    const source = readFileSync(resolve(workflowDir, workflow + ".js"), "utf8");
    const stageSkills = [...source.matchAll(/run(?:Stage|Fanout)\(ctx, "[^"]+", "([a-z0-9-]+)"/g)].map((match) => match[1]);
    assert.ok(stageSkills.length >= 2, workflow + ": expected >=2 runStage/runFanout skill literals, got " + stageSkills.length);
    for (const dir of stageSkills) track(stageDirs, dir, workflow, "");
    for (const match of source.matchAll(/skillDir \+ "\/([a-z0-9-]+)\/SKILL\.md/g)) track(promptDirs, match[1], workflow, "(prompt)");
  }
  assert.ok(stageDirs.size >= 13, "expected >=13 distinct runStage/runFanout skill dirs, got " + stageDirs.size + ": " + [...stageDirs].join(","));
  assert.ok(promptDirs.size >= 1, "expected at least one prompt-level skill dir (report stage); regex may be stale");
  for (const dir of ["run", "rb-report", "rb-triage", "blue-hunt", "purple-verify"]) {
    assert.ok(stageDirs.has(dir) || promptDirs.has(dir), "expected stage skill dir " + dir + " to be referenced by some workflow");
  }
  for (const [dir, workflows] of usedBy) {
    assert.ok(skillDirs.has(dir), "workflow references missing skills/" + dir + "/SKILL.md (used by " + workflows.join(", ") + ")");
    assert.ok(readFileSync(resolve(skillsRoot, dir, "SKILL.md"), "utf8").trim().length > 0, "empty " + dir + "/SKILL.md");
  }
});

// ---------------------------------------------------------------------------
// v0.2.0 regression: reverse lane (probe / degrade / runtime gates / products)
// ---------------------------------------------------------------------------

function reverseScope(overrides = {}) {
  return Object.assign(baseScope(), {
    targets: [{ kind: "source", value: REVERSE_TARGET }],
    mode: "passive",
  }, overrides);
}

function reverseArgs(overrides = {}) {
  return argsFor("reverse", Object.assign({ scope: reverseScope() }, overrides));
}

test("reverse static passive run produces the eight v0.2 products and skips runtime", async () => {
  const { result, harness } = await runWorkflow("reverse", reverseArgs());
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.status, "clean");
  assert.equal(result.exitCode, 0);
  assert.equal(result.sealed, true);
  assert.equal(result.runtime, false);
  assert.equal(result.reverse.targetKind, "pe");
  assert.equal(result.reverse.runtimeExecuted, false);
  assert.deepEqual(Array.from(result.written).sort(), [
    "coverage.json", "evidence/rea-evidence.json", "exports/results.sarif", "findings.json",
    "report.md", "reverse.json", "scan-manifest.json", "scope.json",
  ]);

  const coverage = JSON.parse(fileContentFrom(harness, "coverage.json"));
  const runtimePhase = coverage.phases.find((phase) => phase.name === "runtime");
  assert.ok(runtimePhase, "coverage must include the runtime phase");
  assert.equal(runtimePhase.status, "skipped");
  assert.equal(runtimePhase.agents, 0);
  assert.equal(coverage.workflow, "reverse");

  const reverseDoc = JSON.parse(fileContentFrom(harness, "reverse.json"));
  for (const key of ["schemaVersion", "runId", "workflow", "target", "probe", "route", "sideEffects", "stages", "evidence", "runtime", "degraded", "unknowns", "limitations", "counts"]) {
    assert.ok(key in reverseDoc, "reverse.json missing " + key);
  }
  assert.equal(reverseDoc.workflow, "reverse");
  assert.equal(reverseDoc.target.kind, "source");
  assert.equal(reverseDoc.target.value, REVERSE_TARGET);
  assert.equal(reverseDoc.evidence.retained, true);
  assert.equal(reverseDoc.evidence.deterministic, false);
  assert.match(reverseDoc.evidence.sha256, /^[0-9a-f]{64}$/);
  assert.equal(reverseDoc.runtime.requested, false);
  assert.equal(reverseDoc.stages.runtime.status, "skipped");
  assert.equal(reverseDoc.evidence.path, "evidence/rea-evidence.json");

  const findings = JSON.parse(fileContentFrom(harness, "findings.json"));
  assert.equal(findings.findings.length, 1);
  assert.equal(findings.findings[0].target.kind, "source");
  assert.equal(findings.findings[0].evidenceRefs.length, 1);
  assert.match(findings.findings[0].evidenceRefs[0].sha256, /^[0-9a-f]{64}$/);
  assert.match(findings.findings[0].evidenceRefs[0].path, /rea-evidence\.json$/);
  assert.match(findings.findings[0].evidenceRefs[0].locator, /^rea:ev_[0-9a-f]{64}#/);
  assert.ok(!agentCalls(harness).some((call) => call.label === "reverse-runtime"), "runtime agent must not run when runtime=false");
});

test("reverse runtime=true requires mode>=active and dryRun=false (G-RT-01)", async () => {
  const passive = await runWorkflow("reverse", reverseArgs({ scope: reverseScope({ mode: "passive" }), runtime: true }));
  assert.equal(passive.result.status, "rejected");
  assert.equal(passive.result.exitCode, 1);
  assert.ok(passive.result.rejectedBy.includes("G-RT-01"), JSON.stringify(passive.result.rejectedBy));
  assert.equal(agentCalls(passive.harness).length, 0);

  const dry = await runWorkflow("reverse", reverseArgs({ scope: reverseScope({ mode: "active" }), runtime: true, dryRun: true, confirm: REVERSE_TARGET }));
  assert.equal(dry.result.status, "rejected");
  assert.ok(dry.result.rejectedBy.includes("G-RT-01"), JSON.stringify(dry.result.rejectedBy));
  assert.equal(agentCalls(dry.harness).length, 0, "runtime gates are evaluated before any agent");
});

test("reverse runtime=true requires an exact source confirm (G-RT-02)", async () => {
  const base = { scope: reverseScope({ mode: "active" }), runtime: true, dryRun: false };
  const missing = await runWorkflow("reverse", reverseArgs(base));
  assert.equal(missing.result.status, "rejected");
  assert.ok(missing.result.rejectedBy.includes("G-RT-02"), JSON.stringify(missing.result.rejectedBy));
  assert.equal(agentCalls(missing.harness).length, 0);

  for (const confirm of ["c:/samples/app.exe", "C:\\samples\\..\\app.exe", "C:/samples/other.exe", "app.exe"]) {
    const bad = await runWorkflow("reverse", reverseArgs(Object.assign({}, base, { confirm })));
    assert.equal(bad.result.status, "rejected", confirm);
    assert.ok(bad.result.rejectedBy.includes("G-RT-02"), confirm + ": " + JSON.stringify(bad.result.rejectedBy));
    assert.equal(agentCalls(bad.harness).length, 0, confirm + ": no agent");
  }

  const confirmWithoutRuntime = await runWorkflow("reverse", reverseArgs({ scope: reverseScope(), confirm: REVERSE_TARGET }));
  assert.equal(confirmWithoutRuntime.result.status, "rejected");
  assert.ok(confirmWithoutRuntime.result.rejectedBy.includes("G-RT-02"), JSON.stringify(confirmWithoutRuntime.result.rejectedBy));

  const exact = await runWorkflow("reverse", reverseArgs(Object.assign({}, base, { confirm: "C:\\samples\\app.exe" })));
  assert.equal(exact.result.ok, true, JSON.stringify(exact.result));
  assert.equal(exact.result.runtime, true);
  assert.equal(exact.result.reverse.runtimeExecuted, false);
  const coverage = JSON.parse(fileContentFrom(exact.harness, "coverage.json"));
  const runtimePhase = coverage.phases.find((phase) => phase.name === "runtime");
  assert.equal(runtimePhase.status, "completed");
  assert.equal(runtimePhase.agents, 1);
  assert.ok(agentCalls(exact.harness).some((call) => call.label === "reverse-runtime"));
});

test("reverse requires exactly one kind=source target (G-TGT-05)", async () => {
  const cases = [
    ["multiple sources", [{ kind: "source", value: REVERSE_TARGET }, { kind: "source", value: "C:/samples/b.exe" }]],
    ["domain target", [{ kind: "domain", value: "app.example.com" }]],
    ["empty targets", []],
  ];
  for (const [label, targets] of cases) {
    const { result, harness } = await runWorkflow("reverse", reverseArgs({ scope: reverseScope({ targets }) }));
    assert.equal(result.status, "rejected", label);
    assert.equal(result.exitCode, 1, label);
    assert.ok(result.rejectedBy.includes("G-TGT-05"), label + ": " + JSON.stringify(result.rejectedBy));
    assert.equal(agentCalls(harness).length, 0, label + ": no agent");
  }
});

test("reverse probe unavailable returns blocked G-REA-01 with remediation and no analysis", async () => {
  const custom = (label) => label === "reverse-scope"
    ? { reaAvailable: false, reason: "REA MCP server unavailable" }
    : undefined;
  const { result, harness } = await runWorkflow("reverse", reverseArgs(), custom);
  assert.equal(result.ok, false);
  assert.equal(result.status, "blocked");
  assert.equal(result.exitCode, 1);
  assert.equal(result.code, 1);
  assert.deepEqual(Array.from(result.blockedBy), ["G-REA-01"]);
  assert.equal(result.artifacts.length, 0);
  assert.equal(result.sealed, false);
  assert.equal(result.agents.analysis, 0);
  assert.equal(result.agents.runtime, 0);
  assert.ok(Array.isArray(result.remediation.install) && result.remediation.install.length > 0, "blocked must carry install guidance");
  assert.equal(agentCalls(harness).length, 1, "only the probe agent runs before blocked");
  assert.equal(agentCalls(harness)[0].label, "reverse-scope");
  assert.ok(!agentCalls(harness).some((call) => call.label.startsWith("report-write:")), "blocked must not write products");
  assert.equal(result.counts.candidates, 0);
  assert.equal(result.counts.reportable, 0);
});

test("reverse unreadable target or hash mismatch returns blocked G-REA-02", async () => {
  const badTarget = (label) => label === "reverse-scope"
    ? Object.assign({}, DEFAULT_REPLIES.find(([pattern]) => pattern.test("reverse-scope"))[1]("reverse-scope"), { target: { path: REVERSE_TARGET, sha256: "", bytes: 0, format: "pe" } })
    : undefined;
  const scopeBlocked = await runWorkflow("reverse", reverseArgs(), badTarget);
  assert.equal(scopeBlocked.result.status, "blocked");
  assert.deepEqual(Array.from(scopeBlocked.result.blockedBy), ["G-REA-02"]);
  assert.equal(scopeBlocked.result.artifacts.length, 0);
  assert.equal(agentCalls(scopeBlocked.harness).length, 1);

  const inventoryMismatch = (label) => label === "reverse-inventory"
    ? { ok: true, target: { path: REVERSE_TARGET, sha256: "b".repeat(64), bytes: 118256, format: "pe" }, members: [], evidenceIds: [], sideEffects: [], unknowns: [], degraded: [], limitations: [] }
    : undefined;
  const hashBlocked = await runWorkflow("reverse", reverseArgs(), inventoryMismatch);
  assert.equal(hashBlocked.result.status, "blocked");
  assert.deepEqual(Array.from(hashBlocked.result.blockedBy), ["G-REA-02"]);
  assert.equal(hashBlocked.result.artifacts.length, 0);
  assert.deepEqual(agentCalls(hashBlocked.harness).map((call) => call.label), ["reverse-scope", "reverse-inventory"]);
});

test("reverse missing providers degrade and still produce a clean report", async () => {
  const custom = (label) => label === "reverse-static"
    ? {
        candidates: [],
        evidence: [],
        techniques: [],
        degraded: [
          { capability: "jadx", reason: "provider_missing", remediation: "set REA_JADX_MCP_JAR", effect: "apk_decompile_unavailable" },
          { capability: "wabt", reason: "provider_missing", remediation: "set REA_WABT_BIN_DIRECTORY", effect: "wasm_text_unavailable" },
        ],
        limitations: ["APK/WASM providers missing"],
      }
    : undefined;
  const { result, harness } = await runWorkflow("reverse", reverseArgs(), custom);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.status, "clean");
  assert.equal(result.exitCode, 0);
  assert.ok(result.reverse.degraded >= 1, "degraded count must be reported");
  const reverseDoc = JSON.parse(fileContentFrom(harness, "reverse.json"));
  assert.ok(reverseDoc.degraded.length >= 2, JSON.stringify(reverseDoc.degraded));
  assert.ok(reverseDoc.limitations.some((item) => item.includes("degraded:")), "limitations must record degraded capabilities");
  assert.ok(!agentCalls(harness).some((call) => call.label === "reverse-runtime"));
});

test("reverse runtime provider unavailable degrades instead of blocking", async () => {
  const custom = (label) => label === "reverse-runtime"
    ? { executed: false, providers: [{ id: "frida", available: false, reason: "provider_unavailable" }], actions: [], cleanup: [], candidates: [], evidence: [], degraded: [{ capability: "frida", reason: "provider_unavailable", effect: "runtime_not_executed" }], limitations: ["frida unavailable"] }
    : undefined;
  const { result, harness } = await runWorkflow("reverse", reverseArgs({
    scope: reverseScope({ mode: "active" }),
    runtime: true,
    dryRun: false,
    confirm: REVERSE_TARGET,
  }), custom);
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.status, "clean");
  assert.equal(result.runtime, true);
  assert.equal(result.reverse.runtimeExecuted, false);
  const reverseDoc = JSON.parse(fileContentFrom(harness, "reverse.json"));
  assert.equal(reverseDoc.runtime.requested, true);
  assert.equal(reverseDoc.runtime.executed, false);
  assert.ok(reverseDoc.limitations.some((item) => item.includes("runtime=true 但未执行")), JSON.stringify(reverseDoc.limitations));
});

test("reverse evidence export hash mismatch fails at report without sealing", async () => {
  const custom = (label) => label === "reverse-report-export"
    ? { ok: true, path: "evidence/rea-evidence.json", bytes: Buffer.byteLength(REVERSE_BUNDLE, "utf8"), sha256: "f".repeat(64), records: 1, evidenceIds: [], content: REVERSE_BUNDLE, fallback: false, cleanup: [], limitations: [] }
    : undefined;
  const { result, harness } = await runWorkflow("reverse", reverseArgs(), custom);
  assert.equal(result.ok, false);
  assert.equal(result.status, "error");
  assert.equal(result.exitCode, 1);
  assert.equal(result.failedStage, "report");
  assert.match(result.error, /证据包/);
  assert.ok(!agentCalls(harness).some((call) => call.label === "seal"), "report failure must not seal a manifest");
});

test("reverse evidence seal mismatch writes a failed manifest and errors", async () => {
  const custom = (label) => label === "seal"
    ? { ok: false, checks: [{ name: "hash-match", pass: false }], mismatches: [{ path: "evidence/rea-evidence.json", actualSha256: "0".repeat(64) }] }
    : undefined;
  const { result, harness } = await runWorkflow("reverse", reverseArgs(), custom);
  assert.equal(result.ok, false);
  assert.equal(result.status, "error");
  assert.equal(result.exitCode, 1);
  assert.equal(result.failedStage, "seal");
  const manifest = manifestFromSealWrite(harness);
  assert.equal(manifest.status, "failed");
  assert.equal(manifest.exitCode, 1);
  assert.ok(manifest.mismatches.some((item) => item.path === "evidence/rea-evidence.json"), JSON.stringify(manifest.mismatches));
});

// ---------------------------------------------------------------------------
// t20 regression: exclusion normalization, target parsing, schema limits
// ---------------------------------------------------------------------------

test("G-TGT-04 applies normalized exclusions for URL/domain/IP forms", async () => {
  const cases = [
    ["url default port", { kind: "url", value: "https://app.example.com/" }, ["https://app.example.com:443/"]],
    ["domain trailing dot", { kind: "url", value: "https://app.example.com/" }, ["app.example.com."]],
    ["URL case folding", { kind: "url", value: "https://app.example.com/" }, ["HTTPS://APP.EXAMPLE.COM/"]],
    ["URL fragment", { kind: "url", value: "https://app.example.com/" }, ["https://app.example.com/#frag"]],
    ["URL root slash", { kind: "url", value: "https://app.example.com" }, ["https://app.example.com/"]],
    ["domain target vs URL exclusion", { kind: "domain", value: "app.example.com" }, ["https://app.example.com:443/"]],
    ["IPv4 leading zeros", { kind: "ip", value: "192.0.2.10" }, ["192.000.002.010"]],
    ["domain suffix", { kind: "domain", value: "a.app.example.com" }, ["app.example.com"]],
  ];
  for (const [label, target, exclusions] of cases) {
    const args = argsFor("assess");
    args.scope = baseScope({ targets: [target], exclusions });
    const { result, harness } = await runWorkflow("assess", args);
    assert.equal(result.status, "rejected", label);
    assert.ok(result.rejectedBy.includes("G-TGT-04"), label + ": " + JSON.stringify(result.rejectedBy));
    assert.equal(agentCalls(harness).length, 0, label + ": no agent call");
  }
});

test("unspecified, wrapped, userinfo and malformed targets are rejected", async () => {
  const cases = [
    ["URL 0.0.0.0", { kind: "url", value: "https://0.0.0.0/" }, ["G-TGT-03"]],
    ["URL [::]", { kind: "url", value: "https://[::]/" }, ["G-TGT-03"]],
    ["URL userinfo", { kind: "url", value: "https://user:pass@app.example.com/" }, ["G-TGT-03"]],
    ["invalid IPv6", { kind: "ip", value: "1::2::3" }, ["G-TGT-03"]],
    ["IP 0.0.0.0", { kind: "ip", value: "0.0.0.0" }, ["G-TGT-02"]],
    ["CIDR 0.0.0.0/32", { kind: "cidr", value: "0.0.0.0/32" }, ["G-TGT-02"]],
    ["CIDR ::/128", { kind: "cidr", value: "::/128" }, ["G-TGT-02"]],
    ["CIDR /1 too wide", { kind: "cidr", value: "0.0.0.0/1" }, ["G-TGT-02"]],
  ];
  for (const [label, target, expectedGates] of cases) {
    const args = argsFor("assess");
    args.scope = baseScope({ targets: [target] });
    const { result, harness } = await runWorkflow("assess", args);
    assert.equal(result.status, "rejected", label);
    assert.ok(expectedGates.some((gate) => result.rejectedBy.includes(gate)), label + ": " + JSON.stringify(result.rejectedBy));
    assert.equal(agentCalls(harness).length, 0, label + ": no agent call");
  }
});

test("preflight enforces schema length and count limits", async () => {
  const tooLongReference = argsFor("assess");
  tooLongReference.scope = baseScope({ authorization: { type: "written", reference: "x".repeat(201), grantedBy: "Office", validFrom: isoDate(NOW - 86400000), validTo: isoDate(NOW + 86400000) } });
  const tooManyTargets = argsFor("assess");
  tooManyTargets.scope = baseScope({ targets: Array.from({ length: 201 }, () => ({ kind: "domain", value: "app.example.com" })) });
  const tooLongNotes = argsFor("assess");
  tooLongNotes.scope = baseScope({ notes: "x".repeat(2001) });
  const tooLongLabel = argsFor("assess");
  tooLongLabel.scope = baseScope({ targets: [{ kind: "domain", value: "app.example.com", label: "x".repeat(121) }] });
  const tooLongExclusion = argsFor("assess");
  tooLongExclusion.scope = baseScope({ exclusions: ["x".repeat(513)] });
  const tooManySources = argsFor("hunt");
  tooManySources.scope = baseScope({ dataSources: Array.from({ length: 65 }, (_, i) => ({ kind: "logs", value: "C:/work/logs/" + i + ".jsonl" })) });

  for (const [label, args] of [["reference", tooLongReference], ["targets", tooManyTargets], ["notes", tooLongNotes], ["label", tooLongLabel], ["exclusion", tooLongExclusion], ["dataSources", tooManySources]]) {
    const { result, harness } = await runWorkflow("assess", args);
    assert.equal(result.status, "rejected", label);
    assert.ok(result.rejectedBy.includes("G-CONF-01"), label + ": " + JSON.stringify(result.rejectedBy));
    assert.equal(agentCalls(harness).length, 0, label + ": no agent call");
  }
});
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// t22 regression: gate/workflow limits parity and review-field persistence
// ---------------------------------------------------------------------------

function functionSegment(source, startText, afterText) {
  const start = source.indexOf(startText);
  const end = source.indexOf(afterText, start);
  assert.ok(start >= 0 && end > start, "missing segment: " + startText);
  return source.slice(start, end).replace(/\r\n/g, "\n");
}

const REVIEW_FIELDS = ["confidenceRationale", "counterevidence", "severityChangeConditions", "fixVerification", "basis"];

test("scope limits implementation is identical in gate and all ten workflows", () => {
  const gateSource = readFileSync(resolve(root, "tools/lib/gate.mjs"), "utf8");
  const gateLimits = functionSegment(gateSource, "function validateScopeLimits(rawScope, reject) {", "export function checkScope(raw, options = {}) {");
  assert.match(gateSource, /validateScopeLimits\(raw, reject\);/, "checkScope must call validateScopeLimits (not dead code)");
  let limitsHash = null;
  for (const workflow of WORKFLOWS) {
    const source = readFileSync(resolve(workflowDir, workflow + ".js"), "utf8");
    const limits = functionSegment(source, "function validateScopeLimits(rawScope, reject) {", "function preflight(args, config) {");
    assert.match(limits, /authorization\.reference/, workflow);
    const hash = sha256Of(limits);
    if (limitsHash === null) limitsHash = hash;
    else assert.equal(hash, limitsHash, workflow + ": scope limits drifted from assess");
  }
  assert.equal(sha256Of(gateLimits), limitsHash, "gate limits drifted from the nine workflows");
});

test("scope check and guard reject over-limit scope with G-CONF-01 before spawn", async () => {
  const dir = mkdtempSync(join(tmpdir(), "dsh-redblue-limits-"));
  try {
    const overLimit = {
      authorization: { type: "written", reference: "x".repeat(5000), grantedBy: "Security Office", validFrom: isoDate(NOW - 86400000), validTo: isoDate(NOW + 86400000) },
      targets: Array.from({ length: 300 }, () => ({ kind: "domain", value: "app.example.com" })),
      exclusions: [], mode: "passive",
      window: { start: isoTime(NOW - 3600000), end: isoTime(NOW + 3600000) },
      budget: { maxRequests: 100, maxMinutes: 60 },
      dataHandling: { retain: "findings-only", secrets: "mask-and-redact", destruction: "none" },
      dataSources: [],
    };
    const checked = checkScope(overLimit, { now: new Date(NOW) });
    assert.equal(checked.ok, false);
    assert.ok(checked.rejectedBy.includes("G-CONF-01"), JSON.stringify(checked.rejectedBy));
    assert.ok(checked.errors.some((error) => /authorization\.reference/.test(error.message)), JSON.stringify(checked.errors));
    assert.ok(checked.errors.some((error) => /targets 最多 200/.test(error.message)), JSON.stringify(checked.errors));

    const scopePath = join(dir, "over-limit.json");
    writeFileSync(scopePath, JSON.stringify(overLimit), "utf8");
    const spawnCalls = [];
    const guarded = await runGuard({
      recipeId: "runtime_probe",
      target: "app.example.com",
      scopePath, execute: false, workdir: dir, now: new Date(NOW),
    }, {
      spawnWithLimits: async (...args) => { spawnCalls.push(args); throw new Error("must not spawn"); },
    });
    assert.equal(guarded.exitCode, 1, JSON.stringify(guarded.output));
    assert.ok(guarded.output.rejectedBy.includes("G-CONF-01"), JSON.stringify(guarded.output.rejectedBy));
    assert.equal(spawnCalls.length, 0, "guard must reject over-limit scope before spawn");

    const boundary = checkScope(Object.assign({}, overLimit, {
      authorization: Object.assign({}, overLimit.authorization, { reference: "r".repeat(200) }),
      targets: Array.from({ length: 200 }, () => ({ kind: "domain", value: "app.example.com" })),
    }), { now: new Date(NOW) });
    assert.equal(boundary.ok, true, JSON.stringify(boundary.errors));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("normalizeFinding copies review fields identically in all ten workflows", () => {
  let findingHash = null;
  for (const workflow of WORKFLOWS) {
    const source = readFileSync(resolve(workflowDir, workflow + ".js"), "utf8");
    const segment = functionSegment(source, "function normalizeFinding(raw, defaults) {", "function dedupeFindings(findings) {");
    for (const field of REVIEW_FIELDS) {
      assert.ok(segment.includes('"' + field + '"'), workflow + ": normalizeFinding whitelist missing " + field);
    }
    assert.match(segment, /typeof source\[key\] === "string"/);
    const hash = sha256Of(segment);
    if (findingHash === null) findingHash = hash;
    else assert.equal(hash, findingHash, workflow + ": normalizeFinding drifted from assess");
  }
  let promptHash = null;
  for (const workflow of WORKFLOWS) {
    const source = readFileSync(resolve(workflowDir, workflow + ".js"), "utf8");
    const prompt = functionSegment(source, "function buildPrompt(ctx, stage, skill, extras, options) {", "async function runStage(ctx, stage, skill, extras, options) {");
    assert.ok(prompt.includes("confidenceRationale"), workflow + ": buildPrompt must advertise review fields");
    const hash = sha256Of(prompt);
    if (promptHash === null) promptHash = hash;
    else assert.equal(hash, promptHash, workflow + ": buildPrompt drifted from assess");
  }
});

test("review fields provided by agents are persisted into findings.json", async () => {
  const reviewValues = {
    confidenceRationale: "run-time PoC not executed; static chain only",
    counterevidence: "checked CSP and cookie flags; reflected context escaped",
    severityChangeConditions: "public unauthenticated exposure -> critical",
    fixVerification: "gate 4 (regression) not run",
    basis: "CWE-79 + differential response evidence",
  };
  const custom = (label) => {
    if (label.startsWith("validate:")) {
      return Object.assign({
        title: "Reflected XSS", category: "cross-site scripting",
        target: { kind: "url", value: "https://app.example.com/login?q=x" },
        severity: "medium", disposition: "reportable", confidence: "medium",
        claim: "c", evidence: "e", remediation: "r",
      }, reviewValues);
    }
    if (label === "review") {
      return Object.assign({ reviewNotes: "ok", evidenceRefs: [] }, {
        confidenceRationale: reviewValues.confidenceRationale,
        counterevidence: reviewValues.counterevidence,
      });
    }
    if (label === "disposition") {
      return Object.assign({
        disposition: "reportable", severity: "high", confidence: "medium",
        claim: "c", evidence: "e", remediation: "r", evidenceRefs: [],
      }, reviewValues);
    }
    return undefined;
  };

  const assess = await runWorkflow("assess", argsFor("assess"), custom);
  const assessFindings = JSON.parse(fileContentFrom(assess.harness, "findings.json"));
  const validated = assessFindings.findings.find((finding) => finding.category === "cross-site scripting");
  assert.ok(validated, "assess findings.json must include the validated finding");
  for (const field of REVIEW_FIELDS) {
    assert.equal(validated[field], reviewValues[field], "assess findings.json missing " + field);
  }

  const triage = await runWorkflow("triage", argsFor("triage"), custom);
  const triageFindings = JSON.parse(fileContentFrom(triage.harness, "findings.json"));
  assert.equal(triageFindings.findings.length, 1);
  for (const field of REVIEW_FIELDS) {
    assert.equal(triageFindings.findings[0][field], reviewValues[field], "triage findings.json missing " + field);
  }
});

test("hunt accepts pcap and cloudtrail data sources and still rejects unknown kinds", async () => {
  for (const kind of ["pcap", "cloudtrail"]) {
    const args = argsFor("hunt");
    args.scope.dataSources = [dataSource(kind, "C:/work/" + kind + ".json")];
    const { result, harness } = await runWorkflow("hunt", args);
    assert.equal(result.status, "clean", kind + ": " + JSON.stringify(result.rejectedBy));
    assert.equal(result.exitCode, 0, kind);
    assert.ok(agentCalls(harness).length > 0, kind + ": hunt must run");
  }
  const unknown = argsFor("hunt");
  unknown.scope.dataSources = [{ kind: "network", value: "C:/work/packets.pcap" }];
  const { result, harness } = await runWorkflow("hunt", unknown);
  assert.equal(result.status, "rejected");
  assert.ok(result.rejectedBy.includes("G-CONF-01"), JSON.stringify(result.rejectedBy));
  assert.ok(result.rejectedBy.includes("G-DS-01"), JSON.stringify(result.rejectedBy));
  assert.equal(agentCalls(harness).length, 0, "unknown data source kind must not reach any agent");
});

// t20 regression: schema/doc consistency for review fields, stats, phases, S refs
// ---------------------------------------------------------------------------

function validateSchemaValue(schema, value, path = "$") {
  const type = schema.type;
  if (type === "object") {
    assert.ok(value && typeof value === "object" && !Array.isArray(value), path + " must be object");
    for (const key of schema.required || []) assert.ok(Object.prototype.hasOwnProperty.call(value, key), path + " missing " + key);
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) assert.ok(Object.prototype.hasOwnProperty.call(schema.properties || {}, key), path + " unexpected " + key);
    }
    for (const [key, child] of Object.entries(schema.properties || {})) if (Object.prototype.hasOwnProperty.call(value, key)) validateSchemaValue({ type: child.type, properties: child.properties, required: child.required, additionalProperties: child.additionalProperties }, value[key], path + "." + key);
  } else if (type === "array") {
    assert.ok(Array.isArray(value), path + " must be array");
    if (schema.items) for (const [index, item] of value.entries()) validateSchemaValue(schema.items, item, path + "[" + index + "]");
  } else if (type === "string") {
    assert.equal(typeof value, "string", path + " must be string");
    if (schema.minLength !== undefined) assert.ok(value.length >= schema.minLength, path + " minLength");
    if (schema.maxLength !== undefined) assert.ok(value.length <= schema.maxLength, path + " maxLength");
  } else if (type === "integer") {
    assert.ok(Number.isInteger(value), path + " must be integer");
  } else if (schema.enum) {
    assert.ok(schema.enum.includes(value), path + " enum");
  }
}

test("finding schema accepts review fields and rejects unknown fields", () => {
  const schema = JSON.parse(readFileSync(resolve(root, "schema/finding.schema.json"), "utf8"));
  const reviewFields = ["confidenceRationale", "counterevidence", "severityChangeConditions", "fixVerification", "basis"];
  for (const field of reviewFields) {
    assert.ok(schema.properties[field], "missing schema field " + field);
    assert.equal(schema.properties[field].type, "string", field + " must be string");
  }
  assert.equal(schema.additionalProperties, false);
  const sample = {
    id: "rbf_0123456789abcdef",
    fingerprint: "fp_0123456789abcdef",
    domain: "red",
    kind: "vulnerability",
    title: "review sample",
    target: { kind: "domain", value: "app.example.com" },
    category: "cross-site scripting",
    severity: "medium",
    disposition: "reportable",
    confidence: "medium",
    claim: "claim",
    evidence: "evidence",
    remediation: "remediation",
    runId: "rb_20261119T080000Z_abcd",
    createdAt: "2026-11-19T08:00:00Z",
    confidenceRationale: "run-time proof missing",
    counterevidence: "checked X and Y",
    severityChangeConditions: "if public unauthenticated -> critical",
    fixVerification: "gate 3 not passed",
    basis: "CWE + evidence",
  };
  validateSchemaValue(schema, sample);
  assert.throws(() => validateSchemaValue(schema, Object.assign({}, sample, { shadowField: true })), /unexpected shadowField/);
});

test("value-extraction stats match the ACS/red ledgers and actual skill files", () => {
  const doc = readFileSync(resolve(root, "docs/value-extraction.md"), "utf8");
  for (const needle of ["6 个有 `--dry-run`", "590 个有 `--output`", "184（requests）+ 15（urllib）+ 4（httpx/aiohttp）", "36 个文件含 `verify=False`（字面量 35）", "D1 71 个红队执行/武器化前缀", "D2 14 个纯治理/认证/项目管理", "D3 1 个超 48 KiB 单文件"]) {
    assert.ok(doc.includes(needle), "value-extraction missing: " + needle);
  }
  assert.doesNotMatch(doc, /0 个有 `--dry-run`|227 个使用 `requests`|35 个含 `verify=False`/);
  const skillDirs = readdirSync(resolve(root, "skills"), { withFileTypes: true }).filter((entry) => entry.isDirectory());
  assert.equal(skillDirs.length, 16, "v0.2.0 ships 16 bundled skills");
  const lines = skillDirs.map((entry) => readFileSync(resolve(root, "skills", entry.name, "SKILL.md"), "utf8").replace(/\r?\n$/, "").split(/\r?\n/).length).sort((a, b) => a - b);
  assert.equal(lines[0], 107);
  assert.equal(lines[lines.length - 1], 198);
  // docs/value-extraction.md、docs/assembly-report.md 等文档计数同步属于 v0.2 文档任务（t36 outOfScope）；
  // 这里只锁定 v0.1 历史台账仍在（其 15 技能口径不改写）。
  assert.ok(doc.includes("15 个，107–175 行/个"));
  const redLedger = readFileSync(resolve(root, "references/red/extraction-ledger.md"), "utf8");
  assert.match(redLedger, /\| ACS \|.*\| 818 \|/);
  const dropLine = redLedger.split(/\r?\n/).find((line) => line.includes("9 个与定位冲突项"));
  assert.ok(dropLine, "red ledger §3 must list the 9 conflict drop items");
  const nineDrops = /9 个与定位冲突项（([^）]+)）/.exec(dropLine)[1].split("、").map((item) => item.trim());
  assert.equal(nineDrops.length, 9, "ledger must name exactly 9 conflict drops: " + nineDrops.join(","));
  for (const item of nineDrops) assert.ok(doc.includes(item), "value-extraction §2.1 must name dropped item: " + item);
  assert.doesNotMatch(doc, /9 个定位冲突项（与 dsh-security 源码审计重叠/, "stale drop rationale must be replaced");
  assert.match(redLedger, /find \.work\/sources\/acs/);
});

test("README/DETAIL phase strings match actual workflow stages", () => {
  const readme = readFileSync(resolve(root, "README.md"), "utf8");
  const detail = readFileSync(resolve(root, "docs/DETAIL.md"), "utf8");
  for (const text of [readme, detail]) {
    assert.match(text, /`hunt\.js`[^\n]*scope→hunt→report→seal/);
    assert.doesNotMatch(text, /hunt-plan/);
    assert.match(text, /`triage\.js`[^\n]*report→seal/);
    assert.match(text, /`harden\.js`[^\n]*report→seal/);
  }
});

test("script-patterns has no dangling S8 reference and sanitization-rules is synced", () => {
  const patterns = readFileSync(resolve(root, "references/shared/script-patterns.md"), "utf8");
  assert.doesNotMatch(patterns, /S8/);
  assert.match(patterns, /见 S7/);
  for (let i = 1; i <= 7; i++) assert.match(patterns, new RegExp("S" + i + " "));
  const rules = readFileSync(resolve(root, "docs/sanitization-rules.md"), "utf8");
  assert.match(rules, /27 篇派生参考/);
  assert.doesNotMatch(rules, /17 篇派生参考/);
  assert.match(rules, /node tools\/sanitize-lint\.mjs --strict --json\n/);
});
test("hunt reference data source kinds are registered in schema and workflow", () => {
  const ref = readFileSync(resolve(root, "references/blue/hunt-hypothesis.md"), "utf8");
  const kindLine = /kind:\s+([^\n]+)/.exec(ref);
  assert.ok(kindLine, "hunt reference must expose a kind line");
  const kinds = kindLine[1].split("|").map((value) => value.trim()).filter(Boolean);
  const schema = JSON.parse(readFileSync(resolve(root, "schema/scope.schema.json"), "utf8"));
  const schemaKinds = schema.properties.dataSources.items.properties.kind.enum;
  const huntSource = readFileSync(resolve(workflowDir, "hunt.js"), "utf8");
  const requirement = /requireDataSources: \[\{ gate: "G-DS-01", kinds: \[([^\]]+)\]/.exec(huntSource);
  assert.ok(requirement, "hunt.js must declare the G-DS-01 kind list");
  const requiredKinds = requirement[1].split(",").map((v) => v.trim().replace(/^"|"$/g, ""));
  for (const kind of kinds) assert.ok(requiredKinds.includes(kind), "hunt G-DS-01 must accept reference kind " + kind);
  const workflowKinds = /const DATA_SOURCE_KINDS = \[([^\]]+)\]/.exec(huntSource)[1].split(",").map((v) => v.trim().replace(/^"|"$/g, ""));
  for (const kind of kinds) {
    assert.ok(schemaKinds.includes(kind), "schema missing data source kind " + kind);
    assert.ok(workflowKinds.includes(kind), "workflow missing data source kind " + kind);
  }
});
