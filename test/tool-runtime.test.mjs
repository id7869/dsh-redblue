import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { runGuard, spawnWithLimits } from "../tools/lib/guard.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const SEC = resolve(root, "tools", "sec.mjs");
const LINT = resolve(root, "tools", "sanitize-lint.mjs");
const NOW = new Date("2026-11-19T08:00:00Z");
const tmpRoot = mkdtempSync(join(tmpdir(), "dsh-redblue-tool-"));
after(() => rmSync(tmpRoot, { recursive: true, force: true }));

function tempDir(name) {
  const directory = join(tmpRoot, name);
  mkdirSync(directory, { recursive: true });
  return directory;
}

function run(args) {
  return spawnSync(process.execPath, [SEC, ...args], { cwd: process.cwd(), encoding: "utf8" });
}

function runLint(args, env) {
  return spawnSync(process.execPath, [LINT, ...args], { cwd: process.cwd(), encoding: "utf8", env: Object.assign({}, process.env, env || {}) });
}

function json(result) {
  try {
    return JSON.parse(result.stdout);
  } catch {
    assert.fail("命令未输出 JSON: " + result.stdout + "\n" + result.stderr);
  }
}

function scopeDocument(overrides = {}) {
  return Object.assign({
    authorization: {
      type: "written",
      reference: "ROE-TEST-001",
      grantedBy: "Security Office",
      validFrom: "2026-11-18",
      validTo: "2026-11-20",
    },
    targets: [{ kind: "domain", value: "app.example.com" }],
    exclusions: [],
    mode: "passive",
    window: { start: "2026-11-19T00:00:00Z", end: "2026-11-19T23:00:00Z" },
    budget: { maxRequests: 100, maxMinutes: 60 },
    dataHandling: { retain: "findings-only", secrets: "mask-and-redact", destruction: "none" },
    dataSources: [],
  }, overrides);
}

function writeScope(directory, overrides = {}, name = "scope") {
  const path = join(directory, name + ".json");
  writeFileSync(path, JSON.stringify(scopeDocument(overrides), null, 2), "utf8");
  return path;
}

function parseEvidence(workdir) {
  const evidencePath = join(workdir, "guard-evidence.jsonl");
  assert.ok(existsSync(evidencePath), "guard-evidence.jsonl must exist after execution");
  return readFileSync(evidencePath, "utf8").trim().split(/\r?\n/).map((line) => JSON.parse(line));
}

// ---------------------------------------------------------------------------
// Entry point and recipe whitelist
// ---------------------------------------------------------------------------

test("--help works and describes the guarded tool surface", () => {
  const result = run(["--help"]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /dsh-redblue tool runtime/);
  assert.match(result.stdout, /guard --recipe/);
  assert.match(result.stdout, /shell=false/);
});

test("recipes list returns at least 8 whitelisted recipes without real targets", () => {
  const result = run(["recipes", "list"]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const output = json(result);
  assert.equal(output.ok, true);
  assert.ok(output.count >= 8, "expected >=8 recipes, got " + output.count);
  const ids = new Set();
  for (const recipe of output.recipes) {
    assert.ok(typeof recipe.id === "string" && recipe.id.length > 0);
    assert.ok(!ids.has(recipe.id));
    ids.add(recipe.id);
    assert.ok(["recon", "discover", "exploit", "post", "blue", "purple"].includes(recipe.lane));
    assert.ok(["passive", "active", "exploit", "post"].includes(recipe.requiredMode));
    assert.ok(Array.isArray(recipe.argv) || recipe.argv === undefined);
    assert.ok(recipe.timeoutMs >= 1000);
    assert.ok(recipe.outputLimitBytes >= 1024);
  }
  assert.ok(!/attacker\.com|evil\.com|10\.0\.0\.\d|192\.168\./.test(result.stdout), "recipes must not carry real targets");
  const full = readFileSync(resolve(root, "tools", "recipes.json"), "utf8");
  const document = JSON.parse(full);
  for (const recipe of document.recipes) {
    assert.ok(Array.isArray(recipe.argv) && recipe.argv.length > 0);
    assert.ok(!["sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh"].includes(recipe.binary.toLowerCase()));
  }
});

test("recipes show returns one full recipe and rejects unknown ids", () => {
  const found = run(["recipes", "show", "dns_lookup"]);
  assert.equal(found.status, 0);
  const output = json(found);
  assert.equal(output.recipe.id, "dns_lookup");
  assert.ok(Array.isArray(output.recipe.argv));
  assert.equal(output.recipe.targetKind, "domain");

  const missing = run(["recipes", "show", "no_such_recipe"]);
  assert.equal(missing.status, 1);
  assert.equal(json(missing).ok, false);
});

// ---------------------------------------------------------------------------
// scope check
// ---------------------------------------------------------------------------

test("scope check accepts a valid written scope and prints normalized output", () => {
  const dir = tempDir("scope-good");
  const scopePath = writeScope(dir);
  const result = run(["scope", "check", "--scope", scopePath, "--now", NOW.toISOString()]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const output = json(result);
  assert.equal(output.ok, true);
  assert.deepEqual(output.rejectedBy, []);
  assert.equal(output.normalized.authorization.reference, "ROE-TEST-001");
  assert.deepEqual(output.normalized.targets, [{ kind: "domain", value: "app.example.com" }]);
  assert.equal(output.normalized.mode, "passive");
});

test("scope check rejects at least six classes of invalid scope", () => {
  const dir = tempDir("scope-bad");
  const cases = [
    ["missing authorization", { authorization: undefined }, "G-AUTH-01"],
    ["empty reference", { authorization: { type: "written", reference: "", grantedBy: "Office", validFrom: "2026-11-18", validTo: "2026-11-20" } }, "G-AUTH-01"],
    ["invalid authorization type", { authorization: { type: "verbal", reference: "x", grantedBy: "Office", validFrom: "2026-11-18", validTo: "2026-11-20" } }, "G-AUTH-02"],
    ["expired authorization", { authorization: { type: "written", reference: "x", grantedBy: "Office", validFrom: "2020-01-01", validTo: "2020-12-31" } }, "G-AUTH-07"],
    ["empty targets", { targets: [] }, "G-TGT-01"],
    ["wildcard target", { targets: [{ kind: "cidr", value: "0.0.0.0/0" }] }, "G-TGT-02"],
    ["invalid target kind", { targets: [{ kind: "email", value: "a@example.com" }] }, "G-TGT-03"],
    ["invalid mode", { mode: "bogus" }, "G-MODE-01"],
    ["destruction", { dataHandling: { retain: "findings-only", secrets: "mask-and-redact", destruction: "delete" } }, "G-DH-03"],
    ["secrets", { dataHandling: { retain: "findings-only", secrets: "plain", destruction: "none" } }, "G-DH-02"],
    ["budget", { budget: { maxRequests: 0, maxMinutes: 60 } }, "G-BUD-01"],
    ["window", { window: { start: "2026-11-21T00:00:00Z", end: "2026-11-21T01:00:00Z" } }, "G-WIN-03"],
  ];
  for (const [label, overrides, gate] of cases) {
    const path = join(dir, "scope-" + label.replace(/\W+/g, "-") + ".json");
    writeFileSync(path, JSON.stringify(scopeDocument(overrides), null, 2), "utf8");
    const result = run(["scope", "check", "--scope", path, "--now", NOW.toISOString()]);
    assert.equal(result.status, 1, label + ": expected exit 1\n" + result.stdout + result.stderr);
    const output = json(result);
    assert.equal(output.ok, false, label);
    assert.ok(output.rejectedBy.includes(gate), label + ": expected " + gate + " got " + JSON.stringify(output.rejectedBy));
  }
});

test("scope check reports unreadable/invalid scope as failure", () => {
  const missing = run(["scope", "check", "--scope", join(tmpRoot, "does-not-exist.json"), "--now", NOW.toISOString()]);
  assert.equal(missing.status, 1);
  assert.equal(json(missing).ok, false);
});

test("scope check enforces the same schema limits as the nine workflows", () => {
  const dir = tempDir("scope-limits");
  const overLimit = scopeDocument({
    authorization: { type: "written", reference: "x".repeat(5000), grantedBy: "Security Office", validFrom: "2026-11-18", validTo: "2026-11-20" },
    targets: Array.from({ length: 300 }, () => ({ kind: "domain", value: "app.example.com" })),
  });
  const scopePath = join(dir, "over-limit.json");
  writeFileSync(scopePath, JSON.stringify(overLimit), "utf8");
  const result = run(["scope", "check", "--scope", scopePath, "--now", NOW.toISOString()]);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const output = json(result);
  assert.equal(output.ok, false);
  assert.ok(output.rejectedBy.includes("G-CONF-01"), JSON.stringify(output.rejectedBy));
  assert.ok(output.errors.some((error) => /authorization\.reference/.test(error.message)), JSON.stringify(output.errors));
  assert.ok(output.errors.some((error) => /targets 最多 200/.test(error.message)), JSON.stringify(output.errors));

  const boundary = scopeDocument({
    authorization: { type: "written", reference: "r".repeat(200), grantedBy: "Security Office", validFrom: "2026-11-18", validTo: "2026-11-20" },
    targets: Array.from({ length: 200 }, () => ({ kind: "domain", value: "app.example.com" })),
  });
  const boundaryPath = join(dir, "boundary.json");
  writeFileSync(boundaryPath, JSON.stringify(boundary), "utf8");
  const okResult = run(["scope", "check", "--scope", boundaryPath, "--now", NOW.toISOString()]);
  assert.equal(okResult.status, 0, okResult.stdout + okResult.stderr);
  assert.equal(json(okResult).ok, true);
});

test("guard rejects over-limit scope before spawn (dry-run too)", async () => {
  const dir = tempDir("guard-limits");
  const scopePath = join(dir, "over-limit.json");
  writeFileSync(scopePath, JSON.stringify(scopeDocument({
    authorization: { type: "written", reference: "x".repeat(5000), grantedBy: "Security Office", validFrom: "2026-11-18", validTo: "2026-11-20" },
    targets: Array.from({ length: 300 }, () => ({ kind: "domain", value: "app.example.com" })),
  })), "utf8");
  const spawnCalls = [];
  const result = await runGuard({
    recipeId: "runtime_probe",
    target: "app.example.com",
    scopePath,
    execute: false,
    workdir: dir,
    now: NOW,
  }, {
    spawnWithLimits: async (...args) => { spawnCalls.push(args); throw new Error("must not spawn"); },
  });
  assert.equal(result.exitCode, 1);
  assert.ok(result.output.rejectedBy.includes("G-CONF-01"), JSON.stringify(result.output.rejectedBy));
  assert.equal(spawnCalls.length, 0);
  assert.ok(!existsSync(join(dir, "guard-evidence.jsonl")));
});

// ---------------------------------------------------------------------------
// evidence / sarif / ioc / log / rule
// ---------------------------------------------------------------------------

test("evidence hash/verify build and recompute a SHA256 manifest", () => {
  const dir = tempDir("evidence");
  writeFileSync(join(dir, "a.txt"), "hello\n", "utf8");
  writeFileSync(join(dir, "b.txt"), "world\n", "utf8");
  const manifest = join(dir, "manifest.json");
  const hashed = run(["evidence", "hash", "--dir", dir, "--out", manifest]);
  assert.equal(hashed.status, 0, hashed.stdout + hashed.stderr);
  const output = json(hashed);
  assert.equal(output.files, 2);
  const document = JSON.parse(readFileSync(manifest, "utf8"));
  assert.equal(document.schemaVersion, "dsh-redblue-evidence/v1");
  assert.deepEqual(document.files.map((file) => file.path), ["a.txt", "b.txt"]);
  for (const file of document.files) assert.match(file.sha256, /^[0-9a-f]{64}$/);

  const verified = run(["evidence", "verify", "--manifest", manifest, "--dir", dir]);
  assert.equal(verified.status, 0, verified.stdout + verified.stderr);
  assert.equal(json(verified).ok, true);

  writeFileSync(join(dir, "a.txt"), "tampered\n", "utf8");
  const tampered = run(["evidence", "verify", "--manifest", manifest, "--dir", dir]);
  assert.equal(tampered.status, 1);
  const tamperedOutput = json(tampered);
  assert.equal(tamperedOutput.ok, false);
  assert.equal(tamperedOutput.mismatched.length, 1);
});

test("sarif convert emits SARIF 2.1.0 with rules, levels and locations", () => {
  const dir = tempDir("sarif");
  const findings = join(dir, "findings.json");
  writeFileSync(findings, JSON.stringify({
    schemaVersion: "dsh-redblue-findings/v1",
    runId: "rb_20261119T070000Z_0001",
    workflow: "assess",
    findings: [
      { id: "rbf_1", fingerprint: "fp_1", domain: "red", kind: "vulnerability", title: "XSS", category: "cross-site scripting", severity: "high", disposition: "reportable", claim: "reflected", target: { kind: "url", value: "https://app.example.com/x" } },
      { id: "rbf_2", fingerprint: "fp_2", domain: "red", kind: "vulnerability", title: "Noise", category: "noise", severity: "low", disposition: "suppressed", claim: "x", target: { kind: "host", value: "app.example.com" } },
    ],
  }), "utf8");
  const out = join(dir, "results.sarif");
  const result = run(["sarif", "convert", "--findings", findings, "--out", out]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  assert.equal(json(result).results, 1);
  const sarif = JSON.parse(readFileSync(out, "utf8"));
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.$schema, "https://json.schemastore.org/sarif-2.1.0.json");
  assert.equal(sarif.runs[0].tool.driver.name, "dsh-redblue");
  assert.equal(sarif.runs[0].tool.driver.rules.length, 1);
  assert.equal(sarif.runs[0].results.length, 1);
  assert.equal(sarif.runs[0].results[0].ruleId, "cross-site-scripting");
  assert.equal(sarif.runs[0].results[0].level, "error");
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, "https://app.example.com/x");
  assert.equal(sarif.runs[0].results[0].partialFingerprints.dshRedblueFingerprint, "fp_1");
});

test("ioc extract defangs by default and supports --no-defang", () => {
  const dir = tempDir("ioc");
  const input = join(dir, "sample.txt");
  writeFileSync(input, "https://app.example.com/x 192.0.2.10 example.com 0123456789abcdef0123456789abcdef\n", "utf8");
  const result = run(["ioc", "extract", "--input", input]);
  assert.equal(result.status, 0);
  const output = json(result);
  assert.equal(output.defanged, true);
  assert.deepEqual(output.urls, ["hxxps://app[.]example[.]com/x"]);
  assert.ok(output.domains.includes("app[.]example[.]com"));
  assert.ok(output.domains.includes("example[.]com"));
  assert.deepEqual(output.ips, ["192[.]0[.]2[.]10"]);
  assert.deepEqual(output.hashes, ["0123456789abcdef0123456789abcdef"]);

  const raw = run(["ioc", "extract", "--input", input, "--no-defang"]);
  assert.equal(raw.status, 0);
  const rawOutput = json(raw);
  assert.equal(rawOutput.defanged, false);
  assert.deepEqual(rawOutput.urls, ["https://app.example.com/x"]);
  assert.ok(rawOutput.domains.includes("app.example.com"));
});

test("log normalize handles jsonl, csv and syslog with bad-line counts", () => {
  const dir = tempDir("logs");
  const jsonl = join(dir, "logs.jsonl");
  writeFileSync(jsonl, [
    JSON.stringify({ ts: "2026-11-19T07:00:00Z", host: "h1", user: "u", message: "ok" }),
    "not-json",
    JSON.stringify({ time: 1700000000, msg: "epoch" }),
  ].join("\n") + "\n", "utf8");
  const jsonlOut = join(dir, "jsonl.out.jsonl");
  const jsonlResult = run(["log", "normalize", "--input", jsonl, "--format", "jsonl", "--out", jsonlOut]);
  assert.equal(jsonlResult.status, 0);
  const jsonlSummary = json(jsonlResult);
  assert.equal(jsonlSummary.normalized, 2);
  assert.equal(jsonlSummary.badLines, 1);
  const jsonlLines = readFileSync(jsonlOut, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(jsonlLines[0].ts, "2026-11-19T07:00:00.000Z");
  assert.equal(jsonlLines[0].host, "h1");
  assert.equal(jsonlLines[0].actor, "u");

  const csv = join(dir, "logs.csv");
  writeFileSync(csv, "timestamp,host,user,message\n2026-11-19T07:00:00Z,h1,u,ok\n,bad,u,bad\n", "utf8");
  const csvOut = join(dir, "csv.out.jsonl");
  const csvResult = run(["log", "normalize", "--input", csv, "--format", "csv", "--out", csvOut]);
  assert.equal(csvResult.status, 0);
  const csvSummary = json(csvResult);
  assert.equal(csvSummary.normalized, 2);
  assert.equal(csvSummary.badLines, 0);

  const syslog = join(dir, "syslog.txt");
  writeFileSync(syslog, "<34>1 2026-11-19T07:00:00Z host app 1 ID - hello\nNov 19 07:00:00 host app[1]: world\nbroken\n", "utf8");
  const syslogOut = join(dir, "syslog.out.jsonl");
  const syslogResult = run(["log", "normalize", "--input", syslog, "--format", "syslog", "--out", syslogOut]);
  assert.equal(syslogResult.status, 0);
  const syslogSummary = json(syslogResult);
  assert.equal(syslogSummary.normalized, 2);
  assert.equal(syslogSummary.badLines, 1);
  const syslogLines = readFileSync(syslogOut, "utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.match(syslogLines[0].ts, /^2026-11-19T07:00:00\.000Z$/);
  assert.match(syslogLines[1].ts, /^2026-11-19T07:00:00\.000Z$/);
});

test("rule lint checks Sigma structural keys", () => {
  const dir = tempDir("sigma");
  const valid = join(dir, "valid.yml");
  writeFileSync(valid, [
    "title: Test rule",
    "id: 1b2c3d4e-5f60-4718-9a0b-1c2d3e4f5a6b",
    "status: test",
    "detection:",
    "  selection:",
    "    EventID: 1",
    "  condition: selection",
    "logsource:",
    "  product: windows",
    "level: medium",
  ].join("\n"), "utf8");
  const validResult = run(["rule", "lint", "--file", valid]);
  assert.equal(validResult.status, 0, validResult.stdout + validResult.stderr);
  const validOutput = json(validResult);
  assert.equal(validOutput.ok, true);
  for (const key of ["title", "id", "status", "detection", "logsource", "level"]) assert.ok(validOutput.keys.includes(key));

  const invalid = join(dir, "invalid.yml");
  writeFileSync(invalid, "title: Bad\nstatus: whatever\n", "utf8");
  const invalidResult = run(["rule", "lint", "--file", invalid]);
  assert.equal(invalidResult.status, 1);
  const invalidOutput = json(invalidResult);
  assert.equal(invalidOutput.ok, false);
  assert.ok(invalidOutput.issues.some((issue) => issue.code === "missing-detection"));
  assert.ok(invalidOutput.issues.some((issue) => issue.code === "missing-logsource"));
});

test("sanitize lint R1 validates provenance on assets that declare it (t22 R6)", () => {
  const dir = tempDir("lint-asset-prov");
  const provenance = [
    "# dsh-redblue:provenance",
    "# source-repo: https://github.com/usestrix/strix",
    "# source-commit: 8db295a5b3564be2b430bb3a9afdb4db7850fa24",
    "# source-license: Apache-2.0",
    "# source-path: README.md",
    "# last-verified: 2026-11-19",
    "# rewrite-summary: test asset template",
  ];
  writeFileSync(join(dir, "asset-good.yml"), provenance.concat(["title: test", ""]).join("\n"), "utf8");
  const good = runLint(["--strict", "--json", "--check", "R1-PROVENANCE", dir]);
  assert.equal(good.status, 0, good.stdout + good.stderr);
  assert.equal(json(good).summary.blockers, 0, JSON.stringify(json(good).checks));

  writeFileSync(join(dir, "asset-bad.yml"), provenance.filter((line) => !line.includes("source-license")).concat(["title: test", ""]).join("\n"), "utf8");
  const bad = runLint(["--strict", "--json", "--check", "R1-PROVENANCE", dir]);
  assert.equal(bad.status, 1, bad.stdout + bad.stderr);
  const badOutput = json(bad);
  assert.ok(badOutput.checks.some((check) => check.id === "R1-PROVENANCE" && check.file.endsWith("asset-bad.yml") && /asset provenance/.test(check.message)), JSON.stringify(badOutput.checks));

  writeFileSync(join(dir, "plain.svg"), "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>\n", "utf8");
  const plain = runLint(["--strict", "--json", "--check", "R1-PROVENANCE", join(dir, "plain.svg")]);
  assert.equal(plain.status, 0, "assets without provenance are not R1 objects: " + plain.stdout + plain.stderr);
});

test("sanitize lint --policy is test-only and cannot weaken the release gate (t22 R7)", () => {
  const dir = tempDir("lint-policy");
  const policyPath = join(dir, "policy.json");
  writeFileSync(policyPath, JSON.stringify({ version: "R1-R12/v1" }), "utf8");
  const fixturesGood = resolve(root, "test", "fixtures", "good");
  const blocked = runLint(["--strict", "--json", "--policy", policyPath, fixturesGood], { NODE_ENV: "" });
  assert.equal(blocked.status, 2, blocked.stdout + blocked.stderr);
  assert.match(blocked.stderr, /allow-policy-override/);
  assert.equal(blocked.stdout.trim(), "", "usage error must not emit a lint report");

  const explicit = runLint(["--strict", "--json", "--policy", policyPath, "--allow-policy-override", fixturesGood]);
  assert.equal(explicit.status, 0, explicit.stdout + explicit.stderr);
  assert.equal(json(explicit).policy, "R1-R12/v1");

  const viaEnv = runLint(["--strict", "--json", "--policy", policyPath, fixturesGood], { NODE_ENV: "test" });
  assert.equal(viaEnv.status, 0, viaEnv.stdout + viaEnv.stderr);

  const embedded = runLint(["--strict", "--json", fixturesGood]);
  assert.equal(embedded.status, 0);
  assert.equal(json(embedded).policy, "R1-R12/v1", "default CLI must use the embedded POLICY");
});

// ---------------------------------------------------------------------------
// guard: dry-run, gating and execution
// ---------------------------------------------------------------------------

test("guard dry-run prints a plan without spawning or writing evidence", () => {
  const dir = tempDir("guard-dry");
  const scopePath = writeScope(dir);
  const result = run(["guard", "--recipe", "runtime_probe", "--target", "app.example.com", "--scope", scopePath, "--now", NOW.toISOString()]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const output = json(result);
  assert.equal(output.ok, true);
  assert.equal(output.dryRun, true);
  assert.deepEqual(output.argv, ["--version"]);
  assert.ok(output.note.includes("dry-run"));
  assert.ok(!existsSync(join(dir, "guard-evidence.jsonl")), "dry-run must not write evidence");
});

test("guard dry-run refusals report ok=false and exit 1 (unreadable scope exits 0)", () => {
  const dir = tempDir("guard-reject");
  const validScope = writeScope(dir, {}, "valid-scope");
  const missingScope = join(dir, "missing-scope.json");

  const missing = run(["guard", "--recipe", "runtime_probe", "--target", "app.example.com", "--scope", missingScope]);
  assert.equal(missing.status, 0, "unreadable scope in dry-run: no executable plan, command itself succeeds");
  assert.equal(json(missing).ok, false);
  assert.ok(json(missing).rejectedBy.includes("G-AUTH-01"));
  assert.ok(!existsSync(join(dir, "guard-evidence.jsonl")));

  const expired = run(["guard", "--recipe", "runtime_probe", "--target", "app.example.com", "--scope", writeScope(dir, { authorization: { type: "written", reference: "x", grantedBy: "O", validFrom: "2020-01-01", validTo: "2020-12-31" } }, "expired"), "--now", NOW.toISOString()]);
  assert.equal(expired.status, 1);
  assert.equal(json(expired).ok, false);
  assert.ok(json(expired).rejectedBy.includes("G-AUTH-07"));

  const outOfScope = run(["guard", "--recipe", "runtime_probe", "--target", "other.example.com", "--scope", validScope, "--now", NOW.toISOString()]);
  assert.equal(outOfScope.status, 1);
  assert.equal(json(outOfScope).ok, false);
  assert.ok(json(outOfScope).rejectedBy.includes("G-TGT-04"), JSON.stringify(json(outOfScope).rejectedBy));

  const wildcard = run(["guard", "--recipe", "runtime_probe", "--target", "app.example.com", "--scope", writeScope(dir, { targets: [{ kind: "cidr", value: "0.0.0.0/0" }] }, "wildcard"), "--now", NOW.toISOString()]);
  assert.equal(wildcard.status, 1);
  assert.equal(json(wildcard).ok, false);
  assert.ok(json(wildcard).rejectedBy.includes("G-TGT-02"));

  const mode = run(["guard", "--recipe", "http_headers", "--target", "https://app.example.com/", "--scope", writeScope(dir, { targets: [{ kind: "url", value: "https://app.example.com/" }] }, "mode"), "--now", NOW.toISOString()]);
  assert.equal(mode.status, 1);
  assert.equal(json(mode).ok, false);
  assert.ok(json(mode).rejectedBy.includes("G-MODE-02"), JSON.stringify(json(mode).rejectedBy));

  const internal = run(["guard", "--recipe", "runtime_probe", "--target", "app.example.com", "--scope", writeScope(dir, { authorization: { type: "internal-mandate", reference: "x", grantedBy: "O", validFrom: "2026-11-18", validTo: "2026-11-20" } }, "internal"), "--now", NOW.toISOString()]);
  assert.equal(internal.status, 1);
  assert.equal(json(internal).ok, false);
  assert.ok(json(internal).rejectedBy.includes("G-AUTH-03"));

  const noConfirm = run(["guard", "--recipe", "runtime_probe", "--target", "app.example.com", "--scope", validScope, "--execute", "--now", NOW.toISOString()]);
  assert.equal(noConfirm.status, 1, "--execute refusals exit 1");
  assert.ok(json(noConfirm).rejectedBy.includes("G-CFM-01"));

  const badConfirm = run(["guard", "--recipe", "runtime_probe", "--target", "app.example.com", "--scope", validScope, "--execute", "--confirm", "other.example.com", "--now", NOW.toISOString()]);
  assert.equal(badConfirm.status, 1);
  assert.ok(json(badConfirm).rejectedBy.includes("G-CFM-02"));

  assert.ok(!existsSync(join(dir, "guard-evidence.jsonl")), "rejections must not write evidence");
});

test("guard injection target is rejected before spawn and never reaches argv", async () => {
  const dir = tempDir("guard-inject");
  const scopePath = writeScope(dir);
  const marker = join(tmpRoot, "pwned-marker.txt");
  const target = "app.example.com; touch " + marker;
  const result = run(["guard", "--recipe", "runtime_probe", "--target", target, "--scope", scopePath, "--execute", "--confirm", target, "--now", NOW.toISOString()]);
  assert.equal(result.status, 1);
  assert.ok(json(result).rejectedBy.includes("G-TGT-03"), JSON.stringify(json(result).rejectedBy));
  assert.ok(!existsSync(marker), "injection target must not execute");

  const spawnCalls = [];
  const libResult = await runGuard({
    recipeId: "runtime_probe",
    target,
    scopePath,
    execute: true,
    confirm: target,
    workdir: dir,
    now: NOW,
  }, {
    spawnWithLimits: async (...args) => { spawnCalls.push(args); throw new Error("should not spawn"); },
  });
  assert.equal(libResult.exitCode, 1);
  assert.equal(spawnCalls.length, 0, "guard must not spawn for an injection target");
});

test("guard rejects a missing binary without spawning", async () => {
  const dir = tempDir("guard-binary");
  const scopePath = writeScope(dir);
  const spawnCalls = [];
  const result = await runGuard({
    recipeId: "runtime_probe",
    target: "app.example.com",
    scopePath,
    execute: true,
    confirm: "app.example.com",
    workdir: dir,
    now: NOW,
  }, {
    resolveBinary: () => null,
    spawnWithLimits: async (...args) => { spawnCalls.push(args); throw new Error("should not spawn"); },
  });
  assert.equal(result.exitCode, 1);
  assert.ok(result.output.rejectedBy.includes("G-EXEC-01"));
  assert.equal(spawnCalls.length, 0, "missing binary must not spawn");
});

test("guard executes an allowlisted recipe and writes hashed evidence only", () => {
  const dir = tempDir("guard-execute");
  const scopePath = writeScope(dir);
  const workdir = join(dir, "work");
  const result = run(["guard", "--recipe", "runtime_probe", "--target", "app.example.com", "--scope", scopePath, "--execute", "--confirm", "app.example.com", "--workdir", workdir, "--now", NOW.toISOString()]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const output = json(result);
  assert.equal(output.ok, true);
  assert.equal(output.dryRun, false);
  assert.equal(output.exitCode, 0);
  assert.match(output.stdoutSha256, /^[0-9a-f]{64}$/);
  const records = parseEvidence(workdir);
  assert.equal(records.length, 1);
  const record = records[0];
  assert.equal(record.recipe, "runtime_probe");
  assert.equal(record.target, "app.example.com");
  assert.deepEqual(record.argv, ["--version"]);
  assert.match(record.ts, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(record.exitCode, 0);
  assert.match(record.stdoutSha256, /^[0-9a-f]{64}$/);
  assert.equal(record.stdout, undefined);
  assert.equal(record.stdoutText, undefined);
  assert.equal(record.stderr, undefined);
});

test("spawnWithLimits enforces a hard timeout and output cap", async () => {
  const timeLimited = await spawnWithLimits(process.execPath, ["-e", "setTimeout(() => {}, 5000)"], { timeoutMs: 300, outputLimitBytes: 1048576 });
  assert.equal(timeLimited.timedOut, true);
  assert.notEqual(timeLimited.exitCode, 0);

  const outputLimited = await spawnWithLimits(process.execPath, ["-e", "process.stdout.write('x'.repeat(200000))"], { timeoutMs: 10000, outputLimitBytes: 4096 });
  assert.equal(outputLimited.truncated, true);
  assert.ok(outputLimited.stdoutBytes <= 4096, "stdout must be capped, got " + outputLimited.stdoutBytes);
});

// ---------------------------------------------------------------------------
// Static safety checks
// ---------------------------------------------------------------------------

test("tool runtime imports only Node builtins and has no free command entry", () => {
  const files = ["sec.mjs", ...readdirLib()];
  for (const file of files) {
    const path = resolve(root, "tools", file);
    const source = readFileSync(path, "utf8");
    for (const match of source.matchAll(/^\s*import\s+[\s\S]*?from\s+["']([^"']+)["']/gm)) {
      const specifier = match[1];
      assert.ok(specifier.startsWith("node:") || specifier.startsWith("./"), file + ": unexpected import " + specifier);
    }
    assert.doesNotMatch(source, /\bexecSync\s*\(/, file + ": execSync is forbidden");
    assert.doesNotMatch(source, /\bexec\s*\(\s*["'`]/, file + ": command-string exec is forbidden");
    assert.doesNotMatch(source, /\/tmp\//, file + ": hard-coded /tmp path");
  }
  const cli = readFileSync(resolve(root, "tools", "lib", "cli.mjs"), "utf8");
  assert.ok(!/command\s*:\s*\{\s*type/.test(cli), "no free command option");
});

function readdirLib() {
  return ["lib/args.mjs", "lib/cli.mjs", "lib/common.mjs", "lib/evidence.mjs", "lib/gate.mjs", "lib/guard.mjs", "lib/ioc.mjs", "lib/lognorm.mjs", "lib/recipes.mjs", "lib/sarif.mjs", "lib/sigma.mjs"];
}
test("guard rejects normalized exclusions with G-TGT-04 before spawn", () => {
  const dir = tempDir("guard-exclusion");
  const scopePath = writeScope(dir, {
    targets: [{ kind: "url", value: "https://app.example.com/" }],
    exclusions: ["https://app.example.com:443/", "app.example.com."],
    mode: "active",
  }, "exclusion");
  const result = run(["guard", "--recipe", "http_headers", "--target", "https://app.example.com/", "--scope", scopePath, "--now", NOW.toISOString()]);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const output = json(result);
  assert.ok(output.rejectedBy.includes("G-TGT-04"), JSON.stringify(output.rejectedBy));
  assert.ok(!existsSync(join(dir, "guard-evidence.jsonl")));
});
