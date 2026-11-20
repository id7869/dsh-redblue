import test, { after } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const lint = resolve(root, "tools", "sanitize-lint.mjs");
const fixtures = resolve(here, "fixtures");
const cwd = root;

function run(args) {
  return spawnSync(process.execPath, [lint, ...args], { cwd, encoding: "utf8" });
}

function parseJson(result) {
  try {
    return JSON.parse(result.stdout);
  } catch {
    assert.fail(`lint did not print JSON: ${result.stdout}\n${result.stderr}`);
  }
}

const CASES = [
  { dir: "bad-r1", id: "R1-PROVENANCE" },
  { dir: "bad-r2", id: "R2-RESERVED" },
  { dir: "bad-r3", id: "R3-WEAPON" },
  { dir: "bad-r4", id: "R4-VERIFY-DISABLED" },
  { dir: "bad-r5", id: "R5-FAKE" },
  { dir: "bad-r6", id: "R6-SKILL-SIZE" },
  { dir: "bad-r7", id: "R7-JACCARD" },
  { dir: "bad-r8", id: "R8-SKILL" },
  { dir: "bad-r9", id: "R9-LAST-VERIFIED" },
  { dir: "bad-r10", id: "R10-PII" },
  { dir: "bad-r11", id: "R11-TERMINOLOGY" },
  { dir: "bad-r12", id: "R12-RISK" },
];

test("good fixture passes --strict with no blockers or warnings", () => {
  const result = run(["--strict", "--json", resolve(fixtures, "good")]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const output = parseJson(result);
  assert.equal(output.version, "dsh-redblue-sanitize/v1");
  assert.equal(output.policy, "R1-R12/v1");
  assert.equal(output.summary.blockers, 0);
  assert.equal(output.summary.warnings, 0);
  assert.equal(output.summary.checkedFiles, 3);
  assert.deepEqual(output.checks, []);
});

for (const entry of CASES) {
  test(`${entry.dir} triggers ${entry.id}`, () => {
    const result = run(["--json", resolve(fixtures, entry.dir)]);
    assert.equal(result.status, 0, `non-strict lint should not fail: ${result.stderr}`);
    const output = parseJson(result);
    const match = output.checks.find((check) => check.id === entry.id);
    assert.ok(match, `${entry.dir} did not trigger ${entry.id}: ${JSON.stringify(output.checks)}`);
    assert.equal(match.rule, entry.id.slice(0, entry.id.indexOf("-")));
    assert.equal(match.status, "fail");
    assert.ok(match.line >= 1, "finding must carry a 1-based line number");
    assert.ok(match.file.endsWith(".md") || match.file.endsWith(".js"), `unexpected file: ${match.file}`);
  });
}

test("blockers fail only under --strict; warnings never block", () => {
  const strictBlocker = run(["--strict", "--json", resolve(fixtures, "bad-r2")]);
  assert.equal(strictBlocker.status, 1);
  assert.ok(parseJson(strictBlocker).summary.blockers >= 1);

  const strictWarning = run(["--strict", "--json", resolve(fixtures, "bad-r11")]);
  assert.equal(strictWarning.status, 0);
  const output = parseJson(strictWarning);
  assert.equal(output.summary.blockers, 0);
  assert.ok(output.summary.warnings >= 1);
});

test("--list-checks prints the 36-check registry", () => {
  const result = run(["--list-checks"]);
  assert.equal(result.status, 0);
  const lines = result.stdout.trim().split(/\r?\n/);
  assert.equal(lines.length, 36);
  const ids = lines.map((line) => line.split("\t")[0]);
  for (const id of ["R1-PROVENANCE", "R2-RESERVED", "R3-WEAPON", "R4-DRYRUN-DEFAULT", "R7-JACCARD", "R8-WORKFLOW", "R10-PII", "R12-RISK"]) {
    assert.ok(ids.includes(id), `missing check ${id}`);
  }
  assert.ok(lines.every((line) => /^R\d{1,2}-[A-Z0-9-]+\tR\d{1,2}\t(blocker|warning)\t/.test(line)), "unexpected registry line format");
});

test("--check runs only the selected check IDs", () => {
  const result = run(["--check", "R2-RESERVED", "--json", resolve(fixtures, "bad-r2")]);
  assert.equal(result.status, 0, result.stderr);
  const output = parseJson(result);
  assert.ok(output.checks.length >= 1);
  assert.ok(output.checks.every((check) => check.id === "R2-RESERVED"));
});

test("unknown --check ID is a usage error (exit 2)", () => {
  const result = run(["--check", "R99-NOPE", "--json", resolve(fixtures, "good")]);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /未知检查 ID/);
});

test("text output carries rule ID, file:line and summary", () => {
  const result = run([resolve(fixtures, "bad-r2")]);
  assert.equal(result.status, 0);
  assert.match(result.stdout, /\[blocker\] R2-RESERVED .*:\d+/);
  assert.match(result.stdout, /summary: files=\d+ blockers=\d+ warnings=\d+/);
});

test("explicit fixture paths are scanned even though the default root walk skips test/fixtures", () => {
  const result = run(["--strict", "--json", resolve(fixtures, "bad-r7")]);
  assert.equal(result.status, 1);
  const output = parseJson(result);
  assert.ok(output.summary.checkedFiles >= 2);
});

test("default path scans the plugin root without usage errors", () => {
  const result = run(["--json"]);
  assert.notEqual(result.status, 2, result.stderr);
  const output = parseJson(result);
  assert.ok(output.summary.checkedFiles >= 1);
});

const tempFiles = [];
function tempDir(name) {
  const dir = mkdtempSync(join(tmpdir(), "dsh-redblue-lint-" + name + "-"));
  tempFiles.push(dir);
  return dir;
}
after(() => {
  for (const dir of tempFiles) rmSync(dir, { recursive: true, force: true });
});

test("candidate extensions cover yml/txt/svg package assets", () => {
  const dir = tempDir("ext");
  writeFileSync(join(dir, "evil.yml"), "target: https://evil.com/x\nhost: evil.com\n", "utf8");
  writeFileSync(join(dir, "evil.txt"), "connect evil.com\n", "utf8");
  const result = run(["--strict", "--json", dir]);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const output = parseJson(result);
  assert.equal(output.summary.checkedFiles, 2);
  assert.ok(output.checks.some((f) => f.id === "R2-DENYLIST" && f.file.endsWith("evil.yml")), "evil.yml must be scanned");
  assert.ok(output.checks.some((f) => f.id === "R2-DENYLIST" && f.file.endsWith("evil.txt")), "evil.txt must be scanned");

  const svg = run(["--strict", "--json", "--check", "R2-RESERVED,R2-DENYLIST", resolve(root, "icon.svg")]);
  assert.equal(svg.status, 0, svg.stdout + svg.stderr);
  assert.equal(parseJson(svg).summary.checkedFiles, 1);
});

test("sigma.yml is scanned and clean for R2/R10", () => {
  const sigma = resolve(root, "references", "blue", "templates", "sigma.yml");
  const result = run(["--strict", "--json", "--check", "R1-PROVENANCE,R2-RESERVED,R2-DENYLIST,R10-SECRET,R10-PII", sigma]);
  assert.equal(result.status, 0, result.stdout + result.stderr);
  const output = parseJson(result);
  assert.equal(output.summary.checkedFiles, 1);
  assert.equal(output.summary.blockers, 0);
});

test("empty directory fails unless --allow-empty is explicit", () => {
  const dir = tempDir("empty");
  const failed = run(["--strict", "--json", dir]);
  assert.equal(failed.status, 2, failed.stdout + failed.stderr);
  assert.match(failed.stderr, /allow-empty/);
  const allowed = run(["--strict", "--json", "--allow-empty", dir]);
  assert.equal(allowed.status, 0, allowed.stdout + allowed.stderr);
  assert.equal(parseJson(allowed).summary.checkedFiles, 0);
});

test("R1-PROVENANCE rejects a missing source-path when dev snapshots exist", { skip: !existsSync(resolve(root, "..", ".work", "sources")) }, () => {
  const dir = tempDir("prov");
  mkdirSync(join(dir, "references"));
  writeFileSync(join(dir, "references", "bad.md"), [
    "<!-- dsh-redblue:provenance",
    "source-repo: https://github.com/SnailSploit/Claude-Red",
    "source-commit: 6196ba7464662de34e8744d359f175d1a7bca530",
    "source-license: MIT",
    "source-path: no/such/file.md",
    "last-verified: 2026-11-19",
    "rewrite-summary: test",
    "-->",
    "",
    "# bad",
    "",
  ].join("\n"), "utf8");
  const result = run(["--strict", "--json", "--check", "R1-PROVENANCE", join(dir, "references")]);
  assert.equal(result.status, 1, result.stdout + result.stderr);
  const output = parseJson(result);
  assert.ok(output.checks.some((f) => f.id === "R1-PROVENANCE" && /source-path/.test(f.message)), JSON.stringify(output.checks));
});
