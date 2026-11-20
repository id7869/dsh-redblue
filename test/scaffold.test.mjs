import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { apply, inject, name } from "../lib/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");

const EXPECTED = [
  { name: "dsh-rb-run", dir: "run" },
  { name: "dsh-red-scope", dir: "red-scope" },
  { name: "dsh-red-recon", dir: "red-recon" },
  { name: "dsh-red-surface", dir: "red-surface" },
  { name: "dsh-red-discover", dir: "red-discover" },
  { name: "dsh-red-validate", dir: "red-validate" },
  { name: "dsh-red-exploit", dir: "red-exploit" },
  { name: "dsh-red-post", dir: "red-post" },
  { name: "dsh-rb-report", dir: "rb-report" },
  { name: "dsh-blue-hunt", dir: "blue-hunt" },
  { name: "dsh-blue-detect", dir: "detect" },
  { name: "dsh-blue-dfir", dir: "dfir" },
  { name: "dsh-blue-harden", dir: "harden" },
  { name: "dsh-purple-verify", dir: "purple-verify" },
  { name: "dsh-rb-triage", dir: "rb-triage" },
];

function registerProvider() {
  const captured = [];
  apply({ skills: { registerProvider(factory) { captured.push(factory); } } });
  assert.equal(captured.length, 1, "apply() must register exactly one provider");
  return captured[0]({ signal: new AbortController().signal, invalidate() {} });
}

test("plugin exports name/inject/apply with the skills dependency", () => {
  assert.equal(name, "dsh-redblue");
  assert.deepEqual(inject, ["skills"]);
  assert.equal(typeof apply, "function");
});

test("provider lists the 15 design skills with rank 600 and bundled metadata", async () => {
  const provider = registerProvider();
  assert.equal(provider.name, "dsh-redblue");
  const list = await provider.list({});
  assert.equal(list.length, 15);
  assert.deepEqual(list.map((s) => s.name), EXPECTED.map((s) => s.name));
  for (const [index, skill] of list.entries()) {
    const expected = EXPECTED[index];
    assert.equal(skill.name, expected.name);
    assert.equal(skill.provider, "dsh-redblue");
    assert.equal(skill.source, "bundled");
    assert.equal(skill.rank, 600);
    assert.deepEqual(skill.invocation, { modelInvocable: true, userInvocable: true });
    assert.equal(skill.resourceBase.kind, "directory");
    assert.ok(
      skill.resourceBase.path.replace(/\\/g, "/").endsWith(`skills/${expected.dir}/`),
      `resourceBase must point at skills/${expected.dir}/, got ${skill.resourceBase.path}`,
    );
  }
});

test("fallback descriptions are non-empty, <=500 code points, and keep trigger/negative sections", async () => {
  const provider = registerProvider();
  const list = await provider.list({});
  for (const skill of list) {
    assert.ok(skill.description.length > 0, `${skill.name} description must not be empty`);
    assert.ok([...skill.description].length <= 500, `${skill.name} description exceeds 500 code points`);
    assert.match(skill.description, /触发词：/, `${skill.name} description lacks 触发词：`);
    assert.match(skill.description, /不适用：/, `${skill.name} description lacks 不适用：`);
  }
  const rbRun = list.find((s) => s.name === "dsh-rb-run");
  assert.match(rbRun.description, /9 个授权门禁工作流/);
});

test("get() returns each skill by name and a body from SKILL.md, and undefined for unknown names", async () => {
  const provider = registerProvider();
  for (const expected of EXPECTED) {
    const definition = await provider.get({ name: expected.name, rank: 600, locator: null, description: "", invocation: {}, source: "bundled", provider: "dsh-redblue" });
    assert.equal(definition.name, expected.name);
    assert.equal(typeof definition.content, "string");
    assert.ok(definition.content.length > 0, `${expected.name} body must be loaded from SKILL.md`);
    assert.equal(definition.provider, "dsh-redblue");
  }
  assert.equal(await provider.get({ name: "dsh-does-not-exist" }), undefined);
});

test("lib/index.js has no static peer import and hard-codes BUNDLED_SKILL_RANK", () => {
  const source = readFileSync(resolve(root, "lib/index.js"), "utf8");
  const specifiers = [];
  for (const match of source.matchAll(/^\s*import\s+[\s\S]*?from\s+["']([^"']+)["']/gm)) specifiers.push(match[1]);
  assert.ok(specifiers.length >= 2, "expected the node:fs and node:url imports");
  for (const specifier of specifiers) {
    assert.ok(specifier.startsWith("node:"), `non-builtin static import: ${specifier}`);
  }
  assert.doesNotMatch(source, /^import[^;]*@deepseek-ai\//m);
  const importLines = source.split(/\r?\n/).filter((line) => /^\s*import\b/.test(line));
  assert.ok(importLines.every((line) => !line.includes("@deepseek-ai/")), "no static peer import is allowed");
  assert.match(source, /BUNDLED_SKILL_RANK = 600/);
});

test("package.json is a dependency-free Cordis bundle", () => {
  const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
  assert.equal(pkg.name, "dsh-redblue");
  assert.equal(pkg.version, "0.1.0");
  assert.equal(pkg.type, "module");
  assert.equal(pkg.main, "lib/index.js");
  assert.equal(pkg.types, "lib/index.d.ts");
  assert.equal(pkg.license, "Apache-2.0");
  assert.equal(pkg.dsh.bundle.patch, "./cordis.patch.yml");
  assert.equal(pkg.dependencies, undefined);
  assert.equal(pkg.devDependencies, undefined);
  assert.equal(pkg.icon, "icon.svg");
  assert.equal(pkg.exports["./icon"], "./icon.svg");
  for (const entry of ["lib", "skills", "references", "workflow", "schema", "policy", "tools", "cordis.patch.yml", "NOTICE", "LICENSE", "README.md", "icon.svg", "docs/DETAIL.md", "docs/preview.svg", "docs/tool-runtime.md", "docs/value-extraction.md", "docs/assembly-report.md"]) {
    assert.ok(pkg.files.includes(entry), `files whitelist missing ${entry}`);
    assert.ok(existsSync(resolve(root, entry)), `files whitelist entry does not exist: ${entry}`);
  }
  assert.ok(!pkg.files.includes("docs"), "internal docs must not be shipped wholesale");
  assert.ok(!pkg.files.includes("docs/research-handoff.md"), "research handoff must not ship");
});

test("cordis.patch.yml inserts id/name dsh-redblue", () => {
  const patch = readFileSync(resolve(root, "cordis.patch.yml"), "utf8");
  assert.match(patch, /^-\s*insert:/m);
  assert.match(patch, /id:\s*dsh-redblue/);
  assert.match(patch, /name:\s*'dsh-redblue'/);
});

test("schema files parse as draft-07 with design-aligned required fields", () => {
  const load = (file) => JSON.parse(readFileSync(resolve(root, "schema", file), "utf8"));
  const scope = load("scope.schema.json");
  assert.equal(scope.$schema, "http://json-schema.org/draft-07/schema#");
  assert.deepEqual(scope.required, ["authorization", "targets", "mode", "window", "budget", "dataHandling"]);
  assert.equal(scope.properties.mode.enum.join(","), "passive,active,exploit,post");
  assert.equal(scope.properties.dataHandling.properties.secrets.const, "mask-and-redact");
  assert.equal(scope.properties.dataHandling.properties.destruction.const, "none");

  const finding = load("finding.schema.json");
  assert.equal(finding.$schema, "http://json-schema.org/draft-07/schema#");
  for (const key of ["id", "fingerprint", "domain", "kind", "severity", "disposition", "confidence", "claim", "evidence"]) {
    assert.ok(finding.required.includes(key), `finding schema missing required ${key}`);
  }
  assert.equal(finding.properties.disposition.enum.join(","), "reportable,suppressed,not_applicable,deferred");

  const evidence = load("evidence.schema.json");
  assert.equal(evidence.$schema, "http://json-schema.org/draft-07/schema#");
  assert.equal(evidence.properties.kind.enum.join(","), "evidence-ref,intake-file,timeline-event");

  const report = load("report.schema.json");
  assert.equal(report.$schema, "http://json-schema.org/draft-07/schema#");
  assert.equal(report.properties.schemaVersion.const, "dsh-redblue-report/v1");
  assert.equal(report.properties.sections.minItems, 7);
});

function parseSkillFrontmatter(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (match === null) return null;
  const meta = {};
  for (const line of match[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/.exec(line);
    if (kv === null) continue;
    let value = kv[2].trim();
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value[value.length - 1] === value[0]) value = value.slice(1, -1);
    meta[kv[1]] = value;
  }
  return meta;
}

test("real skill directories and frontmatter match the lib constants", async () => {
  const skillRoot = resolve(root, "skills");
  const actualDirs = readdirSync(skillRoot, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  assert.deepEqual(actualDirs, EXPECTED.map((entry) => entry.dir).sort(), "skills/ must contain exactly the 15 design directories");

  const libSource = readFileSync(resolve(root, "lib/index.js"), "utf8");
  const constants = [...libSource.matchAll(/\{ name: "(dsh-[^"]+)", dir: "([^"]+)", description: "([^"]+)" \}/g)]
    .map((match) => ({ name: match[1], dir: match[2], description: match[3] }));
  assert.equal(constants.length, 15, "lib/index.js must declare exactly 15 SKILLS entries");

  const provider = registerProvider();
  const list = await provider.list({});

  for (const expected of EXPECTED) {
    const constant = constants.find((entry) => entry.name === expected.name);
    assert.ok(constant, `lib/index.js missing constant for ${expected.name}`);
    assert.equal(constant.dir, expected.dir, `${expected.name}: dir drift`);

    const skillPath = resolve(skillRoot, expected.dir, "SKILL.md");
    assert.ok(existsSync(skillPath), `missing real SKILL.md: ${expected.dir}/SKILL.md`);
    const text = readFileSync(skillPath, "utf8");
    const meta = parseSkillFrontmatter(text);
    assert.ok(meta !== null, `${expected.name}: frontmatter must be parseable`);
    assert.equal(meta.name, expected.name, `${expected.name}: frontmatter name drift`);
    assert.equal(meta.description, constant.description, `${expected.name}: frontmatter description drifted from lib fallback constant`);
    assert.ok([...meta.description].length <= 500, `${expected.name}: description exceeds 500 code points`);
    assert.ok(typeof meta.whenToUse === "string" && meta.whenToUse.trim() !== "", `${expected.name}: whenToUse missing`);
    assert.match(meta.description, /触发词：/, `${expected.name}: missing 触发词：`);
    assert.match(meta.description, /不适用：/, `${expected.name}: missing 不适用：`);
    assert.match(text, new RegExp("^# ", "m"), `${expected.name}: SKILL.md body needs a title`);

    const summary = list.find((entry) => entry.name === expected.name);
    assert.ok(summary, `${expected.name}: provider list missing`);
    assert.equal(summary.description, meta.description, `${expected.name}: provider must prefer SKILL.md frontmatter`);
    const definition = await provider.get({ name: expected.name, rank: 600, locator: null, description: "", invocation: {}, source: "bundled", provider: "dsh-redblue" });
    assert.equal(definition.description, meta.description, `${expected.name}: get() must prefer SKILL.md frontmatter`);
    assert.ok(definition.content.length > 0, `${expected.name}: get() body must not be empty`);
  }
});
