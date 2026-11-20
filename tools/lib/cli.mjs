// CLI dispatcher for `node tools/sec.mjs`. All command results are JSON on
// stdout; exit codes: 0 success, 1 rejection/operational failure, 2 usage.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { UsageError, parseIsoOption, parseOptions, requireOption } from "./args.mjs";
import { writeJsonFile, writeTextFile } from "./common.mjs";
import { hashDirectory, verifyManifest } from "./evidence.mjs";
import { runGuard } from "./guard.mjs";
import { extractIocs } from "./ioc.mjs";
import { normalizeLogText, toJsonl } from "./lognorm.mjs";
import { findRecipe, listRecipeSummaries } from "./recipes.mjs";
import { convertFindingsToSarif } from "./sarif.mjs";
import { lintSigma } from "./sigma.mjs";
import { checkScope } from "./gate.mjs";

export const USAGE = `dsh-redblue tool runtime (zero-dependency)

usage:
  node tools/sec.mjs --help
  node tools/sec.mjs scope check --scope <scope.json> [--now <ISO-8601>]
  node tools/sec.mjs evidence hash --dir <workdir> --out <manifest.json>
  node tools/sec.mjs evidence verify --manifest <manifest.json> --dir <workdir>
  node tools/sec.mjs sarif convert --findings <findings.json> --out <results.sarif>
  node tools/sec.mjs ioc extract --input <file> [--defang|--no-defang]
  node tools/sec.mjs log normalize --input <file> --format jsonl|csv|syslog --out <out.jsonl>
  node tools/sec.mjs rule lint --file <sigma.yml>
  node tools/sec.mjs recipes list
  node tools/sec.mjs recipes show <recipe-id>
  node tools/sec.mjs guard --recipe <id> --target <target> --scope <scope.json> [--execute --confirm <target>] [--workdir <dir>] [--now <ISO-8601>]

security:
  - offline commands never access the network;
  - guard only runs recipes from tools/recipes.json, via an argv array and
    spawn(shell=false); default is dry-run; --execute additionally requires a
    written scope, matching mode, target in scope.targets, exact --confirm and
    an available binary;
  - recipe output is capped and only hashes are written to evidence JSONL.
`;

function print(value) {
  process.stdout.write(JSON.stringify(value, null, 2) + "\n");
}

function ok(exitCode, output) {
  return { exitCode, output };
}

function readText(path) {
  return readFileSync(path, "utf8");
}

function commandScope(argv) {
  const spec = { scope: { type: "string", hint: "scope JSON 路径" }, now: { type: "string", hint: "ISO-8601" } };
  const { options, positionals } = parseOptions(argv, spec);
  if (options.help) return ok(0, { usage: USAGE.split("\n").filter((line) => line.includes("scope ")).join("\n") });
  if (positionals[0] !== "check") throw new UsageError("scope 子命令只支持 check");
  const scopePath = requireOption(options, "scope", spec);
  let document;
  try {
    document = JSON.parse(readText(scopePath));
  } catch (error) {
    return ok(1, { ok: false, rejectedBy: [], errors: [{ code: "G-CONF-01", message: "scope 文件不可读或不是合法 JSON: " + error.message }], normalized: null });
  }
  const now = parseIsoOption(options, "now");
  const result = checkScope(document, { now: now || new Date() });
  return ok(result.ok ? 0 : 1, {
    ok: result.ok,
    rejectedBy: result.rejectedBy,
    errors: result.errors,
    warnings: result.warnings,
    mode: result.mode,
    normalized: result.normalized,
  });
}

function commandEvidence(argv) {
  const action = argv[0];
  if (action === "hash") {
    const spec = { dir: { type: "string" }, out: { type: "string" } };
    const { options } = parseOptions(argv.slice(1), spec);
    const directory = resolve(requireOption(options, "dir", spec));
    const out = resolve(requireOption(options, "out", spec));
    const manifest = hashDirectory(directory, { exclude: [out] });
    writeJsonFile(out, manifest);
    const bytes = manifest.files.reduce((sum, file) => sum + file.bytes, 0);
    return ok(0, { ok: true, out, files: manifest.files.length, bytes, schemaVersion: manifest.schemaVersion });
  }
  if (action === "verify") {
    const spec = { manifest: { type: "string" }, dir: { type: "string" } };
    const { options } = parseOptions(argv.slice(1), spec);
    const manifestPath = resolve(requireOption(options, "manifest", spec));
    const directory = resolve(requireOption(options, "dir", spec));
    const result = verifyManifest(manifestPath, directory);
    return ok(result.ok ? 0 : 1, Object.assign({ manifest: manifestPath, dir: directory }, result));
  }
  throw new UsageError("evidence 子命令只支持 hash / verify");
}

function commandSarif(argv) {
  if (argv[0] !== "convert") throw new UsageError("sarif 子命令只支持 convert");
  const spec = { findings: { type: "string" }, out: { type: "string" } };
  const { options } = parseOptions(argv.slice(1), spec);
  const findingsPath = resolve(requireOption(options, "findings", spec));
  const out = resolve(requireOption(options, "out", spec));
  const document = JSON.parse(readText(findingsPath));
  const sarif = convertFindingsToSarif(document);
  writeJsonFile(out, sarif);
  return ok(0, { ok: true, out, results: sarif.runs[0].results.length, rules: sarif.runs[0].tool.driver.rules.length });
}

function commandIoc(argv) {
  if (argv[0] !== "extract") throw new UsageError("ioc 子命令只支持 extract");
  const spec = { input: { type: "string" }, defang: { type: "boolean" }, "no-defang": { type: "boolean" } };
  const { options } = parseOptions(argv.slice(1), spec);
  const input = resolve(requireOption(options, "input", spec));
  const defang = options["no-defang"] === true ? false : true;
  const result = extractIocs(readText(input), { defang });
  return ok(0, Object.assign({ ok: true, input }, result));
}

function commandLog(argv) {
  if (argv[0] !== "normalize") throw new UsageError("log 子命令只支持 normalize");
  const spec = { input: { type: "string" }, format: { type: "string" }, out: { type: "string" } };
  const { options } = parseOptions(argv.slice(1), spec);
  const input = resolve(requireOption(options, "input", spec));
  const out = resolve(requireOption(options, "out", spec));
  const format = requireOption(options, "format", spec);
  if (!["jsonl", "csv", "syslog"].includes(format)) throw new UsageError("--format 必须是 jsonl/csv/syslog");
  const result = normalizeLogText(readText(input), format);
  writeTextFile(out, toJsonl(result.records));
  return ok(0, {
    ok: true,
    input,
    out,
    format,
    total: result.total,
    normalized: result.records.length,
    badLines: result.badLines,
  });
}

function commandRule(argv) {
  if (argv[0] !== "lint") throw new UsageError("rule 子命令只支持 lint");
  const spec = { file: { type: "string" } };
  const { options } = parseOptions(argv.slice(1), spec);
  const file = resolve(requireOption(options, "file", spec));
  const result = lintSigma(readText(file));
  return ok(result.ok ? 0 : 1, { ok: result.ok, file, keys: result.keys, issues: result.issues, warnings: result.warnings });
}

function commandRecipes(argv) {
  const action = argv[0];
  if (action === "list") {
    const summary = listRecipeSummaries();
    return ok(0, { ok: true, ...summary });
  }
  if (action === "show") {
    const recipeId = argv[1];
    if (recipeId === undefined || recipeId === "") throw new UsageError("recipes show 需要 <recipe-id>");
    const recipe = findRecipe(recipeId);
    if (recipe === null) return ok(1, { ok: false, error: "配方不存在: " + recipeId, rejectedBy: ["G-EXEC-01"] });
    return ok(0, { ok: true, recipe });
  }
  throw new UsageError("recipes 子命令只支持 list / show");
}

async function commandGuard(argv) {
  const spec = {
    recipe: { type: "string" },
    target: { type: "string" },
    scope: { type: "string" },
    execute: { type: "boolean" },
    confirm: { type: "string" },
    workdir: { type: "string" },
    now: { type: "string" },
  };
  const { options } = parseOptions(argv, spec);
  const recipe = requireOption(options, "recipe", spec);
  const target = requireOption(options, "target", spec);
  const scope = requireOption(options, "scope", spec);
  const result = await runGuard({
    recipeId: recipe,
    target,
    scopePath: resolve(scope),
    execute: options.execute === true,
    confirm: options.confirm,
    workdir: options.workdir === undefined ? process.cwd() : resolve(options.workdir),
    now: parseIsoOption(options, "now"),
  });
  return ok(result.exitCode, result.output);
}

export async function runCli(argv) {
  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    process.stdout.write(USAGE);
    return 0;
  }
  const [group, ...rest] = argv;
  try {
    let result;
    if (group === "scope") result = commandScope(rest);
    else if (group === "evidence") result = commandEvidence(rest);
    else if (group === "sarif") result = commandSarif(rest);
    else if (group === "ioc") result = commandIoc(rest);
    else if (group === "log") result = commandLog(rest);
    else if (group === "rule") result = commandRule(rest);
    else if (group === "recipes") result = commandRecipes(rest);
    else if (group === "guard") result = await commandGuard(rest);
    else throw new UsageError("未知子命令: " + group);
    print(result.output);
    return result.exitCode;
  } catch (error) {
    if (error instanceof UsageError) {
      print({ ok: false, error: error.message, usage: USAGE });
      return 2;
    }
    print({ ok: false, error: error && error.message ? error.message : String(error) });
    return 1;
  }
}