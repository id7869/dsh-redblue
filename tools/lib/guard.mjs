// Whitelisted, authorization-gated command execution for dsh-redblue.
// Only recipes from tools/recipes.json can run. argv is passed directly to
// spawn with shell=false; there is no user-supplied command string.

import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { appendFileSync, readFileSync, statSync } from "node:fs";
import { delimiter, isAbsolute, join } from "node:path";

import { ensureDir, isPlainObject, nowIso } from "./common.mjs";
import {
  MODE_RANK,
  checkScope,
  exclusionHits,
  normalizeDomain,
  normalizeIpv4,
  normalizeIpv6,
  normalizeTarget,
} from "./gate.mjs";
import { findRecipe, loadRecipes } from "./recipes.mjs";

export const DEFAULT_TIMEOUT_MS = 120000;
export const DEFAULT_OUTPUT_LIMIT_BYTES = 1048576;
export const EVIDENCE_FILE = "guard-evidence.jsonl";

const FORBIDDEN_TARGET = /[;&|`$<>\u0000-\u001f]/;
const FORBIDDEN_SOURCE_TARGET = /[;&|`$<>\u0000-\u001f]/;

function fail(code, message, extra = {}) {
  return { exitCode: 1, output: Object.assign({ ok: false, rejectedBy: [code], errors: [{ code, message }] }, extra) };
}

export function resolveBinary(binary) {
  const name = String(binary ?? "");
  if (name === "") return null;
  const base = name.toLowerCase();
  if (base === "node" || base === "node.exe") return process.execPath;
  const absolute = isAbsolute(name) || /^[A-Za-z]:[\\/]/.test(name) || /^\\\\/.test(name);
  const candidates = [];
  if (absolute) {
    candidates.push(name);
  } else {
    const dirs = String(process.env.PATH || process.env.Path || "").split(delimiter).filter(Boolean);
    const extensions = process.platform === "win32"
      ? [...new Set((process.env.PATHEXT || ".COM;.EXE;.BAT;.CMD").split(";").filter(Boolean).flatMap((ext) => [ext, ext.toLowerCase()]))]
      : [""];
    const set = new Set();
    for (const dir of dirs) for (const extension of extensions) set.add(join(dir, name + extension));
    candidates.push(...set);
  }
  for (const candidate of candidates) {
    try {
      if (statSync(candidate).isFile()) return candidate;
    } catch {
      // keep looking
    }
  }
  return null;
}

export function normalizeGuardTarget(kind, value) {
  if (kind === "host") {
    const domain = normalizeDomain(value);
    if (domain !== null) return { kind: "host", value: domain };
    const ipv4 = normalizeIpv4(value);
    if (ipv4 !== null) return { kind: "ip", value: ipv4 };
    const ipv6 = normalizeIpv6(value);
    if (ipv6 !== null) return { kind: "ip", value: ipv6 };
    return null;
  }
  return normalizeTarget(kind, value);
}

function validateTarget(recipe, target, scope, rejectedBy, errors) {
  const raw = String(target ?? "");
  const reject = (code, message) => {
    if (!rejectedBy.includes(code)) rejectedBy.push(code);
    errors.push({ code, message });
  };
  if (raw.trim() === "" || raw.length < 3 || raw.length > 2048) {
    reject("G-TGT-03", "target 长度必须是 3–2048");
    return null;
  }
  if (raw.startsWith("-")) {
    reject("G-TGT-03", "target 不得以 - 开头（防止被目标程序当作选项）");
    return null;
  }
  if (recipe.targetKind === "source") {
    if (FORBIDDEN_SOURCE_TARGET.test(raw)) reject("G-TGT-03", "source target 含 shell 元字符/控制字符");
    if (!/^[A-Za-z]:[\\/]/.test(raw) && !/^\\\\/.test(raw)) reject("G-PATH-03", "source target 必须是 Windows 绝对路径");
    if (raw.includes("..")) reject("G-PATH-03", "source target 不得含 ..");
  } else {
    if (FORBIDDEN_TARGET.test(raw)) reject("G-TGT-03", "target 含 shell 元字符/控制字符");
    if (/\s/.test(raw)) reject("G-TGT-03", "target 不得含空白");
  }
  const normalized = normalizeGuardTarget(recipe.targetKind, raw);
  if (normalized === null) {
    reject("G-TGT-03", "target 与配方 targetKind 不匹配: " + recipe.targetKind);
    return null;
  }
  const allowed = Array.isArray(scope.targets) && scope.targets.some((candidate) => {
    const candidateNormalized = normalizeTarget(candidate.kind, candidate.value);
    return candidateNormalized !== null && candidateNormalized.value === normalized.value;
  });
  if (!allowed) {
    reject("G-TGT-04", "target 不在 scope.targets allowlist: " + normalized.value);
  }
  if (Array.isArray(scope.exclusions) && exclusionHits(normalized, scope.exclusions)) {
    reject("G-TGT-04", "target 命中 scope.exclusions: " + normalized.value);
  }
  return normalized;
}

export function buildArgv(recipe, target) {
  const argv = recipe.argv.map((item) => item.split("{target}").join(target));
  for (const item of argv) {
    if (/\{[^}]*\}/.test(item)) throw new Error("recipe argv 含未解析占位符: " + item);
  }
  return argv;
}

export function spawnWithLimits(binary, argv, options = {}) {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const outputLimitBytes = options.outputLimitBytes ?? DEFAULT_OUTPUT_LIMIT_BYTES;
  return new Promise((resolve) => {
    const startedAt = Date.now();
    const stdoutChunks = [];
    const stderrChunks = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let totalBytes = 0;
    let timedOut = false;
    let truncated = false;
    let settled = false;
    let timer = null;

    const finish = (exitCode, signal, spawnError) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      const stdout = Buffer.concat(stdoutChunks);
      const stderr = Buffer.concat(stderrChunks);
      resolve({
        spawnError: spawnError || null,
        exitCode: exitCode === undefined ? null : exitCode,
        signal: signal || null,
        timedOut,
        truncated,
        durationMs: Date.now() - startedAt,
        stdoutBytes,
        stderrBytes,
        stdoutSha256: createHash("sha256").update(stdout).digest("hex"),
        stderrSha256: createHash("sha256").update(stderr).digest("hex"),
      });
    };

    let child;
    try {
      child = spawn(binary, argv, {
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
        cwd: options.cwd,
      });
    } catch (error) {
      resolve({
        spawnError: error && error.message ? error.message : String(error),
        exitCode: null,
        signal: null,
        timedOut: false,
        truncated: false,
        durationMs: Date.now() - startedAt,
        stdoutBytes: 0,
        stderrBytes: 0,
        stdoutSha256: createHash("sha256").update("").digest("hex"),
        stderrSha256: createHash("sha256").update("").digest("hex"),
      });
      return;
    }

    const kill = () => {
      try {
        child.kill("SIGKILL");
      } catch {
        // ignore; close/error will settle the promise
      }
    };

    timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, timeoutMs);

    const collect = (stream) => (chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = outputLimitBytes - totalBytes;
      if (remaining <= 0) {
        truncated = true;
        kill();
        return;
      }
      const accepted = buffer.length > remaining ? buffer.subarray(0, remaining) : buffer;
      if (stream === "stdout") {
        stdoutChunks.push(accepted);
        stdoutBytes += accepted.length;
      } else {
        stderrChunks.push(accepted);
        stderrBytes += accepted.length;
      }
      totalBytes += accepted.length;
      if (buffer.length > remaining || totalBytes >= outputLimitBytes) {
        truncated = true;
        kill();
      }
    };

    child.stdout.on("data", collect("stdout"));
    child.stderr.on("data", collect("stderr"));
    child.on("error", (error) => finish(null, null, error && error.message ? error.message : String(error)));
    child.on("close", (code, signal) => finish(code, signal, null));
  });
}

function appendEvidence(workdir, record) {
  ensureDir(workdir);
  const evidencePath = join(workdir, EVIDENCE_FILE);
  appendFileSync(evidencePath, JSON.stringify(record) + "\n", "utf8");
  return evidencePath;
}

function rejectAll(rejectedBy, errors, extra) {
  return { exitCode: 1, output: Object.assign({ ok: false, rejectedBy, errors }, extra) };
}
/**
 * Run guard. `dependencies` is injectable for tests:
 * { spawnWithLimits, resolveBinary, recipesFile }.
 */
export async function runGuard(options, dependencies = {}) {
  const spawnImpl = dependencies.spawnWithLimits || spawnWithLimits;
  const resolveImpl = dependencies.resolveBinary || resolveBinary;
  const now = options.now instanceof Date && !Number.isNaN(options.now.getTime()) ? options.now : new Date();
  const execute = options.execute === true;
  let loaded;
  try {
    loaded = loadRecipes(dependencies.recipesFile);
  } catch (error) {
    return fail("G-CONF-01", "recipes.json 不可读或非法: " + (error && error.message ? error.message : String(error)));
  }
  const recipe = findRecipe(options.recipeId, dependencies.recipesFile);
  if (recipe === null) {
    return fail("G-EXEC-01", "配方不在白名单中: " + String(options.recipeId ?? ""));
  }

  let scopeDocument;
  try {
    scopeDocument = JSON.parse(readFileSync(String(options.scopePath ?? ""), "utf8"));
  } catch (error) {
    return {
      exitCode: execute ? 1 : 0,
      output: {
        ok: false,
        rejectedBy: ["G-AUTH-01"],
        errors: [{ code: "G-AUTH-01", message: "scope 文件不可读或不是合法 JSON: " + (error && error.message ? error.message : String(error)) }],
        dryRun: !execute,
        recipe: recipe.id,
        target: String(options.target ?? ""),
      },
    };
  }

  const check = checkScope(scopeDocument, { now, requireTargets: true });
  const rejectedBy = check.rejectedBy.slice();
  const errors = check.errors.slice();
  const reject = (code, message) => {
    if (!rejectedBy.includes(code)) rejectedBy.push(code);
    errors.push({ code, message });
  };

  if (check.normalized.authorization.type !== "written") {
    reject("G-AUTH-03", "guard 执行需要 written 授权（internal-mandate 不能执行命令）");
  }

  const target = String(options.target ?? "").trim();
  const normalizedTarget = validateTarget(recipe, target, check.normalized, rejectedBy, errors);

  if (Object.prototype.hasOwnProperty.call(MODE_RANK, check.normalized.mode) && MODE_RANK[check.normalized.mode] < MODE_RANK[recipe.requiredMode]) {
    reject("G-MODE-02", `scope.mode=${check.normalized.mode} 低于配方要求 ${recipe.requiredMode}`);
  }

  let argv = null;
  if (normalizedTarget !== null) {
    try {
      argv = buildArgv(recipe, target);
    } catch (error) {
      reject("G-CONF-01", error && error.message ? error.message : String(error));
    }
  }

  if (rejectedBy.length > 0) {
    return {
      exitCode: 1,
      output: {
        ok: false,
        rejectedBy,
        errors,
        dryRun: !execute,
        recipe: recipe.id,
        target,
        normalized: check.normalized,
        recipeMeta: { lane: recipe.lane, requiredMode: recipe.requiredMode },
      },
    };
  }

  const basePlan = {
    ok: true,
    dryRun: !execute,
    recipe: recipe.id,
    lane: recipe.lane,
    target,
    targetKind: recipe.targetKind,
    normalizedTarget,
    argv,
    requiredMode: recipe.requiredMode,
    mode: check.normalized.mode,
    authorizationReference: check.normalized.authorization.reference,
    timeoutMs: recipe.timeoutMs,
    outputLimitBytes: recipe.outputLimitBytes,
    binary: recipe.binary,
  };

  if (!execute) {
    return {
      exitCode: 0,
      output: Object.assign({}, basePlan, {
        binaryAvailable: resolveImpl(recipe.binary) !== null,
        note: "dry-run：只输出执行计划，不启动任何进程",
      }),
    };
  }

  if (typeof options.confirm !== "string" || options.confirm === "") {
    return rejectAll(["G-CFM-01"], [{ code: "G-CFM-01", message: "--execute 必须提供 --confirm <target>" }], { dryRun: false, recipe: recipe.id, target });
  }
  if (options.confirm !== target) {
    return rejectAll(["G-CFM-02"], [{ code: "G-CFM-02", message: "--confirm 必须与 --target 完全相等" }], { dryRun: false, recipe: recipe.id, target });
  }

  const binaryPath = resolveImpl(recipe.binary);
  if (binaryPath === null) {
    return rejectAll(["G-EXEC-01"], [{ code: "G-EXEC-01", message: "目标二进制不存在: " + recipe.binary }], { dryRun: false, recipe: recipe.id, target, binary: recipe.binary });
  }

  const workdir = options.workdir || process.cwd();
  ensureDir(workdir);
  const result = await spawnImpl(binaryPath, argv, {
    timeoutMs: recipe.timeoutMs,
    outputLimitBytes: recipe.outputLimitBytes,
    cwd: workdir,
  });

  const evidence = {
    schemaVersion: "dsh-redblue-guard/v1",
    ts: nowIso(),
    recipe: recipe.id,
    lane: recipe.lane,
    target,
    argv,
    binary: recipe.binary,
    binaryPath,
    mode: check.normalized.mode,
    requiredMode: recipe.requiredMode,
    authorizationReference: check.normalized.authorization.reference,
    exitCode: result.exitCode,
    signal: result.signal,
    timedOut: result.timedOut,
    truncated: result.truncated,
    durationMs: result.durationMs,
    stdoutBytes: result.stdoutBytes,
    stderrBytes: result.stderrBytes,
    stdoutSha256: result.stdoutSha256,
    stderrSha256: result.stderrSha256,
    spawnError: result.spawnError,
  };
  let evidencePath;
  try {
    evidencePath = appendEvidence(workdir, evidence);
  } catch (error) {
    return rejectAll(["G-EXEC-01"], [{ code: "G-EXEC-01", message: "无法写入 evidence JSONL: " + (error && error.message ? error.message : String(error)) }], {
      dryRun: false,
      recipe: recipe.id,
      target,
      spawnResult: {
        exitCode: result.exitCode,
        timedOut: result.timedOut,
        truncated: result.truncated,
      },
    });
  }

  const ok = result.spawnError === null && result.exitCode === 0 && result.timedOut === false && result.truncated === false;
  return {
    exitCode: ok ? 0 : 1,
    output: Object.assign({}, basePlan, {
      ok,
      dryRun: false,
      binaryPath,
      exitCode: result.exitCode,
      signal: result.signal,
      timedOut: result.timedOut,
      truncated: result.truncated,
      durationMs: result.durationMs,
      stdoutBytes: result.stdoutBytes,
      stderrBytes: result.stderrBytes,
      stdoutSha256: result.stdoutSha256,
      stderrSha256: result.stderrSha256,
      spawnError: result.spawnError,
      evidencePath,
    }),
  };
}