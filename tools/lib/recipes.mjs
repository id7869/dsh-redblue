// Load and validate the whitelisted command recipes. Recipes are the only
// commands guard can execute; there is no user-supplied command path.

import { readJsonFile } from "./common.mjs";
import { MODE_RANK } from "./gate.mjs";
import { fileURLToPath } from "node:url";

const RECIPES_FILE = fileURLToPath(new URL("../recipes.json", import.meta.url));
const SHELL_BINARIES = new Set(["sh", "bash", "zsh", "ksh", "csh", "dash", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe"]);
const INTERPRETER_BINARIES = new Set(["node", "node.exe", "python", "python.exe", "python3", "python3.exe", "perl", "ruby", "php"]);
const TARGET_KINDS = ["domain", "url", "host", "ip", "cidr", "source"];
const FORBIDDEN_ARGV = /[;&|`$<>\u0000-\u001f]/;
const PLACEHOLDER = /\{[^}]*\}/g;

function fail(message) {
  throw new Error("recipes.json 校验失败: " + message);
}

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function validateRecipe(raw, index) {
  if (!isPlainObject(raw)) fail(`#${index} 必须是对象`);
  const id = String(raw.id ?? "");
  if (!/^[a-z][a-z0-9_]{2,40}$/.test(id)) fail(`#${index} id 非法: ${id}`);
  const lane = String(raw.lane ?? "");
  if (!["recon", "discover", "exploit", "post", "blue", "purple"].includes(lane)) fail(`${id} lane 非法: ${lane}`);
  const binary = String(raw.binary ?? "");
  if (binary === "" || binary.length > 260) fail(`${id} binary 非法`);
  const binaryBase = binary.toLowerCase().split(/[\\/]/).pop();
  if (SHELL_BINARIES.has(binaryBase)) fail(`${id} 禁止使用 shell 作为 binary: ${binary}`);
  if (!Array.isArray(raw.argv) || raw.argv.length === 0 || raw.argv.length > 32) fail(`${id} argv 必须是 1–32 个字符串`);
  const argv = raw.argv.map((item) => String(item));
  for (const item of argv) {
    if (item.length > 512) fail(`${id} argv 元素过长`);
    if (FORBIDDEN_ARGV.test(item)) fail(`${id} argv 元素含 shell 元字符/控制字符: ${item}`);
    for (const match of item.matchAll(PLACEHOLDER)) {
      if (match[0] !== "{target}") fail(`${id} 含未知占位符: ${match[0]}`);
    }
  }
  if (INTERPRETER_BINARIES.has(binaryBase)) {
    const safe = (binaryBase === "node" || binaryBase === "node.exe") && argv.length === 1 && ["--version", "-v"].includes(argv[0]);
    if (!safe) fail(`${id} 解释器 binary 只允许固定安全 argv（node --version/-v）`);
  }
  const targetKind = String(raw.targetKind ?? "");
  if (!TARGET_KINDS.includes(targetKind)) fail(`${id} targetKind 非法: ${targetKind}`);
  const requiredMode = String(raw.requiredMode ?? "");
  if (!Object.prototype.hasOwnProperty.call(MODE_RANK, requiredMode)) fail(`${id} requiredMode 非法: ${requiredMode}`);
  const timeoutMs = raw.timeoutMs === undefined ? 120000 : Number(raw.timeoutMs);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 600000) fail(`${id} timeoutMs 必须是 1000–600000 的整数`);
  const outputLimitBytes = raw.outputLimitBytes === undefined ? 1048576 : Number(raw.outputLimitBytes);
  if (!Number.isInteger(outputLimitBytes) || outputLimitBytes < 1024 || outputLimitBytes > 10485760) fail(`${id} outputLimitBytes 必须是 1024–10485760 的整数`);
  const notes = String(raw.notes ?? "");
  if (notes.length > 500) fail(`${id} notes 过长`);
  return { id, lane, binary, argv, targetKind, requiredMode, timeoutMs, outputLimitBytes, notes };
}

export function loadRecipes(filePath) {
  const document = readJsonFile(filePath || RECIPES_FILE);
  if (!isPlainObject(document) || !Array.isArray(document.recipes)) fail("顶层必须是 { recipes: [...] }");
  if (document.recipes.length < 8) fail(`至少需要 8 个配方，实际 ${document.recipes.length}`);
  const recipes = document.recipes.map(validateRecipe);
  const ids = new Set();
  for (const recipe of recipes) {
    if (ids.has(recipe.id)) fail(`配方 id 重复: ${recipe.id}`);
    ids.add(recipe.id);
  }
  return { schemaVersion: String(document.schemaVersion ?? "dsh-redblue-recipes/v1"), recipes };
}

export function findRecipe(recipeId, filePath) {
  const { recipes } = loadRecipes(filePath);
  return recipes.find((recipe) => recipe.id === recipeId) || null;
}

export function listRecipeSummaries(filePath) {
  const { schemaVersion, recipes } = loadRecipes(filePath);
  return {
    schemaVersion,
    count: recipes.length,
    recipes: recipes.map((recipe) => ({
      id: recipe.id,
      lane: recipe.lane,
      binary: recipe.binary,
      targetKind: recipe.targetKind,
      requiredMode: recipe.requiredMode,
      timeoutMs: recipe.timeoutMs,
      outputLimitBytes: recipe.outputLimitBytes,
      notes: recipe.notes,
    })),
  };
}