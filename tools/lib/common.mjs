// dsh-redblue tool runtime — shared helpers (zero third-party dependencies).

import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

export const PLUGIN_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const TOOLS_ROOT = fileURLToPath(new URL("../", import.meta.url));

export function toPosix(value) {
  return String(value).split(sep).join("/");
}

export function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}

export function sha256File(absolutePath) {
  return sha256Hex(readFileSync(absolutePath));
}

export function readJsonFile(absolutePath) {
  return JSON.parse(readFileSync(absolutePath, "utf8"));
}

export function writeTextFile(absolutePath, content) {
  mkdirSync(dirname(absolutePath), { recursive: true });
  writeFileSync(absolutePath, content, "utf8");
}

export function writeJsonFile(absolutePath, value) {
  writeTextFile(absolutePath, JSON.stringify(value, null, 2) + "\n");
}

export function ensureDir(absolutePath) {
  mkdirSync(absolutePath, { recursive: true });
}

export function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function nowIso() {
  return new Date().toISOString();
}

export function clampInt(value, fallback, min, max) {
  const number = Number(value);
  if (!Number.isInteger(number)) return fallback;
  return Math.max(min, Math.min(max, number));
}

export function relativePosix(root, absolutePath) {
  return toPosix(relative(root, absolutePath));
}

// Walk regular files only; symlinks are skipped (evidence must not follow
// links outside the selected directory).
export function walkFiles(root, options = {}) {
  const skipNames = new Set(options.skipNames || []);
  const out = [];
  const visit = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      if (skipNames.has(entry.name)) continue;
      const absolute = join(dir, entry.name);
      let stat;
      try {
        stat = lstatSync(absolute);
      } catch {
        continue;
      }
      if (stat.isSymbolicLink()) continue;
      if (stat.isDirectory()) visit(absolute);
      else if (stat.isFile()) out.push(absolute);
    }
  };
  if (existsSync(root) && statSync(root).isDirectory()) visit(root);
  return out;
}

export function fileInfo(absolutePath) {
  const stat = statSync(absolutePath);
  return { bytes: stat.size, sha256: sha256File(absolutePath) };
}

export function safeBasename(absolutePath) {
  return basename(absolutePath);
}

export function resolveFromCwd(value) {
  return resolve(process.cwd(), String(value));
}
