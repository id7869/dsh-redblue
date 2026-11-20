// SHA256 evidence manifests for a work directory.

import { readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileInfo, nowIso, readJsonFile, toPosix, walkFiles, writeJsonFile } from "./common.mjs";

export const EVIDENCE_SCHEMA = "dsh-redblue-evidence/v1";

/**
 * Build a SHA256 manifest for every regular file below `directory`.
 * `exclude` contains absolute paths that must not be hashed (e.g. the output
 * manifest itself). Results are sorted by POSIX relative path.
 */
export function hashDirectory(directory, options = {}) {
  const exclude = new Set((options.exclude || []).map((item) => join(item)));
  const files = [];
  for (const absolute of walkFiles(directory)) {
    if (exclude.has(absolute)) continue;
    const info = fileInfo(absolute);
    files.push({
      path: toPosix(relative(directory, absolute)),
      bytes: info.bytes,
      sha256: info.sha256,
    });
  }
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return {
    schemaVersion: EVIDENCE_SCHEMA,
    generatedAt: nowIso(),
    directory: toPosix(directory),
    files,
  };
}

export function writeManifest(manifestPath, manifest) {
  writeJsonFile(manifestPath, manifest);
}

/**
 * Recompute every file listed in the manifest. Extra files below `directory`
 * are reported but do not fail verification; missing or mismatched files fail.
 */
export function verifyManifest(manifestPath, directory) {
  const manifest = readJsonFile(manifestPath);
  if (!manifest || !Array.isArray(manifest.files)) return { ok: false, error: "manifest 缺少 files[]", checked: 0, missing: [], mismatched: [], extra: [] };
  const listed = new Set();
  const missing = [];
  const mismatched = [];
  let checked = 0;
  for (const entry of manifest.files) {
    if (!entry || typeof entry.path !== "string") continue;
    listed.add(entry.path);
    const absolute = join(directory, entry.path);
    let stat;
    try {
      stat = statSync(absolute);
    } catch {
      missing.push(entry.path);
      continue;
    }
    if (!stat.isFile()) {
      missing.push(entry.path);
      continue;
    }
    checked++;
    const info = fileInfo(absolute);
    if (info.bytes !== entry.bytes || info.sha256 !== entry.sha256) {
      mismatched.push({ path: entry.path, expected: entry.sha256, actual: info.sha256 });
    }
  }
  const extra = [];
  const manifestRelative = toPosix(relative(directory, resolve(manifestPath)));
  for (const absolute of walkFiles(directory)) {
    const path = toPosix(relative(directory, absolute));
    if (!listed.has(path) && path !== manifestRelative) extra.push(path);
  }
  return {
    ok: missing.length === 0 && mismatched.length === 0,
    checked,
    missing,
    mismatched,
    extra,
  };
}

export function readManifest(path) {
  return readJsonFile(path);
}

export function readFileText(path) {
  return readFileSync(path, "utf8");
}