// Scope/authorization gate shared by `scope check` and `guard`.
// Mirrors policy/authorization.md and the workflow preflight logic, including the
// schema length/count limits (validateScopeLimits) enforced by all nine workflows;
// this module is deterministic and reads no files (callers pass parsed JSON).

export const MODE_RANK = { passive: 0, active: 1, exploit: 2, post: 3 };
export const TARGET_KINDS = ["domain", "url", "cidr", "ip", "host", "source"];
export const DATA_SOURCE_KINDS = [
  "siem", "edr", "logs", "pcap", "cloudtrail", "telemetry-export",
  "evidence", "findings", "detections", "baseline", "finding",
];
const SCOPE_KEYS = ["authorization", "targets", "exclusions", "mode", "window", "budget", "dataHandling", "dataSources", "notes"];
const AUTH_KEYS = ["type", "reference", "grantedBy", "validFrom", "validTo", "document"];
const AUTH_TYPES = ["written", "internal-mandate"];

export function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function isWindowsAbsolutePath(value) {
  const path = String(value ?? "");
  if (/^[A-Za-z]:[\\/]/.test(path)) return true;
  return /^\\\\[^\\/\s]+[\\/][^\\/\s]+/.test(path);
}

export function containsParentTraversal(value) {
  return String(value ?? "").includes("..");
}

function toUtcDay(year, month, day) {
  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return null;
  if (month < 1 || month > 12 || day < 1) return null;
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (day > daysInMonth) return null;
  return Date.UTC(year, month - 1, day);
}

export function parseYmd(value) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(value ?? ""));
  if (match === null) return null;
  return toUtcDay(Number(match[1]), Number(match[2]), Number(match[3]));
}

export function utcDayOf(date) {
  return Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate());
}

export function isValidRfc3339(value) {
  const text = String(value ?? "");
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(text)) return false;
  return Number.isFinite(Date.parse(text));
}

export function normalizeDomain(value) {
  const text = String(value ?? "").trim().toLowerCase().replace(/\.+$/, "");
  if (text === "" || /[\s/\\\u0000-\u001f]/.test(text)) return null;
  if (text.includes("*")) return null;
  if (!/^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$/.test(text)) return null;
  return text;
}

export function normalizeIpv4(value) {
  const parts = String(value ?? "").trim().split(".");
  if (parts.length !== 4) return null;
  const out = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const number = Number(part);
    if (number > 255) return null;
    out.push(String(number));
  }
  return out.join(".");
}

export function normalizeIpv6(value) {
  const text = String(value ?? "").trim().toLowerCase();
  if (text === "" || text.includes("%") || !/^[0-9a-f:]+$/.test(text)) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] === "" ? [] : halves[0].split(":");
  const right = halves.length === 2 ? (halves[1] === "" ? [] : halves[1].split(":")) : [];
  if (left.some((g) => g === "" || g.length > 4) || right.some((g) => g === "" || g.length > 4)) return null;
  const total = left.length + right.length;
  if (halves.length === 2) {
    if (total > 7) return null;
  } else if (total !== 8) return null;
  const groups = left.concat(Array(8 - total).fill("0"), right);
  const values = groups.map((g) => parseInt(g, 16));
  if (values.length !== 8 || values.some((n) => !Number.isFinite(n) || n < 0 || n > 65535)) return null;
  const hex = values.map((n) => n.toString(16));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8; i++) {
    if (hex[i] !== "0") continue;
    let j = i;
    while (j < 8 && hex[j] === "0") j++;
    if (j - i > bestLen) { bestLen = j - i; bestStart = i; }
    i = j;
  }
  if (bestLen >= 2) return hex.slice(0, bestStart).join(":") + "::" + hex.slice(bestStart + bestLen).join(":");
  return hex.join(":");
}

export function normalizeUrl(value) {
  const text = String(value ?? "").trim();
  const match = /^(https?):\/\/([^/?#]*)([^?#]*)(\?[^#]*)?(?:#.*)?$/i.exec(text);
  if (match === null) return null;
  const scheme = match[1].toLowerCase();
  const authority = match[2];
  if (authority === "" || authority.includes("@")) return null;
  let host = "";
  let port = "";
  if (authority.startsWith("[")) {
    const v6 = /^\[([0-9a-f:]+)\](?::(\d{1,5}))?$/i.exec(authority);
    if (v6 === null) return null;
    host = normalizeIpv6(v6[1]);
    port = v6[2] || "";
  } else {
    const withPort = /^([^:]+)(?::(\d{1,5}))?$/.exec(authority);
    if (withPort === null) return null;
    host = normalizeIpv4(withPort[1]) || normalizeDomain(withPort[1]);
    port = withPort[2] || "";
  }
  if (host === null || host === "" || host === "0.0.0.0" || host === "::") return null;
  if (port !== "") {
    const p = Number(port);
    if (!Number.isInteger(p) || p < 1 || p > 65535) return null;
    if ((scheme === "http" && p === 80) || (scheme === "https" && p === 443)) port = "";
  }
  const path = match[3] === "" ? "/" : match[3];
  if (!path.startsWith("/")) return null;
  const query = match[4] || "";
  const hostPart = host.includes(":") ? "[" + host + "]" : host;
  return scheme + "://" + hostPart + (port === "" ? "" : ":" + port) + path + query;
}

export function normalizeTarget(kind, value) {
  const k = String(kind ?? "");
  const raw = String(value ?? "").trim();
  if (!TARGET_KINDS.includes(k) || raw.length < 3 || raw.length > 2048) return null;
  let normalized = null;
  if (k === "domain" || k === "host") normalized = normalizeDomain(raw);
  else if (k === "url") normalized = normalizeUrl(raw);
  else if (k === "ip") normalized = normalizeIpv4(raw) || normalizeIpv6(raw);
  else if (k === "cidr") {
    const parts = raw.split("/");
    if (parts.length === 2) {
      const base = normalizeIpv4(parts[0]) || normalizeIpv6(parts[0]);
      const bits = Number(parts[1]);
      const max = base !== null && base.includes(":") ? 128 : 32;
      if (base !== null && Number.isInteger(bits) && bits >= 0 && bits <= max) normalized = base + "/" + bits;
    }
  } else if (k === "source") {
    const source = raw.replace(/\\/g, "/").replace(/\/+$/, "");
    if (isWindowsAbsolutePath(source) && !containsParentTraversal(source)) normalized = source;
  }
  if (normalized === null || normalized.includes("*")) return null;
  return { kind: k, value: normalized };
}

export function targetKey(target) {
  return String(target && target.kind ? target.kind : "").toLowerCase() + ":" + String(target && target.value ? target.value : "").toLowerCase();
}

export function isWildcardTarget(target) {
  const kind = String(target && target.kind ? target.kind : "");
  const value = String(target && target.value ? target.value : "").trim().toLowerCase();
  if (value.includes("*")) return true;
  if (kind === "cidr") {
    const parts = value.split("/");
    if (parts.length !== 2) return true;
    const base = normalizeIpv4(parts[0]) || normalizeIpv6(parts[0]);
    const bits = Number(parts[1]);
    if (base === null || !Number.isInteger(bits)) return true;
    if (base === "0.0.0.0" || base === "::") return true;
    const isV6 = base.includes(":");
    const max = isV6 ? 128 : 32;
    const min = isV6 ? 32 : 8;
    return bits < min || bits > max;
  }
  const ip4 = normalizeIpv4(value);
  if (ip4 === "0.0.0.0") return true;
  if (value.includes(":")) return normalizeIpv6(value) === "::";
  return false;
}

function urlHostOf(value) {
  const match = /^(https?):\/\/(?:\[([^\]]+)\]|([^/:]+))(?::\d+)?(?:\/|$)/.exec(String(value ?? ""));
  if (match === null) return null;
  return (match[2] || match[3] || "").toLowerCase();
}

export function exclusionHits(target, exclusions) {
  const targetKind = String(target && target.kind ? target.kind : "");
  const targetValue = String(target && target.value ? target.value : "").toLowerCase();
  const targetHost = targetKind === "url" ? urlHostOf(targetValue) : (targetKind === "domain" || targetKind === "host" ? normalizeDomain(targetValue) : null);
  for (const raw of exclusions) {
    const text = String(raw ?? "").trim();
    if (text === "") continue;
    let normalized = null;
    let exclusionKind = "";
    if (/^https?:\/\//i.test(text)) {
      normalized = normalizeUrl(text);
      exclusionKind = "url";
    } else if (text.includes("/")) {
      const parts = text.split("/");
      const base = normalizeIpv4(parts[0]) || normalizeIpv6(parts[0]);
      const bits = Number(parts[1]);
      const max = base !== null && base.includes(":") ? 128 : 32;
      if (base !== null && Number.isInteger(bits) && bits >= 0 && bits <= max) {
        normalized = base + "/" + bits;
        exclusionKind = "cidr";
      }
    } else if (normalizeIpv4(text) !== null) {
      normalized = normalizeIpv4(text);
      exclusionKind = "ip";
    } else if (text.includes(":")) {
      normalized = normalizeIpv6(text);
      exclusionKind = "ip";
    } else {
      normalized = normalizeDomain(text);
      exclusionKind = "domain";
    }
    if (normalized === null) continue;
    if (targetValue === normalized.toLowerCase()) return true;
    if (exclusionKind === "url") {
      const host = urlHostOf(normalized);
      if (host === null) continue;
      if (targetKind === "url" && targetValue === normalized) return true;
      if ((targetKind === "domain" || targetKind === "host") && (targetValue === host || targetValue.endsWith("." + host))) return true;
    } else if (exclusionKind === "domain") {
      if ((targetKind === "domain" || targetKind === "host") && (targetValue === normalized || targetValue.endsWith("." + normalized))) return true;
      if (targetKind === "url" && targetHost !== null && (targetHost === normalized || targetHost.endsWith("." + normalized))) return true;
    } else if (exclusionKind === "ip" || exclusionKind === "cidr") {
      if (targetValue === normalized) return true;
    }
  }
  return false;
}

export function normalizeScope(raw) {
  const source = isPlainObject(raw) ? raw : {};
  const scope = {
    authorization: {
      type: typeof source.authorization === "object" && source.authorization ? String(source.authorization.type ?? "") : "",
      reference: String((source.authorization && source.authorization.reference) || "").trim(),
      grantedBy: String((source.authorization && source.authorization.grantedBy) || "").trim(),
      validFrom: String((source.authorization && source.authorization.validFrom) || ""),
      validTo: String((source.authorization && source.authorization.validTo) || ""),
    },
    targets: [],
    exclusions: Array.isArray(source.exclusions) ? source.exclusions.map((item) => String(item).trim()).filter(Boolean) : [],
    mode: String(source.mode ?? ""),
    window: {
      start: String((source.window && source.window.start) || ""),
      end: String((source.window && source.window.end) || ""),
    },
    budget: {
      maxRequests: source.budget && source.budget.maxRequests,
      maxMinutes: source.budget && source.budget.maxMinutes,
    },
    dataHandling: {
      retain: String((source.dataHandling && source.dataHandling.retain) || ""),
      secrets: String((source.dataHandling && source.dataHandling.secrets) || ""),
      destruction: String((source.dataHandling && source.dataHandling.destruction) || ""),
    },
    dataSources: [],
  };
  if (source.authorization && typeof source.authorization.document === "string" && source.authorization.document !== "") {
    scope.authorization.document = source.authorization.document;
  }
  for (const item of Array.isArray(source.targets) ? source.targets : []) {
    if (!isPlainObject(item)) continue;
    const target = normalizeTarget(item.kind, item.value);
    if (target === null) continue;
    if (typeof item.label === "string" && item.label !== "") target.label = item.label;
    scope.targets.push(target);
  }
  for (const item of Array.isArray(source.dataSources) ? source.dataSources : []) {
    if (!isPlainObject(item)) continue;
    const dataSource = { kind: String(item.kind ?? ""), value: String(item.value ?? "") };
    if (typeof item.label === "string" && item.label !== "") dataSource.label = item.label;
    if (typeof item.version === "string" && item.version !== "") dataSource.version = item.version;
    if (typeof item.lastVerified === "string" && item.lastVerified !== "") dataSource.lastVerified = item.lastVerified;
    scope.dataSources.push(dataSource);
  }
  if (typeof source.notes === "string" && source.notes !== "") scope.notes = source.notes;
  return scope;
}

/**
 * Validate a scope object against policy/authorization.md.
 * Returns { ok, rejectedBy, errors, warnings, normalized, mode }.
 * `now` may be overridden for deterministic tests.
 */
function validateScopeLimits(rawScope, reject) {
  const limit = (value, min, max, label) => {
    if (value === undefined || value === null) return;
    if (typeof value !== "string") { reject("G-CONF-01", label + " 必须是字符串"); return; }
    const length = [...value].length;
    if (length < min || length > max) reject("G-CONF-01", label + " 长度必须是 " + min + "–" + max);
  };
  const auth = isPlainObject(rawScope.authorization) ? rawScope.authorization : {};
  limit(auth.reference, 3, 200, "authorization.reference");
  limit(auth.grantedBy, 2, 200, "authorization.grantedBy");
  limit(auth.document, 1, 500, "authorization.document");
  if (rawScope.notes !== undefined) limit(rawScope.notes, 0, 2000, "scope.notes");
  if (Array.isArray(rawScope.targets)) {
    if (rawScope.targets.length > 200) reject("G-CONF-01", "targets 最多 200 项");
    for (const item of rawScope.targets) {
      if (!isPlainObject(item)) continue;
      limit(item.label, 0, 120, "target.label");
    }
  }
  if (Array.isArray(rawScope.exclusions)) {
    if (rawScope.exclusions.length > 200) reject("G-CONF-01", "exclusions 最多 200 项");
    for (const item of rawScope.exclusions) {
      if (typeof item === "string") limit(item, 3, 512, "exclusion");
    }
  }
  if (Array.isArray(rawScope.dataSources)) {
    if (rawScope.dataSources.length > 64) reject("G-CONF-01", "dataSources 最多 64 项");
    for (const item of rawScope.dataSources) {
      if (!isPlainObject(item)) continue;
      limit(item.value, 3, 2048, "dataSource.value");
      limit(item.label, 0, 120, "dataSource.label");
      limit(item.version, 0, 120, "dataSource.version");
    }
  }
}

export function checkScope(raw, options = {}) {
  const now = options.now instanceof Date && !Number.isNaN(options.now.getTime()) ? options.now : new Date();
  const requireTargets = options.requireTargets !== false;
  const rejectedBy = [];
  const errors = [];
  const warnings = [];
  const reject = (code, message) => {
    if (!rejectedBy.includes(code)) rejectedBy.push(code);
    errors.push({ code, message });
  };

  if (!isPlainObject(raw)) {
    reject("G-CONF-01", "scope 必须是对象");
    return { ok: false, rejectedBy, errors, warnings, normalized: normalizeScope({}), mode: "" };
  }
  // 与 9 个 workflow 的 preflight 完全相同的 limits（G-CONF-01），保证
  // `scope check` / `guard` 与 workflow 两套入口不会对同一 scope 给出不同结论。
  validateScopeLimits(raw, reject);
  for (const key of Object.keys(raw)) {
    if (!SCOPE_KEYS.includes(key)) reject("G-CONF-01", "scope 含未声明字段: " + key);
  }

  const auth = isPlainObject(raw.authorization) ? raw.authorization : null;
  if (auth === null) reject("G-AUTH-01", "authorization 缺失或不是对象");
  else {
    for (const key of Object.keys(auth)) {
      if (!AUTH_KEYS.includes(key)) reject("G-CONF-01", "authorization 含未声明字段: " + key);
    }
    if (typeof auth.reference !== "string" || auth.reference.trim() === "") reject("G-AUTH-01", "authorization.reference 为空");
    if (!AUTH_TYPES.includes(auth.type)) reject("G-AUTH-02", "authorization.type 必须是 written 或 internal-mandate");
    if (typeof auth.grantedBy !== "string" || auth.grantedBy.trim() === "") reject("G-AUTH-04", "authorization.grantedBy 为空");
    const from = parseYmd(auth.validFrom);
    const to = parseYmd(auth.validTo);
    if (from === null || to === null) reject("G-AUTH-05", "validFrom/validTo 必须是 YYYY-MM-DD 真实日期");
    else if (to < from) reject("G-AUTH-05", "validTo 早于 validFrom");
    const today = utcDayOf(now);
    if (from !== null && today < from) reject("G-AUTH-06", "授权尚未生效");
    if (to !== null && today > to) reject("G-AUTH-07", "授权已过期");
  }

  const targets = [];
  if (!Array.isArray(raw.targets)) reject("G-TGT-01", "targets 必须是数组");
  else {
    if (requireTargets && raw.targets.length === 0) reject("G-TGT-01", "targets 不得为空");
    for (const item of raw.targets) {
      if (!isPlainObject(item) || !TARGET_KINDS.includes(item.kind) || typeof item.value !== "string") {
        reject("G-TGT-03", "target 必须是 {kind,value} 且 kind 合法");
        continue;
      }
      for (const key of Object.keys(item)) {
        if (!["kind", "value", "label"].includes(key)) reject("G-CONF-01", "target 含未声明字段: " + key);
      }
      if (String(item.value).includes("*")) {
        reject("G-TGT-02", "禁止通配目标: " + String(item.value).slice(0, 80));
        continue;
      }
      const target = normalizeTarget(item.kind, item.value);
      if (target === null) {
        reject("G-TGT-03", "target 值非法: " + String(item.value).slice(0, 120));
        continue;
      }
      if (target.kind === "source" && !isWindowsAbsolutePath(item.value)) {
        reject("G-PATH-03", "source target 必须是 Windows 绝对路径");
        continue;
      }
      if (isWildcardTarget(target)) {
        reject("G-TGT-02", "禁止通配/全网目标: " + target.value);
        continue;
      }
      if (Array.isArray(raw.exclusions) && exclusionHits(target, raw.exclusions)) {
        reject("G-TGT-04", "target 命中 exclusions: " + target.value);
      }
      targets.push(target);
    }
  }

  const mode = String(raw.mode ?? "");
  if (!Object.prototype.hasOwnProperty.call(MODE_RANK, mode)) reject("G-MODE-01", "mode 非法: " + mode);

  const window = isPlainObject(raw.window) ? raw.window : null;
  if (window === null || !isValidRfc3339(window.start) || !isValidRfc3339(window.end)) {
    reject("G-WIN-01", "window.start/end 必须是 RFC 3339");
  } else if (Date.parse(window.end) <= Date.parse(window.start)) {
    reject("G-WIN-02", "window.end 必须晚于 start");
  } else {
    for (const key of Object.keys(window)) {
      if (!["start", "end"].includes(key)) reject("G-CONF-01", "window 含未声明字段: " + key);
    }
    const time = now.getTime();
    if (time < Date.parse(window.start) || time >= Date.parse(window.end)) reject("G-WIN-03", "当前时刻不在 window 内");
  }

  const budget = isPlainObject(raw.budget) ? raw.budget : null;
  if (budget === null) reject("G-BUD-01", "budget 缺失");
  else {
    for (const key of Object.keys(budget)) {
      if (!["maxRequests", "maxMinutes"].includes(key)) reject("G-CONF-01", "budget 含未声明字段: " + key);
    }
    if (!Number.isInteger(budget.maxRequests) || budget.maxRequests < 1 || budget.maxRequests > 100000) reject("G-BUD-01", "budget.maxRequests 必须是 1–100000 的整数");
    if (!Number.isInteger(budget.maxMinutes) || budget.maxMinutes < 1 || budget.maxMinutes > 1440) reject("G-BUD-01", "budget.maxMinutes 必须是 1–1440 的整数");
  }

  const handling = isPlainObject(raw.dataHandling) ? raw.dataHandling : null;
  if (handling === null) {
    reject("G-DH-01", "dataHandling.retain 非法");
    reject("G-DH-02", "dataHandling.secrets 必须为 mask-and-redact");
    reject("G-DH-03", "dataHandling.destruction 必须为 none");
  } else {
    for (const key of Object.keys(handling)) {
      if (!["retain", "secrets", "destruction"].includes(key)) reject("G-CONF-01", "dataHandling 含未声明字段: " + key);
    }
    if (!["findings-only", "none", "full"].includes(handling.retain)) reject("G-DH-01", "dataHandling.retain 非法");
    if (handling.secrets !== "mask-and-redact") reject("G-DH-02", "dataHandling.secrets 必须为 mask-and-redact");
    if (handling.destruction !== "none") reject("G-DH-03", "dataHandling.destruction 必须为 none");
  }

  if (raw.dataSources !== undefined) {
    if (!Array.isArray(raw.dataSources)) reject("G-CONF-01", "dataSources 必须是数组");
    else {
      for (const item of raw.dataSources) {
        if (!isPlainObject(item) || !DATA_SOURCE_KINDS.includes(item.kind) || typeof item.value !== "string") {
          reject("G-CONF-01", "dataSources 项必须是 {kind,value} 且 kind 合法");
          continue;
        }
        for (const key of Object.keys(item)) {
          if (!["kind", "value", "label", "version", "lastVerified"].includes(key)) reject("G-CONF-01", "dataSources 项含未声明字段: " + key);
        }
        if (!isWindowsAbsolutePath(item.value) || containsParentTraversal(item.value)) {
          reject("G-PATH-03", "dataSources.value 必须是 Windows 绝对路径且不含 ..");
        }
      }
    }
  }

  const normalized = normalizeScope(raw);
  normalized.dataSources = Array.isArray(normalized.dataSources) ? normalized.dataSources : [];
  return { ok: errors.length === 0, rejectedBy, errors, warnings, normalized, mode };
}
