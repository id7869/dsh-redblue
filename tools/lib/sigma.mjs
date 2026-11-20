// Structural lint for Sigma rules without a YAML dependency.
// Checks title / id / status / detection / logsource / level and basic nesting.

const STATUSES = ["stable", "test", "experimental", "deprecated", "unsupported"];
const LEVELS = ["informational", "low", "medium", "high", "critical"];

function stripQuotes(value) {
  const text = String(value ?? "").trim();
  if (text.length >= 2 && ((text[0] === '"' && text[text.length - 1] === '"') || (text[0] === "'" && text[text.length - 1] === "'"))) {
    return text.slice(1, -1);
  }
  return text;
}

function indentation(line) {
  const match = /^(\s*)/.exec(line);
  return match ? match[1].replace(/\t/g, "  ").length : 0;
}

/**
 * Parse top-level YAML keys plus direct child keys. Values are kept as trimmed
 * scalar text; nested block contents are not fully parsed (that is the point:
 * this is a structural lint, not a YAML implementation).
 */
function parseSkeleton(lines) {
  const top = new Map();
  let current = null;
  let childIndent = null;
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (line.trim() === "" || line.trim().startsWith("#")) continue;
    const indent = indentation(line);
    const keyMatch = /^([A-Za-z_][A-Za-z0-9_-]*):\s*(.*)$/.exec(line.trim());
    if (indent === 0 && keyMatch !== null) {
      current = { key: keyMatch[1], value: stripQuotes(keyMatch[2]), line: index + 1, children: [] };
      top.set(current.key, current);
      childIndent = null;
      continue;
    }
    if (current !== null && indent > 0 && keyMatch !== null && (childIndent === null || indent >= childIndent)) {
      if (childIndent === null) childIndent = indent;
      if (indent === childIndent) current.children.push({ key: keyMatch[1], value: stripQuotes(keyMatch[2]), line: index + 1 });
    }
  }
  return top;
}

export function lintSigma(text) {
  const lines = String(text).split(/\r\n|\r|\n/);
  const top = parseSkeleton(lines);
  const issues = [];
  const warnings = [];
  const issue = (code, message, line) => issues.push({ code, message, line });
  const warn = (code, message, line) => warnings.push({ code, message, line });

  const title = top.get("title");
  if (title === undefined || title.value === "") issue("missing-title", "缺少非空 title", title ? title.line : 1);
  const id = top.get("id");
  if (id === undefined || id.value === "") issue("missing-id", "缺少非空 id", id ? id.line : 1);
  else if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id.value)) warn("id-format", "id 建议使用 UUID 形式", id.line);

  const status = top.get("status");
  if (status === undefined || status.value === "") issue("missing-status", "缺少非空 status", status ? status.line : 1);
  else if (!STATUSES.includes(status.value)) issue("invalid-status", "status 必须是 " + STATUSES.join("/"), status.line);

  const level = top.get("level");
  if (level === undefined || level.value === "") issue("missing-level", "缺少非空 level", level ? level.line : 1);
  else if (!LEVELS.includes(level.value)) issue("invalid-level", "level 必须是 " + LEVELS.join("/"), level.line);

  const detection = top.get("detection");
  if (detection === undefined) issue("missing-detection", "缺少 detection 块", 1);
  else {
    if (detection.value !== "") issue("bad-detection", "detection 必须是块（不能是标量）", detection.line);
    const childKeys = detection.children.map((child) => child.key);
    if (!childKeys.includes("condition")) issue("missing-condition", "detection 缺少 condition", detection.line);
    const selectionKeys = childKeys.filter((key) => key !== "condition" && key !== "timeframe");
    if (selectionKeys.length === 0) issue("missing-selection", "detection 缺少 selection/filter 子键", detection.line);
  }

  const logsource = top.get("logsource");
  if (logsource === undefined) issue("missing-logsource", "缺少 logsource 块", 1);
  else {
    if (logsource.value !== "") issue("bad-logsource", "logsource 必须是块（不能是标量）", logsource.line);
    const childKeys = logsource.children.map((child) => child.key);
    if (!["product", "category", "service"].some((key) => childKeys.includes(key))) {
      issue("missing-logsource-key", "logsource 至少需要 product/category/service 之一", logsource.line);
    }
  }

  for (const [key, entry] of top.entries()) {
    if (typeof entry.value === "string" && /^[&*]/.test(entry.value)) {
      warn("yaml-anchor", `顶层 ${key} 使用了 YAML 锚点/别名，结构检查可能不完整`, entry.line);
    }
  }

  return {
    ok: issues.length === 0,
    keys: [...top.keys()],
    issues,
    warnings,
  };
}