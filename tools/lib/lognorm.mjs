// Normalize local log exports (JSONL / CSV / syslog) into a common JSONL shape.
// Timestamp normalization is deterministic: all output timestamps are ISO-8601 UTC.

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
const TIMESTAMP_KEYS = ["ts", "timestamp", "time", "@timestamp", "datetime", "date", "_time"];
const HOST_KEYS = ["host", "hostname", "host_name", "computer", "device"];
const ACTOR_KEYS = ["user", "username", "actor", "principal", "account", "subject"];
const ACTION_KEYS = ["action", "event", "event_type", "operation", "activity"];
const OBJECT_KEYS = ["object", "target", "resource", "destination", "dst"];
const MESSAGE_KEYS = ["message", "msg", "description", "detail"];

function firstKey(record, keys) {
  for (const key of keys) {
    if (record[key] !== undefined && record[key] !== null && record[key] !== "") return record[key];
  }
  return undefined;
}

export function normalizeTimestamp(value, options = {}) {
  if (value === undefined || value === null || value === "") return null;
  if (typeof value === "number") {
    const ms = value > 1e12 ? value : value * 1000;
    const date = new Date(ms);
    return Number.isNaN(date.getTime()) ? null : date.toISOString();
  }
  const text = String(value).trim();
  if (/^\d{10,13}$/.test(text)) return normalizeTimestamp(Number(text));
  const rfc3164 = /^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})$/.exec(text);
  if (rfc3164 !== null) {
    let year = options.year ?? new Date().getUTCFullYear();
    const month = MONTHS[rfc3164[1]];
    if (month === undefined) return null;
    let date = new Date(Date.UTC(year, month, Number(rfc3164[2]), Number(rfc3164[3]), Number(rfc3164[4]), Number(rfc3164[5])));
    if (Number.isNaN(date.getTime())) return null;
    // Syslog without a year is read as the most recent occurrence.
    if (date.getTime() > Date.now() + 86400000) {
      year -= 1;
      date = new Date(Date.UTC(year, month, Number(rfc3164[2]), Number(rfc3164[3]), Number(rfc3164[4]), Number(rfc3164[5])));
    }
    return date.toISOString();
  }
  const parsed = Date.parse(text);
  if (!Number.isNaN(parsed)) return new Date(parsed).toISOString();
  return null;
}

function pickFields(record, known) {
  const fields = {};
  for (const [key, value] of Object.entries(record)) {
    if (known.has(key)) continue;
    if (value === null || ["string", "number", "boolean"].includes(typeof value)) fields[key] = value;
  }
  return fields;
}

function normalizeRecord(record, source, line) {
  if (!record || typeof record !== "object" || Array.isArray(record)) return null;
  const known = new Set([...TIMESTAMP_KEYS, ...HOST_KEYS, ...ACTOR_KEYS, ...ACTION_KEYS, ...OBJECT_KEYS, ...MESSAGE_KEYS]);
  const result = {
    ts: normalizeTimestamp(firstKey(record, TIMESTAMP_KEYS)),
    source,
    line,
  };
  const host = firstKey(record, HOST_KEYS);
  const actor = firstKey(record, ACTOR_KEYS);
  const action = firstKey(record, ACTION_KEYS);
  const object = firstKey(record, OBJECT_KEYS);
  const message = firstKey(record, MESSAGE_KEYS);
  if (host !== undefined) result.host = String(host);
  if (actor !== undefined) result.actor = String(actor);
  if (action !== undefined) result.action = String(action);
  if (object !== undefined) result.object = String(object);
  if (message !== undefined) result.message = String(message);
  const fields = pickFields(record, known);
  if (Object.keys(fields).length > 0) result.fields = fields;
  return result;
}

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  let index = 0;
  while (index < text.length) {
    const char = text[index];
    if (quoted) {
      if (char === '"' && text[index + 1] === '"') {
        field += '"';
        index += 2;
        continue;
      }
      if (char === '"') {
        quoted = false;
        index++;
        continue;
      }
      field += char;
      index++;
      continue;
    }
    if (char === '"') {
      quoted = true;
      index++;
      continue;
    }
    if (char === ",") {
      row.push(field);
      field = "";
      index++;
      continue;
    }
    if (char === "\n" || char === "\r") {
      if (char === "\r" && text[index + 1] === "\n") index++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
      index++;
      continue;
    }
    field += char;
    index++;
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((items) => items.some((item) => item !== ""));
}

function normalizeCsv(text) {
  const rows = parseCsv(text);
  const records = [];
  let badLines = 0;
  if (rows.length === 0) return { records, badLines, total: 0 };
  const header = rows[0].map((name) => name.trim());
  for (let index = 1; index < rows.length; index++) {
    const values = rows[index];
    const record = {};
    for (let column = 0; column < header.length; column++) record[header[column]] = values[column] ?? "";
    const normalized = normalizeRecord(record, "csv", index + 1);
    if (normalized === null) badLines++;
    else records.push(normalized);
  }
  return { records, badLines, total: rows.length - 1 };
}

function parseSyslog(line) {
  const rfc5424 = /^<(\d+)>(\d)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(?:-|\[[^\]]*\])\s*(.*)$/.exec(line);
  if (rfc5424 !== null) {
    return {
      ts: rfc5424[3],
      host: rfc5424[4],
      message: rfc5424[8],
      fields: { pri: Number(rfc5424[1]), version: Number(rfc5424[2]), app: rfc5424[5], proc: rfc5424[6], msgId: rfc5424[7] },
    };
  }
  const rfc3164 = /^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$/.exec(line);
  if (rfc3164 !== null) {
    return {
      ts: rfc3164[1],
      host: rfc3164[2],
      message: rfc3164[4],
      fields: { tag: rfc3164[3] },
    };
  }
  return null;
}

function normalizeSyslog(text) {
  const records = [];
  let badLines = 0;
  const lines = text.split(/\r\n|\r|\n/);
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index];
    if (line.trim() === "") continue;
    const parsed = parseSyslog(line);
    if (parsed === null) {
      badLines++;
      continue;
    }
    const record = {
      ts: normalizeTimestamp(parsed.ts),
      source: "syslog",
      line: index + 1,
      host: parsed.host,
      message: parsed.message,
    };
    if (Object.keys(parsed.fields).length > 0) record.fields = parsed.fields;
    records.push(record);
  }
  return { records, badLines, total: lines.filter((line) => line.trim() !== "").length };
}

export function normalizeLogText(text, format) {
  if (format === "jsonl") {
    const records = [];
    let badLines = 0;
    const lines = String(text).split(/\r\n|\r|\n/);
    for (let index = 0; index < lines.length; index++) {
      const line = lines[index];
      if (line.trim() === "") continue;
      let record;
      try {
        record = JSON.parse(line);
      } catch {
        badLines++;
        continue;
      }
      const normalized = normalizeRecord(record, "jsonl", index + 1);
      if (normalized === null) badLines++;
      else records.push(normalized);
    }
    return { records, badLines, total: lines.filter((line) => line.trim() !== "").length };
  }
  if (format === "csv") return normalizeCsv(String(text));
  if (format === "syslog") return normalizeSyslog(String(text));
  throw new Error(`不支持的日志格式: ${format}`);
}

export function toJsonl(records) {
  return records.map((record) => JSON.stringify(record)).join("\n") + (records.length > 0 ? "\n" : "");
}