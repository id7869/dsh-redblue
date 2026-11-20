// Offline IOC extraction (domain / IPv4 / IPv6 / URL / MD5 / SHA1 / SHA256).
// Default output is defanged; no network access.

const TLD_LIST = new Set([
  "com", "net", "org", "io", "dev", "ai", "co", "cn", "uk", "de", "jp", "ru", "in", "br",
  "fr", "nl", "se", "no", "fi", "dk", "pl", "it", "es", "ca", "au", "ch", "at", "be", "cz",
  "pt", "gr", "tr", "kr", "tw", "hk", "sg", "my", "id", "th", "vn", "ph", "nz", "za", "mx",
  "ar", "cl", "il", "ae", "sa", "ir", "pk", "bd", "lk", "np", "site", "xyz", "info", "me",
  "tech", "security", "sh", "run", "top", "online", "store", "edu", "gov", "mil", "us",
  "test", "example", "invalid", "localhost", "local",
]);
const FILE_EXTENSIONS = new Set([
  "md", "json", "jsonl", "js", "mjs", "cjs", "ts", "tsx", "yml", "yaml", "txt", "svg",
  "sarif", "log", "csv", "pcap", "zip", "sha256",
]);

const URL_RE = /\bhttps?:\/\/[^\s"'<>\\)\]]+/gi;
const DOMAIN_RE = /(?<![@A-Za-z0-9_./\\-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9_-])/g;
const IPV4_RE = /(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])/g;
const IPV6_RE = /(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])/g;
const HASH_RE = /\b[a-fA-F0-9]{32,64}\b/g;

function isIpv4(value) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
}

function isIpv6(value) {
  if (!value.includes(":") || !/^[0-9a-f:]+$/i.test(value)) return false;
  if (value.includes(":::")) return false;
  return value.includes("::") || value.split(":").length === 8;
}

function isDomain(value) {
  const lower = value.toLowerCase().replace(/\.$/, "");
  if (lower.includes("/") || lower.includes("\\")) return false;
  const parts = lower.split(".");
  if (parts.length < 2) return false;
  const tld = parts[parts.length - 1];
  if (!TLD_LIST.has(tld)) return false;
  if (FILE_EXTENSIONS.has(tld)) return false;
  return parts.every((part) => /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/.test(part));
}

export function defangDomain(value) {
  return value.replace(/\./g, "[.]");
}

export function defangIp(value) {
  return value.replace(/\./g, "[.]").replace(/:/g, "[:]");
}

export function defangUrl(value) {
  return value
    .replace(/^https:\/\//i, "hxxps://")
    .replace(/^http:\/\//i, "hxxp://")
    .replace(/\./g, "[.]");
}

export function extractIocs(text, options = {}) {
  const defang = options.defang !== false;
  const urls = new Set();
  const domains = new Set();
  const ips = new Set();
  const hashes = new Set();

  for (const match of String(text).matchAll(URL_RE)) urls.add(match[0].replace(/[.,;:]+$/, ""));
  for (const url of urls) {
    const hostMatch = /^https?:\/\/([^/:?#]+)/i.exec(url);
    if (hostMatch !== null) {
      const host = hostMatch[1].toLowerCase();
      if (isDomain(host)) domains.add(host);
    }
  }
  for (const match of String(text).matchAll(DOMAIN_RE)) {
    const value = match[0];
    const start = match.index ?? 0;
    if (start > 0 && text[start - 1] === "@") continue;
    if (isDomain(value)) domains.add(value.toLowerCase());
  }
  for (const match of String(text).matchAll(IPV4_RE)) if (isIpv4(match[0])) ips.add(match[0]);
  for (const match of String(text).matchAll(IPV6_RE)) if (isIpv6(match[0])) ips.add(match[0].toLowerCase());
  for (const match of String(text).matchAll(HASH_RE)) {
    const value = match[0].toLowerCase();
    if ([32, 40, 64].includes(value.length)) hashes.add(value);
  }

  const list = (set) => [...set].sort();
  const rawUrls = list(urls);
  const rawDomains = list(domains);
  const rawIps = list(ips);
  const rawHashes = list(hashes);
  return {
    defanged: defang,
    counts: { urls: rawUrls.length, domains: rawDomains.length, ips: rawIps.length, hashes: rawHashes.length },
    urls: defang ? rawUrls.map(defangUrl) : rawUrls,
    domains: defang ? rawDomains.map(defangDomain) : rawDomains,
    ips: defang ? rawIps.map((ip) => (ip.includes(":") ? defangIp(ip) : defangIp(ip))) : rawIps,
    hashes: rawHashes,
  };
}