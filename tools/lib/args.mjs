// Minimal option parser for the dsh-redblue tool runtime.
// Only `--name value`, `--name=value` and boolean flags are supported; there is
// deliberately no mechanism to pass arbitrary commands through this parser.

export class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = "UsageError";
  }
}

export function parseOptions(argv, spec) {
  const options = {};
  const positionals = [];
  for (let index = 0; index < argv.length; index++) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") {
      options.help = true;
      continue;
    }
    if (!argument.startsWith("--")) {
      positionals.push(argument);
      continue;
    }
    const raw = argument.slice(2);
    const eq = raw.indexOf("=");
    const name = eq === -1 ? raw : raw.slice(0, eq);
    const definition = spec[name];
    if (definition === undefined) throw new UsageError(`未知选项: --${name}`);
    if (definition.type === "boolean") {
      if (eq !== -1) throw new UsageError(`--${name} 不接受取值`);
      options[name] = true;
      continue;
    }
    if (eq !== -1) {
      options[name] = raw.slice(eq + 1);
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined || value.startsWith("--")) throw new UsageError(`--${name} 需要一个值`);
    options[name] = value;
    index++;
  }
  return { options, positionals };
}

export function requireOption(options, name, spec) {
  if (options[name] === undefined || options[name] === "") {
    const definition = spec[name];
    throw new UsageError(`缺少必填选项 --${name}${definition && definition.hint ? "（" + definition.hint + "）" : ""}`);
  }
  return options[name];
}

export function parseIntegerOption(options, name, fallback, min, max) {
  if (options[name] === undefined) return fallback;
  const value = Number(options[name]);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new UsageError(`--${name} 必须是 ${min}–${max} 的整数`);
  }
  return value;
}

export function parseIsoOption(options, name) {
  if (options[name] === undefined) return null;
  const parsed = new Date(options[name]);
  if (Number.isNaN(parsed.getTime())) throw new UsageError(`--${name} 不是合法 ISO 时间: ${options[name]}`);
  return parsed;
}
