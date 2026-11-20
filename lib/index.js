// Bundled skill provider for the dsh-redblue plugin.
// Registers the 16 methodology skills into ctx.skills, mirroring the official
// bundled-provider pattern used by dsh-security.
//
// The rank is hard-coded instead of importing the BUNDLED_SKILL_RANK constant
// from the DSH skill peer package: a local `link:` install has no node_modules
// of its own, and Node would fail to resolve a peer package from the plugin's
// real path. The value (600) is the fixed BUNDLED_SKILL_RANK constant.

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const BUNDLED_SKILL_RANK = 600;
const PROVIDER_NAME = "dsh-redblue";

// name = SKILL.md frontmatter name; dir = subdirectory under skills/ holding SKILL.md.
// description below is only a fallback for when skills/<dir>/SKILL.md cannot be read;
// once the file exists its frontmatter is the single source of truth.
const SKILLS = [
  { name: "dsh-rb-run", dir: "run", description: "dsh-redblue 红蓝安全测试入口：按意图选择并运行 10 个授权门禁工作流（assess/recon/exploit/post/hunt/ir/purple/triage/harden/reverse），校验 scope、mode、confirm、runtime 与 dryRun；reverse 为可选 REA 逆向 lane。触发词：红蓝对抗、授权渗透测试、红队评估、威胁狩猎、应急响应、紫队对齐、逆向分析、REA、dsh-redblue、red team、blue team。不适用：单条外部 finding 独立复核入库用 dsh-rb-triage；纯自有源码审计用 dsh-security-run；无本地制品或无授权时不用 reverse；本技能不直接执行攻击动作。" },
  { name: "dsh-red-scope", dir: "red-scope", description: "授权与交战规则（RoE）建模：把书面授权、目标 allowlist、排除项、时间窗、预算、数据处置与停止条件写成可被 workflow 硬校验的 scope 对象。触发词：授权范围、RoE、rules of engagement、目标白名单、测试时间窗、数据处置、停止条件、scope 校验。不适用：收集目标情报用 dsh-red-recon；本技能不发起探测，只产出并校验 scope。" },
  { name: "dsh-red-recon", dir: "red-recon", description: "被动优先的信息收集：域名、证书、DNS、公开代码与 Favicon 等 OSINT 资产测绘，输出资产清单与置信度；主动扫描须 activeScan=true 且 mode≥active。触发词：信息收集、recon、OSINT、资产测绘、子域枚举、被动侦察、attack surface discovery。不适用：对已收集资产做威胁假设建模用 dsh-red-surface；本技能不对未授权目标发包。" },
  { name: "dsh-red-surface", dir: "red-surface", description: "攻击面与威胁假设建模：消费 recon 资产清单，按信任边界、入口点与数据流产出可验证的威胁假设并排优先级。触发词：攻击面分析、威胁建模、威胁假设、信任边界、攻击路径、threat model、surface mapping。不适用：源码级威胁建模用 dsh-security-threat-model；漏洞验证用 dsh-red-validate，本技能不下漏洞结论。" },
  { name: "dsh-red-discover", dir: "red-discover", description: "分类漏洞发现方法论：web、api、cloud、container、ad、ot、mobile、wireless 的测试清单、判定标准与证据要求，产出候选断言而非结论。触发词：漏洞发现、漏洞挖掘、web 安全测试、API 测试、云安全评估、容器配置检查、AD 安全评估、无线测试。不适用：候选断言独立复核与定级用 dsh-red-validate；实际利用用 dsh-red-exploit；本技能不执行利用。" },
  { name: "dsh-red-validate", dir: "red-validate", description: "独立验证与最小 PoC：重读证据、复现最小影响路径、剔除误报，给出 disposition、CVSS 与 ATT&CK 映射，形成可审计证据链。触发词：漏洞验证、独立复核、误报剔除、最小 PoC、CVSS 评分、ATT&CK 映射、evidence chain、disposition。不适用：受控利用与影响验证用 dsh-red-exploit；全量发现用 dsh-red-discover；本技能不代替发现阶段。" },
  { name: "dsh-red-exploit", dir: "red-exploit", description: "受控利用与影响验证：在书面授权、mode=exploit|post、confirm 串与 dryRun 门禁下做最小影响利用，证明可达性后立即清理，不做持久化。触发词：受控利用、exploit、影响验证、PoC 复现、权限提升验证、authorized exploitation、exploit chain。不适用：批量漏洞发现用 dsh-red-discover；后渗透横向用 dsh-red-post；未授权或破坏性场景一律禁用。" },
  { name: "dsh-red-post", dir: "red-post", description: "后渗透评估（报告-only）：提权、凭据可得性与横向移动路径的只读评估，输出可达性与风险结论，不建立持久化、不驻留、不破坏。触发词：后渗透、post-exploitation、提权评估、横向移动、凭据可得性、权限维持风险评估、lateral movement。不适用：前置利用授权流程用 dsh-red-exploit；本技能禁止写入任何持久化机制。" },
  { name: "dsh-rb-report", dir: "rb-report", description: "红蓝紫统一报告与交付：把 findings、覆盖矩阵、时间线与处置建议组织成可复现报告、SARIF 2.1.0、findings.json、coverage.json 与 scan-manifest.json，含复现步骤、影响、修复建议与证据引用。触发词：红队报告、检测报告、DFIR 报告、覆盖矩阵、SARIF、findings.json、pentest report、复现步骤。不适用：自有代码审计报告格式用 dsh-security-report；单条告警复核入库用 dsh-rb-triage；哈希与封存由 workflow 的 seal 阶段完成，本技能不重算。" },
  { name: "dsh-blue-hunt", dir: "blue-hunt", description: "假设驱动威胁狩猎：从 ATT&CK 技术假设出发定义遥测需求、查询草稿与判定标准，证据不足时明确报告不可判定。触发词：威胁狩猎、threat hunting、狩猎假设、遥测、ATT&CK、hypothesis、数据源覆盖。不适用：编写检测规则与误报调优用 dsh-blue-detect；无遥测数据时不得编造结果。" },
  { name: "dsh-blue-detect", dir: "detect", description: "检测工程设计：产出 Sigma、KQL、SPL 检测规则、测试样例、覆盖矩阵与误报调优建议，规则必须能由既有数据源验证。触发词：检测工程、detection engineering、Sigma 规则、KQL、SPL、检测覆盖、误报调优、detection rule。不适用：验证检测能否被红队动作触发用 dsh-purple-verify；事件时间线分析用 dsh-blue-dfir；本技能不产出利用代码。" },
  { name: "dsh-blue-dfir", dir: "dfir", description: "事件分诊与 DFIR：证据保全（SHA256）、时间线构建、影响范围判定与遏制建议，产出可复算的时间线与处置清单。触发词：应急响应、DFIR、事件分诊、时间线分析、证据保全、遏制建议、incident response、forensics。不适用：威胁狩猎假设验证用 dsh-blue-hunt；本技能不出具司法鉴定意见，不得自动执行遏制动作。" },
  { name: "dsh-blue-harden", dir: "harden", description: "加固基线核查与复测：按 CIS 或厂商基线核对配置与暴露面，标注基线版本与时效，输出缺口、修复优先级与复测结果。触发词：安全加固、基线核查、CIS Benchmark、配置核查、暴露面收敛、harden、compliance baseline。不适用：检测规则设计用 dsh-blue-detect；本技能不作合规认证判定，也不自动改生产配置。" },
  { name: "dsh-purple-verify", dir: "purple-verify", description: "紫队对齐：把红队动作与蓝队检测规则映射为覆盖矩阵，定位未覆盖技术并给出优先级与补测计划，输出可复算的 purple 报告。触发词：紫队、purple team、覆盖矩阵、红蓝对齐、检测缺口、ATT&CK 覆盖、coverage gap。不适用：检测规则编写用 dsh-blue-detect；红队发现复核定级用 dsh-red-validate；本技能不重复红队发现。" },
  { name: "dsh-rb-triage", dir: "rb-triage", description: "外部 finding 或告警的独立复核入库：对单条外部 finding 重读证据、独立判定 disposition 与严重度，写入 findings.jsonl，不修改原 finding 的 severity。触发词：告警复核、finding 入库、triage、告警分级、外部漏洞复核、disposition 判定。不适用：全量扫描编排用 dsh-rb-run；修复复验用 dsh-security-verify-fix；本技能不做全量扫描。" },
  { name: "dsh-red-reverse", dir: "red-reverse", description: "对已授权范围内的本地制品做只读逆向分析：PE/ELF/托管程序集/ASAR/APK/WASM/固件/PCAP/Electron 的结构、能力与证据；Frida/进程捕获/调试等执行类默认关闭且需 runtime+confirm。触发词：逆向分析、二进制分析、reverse engineering、REA、PE 分析、ELF 分析、ASAR、APK 静态分析、WASM、固件、字符串与导入表。不适用：网络资产侦察用 dsh-red-recon；漏洞利用用 dsh-red-exploit；纯源码或无制品场景用 dsh-security；未授权目标或样本执行一律禁用。" },
];

function bodyUrlOf(dir) {
  return new URL(`../skills/${dir}/SKILL.md`, import.meta.url);
}

function resourceBaseOf(dir) {
  return { kind: "directory", path: fileURLToPath(new URL(`../skills/${dir}/`, import.meta.url)) };
}

// Parse the leading YAML frontmatter of a SKILL.md (flat `key: value` lines only).
function parseFrontmatter(text) {
  const match = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (match === null) return { meta: {}, body: text };
  const meta = {};
  for (const line of match[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z][A-Za-z0-9_-]*):\s*(.*)$/.exec(line);
    if (kv === null) continue;
    let value = kv[2].trim();
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value[value.length - 1] === value[0]) value = value.slice(1, -1);
    meta[kv[1]] = value;
  }
  return { meta, body: text.slice(match[0].length).replace(/^\r?\n/, "") };
}

async function readSkillText(dir) {
  try {
    return await readFile(bodyUrlOf(dir), "utf8");
  } catch {
    // Scaffold phase: skills/<dir>/SKILL.md may not exist yet (authors add them later).
    return "";
  }
}

let catalogPromise;
// Resolve the catalog once. Prefer the SKILL.md frontmatter (single source of truth)
// and fall back to the descriptive constants above when a file cannot be read.
function loadCatalog() {
  if (catalogPromise === undefined) {
    catalogPromise = Promise.all(SKILLS.map(async (entry) => {
      const text = await readSkillText(entry.dir);
      const meta = parseFrontmatter(text).meta;
      const description = typeof meta.description === "string" && meta.description.length > 0 ? meta.description : entry.description;
      const whenToUse = typeof meta.whenToUse === "string" && meta.whenToUse.length > 0 ? meta.whenToUse : undefined;
      return { name: entry.name, dir: entry.dir, description, whenToUse };
    }));
  }
  return catalogPromise;
}

function summaryOf(skill) {
  return {
    name: skill.name,
    description: skill.description,
    ...(skill.whenToUse === undefined ? {} : { whenToUse: skill.whenToUse }),
    invocation: { modelInvocable: true, userInvocable: true },
    provider: PROVIDER_NAME,
    source: "bundled",
    resourceBase: resourceBaseOf(skill.dir),
    rank: BUNDLED_SKILL_RANK,
    locator: bodyUrlOf(skill.dir),
  };
}

const provider = {
  name: PROVIDER_NAME,
  async list() {
    const catalog = await loadCatalog();
    return catalog.map(summaryOf);
  },
  async get(candidate) {
    const catalog = await loadCatalog();
    const entry = catalog.find((s) => s.name === candidate?.name);
    if (entry === undefined) return undefined;
    const text = await readSkillText(entry.dir);
    const parsed = parseFrontmatter(text);
    const description = typeof parsed.meta.description === "string" && parsed.meta.description.length > 0 ? parsed.meta.description : entry.description;
    const whenToUse = typeof parsed.meta.whenToUse === "string" && parsed.meta.whenToUse.length > 0 ? parsed.meta.whenToUse : entry.whenToUse;
    return {
      name: entry.name,
      description,
      ...(whenToUse === undefined ? {} : { whenToUse }),
      invocation: { modelInvocable: true, userInvocable: true },
      provider: PROVIDER_NAME,
      source: "bundled",
      resourceBase: resourceBaseOf(entry.dir),
      content: text.length > 0 ? parsed.body : "",
    };
  },
};

/** Cordis plugin name. */
const name = "dsh-redblue";

/** Service required by the bundled provider. */
const inject = ["skills"];

/** Register the bundled dsh-redblue provider on ctx.skills. */
function apply(ctx) {
  ctx.skills.registerProvider(() => provider);
}

export { apply, inject, name };
