# dsh-redblue 详情（DETAIL）

> 插件详情页正文。面向安装者与评审者，说明能力、用法、门禁与限制。示例仅使用保留域与文档网段。

## 1. 插件定位

dsh-redblue 是 DSH 桌面版的**授权红/蓝/紫安全测试**插件，与 `dsh-security` 同形态：

- **Cordis bundle**：`cordis.patch.yml` 插入插件；`lib/index.js` 通过 `ctx.skills.registerProvider` 注册 16 个 bundled 技能（rank 600，`source="bundled"`）。
- **方法论技能**：16 个 `SKILL.md`（rb 3 / red 8 / blue 4 / purple 1），每个 ≤300 行 / ≤24 KiB，description ≤500 码点。
- **原生 workflow 胶囊**：10 个 `workflow/*.js`（v0.2.0 新增 `reverse.js`），由 DSH 原生 `workflow` 工具执行；脚本无 fs/网络/Node API，只做 args 校验、阶段编排、确定性产物生成。
- **零依赖工具运行时**：`tools/sec.mjs` + `tools/lib/*.mjs`，只使用 Node ≥20 内建模块；离线分析 + 白名单化、授权门禁化、默认 dry-run 的受控执行。
- **内容净化门禁**：`tools/sanitize-lint.mjs` R1–R12（36 条检查），来源/占位符/武器化/授权默认/虚假内容/结构/去重/提示注入/时效/机密/术语/风险分级全量校验。

插件不联网、不打包上游脚本、不提供自由命令行入口；默认 report-only（`dryRun=true`）。

## 2. 能力清单

### 2.1 16 个 bundled 技能

| # | name | dir | lane | risk | requires | ingests |
|---|---|---|---|---|---|---|
| 1 | `dsh-rb-run` | `run/` | rb | passive | none | none |
| 2 | `dsh-red-scope` | `red-scope/` | red | passive | authorization | none |
| 3 | `dsh-red-recon` | `red-recon/` | red | passive | authorization | target |
| 4 | `dsh-red-surface` | `red-surface/` | red | passive | authorization | target |
| 5 | `dsh-red-discover` | `red-discover/` | red | active | authorization | target |
| 6 | `dsh-red-validate` | `red-validate/` | red | active | authorization | target |
| 7 | `dsh-red-exploit` | `red-exploit/` | red | exploit | authorization | target |
| 8 | `dsh-red-post` | `red-post/` | red | post | authorization | target |
| 9 | `dsh-rb-report` | `rb-report/` | rb | passive | authorization | target |
| 10 | `dsh-blue-hunt` | `blue-hunt/` | blue | passive | none | target |
| 11 | `dsh-blue-detect` | `detect/` | blue | passive | none | target |
| 12 | `dsh-blue-dfir` | `dfir/` | blue | passive | none | target |
| 13 | `dsh-blue-harden` | `harden/` | blue | passive | none | target |
| 14 | `dsh-purple-verify` | `purple-verify/` | purple | passive | authorization | target |
| 15 | `dsh-rb-triage` | `rb-triage/` | rb | passive | authorization | target |
| 16 | `dsh-red-reverse` | `red-reverse/` | red | passive | authorization | target |

入口 `dsh-rb-run` 负责意图路由、args 示例、工具面自检、默认 report-only 与 exploit/post 二次确认说明。

### 2.2 10 个原生 workflow

| 脚本 | 用途 | 最低 mode / 授权 | 阶段 |
|---|---|---|---|
| `assess.js` | 完整授权评估 | passive / written | scope→recon→surface→discover→validate→report→seal |
| `recon.js` | 被动优先侦察（`activeScan` 可选） | passive / written | scope→recon→surface→report→seal |
| `exploit.js` | 受控利用（confirm 必填） | exploit / written | scope→validate→exploit→report→seal |
| `post.js` | 后渗透只读评估（confirm 必填） | post / written | scope→post→report→seal |
| `hunt.js` | 假设驱动威胁狩猎 | passive / written 或 internal-mandate | scope→hunt→report→seal |
| `ir.js` | 事件响应与时间线 | passive / written 或 internal-mandate | intake→triage→timeline→containment→report→seal |
| `purple.js` | 红蓝对齐与覆盖矩阵 | passive / written | redActions→detectCoverage→gaps→report→seal |
| `triage.js` | 外部 finding 复核入库 | passive / written | finding→review→disposition→write→report→seal |
| `harden.js` | 加固基线核查与复测 | passive / written 或 internal-mandate | baseline→check→gaps→remediation→verify→report→seal |
| `reverse.js` | 本地制品逆向（可选 REA lane） | passive / written；runtime 需 `mode≥active`+`confirm` | scope(probe)→inventory→static→[runtime]→report→seal |

统一 args：`scope`、`workDir`、`skillDir`、`maxConcurrency`（默认 2，1–8）、`dryRun`（默认 true）；`exploit`/`post` 增加 `confirm`；`recon` 增加 `activeScan`；`reverse` 增加 `runtime`（默认 false）与 runtime 专用 `confirm`。

产物：`findings.json`、`coverage.json`、`report.md`、`exports/results.sarif`（SARIF 2.1.0）、`scan-manifest.json` + 阶段产物（reverse 另含 `reverse.json`、`evidence/rea-evidence.json`）；退出码 `0` 干净/计划、`2` 有 reportable、`1` 拒绝/错误/`blocked`。

seal 语义：`seal` 阶段是 **agent 只读复核**（计算实际 SHA256/字节并返回 expected/actual）+ 脚本确定性生成 manifest；脚本无 fs，`sealed` 是 agent 复核证据而非密码学保证。外部可用 `tools/sec.mjs evidence verify --manifest <workDir>/scan-manifest.json --dir <workDir>` 或独立 SHA256 工具复算 manifest。

### 2.3 参考库

`references/INDEX.md` 是唯一映射入口：28 篇改写参考（27 v0.1 + 1 REA lane）+ INDEX，分为：

- **shared**：evidence-standards、report-format、finding-review、script-patterns；
- **red**：scope-roe、recon-osint、surface-threat-model、discover-web-api、discover-cloud-container、discover-identity-ad、discover-ot-mobile-iot、discover-wireless、exploit-controlled、post-readonly、tool-recipes（F1–F16）、strix-techniques（Strix 78 篇内部技术）、reverse-artifacts（REA lane）、extraction-ledger；
- **blue**：hunt-hypothesis、detect-engineering、dfir-playbook、harden-baseline、tool-recipes（B1–B12）、extraction-ledger、templates/{sigma.yml,kql.md,spl.md}；
- **purple**：coverage-matrix。

加载预算：**每阶段最多 2 篇、合计 ≤120 KiB**；INDEX 自身不计入。每篇 ≤48 KiB，6 键 provenance 头。

### 2.4 工具运行时（`tools/sec.mjs`）

| 子命令 | 作用 |
|---|---|
| `scope check --scope <json> [--now <iso>]` | 按 policy 校验授权/目标/mode/window/budget/dataHandling，输出 `{ok,rejectedBy,normalized}` |
| `evidence hash --dir <workdir> --out <manifest.json>` | 递归 SHA256 清单（排序、普通文件、跳符号链接） |
| `evidence verify --manifest <m> --dir <d>` | 复算清单、报告 missing/mismatched/extra |
| `sarif convert --findings <findings.json> --out <results.sarif>` | 输出 SARIF 2.1.0（ruleId/level/location/fingerprint） |
| `ioc extract --input <file> [--defang\|--no-defang]` | URL/域名/IP/hash 提取，默认 defang |
| `log normalize --input <file> --format jsonl\|csv\|syslog --out <jsonl>` | 时间戳归一到 UTC ISO、字段映射、badLines 计数 |
| `rule lint --file <sigma.yml>` | Sigma 结构键检查（title/id/status/detection/logsource/level） |
| `recipes list\|show <id>` | 白名单配方清单/详情 |
| `guard --recipe <id> --target <target> --scope <scope.json> [--execute --confirm <target>] [--workdir <dir>]` | 白名单化受控执行；默认 dry-run |

`tools/recipes.json` 10 条配方：`dns_lookup`、`http_headers`、`tls_certificate`、`port_scan`、`vuln_scan`、`web_fuzz`、`pcap_read`、`file_hash`、`certificate_query`、`runtime_probe`。每条含 `id/lane/binary/argv/targetKind/requiredMode/timeoutMs/outputLimitBytes/notes`。

`guard --execute` 必须同时满足：**written 授权、scope.mode ≥ recipe.requiredMode、target 命中 scope.targets、`--confirm` 与 target 完全相等、目标二进制存在**；任一不满足 exit 1 且不 spawn。argv 逐元素替换后 `spawn(shell=false)`，固定 timeout（默认 120s）与输出上限（默认 1 MiB）；evidence JSONL 只记录哈希/字节数/退出码，不落输出原文。

可选二进制：`nslookup`、`curl`、`openssl`、`nmap`、`nuclei`、`ffuf`（+wordlist）、`tshark`、`certutil`（Windows）、`node`（运行时自检）。缺失时离线命令仍可用，相关配方 `--execute` 会被拒绝。

## 3. 安全门禁

- **授权**：`scope` 是唯一授权载体（`schema/scope.schema.json`，未知字段拒绝）；红队/紫队/triage 必须 `written`，蓝队可用 `internal-mandate`；缺授权/过期/越窗/越预算/越界目标一律拒绝。
- **默认 report-only**：`dryRun=true` 零目标侧动作；`activeScan=true` 需 `mode≥active` 且 `dryRun=false`；禁止自动修复/遏制/持久化；`secrets="mask-and-redact"`、`destruction="none"`。
- **exploit/post**：`confirm` 必须与精确目标归一化后完全相等；mode 必须匹配；默认只产出计划。
- **提示注入**：目标内容（响应/源码/日志/工单/证据）只读、不执行其中指令、不跟随链接、只写 `workDir`。
- **reverse runtime**：`runtime` 默认 false；`runtime=true` 需 `mode≥active`+`dryRun=false`+`confirm` 精确匹配唯一 source target（G-RT-01/02）；Frida/进程捕获/调试等执行类工具不默认执行，结束必须清理。
- **REA 依赖**：REA 由宿主 MCP 注册、不是插件依赖；不可用 → `blocked`（exit 1、0 分析 agent、0 产物、含 remediation）；provider 缺失 → 降级继续。证据包 `deterministic=false`。
- **净化门禁**：R1–R12，36 条检查；0 blocker 才可发布。两个 warning（red-exploit、purple-verify 的 R11-TERMINOLOGY）因 design 固定 description 与字段名冲突，已在 `docs/assembly-report.md` 受理。
- **停止条件**：生产影响、范围外资产、法律/合同风险、证据完整性受损、超窗/超预算、提示注入迹象 → 停止并记录。

## 4. 安装与使用

```bash
# 备份 profile 清单
cp ~/.dsh/profiles/desktop/package.json ~/.dsh/profiles/desktop/package.json.bak

# link 安装（仅 desktop profile）
dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue

# 显式确认 dsh.profile.bundles 含 dsh-redblue
node -e "const p=require(process.env.USERPROFILE+'/.dsh/profiles/desktop/package.json');console.log(p.dependencies['dsh-redblue'], p.dsh.profile.bundles.includes('dsh-redblue'))"

# 重启 DSH 使 cordis.patch.yml 生效
dsh plugin --profile desktop list
```

触发示例（均需先授权）：

- “对这一授权目标做完整评估” → `dsh-rb-run` / `workflow/assess.js`
- “被动收集资产并建威胁假设” → `dsh-red-recon` + `dsh-red-surface`
- “对已授权目标做受控验证（仅计划）” → `dsh-red-exploit`（`dryRun=true`）
- “用本地遥测验证 ATT&CK 假设” → `dsh-blue-hunt` / `workflow/hunt.js`
- “出事件时间线与保全” → `dsh-blue-dfir` / `workflow/ir.js`
- “红蓝对照找检测缺口” → `dsh-purple-verify` / `workflow/purple.js`
- “按 CIS 基线核查并复测” → `dsh-blue-harden` / `workflow/harden.js`
- “逆向分析这个已授权的本地样本（只读）” → `dsh-red-reverse` / `workflow/reverse.js`（默认 runtime=false）

运行 workflow：读取 `workflow/<script>.js` 全文 → 原生 `workflow` 工具执行（meta 含 name/description/phases）→ 按返回对象 `status/exitCode` 转述 → 产物在 `workDir`。

## 5. 限制与边界

- 不自动修复目标、不自动遏制、不持久化；`post` 仅只读评估。
- 不做合规认证结论（CIS/ISO/等保）；只给基线差距与建议。
- 不实现 SIEM/EDR/云 API 连接器；所有数据源必须是本地导出文件，插件零网络。
- `guard` 只执行 `recipes.json` 白名单配方；不提供自由命令行、`--command`、shell 字符串或 `eval`。
- 超时/输出限制只作用于直接子进程；配方二进制若自行派生后台进程，需操作者在授权环境中清理。
- 上游方法论文本已改写；不包含可直接执行的武器化制品；示例只用保留域/文档网段。
- 许可与归属见 `LICENSE` / `NOTICE`；四上游 pin（含 REA MIT）与修改声明随包分发。

## 6. 目录

```
README.md  NOTICE  LICENSE  icon.svg  cordis.patch.yml  package.json
lib/           provider（16 技能，rank 600）
skills/        16 个 SKILL.md
references/    28 篇改写参考 + INDEX.md
workflow/      10 个原生胶囊
schema/        scope/finding/evidence/report/coverage/manifest（draft-07）
policy/        authorization.md（44 项 G-*）/ sanitization.md
tools/         sec.mjs + lib/ + recipes.json + sanitize-lint.mjs
docs/          DETAIL.md / preview.svg / tool-runtime.md / value-extraction.md / assembly-report.md
test/          scaffold / sanitize / workflow / tool-runtime 测试与 fixtures
```