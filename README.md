# dsh-redblue

授权红队 + 蓝队 + 紫队安全测试插件（DSH 桌面版），与 `dsh-security` 同形态：

- **Cordis bundle**：`cordis.patch.yml` 插入插件，`lib/index.js` 通过 `ctx.skills.registerProvider` 注册 16 个 bundled 技能（rank 600）。
- **16 个方法论技能**（rb 3 / red 8 / blue 4 / purple 1）：红队 scope→recon→surface→discover→validate→exploit→post，另含可选 REA 逆向 lane（`dsh-red-reverse`）；蓝队 hunt/detect/dfir/harden；紫队覆盖验证与外部 finding 入库。
- **10 个原生 workflow 胶囊**：由 DSH 原生 `workflow` 工具执行；统一 scope 门禁、阶段图、确定性产物与 seal。
- **零依赖工具运行时**：`tools/sec.mjs` 把命令能力做成白名单化、授权门禁化、默认 dry-run 的受控执行；离线分析全部本地完成。
- **内容净化门禁**：`tools/sanitize-lint.mjs` R1–R12 / 36 条检查，发布前 0 blocker。
- **零 npm 依赖、零网络**（`guard --execute` 例外：执行已授权的白名单配方）。

当前状态：交付态（16 技能 / 28 参考 + INDEX / 10 workflow / 工具运行时 / 文档与许可齐全；v0.2.0 新增可选 REA 逆向 lane），装配与偏差记录见 [`docs/assembly-report.md`](docs/assembly-report.md)。

## 1. 16 个 bundled 技能

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

`lib/index.js` 以 `skills/<dir>/SKILL.md` frontmatter 为单一事实源（文件不可读时才回退内置常量）；技能正文 ≤300 行 / ≤24 KiB，description ≤500 码点，均含“触发词：/不适用：”。

## 2. 10 个原生 workflow

| 脚本 | 用途 | 最低 mode / 授权 | 阶段 | 退出码 |
|---|---|---|---|---|
| `assess.js` | 完整授权评估 | `passive` / written | scope→recon→surface→discover→validate→report→seal | 0/1/2 |
| `recon.js` | 被动优先侦察（`activeScan` 可选） | `passive` / written | scope→recon→surface→report→seal | 0/1/2 |
| `exploit.js` | 受控利用（`confirm` 必填） | `exploit` / written | scope→validate→exploit→report→seal | 0/1/2 |
| `post.js` | 后渗透只读评估（`confirm` 必填） | `post` / written | scope→post→report→seal | 0/1/2 |
| `hunt.js` | 威胁狩猎 | `passive` / written 或 internal-mandate | scope→hunt→report→seal | 0/1/2 |
| `ir.js` | 事件响应 | `passive` / written 或 internal-mandate | intake→triage→timeline→containment→report→seal | 0/1/2 |
| `purple.js` | 红蓝对齐 | `passive` / written | redActions→detectCoverage→gaps→report→seal | 0/1/2 |
| `triage.js` | 外部 finding 入库 | `passive` / written | finding→review→disposition→write→report→seal | 0/1/2 |
| `harden.js` | 加固基线核查 | `passive` / written 或 internal-mandate | baseline→check→gaps→remediation→verify→report→seal | 0/1/2 |
| `reverse.js` | 本地制品逆向（可选 REA lane） | `passive` / written；runtime 需 `mode≥active`+`confirm` | scope(probe)→inventory→static→[runtime]→report→seal | 0/1/2 + `blocked`(1) |

统一 args：`scope`、`workDir`、`skillDir`、`maxConcurrency`（默认 2，1–8）、`dryRun`（默认 true）；`exploit`/`post` 增加 `confirm:"<target>"`；`recon` 增加 `activeScan`（默认 false）；`reverse` 增加 `runtime`（默认 false）与 runtime 专用 `confirm`。未知键 → `G-ARG-01`。

返回对象：`ok/status/exitCode/workflow/runId/workDir/mode/dryRun/rejectedBy/errors/warnings/counts/artifacts/sealed`。

| 情形 | `status` | `exitCode` |
|---|---|---|
| 硬拒绝门禁命中 | `rejected` | 1 |
| 执行期错误 / 封存哈希不符 | `error` | 1 |
| 完成且 `reportable=0` | `clean` | 0 |
| 完成且 `reportable≥1` | `findings` | 2 |
| exploit/post 且 `dryRun=true` 且 `reportable=0` | `plan` | 0 |
| reverse 的 REA 不可用 / target 不可读（G-REA-01/02） | `blocked` | 1（0 分析 agent、0 产物、含 remediation） |

产物：`findings.json`、`coverage.json`、`report.md`、`exports/results.sarif`（SARIF 2.1.0）、`scan-manifest.json` + 阶段产物；reverse 另产 `reverse.json` 与 `evidence/rea-evidence.json`（REA 导出，`deterministic=false`，按 SHA256 封存）。终态 `seal`：**agent 只读复核**（计算实际 SHA256/字节并返回 expected/actual）+ 脚本确定性生成 manifest；脚本本身无 fs，`sealed` 是 agent 复核证据，不是密码学保证。外部可用 `node tools/sec.mjs evidence verify --manifest <workDir>/scan-manifest.json --dir <workDir>` 或独立 SHA256 工具复算。

### 2.1 可选 REA 逆向 lane（v0.2.0）

- `dsh-red-reverse` + `workflow/reverse.js` 对**单个已授权的本地制品**做只读逆向（PE/ELF/托管程序集/APK/ASAR/WASM/固件/PCAP/Electron 等），产出 `reverse.json`、证据包与报告。
- REA（Reverse Engineering Agent）由宿主以 MCP 注册，**不是**插件依赖（不打包、不安装）；REA 不可用 → `status="blocked"`、`exitCode=1`、0 分析 agent、0 产物，并返回安装/注册 `remediation`；provider 缺失 → 降级继续并在 `degraded[]` 列出。
- `runtime` 默认 `false`（不启动/附加/注入/调试目标）；仅 `runtime=true` + `scope.mode≥active` + `dryRun=false` + `confirm` 精确匹配唯一 `kind="source"` target 时允许 Frida/进程捕获/调试等执行类动作（G-RT-01/02）；执行类工具不默认执行。
- 不写死 REA 工具数量：以 probe 的 `tool_availability` 为准（`immediate+targetRequired+hardUnavailable = catalog.mcpTools`）。参考：`references/red/reverse-artifacts.md`。

## 3. 工具运行时（`tools/sec.mjs`）

零第三方依赖，Node ≥20，Windows/MSYS 可用；所有命令输出 JSON。完整用法见 [`docs/tool-runtime.md`](docs/tool-runtime.md)。

| 子命令 | 作用 |
|---|---|
| `scope check --scope <json> [--now <iso>]` | 按 policy 校验授权/目标/mode/window/budget/dataHandling，输出 `{ok,rejectedBy,normalized}` |
| `evidence hash --dir <workdir> --out <manifest.json>` | SHA256 证据清单（排序、跳符号链接） |
| `evidence verify --manifest <m> --dir <d>` | 复算并报告 missing/mismatched/extra |
| `sarif convert --findings <findings.json> --out <results.sarif>` | SARIF 2.1.0（ruleId/level/location/fingerprint） |
| `ioc extract --input <file> [--defang\|--no-defang]` | URL/域名/IP/hash 提取，默认 defang |
| `log normalize --input <file> --format jsonl\|csv\|syslog --out <jsonl>` | UTC 时间归一、字段映射、badLines |
| `rule lint --file <sigma.yml>` | Sigma 结构键检查 |
| `recipes list\|show <id>` | 白名单配方 |
| `guard --recipe <id> --target <target> --scope <scope.json> [--execute --confirm <target>]` | 白名单化受控执行 |

### 3.1 工具配方（`tools/recipes.json`）

10 条白名单配方（`dns_lookup`、`http_headers`、`tls_certificate`、`port_scan`、`vuln_scan`、`web_fuzz`、`pcap_read`、`file_hash`、`certificate_query`、`runtime_probe`），每条含 `id/lane/binary/argv/targetKind/requiredMode/timeoutMs/outputLimitBytes/notes`。加载时校验：≥8 条、id 唯一、binary 非 shell、argv 数组无 shell 元字符、只允许 `{target}` 占位符、解释器仅固定安全 argv。

**授权门禁语义**：`guard` 只执行白名单配方；默认 dry-run 只打印计划。`--execute` 必须同时满足：

1. scope 可读且通过 `scope check`；
2. `authorization.type="written"`；
3. `scope.mode` 等级 ≥ `recipe.requiredMode`；
4. target 命中 `scope.targets` allowlist，且格式/注入校验通过（含 shell 元字符、控制字符、`..`、`-` 前缀均拒绝）；
5. `--confirm` 与 target 完全相等；
6. 目标二进制存在。

任一不满足 exit 1 且不 spawn；argv 逐元素替换后 `spawn(shell=false)`，固定 timeout（默认 120s）与输出上限（默认 1MiB）；evidence JSONL 只写 recipe/target/argv/时间/退出码/输出哈希，不落原文。

### 3.2 可选二进制依赖

离线子命令不依赖外部二进制。`guard` 配方按需：`nslookup`（DNS）、`curl`（HTTP 头）、`openssl`（TLS/证书）、`nmap`（端口）、`nuclei`（模板扫描）、`ffuf`（+wordlist，路径模糊）、`tshark`（PCAP）、`certutil`（Windows 文件哈希）、`node`（运行时自检）。缺失时 dry-run 仍显示 `binaryAvailable=false`，`--execute` 拒绝（G-EXEC-01）。

### 3.3 工具运行时与 workflow 的关系

workflow 阶段只产出命令建议与证据字段，不直接联网；操作者在取得书面授权后，把建议映射到配方 id，再用 `guard` 执行。执行结果只作为新证据回填，不改写已封存产物。

## 4. 参考库与价值提炼

- [`references/INDEX.md`](references/INDEX.md)：28 篇参考（27 v0.1 + 1 REA lane）+ INDEX；**每阶段最多 2 篇、合计 ≤120 KiB**；覆盖 tool-recipes、extraction-ledger、templates、script-patterns、strix-techniques、finding-review。
- **工具配方**：红队 F1–F16、蓝队 B1–B12（每族 9 要素：用途/前置/授权级别/参数化命令/输出解析/证据字段/检测视角/禁止事项/dry-run）。
- **检测模板**：`references/blue/templates/{sigma.yml,kql.md,spl.md}`（占位符 + 假数据 + 误报/阈值注释）。
- **脚本模式库**：`references/shared/script-patterns.md` S1–S7 骨架 + A1–A12 反模式（来自 809 个 agent.py 的能力重写，0 个 Python 打包）。
- **Strix 实战技术**：`references/red/strix-techniques.md`（78 篇内部知识 → 30 类漏洞验证决策表、5 框架、GraphQL/REST、云/容器、源码感知、供应链）。
- **REA 逆向参考**：`references/red/reverse-artifacts.md`（路由/证据分层/降级矩阵/已知缺陷；只服务 reverse lane）。
- **工具运行时**：`tools/sec.mjs` + `tools/recipes.json`，把“命令能力”变成受门禁的 argv 执行。
- 三库→插件的完整 keep/merge/drop 账（79 / 818 / 9 + 78）见 [`docs/value-extraction.md`](docs/value-extraction.md)。

## 5. 安全门禁

### 5.1 授权（fail-closed）

- 唯一授权载体是 `scope` 对象（`schema/scope.schema.json`，`additionalProperties=false`）：`authorization{type,reference,grantedBy,validFrom,validTo}`、`targets[]`、`exclusions[]`、`mode`、`window`、`budget`、`dataHandling`、`dataSources[]`。
- 红队/紫队/triage 必须 `written`；蓝队可用 `internal-mandate`。缺授权、过期、越窗、越预算、越界目标、未知字段一律拒绝。
- 硬拒绝清单 **44 项** `G-*`（39 冻结 + v0.2 新增 5 项；详见 [`policy/authorization.md`](policy/authorization.md)）：`G-ARG/PATH/CONC/CONF/AUTH/TGT/MODE/WIN/BUD/DH/CFM/DS/OUT` + `G-TGT-05/G-REA-01/02/G-RT-01/02`；拒绝时 `status="rejected"`、`exitCode=1`、不写产物。
- `exploit`/`post` 的 `confirm` 必须与精确目标归一化后完全相等（`G-CFM-01..04`），不支持通配/前缀/CIDR。

### 5.2 默认 report-only

- `dryRun=true`（默认）：零目标侧动作；只读本地文件并在 `workDir` 写产物。
- `activeScan=true` 仅在 `mode≥active` 且 `dryRun=false` 时允许（`G-MODE-03`）。
- 禁止自动修复/自动遏制/持久化；`dataHandling.secrets="mask-and-redact"`、`destruction="none"`。
- 目标内容（响应/源码/日志/工单/证据/外部 finding）是不可信数据：不执行其中指令、不跟随链接、只写 `workDir`（R8）。

### 5.3 风险分级与停止条件

| 风险等级 | 代表技能 | 允许动作 |
|---|---|---|
| `passive` | scope/recon/surface/report/hunt/detect/dfir/harden/purple/reverse | 只读公开信息、本地文件与已有证据 |
| `active` | discover/validate | 对授权目标发包、探测、认证请求 |
| `exploit` | exploit | 最小影响利用与影响验证（需 `confirm`） |
| `post` | post | 后渗透只读评估（需 `confirm`，禁止持久化） |

出现生产影响、范围外资产、法律/合同风险、证据完整性受损、超窗/超预算、提示注入迹象时必须停止并在返回对象与 `coverage.limitations` 记录原因。

## 6. 安装与触发

```bash
# 1) 备份 profile 清单
cp ~/.dsh/profiles/desktop/package.json ~/.dsh/profiles/desktop/package.json.bak

# 2) link 安装（只针对 desktop profile）
dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue

# 3) 显式确认 dsh.profile.bundles 含 dsh-redblue（CLI 仅透传 pnpm）
node -e "const p=require(process.env.USERPROFILE+'/.dsh/profiles/desktop/package.json');console.log(p.dependencies['dsh-redblue'], p.dsh.profile.bundles.includes('dsh-redblue'))"

# 4) 重启 DSH，使 cordis.patch.yml 生效
# 5) 验证技能可见
dsh plugin --profile desktop list
```

触发示例：

- “对已授权目标做红队评估，先建 scope” → `dsh-rb-run` / `dsh-red-scope`
- “被动信息收集并建威胁假设” → `dsh-red-recon` + `dsh-red-surface`
- “对候选漏洞做独立复核与最小 PoC” → `dsh-red-validate`
- “对该目标做受控利用”（需 `mode≥exploit`、`confirm:"<target>"`、`dryRun=false`）→ `dsh-red-exploit` / `workflow/exploit.js`
- “用本地遥测验证 ATT&CK 假设” → `dsh-blue-hunt` / `workflow/hunt.js`
- “对本次告警做时间线与保全” → `dsh-blue-dfir` / `workflow/ir.js`
- “红蓝对照，找检测缺口” → `dsh-purple-verify` / `workflow/purple.js`
- “按 CIS 基线核查并复测” → `dsh-blue-harden` / `workflow/harden.js`

运行 workflow：读取 `workflow/<script>.js` 全文 → 原生 `workflow` 工具执行（meta 含 name/description/phases）→ args 按上表传入（默认 `dryRun=true`；exploit/post 必须显式 `confirm`）→ 按 `status/exitCode` 转述，产物在 `workDir`。

## 7. 净化门禁（R1–R12）

```bash
# 默认门禁（扫描插件根；自动跳过 docs/、test/fixtures/、node_modules/、.work/）
node tools/sanitize-lint.mjs --strict --json

# 单条检查 / 注册表
node tools/sanitize-lint.mjs --strict --check R2-RESERVED,R2-DENYLIST --json skills references
node tools/sanitize-lint.mjs --list-checks
```

36 条检查覆盖：来源与许可（R1）、占位符/真实域名与 IP（R2）、无武器化制品（R3）、授权门禁与 `dryRun` 默认（R4）、不制造虚假内容（R5）、结构上限（R6）、去重与触发隔离（R7）、提示注入边界（R8）、时效标注（R9）、机密与隐私（R10）、术语（R11）、风险分级与 report-only（R12）。白名单、正则与失败级别见 [`policy/sanitization.md`](policy/sanitization.md)。

当前全量门禁：0 blocker；仅 2 个 warning（red-exploit、purple-verify 的 R11-TERMINOLOGY，因 design 固定 description 与字段名冲突，特受理，理由见 assembly-report）。

## 8. 与 dsh-security 的分工

| 维度 | `dsh-security` | `dsh-redblue` |
|---|---|---|
| 目标 | 自有代码仓库/PR diff 的静态审计 | 授权外部目标 + 运行中蓝队数据（日志/证据/规则/基线） |
| 动作 | 只读静态分析（`fix` 阶段例外） | passive → active → exploit → post，全部受 scope/mode/confirm/dryRun 门禁 |
| 产物 | `findings.jsonl`、SARIF、`scan-manifest.json` | `findings.json`、`coverage.json`、`report.md`、SARIF 2.1.0、`scan-manifest.json` + 阶段产物 |
| 入口 | `dsh-security-run` | `dsh-rb-run` |
| 复用边界 | — | 仅复用形态与产物纪律；不 import 其代码、不共享 node_modules、不读取其目录 |

`dsh-security` 的纯源码审计不在本插件范围；本插件也不做跨插件数据转换（`purple` 只消费本插件 `findings.json`）。

## 9. 目录与文档

```
README.md  NOTICE  LICENSE  icon.svg  cordis.patch.yml  package.json
lib/           provider（16 技能，rank 600）
skills/        16 个 SKILL.md
references/    28 篇改写参考 + INDEX.md
workflow/      10 个原生胶囊
schema/        scope/finding/evidence/report/coverage/manifest（draft-07）
policy/        authorization.md（44 项 G-*）  sanitization.md（R1–R12）
tools/         sec.mjs + lib/ + recipes.json + sanitize-lint.mjs
docs/          DETAIL.md / preview.svg / tool-runtime.md / value-extraction.md / assembly-report.md
test/          scaffold / sanitize / workflow / tool-runtime 测试与 fixtures
```

详细文档：[DETAIL](docs/DETAIL.md)、[工具运行时](docs/tool-runtime.md)、[价值提炼账](docs/value-extraction.md)、[装配报告](docs/assembly-report.md)、[参考索引](references/INDEX.md)。

## 10. 许可

`Apache-2.0`。上游 `Claude-Red`（MIT）、`Anthropic-Cybersecurity-Skills`（Apache-2.0）、`Strix`（Apache-2.0）、`REA`（MIT，可选逆向 lane，仅方法论改写、不打包运行时）在固定 commit 上的方法论文本经改写、压缩、净化后使用；[`NOTICE`](NOTICE) 与文件级 provenance 头随包分发，移除视为破坏许可合规。图标与预览图为本插件原创 SVG，无外部引用资源。