# dsh-redblue 0.2.0 交付摘要

> 交付日期：2026-11-20
> 交付形态：DSH Desktop Cordis bundle + 16 个 bundled 技能 + 10 个原生 workflow 胶囊 + 零依赖工具运行时 + 可选 REA 逆向 lane
> 许可：Apache-2.0（上游方法论文本按 NOTICE 归属，含 REA MIT）
> 最终判定：**PASS（0 blocker / 0 high）** —— t48 v0.2.0 最终复审（PASS）；本任务关闭其 F1（随包文档/预览图旧版）与 F4（assembly V-6 状态过期），F2/F3/F5 记入 §7 已知限制。

---

## 1. 交付结论

| 项 | 结果 |
|---|---|
| 规格 | 16 技能 / 10 workflow / 28 参考 + INDEX / 6 schema / 10 recipes / 44 门禁 / 36 净化检查 |
| 净化门禁 | `sanitize-lint --strict`：**90 文件、0 blocker、2 warning**（R11 已受理），exit 0 |
| 测试 | **116 个**（scaffold 16 / sanitize 24 / workflow 53 / tool-runtime 23）：115 pass + 1 条按设计 skip + 0 fail |
| 语法 | 28/28 `.js/.mjs` 通过 `node --check`（lib 1 / workflow 10 / tools 2 / tools-lib 11 / test 4） |
| 安全负向 | v0.1 门禁零回归（workflow 哈希逐字节一致）；reverse 25 类拒绝构造 24/24 与预期一致、6/6 blocked、runtime 四条件不可绕过、0 agent |
| 门禁 | 44 项（v0.1 冻结注册表 + 新增 5 项：`G-TGT-05`、`G-REA-01/02`、`G-RT-01/02`）；拒绝/blocked 均 0 agent |
| provider | `dsh-redblue`，`inject=["skills"]`，`list()` 返回 **16** 项（含 `dsh-red-reverse`），rank 600，`source="bundled"` |
| 安装 | desktop profile：`link:` 刷新 exit 0，解析版本 **0.2.0**，`dependencies` 与 `dsh.profile.bundles` 均含 `dsh-redblue`（详见 [install.md](install.md)） |
| 打包 | `package.json files` **22 项**，全部存在；`docs/design-addendum-v0.2-reverse.md` 与内部评审资料不入包 |
| 临时产物 | `.work/` 不存在；本项目在系统临时目录的 131 个脚本/导出已清理（约 6.0 MB）；插件目录无临时脚本/日志/node_modules |

---

## 2. 交付清单

### 2.1 技能（16）

| name | dir | lane | risk | requires | ingests |
|---|---|---|---|---|---|
| `dsh-rb-run` | `run/` | rb | passive | none | none |
| `dsh-red-scope` | `red-scope/` | red | passive | authorization | none |
| `dsh-red-recon` | `red-recon/` | red | passive | authorization | target |
| `dsh-red-surface` | `red-surface/` | red | passive | authorization | target |
| `dsh-red-discover` | `red-discover/` | red | active | authorization | target |
| `dsh-red-validate` | `red-validate/` | red | active | authorization | target |
| `dsh-red-exploit` | `red-exploit/` | red | exploit | authorization | target |
| `dsh-red-post` | `red-post/` | red | post | authorization | target |
| `dsh-rb-report` | `rb-report/` | rb | passive | authorization | target |
| `dsh-blue-hunt` | `blue-hunt/` | blue | passive | none | target |
| `dsh-blue-detect` | `detect/` | blue | passive | none | target |
| `dsh-blue-dfir` | `dfir/` | blue | passive | none | target |
| `dsh-blue-harden` | `harden/` | blue | passive | none | target |
| `dsh-purple-verify` | `purple-verify/` | purple | passive | authorization | target |
| `dsh-rb-triage` | `rb-triage/` | rb | passive | authorization | target |
| `dsh-red-reverse` | `red-reverse/` | red | passive | authorization | target |

实现：`lib/index.js` 单 provider（`ctx.skills.registerProvider`，rank 600）；正文以 `skills/<dir>/SKILL.md` frontmatter 为单一事实源，文件不可读时才回退内置常量（16/16 逐字一致）。

### 2.2 原生 workflow（10）

| 脚本 | 用途 | 最低 mode / 授权 | 阶段 |
|---|---|---|---|
| `assess.js` | 完整授权评估 | passive / written | scope→recon→surface→discover→validate→report→seal |
| `recon.js` | 被动优先侦察（`activeScan` 可选） | passive / written | scope→recon→surface→report→seal |
| `exploit.js` | 受控利用（`confirm` 必填） | exploit / written | scope→validate→exploit→report→seal |
| `post.js` | 后渗透只读评估（`confirm` 必填） | post / written | scope→post→report→seal |
| `hunt.js` | 假设驱动威胁狩猎 | passive / written 或 internal-mandate | scope→hunt→report→seal |
| `ir.js` | 事件响应与时间线 | passive / written 或 internal-mandate | intake→triage→timeline→containment→report→seal |
| `purple.js` | 红蓝对齐与覆盖矩阵 | passive / written | redActions→detectCoverage→gaps→report→seal |
| `triage.js` | 外部 finding 复核入库 | passive / written | finding→review→disposition→write→report→seal |
| `harden.js` | 加固基线核查与复测 | passive / written 或 internal-mandate | baseline→check→gaps→remediation→verify→report→seal |
| `reverse.js` | 本地制品逆向（可选 REA lane） | passive / written；runtime 需 `mode≥active`+`confirm` | scope(probe)→inventory→static→[runtime]→report→seal |

- 统一 args：`scope` / `workDir` / `skillDir` / `maxConcurrency`（1–8）/ `dryRun`（默认 true）；`exploit`/`post` 增加 `confirm`；`recon` 增加 `activeScan`；`reverse` 增加 `runtime`（默认 false）与 `confirm`，`maxConcurrency` 实现默认 1。
- 产物：`findings.json`、`coverage.json`、`report.md`、`exports/results.sarif`（SARIF 2.1.0）、`scan-manifest.json` + 阶段产物；`reverse` 另产 `reverse.json`、`evidence/rea-evidence.json`。
- 退出码：`0` 干净/计划、`2` 有 reportable、`1` 拒绝/错误/`blocked`。

### 2.3 参考库（28 + INDEX）

- **shared 4**：evidence-standards、report-format、finding-review、script-patterns（S1–S7 + A1–A12）
- **red 14**：scope-roe、recon-osint、surface-threat-model、discover-web-api、discover-cloud-container、discover-identity-ad、discover-ot-mobile-iot、discover-wireless、exploit-controlled、post-readonly、tool-recipes（F1–F16）、strix-techniques、reverse-artifacts（REA lane）、extraction-ledger
- **blue 9**：hunt-hypothesis、detect-engineering、dfir-playbook、harden-baseline、tool-recipes（B1–B12）、extraction-ledger、templates/{sigma.yml, kql.md, spl.md}
- **purple 1**：coverage-matrix

加载预算：每阶段最多 2 篇、合计 ≤120 KiB；每篇 ≤48 KiB；参考均带 provenance；`reverse-artifacts.md` 带 REA 的 `rea-agents@6.9.0` MIT pin 与 `last-verified=2026-11-20`。

### 2.4 工具运行时与门禁工具

- `tools/sec.mjs`（零第三方依赖，Node ≥20）：`scope check`、`evidence hash|verify`、`sarif convert`、`ioc extract`（默认 defang）、`log normalize`、`rule lint`、`recipes list|show`、`guard`（白名单受控执行）。
- `tools/recipes.json`：10 条白名单配方（`dns_lookup`、`http_headers`、`tls_certificate`、`port_scan`、`vuln_scan`、`web_fuzz`、`pcap_read`、`file_hash`、`certificate_query`、`runtime_probe`）。
- `tools/lib/*.mjs` 11 个模块；`guard` 与 10 个 workflow 的 scope 限制同源。
- `tools/sanitize-lint.mjs`：R1–R12 / 36 条检查，`--strict` 0 blocker 才可发布；`--policy` 默认拒绝（需 `NODE_ENV=test` 或显式 `--allow-policy-override`）。

### 2.5 架构图与文档

| 文件 | 说明 | 入包 |
|---|---|---|
| `docs/architecture.md` | 装载链、执行架构、逆向 lane（Mermaid 源 + 44 G-* + 实测自查） | ✅ |
| `docs/architecture-plugin.svg` | 插件装载与目录分层图（1440×1308，含 REA 外部面板与 blocked 分支） | ✅ |
| `docs/architecture-workflow.svg` | 意图路由→门禁→阶段→产物执行图（1440×1864，含第 10 个 reverse lane） | ✅ |
| `docs/preview.svg` | 插件预览图（v0.2.0 已更新为 16 技能/10 workflow） | ✅ |
| `docs/install.md` | 安装/验证/重启/REA 可选依赖/升级/回滚/跨 profile/排查/安全前置 | ✅ |
| `docs/delivery-summary.md` | 本文件 | ✅ |
| `docs/DETAIL.md`、`docs/tool-runtime.md`、`docs/value-extraction.md`、`docs/assembly-report.md` | 详情页、工具运行时、价值提炼账、装配报告 | ✅ |
| `docs/requirements.md`、`docs/design.md`、`docs/design-addendum-v0.2-reverse.md`、`docs/sanitization-rules.md`、`docs/verification-report.md`、`docs/review-notes.md`、`docs/smoke-report.md` | 需求/设计/设计增补/净化规则/验证报告/复审记录/冒烟报告（内部资料） | ❌ |
| `docs/research-handoff.md` | 上游研究交接（内部留痕） | ❌ |

---

## 3. 触发示例（均以已有书面授权为前提）

| 你说 | 命中技能 | 走哪条 workflow |
|---|---|---|
| “对已授权目标做红队评估，先建 scope” | `dsh-rb-run` / `dsh-red-scope` | `assess.js` |
| “被动收集资产并建威胁假设” | `dsh-red-recon` / `dsh-red-surface` | `recon.js` |
| “对候选漏洞做独立复核并给最小 PoC” | `dsh-red-validate` | `assess.js`（validate） |
| “对该目标做受控利用” | `dsh-red-exploit` | `exploit.js`（需 `mode≥exploit`、`confirm`、`dryRun=false`） |
| “后渗透只读评估” | `dsh-red-post` | `post.js`（需 `mode=post`、`confirm`） |
| “用本地遥测验证 ATT&CK 假设” | `dsh-blue-hunt` | `hunt.js` |
| “对本次告警做时间线与证据保全” | `dsh-blue-dfir` | `ir.js` |
| “红蓝对照，找检测缺口” | `dsh-purple-verify` | `purple.js` |
| “按 CIS 基线核查并复测” | `dsh-blue-harden` | `harden.js` |
| “复核这条外部 finding 并入库” | `dsh-rb-triage` | `triage.js` |
| “分析这个本地样本/二进制（静态优先）” | `dsh-red-reverse` | `reverse.js`（可选 REA；默认 `runtime=false`） |

运行方式：读取 `workflow/<script>.js` 全文 → DSH 原生 `workflow` 工具执行 → `args` 传 `scope/workDir/skillDir/dryRun`（默认 report-only）→ 按 `status/exitCode` 转述，产物在 `workDir`。通用与逆向 lane 的最小 scope 样例见 [install.md](install.md) §6.3/§6.4（均已用 `scope check` 实测通过）。

---

## 4. 门禁摘要

### 4.1 44 项硬拒绝 `G-*`（`policy/authorization.md` §4）

| 组 | ID | 数量 |
|---|---|---|
| 参数/路径/配置 | `G-ARG-01`、`G-PATH-01..03`、`G-CONC-01`、`G-CONF-01` | 6 |
| 授权 | `G-AUTH-01..07` | 7 |
| 目标 | `G-TGT-01..05`（新增 `G-TGT-05`：reverse 恰好 1 个 source） | 5 |
| 模式 | `G-MODE-01..03` | 3 |
| 时间窗/预算/数据处置 | `G-WIN-01..03`、`G-BUD-01`、`G-DH-01..03` | 7 |
| 数据源 | `G-DS-01..07` | 7 |
| 二次确认 | `G-CFM-01..04` | 4 |
| 写盘前置 | `G-OUT-01` | 1 |
| REA 可用性（reverse，阶段级） | `G-REA-01`（REA 不可用）、`G-REA-02`（target 不可读/哈希不符） | 2 |
| runtime（reverse） | `G-RT-01`（mode/dryRun）、`G-RT-02`（confirm/禁用 confirm） | 2 |

- 拒绝语义：`status="rejected"`、`exitCode=1`、`rejectedBy=[...]`、`artifacts=[]`、`sealed=false`，**0 个 agent**、不写产物（`G-OUT-01` 由首阶段在写盘前判定）。
- `blocked` 语义（仅 reverse）：`status="blocked"`、`exitCode=1`、0 分析 agent、0 产物、含 `remediation`；与 `rejected` 区分。
- `G-EXEC-01` 是 `guard` 专用拒绝码，不在这 44 项注册表内。

### 4.2 默认 report-only 与受控执行

- `dryRun=true`（默认）：零目标侧动作，只读本地文件并写 `workDir` 产物；`activeScan=true` 需 `mode≥active` 且 `dryRun=false`。
- `reverse`：`runtime=false`（默认）只做静态只读分析；`runtime=true` 需 `mode≥active`、`dryRun=false`、`confirm` 与唯一 source target 完全相等；执行类工具不默认执行。
- `guard --execute` 六条件：scope 通过检查 + written 授权 + `scope.mode ≥ recipe.requiredMode` + target 命中 allowlist + `--confirm` 与 target 完全相等 + 目标二进制存在；任一不满足 exit 1 且不 spawn。
- argv 逐元素替换、`spawn(shell=false)`、固定 timeout（默认 120s）与输出上限（默认 1 MiB）；evidence JSONL 只落 recipe/target/argv/时间/退出码/输出哈希，不落原文。

### 4.3 内容净化门禁

`R1–R12 / 36 检查`：来源许可（R1）、保留域/占位符（R2）、无武器化制品（R3）、授权门禁与 dryRun 默认（R4）、不制造虚假内容（R5）、结构上限（R6）、去重/触发隔离（R7）、提示注入边界（R8）、时效标注（R9）、机密与隐私（R10）、术语（R11）、风险分级与 report-only（R12）。当前 **0 blocker**，2 条 `R11-TERMINOLOGY` warning（purple-verify、red-exploit）因 design 固定 description 与 findings 字段名冲突而受理（assembly-report §4）。

---

## 5. 可选 REA 逆向 lane（v0.2.0）

| 项 | 说明 |
|---|---|
| 定位 | REA（Reverse Engineering Agent）由**宿主 MCP 注册**，不是插件依赖；插件不打包 REA 运行时/二进制/安装脚本 |
| 版本/pin | `rea-agents@6.9.0`（MIT），commit `d74549e495c58eb4a560279fd9f05508401ea0a0`（tag `rea-agents-6.9.0`，skill v62）；server `rea 6.9.0` / SDK 2.3.1 / protocol 2026-07-28 |
| 安装/注册 | `npm install -g rea-agents@6.9.0` → `rea setup --client dsh` → `rea doctor --client dsh --skill` → 重启；环境变量见 [install.md](install.md) §7.3 |
| 能力 | 本地制品静态逆向：PE/ELF/托管 PE/CLI/APK 容器/ASAR-JS-Electron/WASM/固件/PCAP/EVM/archive；runtime（Frida/调试/进程捕获/ADB）受 `G-RT-01/02` |
| 门禁 | `G-REA-01`（REA 不可用）、`G-REA-02`（target 不可读/哈希不符）→ `blocked`；`G-RT-01/02` → `rejected`；静态默认 passive |
| 降级 | provider 缺失（JADX/ADB/apktool/WABT/固件/GDB/rizin/EVM/pwntools/TShark/Wakaru/JEB/Hopper/IDA/Kuna）**不 blocked**：继续静态分析并在 `degraded[]` 列 remediation；不得把缺失当“无问题” |
| 证据 | `evidence/rea-evidence.json` 由 REA 导出并 SHA256 封存；`deterministic=false`（含时间戳/会话状态），`retain=none` 不导出 |
| 不打包验证 | `package.json` 依赖为空；`find . -name '*.py'` 为 0；无 REA/Ghidra/JADX/ADB 二进制或安装脚本 |
| 不可用影响面 | 只有 `reverse` 受影响（`blocked` + remediation）；其余 workflow 完全不受影响 |

---

## 6. 安装状态（本机，2026-11-20 刷新）

| 项 | 结果 |
|---|---|
| profile | `C:/Users/<you>/.dsh/profiles/desktop` |
| 刷新命令 | `dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue` |
| 退出码 | **0**（`Done in 8.7s using pnpm v11.28.5`） |
| 解析版本 | **0.2.0**（`<profile>/node_modules/dsh-redblue/package.json`；`pnpm list` 对 link 依赖显示 link 目标而非版本号） |
| dependencies | `"dsh-redblue": "link:C:/dsh-workspace/branch1/dsh-redblue"`（package.json:14） |
| bundles | `dsh.profile.bundles` 含 `dsh-redblue`（package.json:34） |
| 列表 | `dsh-redblue@link:../../../../../dsh-workspace/branch1/dsh-redblue`（`dsh plugin --profile desktop list`，13 packages） |
| provider 冒烟 | `list()` = **16**（含 `dsh-red-reverse`），rank 600 |
| 符号链接 | `node_modules/dsh-redblue` → `C:\dsh-workspace\branch1\dsh-redblue` |
| 安装前备份 | `package.json.bak-dsh-redblue-v020-20261120-170500`（sha256 `c49334cc…`）；`cordis.patch.yml` 未改动（sha256 `6924dedb…`） |
| REA（可选） | `rea --version` = `6.9.0`；`rea doctor --client dsh --skill` 实测 `dsh=aligned`；会话内 `mcp__rea__binary_session` 可见 |
| 生效状态 | **未声称已生效**；需完全退出并重启 Desktop 后按 [install.md](install.md) §5 三条判定 |

其它 profile（web/headless/qqbot）本任务未安装，命令与注意事项见 [install.md](install.md) §9。

> **安装副作用（如实记录）**：pnpm 在 profile 目录重算依赖图（本机 `+1 -56`），并重试可选依赖 `cpu-features`（ssh2 传递依赖）构建失败但命令 exit 0；13 个直接依赖模块均在位。若后续发现其它插件异常，按 install.md §8.2 恢复备份并重装。

---

## 7. 已知限制

### 7.1 本任务关闭的 t48 findings

- **F1（medium，已关闭）**：随包分发的 `docs/install.md`、`docs/delivery-summary.md`、`docs/preview.svg` 仍是旧版口径。本任务已全部更新为 v0.2.0（16 技能 / 10 workflow / 28 参考 / 44 门禁），`preview.svg` 保持独立 SVG、无脚本、无外部引用。
- **F4（low，已关闭）**：`docs/assembly-report.md` §11.2 的 V-6 状态过期。本任务已改为 **closed（t46：lib 回退常量 344 码点逐字一致；4 测试 116/115/1；t47 §19 复验）**，并新增 §11.6 后续状态记录。

### 7.2 仍为 known limitation 的 t48 findings（low，文档/测试一致性）

- **F2（low）**：`skills/red-reverse/SKILL.md` 输入表的默认值与实现不同——SKILL 写 `maxConcurrency` 默认 4，实现默认 1（`workflow/reverse.js:647`）；SKILL 把 `dryRun=true` 描述为“只输出计划与探测”，实际静态只读分析照常执行，`dryRun=false` 只约束 runtime（`G-RT-01`）。**以本手册 §6.2/§6.5 与实现为准**；技能文件待下一版同步（skills/ 不在本任务范围）。
- **F3（low）**：`docs/architecture.md` 把 reverse preflight 的 32 个门拆成“冻结注册表 + 新增 5 个”不精确。实际 reverse preflight = **32**（既有 preflight 29 + 新增 3：`G-TGT-05`/`G-RT-01`/`G-RT-02`）；`G-REA-01/02` 是阶段级、`G-OUT-01` 是写盘阶段级。数值 32 正确，拆解表述待 architecture.md 下一次同步。
- **F5（low）**：`test/workflow.test.mjs` 的入口路由回归测试仍把 `reverse` 排除在 `ENTRY_ROUTED_WORKFLOWS` 之外（入口 `skills/run/SKILL.md` 已有 reverse 行）；属测试覆盖缺口，不影响当前功能。

### 7.3 验证期观察（W1–W3，均非阻塞）

- **W1（low）**：`guard` 缺少 `--scope` 时返回 **exit 2**（usage 语义），而非字面要求的 1；不 spawn、不读目标，**不是门禁绕过**。
- **W2 / R10（low）**：`rule lint` 不剥离行内 `#` 注释，自带 `references/blue/templates/sigma.yml` 被自身 linter 判 exit 1；正式规则把注释移到独立行即可。
- **W3（low，环境）**：Node 24 的 `node --test dsh-redblue/test/` 目录形式失败；用 `node --test dsh-redblue/test/*.test.mjs` 或 `npm test`。

### 7.4 架构语义限制

- **seal 自证**：`seal` 阶段是 **agent 只读复核**（计算实际 SHA256/字节并返回 expected/actual）+ 脚本确定性生成 `scan-manifest.json`；workflow 脚本无 fs，`sealed=true` 是复核证据，**不是密码学保证**。外部可用 `node tools/sec.mjs evidence verify --manifest <workDir>/scan-manifest.json --dir <workDir>` 或独立 SHA256 工具复算。
- **内联脚本未落盘**：DSH 原生 `workflow` 工具不持久化脚本副本，无法对“提交给工具的脚本文本”做字节级复核；行为一致性（门禁/产物/哈希）支持“内联的是磁盘同源版本”，但不是字节级证明。
- **v0.2.0 未重跑真实 E2E（waiver）**：`.work` 未重建、未重跑真实 workflow；历史 E2E 证据（smoke-report §11 的 14 个产物行、verification-report §15.6 的 14/14 零 mismatch）属 v0.1 基线，仅作回归参考。v0.2.0 的验证为代码/门禁/回归/静态产物级（t37 §18、t47 §19、t48 §18），未伪造 E2E。
- **数据源仅本地导出**：不实现 SIEM/EDR/云 API 连接器；`hunt/ir/purple/triage/harden` 的 `dataSources` 必须是本地文件（Windows 绝对路径，无 `..`）。
- **可选二进制缺失**：离线命令照常工作；相关配方 `--execute` 会被拒绝（`G-EXEC-01`），dry-run 仍能看到 `binaryAvailable=false`。
- **超时/输出上限只作用于直接子进程**：配方二进制若自行派生后台进程，需操作者在授权环境内清理。

### 7.5 v0.2.0 已受理偏差（assembly-report §11.2）

| ID | 内容 | 受理 |
|---|---|---|
| V-1 | `inspect_binary_hardening` 在 Windows 绝对路径返回客户端 schema 错误（REA 已知缺陷 K-1） | 受理：reverse 改用加载配置/notes/导入表/人工基线；非 Windows 可重试 |
| V-2 | Windows provider 缺口（JADX/ADB/apktool/WABT/固件/GDB/rizin/EVM/pwntools/TShark/Wakaru/JEB/Hopper/IDA/Kuna） | 受理：缺失一律降级并列出 remediation；只有 REA 不可用/目标不可读才 blocked |
| V-3 | schema enum 未扩展（`report.status` 无 `blocked`、`evidence.kind` 无 REA 专用值） | 受理：运行期状态与产物正确；schema 文档债留待下一版 |
| V-4 | 共享 report 模板 §3 未包含 route/provider | 受理：机器可读信息在 `reverse.json.probe/route`；建议下一版加入模板 |
| V-5 | `cordis.patch.yml` 注释仍写旧技能数 | 受理（注释级、无运行时影响） |
| V-7 | 新增测试分布与设计预测不同（总数一致） | 受理 |
| V-8 | 设计增补写参考数不变，实际 +1（`reverse-artifacts.md`） | 受理：以 28 为准 |

### 7.6 文档与观察项

- **R9（low）**：`skills/blue-hunt/SKILL.md`、`skills/detect/SKILL.md` 的内联 dataSources 表仍写 4 类 kind（实现/policy 已 6 类）；属“文档比实现窄”，不构成门禁弱化。
- **R11 受理**：2 条 `R11-TERMINOLOGY` warning（purple-verify / red-exploit），原因见 assembly-report §4。
- **冻结基线**：`docs/requirements.md`、`docs/design.md` 仍为 v0.1 冻结内容（计数与 sealed 语义等未同步 v0.2.0），以 `docs/design-addendum-v0.2-reverse.md` + `policy/authorization.md` + 代码为运行期事实源。
- **O-1（info）**：`reverse` 的 blocked 返回里 `agents` 字段是契约口径（scope/probe 计数），不等于实际调用数；与设计增补一致，建议 v0.3 明确口径。
- **O-2（info）**：E2E waiver 同上（§7.4）。
- **O-3（info）**：`cordis.patch.yml` 注释仍写旧技能数（V-5 已受理）。
- **O-4（info）**：插件目录含 `.git`（v0.1 基线 commit `277ec2e`；v0.2.0 工作树未提交/tag）。`.git` 不入包；若以 git 交付/审计，建议提交并 tag `v0.2.0`。
- **O-5（info）**：`retain` 语义在 `references/shared/evidence-standards.md` 与设计增补之间存在口径差异（reverse 的 `findings-only` 仍导出完整 REA 证据包）；实现按设计增补，建议下一版加注记。
- **输入 scope 白名单**：输入只接受九个键；`workDir/scope.json` 产物额外含 `schemaVersion`/`scopeDigest`/`validatedAt`，不可回灌为输入（会触发 `G-CONF-01`）。

---

## 8. 许可与归属

- 插件原创部分：**Apache-2.0**（[`LICENSE`](../LICENSE) 全文）。
- 四上游方法论文本在固定 commit 上**改写、压缩、净化**后使用；不含上游可执行脚本、agent 运行时或课程原文：

| 上游 | commit | 许可 | 用途 | 排除 |
|---|---|---|---|---|
| Claude-Red（SnailSploit） | `6196ba7464662de34e8744d359f175d1a7bca530` | MIT | recon/web/api/cloud/container/AD/wireless/exploit-dev/post/privesc 方法论改写 | 课程 dump、持久化/C2/外传配方、武器化制品 |
| Anthropic-Cybersecurity-Skills | `54a798831d2266a3ca61ce68a7acb80b81160d57` | Apache-2.0 | 蓝队检测/狩猎/DFIR/加固方法论、红队缺口补充、检测模板与脚本纪律 | 809 个 `agent.py`、逐技能 LICENSE 副本、课程 dump |
| Strix | `8db295a5b3564be2b430bb3a9afdb4db7850fa24` | Apache-2.0 | agent 作业纪律、预算/scope 纪律、SARIF/退出码约定、门禁设计、内部技术压缩 | Strix 运行时、Docker 依赖、CLI、知识库原文件 |
| **REA**（Reverse Engineering Agent） | `d74549e495c58eb4a560279fd9f05508401ea0a0`（`rea-agents@6.9.0`，skill v62） | **MIT** | 逆向 lane 的路由/证据纪律/降级矩阵（`skills/red-reverse` + `references/red/reverse-artifacts.md`） | REA 运行时、provider 二进制（Ghidra/JADX/ADB/…）、安装脚本与示例执行说明 |

- [`NOTICE`](../NOTICE) 含四 pin、MIT 全文与修改声明；参考与技能文件带 provenance 头。**移除 NOTICE / provenance 视为破坏许可合规。**
- 插件不打包 REA，也不复制 REA 源码；REA 由其自身 MIT 许可约束。
- 图标与预览图（`icon.svg`、`docs/preview.svg`）为本插件原创 SVG，无外部引用资源。

---

## 9. 清理记录（本任务）

用户硬要求：`.work` 不存在；插件目录无临时脚本/导出/日志/node_modules；清理系统临时目录中本项目脚本（至少 `%TEMP%/t37-verify` 与 t43–t48 临时导出）。

### 9.1 删除清单

| 位置 | 内容 | 数量 | 大小 |
|---|---|---|---|
| `%TEMP%/t37-verify` | t37 独立验证脚本（content-audit/core-parity/reverse-probes/structure/waiver-check） | 5 文件 | 44 KB |
| `%TEMP%/t47-verify` | t47 增量验证脚本（doc-audit） | 1 文件 | 4 KB |
| `%TEMP%/t26-verify`、`%TEMP%/t31-verify` | 早期独立验证脚本 | 28 文件 | 264 KB |
| `%TEMP%/t22-*`、`t30-*`、`t31-*`、`t36-*`、`t37*`、`t46*`、`t47*` | 各任务 lint/测试/探针日志与 JSON 导出 | 约 80 个文件 | — |
| `%TEMP%/dsh-redblue-*`、`dsh-t22-*`、`dsh-t30-*`、`dsh-t35`、`dsh-t36-*`、`dsh-t46-*`、`dsh-review2`、`dshrb-*`、`dsh-wf-check` | 本项目历史临时脚本/文档副本/SVG 渲染/REA 测试包 | 约 40 项 | 约 5 MB |
| `%TEMP%/rea-caps.json`、`rb-gate-*`、`gate-limits.txt`、`workflow-limits.txt`、`wf-nocrlf.txt`、`r21*`、`lint-*`、asar 读取辅助脚本 | 探针输出/门禁样本/lint 输出 | 约 30 个文件 | — |
| **合计** | | **131 项** | **约 6.0 MB** |

删除方式：逐项 `rm -rf`（exit 0），删除前用显式名称/前缀清单核对，未触碰 DSH 运行时临时目录与其它项目文件。t43–t45/t48 未在该目录留下本项目命名导出（全目录扫描无匹配）；v0.2.0 刷新安装日志（`t49-install-refresh.log`）也已删除。

### 9.2 保留清单

| 保留项 | 原因 |
|---|---|---|
| `dsh-redblue/`（125 文件 / 4.2 MB，不含 `.git`；`.git` 1.6 MB 为版本库） | 交付物本体（16 技能/10 workflow/28 参考/schema/policy/tools/lib/preview/test/docs） |
| `dsh-redblue/docs/design-addendum-v0.2-reverse.md`、`docs/requirements.md`、`docs/design.md`、`docs/sanitization-rules.md`、`docs/verification-report.md`、`docs/review-notes.md`、`docs/smoke-report.md`、`docs/research-handoff.md` | 内部评审/设计资料，保留但不入包 |
| 工作区其它目录（`dsh-security/`、`dsh-sticky-notes/`、`.agent-teams/`、`.archify/` 等） | 非本任务范围，未触碰 |
| DSH 运行时临时目录（`%TEMP%/dsh-spill-*`、`dsh-subprocess-*`、`dsh-acl-*`、`dsh-workspace-changes-*` 等） | DSH 自身运行时数据，不属于本项目脚本 |
| 插件内 | 无 `node_modules/`、无 `.log`、无 `.py`、无临时脚本/导出/构建产物（逐项扫描为空） |

### 9.3 清理后的影响与恢复

- `.work` 自 v0.1 交付时删除后未重建；`sanitize-lint` 的 R1 `source-path` 存在性检查自动跳过（设计如此），**仍为 0 blocker**；`test/sanitize.test.mjs` 中依赖 `.work/sources` 的 1 条测试按设计 skip（115 pass + 1 skip）。
- `docs/verification-report.md`、`docs/smoke-report.md` 中 `.work/smoke/*` 的路径成为历史记录（原始产物已删除，结论与命令保留）。
- 需复核来源 provenance 时：按 [`NOTICE`](../NOTICE) 的四 pin 重新拉取上游（含 REA）到 `.work/sources/{acs,claude-red,strix,rea}`，lint 会恢复 `source-path` 校验。
- 未删除工作区内其它项目的临时文件（如 CC Switch 反编译脚本等），避免越界。

### 9.4 清理验证

```bash
test ! -d .work && echo work-cleaned
test ! -e "${TEMP:-/tmp}/t37-verify" && echo temp-cleaned
# 实测输出：work-cleaned / temp-cleaned
```

---

## 10. 打包白名单（`package.json files`，22 项）

```text
lib  skills  references  workflow  schema  policy  tools
docs/DETAIL.md  docs/preview.svg  docs/tool-runtime.md  docs/value-extraction.md
docs/assembly-report.md  docs/architecture.md  docs/architecture-plugin.svg
docs/architecture-workflow.svg  docs/install.md  docs/delivery-summary.md
cordis.patch.yml  NOTICE  LICENSE  README.md  icon.svg
```

- 22/22 路径存在（`files-ok 22`）；v0.2.0 新增的 `skills/red-reverse/`、`references/red/reverse-artifacts.md`、`workflow/reverse.js` 由目录条目（`skills`/`references`/`workflow`）覆盖。
- **不入包**：`docs/` 整目录、`docs/design-addendum-v0.2-reverse.md`、`docs/research-handoff.md`、其余内部评审文档、`test/`、`.git/`、`.work/`（不存在）、`node_modules/`。

---

## 11. 本任务变更（t49）

| 文件 | 变更 | 说明 |
|---|---|---|
| `docs/install.md` | 重写为 v0.2.0 | 16/10/28/44；REA 可选依赖（安装/MCP 注册/`REA_*`/Windows 缺失矩阵/blocked 降级）；标题、验证、重启、升级/回滚、排查、实测记录全部更新 |
| `docs/delivery-summary.md` | 重写为 v0.2.0 | 计数、REA lane、已知限制（含 F2/F3/F5、V-1..V-5、W1/W3、seal 自证、E2E waiver 等）、REA MIT 归属、清理记录 |
| `docs/preview.svg` | 更新预览图 | 技能/工作流计数更新为 16 技能 / 10 workflow，补充 reverse lane 与 44 门禁说明；保持独立 SVG、无脚本、无外部引用 |
| `docs/assembly-report.md` | V-6 状态收口 | §11 结论/V-6 行/§11.4 说明/§11.5 建议改为 “t46 已关闭”；新增 §11.6 后续状态（t46 关闭 + t49 文档更新） |

未改：插件实现（`lib/`、`skills/`、`references/`、`workflow/`、`tools/`、`test/`、`policy/`、`cordis.patch.yml`）、`package.json`、README/DETAIL、冻结的 design/requirements。`package.json files` 已覆盖全部随包文档与架构图（22 项），无需变更。

---

## 12. 验证证据索引

| 证据 | 位置 |
|---|---|
| v0.2.0 最终复审（F1–F5、门禁/降级/内容/入口） | [`review-notes.md`](review-notes.md) §18 |
| t43+t46 增量验证（run/lib 一致、116 测试） | [`verification-report.md`](verification-report.md) §19 |
| v0.2.0 独立验证（16/10、探测降级、零回归） | [`verification-report.md`](verification-report.md) §18 |
| v0.2.0 装配与偏差受理（V-1..V-8） | [`assembly-report.md`](assembly-report.md) §11（含 §11.6 状态更新） |
| 逆向 lane 设计基线 | [`design-addendum-v0.2-reverse.md`](design-addendum-v0.2-reverse.md) |
| 安装/验证/REA/回滚 | [`install.md`](install.md) |
| 装载链与执行架构 | [`architecture.md`](architecture.md)、两张 SVG |
| E2E 冒烟（v0.1 历史，waiver） | [`smoke-report.md`](smoke-report.md) §11、[`verification-report.md`](verification-report.md) §15.6 |

---

## 13. 交付验收清单

- [x] 16 技能 / 10 workflow / 28 参考 + INDEX / 6 schema / 10 recipes / 44 门禁齐全且相互一致
- [x] 净化门禁 `--strict` 90 文件 0 blocker（2 条 R11 已受理）
- [x] 测试 116 个（115 pass + 1 skip + 0 fail）、`node --check` 28/28
- [x] reverse 25 类拒绝构造、6/6 blocked、runtime 四条件不可绕过、0 agent；v0.1 门禁零回归
- [x] desktop profile link 刷新（exit 0）、解析版本 0.2.0、dependencies + bundles 双命中、provider 16 项
- [x] 安装文档含 REA 可选依赖（安装/MCP 注册/环境变量/Windows 缺失矩阵/blocked 降级）、升级/回滚、重启/排查
- [x] 交付摘要为 v0.2.0 口径，含 REA lane、已知限制与四上游许可（含 REA MIT）
- [x] 预览图与架构图入册；`package.json files` 22 项全存在；scaffold 16/16
- [x] `.work` 不存在；系统临时目录本项目 131 项已清理；插件目录无临时脚本/日志/node_modules
- [x] 未修改插件实现与被评审内容（除本任务 in-scope 的 4 个文档文件）
- [x] 许可与归属（NOTICE 四 pin + MIT 全文 + 修改声明；REA 不打包）

**结论：可交付（v0.2.0）。** 剩余项均为 §7 已列明的 low/受理限制，不阻塞交付；用户需重启 Desktop 完成生效。