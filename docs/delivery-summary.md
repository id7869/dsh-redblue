# dsh-redblue 0.1.0 交付摘要

> 交付日期：2026-11-20
> 交付形态：DSH Desktop Cordis bundle + 15 个 bundled 技能 + 9 个原生 workflow 胶囊 + 零依赖工具运行时
> 许可：Apache-2.0（上游方法论文本按 NOTICE 归属）
> 最终判定：**PASS（0 blocker）** —— t27 最终复审（当前字节）+ t32 t30 增量复审（hunt 技能目录修复）

---

## 1. 交付结论

| 项 | 结果 |
|---|---|
| 规格 | 15 技能 / 9 workflow / 27 参考 + INDEX / 6 schema / 2 policy / 10 recipes / 39 G-* / 36 净化检查 |
| 净化门禁 | `sanitize-lint --strict`：**87 文件、0 blocker、2 warning**（R11 已受理），exit 0 |
| 测试 | **99 个**（scaffold 9 / sanitize 24 / workflow 43 / tool-runtime 23）；清理 `.work` 后 98 pass + 1 条按设计 skip |
| 语法 | 27/27 `.js/.mjs` 通过 `node --check`（lib 1 / workflow 9 / tools 2 / tools-lib 11 / test 4） |
| 安全负向 | t26 全量 17/17 拒绝构造（缺 scope、通配、越界路径、exclusions、mode、confirm、activeScan、未知 kind、超宽 CIDR、过期授权、超限 reference/targets、未知 args、窗口越界）均 `rejected/exit1/0 agent`；t32 在 t30 后复验 9 类仍全部拒绝 |
| 门禁保持 | t20/t22/t30 修复后 G-* 语义与顺序未弱化（9 workflow 的 normalization/exclusions/limits 段哈希一致；gate 与 workflow 同源） |
| provider | `dsh-redblue`，`inject=["skills"]`，`list()` 返回 **15** 项，rank 600，`source="bundled"` |
| 安装 | desktop profile：`link:` 安装 exit 0，`dependencies` 与 `dsh.profile.bundles` 均含 `dsh-redblue`（详见 [install.md](install.md)） |
| 打包 | `package.json files` **22 项**，全部存在；`docs/research-handoff.md` 内部留痕保留但**不入包** |
| 临时产物 | `.work/` 已整体删除（5,786 文件 / 75 MB），插件与工作区无临时脚本/导出/构建产物/日志/node_modules |

---

## 2. 交付清单

### 2.1 技能（15）

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

实现：`lib/index.js` 单 provider（`ctx.skills.registerProvider`，rank 600）；正文以 `skills/<dir>/SKILL.md` frontmatter 为单一事实源，文件不可读时才回退内置常量。

### 2.2 原生 workflow（9）

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

统一 args：`scope` / `workDir` / `skillDir` / `maxConcurrency`（1–8，默认 2）/ `dryRun`（默认 true）；`exploit`/`post` 增加 `confirm`；`recon` 增加 `activeScan`；未知键 `G-ARG-01`。
产物：`findings.json`、`coverage.json`、`report.md`、`exports/results.sarif`（SARIF 2.1.0）、`scan-manifest.json` + 阶段产物；退出码 `0`/`2`/`1`。

### 2.3 参考库（27 + INDEX）

- **shared 4**：evidence-standards、report-format、finding-review、script-patterns（S1–S7 + A1–A12）
- **red 13**：scope-roe、recon-osint、surface-threat-model、discover-web-api、discover-cloud-container、discover-identity-ad、discover-ot-mobile-iot、discover-wireless、exploit-controlled、post-readonly、tool-recipes（F1–F16）、strix-techniques、extraction-ledger
- **blue 9**：hunt-hypothesis、detect-engineering、dfir-playbook、harden-baseline、tool-recipes（B1–B12）、extraction-ledger、templates/{sigma.yml, kql.md, spl.md}
- **purple 1**：coverage-matrix

加载预算：每阶段最多 2 篇、合计 ≤120 KiB；每篇 ≤48 KiB；27/27 带六键 provenance（repo/commit/license/path/last-verified/rewrite-summary）。

### 2.4 工具运行时与门禁工具

- `tools/sec.mjs`（零第三方依赖，Node ≥20）：`scope check`、`evidence hash|verify`、`sarif convert`、`ioc extract`（默认 defang）、`log normalize`、`rule lint`、`recipes list|show`、`guard`（白名单受控执行）。
- `tools/recipes.json`：10 条白名单配方（`dns_lookup`、`http_headers`、`tls_certificate`、`port_scan`、`vuln_scan`、`web_fuzz`、`pcap_read`、`file_hash`、`certificate_query`、`runtime_probe`）。
- `tools/lib/*.mjs` 11 个模块（gate/guard/evidence/sarif/ioc/log/rule/recipes/cli/policy/…）；`guard` 与 9 个 workflow 的 scope 限制同源（R1 修复）。
- `tools/sanitize-lint.mjs`：R1–R12 / 36 条检查，`--strict` 0 blocker 才可发布；`--policy` 默认拒绝（需 `NODE_ENV=test` 或显式 `--allow-policy-override`）。

### 2.5 架构图与文档

| 文件 | 说明 | 入包 |
|---|---|---|
| `docs/architecture.md` | 装载链 + workflow/skill 执行架构（Mermaid 源 + 执行说明 + 39 G-* + 实测自查） | ✅ |
| `docs/architecture-plugin.svg` | 插件装载与目录分层图（1440×1117，手写独立 SVG） | ✅ |
| `docs/architecture-workflow.svg` | 意图路由→门禁→阶段→产物→seal 执行图（1440×1600，手写独立 SVG） | ✅ |
| `docs/install.md` | 安装/验证/重启/升级/卸载/回滚/跨 profile/排查/安全前置 | ✅ |
| `docs/delivery-summary.md` | 本文件：交付清单/触发/门禁/限制/许可/清理 | ✅ |
| `docs/DETAIL.md`、`docs/preview.svg`、`docs/tool-runtime.md`、`docs/value-extraction.md`、`docs/assembly-report.md` | 详情页、预览图、工具运行时、价值提炼账、装配报告 | ✅ |
| `docs/requirements.md`、`docs/design.md`、`docs/sanitization-rules.md`、`docs/verification-report.md`、`docs/review-notes.md`、`docs/smoke-report.md` | 需求/设计/净化规则/验证报告/复审记录/冒烟报告（内部评审资料） | ❌（不入包） |
| `docs/research-handoff.md` | 三上游研究交接（内部留痕，保留文件） | ❌（不入包） |

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

运行方式：读取 `workflow/<script>.js` 全文 → DSH 原生 `workflow` 工具执行 → `args` 传 `scope/workDir/skillDir/dryRun`（默认 report-only）→ 按 `status/exitCode` 转述，产物在 `workDir`。最小 scope 样例见 [install.md](install.md) §6.3（已用 `scope check` 实测通过）。

---

## 4. 门禁摘要

### 4.1 39 项硬拒绝 `G-*`（`policy/authorization.md` §4）

| 组 | ID | 数量 |
|---|---|---|
| 参数/路径/配置 | `G-ARG-01`、`G-PATH-01..03`、`G-CONC-01`、`G-CONF-01` | 6 |
| 授权 | `G-AUTH-01..07` | 7 |
| 目标 | `G-TGT-01..04` | 4 |
| 模式 | `G-MODE-01..03` | 3 |
| 时间窗/预算/数据处置 | `G-WIN-01..03`、`G-BUD-01`、`G-DH-01..03` | 7 |
| 数据源 | `G-DS-01..07` | 7 |
| 二次确认 | `G-CFM-01..04` | 4 |
| 写盘前置 | `G-OUT-01` | 1 |

- 拒绝语义：`status="rejected"`、`exitCode=1`、`rejectedBy=[...]`、`artifacts=[]`、`sealed=false`，**0 个 agent**、不写产物（`G-OUT-01` 例外地由首阶段在写盘前判定）。
- `G-EXEC-01` 是 `guard` 专用拒绝码，不在这 39 项注册表内。

### 4.2 默认 report-only 与受控执行

- `dryRun=true`（默认）：零目标侧动作，只读本地文件并写 `workDir` 产物；`activeScan=true` 需 `mode≥active` 且 `dryRun=false`。
- `guard --execute` 六条件：written 授权 + `scope.mode ≥ recipe.requiredMode` + target 命中 allowlist + `--confirm` 与 target 完全相等 + 目标二进制存在 + scope 通过检查；任一不满足 exit 1 且不 spawn。
- argv 逐元素替换、`spawn(shell=false)`、固定 timeout（默认 120s）与输出上限（默认 1 MiB）；evidence JSONL 只落 recipe/target/argv/时间/退出码/输出哈希，不落原文。

### 4.3 内容净化门禁

`R1–R12 / 36 检查`：来源许可（R1）、保留域/占位符（R2）、无武器化制品（R3）、授权门禁与 dryRun 默认（R4）、不制造虚假内容（R5）、结构上限（R6）、去重/触发隔离（R7）、提示注入边界（R8）、时效标注（R9）、机密与隐私（R10）、术语（R11）、风险分级与 report-only（R12）。当前 **0 blocker**，2 条 `R11-TERMINOLOGY` warning（purple-verify、red-exploit）因 design 固定 description 与 findings 字段名冲突而受理（assembly-report §4）。

---

## 5. 安装状态（本机，2026-11-20）

| 项 | 结果 |
|---|---|
| profile | `C:/Users/<you>/.dsh/profiles/desktop` |
| 安装命令 | `dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue` |
| 退出码 | **0**（`Done in 33s using pnpm v11.28.5`） |
| dependencies | `"dsh-redblue": "link:C:/dsh-workspace/branch1/dsh-redblue"`（package.json:14） |
| bundles | `dsh.profile.bundles` 含 `dsh-redblue`（package.json:36，14→15） |
| 列表 | `dsh-redblue@link:../../../../../dsh-workspace/branch1/dsh-redblue`（`dsh plugin --profile desktop list`，13 packages） |
| provider 冒烟 | `list()` = **15**，`dsh-rb-run` … `dsh-rb-triage`，rank 600 |
| 符号链接 | `node_modules/dsh-redblue` → `C:\dsh-workspace\branch1\dsh-redblue` |
| 安装前备份 | `package.json.bak-dsh-redblue-20261120-103600`（sha256 `7f327a33…`）；`cordis.patch.yml` 未被改动（sha256 `6924dedb…`） |
| 生效状态 | **未声称已生效**；需完全退出并重启 Desktop 后按 [install.md](install.md) §5 三条判定 |

其它 profile（web/headless/qqbot）本任务未安装，命令与注意事项见 [install.md](install.md) §9。

> **安装副作用（已核实，如实记录）**：pnpm 在 profile 目录重算依赖图（本机 `+1 -56`，清理了不在 lockfile 图内的旧包），并尝试构建可选依赖 `cpu-features`（ssh2 传递依赖）失败但命令 exit 0。安装后 `node_modules` 共 278 个条目，13 个直接依赖模块均在位（含 `dsh-security`、`dsh-ops`、`dsh-mnemon`、`ds-bot`、`dsh-im`、`dsh-agent-teams` 等），未发现其它插件模块缺失。若后续发现其它插件异常，按 install.md §8.2 恢复备份并重装。

---

## 6. 已知限制（交付时必须知悉）

### 6.1 验证期观察（W1–W3，均非阻塞）

- **W1（low）**：`guard` 缺少 `--scope` 时返回 **exit 2**（usage 语义），而非字面要求的 1；不 spawn、不读目标，**不是门禁绕过**。
- **W2 / R10（low）**：`rule lint` 不剥离行内 `#` 注释，自带 `references/blue/templates/sigma.yml` 被自身 linter 判 exit 1；正式规则把注释移到独立行即可。
- **W3（low，环境）**：Node 24 的 `node --test dsh-redblue/test/` 目录形式失败；用 `node --test dsh-redblue/test/*.test.mjs` 或 `npm test`。

### 6.2 架构语义限制

- **seal 自证**：`seal` 阶段是 **agent 只读复核**（计算实际 SHA256/字节并返回 expected/actual）+ 脚本确定性生成 `scan-manifest.json`；workflow 脚本无 fs，`sealed=true` 是复核证据，**不是密码学保证**。外部可用 `node tools/sec.mjs evidence verify --manifest <workDir>/scan-manifest.json --dir <workDir>` 或独立 SHA256 工具复算。
- **内联脚本未落盘**：DSH 原生 `workflow` 工具不持久化脚本副本（本机 `.dsh/workflow-runs/` 无记录），无法对“提交给工具的脚本文本”做字节级复核；行为一致性（门禁/产物/哈希）支持“内联的是磁盘同源版本”，但不是字节级证明。
- **数据源仅本地导出**：不实现 SIEM/EDR/云 API 连接器；`hunt/ir/purple/triage/harden` 的 `dataSources` 必须是本地文件（Windows 绝对路径，无 `..`）。
- **可选二进制缺失**：离线命令照常工作；相关配方 `--execute` 会被拒绝（`G-EXEC-01`），dry-run 仍能看到 `binaryAvailable=false`。
- **超时/输出上限只作用于直接子进程**：配方二进制若自行派生后台进程，需操作者在授权环境内清理。

### 6.3 冻结文档偏差（design/requirements 冻结，已受理 R8）

实现为运行期事实源；以下为已受理的文档债，下一版设计评审核对同步：

- `design` §6.8/§6.9：triage/harden 仍写无 `report` 阶段；实现为 `…→report→seal`。
- `design` §8.5：seal 未加 attestation 字段；manifest 结构与 schema 未改。
- `requirements` §9.3 / `design` §6.5 / `skills/{blue-hunt,detect}` 内联表：G-DS-01 仍写 4 类 kind；实现/policy 已为 6 类（`siem/edr/logs/pcap/cloudtrail/telemetry-export`）。属“文档比实现窄”，不构成门禁弱化。
- `design` §8.2：`schema/finding.schema.json` 的 5 个可选复核字段（`confidenceRationale`/`counterevidence`/`severityChangeConditions`/`fixVerification`/`basis`）未写入设计字段表。
- `design` §7.2：CIDR 写 0–32；运行期以 policy + 9 workflow/`gate.mjs` 为准（IPv4 /8–/32、IPv6 /32–/128），更宽 CIDR 属设计变更。

### 6.4 文档与观察项

- **R9（low）**：`skills/blue-hunt/SKILL.md`、`skills/detect/SKILL.md` 的内联 dataSources 表仍写 4 类（见 6.3）。
- **R11 受理**：2 条 `R11-TERMINOLOGY` warning（purple-verify / red-exploit），原因见 assembly-report §4。
- **O-1 / O-2（low）**：t30 完成说明中“合成 `rb-run` 反向验证”未落在测试文件（机制上仍会被 `skills/<dir>/SKILL.md` 存在性断言拦截）；阶段目录测试提取器依赖双引号字面量形态。
- **architecture.md 时序漂移（low）**：`docs/architecture.md` §2 表与 §5.5 写于 t28，仍把 hunt 的 scope 技能目录记为 `rb-run`；t30 已修复为 `run`（`workflow/hunt.js:1462`，`grep rb-run workflow/` = 0）；交付收口时已同步文档（§2 表与 §5.5 更新为 `run`，历史注记保留）。
- **输入 scope 白名单**：输入只接受 9 个键；`workDir/scope.json` 产物额外含 `schemaVersion`/`scopeDigest`/`validatedAt`，不可回灌为输入（会触发 `G-CONF-01`）。
- **未做**：未重跑原生 workflow E2E（以 `node:vm` 宿主验证）、未运行真实配方/网络、未安装到其它 profile、未执行卸载/升级命令（避免破坏性验证）。

---

## 7. 许可与归属

- 插件原创部分：**Apache-2.0**（[`LICENSE`](../LICENSE) 全文）。
- 三上游方法论文本在固定 commit 上**改写、压缩、净化**后使用；不含上游可执行脚本、agent 运行时或课程原文：

| 上游 | commit | 许可 | 用途 | 排除 |
|---|---|---|---|---|
| Claude-Red（SnailSploit） | `6196ba7464662de34e8744d359f175d1a7bca530` | MIT | recon/web/api/cloud/container/AD/wireless/exploit-dev/post/privesc 方法论改写 | 4 门课程 dump、持久化/C2/外传配方、武器化制品 |
| Anthropic-Cybersecurity-Skills | `54a798831d2266a3ca61ce68a7acb80b81160d57` | Apache-2.0 | 蓝队检测/狩猎/DFIR/加固方法论、红队缺口补充、检测模板与脚本纪律 | 809 个 `agent.py`、逐技能 LICENSE 副本、课程 dump |
| Strix | `8db295a5b3564be2b430bb3a9afdb4db7850fa24` | Apache-2.0 | agent 作业纪律、预算/scope 纪律、SARIF/退出码约定、门禁设计、78 篇内部技术压缩 | Strix 运行时、Docker 依赖、CLI、知识库原文件 |

- [`NOTICE`](../NOTICE) 含三 pin、MIT 全文与修改声明；27 篇参考与技能文件带六键 provenance 头。**移除 NOTICE / provenance 视为破坏许可合规。**
- 图标与预览图（`icon.svg`、`docs/preview.svg`）为本插件原创 SVG，无外部引用资源。

---

## 8. 清理记录（`.work` 整体删除）

用户硬要求：删除整个 `.work`（sources/tmp/smoke），确认无临时脚本/导出/构建产物/日志/node_modules。

### 8.1 删除清单（2026-11-20 10:40，`rm -rf .work`，exit 0）

| 路径 | 内容 | 文件数 | 大小 |
|---|---|---|---|
| `.work/sources/` | 三上游固定 commit 快照：`acs/`、`claude-red/`、`strix/` | 5,267 | 70 MB |
| `.work/tmp/` | 研究/验证临时脚本与导出：`gen-ledger.{mjs,py}`、`acs-*.mjs/json`、`t7-*.mjs/log/json/sh`、`verify-t4.mjs`、`probe-atfile.js` 等 | 56 | 500 KB |
| `.work/smoke/` | 5 次 E2E 冒烟产物目录（assess×3、recon×1、neg×1） | 462 | 3.9 MB |
| `.work/tmp_r8_gates.mjs` | 门禁探针脚本（根级散落） | 1 | — |
| **合计** | | **5,786** | **75 MB** |

### 8.2 保留清单

| 保留项 | 原因 |
|---|---|
| `dsh-redblue/`（清理时 118 文件 / 2.3 MB；加入本文与 `install.md` 后 120 文件 / 2.4 MB） | 交付物本体（技能/workflow/参考/schema/policy/tools/lib/test/docs） |
| `dsh-redblue/docs/research-handoff.md`（21,919 B） | 三上游研究内部留痕；**保留但不入包**（不在 `files` 白名单，scaffold 断言守护） |
| `dsh-redblue/docs/{requirements,design,sanitization-rules,verification-report,review-notes,smoke-report}.md` | 内部评审资料，保留但不入包 |
| 工作区其它目录（`dsh-security/`、`dsh-sticky-notes/`、`.agent-teams/` 等） | 非本任务范围，未触碰 |
| 插件内 | 无 `node_modules/`、无 `.log`、无 `.py`、无临时脚本/导出/构建产物（逐项扫描为空） |

### 8.3 清理后的影响与恢复

- `.work` 删除后，`sanitize-lint` 的 R1 `source-path` 存在性检查自动跳过（设计如此：`sourceRoot()` 找不到 `.work/sources` 时返回 null），**仍为 0 blocker**；`test/sanitize.test.mjs` 中依赖 `.work/sources` 的 1 条测试按设计 skip（98 pass + 1 skip）。
- `docs/verification-report.md`、`docs/smoke-report.md` 中 `.work/smoke/*` 的路径成为**历史记录**（原始产物已删除，不可再复算；结论与命令仍保留）。
- 需复核来源 provenance 时：按 [`NOTICE`](../NOTICE) 的三 pin 重新拉取上游到 `.work/sources/{acs,claude-red,strix}`，lint 会自动恢复 `source-path` 校验（详见 `docs/sanitization-rules.md` R1 覆盖范围）。
- 未删除 `.archify/`（工作区内 archify 工具缓存，属其它任务产物，不在本任务 in-scope）。

### 8.4 清理验证

```bash
test ! -d .work && echo work-cleaned
# 实测输出：work-cleaned
```

---

## 9. 打包白名单（`package.json files`，22 项）

```text
lib  skills  references  workflow  schema  policy  tools
docs/DETAIL.md  docs/preview.svg  docs/tool-runtime.md  docs/value-extraction.md
docs/assembly-report.md  docs/architecture.md  docs/architecture-plugin.svg
docs/architecture-workflow.svg  docs/install.md  docs/delivery-summary.md
cordis.patch.yml  NOTICE  LICENSE  README.md  icon.svg
```

- 22/22 路径存在（`files-ok 22`）。
- **不入包**：`docs/` 整目录、`docs/research-handoff.md`、其余内部评审文档、`test/`、`.work/`（已删除）、`node_modules/`。

---

## 10. 验证证据索引

| 证据 | 位置 |
|---|---|
| 最终复审（当前字节，F1/F12/R1–R8/净化/价值层） | [`review-notes.md`](review-notes.md) §16 |
| t30 增量复审（hunt 技能目录修复 + 回归测试） | [`review-notes.md`](review-notes.md) §17 |
| 独立全量验证（门禁/负向/指标/E2E 只读） | [`verification-report.md`](verification-report.md) §15 |
| t30 增量验证（阶段目录存在性） | [`verification-report.md`](verification-report.md) §16 |
| E2E 冒烟与早期验证 | [`smoke-report.md`](smoke-report.md)、[`verification-report.md`](verification-report.md) §10–§14 |
| 装配、修复、偏差与受理 | [`assembly-report.md`](assembly-report.md) §1–§10 |
| 净化规则与 R1–R12 | [`sanitization-rules.md`](sanitization-rules.md) |
| 安装/验证/回滚 | [`install.md`](install.md) |
| 装载链与执行架构 | [`architecture.md`](architecture.md)、两张 SVG |

---

## 11. 交付验收清单

- [x] 15 技能 / 9 workflow / 27 参考 + INDEX / 6 schema / 10 recipes / 39 G-* 齐全且相互一致
- [x] 净化门禁 `--strict` 87 文件 0 blocker（2 条 R11 已受理）
- [x] 测试 99 个（清理后 98 pass + 1 skip）、`node --check` 27/27
- [x] 安全负向 17/17 拒绝且 0 agent；G-* 未弱化
- [x] desktop profile link 安装（exit 0）、dependencies + bundles 双命中、provider 15 项
- [x] 安装文档含安装/卸载/回滚/跨 profile/升级/重启/排查/安全前置
- [x] 架构图与新增文档入册（22 项白名单，scaffold 断言通过）
- [x] `.work` 整体删除（5,786 文件 / 75 MB），无临时脚本/导出/构建产物/日志/node_modules
- [x] 未修改插件实现与被评审内容（skills/workflow/tools/lib/references/policy/test）
- [x] 许可与归属（NOTICE 三 pin + MIT 全文 + 修改声明）

**结论：可交付。** 剩余项均为 §6 已列明的低风险/已受理限制，不阻塞交付。