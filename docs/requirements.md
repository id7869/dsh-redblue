# dsh-redblue 需求基线（requirements）

- 插件名：`dsh-redblue`
- 版本：`0.1.0`
- 许可：Apache-2.0（见 §3 SC-9、§13 DL-4、design §12、sanitization R1）
- 文档状态：基线 v1，**后续所有实现/测试/评审任务的唯一需求决策源**
- 输入事实源：`docs/research-handoff.md`（Captain 实测与草案）+ 本文件 §2 的复测记录 + workspace 内 `dsh-security` 参考实现
- 正文中文、标识符英文；来源标注约定：`〔用户目标〕`= 用户目标，`〔handoff §x〕`= research-handoff 章节，`〔复测 F-x〕`= 本文件 §2.1，`〔标准实践：…〕`= 公开标准/规范，`〔假设待确认 H-x〕`= 本文件 §2.2

> 本文档只定义"做什么/拒绝什么/如何判定完成"。结构与契约细节见 `docs/design.md`，净化规则规范见 `docs/sanitization-rules.md`。

---

## 1. 目标

| ID | 目标 | 来源 |
|---|---|---|
| OBJ-1 | 为 DSH 桌面版（`profile=desktop`）提供**红蓝双覆盖**的安全测试插件：授权红队测试 + 蓝队检测/狩猎/DFIR/加固 + 紫队对齐。 | 〔用户目标〕、〔handoff §0〕 |
| OBJ-2 | 形态与 `dsh-security` 完全同构：Cordis bundle → `ctx.skills.registerProvider` 注册 bundled 技能 → 技能为 `SKILL.md` 分阶段方法论 → 编排由 **DSH 原生 `workflow` 工具**执行插件内 `workflow/*.js` 脚本。 | 〔用户目标〕、〔handoff §0/§2〕、〔复测 F-3〕 |
| OBJ-3 | **内容净化是核心门禁**：只保留 Strix / Anthropic-Cybersecurity-Skills（ACS）/ Claude-Red 的核心方法论，剔除武器化制品、虚假内容、课程灌水、真实第三方目标；净化规则可确定性判定、可失败、可复跑（R1–R12）。 | 〔用户目标〕、〔handoff §0/§5〕 |
| OBJ-4 | 安全默认不可绕过：默认 **report-only**、默认 `dryRun=true`、授权门禁、破坏性禁止、零依赖离线可运行。 | 〔用户目标〕、〔handoff §2.4/§5〕、〔标准实践：authorization scope / least change〕 |
| OBJ-5 | 可安装、可加载、可验证：`link:` 安装进 desktop profile，15 个技能全部可 `list/get`，9 个 workflow 可被原生 `workflow` 工具执行，产物可被 CI 与复核者消费（确定性 + SHA256 封存 + 退出码）。 | 〔handoff §2/§6〕、〔标准实践：SARIF 2.1.0 / reproducible artifact〕 |

## 2. 输入事实与复测记录

### 2.1 已复测事实（F）

复测环境：2026-11-19，工作区 `C:\dsh-workspace\branch1`，Windows + MSYS Bash；上游源码只读（`git` 只用于 `rev-parse`，未修改任何上游文件）。

| ID | 事实 | 来源 | 复测命令/方法 | 结论 |
|---|---|---|---|---|
| F-1 | DSH 版本 `0.2.2-rc.5` | 〔handoff §1〕 | `dsh --version` | 一致 |
| F-2 | desktop profile 存在；`dsh-security` 以 `link:C:/dsh-workspace/branch1/dsh-security` 安装，并列入 `dsh.profile.bundles` | 〔handoff §1〕 | 读 `~/.dsh/profiles/desktop/package.json` | 一致 |
| F-3 | `dsh-security`：17 个技能目录、5 个 workflow（`scan.js`/`diff.js`/`fix.js`/`track.js`/`triage.js`）、`lib/index.js` 硬编码 `BUNDLED_SKILL_RANK = 600`、2 个 schema、2 个测试文件 | 〔handoff §2〕 | `ls dsh-security/{skills,workflow,schema,test}`、`wc -c`、读 `lib/index.js` | 一致 |
| F-4 | Claude-Red：79 个 `SKILL.md` / 23 类目 / 合计 3,675,049 B；4 个课程巨型文件精确为 583,006 / 545,372 / 422,054 / 365,412 B（合计 1,915,844 B，占 52.1%） | 〔handoff §3.1〕 | `find Skills -name SKILL.md \| wc -l`、`wc -c`、`sort -rn` | 一致 |
| F-5 | Claude-Red frontmatter：0 个缺失；**18 个 description > 1024 字符**；**0 个含负向触发语**；另测得 40 个 > 500 字符、79 个全无 `whenToUse` 字段 | 〔handoff §3.1（原标"待实测复核"）〕 | Node 扫描 79 个文件 frontmatter | **已复测**：确认 18 与 0，并新增两项事实（>500 = 40、`whenToUse` = 0） |
| F-6 | ACS：818 个技能 / 818 个 `SKILL.md` / 809 个 `scripts/agent.py` / 817 个技能目录含独立 `LICENSE` | 〔handoff §3.2〕 | `ls skills \| wc -l`、`find skills -name … \| wc -l` | 一致 |
| F-7 | ACS 框架映射覆盖：ATT&CK 806（98.5%）、NIST CSF 805（98.4%）、D3FEND 139（17.0%）、NIST AI RMF 97（11.9%）、F3 94（11.5%）、ATLAS 93（11.4%） | 〔handoff §3.2（原标"待复核"）〕 | 统计 `SKILL.md` frontmatter 键 `mitre_attack`/`nist_csf`/`d3fend_techniques`/`nist_ai_rmf`/`mitre_f3`/`atlas_techniques` | **已复测**：6 项比例与 handoff 一致，并给出精确计数 |
| F-8 | ACS 809 个 `agent.py` 中 **35 个**含字面量 `verify=False`（handoff 记 38，计数口径未说明） | 〔handoff §3.2（原标"待复核"）〕 | `find skills -name agent.py -print0 \| xargs -0 grep -l "verify=False" \| wc -l` | **复测值 35**；设计不依赖 38 这一数字，仅依赖"存在不安全脚本层，故不打包任何 `agent.py`" |
| F-9 | Strix：9 个官方 `SKILL.md`（4,320–23,637 B），frontmatter 声明 `license: Apache-2.0`；CLI 使用退出码 `0/1/2` | 〔handoff §3.3〕 | `find strix/skills -name '*.md'`、`wc -c`、grep `strix/interface/main.py` 的 `sys.exit(0/1/2)` | 一致 |
| F-10 | 三上游 pin commit：claude-red `6196ba7464662de34e8744d359f175d1a7bca530`（MIT）、acs `54a798831d2266a3ca61ce68a7acb80b81160d57`（Apache-2.0）、strix `8db295a5b3564be2b430bb3a9afdb4db7850fa24`（Apache-2.0）；三者在 pin 点均无 `NOTICE` 文件 | 〔handoff §1/§3〕 | `git -C .work/sources/<repo> rev-parse HEAD`、读 `LICENSE` 首行、`ls NOTICE` | 一致 |
| F-11 | 本机未安装 Docker | 〔handoff §1〕 | handoff 实测（不重复执行） | 沿用：任何设计不得依赖 Docker/Strix 运行时 |
| F-12 | `dsh plugin` 只是把参数透传给 profile 目录内的 pnpm（`dsh plugin --help`：`forwarding the remaining arguments to pnpm in the profile directory`） | 〔复测 F-12〕 | `dsh plugin --help` | 影响安装步骤：bundle 列表需显式确认/补充（见 IR-2、H-5） |

### 2.2 假设待确认（H）

无支撑或无法离线核实的条目一律标为假设，**不得作为实现依据的硬事实**：

| ID | 假设内容 | 影响 | 处置 |
|---|---|---|---|
| H-1 | 上游 ACS 的 GitHub issue #103（运行时崩溃）与 PR #106 状态无法离线核实 | 仅影响"上游质量"叙述，不影响设计 | 设计不依赖该结论；仅按 F-6/F-8 的本地事实决策 |
| H-2 | handoff "22 个脚本无授权门禁"的口径不可复现（本次测得 303/809 个 `agent.py` 含 `authorization` 字样、35 个含 `verify=False`） | 仅影响风险叙述 | 以 F-8 为决策依据；不引用"22" |
| H-3 | 插件版权人/组织署名未确定 | NOTICE 与 package.json `author` 字段 | NOTICE 用 `dsh-redblue contributors`，待产品方确认后替换 |
| H-4 | TPM 限流的具体阈值未量化；`maxConcurrency=2` 是保守默认 | 并发默认值 | 按 handoff 执行偏好固定：默认 2、允许 1–8 |
| H-5 | `dsh plugin add link:` 是否会自动把包写入 `dsh.profile.bundles` 未实测（profile 中为显式列表，CLI 仅透传 pnpm） | 安装步骤 | 安装流程显式包含"确认/补充 bundles"步骤；失败可回滚（IR-7） |
| H-6 | 原生 workflow 脚本沙箱是否提供 `URL`/`crypto`/`fetch` 等全局未逐一验证 | 脚本实现方式 | 设计规定：脚本只使用 ECMAScript 标准内建，SHA256/FNV 自实现（与 dsh-security 同法），不依赖上述全局 |
| H-7 | `agent()` 并发上限与 TPM 限流的量化关系未知 | 并发策略 | 保守：默认 2，批量阶段用 `parallelLimited` 分批 |
| H-8 | 插件 `icon.svg` 的视觉规范（桌面详情页外观）未定 | 非核心交付 | 采用与 dsh-security 同形态的最小 SVG，不阻塞功能验收 |

## 3. 范围（In scope）

| ID | 范围项 | 来源 |
|---|---|---|
| SC-1 | 15 个 bundled 技能（红/蓝/紫/门禁 4 类），每技能 `SKILL.md` ≤300 行且 ≤24 KiB，`description` ≤500 字符。 | 〔handoff §4.1/§5 R6〕 |
| SC-2 | 9 个原生 workflow 脚本：`assess` `recon` `exploit` `post` `hunt` `ir` `purple` `triage` `harden`，统一 args 与门禁。 | 〔handoff §4.2〕 |
| SC-3 | 授权对象 `scope` 的 JSON Schema 与硬门禁实现。 | 〔handoff §4.3〕、〔用户目标：授权门禁〕 |
| SC-4 | 产物与封存：`findings.json`、`coverage.json`、`exports/results.sarif`（SARIF 2.1.0）、`report.md`、`scan-manifest.json`，以及各 workflow 的阶段产物。 | 〔handoff §2.4/§4.2〕、〔标准实践：SARIF 2.1.0〕 |
| SC-5 | 净化规则 R1–R12 的可执行检查工具 `tools/sanitize-lint.mjs`（零依赖）与策略文件 `policy/`。 | 〔handoff §5〕、〔用户目标：内容净化〕 |
| SC-6 | 派生参考库 `references/{shared,red,blue,purple}/*.md`（每篇 ≤48 KiB，带 provenance 头）与 `references/INDEX.md`。 | 〔handoff §4/§5 R1/R6〕 |
| SC-7 | 测试：scaffold/provider 契约、sanitize 门禁、workflow 门禁（缺 scope/越界/模式不足/确认串不符必须拒绝）。 | 〔handoff §6〕 |
| SC-8 | 文档：`requirements.md`、`design.md`、`sanitization-rules.md`，以及安装/验证记录（后续任务补齐）。 | 〔用户目标〕、〔handoff §4〕 |
| SC-9 | 许可与归属：Apache-2.0 `LICENSE`、`NOTICE`、每篇 provenance 头、三个上游 commit 固定。 | 〔handoff §0/§4〕、〔标准实践：Apache-2.0 §4、MIT〕 |

## 4. 非目标（Out of scope）

照 handoff 第 7 节定稿，并补两条边界：

| ID | 非目标 | 来源 |
|---|---|---|
| NG-1 | **不打包** ACS 的 809 个 `agent.py` 脚本；不发布任何可执行攻击代码。 | 〔handoff §7-1〕 |
| NG-2 | **不依赖** Strix 运行时 / Docker / 云 API；不把 Strix CLI 装进插件。 | 〔handoff §7-2〕、〔F-11〕 |
| NG-3 | **不搬运** Claude-Red 4 个课程巨型文件（583/545/422/365 KB）；不做整篇复制，一律压缩改写。 | 〔handoff §7-3〕、〔F-4〕 |
| NG-4 | 插件不自动对真实目标发起攻击：它产出方法论与**受门禁的编排**；实际命令在授权环境由 agent 执行。 | 〔handoff §7-4〕 |
| NG-5 | 不做自定义 Web UI / 主题 / 详情页之外的客户端插件；与 `dsh-security` 保持同形态。 | 〔handoff §7-5〕 |
| NG-6 | **不修改** `dsh-security` 与上游 sources。 | 〔handoff §7-6〕 |
| NG-7 | 不承诺合规认证结论（CIS/ISO/等保判定不在范围）。 | 〔handoff §7-7〕 |
| NG-8 | 不实现遥测平台连接器（SIEM/EDR/云 API 查询）：所有数据源必须是本地导出文件；插件零网络。 | 〔复测 F-3、用户目标：零依赖〕 |
| NG-9 | 不提供多租户、计费、任务队列、持久化数据库或跨运行状态服务；状态仅限单次 `workDir` 产物。 | 〔标准实践：最小面〕、〔用户目标：零依赖〕 |

## 5. 用户场景

### 5.1 红队场景（授权测试）

| ID | 场景 | 输入 | 流程（workflow） | 产物 | 关键门禁 |
|---|---|---|---|---|---|
| SCN-R1 | 完整授权渗透测试（黑盒，资产已知） | 书面授权 + `scope.targets` + 时间窗 + 预算 | `assess`：scope→recon→surface→discover→validate→report→seal | findings.json、coverage.json、report.md、SARIF、manifest | 全部门禁；默认 `dryRun=true`（0 目标侧动作） |
| SCN-R2 | 攻击面快速评估（被动优先） | 授权 + 目标域名/URL；不要求主动扫描 | `recon`：scope→recon→surface→report→seal | recon.json、surface.json、findings.json（exposure）、coverage.json、report.md、SARIF、manifest | `activeScan` 仅在 `mode≥active` 且 `dryRun=false` 时可用 |
| SCN-R3 | 已验证漏洞的受控利用与后渗透影响验证 | `mode ∈ {exploit, post}` + `confirm:"<target>"` + `dryRun=false` + `dataSources.kind="findings"` | `exploit`：scope→validate→exploit→report→seal；`post`：scope→post→report→seal | exploit-log.json / post.json、findings.json、report.md、SARIF、manifest | `confirm` 必须精确等于一个精确目标；禁止持久化/破坏性动作 |

### 5.2 蓝队场景（检测、狩猎、DFIR、加固）

| ID | 场景 | 输入 | 流程（workflow） | 产物 | 关键门禁 |
|---|---|---|---|---|---|
| SCN-B1 | 假设驱动威胁狩猎 | 本地遥测导出（`siem`/`edr`/`logs`/`telemetry-export`）+ ATT&CK 假设 | `hunt`：scope→hunt→report→seal | hunt-plan.json、hunt-results.json、findings.json、coverage.json | 无数据源即 `exit 1`（G-DS-01），不得编造 |
| SCN-B2 | 事件响应与时间线 | 本地证据目录（`evidence`） | `ir`：intake→triage→timeline→containment→report→seal | intake.json、timeline.json、containment.json、findings.json | 证据 SHA256 保全；时间线可复算；不自动执行遏制 |
| SCN-B3 | 加固基线核查与复测 | 基线导出文件 + `baseline.version`/`lastVerified` | `harden`：baseline→check→gaps→remediation→verify→seal | baseline.json、gaps.json、remediation.json（建议，不自动实施） | 基线缺版本/时效或 `lastVerified` 超 180 天即 `exit 1` |

### 5.3 紫队场景（红蓝对齐）

| ID | 场景 | 输入 | 流程（workflow） | 产物 | 关键门禁 |
|---|---|---|---|---|---|
| SCN-P1 | 红队动作→检测覆盖矩阵 | `findings`（dsh-redblue findings.json）+ `detections`（Sigma/KQL/SPL 规则目录） | `purple`：redActions→detectCoverage→gaps→report→seal | coverage-matrix.json、findings.json（检测缺口）、report.md | 缺 findings 或 detections 即 `exit 1`（G-DS-03） |
| SCN-P2 | 检测缺口排序与补测计划 | 同 SCN-P1 | 同上（`gaps` 阶段输出优先级与补测计划） | 同上 | 不得重复红队发现（R7 边界） |
| SCN-P3 | 外部 finding/告警入库 | 单条外部 finding JSON（`dataSources.kind=finding`） | `triage`：finding→review→disposition→write→seal | findings.json、state/findings.jsonl | 独立复核；不修改原 finding 的 `severity`；无输入即 `exit 1` |

> 三类场景均要求"先授权、后动作"：红队与紫队必须 `authorization.type="written"`；蓝队可用 `"internal-mandate"`（内部 IR/检测授权），但同样必须有授权引用、有效期与数据处置声明（§9）。

## 6. 与 dsh-security 的职责边界

| ID | 维度 | `dsh-security`（已装参考实现） | `dsh-redblue`（本插件） | 来源 |
|---|---|---|---|---|
| BD-1 | 目标对象 | 自有代码仓库/PR diff 的**静态审计** | **授权外部目标**（域名/URL/IP/源码树）的测试 + **运行中蓝队数据**（日志/证据/规则/基线） | 〔用户目标〕、〔handoff §2/§4〕 |
| BD-2 | 动作性质 | 只读静态分析（不改源码，除 `fix` 显式阶段） | 被动→主动→受控利用→后渗透（全部受 scope/mode/confirm/dryRun 门禁） | 〔handoff §2.4/§4.2〕 |
| BD-3 | 产物 | `findings.jsonl`、`classification.jsonl`、SARIF、`scan-manifest.json` | `findings.json`、`coverage.json`、`report.md`、SARIF 2.1.0、`scan-manifest.json`、`timeline.json`/`coverage-matrix.json` 等 | 〔handoff §4.2〕 |
| BD-4 | 触发隔离 | 入口 `dsh-security-run`；description 声明"源码审计" | 入口 `dsh-rb-run`；description 声明"红蓝测试"，并点名 `dsh-security-run` 为源码审计替代 | 〔handoff §4.1〕、〔handoff §2.1〕 |
| BD-5 | 复用边界 | — | 仅复用**形态与产物纪律**（provider/rank、workflow 胶囊、SARIF、退出码、SHA256 封存），**不 import 其代码、不共享 node_modules** | 〔handoff §2.4〕、〔用户目标：零依赖〕 |
| BD-6 | 共存与隔离 | 已安装于 desktop profile | 以独立 bundle `dsh-redblue` 安装；provider 名 `dsh-redblue`；技能名全部以 `dsh-rb-`/`dsh-red-`/`dsh-blue-`/`dsh-purple-` 前缀区分，无重名 | 〔复测 F-2/F-3〕 |

约束：`dsh-redblue` 不读取、不修改 `dsh-security` 的目录与产物；跨插件数据转换（例如把 `dsh-security` 的 JSONL 转成 redblue `findings.json`）**不在范围内**（SCN-P1 要求 `findings.json` 为本插件格式）。

## 7. 法律与合规约束

| ID | 约束 | 判定/落点 | 来源 |
|---|---|---|---|
| LC-1 | **书面授权前置**：红队/紫队/triage 工作流必须携带 `authorization.type="written"` 且 `reference`/`grantedBy`/`validFrom`/`validTo` 齐全；蓝队工作流可用 `"internal-mandate"`。缺任一即拒绝（`exit 1`）。 | G-AUTH-01..03、`policy/authorization.md` | 〔用户目标：授权门禁〕、〔标准实践：RoE〕 |
| LC-2 | **目标白名单**：`targets` 必须显式枚举且与 `confirm`/动作精确匹配；禁止通配、CIDR 全网、未列目标；`exclusions` 必须生效且优先于 targets。 | G-TGT-01..04 | 〔handoff §4.3〕 |
| LC-3 | **时间窗与预算**：仅在 `window.start ≤ now < window.end` 内执行；`budget.maxRequests ≤ 100000`、`maxMinutes ≤ 1440`；超出即拒绝。 | G-WIN-01..03、G-BUD-01 | 〔handoff §4.3〕、〔标准实践：engagement budget〕 |
| LC-4 | **数据处置**：默认 `retain="findings-only"`；`secrets="mask-and-redact"`（固定）；`destruction` 必须为 `"none"`（禁止破坏性），否则拒绝。 | G-DH-01..03 | 〔handoff §4.3〕、〔handoff §7-4〕 |
| LC-5 | **禁止武器化与破坏性**：不产出 webshell/反弹 shell/C2/凭据 dump/malware/真实密钥；禁止 `rm -rf /`、`dd of=/dev/*`、fork bomb、删除卷影等；确需示例必须带授权前置标注且仅用于检测/教学语境。 | R3 全部检查 | 〔handoff §5 R3〕、〔用户目标：内容净化〕 |
| LC-6 | **不持久化**：`post` 技能与工作流只做只读评估与报告；禁止写入定时任务/服务/注册表 Run 键/SSH key 等持久化机制；`dataHandling.destruction="none"` 与"不做持久化"共同保证可回滚。 | R3-AUTH-BANNER、R12-REPORT-ONLY、`dsh-red-post` 边界 | 〔handoff §4.1/§4.2〕、〔用户目标〕 |
| LC-7 | **停止条件**：出现以下任一情况必须中止并报告——生产影响迹象、发现范围外资产、可能触犯法律/合同、证据完整性受损、超出预算/时间窗。停止条件写入 `dsh-red-scope` 与每个红队 workflow 的阶段 prompt。 | `policy/authorization.md`、技能边界段 | 〔标准实践：RoE stop conditions〕 |
| LC-8 | **证据与数据保护**：证据文件必须记录 SHA256；报告不得包含明文凭据/令牌/个人数据（R10）；保留策略遵循 `dataHandling.retain`。 | R10、manifest/coverage 字段 | 〔handoff §4.2〕、〔标准实践：forensic integrity〕 |
| LC-9 | **披露与司法边界**：报告交付范围由授权方决定；不代替司法取证程序，不出具鉴定意见；未经批准不得公开披露。 | `dsh-blue-dfir` 边界、`dsh-rb-report` 交付字段 | 〔handoff §4.1〕、〔标准实践：disclosure〕 |
| LC-10 | **不作合规认证结论**：`harden` 只给基线差距与修复建议，不给出"通过/符合 CIS/ISO/等保"的结论。 | `dsh-blue-harden` 边界、report 字段 | 〔handoff §7-7〕 |

## 8. 安装与运行约束

| ID | 约束 | 判定/命令 | 来源 |
|---|---|---|---|
| IR-1 | 仅安装到 **desktop profile**（`~/.dsh/profiles/desktop`），不修改其他 profile。 | 安装与验证步骤只针对 `--profile desktop` | 〔用户目标〕、〔复测 F-2〕 |
| IR-2 | 以 `link:` 方式安装：`dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue`；随后**显式确认** `~/.dsh/profiles/desktop/package.json` 的 `dsh.profile.bundles` 含 `"dsh-redblue"`，缺失则补充（CLI 仅透传 pnpm，见 F-12/H-5）。 | 命令 + 读 profile package.json | 〔handoff §1〕、〔复测 F-12〕、〔假设 H-5〕 |
| IR-3 | 安装/更新后必须**重启 DSH** 才生效（bundle patch 在启动时应用）。 | 重启后 `dsh plugin --profile desktop list` 出现 `dsh-redblue`，15 个技能可 `list/get` | 〔handoff §2.1〕 |
| IR-4 | 安装前备份 profile `package.json`；失败可回滚（删除 bundles 条目与依赖、重启）。 | 备份文件 + 回滚命令写入安装记录 | 〔handoff §8 风险表〕 |
| IR-5 | **零依赖**：`dependencies`/`devDependencies` 为空；运行时不联网、不下载、不调用外部 CLI。 | `package.json` 校验 + 代码 grep（无 `fetch`/`http`/`child_process`） | 〔用户目标：零依赖〕、〔handoff §2.4〕 |
| IR-6 | **TPM 串行**：`maxConcurrency` 默认 `2`，允许 `1–8`；越界或非整数即拒绝（G-CONC-01）；批量阶段用 `parallelLimited` 分批。 | 各 workflow 的 args 校验与测试 | 〔handoff §1〕、〔假设 H-4/H-7〕 |
| IR-7 | Windows 路径：`workDir`/`skillDir`/`dataSources` 必须为 Windows 绝对路径（`^[A-Za-z]:[\\/]` 或 UNC）且不含 `..`；MSYS `/c/...` 形式会被拒绝并提示转换。 | G-PATH-01..03 | 〔handoff §1〕、〔标准实践：路径穿越防御〕 |
| IR-8 | workflow 脚本无文件系统/网络/Node API；只做 args 校验、阶段编排、确定性计算（哈希/SARIF/manifest/报告文本）、错误返回；所有读写由阶段 subagent 完成。 | 脚本语法与实现审查；测试用 vm stub | 〔handoff §2.3〕、〔假设 H-6〕 |
| IR-9 | 加载预算：每个 `SKILL.md` ≤300 行且 ≤24 KiB；每次加载 ≤3 篇 references、合计 ≤120 KiB；单篇 reference ≤48 KiB。 | R6 检查 + `references/INDEX.md` 映射 | 〔handoff §5 R6〕 |
| IR-10 | 交付前清理临时产物：`.work/sources`、临时脚本/导出文件不得进入插件目录或交付物。 | 交付检查清单 | 〔handoff §1 交付纪律〕 |

## 9. 授权对象 scope 需求

### 9.1 字段语义（结构以 design §7 的 JSON Schema 为准）

| 字段 | 类型 | 必填 | 语义/约束 | 来源 |
|---|---|---|---|---|
| `authorization.type` | `"written"｜"internal-mandate"` | 是 | 红队/紫队/triage 仅 `written`；蓝队二者皆可 | 〔用户目标〕、〔标准实践：RoE〕 |
| `authorization.reference` | string | 是 | 授权编号/合同号，非空（≤200 字符） | 〔handoff §4.3〕 |
| `authorization.grantedBy` | string | 是 | 授权主体（客户/内部授权人） | 〔handoff §4.3〕 |
| `authorization.validFrom` / `validTo` | `YYYY-MM-DD` | 是 | 含首尾日期（UTC 日期比较）；`validTo >= validFrom` | 〔handoff §4.3〕 |
| `authorization.document` | string | 否 | 授权文档路径/编号（不打包原文） | 〔handoff §4.3〕 |
| `targets[]` | `{kind, value, label?}` | 红队/紫队/triage 必填 | `kind ∈ {domain,url,cidr,ip,host,source}`；`source` 表示授权源码树 | 〔handoff §4.3〕、〔用户目标〕 |
| `exclusions[]` | string[] | 否 | 排除目标/排除模式（后缀匹配），**优先于 targets** | 〔handoff §4.3〕 |
| `mode` | `"passive"｜"active"｜"exploit"｜"post"` | 是 | 单调能力等级；决定可用动作上限 | 〔handoff §4.2〕 |
| `window.start/end` | RFC 3339 date-time | 是 | `start ≤ now < end` | 〔handoff §4.3〕 |
| `budget.maxRequests` | int | 是 | 1–100000 | 〔handoff §4.3〕 |
| `budget.maxMinutes` | int | 是 | 1–1440 | 〔handoff §4.3〕 |
| `dataHandling.retain` | `"findings-only"｜"none"｜"full"` | 是 | 默认 `findings-only` | 〔handoff §4.3〕 |
| `dataHandling.secrets` | 固定 `"mask-and-redact"` | 是 | 不允许其他值 | 〔handoff §4.3〕、〔用户目标〕 |
| `dataHandling.destruction` | 固定 `"none"` | 是 | 破坏性一律禁止 | 〔handoff §4.3〕 |
| `dataSources[]` | `{kind, value, label?, version?, lastVerified?}` | 按 workflow | 本地导出文件/目录的绝对路径；`kind` 见 §9.3 | 〔handoff §4.2〕 |
| `notes` | string | 否 | 自由备注（≤2000） | 〔标准实践〕 |

**下层禁止字段**：scope 对象 `additionalProperties=false`，出现未知字段即拒绝（G-CONF-01），避免"影子授权"。

### 9.2 归一化与 `confirm` 规则

| ID | 规则 | 来源 |
|---|---|---|
| SO-1 | `domain`：转小写、去尾部 `.`；`url`：转小写 scheme/host、去默认端口（80/443）、去 fragment、保留 path/query 原样；`ip`：IPv4 去前导零、IPv6 转小写；`cidr`：同 host 部分规则并保留前缀长度；`host`/`source`：去首尾空白、统一 `/` 分隔符。 | 〔标准实践：URL/host 归一化〕、〔假设 H-6：不依赖 URL API 时用等价正则实现〕 |
| SO-2 | `exclusions` 命中判定：归一化后**相等**或 target 为 `domain`/`host` 且以 `.`+排除项结尾（后缀匹配）；命中即拒绝该 target（G-TGT-04）。 | 〔handoff §4.3〕 |
| SO-3 | `confirm` 匹配：`String(args.confirm).trim()` 与某个 `kind ∈ {domain,url,host,ip}` 的 target **归一化后精确相等**；不支持通配、前缀、子串、CIDR（G-CFM-02/04）。 | 〔用户目标：显式确认〕、〔handoff §4.2〕 |
| SO-4 | `confirm` 只在 `exploit`/`post` 工作流使用；其他工作流即使传入也忽略。 | 〔handoff §4.2〕 |
| SO-5 | `activeScan` 仅在 `recon` 工作流使用；必须 `activeScan=true` 且 `mode≥active` 且 `dryRun=false`，否则拒绝（G-MODE-03）。 | 〔handoff §4.2〕、〔用户目标：默认 report-only〕 |

### 9.3 全局硬门禁注册表（G-*）

| Gate ID | 拒绝条件 | 适用 workflow | 来源 |
|---|---|---|---|
| G-ARG-01 | args 非对象，或含未声明的顶层键 | 全部 | 〔标准实践：fail-closed〕 |
| G-PATH-01 | `workDir` 空/非 Windows 绝对路径/含 `..` | 全部 | 〔IR-7〕 |
| G-PATH-02 | `skillDir` 空/非 Windows 绝对路径/含 `..`/不以 `skills` 结尾 | 全部 | 〔IR-7〕 |
| G-PATH-03 | 路径型 `dataSources.value` 或 `kind="source"` 的 target `value` 非 Windows 绝对路径或含 `..` | 全部（出现相应字段时） | 〔IR-7〕 |
| G-CONC-01 | `maxConcurrency` 非整数或不在 1–8 | 全部 | 〔IR-6〕 |
| G-CONF-01 | scope 含未声明字段 | 全部 | §9.1 |
| G-AUTH-01 | `authorization` 缺失/非对象/`reference` 空 | 全部 | LC-1 |
| G-AUTH-02 | `type` 不在 `{written, internal-mandate}` | 全部 | LC-1 |
| G-AUTH-03 | 该 workflow 要求 `written` 但 `type="internal-mandate"` | assess/recon/exploit/post/purple/triage | LC-1 |
| G-AUTH-04 | `grantedBy` 缺失/空 | 全部 | LC-1 |
| G-AUTH-05 | `validFrom/validTo` 非 `YYYY-MM-DD`，或 `validTo < validFrom` | 全部 | LC-1 |
| G-AUTH-06 | 当前 UTC 日期 < `validFrom` | 全部 | LC-3 |
| G-AUTH-07 | 当前 UTC 日期 > `validTo`（过期） | 全部 | LC-3 |
| G-TGT-01 | `targets` 缺失或为空 | assess/recon/exploit/post/purple/triage | LC-2 |
| G-TGT-02 | 通配/全网目标：`*`、`0.0.0.0/0`、`::/0`、前缀长度为 0 的任意 CIDR、`0.0.0.0`、`::` 作为 target | 全部（targets 非空时） | LC-2 |
| G-TGT-03 | target `kind`/`value` 非法（格式不符、空值、非 ASCII 控制字符） | 全部（targets 非空时） | LC-2 |
| G-TGT-04 | target 命中 `exclusions` | 全部（targets 非空时） | LC-2 |
| G-MODE-01 | `mode` 非法值 | 全部 | LC-3 |
| G-MODE-02 | `mode` 低于该 workflow 最低要求 | 全部 | 〔handoff §4.2〕 |
| G-MODE-03 | `recon` 的 `activeScan=true` 但 `mode=passive` 或 `dryRun≠false` | recon | SO-5 |
| G-WIN-01 | `window` 缺失/`start`/`end` 非 RFC 3339 | 全部 | LC-3 |
| G-WIN-02 | `end <= start` | 全部 | LC-3 |
| G-WIN-03 | 当前时刻不在 `[start, end)` 内 | 全部 | LC-3 |
| G-BUD-01 | `maxRequests`/`maxMinutes` 非整数或越界 | 全部 | LC-3 |
| G-DH-01 | `dataHandling.retain` 非法值 | 全部 | LC-4 |
| G-DH-02 | `dataHandling.secrets != "mask-and-redact"` | 全部 | LC-4 |
| G-DH-03 | `dataHandling.destruction != "none"` | 全部 | LC-4 |
| G-CFM-01 | `confirm` 缺失/空/非 string | exploit/post | LC-2、SO-3 |
| G-CFM-02 | `confirm` 不等于任何精确目标的归一化值 | exploit/post | SO-3 |
| G-CFM-03 | `exploit` 要求 `mode ∈ {exploit,post}`；`post` 要求 `mode="post"` | exploit/post | 〔handoff §4.2〕 |
| G-CFM-04 | 无 `kind ∈ {domain,url,host,ip}` 的目标可用于 confirm | exploit/post | SO-3 |
| G-DS-01 | `hunt` 缺 `dataSources`，或无 `kind ∈ {siem,edr,logs,telemetry-export}` | hunt | SCN-B1 |
| G-DS-02 | `ir` 缺 `kind="evidence"` 的数据源 | ir | SCN-B2 |
| G-DS-03 | `purple` 缺 `kind="findings"` 或 `kind="detections"` | purple | SCN-P1 |
| G-DS-04 | `harden` 缺 `kind="baseline"`，或 baseline 缺 `version`/`lastVerified` | harden | SCN-B3 |
| G-DS-05 | `harden` 的 baseline `lastVerified` 距今 >180 天 | harden | R9 时效 |
| G-DS-06 | `triage` 缺 `kind="finding"` 的数据源 | triage | SCN-P3 |
| G-DS-07 | `exploit` 缺 `kind="findings"` 的数据源（已验证 finding 输入） | exploit | SCN-R3、§10.3、〔handoff §4.2〕 |
| G-OUT-01 | `workDir` 内已存在 `scan-manifest.json` 且其 `runId` 与本次不同（防覆盖他人结果）；由**首个 phase 在写盘前**检查（脚本无 fs 访问） | 全部 | 〔标准实践：产物完整性〕 |

## 10. 工作流门禁需求（9 个 workflow 的硬拒绝条件清单）

统一约定：

- **args**：`scope`（对象）、`workDir`（绝对路径）、`skillDir`（绝对路径）、`maxConcurrency`（默认 2，1–8）、`dryRun`（默认 `true`）；`exploit`/`post` 增加 `confirm`，`recon` 增加 `activeScan`。额外键一律拒绝（G-ARG-01）。
- **拒绝语义**：任一硬门禁命中 → 在进入任何 phase 前返回，`status="rejected"`、`exitCode=1`、`rejectedBy=[gateId…]`，**不写任何产物**；门禁按注册表顺序全部求值（collect-all），便于一次修正。唯一例外：`G-OUT-01` 需读取 `workDir`，由**首个 phase 在写盘前**判定；命中时同样返回 `rejected`/`1` 且不写任何产物（脚本本身无 fs 访问）。
- **退出码**：`0` 全部通过且无可报告项；`2` 全部通过且有 ≥1 条 `disposition=reportable` 的 finding；`1` 任一硬拒绝门禁命中，或执行期错误/封存校验失败。各 workflow 的具体映射见 design §6。
- **默认 report-only**：`dryRun=true` 时零目标侧动作（不发包、不利用、不执行遏制/加固），只读本地文件与产物；`dryRun=false` 仅解除目标侧动作限制，**不解除** scope/mode/confirm/window/budget 约束。

### 10.0 门禁适用矩阵

下表定义"通用门禁"；`✓` = 该 workflow 硬拒绝清单包含此项，`—` = 不适用，`✓*` = 条件适用。每节再逐项展开。

| 门禁组（ID） | assess | recon | exploit | post | hunt | ir | purple | triage | harden |
|---|---|---|---|---|---|---|---|---|---|
| `G-ARG-01` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `G-PATH-01`、`G-PATH-02` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `G-PATH-03`（出现路径型 `dataSources` 或 `kind="source"` 目标时） | ✓* | ✓* | ✓ | ✓* | ✓ | ✓ | ✓ | ✓ | ✓ |
| `G-CONC-01`、`G-CONF-01` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `G-AUTH-01`、`G-AUTH-02`、`G-AUTH-04`、`G-AUTH-05` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `G-AUTH-03`（必须 `written`） | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | ✓ | — |
| `G-AUTH-06`、`G-AUTH-07` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `G-TGT-01`（`targets` 必填） | ✓ | ✓ | ✓ | ✓ | — | — | ✓ | ✓ | — |
| `G-TGT-02`、`G-TGT-03`、`G-TGT-04`（targets 非空时） | ✓* | ✓* | ✓ | ✓* | ✓* | ✓* | ✓ | ✓ | ✓* |
| `G-MODE-01`、`G-MODE-02` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `G-MODE-03`（recon activeScan） | — | ✓ | — | — | — | — | — | — | — |
| `G-WIN-01`..`G-WIN-03`、`G-BUD-01`、`G-DH-01`..`G-DH-03`、`G-OUT-01` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `G-CFM-01`..`G-CFM-04` | — | — | ✓ | ✓ | — | — | — | — | — |
| `G-DS-01` / `G-DS-02` / `G-DS-03` / `G-DS-04`+`G-DS-05` / `G-DS-06` / `G-DS-07` | — | — | `G-DS-07` | — | `G-DS-01` | `G-DS-02` | `G-DS-03` | `G-DS-06` | `G-DS-04`+`G-DS-05` |

条件说明：`G-PATH-03` 只在该 workflow 确实出现路径型数据源或 `source` 目标时求值；`G-TGT-02..04` 只在 `targets` 非空时求值（仅 hunt/ir/harden 允许空 targets，其余 workflow 由 `G-TGT-01` 先拒绝）。`exploit`/`post` 的 `G-MODE-02` 按等级校验，`G-CFM-03` 按 confirm 的 mode 匹配校验，两者同时生效。

### 10.1 `assess.js`（完整评估）

- 阶段：`scope → recon → surface → discover → validate → report → seal`
- 最低 mode：`passive`；要求 `authorization.type="written"`、`targets` 非空。
- 硬拒绝清单：`G-ARG-01`、`G-PATH-01`、`G-PATH-02`、`G-PATH-03`（条件）、`G-CONC-01`、`G-CONF-01`、`G-AUTH-01`、`G-AUTH-02`、`G-AUTH-03`、`G-AUTH-04`、`G-AUTH-05`、`G-AUTH-06`、`G-AUTH-07`、`G-TGT-01`、`G-TGT-02`、`G-TGT-03`、`G-TGT-04`、`G-MODE-01`、`G-MODE-02`、`G-WIN-01`、`G-WIN-02`、`G-WIN-03`、`G-BUD-01`、`G-DH-01`、`G-DH-02`、`G-DH-03`、`G-OUT-01`。
- 退出码：`0` 无 reportable；`2` 有 reportable；`1` 门禁拒绝/执行错误。

### 10.2 `recon.js`（被动优先侦察）

- 阶段：`scope → recon → surface → report → seal`
- 最低 mode：`passive`；`authorization.type="written"`、`targets` 非空；`activeScan` 默认 `false`。
- 硬拒绝清单：`G-ARG-01`、`G-PATH-01`、`G-PATH-02`、`G-PATH-03`（条件）、`G-CONC-01`、`G-CONF-01`、`G-AUTH-01`、`G-AUTH-02`、`G-AUTH-03`、`G-AUTH-04`、`G-AUTH-05`、`G-AUTH-06`、`G-AUTH-07`、`G-TGT-01`、`G-TGT-02`、`G-TGT-03`、`G-TGT-04`、`G-MODE-01`、`G-MODE-02`、`G-MODE-03`、`G-WIN-01`、`G-WIN-02`、`G-WIN-03`、`G-BUD-01`、`G-DH-01`、`G-DH-02`、`G-DH-03`、`G-OUT-01`。
- 退出码：`0` 无可报告暴露；`2` 有 reportable 暴露类 finding；`1` 门禁拒绝（含"主动扫描但 mode/dryRun 不足"）/执行错误。

### 10.3 `exploit.js`（受控利用）

- 阶段：`scope → validate → exploit → report → seal`
- 最低 mode：`exploit`（`mode ∈ {exploit,post}`）；`authorization.type="written"`、`targets` 非空且含可 confirm 的精确目标；`dataSources` 必须含 `kind="findings"`（已验证 finding 输入）。
- 硬拒绝清单：`G-ARG-01`、`G-PATH-01`、`G-PATH-02`、`G-PATH-03`、`G-CONC-01`、`G-CONF-01`、`G-AUTH-01`、`G-AUTH-02`、`G-AUTH-03`、`G-AUTH-04`、`G-AUTH-05`、`G-AUTH-06`、`G-AUTH-07`、`G-TGT-01`、`G-TGT-02`、`G-TGT-03`、`G-TGT-04`、`G-MODE-01`、`G-MODE-02`、`G-WIN-01`、`G-WIN-02`、`G-WIN-03`、`G-BUD-01`、`G-DH-01`、`G-DH-02`、`G-DH-03`、`G-CFM-01`、`G-CFM-02`、`G-CFM-03`、`G-CFM-04`、`G-DS-07`、`G-OUT-01`。
- confirm 约束：**`confirm` 必须等于 `targets` 中某个精确目标的归一化值**，且 `mode` 必须 ≥`exploit`（G-CFM-02/G-CFM-03）。
- 执行条件：`dryRun=false` 才允许目标侧利用动作；`dryRun=true`（默认）只产出计划与证据要求（plan-only），仍必须通过 confirm/mode 门禁。
- 退出码：`0` 无 reportable 且 plan 完成；`2` 有 reportable 或已验证影响；`1` 门禁拒绝/执行错误。

### 10.4 `post.js`（后渗透，报告-only）

- 阶段：`scope → post → report → seal`
- 最低 mode：`post`（严格 `mode="post"`）；`authorization.type="written"`；含可 confirm 的精确目标。
- 硬拒绝清单：`G-ARG-01`、`G-PATH-01`、`G-PATH-02`、`G-PATH-03`（条件）、`G-CONC-01`、`G-CONF-01`、`G-AUTH-01`、`G-AUTH-02`、`G-AUTH-03`、`G-AUTH-04`、`G-AUTH-05`、`G-AUTH-06`、`G-AUTH-07`、`G-TGT-01`、`G-TGT-02`、`G-TGT-03`、`G-TGT-04`、`G-MODE-01`、`G-MODE-02`、`G-WIN-01`、`G-WIN-02`、`G-WIN-03`、`G-BUD-01`、`G-DH-01`、`G-DH-02`、`G-DH-03`、`G-CFM-01`、`G-CFM-02`、`G-CFM-03`、`G-CFM-04`、`G-OUT-01`。
- 额外约束：`dataHandling.destruction` 必须 `none`（G-DH-03）；**禁止任何持久化/驻留动作**（由技能与阶段 prompt 强约束，R12-REPORT-ONLY 检查）。
- 执行条件：`dryRun=false` 才允许只读后渗透探测；`dryRun=true` 仅产出评估计划。
- 退出码：`0` 无 reportable；`2` 有 reportable；`1` 门禁拒绝/执行错误。

### 10.5 `hunt.js`（威胁狩猎）

- 阶段：`scope → hunt → report → seal`
- 最低 mode：`passive`；`authorization.type ∈ {written, internal-mandate}`；`targets` 可为空。
- 硬拒绝清单：`G-ARG-01`、`G-PATH-01`、`G-PATH-02`、`G-PATH-03`、`G-CONC-01`、`G-CONF-01`、`G-AUTH-01`、`G-AUTH-02`、`G-AUTH-04`、`G-AUTH-05`、`G-AUTH-06`、`G-AUTH-07`、`G-TGT-02`、`G-TGT-03`、`G-TGT-04`（条件）、`G-MODE-01`、`G-MODE-02`、`G-WIN-01`、`G-WIN-02`、`G-WIN-03`、`G-BUD-01`、`G-DH-01`、`G-DH-02`、`G-DH-03`、`G-DS-01`、`G-OUT-01`。**无遥测数据源即拒绝，禁止编造结果**。
- 退出码：`0` 无可报告狩猎结论；`2` 有 reportable 狩猎发现；`1` 门禁拒绝（含无数据源）/执行错误。

### 10.6 `ir.js`（事件响应）

- 阶段：`intake → triage → timeline → containment → report → seal`
- 最低 mode：`passive`；`authorization.type ∈ {written, internal-mandate}`；`targets` 可为空。
- 硬拒绝清单：`G-ARG-01`、`G-PATH-01`、`G-PATH-02`、`G-PATH-03`、`G-CONC-01`、`G-CONF-01`、`G-AUTH-01`、`G-AUTH-02`、`G-AUTH-04`、`G-AUTH-05`、`G-AUTH-06`、`G-AUTH-07`、`G-TGT-02`、`G-TGT-03`、`G-TGT-04`（条件）、`G-MODE-01`、`G-MODE-02`、`G-WIN-01`、`G-WIN-02`、`G-WIN-03`、`G-BUD-01`、`G-DH-01`、`G-DH-02`、`G-DH-03`、`G-DS-02`、`G-OUT-01`。
- 额外约束：证据必须记录 SHA256；时间线必须由证据事件确定性排序生成（可复算）；`containment` 只输出建议，不执行。
- 退出码：`0` 无 reportable 事件观察；`2` 有 reportable 事件观察；`1` 门禁拒绝（无证据）/执行错误。

### 10.7 `purple.js`（红蓝对齐）

- 阶段：`redActions → detectCoverage → gaps → report → seal`
- 最低 mode：`passive`；`authorization.type="written"`；`targets` 非空。
- 硬拒绝清单：`G-ARG-01`、`G-PATH-01`、`G-PATH-02`、`G-PATH-03`、`G-CONC-01`、`G-CONF-01`、`G-AUTH-01`、`G-AUTH-02`、`G-AUTH-03`、`G-AUTH-04`、`G-AUTH-05`、`G-AUTH-06`、`G-AUTH-07`、`G-TGT-01`、`G-TGT-02`、`G-TGT-03`、`G-TGT-04`、`G-MODE-01`、`G-MODE-02`、`G-WIN-01`、`G-WIN-02`、`G-WIN-03`、`G-BUD-01`、`G-DH-01`、`G-DH-02`、`G-DH-03`、`G-DS-03`、`G-OUT-01`。
- 额外约束：输入 `findings` 必须为 dsh-redblue `findings.json`；不得改写红队 finding 的 `severity`/`disposition`（只读消费）。
- 退出码：`0` 全覆盖无缺口；`2` 有 reportable 检测缺口；`1` 门禁拒绝（缺 findings/detections）/执行错误。

### 10.8 `triage.js`（外部 finding 入库）

- 阶段：`finding → review → disposition → write → seal`
- 最低 mode：`passive`；`authorization.type="written"`；`targets` 非空。
- 硬拒绝清单：`G-ARG-01`、`G-PATH-01`、`G-PATH-02`、`G-PATH-03`、`G-CONC-01`、`G-CONF-01`、`G-AUTH-01`、`G-AUTH-02`、`G-AUTH-03`、`G-AUTH-04`、`G-AUTH-05`、`G-AUTH-06`、`G-AUTH-07`、`G-TGT-01`、`G-TGT-02`、`G-TGT-03`、`G-TGT-04`、`G-MODE-01`、`G-MODE-02`、`G-WIN-01`、`G-WIN-02`、`G-WIN-03`、`G-BUD-01`、`G-DH-01`、`G-DH-02`、`G-DH-03`、`G-DS-06`、`G-OUT-01`。
- 额外约束：不得修改原 finding 的 `severity`（新结论写入新字段/新记录）；`state/findings.jsonl` 按 `id` 幂等合并。
- 退出码：`0` 复核为 suppressed/not_applicable/deferred；`2` 复核为 reportable；`1` 门禁拒绝（无 finding 输入）/执行错误。

### 10.9 `harden.js`（加固基线核查）

- 阶段：`baseline → check → gaps → remediation → verify → seal`
- 最低 mode：`passive`；`authorization.type ∈ {written, internal-mandate}`；`targets` 可为空。
- 硬拒绝清单：`G-ARG-01`、`G-PATH-01`、`G-PATH-02`、`G-PATH-03`、`G-CONC-01`、`G-CONF-01`、`G-AUTH-01`、`G-AUTH-02`、`G-AUTH-04`、`G-AUTH-05`、`G-AUTH-06`、`G-AUTH-07`、`G-TGT-02`、`G-TGT-03`、`G-TGT-04`（条件）、`G-MODE-01`、`G-MODE-02`、`G-WIN-01`、`G-WIN-02`、`G-WIN-03`、`G-BUD-01`、`G-DH-01`、`G-DH-02`、`G-DH-03`、`G-DS-04`、`G-DS-05`、`G-OUT-01`。
- 额外约束：基线必须带 `version` 与 `lastVerified`；`remediation` 只输出建议，不自动修改生产配置。
- 退出码：`0` 无报告缺口；`2` 有 reportable 加固缺口；`1` 门禁拒绝（缺基线/基线过期）/执行错误。

## 11. 净化需求

| ID | 需求 | 规范源 | 来源 |
|---|---|---|---|
| SAN-1 | R1 来源与许可：每个技能与每篇 reference 带 provenance（repo/commit/license/path/last-verified/rewrite-summary）；`NOTICE` 列全三上游；commit 固定为 §2.1 F-10。 | `sanitization-rules.md` R1 | 〔handoff §5 R1〕、〔标准实践：Apache-2.0 §4、MIT〕 |
| SAN-2 | R2 占位符净化：仅保留域/文档网段/回环/OAST；引用链接仅权威域白名单；`attacker.com`/`evil.com` 等直接失败。 | R2 | 〔handoff §5 R2〕、〔标准实践：RFC 2606/6761、RFC 5737、RFC 3849〕 |
| SAN-3 | R3 无武器化制品：webshell/反弹 shell/C2/malware/凭据 dump/真实密钥/破坏性命令禁入；示例须带授权横幅。 | R3 | 〔handoff §5 R3〕 |
| SAN-4 | R4 授权门禁：workflow 缺 scope/越界/模式不足必须拒绝；无 `verify=False`；默认 dry-run；禁止无界扫描与 `0.0.0.0/0`。 | R4 | 〔handoff §5 R4〕 |
| SAN-5 | R5 不制造虚假内容：禁 simulated/fake/mock 结果生成器；效能数字必须可溯源；CVE 必须 `CVE-YYYY-NNNN` 并标核验状态。 | R5 | 〔handoff §5 R5〕 |
| SAN-6 | R6 结构上限：`SKILL.md` ≤300 行且 ≤24 KiB；description ≤500 字符；必须有 `whenToUse`；reference ≤48 KiB。 | R6 | 〔handoff §5 R6〕、〔复测 F-5：上游 18 个超 1024，不能沿用〕 |
| SAN-7 | R7 去重与触发隔离：技能名唯一；同 lane description 的 CJK bigram Jaccard ≤0.35；每个 description 必须有 `触发词：`、`不适用：` 且点名最近兄弟技能。 | R7 | 〔handoff §5 R7〕、〔复测：15 技能最大同 lane Jaccard 0.130〕 |
| SAN-8 | R8 提示注入防御：凡消费目标制品的技能必须有 4 元素边界句；workflow 阶段 prompt 必须注入同一常量。 | R8 | 〔handoff §5 R8/§2.3〕 |
| SAN-9 | R9 时效标注：时效内容必须 `last-verified`；厂商/版本/CVE/CLI 参数须标"版本时效"。 | R9 | 〔handoff §5 R9〕 |
| SAN-10 | R10 机密与隐私：无凭据/令牌/私钥/个人数据/内网主机名/真实客户名。 | R10 | 〔handoff §5 R10〕 |
| SAN-11 | R11 语言与术语：正文中文、标识符英文、术语表统一；术语混用只告警，人工评审签字。 | R11 | 〔handoff §5 R11〕 |
| SAN-12 | R12 风险分级与安全默认：每技能声明 `risk` 与 `requires`；默认 report-only；exploit 需 `confirm:"<target>"`；字段与技能名矛盾即失败。 | R12 | 〔handoff §5 R12〕 |

净化门禁以 `tools/sanitize-lint.mjs --strict` 为唯一确定性判据；**lint 退出码非 0 视为发布阻断**（详见 `sanitization-rules.md` §3）。

## 12. 可验证性需求

| ID | 验证对象 | 验证方式 | 来源 |
|---|---|---|---|
| VER-1 | 文档三件套存在且非空 | `test -s docs/{requirements,design,sanitization-rules}.md` | 本任务 Verify |
| VER-2 | 15 技能可 `list/get`，name/描述/frontmatter 与常量一致 | `node --test test/scaffold.test.mjs`（provider 直接调用 `list()`/`get()`） | 〔handoff §6〕 |
| VER-3 | workflow 门禁：缺 scope/越界/模式不足/confirm 不符/无遥测/基线过期必须拒绝 | `node --test test/workflow.test.mjs`（vm stub `agent/phase/log/parallel`） | 〔handoff §6〕 |
| VER-4 | 净化门禁 | `node tools/sanitize-lint.mjs --strict --json skills references`（发布门禁再加 `workflow lib policy schema package.json NOTICE`） | 〔handoff §6〕 |
| VER-5 | 脚本语法 | 对所有 `*.js`/`*.mjs` 执行 `node --check` | 〔handoff §6〕 |
| VER-6 | 确定性产物：fingerprint/id 跨运行稳定；给定同一 `runId` 时 findings/coverage/SARIF/manifest 的文本与哈希可复算（`runId` 本身含时间/随机，显式非确定性）。 | `node --test test/contract.test.mjs`（`@contract-helpers` 块） | 〔handoff §2.3/§6〕 |
| VER-7 | 安装生效 | `dsh plugin --profile desktop list` 含 `dsh-redblue`；重启后技能可见 | IR-2/IR-3 |
| VER-8 | 零依赖 | `package.json` 无 dependencies；代码无 `fetch`/`http`/`child_process` | IR-5 |
| VER-9 | 退出码语义 | 各 workflow 单测断言 `exitCode` 为 0/1/2 且与 `status` 一致 | design §6 |
| VER-10 | 文档可逐条判定 | requirements/design/sanitization-rules 中每个 REQ/Gate/Check 都有 ID 与判定方法 | 本任务 Acceptance |

## 13. 交付与清理要求

| ID | 要求 | 来源 |
|---|---|---|
| DL-1 | 插件目录内不得出现上游仓库副本、课程原文、`agent.py` 或任何可执行攻击代码。 | NG-1/NG-3 |
| DL-2 | 交付前删除 `.work/sources` 与临时脚本/导出文件；`.work` 不进入插件 `files` 白名单。 | 〔handoff §1 交付纪律〕 |
| DL-3 | 安装/验证记录写入 `docs/`（后续任务产出 `docs/verification.md`、`docs/install.md`），包含命令与输出摘要。 | SC-8、VER-7 |
| DL-4 | `NOTICE` 与每篇 provenance 头必须随包分发；移除任何 NOTICE 视为破坏许可合规（R1）。 | 〔标准实践：Apache-2.0 §4(d)〕 |

## 14. 风险与假设

| 风险 | 缓解 | 来源 |
|---|---|---|
| 双用途内容被误用 | R4 授权门禁 + R12 风险分级 + 默认 dry-run/report-only + 破坏性拒绝 | 〔handoff §8〕 |
| 提示注入（目标页面/源码/日志含指令） | R8 边界句 + workflow 阶段 prompt 固定模板 + `ingests: target` 标记 | 〔handoff §8〕 |
| 上游许可/归属遗漏 | R1 provenance + NOTICE；Apache-2.0 保留声明与修改说明 | 〔handoff §8〕、F-10 |
| 内容注水/虚假效能 | R5 + 篇幅上限 + 每篇改写摘要 | 〔handoff §8〕 |
| 触发器互相抢占 | R7 Jaccard + 负向边界 + 入口技能路由表 | 〔handoff §8〕、〔复测：0.130〕 |
| Windows/TPM/上下文 | 零依赖、MSYS 路径规则、`maxConcurrency=2`、技能 ≤300 行 | 〔handoff §8〕、IR-6/IR-7 |
| 安装破坏现有 profile | link 安装 + 安装前备份 + 失败回滚；只动 desktop profile | 〔handoff §8〕、IR-4 |
| 退出码/产物被 CI 误读 | design §6 固定 `status`↔`exitCode` 映射，测试断言 | VER-9 |

未决假设见 §2.2（H-1..H-8）；其中 H-3（署名）、H-5（bundle 自动注册）需在安装任务前确认，其余不影响核心实现。

## 15. 追踪矩阵与本任务验收对照

### 15.1 需求追踪（关键需求 → 实现落点 → 验证）

| 需求 | 实现落点 | 验证 |
|---|---|---|
| OBJ-2（同形态） | `package.json` + `cordis.patch.yml` + `lib/index.js` | VER-2/VER-7 |
| OBJ-3/§11（净化） | `skills/`、`references/`、`policy/`、`tools/sanitize-lint.mjs` | VER-4 |
| §9（scope 门禁） | `schema/scope.schema.json` + 各 workflow 的 `validateScope()` | VER-3/VER-9 |
| §10（9 workflow 契约） | `workflow/*.js` | VER-3/VER-6/VER-9 |
| SC-4（产物） | 各 workflow 的 report/seal 阶段 + `schema/*.schema.json` | VER-6 |
| §13（许可归属） | `LICENSE`、`NOTICE`、frontmatter provenance | R1 检查 |
| IR-1..IR-10（安装运行） | 文档 + `package.json` + 测试 | VER-7/VER-8 |

### 15.2 本任务（t1）验收对照

| 验收条目 | 落点 |
|---|---|
| requirements 含目标/范围/非目标/红蓝紫场景/与 dsh-security 边界/合规/安装运行 | §1、§3、§4、§5、§6、§7、§8 |
| design 含 bundle 结构、15 技能表、9 workflow 契约表、scope schema、产物封存格式 | design §2–§10 |
| sanitization-rules 含 R1–R12 定义/判定/检查 ID/白名单/级别 | sanitization-rules §4、§6、§7 |
| 15 技能 name 一一对应无重名；description 有触发词与"不适用"且点名兄弟 | design §4；R7 复算值 0.130 |
| 每个 workflow 硬拒绝清单；exploit/post 要求 `confirm:"<target>"` 且 mode 匹配 | §10.3/§10.4 + §9.3（G-CFM-01..04） |
| 许可与归属策略（Apache-2.0 + NOTICE + provenance 头格式），三上游 commit 固定 | §3 SC-9、§13 DL-4、design §12、sanitization R1 |
| 每条关键需求有来源；无支撑标假设；无遗留未决占位标记（核心决策全部定稿） | 全文标注 + §2.2 |
| 中文正文、英文标识符；可逐条判定 | 全文 |
