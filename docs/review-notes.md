# dsh-redblue 独立评审记录（t8 round-1 / t21 round-2）

- 评审人：reviewer（AgentTeams member；t8 round-1，t21 round-2）
- 评审时间：t8 2026-11-19 22:51–23:20；t21 2026-11-19 23:30–23:50 +08:00
- 评审对象：`dsh-redblue@0.1.0` 交付态；t8 被评审实现任务 t6，t21 被评审修复任务 t20
- 评审基线：`docs/requirements.md`、`docs/design.md`、`docs/sanitization-rules.md`、`docs/verification-report.md`、`policy/authorization.md`、`policy/sanitization.md`
- 方式：**只读 + 独立构造/复算**。除本文件外未修改任何被评审文件；未触发网络；未运行任何白名单工具配方。
- **t21 round-2 结论：PASS**。F1（high）已修复并通过独立构造复核；F12、F4、F5、F6、F9、F10、F11、F13 已验证修复；F2/F3/F7/F8 有残余（R1–R4，medium/low），另有 R5–R8（文档/保证性 low），见 §15。无 blocker/high，按本任务规则判 pass。
- t8 round-1 历史结论：**needs_revision**（F1 high；其余 5 medium/7 low，已由 t20 处置，见 §12/§15）。

## 0. 十一个维度结论摘要

| # | 维度 | 结论 | 最强证据 |
|---:|---|---|---|
| 1 | 需求符合性 | **通过** | 15 技能、9 workflow、report-only 默认、红蓝紫闭环、与 dsh-security 分工均兑现；provider 实测 15/rank600 |
| 2 | 净化合规（内容级 R1–R12） | **基本通过，1 处 provenance 失实（F5）** | 83 文件 0 blocker/2 受理 warning；我独立核对 42 条 provenance、3 个 pin、NOTICE/LICENSE 全文 |
| 3 | 方法论深度（红 3/蓝 3） | **通过** | 6 篇抽样均保留命令配方/判定标准/证据要求/检测视角，未退化为清单或课程 |
| 4 | 安全默认不可绕过 | **不通过（F1 high；F12 medium）** | 13 类构造中 11 类正确拒绝且 0 agent；exclusions 归一化构造绕过 G-TGT-04（workflow 与 guard 均复现） |
| 5 | 双用途风险 | **通过（有边界约束）** | 无可复制武器化制品；授权前置/停止条件/数据处置/零持久化清晰 |
| 6 | 许可与归属 | **通过（1 处 provenance 路径失实）** | Apache-2.0 全文 + NOTICE 三上游 pin/MIT 全文/修改声明；上游 LICENSE 与 pin 逐项核对一致 |
| 7 | DSH 集成正确性 | **通过** | bundle patch/provider 与 dsh-security 同构；provider list/get 实测；两段 smoke 7/7 产物哈希独立复算零 mismatch |
| 8 | 可维护性 | **部分不通过（F3/F6/F9/F10/F14）** | 无死链；但 docs/value-extraction、README/DETAIL、sanitization-rules 与实现/台账存在数字与阶段名不一致 |
| 9 | 价值提炼充分性 | **通过（有台账/文档瑕疵 F3/F6）** | 红蓝配方各抽样 1 族、sigma 模板、79/78/818/809 台账逐项复算；可直接执行到命令/参数/证据/判定级 |
| 10 | Strix 吸收与 finding-review | **通过（F2 schema 不一致）** | 30 类表、5 框架、AWS 抽样均含假设/验证/证据/误判边界/检测视角；78 篇逐篇账实一致 |
| 11 | 工具运行时安全 | **通过（F1 同源 exclusions 缺陷；W1 已知）** | guard 仅白名单、argv 直传 shell=false、dry-run 默认、execute 四重门禁、注入型 target 无法进 argv、evidence 只落哈希 |

---

## 1. 需求符合性（维度 1）

| 需求 | 判定 | 证据 |
|---|---|---|
| 15 个 bundled 技能 | 通过 | `lib/index.js` 实测 `list()` 15 项，name 与 `skills/*/SKILL.md` 一一对应，`rank=600`、`source=bundled`、未知 name → undefined；15/15 目录与 frontmatter 12 键齐全 |
| 9 个原生 workflow | 通过 | `workflow/` 恰 9 个脚本 + 目录级 package.json；各脚本 CONFIG 的 workflow/minMode/authTypes/requireTargets/requireDataSources 与 requirements §10.0/§10.1–10.9 一致 |
| 授权门禁 | 通过（除 F1） | 9/9 在首个 agent 前执行 preflight；13 类构造中 11 类 `rejected`/exit1/0 agent（§4） |
| 默认 report-only | 通过 | 9/9 `dryRun` 缺省 true（固定表达式）；`activeScan` 仅 recon 且 mode≥active+dryRun=false |
| 红蓝紫闭环 | 通过 | 红 7 + 蓝 4 + 紫 1 + rb 3；workflow 阶段→技能映射与 design §5.3 一致 |
| 与 dsh-security 分工 | 通过 | README §8、requirements BD-1..6；两插件不同名/不同 provider/无静态 import/无共享 node_modules |

补充：`hunt`/`ir`/`harden` 允许空 targets（CONFIG `requireTargets:false`），`assess`/`recon`/`exploit`/`post`/`purple`/`triage` 拒绝空 targets，符合 requirements §10.0 条件矩阵。

## 2. 净化合规（维度 2，内容级，不只看 lint）

### 2.1 门禁实测

- `node tools/sanitize-lint.mjs --strict --json dsh-redblue` → `checkedFiles=83, blockers=0, warnings=2`（R11-TERMINOLOGY：`skills/purple-verify/SKILL.md:3`、`skills/red-exploit/SKILL.md:3`，assembly-report §4 已受理，维持 warning 级别）。
- `--list-checks` → 36 条，34 blocker + 2 warning，与 sanitization-rules §7 一致。

### 2.2 R1 provenance 真实性（独立核对）

- `git -C .work/sources/{claude-red,acs,strix} rev-parse HEAD` 分别为 `6196ba74…`、`54a79883…`、`8db295a5…`，与 NOTICE、frontmatter、INDEX 三处 pin 完全一致。
- 脚本核对 42 条 provenance（15 技能 + 27 参考/模板）：15/15 技能的 `source-path` 在对应上游 commit 存在；参考侧 31/32 存在，**1 条失实**：`references/red/extraction-ledger.md:5` 写 `Skills/README.md`，上游实际是仓库根 `README.md`（`Skills/` 下无 README）。
- `rewrite-summary` 全部 ≤120 码点；`last-verified` 全部为 2026-11-19；`source-license` 与仓库许可逐条匹配（Claude-Red MIT、ACS/Strix Apache-2.0）。

### 2.3 R2/R3/R5/R6/R7/R8/R9/R10/R11/R12 抽样

- R2：示例目标仅保留域/文档网段；`references/red/discover-web-api.md` 的 curl 示例使用 `app.example.com`；未见真实第三方目标。
- R3：全库搜索 `msfvenom|meterpreter|mimikatz|sekurlsa|procdump|comsvcs|secretsdump|webshell|反弹|nc -e|bash -i|/dev/tcp|verify=False|rm -rf /` 等，命中仅为：`test/fixtures/`（负向断言样本，发布排除）、检测/禁令文本、上游技能名与台账；未发现可复制武器化制品。
- R5：内容中 0 条 `CVE-20xx-xxxx` 断言；无“百分比+效能词”无来源命中。
- R6：技能 108–176 行 / 5,782–8,939 B / desc 157–286 码点；参考最大 32,841 B（`strix-techniques.md`）≤48 KiB。
- R7：15 名唯一，名称与目录/lib 一致；同 lane Jaccard 实测（verification-report 14.4.2）最大 0.1395 ≤0.35；15/15 含 `触发词：` 与 `不适用：`。
- R8：13 个 `ingests: target` 技能逐字含 4 元素边界句；9/9 workflow 含同一 `UNTRUSTED_CLAUSE`，并在 `buildPrompt` 首行注入。
- R9：42/42 `last-verified` 合法；无过期 >180 天。
- R10：无真实邮箱/手机/SSN/私钥/云密钥；内网后缀仅出现在策略禁令文本。
- R12：15/15 `risk`/`requires` 与 design §4.3 期望表一致；9/9 默认 dryRun；exploit/post confirm 门禁在 preflight。

结论：**内容级净化真实有效**，不是“lint 过但内容脏”。唯一 provenance 失实见 F5。

## 3. 方法论深度（维度 3：红 3 / 蓝 3 抽样）

| 抽样 | 判读 | 保留的内容 | 是否退化 |
|---|---|---|---|
| `references/red/discover-web-api.md`（150 行） | **保留** | 21 类目判定表（CWE/差分信号/最小只读验证/常见误报）、SSRF/走私/竞态/反序列化深入、API/身份/LLM 专项、候选字段（hypothesisId/evidenceRefs≥2/confidence）、2 段带授权横幅的 curl 差分模板、禁止事项与升级路径 | 否；可直接指导授权测试 |
| `references/red/discover-identity-ad.md`（149 行） | **保留** | 只读允许/禁止矩阵、AD 姿态 8 项判定（信任/特权组/ACL/Kerberoast/委派/ADCS/会话/LAPS）、LDAP/nxc/BloodHound/certipy 只读命令、OIDC/JWT/SAML 判定、CI/供应链 7 项、初始访问检测视角、身份侧检测表 | 否；不是工具名罗列 |
| `references/red/exploit-controlled.md`（149 行） | **保留** | 7 项门禁、四步流程、可利用性 5 因子、L1–L5 影响阶梯（L5 禁止）、执行纪律（一次一个动作/不落凭据/不横向/不持久化/不规避/可停止）、清理清单、7 条停止条件、exploit-log 字段与红线 | 否；把“利用”约束成可审计最小验证 |
| `references/blue/hunt-hypothesis.md`（209 行） | **保留** | 可证伪定义、五元组假设卡、三态判定门槛（confirmed 两独立证据/refuted 明确反例/undetermined 缺失记录）、遥测矩阵与字段体检、查询草稿纪律、12 条假设库、误判来源表、交接边界 | 否；比课程材料更可执行 |
| `references/blue/detect-engineering.md`（194 行） | **保留** | 检测闭环六阶段、规则六要素、Sigma 结构规范、KQL/SPL 转译差异表与代码、四类测试样例、误报抑制 6 手段、ATT&CK 覆盖登记、评审清单 | 否；有真实查询骨架与判定 |
| `references/blue/dfir-playbook.md`（189 行） | **保留** | 五阶段与完成判定、证据保全 6 原则、可复算时间线定义（(ts,source,locator)）、主机/网络/云 IR 要点、影响范围四维、遏制建议字段（requiresApproval=true/executed=false/rollback）、提示注入处理 | 否；时间线与遏制可操作 |

未发现“课程灌水”式长篇复述；6 篇均 ≤48 KiB，且每篇有明确消费者与加载预算。

## 4. 安全默认不可绕过（维度 4：构造与结果）

### 4.1 workflow preflight 构造（Node `new Function` 沙箱，stub agent 记录调用次数）

| 构造 | 期望 | 实测 | 结论 |
|---|---|---|---|
| 无 scope（仅 workDir/skillDir） | G-ARG-01 | `rejectedBy=["G-ARG-01"]`，agents=0 | 不可绕过 |
| assess targets=[] | G-TGT-01 | G-TGT-01，agents=0 | 不可绕过 |
| `cidr=0.0.0.0/0` | G-TGT-02 | G-TGT-02，agents=0 | 不可绕过 |
| `authorization.validTo` 已过期 | G-AUTH-07 | G-AUTH-07，agents=0 | 不可绕过 |
| assess 用 `internal-mandate` | G-AUTH-03 | G-AUTH-03，agents=0 | 不可绕过 |
| scope 含未知键 | G-CONF-01 | G-CONF-01，agents=0 | 不可绕过 |
| workDir=`C:/work/../etc` | G-PATH-01 | G-PATH-01，agents=0 | 不可绕过 |
| hunt 无遥测数据源 | G-DS-01 | G-DS-01，agents=0 | 不可绕过 |
| exploit 缺 confirm | G-CFM-01 | G-CFM-01，agents=0 | 不可绕过 |
| exploit confirm 与目标不符 | G-CFM-02 | G-CFM-02，agents=0 | 不可绕过 |
| exploit mode=passive | G-MODE-02+G-CFM-03 | 两项同时命中，agents=0 | 不可绕过 |
| hunt targets=[] + logs 数据源 | 允许 | agents=1（按设计允许空 targets） | 符合设计 |
| **target URL + exclusion 默认端口** | G-TGT-04 | **无拒绝，agents=1** | **F1 绕过** |
| **target domain + exclusion 尾点** | G-TGT-04 | **无拒绝，agents=1** | **F1 绕过** |
| 对照：exact URL exclusion | G-TGT-04 | G-TGT-04，agents=0 | 证明差异来自归一化 |
| `cidr=0.0.0.0/32` / `::/128` / `https://0.0.0.0/` | G-TGT-02 | 通过（agents=1） | F12 表示形式缺口 |
| `cidr=0.0.0.0/1` | 期望拒绝（若按“无界扫描”语义） | 通过（agents=1） | F12 范围缺口 |
| URL `https://user:pass@app.example.com/` | G-TGT-03 | 通过（agents=1） | F12 格式校验缺口 |
| IPv6 `1::2::3` | G-TGT-03 | 通过（agents=1） | F12 格式校验缺口 |
| `dryRun:"0"` / `"TRUE"` | G-ARG-01 / 视为 true | 分别 G-ARG-01 / 通过 | 符合 |

### 4.2 guard（`tools/sec.mjs`）构造

- 精确 exclusion：`scope.exclusions=["https://app.example.com/"]`、target `https://app.example.com/` → `exit 1`、`rejectedBy=["G-TGT-04"]`、未 spawn。
- exclusion 写成 `https://app.example.com:443/`（默认端口）→ **`ok:true`、`dryRun:true`、argv 含目标**（`exit 0`）；同样输入的 workflow preflight 也不拒绝。→ F1 在工具运行时同源存在。
- exclusion 写成 `app.example.com.`（尾点）→ 同样 `ok:true`；这是**授权边界失效**，不只是文档问题。
- 缺 `--scope` 选项 → exit 2 usage（未 spawn）；`--scope` 不可读 → exit 1/G-AUTH-01（与 t7 W1 一致；W1 为 CLI usage 语义，不是门禁绕过）。

### 4.3 lint 是否可被绕过

- 不存在的路径 → `无法读取路径` exit 2（非静默通过）。
- **空目录**：`--strict --json <empty-dir>` → `checkedFiles=0, blockers=0`，**exit 0**（vacuous pass）。
- **未扫描扩展名**：构造 `references/evil.yml` 含真实非白名单域名，扫描根下同时有 `evil.md`；结果只报 `evil.md`，`.yml` 完全未读（checkedFiles=1）。当前插件内 `references/blue/templates/sigma.yml`、`icon.svg`、`cordis.patch.yml` 均属该缺口；人工通读确认当前内容干净，但“唯一确定性判据”无法证明未来变更。
- `--policy <path>` 可运行时覆盖 POLICY 常量（测试用），与“白名单/正则/阈值不允许运行时逐条豁免”存在张力（F4/F5）。

**对“授权门禁是否可绕过”的明确回答**：授权类型/有效期/时间窗/预算/targets 空/通配 `/0`/mode/confirm/未知键/路径穿越**未发现绕过**；但 **exclusions 归一化（G-TGT-04）存在可构造绕过（F1，high）**，且 0.0.0.0 的 `/32`、`::/128`、URL 包装形式与超宽 CIDR 未被 G-TGT-02 覆盖（F12，medium，低于 F1）。

## 5. 双用途风险（维度 5）

- 未发现可直接复制用于攻击第三方的完整制品：无 webshell/反弹 shell/C2/凭据 dump/malware/真实密钥；`test/fixtures/bad-r3` 的反例样本在 `test/`，不随包发布，且为 R3 负向测试所必需。
- 命令配方均参数化，且 bash 块前有 R3 授权横幅；红队参考明确“仅 scope.targets 内、重定向出域即停、不读业务数据、不落地凭据”。
- 停止条件/数据处置：`policy/authorization.md` §6 七条停止条件、§5 数据处置；`exploit-controlled.md` §6 清理清单、§7 停止条件；`dfir-playbook.md` §8 遏制只建议不执行。清晰。
- 残余风险：`guard --execute` 在授权齐备时是真执行（设计如此）；配方输出会返回 stdout 摘要（非原文落盘），操作者需自行遵守授权范围；`test/fixtures` 含一行反弹 shell 负例（不发布）。

## 6. 许可与归属（维度 6）

- `LICENSE` 11,271 B：Apache-2.0 全文（含 APPENDIX 与 `Copyright 2026 dsh-redblue contributors`）。
- `NOTICE` 3,626 B：三上游 repo URL + 三 commit + 许可 + used/excluded + `Modifications:` + Claude-Red MIT 全文（版权行与上游 `LICENSE` 逐字一致）+ 下游保留要求。
- 上游 pin 核对：三者 HEAD 与 NOTICE/frontmatter 一致；三者 pin 点均无 `NOTICE`，因此不触发 Apache-2.0 §4(d) 继承上游 NOTICE；本插件自建 NOTICE 合法。
- 修改声明：NOTICE 声明“rewritten/condensed/sanitized、非逐字复制、示例仅保留域”；references 的 `rewrite-summary` 逐篇记录删除内容。
- 结论：**许可合规（Apache-2.0 + MIT 归属）**；唯一瑕疵是 `references/red/extraction-ledger.md:5` 的 provenance 路径失实（F5），不影响许可结论。

## 7. DSH 集成正确性（维度 7）

- `package.json`：`type:module`、`main:lib/index.js`、`dsh.bundle.patch:./cordis.patch.yml`、零 dependencies/devDependencies、17 项 files 全部存在；与 `dsh-security` 的 bundle 形状一致（对照其 `lib/index.js`/`cordis.patch.yml`）。
- `cordis.patch.yml`：可解析的 `- insert: [{id:dsh-redblue,name:dsh-redblue}]`；与 dsh-security 相同模式。
- provider：实测 `apply(ctx)` 捕获 provider；`list()` 15 项、`rank=600`、`source=bundled`、`resourceBase` 指向存在的 skills 目录；`get()` 返回正文；未知 name → undefined；`lib/index.js` 仅 import `node:fs/promises`/`node:url`，无静态 peer import。
- workflow 工具约定：脚本无 fs/网络/Node API；使用 `args/phase/log/agent/parallel`；所有 agent 调用带 `{label,phase}`；meta 由入口技能要求 name/description/phases；`node --check` 通过（含 workflow/package.json commonjs 的 D-4 说明）。
- 运行证据：我独立复算 `.work/smoke/assess-captain-20261119-2115` 与 `recon-captain-20261119-2105` 的 manifest：两段各 7 件产物，**字节与 SHA256 均 0 mismatch**，`status=completed`、`exitCode=0`、`dryRun=true`、`mode=passive`；旧失败段 `assess-captain-20261119-1625` 仍为 `failed` 且 2 mismatch（未被隐藏）。
- 加载即崩风险：未发现；`workflow/package.json` 的 commonjs 只影响 Node 直接执行/`--check`，不影响以脚本文本执行的 workflow 工具（D-4 已记录）。

## 8. 可维护性（维度 8）

- 相对链接检查：13 条相对链接，唯一“DEAD”命中是 `docs/sanitization-rules.md:219` 的示例 `[x](url)`（非真实链接）；无实际死链。
- 参考清单：INDEX 列 27 篇 + INDEX；`find references -type f` 28 个文件（含 INDEX）一致；全部有消费者。
- **不一致项**：见 F3（value-extraction 数字/理由）、F6（red ledger ACS 2588）、F9（README/DETAIL hunt 阶段名；triage/harden report 阶段与 design/requirements 不一致）、F10（S8 笔误）、F14（sanitization-rules 仍写 17 篇、默认命令仍写 skills references，而实际 27 篇/默认插件根）。
- 装配报告 D-1..D-8 已记录新增 10 篇参考、预算收紧、dfir 两字符、workflow package.json、schema 6 件、tools 运行时等偏差；这些偏差本身不判失败。

## 9. 价值提炼充分性（维度 9）

- **红队 tool-recipes 抽样 F1（资产/子域）**：用途/前置/授权级别/三行命令模板（subfinder→dnsx→httpx，后者标注需 activeScan+dryRun=false）/输出解析（jq 过滤）/证据字段（commandSummary/ts/outputPath/sha256/bytes/excerpt/source）/检测视角/禁止事项/dry-run 语义，齐全且可直接执行。
- **蓝队 tool-recipes 抽样 B1/B2**：B1 sigma check/convert（离线 pipeline、产物写 workDir、证据字段 ruleId/ruleSha256/validatorOutput/convertedQuery/engine/convertedAt/pipelineRef）、B2 本地 jq 回放/阈值聚合/时间窗过滤、ATT&CK 映射、误报调优、边界与 dry-run，齐全；零网络本地导出，符合 NG-8。
- **sigma 模板**：14 个顶层键、`<RULE_TITLE>/<UUID>/<LEVEL>` 等占位符、假数据正例/反例/边界/缺失例、`condition` 显式 `not filter_*`、falsepositives 至少 3 条、误报/阈值注释；可用。已知 `rule lint` 不剥行内注释导致模板自身 exit 1（t7 W2，medium，已在 verification-report §14.11 受理；本次不重复计为 blocker，但建议一并修）。
- **台账 2 条抽样**：`references/red/extraction-ledger.md` #79（zigbee/thread/matter，6,586 B，merge→discover-wireless.md，理由“入网/密钥判定，去注入”）与 §8 I5（source_aware_discovery，10,895 B，keep→strix-techniques §5.2）都能在上游对应文件与插件目标文件中定位；我进一步用脚本逐行核对 **78/79 行全部路径与字节**（0 missing/0 size mismatch）。
- **809 agent.py → script-patterns**：S1 归一化、S2 授权门禁（39 G-*）、S3 dry-run 默认、S4 限速/超时、S5 结构化输出、S6 证据落盘、S7 退出码/状态；A1–A12 反模式（verify=False/shell=True/os.system/eval/无 dry-run/无限速/0-1 退出码/print/硬编码凭据/仅注释授权/结论外推/TODO）均来自 809 脚本统计，并给出正确做法。验收要求的六类（授权门禁/dry-run/限速/结构化输出/反模式）**全部被提炼**。
- **账目诚实性**：Claude-Red 79 = 14 keep/49 merge/16 drop（逐行与上游字节一致）；Strix 78 = 47/29/2（逐行一致）；Strix 9 = 2/7/0；ACS 818 = 60/672/86（60 具名 keep + 71 D1 + 14 D2 + 1 D3 + 672 余集，算术闭合；我用上游目录复算 818、D1 71、D2 14、>48KiB 1、809 agent.py，全部成立）；未发现静默遗漏。瑕疵：D1 规则未覆盖 `performing-*-penetration*` 等 9 个语义上的红队执行项，仍计入 merge；以及 red ledger 的 ACS 2588 误值（F6）。
- 结论：价值提炼层**充分**；问题主要是文档数字/分类口径，不是内容缺失。

## 10. Strix 吸收与 finding-review（维度 10）

- `strix-techniques.md` 抽样：§1 #1 SQLi（假设→最小验证→所需证据→误判边界→检测视角）、§2.1 Django（10 要素：入口/sink/授权陷阱/批量赋值/SSRF/模板/反序列化/CVE 族/高价值目标）、§4.1 AWS（IMDS v1/v2、ECS、IAM 提权与权限边界/SCP 误判、S3/快照、根因字段、验证要求）——**不是结论列表**，均含可执行验证与反证边界。
- 78 篇台账：逐行脚本核对 78 行、0 缺失、0 字节差异；47 keep/29 merge/2 drop；drop 仅 agent_browser.md 与 python.md，理由与零依赖/无浏览器一致；治理/基准 9 篇单独说明 78+9=87，不与技术正文混算。
- `finding-review.md`：三关闭态（confirmed/ruled_out/open_proof_gap）与 disposition 映射、九条“不能排除”、负向对照、归档四步、未确认候选门槛（四要素）、严重度校准（先可达性后定级、降级不删除）、修复验证六道门、withhold 与 gap 记录——**可操作**，不是原则口号。
- 瑕疵：§8/§187 声称 `confidenceRationale/counterevidence/severityChangeConditions/fixVerification/basis` 与 `schema/finding.schema.json` 一致，但 schema 为 `additionalProperties:false` 且未定义这些字段（F2）。

## 11. 工具运行时安全审查（维度 11）

- 入口唯一：`tools/sec.mjs` → `lib/cli.mjs` 固定 10 个子命令；未知子命令 `exec --cmd whoami` → usage exit 2，**无自由命令行入口**。
- `guard`：`findRecipe` 只接受 `tools/recipes.json` 中 10 条 id；argv 由 recipe 模板逐元素替换，`spawn(binary, argv, {shell:false})`（`tools/lib/guard.mjs:155`）；target 经 `validateTarget` 拒绝 `-` 前缀、空白、`;&|`$<>` 控制字符、`..`、非绝对 source 路径；allowlist 按归一化值精确匹配；`--execute` 还需 written 授权 + mode ≥ requiredMode + confirm 与 target 完全相等 + 二进制存在（`guard.mjs:275-347`）。
- 默认 dry-run（`execute===true` 才 spawn）；timeout/output 上限固定；evidence JSONL 仅 recipe/target/argv/ts/退出码/哈希，不落 stdout/stderr 原文（`guard.mjs:358-380`）。
- 注入构造：target 含 `;`/`$()`/空白/`-` 前缀被 G-TGT-03；URL 中 `%0a` 等编码形式仍在单个 argv 中且无 shell，不构成命令注入；source target 的 `..` 被 G-PATH-03。
- 发现：guard 与 workflow 共用 `gate.mjs`，因此 **F1 的 exclusions 归一化缺陷同样存在**；缺 `--scope` 为 usage exit 2（W1，未 spawn）；`--policy` 是测试注入点（F5）。
- 结论：guard 的“仅白名单 + argv 直传 + dry-run 默认 + execute 四重门禁 + evidence 只落哈希”成立；未发现自由命令或 shell 注入入口。

---

## 12. Findings（file:line 级，可直接修复）

> 以下为 t8 round-1 的 findings（历史记录）；逐条修复状态与残余项见 §15.2/§15.3。t20 已修复 F1、F4–F6、F9–F13；F2/F3/F7/F8 有残余（R1–R4）。

> 判定：F1 为 **high**，按任务规则 verdict=needs_revision；F2–F5、F12 为 medium；F6–F11、F13 为 low。无 blocker。R11 两条 warning 为已受理项，不重复计入。

### F1（high）G-TGT-04 exclusions 未按 SO-2 归一化，排除目标可被继续测试

- 位置：`workflow/assess.js:337`（`exclusionHits`，337–346）；同一内联块存在于其余 8 个 `workflow/*.js`；`tools/lib/gate.mjs:137`（`exclusionHits`，137–146）。
- 问题：实现只做 `toLowerCase()/trim()`，未按 SO-1 对 exclusion 做 domain/url/ip/cidr 归一化（requirements §9.2 SO-2、design §7.3 步骤 5、policy §2.2 明确要求）。构造证据：
  - assess：target `https://app.example.com/` + exclusions `["https://app.example.com:443/"]` → 未拒绝，agent 被调用；exact `["https://app.example.com/"]` → `G-TGT-04`、0 agent。
  - assess：target `app.example.com` + exclusions `["app.example.com."]` → 未拒绝；exact → G-TGT-04。
  - guard：同一默认端口/尾点 scope → `ok:true`（dry-run，argv 已含目标）；exact → exit 1/G-TGT-04。
  - 影响：`dryRun=false` 时授权客户明确排除的目标可能被探测/利用，违反 LC-2 “exclusions 必须生效且优先于 targets”，属于授权边界失效。
- requiredFix：在 `exclusionHits`/`checkScope` 中对 exclusion 按可推断 kind 调用 `normalizeDomain/normalizeUrl/normalizeIpv4/normalizeIpv6`（或同时比较原始与归一化值），再做相等与 domain/host 后缀匹配；同步修改 9 个 workflow 内联副本与 `tools/lib/gate.mjs`；在 `test/workflow.test.mjs` 增加“URL 默认端口/尾斜杠/fragment、domain 尾点、IP 前导零”exclusion 回归用例，并让 guard 测试复用同一构造。

### F2（medium）finding-review 声称的复核字段不在 finding schema 中

- 位置：`references/shared/finding-review.md:187`（另见 :63、:71、:181）；`schema/finding.schema.json:7`（additionalProperties:false）。
- 问题：reference 写“字段命名与 schema/finding.schema.json 一致：… confidenceRationale、counterevidence、severityChangeConditions、fixVerification、basis”，但 schema 的 properties 未定义这些字段且禁止额外字段。按 reference 产出的 finding 无法通过 schema 校验（或这些字段在写入时被丢弃），与“可审计证据链”目标冲突。
- requiredFix：二选一并保持一致——(a) 在 schema 中增加这些可选字段（同步 design §8.2 与 finding 字段表）；或 (b) 将复核意见定义为独立 review 记录/`notes` 子结构，并改写 reference 不再声称与 finding schema 一致；为 triage/validate 增加 schema 校验测试。

### F3（medium）docs/value-extraction.md 的统计与 drop 理由与台账/实测矛盾

- 位置：`docs/value-extraction.md:56`（另见 :28、:52、:105）。
- 问题：
  - :56 称“809 脚本中 0 个有 `--dry-run`、0 个有 `--output`、227 个使用 `requests`、35 个含 verify=False”；`references/blue/extraction-ledger.md` §7.3/§7.4 实测为 6 个 `--dry-run` 开关（8 处）、590 个 output 相关、HTTP 客户端 184+15+4（非 227）、36 个文件含 verify=False（字面量 35）。
  - :52 把 86 个 drop 描述为“纯课程/工具安装/与蓝队重复/连接器”，而台账 §5 是 D1 71 红队执行/武器化 + D2 14 治理 + D3 1 超限。
  - :28 把 9 个 drop 描述为“与 dsh-security 重叠或价值更低”，而红队台账实际是反取证/C2/EDR 规避/键盘记录/shellcode/数据外传/持久化/钓鱼/社工。
  - :105 写“107–175 行/个”，实测技能为 108–176 行。
- requiredFix：以台账 §7/§5/§3 与实测为准重写该文件相关段落；在 `test/` 增加一个文档一致性断言（至少校验 15 技能行数、809 统计关键数、drop 分类），或将该文件标注为“摘要，数字以台账为准”并去除具体错误数字。

### F4（medium）sanitize-lint 不扫描部分随包分发的非候选扩展名

- 位置：`tools/sanitize-lint.mjs:227`（`isCandidateFile`，仅 md/json/jsonl/js/mjs/cjs + NOTICE/LICENSE/SKILL.md）。
- 问题：`references/blue/templates/sigma.yml`、`icon.svg`、`cordis.patch.yml` 等随包文件不被 R1–R12 文本检查。实测在扫描根放 `evil.yml`（含真实非白名单域名）+ `evil.md`，只报 `evil.md`，`.yml` 未被读取（checkedFiles=1）。当前三件内容经人工通读干净，但“唯一确定性判据”无法覆盖未来变更。
- requiredFix：将 `.yml/.yaml/.svg/.txt` 纳入候选（至少对 `references/**/*.yml`、`cordis.patch.yml`、`icon.svg` 做 R2/R3/R10 文本检查）；为 `sigma.yml` 增加 R2/R10 断言；在 `test/sanitize.test.mjs` 增加扩展名正反例。

### F5（medium）provenance source-path 实际失实且 lint 不校验路径

- 位置：`references/red/extraction-ledger.md:5`（`source-path: Skills/README.md`）；`tools/sanitize-lint.mjs:554` 起的 R1-PROVENANCE 只校验键/pin/license/rewrite-summary。
- 问题：Claude-Red 在 pin 点只有仓库根 `README.md`，不存在 `Skills/README.md`；42 条 provenance 中 41 条路径可对应，1 条失实。路径真实性与 commit 一样属于 R1 可追溯性，但 lint 只做格式/集合检查，无法发现该错误。
- requiredFix：把该行改为 `source-path: README.md`；在 R1-PROVENANCE 中增加“source-path 在对应 pin 仓库存在”的可选检查（开发环境有 `.work/sources` 时执行，或用白名单常量），或在 `docs/verification-report.md` 增加逐条路径核对记录并作为人工评审门。

### F6（low）红队台账 ACS 库存数写成 2588

- 位置：`references/red/extraction-ledger.md:24`。
- 问题：行标签是 `skills/**/SKILL.md`，数量写 2588；实测 ACS `skills/<dir>/SKILL.md` = 818，2588 是整个 ACS 仓库的 `.md` 文件数。该错误与 requirements F-6（818/818）和 blue 台账 §1（818）矛盾。
- requiredFix：改为 818；若确实要统计全部 `.md`，另起一行标注“all .md = 2588，非技能数”，并在 §6 增加对应核对命令。

### F7（low）hunt-hypothesis 的 dataSources kind 不在 schema/G-DS-01 枚举内

- 位置：`references/blue/hunt-hypothesis.md:41`（`siem | edr | logs | telemetry-export | network | cloud | identity`）；:80–82 使用 `network/cloud/identity`。
- 问题：`schema/scope.schema.json` 的 `dataSources[].kind` 枚举无 `network/cloud/identity`；hunt 的 G-DS-01 只接受 `siem/edr/logs/telemetry-export`。按该参考写 scope 会被 G-CONF-01 拒绝，参考与可执行契约不一致。
- requiredFix：把矩阵中的 `network/cloud/identity` 映射到已注册 kind（`pcap`/`cloudtrail`/`logs`/`siem`），或同步扩展 schema、workflow `DATA_SOURCE_KINDS`/G-DS-01 与 requirements；增加 grep/单测确保 reference 中列出的 kind 均在 schema 中。

### F8（low）workflow preflight 未执行 schema 的长度/数量上限

- 位置：`workflow/assess.js:545`（reference 只查非空；:561 targets 只查数组；:640–663 dataSources 只查数组/路径）；`schema/scope.schema.json:16`（minLength 3、maxLength 200）、`:25`（targets maxItems 200）、`:73`（dataSources maxItems 64）、`:87`（notes maxLength 2000）。
- 问题：构造验证显示 `reference` 1/5000 字符、targets 300 项、label 500 字符、notes 5000 字符、dataSources 100 项、document 1000 字符均通过 preflight 并调用 agent。scope 可被放大，schema 契约与实现不一致。
- requiredFix：在 preflight 中实现 schema 的 minLength/maxLength/maxItems（或明确把 schema 当“建议”并改写 design §7.3）；为超限输入增加拒绝测试；同步 9 个 workflow。

### F9（low）README/DETAIL 的 hunt 阶段名与实现不符；triage/harden 的 report 阶段与 design/requirements 不一致

- 位置：`README.md:44`、`docs/DETAIL.md:49` 写 `scope→hunt-plan→hunt→report→seal`；实际 `workflow/hunt.js` 只有 `phase("scope")`、`phase("hunt")`、`phase("report")`、`phase("seal")`（design:469、requirements:104 为 `scope→hunt→report→seal`）。
- 另：`README.md:47`/`:48`、`docs/DETAIL.md:52`/`:53` 写 triage/harden 含 `report`，而 design:472/473 与 requirements:114/106 的 phase 列表不含 `report`；实际脚本通过 `finalize()` 调用了 `phase("report")`。三方（README/DETAIL、design/requirements、脚本）不一致。
- requiredFix：hunt 行改为 `scope→hunt→report→seal`；对 triage/harden 明确 `report` 是统一 finalize 阶段，更新 design/requirements 的 phase 列表（或从 README/DETAIL 删除）；在 `test/workflow.test.mjs` 或文档测试中断言 README 阶段串与 `phase()` 调用集合一致。

### F10（low）script-patterns 引用不存在的 S8

- 位置：`references/shared/script-patterns.md:279`（A7 正确做法列写“见 S8”）。
- 问题：全文骨架为 S1–S7，无 S8；读者无法跳转。
- requiredFix：改为“见 S7”；增加文档内 `S[1-9]` 引用检查。

### F11（low）seal 的“复算”是 agent 自证，不是脚本可强制的密码学校验

- 位置：`workflow/assess.js:1244`（`const sealed = seal.ok === true && mismatches.length === 0;`）；`README.md:62` 声称“seal 复算校验”。
- 问题：脚本无 fs，无法自行计算磁盘 SHA256；seal 阶段的 `ok/mismatches` 与 report-write 的 `sha256/bytes` 都是 agent 返回值。report-write 的 prompt 已包含期望 sha256，理论上 agent 可不写盘而回显期望值。当前 E2E 磁盘哈希与 manifest 一致（我独立复算 14/14），但这是“证据”而非脚本强制。属已知架构限制，需避免把“agent 自证”表述为密码学保证。
- requiredFix：在 README/design/policy 明确“seal 为 agent 复核 + 外部可复算”；在 `docs/tool-runtime.md` 推荐用 `tools/sec.mjs evidence verify` 或独立 SHA256 工具对 manifest 复算；可在 manifest 增加 `attestation: "agent-reported"` 字段（schema 同步）以消除歧义。

### F12（medium）G-TGT-02/G-TGT-03 仍是字面量匹配，未覆盖等价表示与 URL/IPv6 格式

- 位置：`workflow/assess.js:328`（`isWildcardTarget`）、`:258–321`（`normalizeIpv6`/`normalizeUrl`/`normalizeConfirm`）；`tools/lib/gate.mjs:129`。
- 问题：构造 `cidr=0.0.0.0/32`、`cidr=::/128`、`url=https://0.0.0.0/`、`cidr=0.0.0.0/1` 均通过 preflight（agent 被调用）；`url=https://user:pass@app.example.com/` 与 `ip=1::2::3` 通过 G-TGT-03。G-TGT-02 只匹配字面 `0.0.0.0`/`::`/`/0`，G-TGT-03 未校验 URL host 语法与 IPv6 组数。当前不导致第三方范围扩张（0.0.0.0 是本机/未指定地址；`/1` 仍受 budget 限制），但属“安全默认”与格式校验的完整性缺口。
- requiredFix：对 URL 目标解析 host 后拒绝 `0.0.0.0`/`::` 与非法 host（含 userinfo 明确策略）；`normalizeIpv6` 校验组数与 `::` 唯一性；`isWildcardTarget` 拒绝 unspecified address 的等价表示；对 CIDR 增加最小前缀/最大地址数限制（或在 policy 明确允许范围）；为以上构造增加测试。

### F13（low）sanitization-rules 仍写 17 篇参考/默认命令为 skills references

- 位置：`docs/sanitization-rules.md:33`（“17 篇派生参考 + INDEX”）、`:46`/`:435`（默认门禁 `skills references`）。
- 问题：实际 27 篇 + INDEX（assembly D-1 已记录新增 10 篇，但规则书未同步）；lint 无路径参数时默认扫描 `PLUGIN_ROOT`（`tools/sanitize-lint.mjs:1579`），README 也写“扫描插件根”，规则书仍写 `skills references`。这是基线文档与实现的漂移。
- requiredFix：将 §2 改为 27 篇（或“27 篇 + INDEX，新增见 assembly D-1”）；§3/§9 的默认命令改为与实现一致（默认插件根），保留“显式 skills references”作为快速门禁；在 docs 中记录一次变更。

---

## 13. Verdict（t8 round-1，历史）

- **needs_revision（仅 round-1）**。依据：F1（high）是授权边界（exclusions）的可构造绕过，未解决前不得判定可交付；F2–F5、F12（medium）与 F6–F11、F13（low）应在同一返工轮次修复或在 assembly/verification 报告中逐条受理。**t21 round-2 已据此修复并改判 PASS，见 §15。**
- **无 blocker**；两条 R11 warning（red-exploit/purple-verify）为 design 固定 description 触发，已在 `docs/assembly-report.md` §4 受理，不改变本判定。
- 返工后复审重点：F1 的 workflow + guard 双实现与负向用例；F2 schema 与 reference 对齐；F3 数字重写；F4/F5 lint 覆盖；F9 阶段名/文档一致性。

## 14. 证据与限制

### 14.1 本次实际执行的独立检查（摘要）

- 上游 pin：`git -C .work/sources/{claude-red,acs,strix} rev-parse HEAD` → 三个 pin 与 NOTICE 一致。
- 台账逐行：`.work/tmp_r8_ledger_check.mjs` → Strix 78 行 0 missing/0 size mismatch、47/29/2；Claude-Red 79 行 0 missing/0 size mismatch、14/49/16。
- ACS：`.work/tmp_r8_acs_check.mjs` / `_acs2.mjs` → 818 目录、D1 71、D2 14、D3 1（52,765 B）、809 agent.py；`verify=False` 36/118、`shell=True` 3/8、`os.system(` 2/2、`timeout=` 480/1410、`json.dump` 744/1275，均与台账 §7 量级一致。
- provenance：`.work/tmp_r8_prov.mjs` → 32 条注释头，1 条路径失实（F5）；`.work/tmp_r8_skillprov.mjs` → 15 技能 12 键/路径全通过。
- 技能字段：`.work/tmp_r8_skills.mjs` → 15/15 唯一、risk/requires/ingests 全匹配、13 个 target 技能全含 4 短语、desc 157–286、108–176 行。
- 门禁构造：`.work/tmp_r8_gate_probe.mjs` → 22 个构造，主要结果见 §4.1；`.work/tmp_r8_schema_probe.mjs` → 长度/数量上限未执行（F8）。
- 工具运行时：`node dsh-redblue/tools/sec.mjs guard ...` → exact exclusion exit1/G-TGT-04；默认端口/尾点 `ok:true`（F1）。
- 净化：`node tools/sanitize-lint.mjs --strict --json dsh-redblue` → 83 文件/0 blocker/2 warning；`--list-checks` 36；空目录/`.yml` 扫描构造见 §4.3（F4/F5）。
- DSH：`node --input-type=module` 调用 `apply`/`list`/`get` → 15 项/rank600/未知 undefined；`.work/tmp_r8_smoke.mjs` → 两段 7/7 产物 0 mismatch，旧失败段 2 mismatch 保留。
- 许可：`head` 对照三上游 LICENSE；`NOTICE`/`LICENSE` 全文与字节数；三 pin 无 NOTICE。
- 链接：`.work/tmp_r8_links.mjs` → 13 条相对链接，唯一命中为 `[x](url)` 示例（非死链）。

### 14.2 限制（如实记录）

- 未在本轮重新用原生 `workflow` 工具跑 E2E（会改变 `.work/smoke`，且 t19 已复验）；改为对现有两段 workDir 独立复算 14/14 哈希与 manifest，并核对旧失败段未被隐藏。
- 未逐行通读 78 篇上游全文；采用逐文件路径/字节/决策账 + 插件内容的 3 类抽样（SQLi/Django/AWS）。
- 未在非 MSYS 的纯 Windows shell/无 Node 环境复测；未运行网络/白名单工具配方（按授权门禁保持零网络）。
- 未修改 `.work/sources/`、workflow/skills/references/tools/test/package.json/policy/docs（本文件除外）；临时脚本位于 `.work/tmp/`，评审后清理。
- 未把 `docs/verification-report.md` 的 W1–W3 重新计为 findings；其中 W2（sigma 模板 rule lint 行内注释）与 F4 相关，建议一并修。

---

# 第 2 部分：t21 第二轮复审（review-round-2）

## 15. t21 复审记录

- 复审对象：t20 对 t8 F1–F13 的修复（`workflow/*.js` 9 份、`tools/lib/{gate,guard}.mjs`、`tools/sanitize-lint.mjs`、`schema/finding.schema.json`、`test/{workflow,sanitize,tool-runtime}.test.mjs`、`policy/*.md`、`docs/{value-extraction,sanitization-rules,assembly-report,DETAIL}.md`、`README.md`、`references/{red/extraction-ledger,blue/hunt-hypothesis,shared/script-patterns}.md`）。
- 复审时间：2026-11-19 23:30–23:50 +08:00。
- 方式：**只读 + 独立构造/复算**；未修改被评审文件；未触发网络；未运行白名单工具配方；未重跑原生 E2E（沿用 t19 的 `.work/smoke` 证据，本轮只读复算未变）。
- **结论：PASS（0 blocker / 0 high）**。F1 已修复并被独立构造确认；F12/F4/F5/F6/F9/F10/F11/F13 已验证修复；F2/F3/F7/F8 有残余 R1–R5（medium/low），按任务判定规则（无 blocker/high 且中低风险可接受）判 pass，残余项列入 §15.3 供后续修复。

### 15.1 复审命令与证据（本次实际执行）

| 检查 | 结果 |
|---|---|
| 自建 `new Function` 门禁探针（41 个构造，含 9 类 exclusion、CIDR/URL/IPv6、schema 上限、正例回归） | **41/41 符合期望**；见 §15.2 |
| `node tools/sanitize-lint.mjs --strict --json dsh-redblue` | 87 文件、0 blocker、2 warning（R11 既有两处，已受理），exit 0 |
| `node tools/sanitize-lint.mjs --strict --json skills references workflow lib policy schema package.json NOTICE` | exit 0 |
| `node tools/sanitize-lint.mjs --list-checks` | 36 条（34 blocker/2 warning） |
| 空目录扫描 | 无 `--allow-empty` → exit 2（不再 vacuous pass） |
| 临时 `evil.yml` + `evil.md` | 两者都被 R2 命中；`evil.yml` 不再漏扫 |
| 临时 provenance `source-path: Skills/README.md` | R1-PROVENANCE 报“不存在”，exit 1（路径校验生效） |
| `node --test test/scaffold.test.mjs test/sanitize.test.mjs test/workflow.test.mjs test/tool-runtime.test.mjs` | **89/89 pass**（scaffold 9 / sanitize 24 / workflow 37 / tool-runtime 19） |
| 全部 `.js/.mjs` `node --check` | 27/27 通过 |
| `guard` 精确 exclusion / 默认端口 / 尾点 / CIDR /1 / userinfo scope | 均 exit 1 且未 spawn；合法 URL/domain dry-run exit 0 |
| 上游 pin | 三仓库 HEAD 仍为 `6196ba74…`、`54a79883…`、`8db295a5…`，与 NOTICE/台账一致 |
| 台账 | 78 行 I1–I78（47/29/2）、79 行 Claude-Red（14/49/16）未漂移；插件 0 个 `.py` |

### 15.2 逐条 finding 复核

| ID | 状态 | 本轮证据 |
|---|---|---|
| F1 high | **fixed** | 9 个 `workflow/*.js` 与 `tools/lib/gate.mjs` 均有归一化 exclusion；独立构造：URL 默认端口/fragment/根斜杠、domain 尾点/大小写、IPv4 前导零、domain↔URL 交叉、domain 后缀 **全部 G-TGT-04 + 0 agent**；exact 对照同样拒绝；非命中 exclusion 仍允许（agent 调用）；guard 同 scope exit1/G-TGT-04，合法 scope dry-run exit0 |
| F2 medium | **partial / 残余 R2** | schema 已增加 5 个可选字段并通过结构测试；但 `normalizeFinding` 仍未复制这些字段（见 R2） |
| F3 medium | **partial / 残余 R4** | 6 dry-run/590 output/184+15+4/36 verify=False 已修正；D1/D2/D3 已修正；但 §2.1 的 9 个 drop 理由仍错误（见 R4）；15 技能 107–175 行按 R6 口径正确（本轮确认 t8 的 108–176 是未剥离尾空行的计数差异，不构成缺陷） |
| F4 medium | **fixed** | `.yml/.yaml/.svg/.txt` 纳入候选 + asset kind；空目录 exit 2；sigma.yml/asset 参与 R2/R10；实测见 §15.1 |
| F5 medium | **fixed** | ledger `README.md`；R1 在 `.work/sources` 存在时校验 source-path；负向 fixture 被 blocker |
| F6 low | **fixed** | ACS 行 818，另注 all .md=2588；§6 核对命令 |
| F7 low | **partial / 残余 R3** | kind 改为 siem/edr/logs/telemetry-export/pcap/cloudtrail 并过 schema；但 hunt 的 G-DS-01 仍只接受四类（见 R3） |
| F8 low | **partial / 残余 R1** | 9 个 workflow 已执行 `validateScopeLimits`（1/5000 ref、300 targets、500 label、5000 notes、100 dataSources、1000 document 均拒绝；边界值 3/200 ref、200 targets、64 dataSources 通过）；但 `tools/lib/gate.mjs` 的同名函数是死代码（见 R1） |
| F9 low | **fixed（有受理限制）** | README/DETAIL hunt 行已改 `scope→hunt→report→seal`，无 `hunt-plan`；triage/harden 保留最终 `report`；design/requirements 冻结仍写 triage/harden 无 report，已在 assembly §9.3 记录 |
| F10 low | **fixed** | A7 改“见 S7”，无 S8；测试通过 |
| F11 low | **fixed** | README §2 明确 seal = agent 只读复核 + 外部 `evidence verify`，不再表述为密码学保证；design §8.5 冻结，未同步（受理） |
| F12 medium | **fixed** | 0.0.0.0/32、::/128、0.0.0.0/1、URL 0.0.0.0、userinfo、`1::2::3` 全部拒绝；`10.0.0.0/8`、`2001:db8::/32`、`https://app.example.com:8443/x`、`http://[::1]/` 仍通过；见 §15.1 |
| F13 low | **fixed** | sanitization-rules 27 篇 + INDEX；默认/发布命令为插件根；测试通过 |

### 15.3 残余 findings（本轮不阻塞，建议下一轮修复）

#### R1（medium）`tools/lib/gate.mjs` 的 `validateScopeLimits` 是死代码，`scope check`/guard 仍不执行 schema 上限

- 位置：`tools/lib/gate.mjs:295`（定义）；`tools/lib/gate.mjs:334` 起的 `checkScope` 未调用它（`grep validateScopeLimits` 只有 295 一行）。
- 问题：独立实测 `node tools/sec.mjs scope check --scope <reference 5000 字符>` 返回 `ok:true`；同 scope 的 `guard` dry-run 返回 `ok:true`。与 9 个 workflow 已执行的 limits 不一致，也与 `schema/scope.schema.json` 的 min/maxLength/maxItems 不一致。当前不是授权绕过（target 仍逐项校验），但 scope 可被放大，且 t20 的“workflow + gate 同步”声明只对 workflow 成立。
- requiredFix：在 `checkScope` 的对象检查后调用 `validateScopeLimits(raw, reject)`；把 `limit`/maxItems 逻辑抽成共享函数；为 `scope check` 与 guard 增加 5000-char reference/300 targets 拒绝测试；如需保持 CLI 向后兼容，可先在 `scope check` 默认启用、guard 强制执行。

#### R2（medium）finding-review 的 5 个复核字段仍未写入 workflow 产物

- 位置：`workflow/assess.js:983`（finding 对象构造）、`workflow/triage.js:1491`（merged 构造）；`references/shared/finding-review.md:181/187` 声称这些字段在 `findings.json`。
- 问题：schema 已接受 `confidenceRationale/counterevidence/severityChangeConditions/fixVerification/basis`，但 `normalizeFinding` 只复制固定字段列表，不复制这 5 个；triage 的 `merged` 也只列固定字段。因此“schema 接受”与实际落盘不一致，finding-review 的审计字段无法出现在 `findings.json`。`basis` 在 `normalizeFinding` 中只是指纹局部变量，不会落盘。
- requiredFix：在 `normalizeFinding` 中按白名单复制这 5 个可选字符串字段（长度≤4000），或在 `references/shared/finding-review.md`/schema 中把它们定义为独立 review 记录并改写“findings.json 字段”表述；为 triage 输出增加“字段落盘”断言（不只是 schema 结构断言）。

#### R3（medium）hunt reference 的 pcap/cloudtrail 仍不满足 G-DS-01

- 位置：`references/blue/hunt-hypothesis.md:41`（`... | pcap | cloudtrail`）、`:80–82`；`workflow/hunt.js:1446`（`requireDataSources: kinds ["siem","edr","logs","telemetry-export"]`）。
- 问题：reference 把网络流量/云审计标为 `pcap`/`cloudtrail`，但 hunt preflight 的 G-DS-01 只接受四类；授权操作者按 reference 提供 pcap/cloudtrail 时会被拒绝，尽管 schema 与 `DATA_SOURCE_KINDS` 允许这两个 kind。t20 的测试只检查“kind ∈ schema/全局常量”，未检查 hunt 的 requireDataSources。
- requiredFix：二选一并测试——(a) reference 将 pcap/cloudtrail 映射为 `telemetry-export`（或 `logs`）登记，注明“pcap 以 telemetry-export 接入”；或 (b) 在 requirements/design 允许的前提下把 pcap/cloudtrail 加入 G-DS-01，并同步 workflow CONFIG 与测试。

#### R4（low）value-extraction §2.1 的 9 个 drop 理由仍与红队台账不符

- 位置：`docs/value-extraction.md:28`。
- 问题：仍写“9 个定位冲突项（与 dsh-security 源码审计重叠、或与 Strix/ACS 重复且价值更低）”；红队台账 §3 的 9 项是反取证、C2、EDR 规避、键盘记录、shellcode、数据外传、持久化、钓鱼、社工。t20 只修了 §3.1 的 D1/D2/D3；本条仍误导价值判断。
- requiredFix：按红队台账 §3 重写这 9 项分类（或直接引用台账 §3，不再自写摘要）；在 value-extraction 测试中加一条“9 项名单/理由与红队台账一致”的断言。

#### R5（low）CIDR /8–/32 与 /32–/128 的运行期限制未同步到 design/schema/requirements（受理限制）

- 位置：`policy/authorization.md:78`（允许 /8–/32、/32–/128）；`schema/scope.schema.json:31`（kind 枚举，无 CIDR 前缀静态约束）；`docs/design.md:751` 仍为“IPv4 0–32、IPv6 0–128、前缀 0 拒绝”。
- 问题：实现比冻结基线更严格（`10.0.0.0/7` 被 G-TGT-02 拒绝），安全方向正确，但授权方若确实持有 /7 会被误拒；design/requirements 未同步是 t20 已知受理限制（assembly §9.3），不是安全漏洞。
- requiredFix：下一版设计评审在 design §7.2/§7.3 和 schema 增加 `pattern`/`description`（或在前言声明“静态 schema 允许、运行期最小前缀 /8、/32 由 policy 生效”）；若产品要允许更宽 CIDR，改成可配置最小前缀并加测试。

#### R6（low）R1 仍不检查 asset（sigma.yml/icon.svg）的 provenance，assembly 的“纳入 R1”表述不准确

- 位置：`tools/sanitize-lint.mjs:586`（R1 只遍历 `["skill"]` 与 `["reference"]`）；`docs/assembly-report.md:128` 声称 `sigma.yml/icon.svg` 纳入 R1/R2/R10。
- 问题：`references/blue/templates/sigma.yml` 是 asset，R2/R10 已覆盖，R1-PROVENANCE 未遍历 asset；该文件手工检查 provenance 6 键齐全，但 lint 不证明。属覆盖表述/覆盖范围瑕疵，不是内容缺陷。
- requiredFix：R1 对带 `# dsh-redblue:provenance` 的 asset 执行 6 键/pin/license/path 检查，或修正 assembly 表述为“R2/R10 覆盖 asset，R1 由人工抽样”；加一个 asset provenance 正/反例。

#### R7（low）`--policy` 仍可在运行期覆盖 POLICY，发布门禁可被弱化

- 位置：`tools/sanitize-lint.mjs:1561/1575/1616`。
- 问题：`--policy <path>` 以 `{...DEFAULT_POLICY, ...raw}` 覆盖白名单/阈值；policy/sanitization §8 说“不允许运行时逐条豁免”。该参数是测试用，但发布命令若误用可绕过 R1–R12。属可用性/保证性风险，不是当前内容缺陷。
- requiredFix：将 `--policy` 限制为 `NODE_ENV=test` 或显式 `--allow-policy-override`；在 README/§3 标注“发布门禁不得带 --policy”；加测试确认默认 CLI 无该参数时使用内嵌 POLICY。

#### R8（low）design/requirements 冻结导致 triage/harden 的 report 阶段仍是“文档缺失”，seal 仍无 attestation 字段

- 位置：`docs/design.md:472/473`（triage/harden phase 无 report）、`docs/design.md` §8.5（seal 字段）；`docs/assembly-report.md` §9.3 已受理。
- 问题：README/DETAIL/实现一致（含 report），design/requirements 与实现不一致；seal 的 agent 自证语义已由 README 说明，但 design 未同步。属文档债，不是行为缺陷。
- requiredFix：下一版设计评审同步两处；若允许改 schema，给 manifest 加 `attestation:"agent-reported"` 或在 design §8.5 写明外部复算命令。

### 15.4 结论与判定

- **PASS**：F1 high 已修复且独立构造复核；无 blocker/high。F12（medium）亦已修复；F2/F3/F7/F8 的残余为 R1–R4（medium/low），R5–R8 为文档/保证性 low；按“无 blocker/high 且中低风险可接受”判 pass。
- 残余项不改变交付判定，但建议在下一轮一并修复 R1（gate limits）、R2（review 字段落盘）、R3（hunt pcap/cloudtrail）——这三项影响契约完整性/可用性；R4–R8 为文档与保证性改进。
- 本轮未修改被评审文件；仅追加本 §15。临时探针脚本在 `.work/tmp/`，评审后清理；未改 `.work/smoke`、`.work/sources`。

### 15.5 本轮证据限制

- 未重跑原生 `workflow` 工具 E2E（避免改变 `.work/smoke`；t19 已对两段 14/14 哈希复算，本轮只读核对 manifest 未变）。
- 未逐行重读 78 篇上游全文；以逐文件账目 + 抽样（SQLi/Django/AWS）判定；t20 未改这些内容。
- 未在无 `.work/sources` 的打包环境验证 R1 source-path 检查（该检查按设计仅在开发快照存在时执行）；这是 F5 的已受理限制。
- 未把 t7 的 W1–W3 重新计为 findings；W2（rule lint 行内注释）仍建议与 F4 一起修。

---

# 第 3 部分：t27 当前字节最终复审（final，替代 t21 verdict）

## 16. t27 复审记录

- 复审人：reviewer2（AgentTeams member；t27 final round）
- 复审时间：2026-11-20 09:36–09:58 +08:00；主机 Windows x64 / Node v24.22.1
- 复审对象：`dsh-redblue@0.1.0` **当前字节**（t20 + t22 修复、t26 全量验证之后的工作区快照）。§15 的 t21 verdict 不覆盖当前字节，本部分为新的独立判定。
- 方式：**只读 + 独立构造/复算**。除本文件外未修改任何被评审文件（改动前后对插件 116 个文件做 SHA256 快照比对，见 §16.10）；未触发网络；未运行任何白名单工具配方（guard 的 `--execute` 只走到“拒绝/缺二进制”分支，未 spawn 任何目标程序）。
- **结论：PASS（0 blocker / 0 high）**。F1/F12 修复保持有效（9 workflow + gate + guard 三入口独立构造）；R1–R3 已修复且本轮独立复跑确认；R4–R7 已修复、R8 维持受理（理由充分）；净化与价值层未被 t20/t22 改坏。残余 2 条 low（R9/R10）+ 3 条观察不改变判定。

### 16.1 本轮实际执行的检查（命令与结果）

| 检查 | 命令/方法 | 结果 |
|---|---|---|
| 净化门禁 | `node dsh-redblue/tools/sanitize-lint.mjs --strict --json dsh-redblue` | **87 文件 / 0 blocker / 2 warning**（purple-verify:3、red-exploit:3，§4 已受理），exit 0 |
| 检查表 | `node dsh-redblue/tools/sanitize-lint.mjs --list-checks` | 36 条（与 sanitization-rules §7 一致） |
| 测试 | `node --test test/{scaffold,sanitize,workflow,tool-runtime}.test.mjs` | **98/98**（9/24/42/23），exit 0 |
| 语法 | 全部 `.js/.mjs` `node --check` | **27/27** |
| 工作流探针 | 自建 `node:vm` 沙箱（9 胶囊 × 25 构造） | **225/225**；负向均 `rejected` + 0 agent |
| gate 直连 | `import { checkScope } from tools/lib/gate.mjs`（同 25 构造） | **25/25** |
| limits 直连 | gate `checkScope` 6 例（5000 参考/300 targets/5000 notes/100 dataSources/200+200 边界） | **6/6** |
| CLI scope check | 5000 reference、300 targets、200/200 边界 | exit 1/1/0（G-CONF-01） |
| CLI guard | dry-run 合法、超限 `--execute`、默认端口/尾点 exclusion、缺二进制 `--execute` | exit 0 / 1(G-CONF-01) / 1(G-TGT-04) / 1(G-EXEC-01)；拒绝时 workdir **0 文件** |
| F1/F12 段落一致性 | 9 workflow normalization/exclusion/limits 段 + gate 段哈希 | 9 份 `norm=e799b749…`、`excl=8e0a96be…`、`limits=54f3f88b…`；gate 段去 `export` 后逐字节相同 |
| R2 | 9 workflow `normalizeFinding` 段哈希 + assess/triage 全量跑 | 段哈希唯一 `fc3b7f3b…`；findings.json 5/5 字段落盘（triage 含 review→disposition 回退） |
| R3 | hunt pcap/cloudtrail/telemetry-export/siem + network/zeek/proxy | 前 4 类 `clean/exit0/7 artifacts`；后 3 类 `rejected`、`G-CONF-01`+`G-DS-01`、0 agent |
| 净化内容级 | 密钥/凭据/武器化/长 hex 全库 grep + provenance 复核 | 0 命中（仅规则文本、fixture、台账理由）；27/27 provenance 六键 |
| 价值层账目 | 只读复跑 `.work/tmp/acs-script-stats.mjs` + 台账逐行解析 | 818/60/672/86、79/14/49/16、78/47/29/2 全部对上；§7 统计逐项对上（见 §16.7） |
| E2E 只读 | 独立复算 `.work/smoke` 两段 manifest | recon 7/7、assess 7/7 = **14/14** 零 mismatch；`completed/exit0/dryRun=true/mode=passive` |
| DSH provider | 以 stub ctx 调 `lib/index.js` 导出的 `apply` | 15 项、`rank=600`、`source=bundled`、未知 name → `undefined`、正文来自 SKILL.md |
| 改动面 | 插件根 116 文件 SHA256 前后比对 | 仅本文件变化（§16.10） |

### 16.2 十一维度结论（当前字节）

| # | 维度 | 结论 | 最强证据 |
|---:|---|---|---|
| 1 | 需求符合性 | **通过** | 15 技能/9 workflow/授权门禁/report-only 默认/红蓝紫闭环/与 dsh-security 分工均在当前字节成立（§16.1、§16.7） |
| 2 | 净化合规（R1–R12） | **通过** | 87 文件 0 blocker、2 条 R11 已受理；27/27 provenance 六键 + source-path 在 `.work/sources` 快照中真实存在；docs/fixtures 排除为规则书明文 |
| 3 | 方法论深度 | **通过** | 抽样 `skills/blue-hunt`（判定标准/证据要求/三态收口）、`skills/red-validate`（证据重读/独立推断/误报剔除/CVSS/ATT&CK）、`strix-techniques.md` §1/§4 均到判定级 |
| 4 | 安全默认不可绕过 | **通过** | 9 workflow × 25 构造 225/225；gate 直连 25/25；F1/F12 三入口一致；guard `--execute` 四重门禁未被弱化 |
| 5 | 双用途风险 | **通过（有边界约束）** | 0 可复制武器化制品；仅 fixture/规则文本/台账理由命中关键词；默认 dry-run、confirm、exclusions、数据处置齐备 |
| 6 | 许可与归属 | **通过** | 三上游 HEAD 与 NOTICE/provenance pin 逐字一致（6196ba74…/54a79883…/8db295a5…）；Apache-2.0 全文 + MIT 全文 + 修改声明 |
| 7 | DSH 集成正确性 | **通过** | 与 dsh-security 同形态 `cordis.patch.yml` + `apply/inject/name`；stub provider 15/rank600/bundled；`package.json` exports 含 `./icon`；17 项发布清单 |
| 8 | 可维护性 | **通过（残余 1 条 low 文档漂移）** | 无死链；R9：2 个技能内联表仍写 4 类 dataSources（见 §16.8）；不影响门禁/落盘 |
| 9 | 价值提炼充分性 | **通过** | 红/蓝配方各抽样 1 族（9 要素 + 授权横幅）、3 模板（provenance + 占位符）、台账逐行复算（§16.7） |
| 10 | Strix 吸收与 finding-review | **通过** | 78 篇库存 78/78 全覆盖（0 missing/0 size mismatch、47/29/2）；30 行漏洞决策表 + 5 框架；finding-review 被 rb-triage/purple-verify 引用 |
| 11 | 工具运行时安全 | **通过** | 10 条白名单配方、dry-run 默认、`--execute` 需 written+mode+allowlist+confirm+二进制；超限 scope 在 spawn 前 exit 1、0 文件 |

### 16.3 F1 / F12 保持有效（独立构造，不复用 t20/t21/t26 用例）

方法：自写 `node:vm` 胶囊宿主（`agent/phase/parallel/pipeline` stub，记录 agent 调用次数），对 9 个 workflow 各跑 25 个构造；另用 `tools/lib/gate.mjs` 直连同构造；CLI 侧用自建 scope JSON 跑 `scope check`/`guard`。

**F1 exclusions（9 workflow × 11 构造 = 99/99 符合期望）**

| 构造 | 期望 | 实测 |
|---|---|---|
| target `https://app.example.com/` + exclusion `https://app.example.com:443/` | 拒绝 | 9/9 `G-TGT-04` + 0 agent |
| target URL + exclusion 带 `#frag` | 拒绝 | 9/9 `G-TGT-04` |
| target `https://app.example.com` + exclusion `https://app.example.com/`（根斜杠） | 拒绝 | 9/9 `G-TGT-04` |
| target domain + exclusion 尾点 `app.example.com.` | 拒绝 | 9/9 `G-TGT-04` |
| target 大写 + exclusion 大小写混合 | 拒绝 | 9/9 `G-TGT-04` |
| target ip `10.1.2.3` + exclusion `010.001.002.003` | 拒绝 | 9/9 `G-TGT-04` |
| domain target ↔ URL exclusion（交叉） | 拒绝 | 9/9 `G-TGT-04` |
| URL target ↔ domain exclusion（交叉） | 拒绝 | 9/9 `G-TGT-04` |
| domain target 子域 + 父域 exclusion（后缀） | 拒绝 | 9/9 `G-TGT-04` |
| exact 对照 | 拒绝 | 9/9 `G-TGT-04` |
| 非命中 exclusion | 放行 | 9/9 放行（agent 23–34 次） |

**F12 目标形态（9 workflow × 14 构造 = 126/126 符合期望）**

| 构造 | 期望 gate | 实测 |
|---|---|---|
| cidr `0.0.0.0/32`、`0.0.0.0/1`、`10.0.0.0/7`、`::/128`、`2001:db8::/31` | G-TGT-02 | 9/9 全部 G-TGT-02 + 0 agent |
| ip `0.0.0.0` | G-TGT-02 | 9/9 |
| url `https://0.0.0.0/`、`https://[::]/`、`https://user:pass@app.example.com/` | G-TGT-03 | 9/9 |
| ip `1::2::3`（非法 IPv6） | G-TGT-03 | 9/9 |
| 正向：`10.0.0.0/8`、`2001:db8::/32`、`https://app.example.com:8443/x`、`http://[::1]/` | 放行 | 9/9 放行 |

- gate 直连同 25 构造 **25/25**；`normalizeDomain/normalizeIpv6/normalizeUrl/exclusionHits` 在 9 workflow 与 gate 中一致（段哈希见 §16.1）。
- guard CLI：默认端口 exclusion `--execute` → exit 1 `["G-TGT-04"]` 且 workdir 0 文件；尾点 exclusion（dry-run）→ exit 1 `G-TGT-04`；非命中 exclusion dry-run → exit 0；合法 dry-run → exit 0。
- 结论：**F1（high）与 F12（medium）修复保持有效，t20/t22 未回退**。

### 16.4 R1–R3 复核（t22 修复验证）

**R1（gate/guard 执行 schema 上限）— fixed**

- 代码：`tools/lib/gate.mjs:296` 定义 `validateScopeLimits`，`:349` 在 `checkScope` 对象检查后调用；与 9 workflow 的 limits 段去 `export` 后**逐字节相同**（9 份 `54f3f88b…`）。
- CLI：`scope check` 5000 字符 reference → exit 1 `G-CONF-01`（“长度必须是 3–200”）；300 targets → exit 1 `G-CONF-01`（“targets 最多 200 项”）；5000 notes、100 dataSources 同拒绝；200 字符 + 200 targets 边界 → exit 0。
- guard：超限 scope `--execute` → exit 1 `G-CONF-01`、workdir 0 文件、未 spawn；合法 dry-run → exit 0。
- 结论：t21 R1 的“死代码/两套入口不一致”已消除。

**R2（5 个复核字段落盘）— fixed**

- 9 份 `normalizeFinding` 的复核字段块哈希唯一（`fc3b7f3b…`）；`buildPrompt` 9/9 含同一提示（`workflow/assess.js:887`）。
- 我用自建 agent 回复跑完整 assess：findings.json 中 `confidenceRationale/counterevidence/severityChangeConditions/fixVerification/basis` **5/5 与输入逐字相等**，`status=clean/exitCode=0`。
- triage：只把 `confidenceRationale` 放在 review、其余 4 项放在 disposition → findings.json **5/5 仍完整**（`workflow/triage.js:1518–1522` 的回退生效），`status=clean/exitCode=0`。
- schema 接受 5 字段（`schema/finding.schema.json:83–87`，`additionalProperties:false` 不变）。

**R3（hunt 接受 pcap/cloudtrail）— fixed**

- `workflow/hunt.js:1451` 的 G-DS-01 kinds = `siem/edr/logs/pcap/cloudtrail/telemetry-export`；`DATA_SOURCE_KINDS`（`hunt.js:16`）同集；schema `dataSources[].kind` 枚举（`schema/scope.schema.json:79`）包含两类；`policy/authorization.md:142`、`references/blue/hunt-hypothesis.md:41` 同步。
- 独立跑：pcap / cloudtrail → `status=clean`、`exitCode=0`、7 artifacts、12 agent；telemetry-export/siem 同；未知 kind `network`/`zeek`/`proxy` → `rejected` + `["G-CONF-01","G-DS-01"]` + 0 agent。
- 残余：`skills/blue-hunt/SKILL.md:42`、`skills/detect/SKILL.md:42` 仍写 4 类（低风险文档漂移，见 §16.8 R9）。

### 16.5 R4–R8 逐条判定

| ID | 判定 | 依据（file:line） |
|---|---|---|
| R4 low | **已修复** | `docs/value-extraction.md:28` 9 项 drop 改为「反取证、C2、EDR 规避、键盘记录、shellcode、数据外传、持久化、钓鱼、社工」，并指向 `references/red/extraction-ledger.md` §2 的 #21/#22/#28/#30/#31/#37/#39/#44/#45；我逐行核对台账 §2 行 50/51/57/59/60/66/68/73/74 与 §3 汇总行 121 一致，旧表述“重叠/价值更低”仅出现在“而非…”否定句中 |
| R5 low | **已修复（文档侧）** | `policy/authorization.md:82` 明示 IPv4 /8–/32、IPv6 /32–/128 运行期限制与冻结 design §7.2 的差异；我的构造 `10.0.0.0/7`、`2001:db8::/31` 均 G-TGT-02，`/8`、`/32` 放行；`schema/scope.schema.json:31` 仍无前缀 pattern（已受理，静态 schema 无法表达） |
| R6 low | **已修复** | `tools/sanitize-lint.mjs:665` 对声明 provenance 的 asset 执行六键/pin/license/path 校验（helper `:584`，消息前缀 `asset `）；独立构造：坏 commit 的 `sigma.yml` → 1 blocker、合法副本 → 0 blocker；`references/**` 下的复制品按 reference 归类（`icon.svg` 在根目录时才属无 provenance asset）；`docs/sanitization-rules.md:213–214` 与 `docs/assembly-report.md:128` 表述同步 |
| R7 low | **已修复** | `tools/sanitize-lint.mjs:1602` 默认拒绝 `--policy`（exit 2，stderr 明确指出 `--allow-policy-override`）；`NODE_ENV=test` 或 `--allow-policy-override` 放行；`docs/sanitization-rules.md:65–67/86–87/433` 写明发布门禁不得携带；独立三态复测与 t22 一致 |
| R8 low | **维持受理（理由充分）** | `docs/assembly-report.md:171` + §9.3（`146–152`）逐条受理 design/requirements 冻结债：triage/harden 的 report 阶段、seal attestation、`docs/requirements.md:231` 的 G-DS-01 四类 kind 与实现差异。实现是**放宽数据源枚举**（不削弱拒绝语义），且 policy/schema/reference 已按现实同步；下一版设计评审统一同步，属可接受文档债 |

补充：t21 的 F2/F3/F7/F8 残余（即 R1/R2/R3/R4）均已在 t22 修复并本轮复核；F4/F5/F6/F9/F10/F11/F13 的 t20 修复未被 t22 改动（对应文件 mtime/hash 与 §15 记录一致）。

### 16.6 净化合规复核（内容级，不只看 lint）

- **门禁**：87 文件 0 blocker、2 warning（R11 术语：`skills/purple-verify/SKILL.md:3`、`skills/red-exploit/SKILL.md:3`），`docs/assembly-report.md:64–88` 已受理；R11 为 warning 级且 design 固定 description，不阻断。
- **扫描范围**：`isCandidateFile`/`collectFiles` 覆盖 yml/yaml/svg/txt/ts 等，且明确排除 `docs/`、`test/fixtures/`、`.work/`（`docs/sanitization-rules.md:6/41`；`tools/sanitize-lint.mjs:280`）；`--allow-empty` 语义保留。
- **provenance**：27/27（26 篇 `.md` + `references/blue/templates/sigma.yml`）六键齐全，`references/INDEX.md` 使用 index 头；三 pin 集合 = 三上游 commit；我用假 `source-path` 构造 → lint 报 “source-path 在固定 commit 快照中不存在”（证明路径校验在当前 `.work/sources` 环境真实生效），因此全量 0 blocker 意味着 27 条路径全部存在。
- **许可/归属**：三仓库 `git rev-parse HEAD` 与 NOTICE/provenance pin 逐字一致；NOTICE 含 MIT 全文与修改声明；LICENSE 为 Apache-2.0 全文。
- **真实目标/凭据/武器化**：全库 grep（AKIA/ghp_/sk_live/BEGIN PRIVATE/password=/msfconsole/meterpreter/mimikatz/反弹 shell/shellcode）命中仅：`test/fixtures/bad-r3`（负向样本、不随包）、规则书/R3 禁令文本、台账 drop 理由、`docs/review-notes.md` 自身。长 hex 仅三上游 commit；示例域全为 example.com/.test 与文档网段。
- **文件卫生**：插件内 0 个 `.py`、0 `node_modules`/`.log`/临时脚本；`package.json` 17 项显式清单不含 `docs/` 其余文件与 `test/`。

### 16.7 价值提炼与 Strix 吸收抽样（当前字节）

- **台账账目（独立复算）**：
  - ACS：818 目录 = keep 60（§3 逐行具名，全部可在 `.work/sources/acs/skills` 命中）+ merge 672（§4 分组 118+33+96+192+32+16+185，与 `.work/tmp/acs-merge.json` 的 `groups` 完全一致）+ drop 86（D1 71 + D2 14 + D3 1；D3 `detecting-command-and-control-over-dns` 实测 52,765 B）。keep/drop 无交集。
  - ACS 脚本统计：以**只读**方式复跑 `.work/tmp/acs-script-stats.mjs`（不写文件）→ `scripts=809`，`outputFlag 590/1377`、`requestsCall 184/489`、`urllib 15/46`、`httpLib 4/5`、`verifyFalse 36/118`、`dryRunFlag 6/8`、`timeout 480/1410`、`jsonDump 744/1275` 与台账 §7 逐项一致（`argparse` 行 625/626 对应 `files.argparse=625`、`occurrences.ArgumentParser=626`）。
  - Claude-Red：79 行 14/49/16，逐行 `Skills/<path>/SKILL.md` 存在且字节数与台账**全部相等**（0 missing / 0 size mismatch）。
  - Strix：78 行 47/29/2，`strix/strix/skills` 78 个 `.md` **全部被覆盖**（0 uncovered / 0 duplicate / 0 size mismatch）。
- **红队抽样**：`references/red/tool-recipes.md` F7 SQLi（用途/前置/授权级别/命令模板/输出解析/证据字段/检测视角/禁止事项/dry-run 默认 9 要素；`sqlmap` 模板带授权横幅、禁止 `--os-shell/--dump-all`）。
- **蓝队抽样**：`references/blue/tool-recipes.md` B2 SIEM 回放（9 要素；jq/SPL/KQL 三段模板 + 授权横幅 + “不连 SIEM”边界）；B1–B12 共 12 族、12 个 bash 块、12 条授权横幅。
- **模板**：`sigma.yml` 4,437 B（14 顶层键、48 占位符、`falsepositives` 与阈值注释齐备、示例为保留域）、`kql.md` 7,509 B、`spl.md` 6,386 B，三件均带六键 provenance。
- **Strix 矩阵**：`references/red/strix-techniques.md` 32,841 B（≤48 KiB），§1 为 30 行决策表（假设/最小验证/证据/误判边界/检测视角），§2 五个框架特化，§4 AWS/Azure/GCP/K8s 均含根因字段与误判边界。

### 16.8 残余与观察（不改变 PASS 判定）

**R9（low，新）两个技能内联 dataSources 表仍写 4 类 kind**

- 位置：`skills/blue-hunt/SKILL.md:42`、`skills/detect/SKILL.md:42`（另 `docs/architecture.md:143` 为未随包发布文档）。
- 问题：写 `kind ∈ {siem, edr, logs, telemetry-export}`，与 `workflow/hunt.js:1451`、`policy/authorization.md:142`、`schema/scope.schema.json:79`、`references/blue/hunt-hypothesis.md:41` 的 6 类不一致；blue-hunt 同句“缺该集合 → G-DS-01 拒绝”对“只有 pcap/cloudtrail 的 scope”已不成立。
- 影响：仅文档口径偏窄，不会放行未授权目标、不影响落盘与门禁；属交付内容文档漂移。
- requiredFix：把两处改为 `siem/edr/logs/pcap/cloudtrail/telemetry-export`，或直接引用 `policy/authorization.md` §5 的 kind 表；`docs/architecture.md` 若随包再同步。

**R10（low，既有 W2）`rule lint` 不剥离行内 `#` 注释，自带 sigma 模板被自身 linter 判失败**

- 位置/复现：`docs/verification-report.md:386`；`node tools/sec.mjs rule lint --file references/blue/templates/sigma.yml` → exit 1（`invalid-status` L23、`invalid-level` L24）。
- 影响：模板为占位符起点，用户替换占位符后仍会撞到同一 lint；不影响净化门禁与安全语义，且已在验证报告 W2 记录。
- requiredFix：`tools/lib/sigma.mjs` 的 `parseSkeleton` 对 value 取 `split("#")[0].trim()`，或删掉模板枚举行行内注释。

**观察（O-1..O-3，均非缺陷）**

- O-1：exclusion 的跨形态/非常规写法不被匹配：构造 `*.app.example.com`（通配）、`app.example.com:443`（host:port）、`192.0.2.10`（ip）对 URL target `https://192.0.2.10/` 均 `ok:true`。这与 SO-2“归一化后相等或 domain/host 后缀”的字面契约一致（归一化后不同值），且目标仍在显式 targets 内、不属于 F1 的“等价表示”类；建议下一版设计评审在 policy 明示“exclusions 不支持通配/host:port/CIDR 包含”，避免授权方误解。
- O-2：`docs/` 不参与 R1–R12 扫描是规则书明文设计（`docs/sanitization-rules.md:6/41`）；本轮对 docs 做了人工 grep（凭据/真实域/武器化），0 命中。
- O-3：未在本机 DSH 运行时内装载插件；以 `cordis.patch.yml` 同构性 + `apply/list/get` stub 实测（15/rank600/bundled）判定集成正确性。t8 曾在真实 provider 契约上实测，`package.json` 的 `dsh.bundle.patch` 与 dsh-security 同形态。

### 16.9 结论与判定

- **PASS（0 blocker / 0 high）**。依据：
  1. F1（high）与 F12（medium）修复在 9 workflow、`gate.mjs`、guard 三个入口均保持有效（225/225 + 25/25 + CLI 构造）。
  2. R1–R3（medium）已修复并经独立复跑：limits 在 gate/guard 真实生效（超限 exit 1、0 spawn、0 文件）、5 个复核字段真实落盘（assess+triage）、hunt 接受 pcap/cloudtrail 并拒绝未知 kind。
  3. R4–R7（low）已修复；R8（low）维持受理且理由充分（实现为放宽输入枚举、非削弱拒绝；冻结文档债有逐条记录）。
  4. 净化门禁 0 blocker、2 条 R11 已受理、27/27 provenance 完整、无真实目标/凭据/武器化制品；价值层 818/79/78 台账与配方/模板抽样仍成立。
  5. 残余仅 R9/R10（low，文档/工具易用性）+ O-1..O-3（观察），不影响门禁、落盘与可用性，按任务规则判 pass 并记录。
- 本轮未修改任何被评审文件；仅追加本 §16。

### 16.10 本轮证据限制与改动声明

- 未重跑原生 `workflow` 工具 E2E（避免改变 `.work/smoke`）；改为独立复算现有两段 manifest 哈希与字段（14/14），并保留旧失败段（5/7）未隐藏。
- 未逐行重读 78 篇 Strix 上游全文；以逐文件账目（路径/字节/决策全覆盖）+ 插件内容抽样（30 行表、5 框架、AWS/K8s 节）判定。
- 未运行真实工具配方/网络：guard 正向 `--execute` 使用“二进制缺失”分支验证 exit 1 + 0 spawn；拒绝路径验证 0 evidence。
- provider 测试为 stub ctx（非 DSH 运行时）；`lib/index.js` 仅依赖 `node:fs/promises`/`node:url`，与 dsh-security 同形态。
- 改动面：插件根 116 个文件改动前后 SHA256 清单比对，**唯一变化为本文件**（其余 115 个文件哈希一致）；本轮临时探针脚本在系统临时目录（`%TEMP%/dsh-review2`），未进入插件目录，也未改 `.work/`。

---

# 第 4 部分：t32 t30 增量复审（review round-3）

## 17. t32 复审记录

- 复审人：reviewer2（AgentTeams member；t32 incremental round）
- 复审时间：2026-11-20 10:28–10:40 +08:00；主机 Windows x64 / Node v24.22.1
- 复审对象：t30「hunt scope 阶段技能目录 `rb-run`→`run` + 全 workflow 阶段目录存在性回归测试」对当前字节的增量影响（含 t31 验证后的工作区快照）。
- 方式：**只读 + 独立构造/复算**。除本文件外未修改任何被评审文件（改动前后对插件全部文件做 SHA256 比对，见 §17.4）；未触发网络；未运行真实工具配方。
- **结论：PASS（0 blocker / 0 high）**。hunt scope 目录已与 `skills/run` 及 design §5.3 映射一致，`workflow/` 无 `rb-run` 残留；新增测试是对 9 个 workflow 的**枚举式**存在性断言（非硬编码单值），且我用独立实现复现同一 32 stage/18 prompt/14 目录结果；改动面确认为 `workflow/hunt.js` + `test/workflow.test.mjs` 两文件，G-* 门禁段与 preflight 逻辑字节级未变，99/99 + lint 0 blocker 无回归。残余 2 条 low 观察（§17.7），不影响交付。

### 17.1 本轮实际执行的检查（命令与结果）

| 检查 | 命令/方法 | 结果 |
|---|---|---|
| scope 目录 | `grep -n 'runStage(ctx, "scope"' workflow/*.js` | hunt `"run"`（`hunt.js:1462`）；assess/exploit/post/recon 仍 `"red-scope"` |
| 残留扫描 | `grep -rn 'rb-run' workflow/` + 全库 `rb-run` 复核 | workflow/ **0 命中**；库内其余 `rb-run` 均为技能名 `dsh-rb-run`/示例 workDir，非目录引用 |
| 测试 | `node --test test/{scaffold,sanitize,workflow,tool-runtime}.test.mjs` | **99/99**（9/24/43/23），exit 0；新测试 `every workflow stage skill directory exists under skills/` 通过 |
| 测试名集合 | 对比 t27 运行日志（98 条 ✔）与本轮（99 条 ✔） | 唯一新增为上述测试；既有 98 条名称与结果不变 |
| 语法 | 全部 `.js/.mjs` `node --check` | **27/27** |
| 净化门禁 | `node tools/sanitize-lint.mjs --strict --json dsh-redblue` | **87 文件 / 0 blocker / 2 warning**（R11：purple-verify:3、red-exploit:3，assembly §4 受理），exit 0 |
| 阶段目录审计（独立实现） | 自写正则扫 9 workflow 的 `runStage/runFanout` 与 `skillDir + "/<dir>/SKILL.md"` | 32 stage 调用 + 18 prompt 引用 → 13 stage 目录 + 1 prompt 目录（`rb-report`）= **14**；`skills/<dir>/SKILL.md` 全部存在且非空（missing=0 / empty=0） |
| 合成负例 | 自写合成源码含 `runStage(ctx, "scope", "rb-run", ...)` 与 `skillDir + "/rb-run/SKILL.md"` | 我的提取器取到 `rb-run`，`skills/rb-run` 不存在 → 存在性断言会失败（证明同类残留可被拦截） |
| hunt 功能探针 | `node:vm` 跑 hunt（pcap 数据源 + 完整 agent 回复） | `status=clean`、`exitCode=0`、`sealed=true`、7 artifacts；scope 阶段 prompt 含 `/skills/run/SKILL.md`，全部 prompt **不含** `rb-run` |
| 门禁回归 | hunt 构造：缺 dataSources / 未知 kind / 默认端口 exclusion / userinfo / 0.0.0.0/32 / 非法 mode / 5000 字符 reference / 300 targets / 过期授权 | 依次 `G-DS-01`、`G-CONF-01`+`G-DS-01`、`G-TGT-04`、`G-TGT-03`、`G-TGT-02`、`G-MODE-01`、`G-CONF-01`、`G-CONF-01`、`G-AUTH-07`，均 `rejected/exit1/code1` + **0 agent** |
| 门禁段一致性 | 9 workflow 的 normalize/exclusion/limits 段哈希 + preflight 段哈希 | norm/excl/limits 与 t27 相同（`e799b749…`/`8e0a96be…`/`54f3f88b…`）；hunt 的 preflight 段 `358b5854e500` 与 6 个未改动非 confirm workflow（assess/harden/ir/purple/recon/triage）**同哈希** |
| G-ID 集合 | 提取 hunt 全部 `G-*` 并统计 | 31 个（与 t26/t27 记录一致）；仅 exploit/post 含 `G-CFM-*`，hunt 无 confirm 门禁 |
| 改动面 | 当前树 SHA256 vs t27 final 快照 + team.json t30.changedPaths + mtime | t30 仅 2 文件（见 §17.4） |

### 17.2 修复核验：hunt scope 技能目录 = `run`

- 代码：`workflow/hunt.js:1462` 为 `await runStage(ctx, "scope", "run", [`；`grep -rn 'rb-run' dsh-redblue/workflow/` = **0**。
- 目录事实：`skills/run/SKILL.md` 存在且非空（8,889 B，frontmatter `name: dsh-rb-run`）；`skills/rb-run/` **不存在**。
- 与基线一致：`docs/design.md:37`/`:211` 定义技能名 `dsh-rb-run` 的目录为 `run/`；`docs/design.md:403` 的 hunt 映射为 `scope→dsh-rb-run；hunt→dsh-blue-hunt；report→dsh-rb-report；seal→内置`。`runStage` 的第二参数是**目录名**（prompt 以 `skillDir + "/" + skill + "/SKILL.md"` 拼路径），故 `"run"` 是唯一正确值。
- 修复前行为：scope 阶段 prompt 会指向 `.../skills/rb-run/SKILL.md`（不存在），agent 只能走“若不可读则按本提示执行”；修复后功能探针显示 scope prompt 指向 `/skills/run/SKILL.md`（存在），hunt 全流程 `clean/0/sealed/7 artifacts`。
- 字节证据：`workflow/hunt.js` 74,288 B（t27）→ **74,285 B**（−3，恰为 `rb-run`→`run` 少 3 字符）；sha256 `7c68673f…` → `1d322287…`；其 normalize/exclusion/limits/preflight/finalize 段哈希与 t27/未改动 workflow 完全一致（见 §17.5）。

### 17.3 回归测试有效性：枚举式而非硬编码

- 位置：`test/workflow.test.mjs:838–865`（新增 28 行，1,807 B）。
- 实现：对 `WORKFLOWS`（9 个）**逐个读源文件**，用 `run(?:Stage|Fanout)\(ctx, "<stage>", "<dir>"` 提取所有阶段技能目录、用 `skillDir + "/<dir>/SKILL.md"` 提取 prompt 内目录；断言
  - 每个 workflow 至少 2 个字面量（`:850` 附近），
  - `stageDirs.size >= 13`（`:856`）、`promptDirs.size >= 1`（`:857`），
  - 显式要求 `run`/`rb-report`/`rb-triage`/`blue-hunt`/`purple-verify` 至少被某 workflow 引用（`:859`），
  - 每个被引用目录 `skills/<dir>/SKILL.md` 存在（`:862`）且非空（`:863`）。
- 独立复现：我的实现（非复用其代码）得到 32 stage 调用（每 workflow 2–5 个）、18 prompt 引用、stage 目录 13 + prompt 目录 1（`rb-report`）= 14 个唯一目录；与新增测试的覆盖下限与显式要求一致，missing=0。
- 非硬编码证据：该测试不写死目录清单，而是遍历 9 个文件；若把任一 workflow 的目录改成 `rb-run`，`:862` 的存在性断言会失败（我的合成负例显示 `rb-run` 可被提取且 `skills/rb-run` 不存在）。
- 局限（低风险，§17.7 O-2）：提取仅覆盖双引号字面量与 `runStage/runFanout` 调用形态；当前 32/32 调用均为字面量，且有“每 workflow ≥2 + 全局 ≥13 + 显式必需目录”三重下限，未来改成动态传参才可能出现盲区。

### 17.4 改动面核验：仅 hunt.js 与 test/workflow.test.mjs（t30）

- 与我 t27 保存的插件全量 SHA256 快照对比（t27 final → 本轮前）：变化仅 6 个文件，按 mtime 归因——
  - **t30（10:19:10 / 10:22:06）**：`workflow/hunt.js`、`test/workflow.test.mjs`（team.json `t30.changedPaths` 亦恰为这 2 项）；
  - t28（10:15:29）：`docs/architecture.md` + 新增 `docs/architecture-plugin.svg`、`docs/architecture-workflow.svg`（早于 t30，属架构图任务）；
  - t31（10:28:06）：`docs/verification-report.md`（增量验证报告）。
- 其余 110 个插件文件哈希与 t27 完全一致（lib/skills/references/tools/policy/schema/README/package.json/workflow 其余 8 份等）。
- 测试文件增量自洽：t27 69,541 B → 71,378 B（+1,837 B）；新增测试块 838–865 行 1,807 B，差额 30 B = 空行 + CRLF 计数，说明为**纯追加**；测试总数 42→43，测试名集合差异仅新增 1 条（见 §17.1）。
- 作用面：未改任何被评审内容文件（skills/references/policy/README 哈希不变），未改其它 workflow。

### 17.5 G-* 门禁未弱化（语义/顺序）

- 段哈希：9 workflow 的 `normalizeDomain…exclusionHits`（`e799b749…`）、`exclusionHits…normalizeScope`（`8e0a96be…`）、`validateScopeLimits…preflight`（`54f3f88b…`）与 t27 记录逐项相同；hunt 的 `preflight…makeContext` 段 `358b5854e500` 与 assess/harden/ir/purple/recon/triage 六个未改动工作流**完全同哈希**（exploit/post 因 confirm 门禁不同而不同，属预期）。
- G-ID 集合：hunt 31 个（G-ARG/PATH/CONC/AUTH-01..07/TGT-01..04/MODE-01..03/WIN/BUD/DH/DS-01/DS-04/DS-05/OUT），与 t26/t27 相同；仅 exploit/post 含 `G-CFM-01..04`。
- 拒绝顺序/collect-all 未变（preflight 段整段同哈希）；功能构造 9/9 期望：缺数据源 `G-DS-01`、未知 kind `G-CONF-01`+`G-DS-01`、exclusion 默认端口 `G-TGT-04`、userinfo `G-TGT-03`、`0.0.0.0/32` `G-TGT-02`、非法 mode `G-MODE-01`、5000 字符 reference/300 targets `G-CONF-01`、过期授权 `G-AUTH-07`——全部 `rejected/exit1/code1` 且 **0 agent**；合法 pcap scope 仍通过门禁并运行（完整回复下 `clean/0/sealed/7 artifacts`）。
- 结论：t30 的 3 字节修改位于 stage 调用参数，不触及任何门禁代码；无门禁语义/顺序变化。

### 17.6 回归与交付面

- 99/99 测试通过（scaffold 9 / sanitize 24 / workflow 43 / tool-runtime 23）；`node --check` 27/27；lint 87 文件 0 blocker、2 条既有 R11 已受理（`docs/assembly-report.md:64–88`）；36 条检查项不变。
- 运行行为：hunt 在完整回复下的 `status/exitCode/sealed/artifacts` 与 t27 的 hunt 探针一致（clean/0/true/7）；scope prompt 技能路径由不存在的 `skills/rb-run` 修正为 `skills/run`，属可用性修复，无安全面变化。
- 未受影响：t27 已复核的 F1/F12（hunt 的 exclusion/规范段哈希未变；本轮抽样 `G-TGT-04`/`G-TGT-03`/`G-TGT-02` 仍拒绝）、R1–R3 门禁/落盘（hunt 的 preflight/limits 段未变）、净化与价值层（skills/references 哈希未变）。

### 17.7 残余与观察（不改变 PASS 判定）

**O-1（low，与 t31 一致）t30 完成说明声称的“合成 `rb-run` 反向验证”未落在测试文件中**

- 证据：`grep -c 'rb-run' test/workflow.test.mjs` = **0**；`test/workflow.test.mjs:838–865` 只有正向枚举/存在性/覆盖下限断言，无合成负例 fixture。
- 影响：仅是 t30 报告表述与测试文件不一致；修复本身正确，且**同类残留仍会被拦截**——`:862` 对每个被引用目录断言存在，我的合成负例（`rb-run` 字面量）会被提取并因 `skills/rb-run` 不存在而失败。不影响门禁/落盘/可用性。
- 建议：后续补一条合成源码负例（或把 t30 说明改为“机制上可拦截”），避免复审误判。

**O-2（low）测试提取器的形态依赖**

- 位置：`test/workflow.test.mjs:845–848` 的两条正则。
- 说明：只匹配双引号字面量与 `runStage/runFanout(ctx, "<stage>", "<dir>"` 形态；若未来改为变量传参/单引号，可能漏提取。当前 32/32 调用均为字面量（本轮独立审计），且有“每 workflow ≥2、全局 ≥13、显式必需目录、非空”四重下限，属可接受的维护性限制；建议下次改动阶段调用时保持字面量或同步正则。

### 17.8 结论与判定

- **PASS（0 blocker / 0 high）**：t30 的修复正确（`hunt scope→run`，无 `rb-run` 残留，功能探针指向存在的 `skills/run/SKILL.md`）；新增测试确为 9 workflow 枚举式存在性断言（独立复现 32/18/14，missing=0）；改动面仅 2 文件；G-* 门禁段/preflight 与未改动工作流同哈希、9 类负向构造全部 0 agent 拒绝；99/99、27/27、lint 87/0/2 无回归。
- 残余 O-1/O-2 为 low（报告表述/测试形态），不影响交付判定；无 blocker/high，可进入最终交付。
- 本轮未修改任何被评审文件；仅追加本 §17。

### 17.9 本轮证据限制与改动声明

- 未重跑原生 `workflow` 工具 E2E（避免改变 `.work/smoke`）；hunt 行为以自建 `node:vm` 宿主 + 完整 stub 回复验证（clean/0/sealed/7 artifacts）。
- 未运行真实工具配方/网络；未修改 `.work/`、skills/references/policy 或其它 workflow/test 文件。
- 改动面：编辑前后对插件全部文件再做 SHA256 比对，**唯一变化为本文件**；本轮临时探针脚本位于系统临时目录（`%TEMP%/dsh-review2`），未进入插件目录。