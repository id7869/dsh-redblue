# 装配报告（assembly-report）

- 任务：t6 插件总装、一致性自检与交付文档
- 版本：`dsh-redblue 0.1.0`；日期：2026-11-19
- 范围：`README.md`、`NOTICE`、`LICENSE`、`icon.svg`、`docs/DETAIL.md`、`docs/preview.svg`、`docs/assembly-report.md`、`docs/value-extraction.md`、`references/INDEX.md`、`lib/index.js`、`test/scaffold.test.mjs`、`package.json`
- 结论：**交付态通过**。全量 lint 0 blocker（2 个有据受理的 warning）；4 个测试文件 72/72 通过；所有 `.js/.mjs` 通过 `node --check`；未发现未披露的失败项

## 1. 总装自检结果

| 项 | 结果 | 证据 |
|---|---|---|
| 15 技能目录与 `lib/index.js` 常量一一对应 | 通过 | `skills/` 恰好 15 个目录；frontmatter `name/dir/description` 与 lib 常量逐项一致；`test/scaffold.test.mjs` 新增真实目录/frontmatter 断言 |
| provider 以 frontmatter 为准 | 通过 | `list()/get()` 的 description 与每个 `SKILL.md` frontmatter 相等；正文非空 |
| 全量净化门禁 | 通过 | `node tools/sanitize-lint.mjs --strict --json dsh-redblue`：83 文件、0 blocker、2 warning（见 §4） |
| 测试 | 通过 | scaffold 9/9、sanitize 20/20、workflow 25/25、tool-runtime 18/18，共 72 |
| 脚本语法 | 通过 | 全部 `.js/.mjs`（含 workflow）`node --check` 退出 0 |
| 工具价值层入册 | 通过 | README/DETAIL/value-extraction 均描述 `tools/sec.mjs` 子命令、10 条 recipes 白名单、guard 授权门禁与可选二进制；tool-runtime 18/18 |
| 许可与归属 | 通过 | `LICENSE` Apache-2.0 全文；`NOTICE` 三上游 repo/commit/license、修改声明、MIT 全文；`package.json license=Apache-2.0` |
| 清理 | 通过 | 插件内无临时脚本/测试产物/`node_modules`/`.log`；`package.json files` 为显式清单且逐项存在 |

## 2. 本次改动

### 2.1 目录一致性

- 复算发现唯一漂移：`dsh-blue-dfir` 的 lib 回退 description 仍为 design §4.2 原文（“……**也不**自动执行遏制动作”），而 `skills/dfir/SKILL.md` frontmatter 已是“……**不得**自动执行遏制动作”（t4 的 2 字符收紧）。
- 处理：按“provider 常量以 SKILL.md frontmatter 为准”，把 `lib/index.js` 的 fallback 常量同步为 frontmatter 文本；其余 14 条逐字一致。codepoint 长度仍为 172。
- `test/scaffold.test.mjs` 新增：
  - `skills/` 目录恰好 15 个，且与 `EXPECTED` dir 集合相等；
  - 每个 `SKILL.md` 存在、frontmatter 可解析、`name`/`description`/`whenToUse` 合法；
  - lib 常量（name/dir/description）与 frontmatter 逐项相等；
  - `list()/get()` 的 description 等于 frontmatter，`get().content` 非空；
  - `package.json files` 每个条目存在，且 `docs` 整目录 / `docs/research-handoff.md` 不被发布。

### 2.2 交付文档

- **README.md** 终稿：15 技能表、9 workflow 表、工具运行时子命令 + 10 配方 + 可选二进制 + guard 门禁、工具配方/检测模板/脚本模式库/工具运行时/Strix 实战技术能力说明、参考 INDEX 预算、安全门禁、安装与触发、R1–R12、与 dsh-security 分工、许可。
- **docs/DETAIL.md**：详情页正文（能力、workflow、参考、工具运行时、门禁、安装、限制、目录）。
- **docs/value-extraction.md**：三库 → 插件的价值转化总账（79 / 818 / 9 + 78 → 15 技能；809 agent.py → script-patterns；命令配方 → tool-recipes；检测规则 → templates；运行时纪律 → workflow；脚本能力 → tools/sec.mjs + recipes）。
- **references/INDEX.md**：27 篇参考 + 上游 3 commit 的 index 头；阶段加载表，**每阶段 ≤2 篇 / ≤120 KiB**；列出 tool-recipes、extraction-ledger、templates、script-patterns、strix-techniques、finding-review。
- **NOTICE / LICENSE**：三上游归属、修改声明、MIT 全文、Apache-2.0 全文；`Copyright 2026 dsh-redblue contributors`（H-3 待产品方确认）。
- **icon.svg / docs/preview.svg**：原创 SVG，无外部图片/字体/URI 资源。
- **package.json**：`files` 改为显式交付清单（含 `icon.svg`、NOTICE、LICENSE、README 与 5 个 docs），排除 `docs/research-handoff.md`、需求/设计/净化规范等内部文档；新增 `icon` 与 `exports["./icon"]`；测试脚本改为显式 4 个测试文件。

### 2.3 工具价值层（t10）

- `tools/sec.mjs`：`scope check`、`evidence hash/verify`、`sarif convert`、`ioc extract`、`log normalize`、`rule lint`、`recipes list/show`、`guard`。
- `tools/recipes.json`：10 条白名单配方（DNS/HTTP 头/TLS/端口/漏洞扫描/Web 模糊/PCAP/文件哈希/证书查询/运行时自检）。
- guard：只执行白名单配方；argv 数组直传 `spawn(shell=false)`；默认 dry-run；`--execute` 需 written 授权 + mode + target allowlist + confirm 全等 + 二进制存在；固定 timeout/output 上限；evidence JSONL 只落哈希。
- 文档一致性：README、DETAIL、tool-runtime、value-extraction 均列出相同子命令/配方/门禁；tool-runtime 18/18 通过。

## 3. 与 design 的偏差记录

| # | 偏差 | 原因 | 处置/责任 |
|---|---|---|---|
| D-1 | design §5.1 列 17 篇参考；实际 27 篇 + INDEX | t3/t4/t11 新增能力层：`red/tool-recipes`（F1–F16）、`red/strix-techniques`（Strix 78 篇）、`red/extraction-ledger`、`blue/tool-recipes`（B1–B12）、`blue/extraction-ledger`、`blue/templates/{sigma.yml,kql.md,spl.md}`、`shared/finding-review`、`shared/script-patterns`（共 10 篇） | INDEX §4 列出新增与理由；assembly 责任：engineer |
| D-2 | design §5.2 加载预算“≤3 篇”；t6 验收要求“≤2 篇” | 总装阶段收紧上下文预算，避免 TPM/上下文压力 | INDEX 阶段表按 ≤2 篇 / ≤120 KiB 执行；assembly 责任：engineer |
| D-3 | `dsh-blue-dfir` description 由 design §4.2 原文“也不”改为“不得”（2 字符，172 码点不变） | 满足 R12-REPORT-ONLY 的“不得自动执行”否定上下文，同时避免与字段名 `findings` 触发术语冲突 | t4 已在 SKILL.md 注明；t6 同步 lib fallback；design 基线 owner 若要求逐字一致需在下一版设计评审确认 |
| D-4 | design §2 树未列 `workflow/package.json` | 让含顶层 `return`/`await` 的 workflow 胶囊可通过 `node --check`（commonjs 解析），workflow 工具仍按正文执行 | t5 新增；本报告备案 |
| D-5 | schema 现有 6 个（scope/finding/evidence/report/coverage/manifest）；design §2 列 coverage/manifest，t2 任务要求 evidence/report | 覆盖两类产物契约 | t2/t5 分别交付；本报告备案 |
| D-6 | 新增 `tools/sec.mjs`、`tools/lib/*`、`tools/recipes.json`、`docs/tool-runtime.md` | design §2 仅列 `tools/sanitize-lint.mjs`；t10 要求把脚本能力做成零依赖工具运行时 | t10 交付；README/DETAIL/value-extraction 入册 |
| D-7 | README/DETAIL/NOTICE/LICENSE/icon/preview/assembly-report/value-extraction 为 t6 新增 | 交付态文档与许可补齐（t1/t2 未要求） | 本任务交付 |
| D-8 | package `files` 由 `docs` 整目录改为显式清单 | 避免把 `docs/research-handoff.md` 与内部规范随包发布；同时纳入 icon/NOTICE/LICENSE | 本任务交付；测试断言每个条目存在 |

## 4. 两条 R11 warning 的受理

全量 lint 仅 2 个 warning，均为 `R11-TERMINOLOGY`（warning 级，policy 允许经评审受理）：

1. `skills/red-exploit/SKILL.md`：description 为 design §4.2 固定原文“批量漏洞**发现**用”，与契约字段名 `kind="findings"`/`status="findings"` 同现；R11 规则按“finding 与中文‘发现’名词混用”告警。
2. `skills/purple-verify/SKILL.md`：description 为 design §4.2 固定原文“红队**发现**复核定级”，同样与 `findings` 字段名同现。

受理理由：

- 两条 description 是 design §4.2/§4.5 的**固定契约**，逐字影响触发隔离与文档一致性；t6 不擅自改写方法论/契约文本。
- 规则级别为 warning（非 blocker）；`docs/sanitization-rules.md` 与 `policy/sanitization.md` 均允许人工评审受理。
- 两个技能正文已内嵌“术语评审……一致（2026-11-19）”记录（t3/t4）。
- 若后续设计评审要求消除 warning，应由 design owner 同时修改 design §4.2/§4.5、frontmatter、lib fallback 与文档，再重跑 R7 Jaccard。

## 5. 未通过项与遗留风险

**未通过项：无。** 没有 blocker、失败测试或缺失交付文件。以下为已知风险/待确认项，不阻塞本任务：

| 风险 | 影响 | 缓解/责任人 |
|---|---|---|
| H-3 署名未定 | NOTICE/LICENSE 使用 `dsh-redblue contributors` | 产品方确认后替换；assembly 责任：captain/product |
| H-5 bundle 自动注册未实测 | link 安装后 `dsh.profile.bundles` 可能需手工补充 | 安装任务按 README §6 显式确认；责任人：安装验证任务 |
| 可选二进制缺失 | 相关 `guard --execute` 配方拒绝（G-EXEC-01），dry-run 仍可用 | README/DETAIL/tool-runtime 已列可选依赖；责任人：操作者 |
| guard dry-run 不可读 scope 返回 exit 0（ok=false） | 与“执行前置 exit 1”语义不同 | 文档 §4.1 已说明；`--execute` 同条件 exit 1；责任人：engineer |
| 两条 R11 warning | 发布门禁仍为 0 blocker | §4 已受理；责任人：design owner/assembly |
| `workflow/package.json`（commonjs）被误认为运行时依赖 | 无运行时影响 | 报告 D-4 备案 |
| 超时/输出限制只作用于直接子进程 | 配方二进制若自行派生后台进程需人工清理 | tool-runtime §7 已声明 |

## 6. 清理与发布清单

- 插件内无临时脚本、测试产物、`node_modules`、`.log`、`.tmp`、`.bak`。
- `package.json files` 全部条目存在；不发布 `docs/research-handoff.md`、`docs/requirements.md`、`docs/design.md`、`docs/sanitization-rules.md`、`test/`。
- 发布文件：`lib/`、`skills/`、`references/`（27 + INDEX）、`workflow/`（9 + package.json）、`schema/`（6）、`policy/`（2）、`tools/`（sec + lib + recipes + sanitize-lint）、5 个 docs、`cordis.patch.yml`、`NOTICE`、`LICENSE`、`README.md`、`icon.svg`。
- 上游原始仓库、课程文件、809 个 agent.py、Strix 运行时均未打包（0 个 `.py`）。

## 7. 验证命令与结果

| 命令 | 结果 |
|---|---|
| `node dsh-redblue/tools/sanitize-lint.mjs --strict --json dsh-redblue` | 83 文件；0 blocker；2 warning（均已受理）；exit 0 |
| `node --test dsh-redblue/test/scaffold.test.mjs dsh-redblue/test/sanitize.test.mjs dsh-redblue/test/workflow.test.mjs dsh-redblue/test/tool-runtime.test.mjs` | 72/72 通过（9 + 20 + 25 + 18） |
| `for f in $(find dsh-redblue -name '*.js' -o -name '*.mjs'); do node --check "$f"; done` | 全部通过 |
| `test -s README.md && test -s NOTICE && test -s LICENSE && test -s docs/DETAIL.md && test -s docs/value-extraction.md && test -s docs/tool-runtime.md && test -s references/INDEX.md` | 全部非空 |

- 文档与实现一致性抽查：README/DETAIL/value-extraction 的 skill/workflow/recipe 数量与目录一致；`references/INDEX.md` 的 27 篇与 `find` 结果一致；`pkg.files` 与发布清单一致。
- 未修改 `skills/`（除前置任务已交付内容）、`references/red|blue|purple/`、`workflow/`、`policy/`、`tools/sec|lib|recipes`、`.work/sources/`、`dsh-security/`；本任务仅改 in-scope 文件。

## 8. 责任与签核

- 装配/文档/许可/一致性：engineer（本任务）
- 需求/设计/净化基线与固定 description：t1 design owner
- 技能/参考内容与 R11 术语评审：t3/t4/t11 作者 + 人工评审
- 安装生效验证（H-5）与署名确认（H-3）：captain / 产品方
- 结论：可进入独立验证（t7）；如验证发现内容级缺陷，按“不掩盖”原则回填本报告并返工对应 owner。## 9. t20 修复记录（2026-11-19）

> 修复依据：t8 独立评审 13 条 finding（F1–F13）；task t20 修订 scope 包含 workflow/tools/test、schema/finding、refs/red ledger、refs/blue hunt、refs/shared script-patterns、policy/authorization、docs/value-extraction、docs/sanitization-rules、docs/assembly-report、docs/DETAIL、README。design/requirements 已冻结（outOfScope），相关偏差在本节按“受理限制”记录。

### 9.1 逐条处置

| ID | 状态 | 修复/受理 |
|---|---|---|
| F1 high | fixed | 9 个 workflow 的 `exclusionHits` + `tools/lib/gate.mjs` 同步：exclusion 按 URL/domain/IP 归一化（URL 默认端口/fragment/根斜杠、domain 尾点/大小写、IPv4 前导零），再做相等、domain/host 后缀匹配；`guard` 在 allowlist 检查后也执行 exclusionHits → G-TGT-04。回归：test/workflow 8 类（默认端口/尾点/大小写/fragment/根斜杠/domain 目标/IP 前导零/后缀）+ test/tool-runtime guard 1 类。 |
| F2 medium | fixed | `schema/finding.schema.json` 增加可选 `confidenceRationale`/`counterevidence`/`severityChangeConditions`/`fixVerification`/`basis`（string ≤4000），`additionalProperties=false` 保持；test/workflow 增加 schema 结构/未知字段断言。**受理限制**：design §8.2 字段表冻结，未同步该 5 行；schema 为运行期事实源。 |
| F3 medium | fixed | `docs/value-extraction.md` 按 blue 台账 §7.3/§7.4 改为 6 dry-run / 590 output / 184+15+4 HTTP 客户端 / 36 文件 verify=False（字面量 35）；drop 改为 D1 71 + D2 14 + D3 1；test/workflow 校验 15 技能行数 107–175 与关键数字。 |
| F4 medium | fixed | `tools/sanitize-lint.mjs` 候选扩展改为 `POLICY.fileExtensions`（含 yml/yaml/svg/txt）；新增 `asset` kind 覆盖根资产；空目录无 `--allow-empty` 时 exit 2；YAML `# dsh-redblue:provenance` 解析；`sigma.yml` 因位于 `references/` 归为 reference 并由 R1 校验，`icon.svg`/`cordis.patch.yml` 为无 provenance 的 asset（仅 R2/R10）；test/sanitize 增加扩展名正反例/sigma/空目录/icon 用例。**t22 修正**：R1 现已覆盖“声明了 provenance 的 asset”（见 §10 R6），原“sigma.yml/icon.svg 纳入 R1”表述按实际分类改正。 |
| F5 medium | fixed | `references/red/extraction-ledger.md` provenance `source-path` 改 `README.md`；`R1-PROVENANCE` 在存在 `.work/sources` 时校验 source-path 存在（fixtures 跳过；打包环境无 `.work` 时跳过）。当前 39 条路径全部存在；lint 0 blocker。 |
| F6 low | fixed | red 台账 ACS 行 2588→818，另注“仓库全部 .md=2588（非技能数）”；§6 增加 ACS 库存核对命令。 |
| F7 low | fixed | `references/blue/hunt-hypothesis.md` 的 kind 改为已注册 `siem/edr/logs/telemetry-export/pcap/cloudtrail`（network→pcap、cloud→cloudtrail、identity→logs）；test/workflow 断言 reference kind ⊆ schema enum ⊆ workflow DATA_SOURCE_KINDS。 |
| F8 low | fixed | 9 个 workflow + gate 增加 `validateScopeLimits`：reference/grantedBy/document、notes、targets≤200/label≤120、exclusions≤200/每项3–512、dataSources≤64/value 3–2048/label/version≤120；test/workflow 覆盖 reference/targets/notes/label/exclusion 超限。 |
| F9 low | fixed | README/DETAIL hunt 行改为 `scope→hunt→report→seal`；triage/harden 保留统一 finalize 的 `report` 阶段；test/workflow 校验文档阶段串。**受理限制**：design §6.0.1/requirements §10.8–10.9 冻结，仍写 triage/harden 无 report；装配报告记录此已知偏差。 |
| F10 low | fixed | `references/shared/script-patterns.md` A7 “见 S8”→“见 S7”；test/workflow 断言无 S8 且有 S1–S7。 |
| F11 low | fixed | README/DETAIL/policy/authorization 明确“seal = agent 只读复核 + 外部可复算”，推荐 `tools/sec.mjs evidence verify` 或独立 SHA256；**受理限制**：design §8.5 冻结，未同步；manifest 未加 attestation 字段（schema 未改）。 |
| F12 medium | fixed | URL 拒绝 userinfo/`0.0.0.0`/`[::]`/非法 host；IPv6 校验组数与 `::` 唯一性并规范压缩；CIDR 允许范围 IPv4 /8–/32、IPv6 /32–/128，拒绝 /1 与 unspecified base；target 0.0.0.0/::、`0.0.0.0/32`、`::/128` 均 G-TGT-02；policy §2.2/§6 同步；test/workflow 8 类负向。 |
| F13 low | fixed | `docs/sanitization-rules.md` §2 改 27 篇 + INDEX；§3 默认/发布命令改为插件根（无路径=PLUGIN_ROOT），保留显式快速门禁；test/workflow 校验。 |

### 9.2 验证

- `node tools/sanitize-lint.mjs --strict --json dsh-redblue`：**87 文件、0 blocker、2 warning**（两条既有 R11，已受理）。
- `node --test`：scaffold 9 + sanitize 24 + workflow 37 + tool-runtime 19 = **89/89**。
- 全部 `.js/.mjs` `node --check` 通过。
- 9 个 workflow 的 normalization/exclusion 段与 preflight limits 段哈希一致；finalize 核心段仍一致（t16 修复未回退）。

### 9.3 受理限制与后续

- design/requirements 冻结导致 F2/F9/F11 的 docs/design 同步未做；以 schema/代码/README 为准，建议下一版设计评审同步。
- `schema/scope.schema.json` 未加入 CIDR 前缀上下限（运行期 preflight/gate 强制）；如要求静态 schema 也表达，需单独允许 schema 修改。
- F5 的路径存在性检查仅在开发环境有 `.work/sources` 时执行；打包环境依赖 NOTICE/provenance 常量，建议发布验证补充快照核对记录。
- 未改 skills 内容；references 仅改 F5 ledger 一行、F7 hunt-hypothesis、F10 script-patterns。
- t22 复审 R8（冻结文档债）在 §10 再次受理；design/requirements 的 triage/harden report 阶段与 seal attestation 仍待下一版设计评审统一同步。

## 10. t22 修复记录（2026-11-20，复审 R1–R8）

- 任务：t22「修复 t21 复审遗留：R1 gate limits / R2 复核字段落盘 / R3 hunt 数据源，及 R4–R8」
- 依据：`docs/review-notes.md` §15.3 的 R1–R8（round-2 复审 PASS 后的残余项）
- 结论：**R1/R2/R3（medium）全部 fixed；R4/R5/R6/R7 fixed（R5 为文档侧修复，schema 静态上下限仍受理）；R8 维持受理**。门禁未弱化：G-* 语义与顺序不变，F1/F12 修复保持有效，原有测试不回归。

### 10.1 逐条处置

| ID | 状态 | 处置与证据（文件:行） |
|---|---|---|
| R1 medium | **fixed** | `tools/lib/gate.mjs:349` 在 `checkScope` 对象检查后调用 `validateScopeLimits(raw, reject)`（定义 `:296`），与 9 个 workflow 的 limits 逐字节相同（`test/workflow.test.mjs:919` 哈希比对，并断言 gate 不再是死代码）；`scope check` 5000 字符 reference / 300 targets → exit 1 + `G-CONF-01`（`test/tool-runtime.test.mjs:173`）；`guard` 同 scope dry-run → exit 1、0 spawn（`test/workflow.test.mjs:935`、`test/tool-runtime.test.mjs:200`）；边界值 200 字符 / 200 targets 仍通过。workflow 胶囊按设计不可 import（单文件、无 Node API），故用“同一段代码 + 测试哈希锁定”保证两套入口一致，而非共享模块。 |
| R2 medium | **fixed** | 9 个 workflow 的 `normalizeFinding` 白名单复制 5 个复核字段并按 schema 截断 4000（`workflow/assess.js:1020` 等 9 份哈希一致，`test/workflow.test.mjs:977`）；`buildPrompt` 统一提示这些字段（`workflow/assess.js:887`，9 份一致）；`triage` 的 merged 透传 disposition/review 字段（`workflow/triage.js:1518–1522`）并在复核/处置 prompt 写明（`:1478/:1489`）；落盘断言 `test/workflow.test.mjs:1001`（assess + triage 的 findings.json 逐字段相等）。 |
| R3 medium | **fixed** | `workflow/hunt.js:1451` 的 G-DS-01 kinds 扩为 `siem/edr/logs/pcap/cloudtrail/telemetry-export`；`DATA_SOURCE_KINDS`（`hunt.js:16`）自 t20 已含 pcap/cloudtrail，本轮补齐门禁侧并要求测试解析 `requireDataSources` 与 reference/schema 三方一致；与 `references/blue/hunt-hypothesis.md:41` 一致。pcap/cloudtrail 正向跑通、未知 kind `network` → `G-CONF-01`+`G-DS-01` 且 0 agent（`test/workflow.test.mjs:1049`）；kind 对齐测试新增 `requireDataSources` 断言（`test/workflow.test.mjs:1179` 起）。`policy/authorization.md:142` 同步。 |
| R4 low | **fixed** | `docs/value-extraction.md:28` 按红队台账 §3 重写 9 项 drop 名单与理由（反取证/C2/EDR 规避/键盘记录/shellcode/数据外传/持久化/钓鱼/社工），并注明逐项见 `references/red/extraction-ledger.md` §2 的 #21/#22/#28/#30/#31/#37/#39/#44/#45；测试从台账 §3 抽取 9 项、要求文档逐项一致且旧的“与 dsh-security 重叠/价值更低”表述消失（`test/workflow.test.mjs:1145`）。 |
| R5 low | **fixed（文档侧）** | `policy/authorization.md:82` 增加 CIDR 运行期限制与冻结基线说明（IPv4 /8–/32、IPv6 /32–/128；`docs/design.md` §7.2 冻结仍写 0–32，以 policy + 运行期为准；更宽 CIDR 属设计变更）。`schema/scope.schema.json` 未加前缀 pattern（需允许改 schema），已在 `:83` 注明。 |
| R6 low | **fixed（lint 侧）** | `tools/sanitize-lint.mjs:665` 新增 asset provenance 校验：声明 `dsh-redblue:provenance` 的 yml/svg/txt 资产按 reference 六键/pin/license/path 校验（消息前缀 `asset `，helper `:584`）；未声明 provenance 的资产不属 R1、由 R2/R10 覆盖；正/反/无 provenance 三例测试 `test/tool-runtime.test.mjs:376`。`docs/sanitization-rules.md:213` R1 覆盖范围同步；§9.1 F4 的旧表述已按实际分类改正（sigma.yml 属 reference 由 R1 校验；icon.svg/cordis.patch.yml 无 provenance 仅 R2/R10）。 |
| R7 low | **fixed** | `tools/sanitize-lint.mjs:1601` 默认拒绝 `--policy`（仅 `NODE_ENV=test` 或显式 `--allow-policy-override` 放行，`:1583`）；usage `:1569–1571`；`docs/sanitization-rules.md:65–66、:86、:432` 写明“发布门禁不得带 --policy”；测试 `test/tool-runtime.test.mjs:403`（无 override exit 2、显式 override exit 0、NODE_ENV=test exit 0、默认 CLI 仍用内嵌 POLICY）。 |
| R8 low | **accepted（维持受理）** | design/requirements 冻结未同步：triage/harden 的 report 阶段（`docs/design.md` §6.8/§6.9）、seal 的 attestation 字段（§8.5）、`docs/requirements.md:231` 的 G-DS-01 四类 kind 与实现的差异，保持 §9.3/本节受理，下一版设计评审统一同步（含 R3/R5）。 |

### 10.2 验证

| 命令 | 结果 |
|---|---|
| `for f in dsh-redblue/workflow/*.js dsh-redblue/tools/lib/*.mjs dsh-redblue/tools/sec.mjs; do node --check "$f"; done` | 21/21 通过（9 workflow + 11 lib + sec） |
| `node --test dsh-redblue/test/workflow.test.mjs dsh-redblue/test/tool-runtime.test.mjs dsh-redblue/test/sanitize.test.mjs` | **89/89**（workflow 42 + tool-runtime 23 + sanitize 24） |
| `node --test dsh-redblue/test/scaffold.test.mjs` | 9/9（回归） |
| 4 个测试文件合计 | **98/98**（原 89 + 新增 9） |
| `node dsh-redblue/tools/sanitize-lint.mjs --strict --json dsh-redblue` | 87 文件、**0 blocker**、2 warning（既有 R11，§4 受理）；exit 0 |
| `grep -c 'pcap' dsh-redblue/workflow/hunt.js` | 2 |
| `grep -c 'confidenceRationale' dsh-redblue/workflow/triage.js` | 5 |

- 9 个 workflow 的 `validateScopeLimits` / `normalizeFinding` / `buildPrompt` 段哈希一致（测试内断言）；gate 与 workflow 的 limits 段逐字节相同。
- 新增测试 9 个：workflow 5（limits 同源、gate/guard 超限、review 字段同源、review 字段落盘、hunt pcap/cloudtrail）、tool-runtime 4（scope check 超限、guard 超限、R6 asset provenance、R7 --policy 门禁）。`test/sanitize.test.mjs` 未保留改动（内容逐字节恢复 8439 B，24 个原测试全过），R6/R7 测试放在 in-scope 的 `test/tool-runtime.test.mjs`。
- 未修改 `skills/`、`lib/`、`package.json`、`cordis.patch.yml`、`docs/requirements.md`、`docs/design.md`、`docs/review-notes.md`、其他 references、`.work/` 与 `dsh-security`。

### 10.3 变更文件（changedPaths）

- `tools/lib/gate.mjs`（R1 limits 生效）
- `workflow/assess.js`、`workflow/recon.js`、`workflow/exploit.js`、`workflow/post.js`、`workflow/hunt.js`、`workflow/ir.js`、`workflow/purple.js`、`workflow/triage.js`、`workflow/harden.js`（R2 全 9 份；R3 仅 hunt；R2 triage 透传/prompt）
- `tools/sanitize-lint.mjs`（R6 asset provenance、R7 --policy 门禁）
- `test/workflow.test.mjs`、`test/tool-runtime.test.mjs`（新增 9 个测试；`test/sanitize.test.mjs` 内容逐字节恢复，未计变更）
- `docs/value-extraction.md`（R4）
- `docs/sanitization-rules.md`（R6 覆盖范围、R7 说明）
- `policy/authorization.md`（G-CONF-01 limits、G-DS-01 kinds、R5 CIDR、两套入口一致）
- `docs/assembly-report.md`（本记录 + §9.1 F4 表述修正 + §9.3 R8 指向）

### 10.4 未改/受理与残余

- `skills/blue-hunt/SKILL.md`、`docs/requirements.md:231`、`docs/design.md` §6.5 仍写 G-DS-01 四类 kind（冻结/outOfScope）：实现与 policy 已扩为六类，属“文档比实现窄”，不构成门禁弱化；下一版设计评审同步。
- `docs/architecture.md:143` 的 hunt 数据源行同样未同步（本轮 outOfScope）。
- `docs/design.md` §7.2 的 CIDR 0–32 与实现 /8–/32 差异按 R5 受理；`schema/scope.schema.json` 未加 CIDR pattern（需允许改 schema 的单独授权）。
- G-DS-01 的 kind 枚举按复审 R3 指令扩为六类（pcap/cloudtrail 均为本地导出）；门禁语义未变：缺数据源仍拒绝、未知 kind 仍 `G-CONF-01`、`value` 仍必须 Windows 绝对路径且不含 `..`。
- R8：design/requirements 冻结文档债（triage/harden report 阶段、seal attestation）维持受理。