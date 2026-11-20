# dsh-redblue 独立复验报告

> **最终交付验证（t7）见文末 §14：PASS（0 blocker，3 条非阻塞观察 W1–W3）。**
> 本文件按时间顺序保留各轮验证记录：§1–§13 为 smoke 收口复验（t14/t19，均已 PASS），§14 为交付前的全量独立验证（净化门禁 R1–R12、工作流拒绝路径、provider 契约、工具运行时、价值提炼层、E2E smoke、可移植性）。

# 第 1 部分：smoke 收口复验记录（t14 / verification-round-2）

- 复验人：verifier（AgentTeams member "verifier"，task t14，attempt `e1db13eb-5324-421b-ab89-4b051a185713`）
- 复验时间：2026-11-19 22:25–23:05 +08:00
- 复验对象：`.work/smoke/recon-captain-20261119-2105`（recon 全链路）、`.work/smoke/assess-captain-20261119-2115`（assess 全链路）及其记录 `dsh-redblue/docs/smoke-report.md` §11
- 方式：**只读 + 独立复算**（不复用 captain 的结论数字；所有哈希、字节数、结构均由本会话重新计算）；除本文件外未修改任何被验证文件
- **总体判定：不通过（1 项验收未满足：§11 缺“产物哈希表”）**。两段全链路的**实际运行证据全部通过独立复验**（7 件产物 + manifest、14/14 哈希与字节零 mismatch、status=completed、exitCode=0、结构完整、dryRun 可追溯、缺陷 A/B 在真实运行中生效）；唯一缺口是 smoke-report §11 只列了产物**字节数**与 `mismatches 0` 摘要，未给出**逐件 SHA256 表**，不满足验收第 1 条的字面要求。

## 1. 结论摘要

| 验收项 | 判定 | 依据（本会话独立复算） |
|---|---|---|
| §11 含脚本 SHA256 / meta / args / 返回关键字段 / 产物哈希表 / 负路径结论 | **FAIL** | 前四项与负路径结论齐备；**缺逐件产物 SHA256 表**（§11.3/§11.4 仅列字节数 + `mismatches 0` 摘要） |
| recon 全链路 PASS | PASS | 7 件产物 + manifest；7/7 哈希与字节零 mismatch；`status=completed`、`exitCode=0`；§11.3 记录 `ok=true/sealed=true` |
| assess 全链路 PASS | PASS | 7 件产物（含 `exports/results.sarif`）+ manifest；7/7 零 mismatch；`status=completed`、`exitCode=0`；§11.4 记录 `ok=true/sealed=true` |
| report.md 章节完整；findings.json schema/字段 | PASS | 两段均含 `## 1. 概览`…`## 7. 封存`；`schemaVersion="dsh-redblue-findings/v1"`；`findings` 为空数组（clean 运行，见 §6 注） |
| 两段 manifest `dryRun=true`、`mode="passive"`；target 仅 `app.example.com`；无发包证据 | PASS | manifest 原值 + scope 投影 + 全部落盘证据仅本地命令/guard dry-run/拒绝记录；产物内无任何白名单外 URL 主机 |
| 缺陷 A 生效（逐字写入 + seal 复算） | PASS | 磁盘实际字节 == 脚本确定性期望（哈希），即写 agent 逐字落盘；seal 零 mismatch |
| 缺陷 B（scope.json 纯输入投影） | PASS | `scope.json` 8 键、无 `scopeDigest`/`validatedAt`；`scope.archive.json` 含两者；两段 `scope.json` 字节级相同 |
| 负路径结论仍成立；未用 vm/mock；脚本未落盘如实记录限制 | PASS（含限制） | §4/§11.5 结论在案；当前 `assess.js` 的 `G-ARG-01` 在任何 `agent()` 之前（`preflight` L1322 → 拒绝 L1323 → stage try L1330）；限制见 §10 |

## 2. 复验方法与环境

- 环境：Windows（win32 x64）、DSH 桌面版 0.2.2-rc.5、Node v24.22.1；工作区 `C:/dsh-workspace/branch1`。
- 独立复算：对两段 workDir 递归枚举文件；对 manifest 声明的每件产物重新计算 SHA256 与字节数并与 manifest 声明比较；重新解析 `scope.json`/`scope.archive.json`/`findings.json`/`coverage.json`/`exports/results.sarif`/`report.md`。
- 独立一致性核对：脚本 SHA256（磁盘）vs §11 表；`scopeDigest` 由 `scope.json` 重新推导 vs manifest；文内 runId/时间戳 vs manifest；文件 mtime vs 运行窗口；跨产物 URL 主机白名单扫描。
- 契约 verify 三条命令逐字执行（见 §9），全部 exit 0。

## 3. 两段运行基本信息（取自各自 `scan-manifest.json`）

| 项 | recon | assess |
|---|---|---|
| workDir | `.work/smoke/recon-captain-20261119-2105` | `.work/smoke/assess-captain-20261119-2115` |
| runId | `rb_20261119T130616Z_29e4` | `rb_20261119T132506Z_67b9` |
| workflow | recon | assess |
| status / exitCode | completed / 0 | completed / 0 |
| dryRun / mode | true / passive | true / passive |
| startedAt → finishedAt | 2026-11-19T13:06:16.386Z → 13:14:41.584Z | 2026-11-19T13:25:06.643Z → 14:10:51.538Z |
| manifest artifacts | 7 | 7 |
| scopeDigest | `dsh-redblue-scope/v1:sha256:d6eda1c1…dfd95c` | 同左（两段 scope 相同） |
| workDir 文件总数 | 16 | 99 |
| 全部文件 mtime 是否落在 [start-1m, end+10m] | 是（0 例外） | 是（0 例外） |

补充：两段另有 `scope.archive.json`（643 B）与阶段级产物（recon：`recon/*`、`recon-logs/*`、`recon-manifest.json`；assess：`discover/**`、`recon/**`、`surface/**`），均为 agent 阶段产物，不在 manifest 封存清单内（符合胶囊设计：manifest 只封存 7 件确定性产物）。

## 4. 哈希复算（本会话独立计算，非引用）

### 4.1 recon 全链路

manifest：1,622 B，SHA256 `597bcda01de63492f7fee6a88a832f5e8f939a388252defe7302c40ce1cb4c2f`。

| 产物 | 实际字节 | manifest 字节 | 实际 SHA256（=manifest，逐条比对） | 结果 |
|---|---|---|---|---|
| `coverage.json` | 5345 | 5345 | `b28d8bda7946037c8a0075f1de8c2d0246c049f4cd0fd05d09823b35ed086746` | OK |
| `exports/results.sarif` | 404 | 404 | `0e155f9cf8c066d49d10a6fc268bc9daf19930b83a4b8a6367fc26b42873bb5c` | OK |
| `findings.json` | 439 | 439 | `c8d29c033bcd00f94e3a5a988a49d6f9b8d577071552861568c674fbbfbe0ac1` | OK |
| `recon.json` | 1656 | 1656 | `19206c1f89eafb8c0d428d9ec6a16a4025dafde351b5af32a1bbba6a221d9273` | OK |
| `report.md` | 6168 | 6168 | `0d770a51a0a2ac060ce6bc675bf63e50070bfe1f29962961c657c5caf39a5050` | OK |
| `scope.json` | 493 | 493 | `d6eda1c1926cabf42e8193ef579b6e8ab9ef6a4b5d0909a4b677c76ac4dfd95c` | OK |
| `surface.json` | 2764 | 2764 | `4733df860cf35dc76993f66613f5c8948b773c70e8e471d205d9cef4ca03bc50` | OK |

mismatch = **0/7**。

### 4.2 assess 全链路

manifest：1,625 B，SHA256 `9b05596f00711ddc726b6eed5793d3a4de022873da40672607574d0e7e4c061e`。

| 产物 | 实际字节 | manifest 字节 | 实际 SHA256（=manifest，逐条比对） | 结果 |
|---|---|---|---|---|
| `coverage.json` | 37128 | 37128 | `de4c835fb07d514e29474bc782a26c68950ef555d58116944d2bb70efd51e447` | OK |
| `exports/results.sarif` | 405 | 405 | `e6c11f3e8d5a8956f02474d47234dd76a7e45736fba9d292c217259d9d985601` | OK |
| `findings.json` | 440 | 440 | `468ca1bfff4a64ddff2a68f1ec6cd1cc1ce1f9bf289e149ffb608dffa8c195f7` | OK |
| `recon.json` | 1706 | 1706 | `fd67483d249a577adff63c9e41ebf69d7ddb2a030cabe2b639a80615f49497e9` | OK |
| `report.md` | 37228 | 37228 | `9f45425a98f64dccd05e5c1458060fd1f03fe286eb4c908cff29a30b98eb0edd` | OK |
| `scope.json` | 493 | 493 | `d6eda1c1926cabf42e8193ef579b6e8ab9ef6a4b5d0909a4b677c76ac4dfd95c` | OK |
| `surface.json` | 3145 | 3145 | `9131d9d0983461b08278c3ac8c95c53f2e4688d7d88014f298d184f874db9f7e` | OK |

mismatch = **0/7**；`exports/` 目录存在且含 `results.sarif`。

## 5. 结构与内容

- `report.md` 章节：两段均含 `## 1. 概览`、`## 2. 授权与范围`、`## 3. 方法与覆盖`、`## 4. 发现`、`## 5. 限制与未测项`、`## 6. 数据处置与清理`、`## 7. 封存`（7/7）；文中含 `dryRun`，`app.example.com` 分别出现 7 / 18 次。
- `findings.json`：两段 `schemaVersion="dsh-redblue-findings/v1"`，`findings=[]`（clean），`summary.candidates/reportable/bySeverity/byDisposition` 齐全且全 0。
- `coverage.json`：recon `techniques=2/limitations=23/targets=1/phases=scope:1,recon:1,surface:1`；assess `techniques=6/limitations=104/targets=1/phases=scope:1,recon:1,surface:1,discover:8`，与 §11.4 的 techniques=6/limitations=104/targets=1 陈述一致（`validate` 因 0 候选短路未入 phaseLog，属设计行为）。
- `exports/results.sarif`：两段均 `version=2.1.0`、1 个 run、`tool.driver.name=dsh-redblue`、`results=[]`。

## 6. 缺陷 A / B 的真实生效证据

**缺陷 A（report 写入非逐字 → seal 失败）**：

- 当前胶囊（70,107 B）在 report 阶段为每件产物给出 `expected sha256`/`bytes`，要求写 agent **写入后回读**并返回实际值，最多 3 次重试，mismatch 汇入 seal 校验（代码位置：`phase("report")` 块，L1144–L1200 附近）。
- 更强证据：manifest 的期望哈希是脚本在写盘**之前**确定性生成的，而磁盘实际字节与期望**逐件完全一致**（§4）。写 agent 只要改写过任何字符，二者就不可能相等 → 真实运行中 7 件产物均为**逐字写入**，seal 复算 PASS。
- §11.4 记录 7 个 `report-write:*` agent 各 1 次写入即通过、零重试；本次复验无法从磁盘直接证明“恰好 1 次尝试”，但最终一致性已由哈希证明（重试是允许路径，不影响结论）。

**缺陷 B（scope.json 混入注解）**：

- 两段 `scope.json` 均 493 B、键恰为 `authorization,budget,dataHandling,dataSources,exclusions,mode,targets,window` 8 个；无 `scopeDigest`、`validatedAt`、`confirmedTarget`、`annotations`。
- `scope.archive.json` 643 B，键含 `scopeDigest`、`validatedAt`；其 `scopeDigest` 与 manifest 一致（`d6eda1c1…`）。
- 由 `scope.json` 重新推导 `sha256(stableStringify(8 键))` = `d6eda1c1…` = manifest `scopeDigest`；两段 `scope.json` 字节级相同。

## 7. 目标侧零动作与 dryRun 可追溯（无发包证据）

- 两段 manifest：`dryRun=true`、`mode="passive"`；`scope.targets` 仅 `domain: app.example.com`；`dataSources=[]`；`budget.maxRequests=1`。
- 落盘证据均为**本地、只读或 dry-run**：
  - `recon/evidence.jsonl` 4 条：`sec.mjs scope check`、`sec.mjs recipes show dns_lookup`、`sec.mjs guard --recipe dns_lookup`（`"dryRun": true`、`"note": "dry-run：只输出执行计划，不启动任何进程"`）、读取 `scope.json` 的 observation；`limitations` 明写“不访问网络/不启动进程”。
  - assess `recon.json` 明写 `targetRequestsSent=0`、未做 DNS/TLS/HTTP/端口/爬取；`discover/*/plan/*attempts.log` 为 `G-EXEC-01 配方不在白名单` / `无 --execute` 的**拒绝或计划**记录；`run-*-local.sh` 头部注明 “no --execute, no binary spawn, no network”。
  - 全量扫描两段 workDir（含 json/md/jsonl/log/sh/sarif）：除 `app.example.com`、`dsh.local`、`w3.org`、`json.schemastore.org` 等允许项外，**无任何其它 URL 主机**。
  - 未发现 `nslookup`/curl/nmap 等实际执行输出；`binaryAvailable=true` 仅为 PATH 探测，guard 输出明确未 spawn。

## 8. 反造假一致性核对

| 核对 | 结果 |
|---|---|
| §11.1 脚本 SHA256/字节 vs 磁盘当前文件 | recon 65,983 B / `b3f43c3e…c92bf72` ✔；assess 70,107 B / `52cccaf6…7ee7c1a3` ✔（**完全一致**） |
| §11 的 runId vs 两段 manifest | `rb_20261119T130616Z_29e4` / `rb_20261119T132506Z_67b9` ✔ |
| §11.3/§11.4 的产物字节 vs 磁盘 | 逐件一致 ✔ |
| §11.2 的 `scope.json` SHA256 声明 | 两段均为 `d6eda1c1…` ✔（= 文件 SHA256，也 = manifest scopeDigest 的摘要值） |
| §11.4 “coverage techniques=6 / limitations=104 / targets=1” | ✔ |
| 文件 mtime vs manifest 运行窗口 | 两段 0 例外（最晚文件 `scan-manifest.json` 分别写入 13:20:24Z / 14:20:12Z，晚于 `finishedAt` 属 seal 阶段正常顺序） |
| 旧失败运行是否被隐藏 | 否：`.work/smoke/assess-captain-20261119-1625/`（`runId=rb_20261119T082915Z_c548`，`status=failed`，7 件中 **2 件哈希不一致**）在报告 §10 中被显式引用并归因（seal 失败/缺陷 A），未被当作本次证据 |
| 契约 verify 目录选择副作用 | `assess-captain-` 前缀按字典序取到 `…-2115`（修复后 PASS 段）；旧失败段 `…-1625` 不被选中——本报告已单独核对并在 §10 说明，不构成隐瞒 |

## 9. 契约 verify 命令（逐字执行结果）

```
$ test -s dsh-redblue/docs/smoke-report.md
exit=0    # 32,437 B

$ node -e "...for pref of ['recon-captain-','assess-captain-']..."
recon-captain- recon-captain-20261119-2105 artifacts 7 mismatches 0 status completed exitCode 0 sealed undefined
assess-captain- assess-captain-20261119-2115 artifacts 7 mismatches 0 status completed exitCode 0 sealed undefined
exit=0

$ node -e "...assess-captain- ... findings.json..."
schema dsh-redblue-findings/v1 findings 0
exit=0
```

说明：`sealed undefined` 是因为 manifest 文档本身不含 `sealed` 字段（`sealed=true` 只出现在工具返回对象中，§11.3/§11.4 已记录）；本报告在 §10 说明该字段不可由磁盘独立验证。

## 10. 证据限制（如实记录）

1. **工具返回对象不可独立观测**：两段运行的 `ok=true`、`sealed=true`、`agents=12/20` 只存在于 captain 的会话返回与 §11 记录中；本复验只能验证落盘产物与 manifest，无法重放该返回。可验证的等价证据是：seal 阶段按约定只有在逐件一致时才写 `status=completed` 的 manifest（否则写 failed 变体并由脚本抛错），且本次独立复算 14/14 哈希与期望零 mismatch，佐证该状态不是虚报。
2. **内联脚本字节未落盘**：本机原生 `workflow` 工具不持久化脚本副本（`.dsh/workflow-runs/` 无本次记录），无法对“提交给工具的脚本文本”做字节级复核；§9 已记录该限制，§11.1 给出磁盘版本 SHA256 与内联方式。行为一致性（门禁/产物/哈希）支持“内联的是磁盘同源版本”，但不是字节级证明。
3. **“每件产物 1 次写入即通过”**：磁盘无 attempt 级日志，无法直接验证重试次数；最终一致性由哈希证明。
4. **负路径未在本轮原生重跑**：§11.5 沿用 t12 结论。本复验改为代码顺序核对：当前 `assess.js` 中 `preflight(args, CONFIG)`（L1322）与 `if (pre.rejectedBy.length > 0) return rejectedResult(...)`（L1323）位于任何 stage/agent 调用之前，`scope` 缺失在 L531 触发 `G-ARG-01` 并 `return pre`；`agent()` 仅存在于其后被调用的 `runStage`/`runFanout` 中。结合 §4 的 `status=rejected`、`exitCode=1`、`rejectedBy=["G-ARG-01"]`、`0 agents` 原始记录，结论仍然成立。
5. **旧失败 manifest 的 `mismatches=[]`**：`.work/smoke/assess-captain-20261119-1625/scan-manifest.json` 为修复前产物（`status=failed` 但 `mismatches` 为空，即 §10 所述缺陷 C 样本）；本轮两段成功运行不触发 failed 分支，其正确性依赖 t16/t17（不在本任务 in-scope）。

## 11. 发现与修复要求

**F1（medium，验收缺口）**：`docs/smoke-report.md` §11 缺少“产物哈希表”。

- 现状：§11.1 有脚本 SHA256 表；§11.3/§11.4 仅列产物**字节数**与 `artifacts 7 mismatches 0 …` 摘要；§10（修复前失败段）反而有完整逐件哈希表。
- 影响：验收第 1 条“§11：…产物哈希表…”字面不满足；不影响两段运行的功能结论（本报告 §4 已独立复算 14/14 全对）。
- 修复要求（只改 `docs/smoke-report.md`，不改运行目录）：在 §11.3/§11.4 各追加一张 7 行表，列为 `产物 | 实际字节 | manifest 字节 | 实际 SHA256 | 结果`，数值可直接采用本报告 §4.1/§4.2（已由本会话对磁盘独立复算）。修复后本任务可复审通过。

## 12. 改动声明

- 本复验只新增 `dsh-redblue/docs/verification-report.md`；另有临时复算脚本 `.work/tmp/t14-verify.mjs`（临时区，非插件文件，t9 清理）。
- 未修改 `dsh-redblue/docs/smoke-report.md`、`workflow/`、`skills/`、`references/`、`lib/`、`tools/`、`test/`、`package.json`、`policy/`、`docs/{requirements,design,sanitization-rules,assembly-report}.md`、`.work/sources/`、`dsh-security/`。
- 未触发任何网络请求；未运行任何白名单工具；仅执行只读文件读取、`node` 哈希/JSON 计算与契约 verify 命令。

## 13. 复审（t19 / verification-round-3）

- 复审对象：t18 对 `docs/smoke-report.md` 的追加修复；方式同 §2（只读 + 独立复算，不引用修复方数字）。
- **结论：F1 已修复，全部复验项通过，本任务可 completed。**
- 证据：
  1. **表格存在且正确**：§11.3/§11.4 各新增 5 列 × 7 行产物表（产物 | 实际字节 | manifest 字节 | 实际 SHA256 | 结果）。脚本逐行解析两表 14 行并与磁盘重新计算比对：**14/14 行字节与 SHA256 全部一致**（recon：5,345/404/439/1,656/6,168/493/2,764 B；assess：37,128/405/440/1,706/37,228/493/3,145 B），且与各自 `scan-manifest.json` 声明一致。
  2. **修复范围最小且可证**：剥离两段追加块（978 B + 982 B）后，文档字节数精确回到 **32,437 B**（= §12 记录的修复前大小）→ 除这两张表外未改动任何字节（§1–§10 与 §11 其余内容保持原样）。
  3. 文档现状：34,397 B / 472 行 / SHA256 `672bdc2505dcddd1726669623eae873bd94cede96c06b1428e3232986f666399`（与 t18 声明一致）。
  4. **运行证据未被触碰**：两段 workDir 的 manifest mtime 仍为 21:20:24 / 22:20:12（早于修复），全量 14/14 哈希复算仍零 mismatch；`status=completed`、`exitCode=0`、`dryRun=true`、`mode=passive`；`report.md` 7 章节、`findings.json` = `dsh-redblue-findings/v1`、`scope.json` 8 键无注解/`scope.archive.json` 含注解且 digest 与 manifest 一致、SARIF 2.1.0、target 仅 `app.example.com` —— 与 t14 复验结论逐项相同。
  5. **负路径结论仍在案**：§4 与 §11.5 的 `status=rejected`、`exitCode=1`、`rejectedBy=["G-ARG-01"]`、`0 agents` 未被改动（t14 已做代码顺序核对，本轮文档仅增表）。
  6. 契约 verify 三条命令逐字执行全部 **exit 0**（报告非空；`ls .work/smoke` 正常；assess manifest 复算 `artifacts 7 mismatches 0 status completed exitCode 0`）。
- 残余证据限制：与 §10 相同（返回对象不可独立观测、内联脚本未落盘、重试次数不可验、负路径未原生重跑），本轮不重复展开。
- 本轮未修改 `docs/smoke-report.md`、`.work/smoke/**` 及任何插件源码；仅追加本节。
# 第 2 部分：最终交付验证（t7）

## 14. 交付前全量独立验证（t7 / verification-round-1）

- 验证人：verifier（AgentTeams member "verifier"，task t7，attempt `89ab1f6c-8ba1-46a7-a2ff-8d441a932707`）
- 时间：2026-11-19 22:30–23:10 +08:00
- 范围：`dsh-redblue` 全插件（114 个文件）；方式：**只读 + 可复跑命令 + 独立复算**，除本文件外未修改任何文件
- **总体判定：PASS（0 blocker；3 条非阻塞观察 W1–W3，见 §14.11）**

### 14.1 环境

| 项 | 值 |
|---|---|
| OS / Shell | Windows 11（win32 x64），MSYS Bash，工作区 `C:/dsh-workspace/branch1` |
| Node | `v24.22.1`（`node --check`/`--test`/工具运行时均用此版本） |
| 插件 | `dsh-redblue@0.1.0`，Apache-2.0，零 npm 依赖（`dependencies`/`devDependencies` 均无，`engines.node>=20`） |
| 插件文件数 | 114（0 个 `.py/.sh/.exe/.bat/.ps1/.vbs`） |
| 验证辅助脚本 | 仅临时区 `.work/tmp/t7-*.mjs|sh`（非插件文件） |

### 14.2 命令表（实际执行 + 退出码 + 关键输出）

| # | 命令 | 退出码 | 关键输出 |
|---|---|---|---|
| C1 | `node dsh-redblue/tools/sanitize-lint.mjs --strict --json dsh-redblue` | **0** | `checkedFiles=83`、`blockers=0`、`warnings=2`；两条均为 `R11-TERMINOLOGY`（`skills/purple-verify/SKILL.md:3`、`skills/red-exploit/SKILL.md:3`，design 固定 description 触发，assembly-report §4 已受理） |
| C2 | `node --test dsh-redblue/test/scaffold.test.mjs dsh-redblue/test/sanitize.test.mjs dsh-redblue/test/workflow.test.mjs dsh-redblue/test/tool-runtime.test.mjs` | **0** | `tests 76 / pass 76 / fail 0`（scaffold 9、sanitize 20、workflow 29、tool-runtime 18） |
| C3 | `node --test dsh-redblue/test/`（任务书目录形式） | **1** | `Cannot find module 'C:\...\dsh-redblue\test'`（Node v24 测试运行器要求文件/glob 参数）→ **非插件缺陷**，见 W3；插件自带 `npm test`（=C2）通过 |
| C4 | 全部 js/mjs `node --check`（27 个：lib 1、workflow 9、tools 15、test 2） | **0** | 27/27 OK，0 语法错误 |
| C5 | 工作流负向用例独立复跑（自建 vm 沙箱 + 11 用例，见 §14.7） | **0** | 11/11 被拒绝：`status=rejected`、`exitCode=1`、`rejectedBy` 命中期望门禁，**agent 调用总数 0** |
| C6 | 10 个关键参考/模板 `test -s` | **0** | 全部存在且非空 |
| C7 | `node dsh-redblue/tools/sec.mjs recipes list` | **0** | `count=10`，配方 `dns_lookup/http_headers/tls_certificate/port_scan/vuln_scan/web_fuzz/pcap_read/file_hash/certificate_query/runtime_probe` |
| C8 | 工具运行时子命令（scope check / evidence hash+verify / sarif / ioc / log / rule / recipes show） | **0/0/0/0/0/0/1/0** | 见 §14.7；`rule lint` 对自带 sigma 模板 exit 1（见 W2） |
| C9 | guard 拒绝矩阵 G1–G10 | 见 §14.7 | 7 类安全拒绝均 `exit 1` 且未 spawn；缺 `--scope` 选项时 `exit 2`（usage，见 W1）；`--scope` 不可读时 `exit 1/G-AUTH-01` |
| C10 | `test -s dsh-redblue/docs/smoke-report.md` | **0** | 34,397 B，含 §11 修复后真实运行与负路径结论 |
| C11 | `find dsh-redblue -type f \( -name '*.py' -o -name '*.sh' -o -name '*.exe' -o -name '*.bat' -o -name '*.ps1' -o -name '*.vbs' \) \| wc -l` | **0** | `0` |
| C12 | E2E smoke manifest 复算（两段各 7 件产物） | **0** | 两段 `mismatches=0`、`status=completed`、`exitCode=0` |

### 14.3 R1–R12 判定表（36 条检查全跑，另加人工抽样）

| 规则 | 判定 | 取证来源 |
|---|---|---|
| R1 来源与许可 | **pass** | lint `R1-PROVENANCE/R1-NOTICE/R1-LICENSE` 0 blocker；42 个技能/参考中 41 个含 6 键 provenance（`references/INDEX.md` 为索引，仅 `last-verified`，设计豁免）；`source-commit` 集合恰为 3 个 pin（`6196ba74…`、`54a79883…`、`8db295a5…`）；`NOTICE` 3,626 B 含三上游归属 + pin + MIT 全文 + `Modifications:` 修改声明 + 下游保留要求；`LICENSE` 11,271 B 为 Apache-2.0 全文 |
| R2 占位符净化 | **pass** | lint 5 条 R2 检查 0 blocker；抽样：域名类命中 7 处全为字段路径/OAST/allowed（§14.4.3）；IPv4 0、真实邮箱 0、32/40/64 位哈希 0（3 个 pin 已白名单） |
| R3 无武器化制品 | **pass** | lint `R3-WEAPON/R3-DESTRUCTIVE/R3-AUTH-BANNER` 0 blocker；denylist 抽样 11 处命中全为“检测正则本身/策略禁令文本/上游技能名/风险表述”（§14.4.4），无可复制制品 |
| R4 授权门禁与安全默认 | **pass** | lint 4 条 R4 检查 0 blocker；11 个负向工作流用例 + guard 矩阵（§14.7）；`dryRun` 默认 true（G9 输出 `"dryRun": true`、`note: 不启动任何进程`） |
| R5 不制造虚假内容 | **pass** | lint `R5-FAKE/R5-METRIC/R5-CVE` 0 blocker；人工抽样：内容文件“百分比 + 效能词且 ±3 行无 source/权威链接” **0 命中**；内容中无任何 `CVE-*` 断言 |
| R6 结构上限 | **pass** | lint 4 条 R6 检查 0 blocker；实测：SKILL.md 最大 8,939 B / 176 行（≤24 KiB/≤300 行）；description 最大 286 码点（≤500）；参考最大 32,841 B（≤48 KiB） |
| R7 去重与触发隔离 | **pass** | lint `R7-NAME/R7-JACCARD/R7-NEGATIVE` 0 blocker；15/15 目录↔frontmatter↔provider 名称一致；105 对 description CJK bigram Jaccard 最大 **0.1395**（red-recon~red-surface，阈值 0.35，冲突对 0）；15/15 含“不适用：”，触发词最少 6 个 |
| R8 提示注入防御 | **pass** | lint `R8-SKILL/R8-WORKFLOW` 0 blocker；15/15 技能中 `ingests:target` 的 13 个全部含边界句（抽样 `skills/red-recon/SKILL.md:110-111`、`skills/blue-hunt/SKILL.md:99-100`）；9/9 workflow 阶段 prompt 注入 `UNTRUSTED_CLAUSE` |
| R9 时效标注 | **pass** | lint `R9-LAST-VERIFIED` 0 blocker、`R9-VERSION-FRESH` 0 warning；42/42 技能/参考 `last-verified: 2026-11-19` |
| R10 机密与隐私 | **pass** | lint `R10-SECRET/R10-PII/R10-INTERNAL-HOST` 0 blocker；抽样 `AKIA*/PEM/GitHub token/Slack token` 0 命中；真实邮箱 0；`.internal/.corp/.lan` 仅出现在策略禁令文本（`policy/sanitization.md:206`） |
| R11 语言与术语（warning） | **pass（2 条已受理 warning）** | `R11-TERMINOLOGY` 2 条：`skills/purple-verify/SKILL.md:3`、`skills/red-exploit/SKILL.md:3`；均为 design §4.2 固定 description 中“发现”与字段名 `findings` 同现，policy 定为 warning 级，`docs/assembly-report.md §4` 已受理；除此外 0 条 |
| R12 风险分级与安全默认 | **pass** | lint `R12-RISK/R12-CONFIRM/R12-REPORT-ONLY` 0 blocker；15/15 技能 `risk∈{passive,active,exploit,post}`、`requires∈{none,authorization}`；exploit/post confirm 精确匹配由 N5–N8 与 guard G5 验证 |

### 14.4 量化指标与抽样

#### 14.4.1 技能结构（15 项）

| 指标 | 实测 |
|---|---|
| 技能数 | 15（rb 3 / red 7 / blue 4 / purple 1；目录与 `lib/index.js` 常量一一对应） |
| SKILL.md 行数 | 108–176（上限 300） |
| SKILL.md 字节 | 5,782–8,939（上限 24,576） |
| description 码点 | 157–286（上限 500；全部含“触发词：”≥6 项与“不适用：”） |
| frontmatter 键 | 15/15 均 12 键齐全（name/description/whenToUse/risk/requires/ingests/source-repo/source-commit/source-license/source-path/last-verified/rewrite-summary） |
| whenToUse | 15/15 非空；负向触发（不适用）15/15 |
| ingests | 13 个 `target`（全部含 4 元素边界句）、2 个 `none`（`red-scope`、`run`） |
| risk/requires | `risk` 分布 passive 11、active 2、exploit 1、post 1；`requires` = authorization（10）/none（5） |

#### 14.4.2 参考与触发隔离

| 指标 | 实测 |
|---|---|
| 参考文件 | 27 篇（含 INDEX 1 篇）；最大 32,841 B（`strix-techniques.md`），全部 ≤48 KiB；provenance 6 键完整 26/27（INDEX 仅 `last-verified`，豁免） |
| Jaccard（105 对） | 最大 **0.1395**（red-recon~red-surface）；>0.35 的冲突对 **0** |
| workflow 引用实际参考 | 9/9 胶囊 prompt 引用真实参考路径；8/9 引用 `tool-recipes.md`（triage 为复核类、无工具执行，仅引用 `shared/evidence-standards.md`/`shared/finding-review.md`，符合设计） |
| workflow 门禁覆盖 | 每胶囊 30–35 个唯一 `G-*` 门禁引用；9/9 注入不可信数据边界句 |

#### 14.4.3 占位符/真实标识抽样（R2）

| 类别 | 命中 | 判定 |
|---|---|---|
| 非白名单域名 | **0**（7 处候选全为良性：`references/blue/tool-recipes.md:239 dns.qry.name`、`references/red/discover-cloud-container.md:113 metadata.name`、`references/red/tool-recipes.md:271 metadata.name` 为 Sigma/K8s 字段路径；`references/red/recon-osint.md:35 com.example.app` 为 Android 包名；`policy/sanitization.md:97 oast.example.test/oast.test/interact.test` 为 §3.3 允许的 OAST 域） |
| 真实 IPv4（非文档网段/回环/白名单） | **0** |
| 真实邮箱 | **0** |
| 恶意样本/真实哈希（32/40/64 hex） | **0**（3 个上游 pin commit 已显式白名单） |
| 内网主机名后缀 | 1 处理论文本（`policy/sanitization.md:206` 为禁令说明） |
| 私有网段 | 0 处示例（仅 `tools/sanitize-lint.mjs:104` 的策略常量定义） |

#### 14.4.4 武器化 denylist 抽样（R3）

| 类别 | 命中 | 位置与判定 |
|---|---|---|
| webshell | 1 | `tools/sanitize-lint.mjs:771` 检测正则本身（`/aspxspy|c99shell|b374k/i`）— 检测器定义，非制品 |
| 反弹 shell | 0 | — |
| C2 | 3 | `references/blue/extraction-ledger.md:172/175`（上游 ACS 技能**名**，列于 §5.1 “D1 红队执行与武器化 71 个 drop 名单”）+ `tools/sanitize-lint.mjs:785` 检测正则 — 均为文档/检测器，非制品 |
| 凭据 dump | 5 | `references/blue/extraction-ledger.md:181/218`（drop 名单技能名）、`references/red/discover-identity-ad.md:50`（“存在可 Kerberoast 服务账号”风险表述，无命令）、`tools/sanitize-lint.mjs:780/783`（检测正则） |
| 破坏性命令 | 1 | `policy/sanitization.md:153` 禁令文本 |
| 凭据材料（AKIA/PEM/token/password=） | 1 | `policy/sanitization.md:205` 禁令文本；代码/参考中 0 命中 |
| 武器化下载执行（curl|sh 等） | 0 | — |

结论：**0 个可复制武器化制品**；全部 11 处命中均为检测器定义、策略禁令文本、上游技能名清单或风险表述，且 lint `R3-WEAPON` 判定 0 blocker。

#### 14.4.5 虚假声明抽样（R5）

- “百分比 + 检出率/准确率/成功率/覆盖率/误报率”且 ±3 行内无 `source:`/`来源:`/权威链接：**0 命中**。
- 内容中无 `CVE-*` 编号断言（`grep CVE-20xx-xxxx` 0 命中）。

### 14.5 集成契约

| 检查 | 实测 |
|---|---|
| provider 注册 | `apply(ctx)` → `ctx.skills.registerProvider(() => provider)`；`inject=["skills"]`；插件名 `dsh-redblue` |
| `provider.list()` | **15 项**；每项 `provider=dsh-redblue`、`source=bundled`、`rank=600`、`resourceBase` 指向存在的 `skills/<dir>/`、`locator` 可读 |
| name/dir/frontmatter 一致 | 15/15 一致（`nameFrontmatterMismatch=0`）；`provider.get(name)` 返回非空正文 |
| 静态 peer import | 无：`lib/index.js` 仅 import `node:fs/promises` 与 `node:url`；`lib/index.d.ts` 仅 `import type`（编译期擦除）；`test/scaffold.test.mjs:99` 断言禁止 `@deepseek-ai/` 静态 import |
| bundle patch | `cordis.patch.yml` 可解析：`- insert:` → `id: dsh-redblue` / `name: 'dsh-redblue'`；`package.json` 的 `dsh.bundle.patch` 指向该文件 |

### 14.6 可移植性

| 检查 | 实测 |
|---|---|
| 硬编码 `/tmp` | 插件代码/内容 **0**（唯一匹配为本报告自身的临时路径文字） |
| `0.0.0.0/0` 等通配 | 11 处，全部位于**拒绝/检测**语境（9 个胶囊的 `isWildcardTarget` 守卫、`tools/lib/gate.mjs:133`、`tools/sanitize-lint.mjs:106` 常量），符合 policy §3.2 例外 |
| 外部网络调用 | 代码中 `fetch/http.request/net.connect/dns.lookup` **0**（唯一命中是 `test/workflow.test.mjs:212` 的**禁止**断言） |
| npm 依赖 | `dependencies`/`devDependencies` 均空；零第三方依赖 |
| MSYS 路径 | 全部命令在 MSYS Bash + 正斜杠路径下通过（C1–C12） |

### 14.7 工具运行时（`tools/sec.mjs`）与 guard 拒绝矩阵

**子命令实测**

| 子命令 | 退出码 | 关键输出 |
|---|---|---|
| `scope check --scope <valid>` | 0 | `ok=true`，归一化 targets=1、mode=passive |
| `evidence hash --dir <dir> --out m.json` | 0 | `files=2`，生成 SHA256 清单 |
| `evidence verify --manifest m.json --dir` | 0 | `ok=true`（checked=2、missing/mismatched/extra 空） |
| `sarif convert --findings f.json --out s.sarif` | 0 | `version=2.1.0`、`runs[0].results=1`、`tool=dsh-redblue` |
| `ioc extract --input i.txt` | 0 | 返回 `ok/input/defanged/counts/urls/domains/ips/hashes`（默认 defang） |
| `log normalize --input in.csv --format csv --out o.jsonl` | 0 | 输出 1 行 JSONL |
| `rule lint --file <sigma 模板>` | **1** | `invalid-status`(L23)、`invalid-level`(L24)、`id-format` warning（模板含占位符+行内注释；见 W2） |
| `recipes list` / `recipes show dns_lookup` | 0 / 0 | `count=10` / `recipe.id=dns_lookup` |

**guard 拒绝矩阵（全部使用保留域 `app.example.com` 或文档网段，未触发任何发包）**

| 用例 | 条件 | exit | rejectedBy |
|---|---|---|---|
| G1 | 缺 `--scope` 选项 | **2** | `{ok:false,error:"缺少必填选项 --scope"}`（usage；未 spawn，见 W1） |
| G1b | `--scope` 指向不存在文件 | **1** | `G-AUTH-01`（scope 不可读） |
| G2 | 授权已过期 + 窗口过期 | **1** | `G-AUTH-07,G-WIN-03` |
| G3 | 目标不在 `scope.targets` | **1** | `G-TGT-04` |
| G4 | 通配目标 `0.0.0.0/0` | **1** | `G-TGT-03` |
| G5 | `--confirm` 与 target 不符 | **1** | `G-CFM-02` |
| G6 | mode 不足（`http_headers` 需 active，scope=passive） | **1** | `G-MODE-02`（并伴随 `G-TGT-04`，因 URL 目标未在 scope 内） |
| G7 | 二进制缺失（nmap） | **1** | `G-EXEC-01`（目标二进制不存在，spawn 之前拒绝） |
| G8 | 配方不在白名单 | **1** | `G-EXEC-01` |
| G9 | dry-run 默认（dns_lookup） | **0** | `ok=true/dryRun=true/note:"只输出执行计划，不启动任何进程"` |
| G10 | 未知子命令 `exec --cmd whoami` | **2** | usage（无自由命令入口） |

**无自由命令入口**：CLI 只暴露 10 个固定子命令与 10 条白名单配方；`spawn(` 仅在 `tools/lib/guard.mjs:155` 一处，argv 由配方逐元素替换、`shell:false`；`--cmd/--command/--exec-string/shell: true` 命中 0。

**配置校验**：`scope check` 与 guard 复用 `tools/lib/gate.mjs`；工作流与工具运行时拒绝语义一致（G-AUTH/G-TGT/G-MODE/G-WIN/G-BUD/G-DH/G-CONF + G-EXEC/G-CFM）。

### 14.8 价值提炼层

| 项 | 实测 |
|---|---|
| 红队配方 | `references/red/tool-recipes.md` 27,766 B，**16 族**（F1–F16 唯一 id） |
| 蓝队配方 | `references/blue/tool-recipes.md` 30,445 B，**12 族**（B1–B12 唯一 id） |
| Claude-Red 台账 | `references/red/extraction-ledger.md` §2 行数 **79** = keep 14 + merge 49 + drop 16 |
| Strix 9 技能 | 同文件 §4 行数 **9** = keep 2 + merge 7 + drop 0 |
| Strix 78 篇 | 同文件 §8 行数 **78** = keep 47 + merge 29 + drop 2 |
| ACS 台账 | `references/blue/extraction-ledger.md` §6.1：keep 60 / merge 672 / drop 86（D1 71+D2 14+D3 1）= **818**；§7 有 809 个 `agent.py` 的 58 行统计表 |
| 检测模板 | `sigma.yml` 4,437 B（14 个顶层键含 title/id/status/level/logsource/detection/falsepositives）、`kql.md` 7,509 B、`spl.md` 6,386 B；三者均含 `<PLACEHOLDER>`、示例为假数据 |
| 脚本模式库 | `references/shared/script-patterns.md` 18,260 B，S1–S7 七段骨架 + A1–A12 反模式表 + 809 统计 |
| workflow→配方路径 | 8/9 胶囊 prompt 引用 `references/*/tool-recipes.md`（triage 无工具执行，只引用共享参考，符合设计） |

### 14.9 Strix 内部知识吸收与 finding-review

| 检查 | 实测 |
|---|---|
| `references/red/strix-techniques.md` | 32,841 B；§1 漏洞决策表 **30 行**；框架特化 5（Django/FastAPI/NestJS/Next.js/Spring Boot）；云/容器 4（AWS/Azure/GCP/Kubernetes）；GraphQL 与 SAST（opengrep/ast-grep）均覆盖 |
| 78 篇台账合计 | 47 keep + 29 merge + 2 drop = 78（与 §8 行数一致） |
| `references/shared/finding-review.md` | 17,892 B；含 `counterevidence`、`severity_calibration`、`fix_verification` 三要素 |
| 引用关系 | `skills/rb-triage/SKILL.md` 与 `skills/purple-verify/SKILL.md` 均引用 `references/shared/finding-review.md`；`workflow/assess.js`、`triage.js`、`harden.js` 的 prompt 亦引用 |

### 14.10 E2E smoke（引用 t14/t19 结论并复核磁盘）

| 检查 | 实测 |
|---|---|
| smoke 报告 | `docs/smoke-report.md` 34,397 B；§11 含两段脚本 SHA256、meta/args、返回关键字段、**逐件产物 SHA256 表**（14 行，本轮逐行复核与磁盘一致）、负路径结论 |
| recon 全链路 | `.work/smoke/recon-captain-20261119-2105`：5 件公共产物 5/5、artifacts 7、**mismatch 0**、`status=completed`、`exitCode=0`、`dryRun=true`、`mode=passive` |
| assess 全链路 | `.work/smoke/assess-captain-20261119-2115`：5 件公共产物 5/5（含 `exports/results.sarif`）、artifacts 7、**mismatch 0**、`status=completed`、`exitCode=0`、`dryRun=true`、`mode=passive` |
| 负路径 | t12 两条空 workDir 仍在；`docs/smoke-report.md` §4/§11.5 记录 `status=rejected`/`exitCode=1`/`rejectedBy=["G-ARG-01"]`/`0 agents`；本轮对**当前胶囊**独立复跑缺 scope 用例（N1）同样得到 `rejected/G-ARG-01/0 agents` |
| 无第三方目标 | 两段 workDir 全量 URL 主机扫描（允许保留域/权威域/`dsh.local`）→ **0** 个外部主机；阶段证据仅本地 `sec.mjs` 命令与 guard dry-run/拒绝记录 |
| dryRun 可追溯 | 两段 manifest `dryRun=true`、`mode="passive"`；`scope.targets` 仅 `domain:app.example.com` |

### 14.11 非阻塞观察（W1–W3，逐条说明）

**W1（low）缺 `--scope` 选项时 guard 退出码为 2 而非验收字面要求的 1**

- 实测：`node dsh-redblue/tools/sec.mjs guard --recipe runtime_probe --target app.example.com --execute --confirm app.example.com` → exit **2**，输出 `{ok:false,error:"缺少必填选项 --scope",usage:…}`；未 spawn、无产物。
- 代码定位：`tools/lib/args.mjs:50` 抛 `UsageError`；CLI 将 usage 错误映射为 exit 2（CLI 约定），门禁拒绝映射 exit 1。
- 安全语义满足：`--scope` 指向不可读文件时 exit **1** + `G-AUTH-01`（G1b）；其余 7 类安全拒绝均 exit 1。差异仅在“选项缺失”这一 CLI usage 场景。
- 建议（二选一，不需要重跑 smoke）：修订验收措辞为“非零退出且未 spawn”，或将缺失 `--scope` 映射为 exit 1。

**W2（medium）`rule lint` 不剥离行内 `#` 注释，导致自带 sigma 模板被自身 linter 判失败**

- 复现：`node dsh-redblue/tools/sec.mjs rule lint --file dsh-redblue/references/blue/templates/sigma.yml` → exit 1，`invalid-status`（L23）、`invalid-level`（L24）。
- 最小复现：任一合法 Sigma 规则中 `status: experimental  # 注释` / `level: high  # 注释` 即被判非法。
- 代码定位：`tools/lib/sigma.mjs:25-48` 的 `parseSkeleton` 直接取 `key: value` 冒号后整段文本（未执行 `split("#")[0]`），故行内注释进入枚举校验。
- 影响：模板说明“复制后替换 `<...>` 占位符”但保留行内注释，用户复制后会立即撞到该 lint 失败；不影响净化门禁与安全语义（sanitize-lint 仍 0 blocker）。建议 `value.split("#")[0].trim()` 或移除模板枚举行的行内注释。

**W3（low，环境）`node --test dsh-redblue/test/` 目录形式在 Node v24 失败**

- 实测：exit 1，`Cannot find module 'C:\...\dsh-redblue\test'`；Node v24 测试运行器要求文件/glob 参数，不遍历裸目录。
- 插件自带命令（`npm test` = 四个显式 test 文件）通过 76/76；契约 verify 亦使用显式文件。无需修改插件，仅记录命令形式差异。

### 14.12 Blocking 缺陷清单

**空（0 blocker）。** 上节 W1–W3 均不阻塞交付：无安全门禁绕过、无数据处置缺陷、无 E2E smoke 失败、无伪造证据、无真实目标/凭据/武器化制品。

### 14.13 总体判定

**PASS。** 依据：C1–C12 全部关键门禁通过（唯一非零项为 Node 目录形式的 W3 与模板 rule-lint 的 W2，均已定位且非阻塞）；R1–R12 全部 36 条检查 0 blocker，2 条 warning 均为已受理的 R11；15 技能/27 参考/16+12 配方族/79+9+818+78 台账/模板/模式库/Strix 矩阵/provider 契约/E2E smoke 均以可复跑命令与文件级证据核实；除 W1–W3 外无其它 warning。

### 14.14 本轮改动声明

- 仅修改 `dsh-redblue/docs/verification-report.md`（新增本部分与顶部指引）；临时验证脚本在 `.work/tmp/t7-*`（非插件文件，t9 清理）。
- **未修改** `lib/`、`skills/`、`references/`、`workflow/`、`tools/`、`test/`、`package.json`、`README.md`、`policy/`、`docs/{requirements,design,sanitization-rules,assembly-report}.md`、`.work/smoke/**`、`.work/sources/`、`dsh-security/`。
- 未触发任何网络请求；未运行任何白名单工具配方（guard 全部为 dry-run 或被拒绝；G7 的 nmap 因二进制缺失在 spawn 前拒绝）。

---

# 第 3 部分：t26 当前字节独立复验（verification-round-2，替代 t7）

> 复验人：verifier2（独立验证，未参与 t20/t22 的修复实现）。时间：2026-11-20（UTC+8）。对象：**t22 完成后的当前工作树字节**；本部分全部数字均为本轮重新计算/重新执行所得，未引用 §14（t7）的结论或数字。除本文件外未修改任何被验证文件。

## 15. 结论摘要

| 项 | 结果 |
|---|---|
| 总体判定 | **PASS（0 blocker）** |
| 静态净化门禁 | `sanitize-lint --strict --json`：87 文件、0 blocker、2 warning（R11 既有，assembly-report §4 受理），exit 0 |
| 测试 | 4 个显式测试文件 **98/98 通过**（scaffold 9、sanitize 24、workflow 42、tool-runtime 23），exit 0 |
| 语法 | 全部 `.js/.mjs` **27/27** 通过 `node --check`，0 失败 |
| 工作流负向 | 独立沙箱构造 **17/17** 拒绝：`rejected` + `exitCode=1` + `code=1` + **0 agent**；另有正向/复核 5/5（合计 22/22） |
| R1–R3 复核 | scope check 与 guard 超限均 exit 1 + `G-CONF-01`（guard 0 spawn、workdir 0 文件）；findings.json 5/5 复核字段落入 assess 与 triage；hunt 接受 pcap/cloudtrail、拒绝未知 kind |
| 量化指标 | 15 技能 / 9 workflow / 27 参考 / 6 schema / 10 recipes；Jaccard 最大 0.1375 ≤0.35；description 157–286 码点；provenance 27/27 六键齐全 |
| E2E 证据 | `.work/smoke` recon 与 assess 各 7 件、合计 **14/14 哈希零 mismatch**；`status=completed`、`exitCode=0`、`dryRun=true`、`mode=passive`（只读复核，未重跑） |
| Blocking | **空（0）**；非阻塞观察 O-1..O-4 见 §15.8 |

## 15.1 环境

| 项 | 值 |
|---|---|
| 主机/运行时 | Windows x64；Node **v24.22.1**（`process.platform=win32`、`process.arch=x64`） |
| 工作树 | `C:\dsh-workspace\branch1`；插件 `dsh-redblue` 0.1.0；工作目录 `dsh-redblue/` |
| 插件策略版本 | `R1-R12/v1`；workflow toolchain `dsh-redblue-native-workflow/v1`；manifest `dsh-redblue-manifest/v1` |
| 上游 pin | claude-red `6196ba7464662de34e8744d359f175d1a7bca530`、ACS `54a798831d2266a3ca61ce68a7acb80b81160d57`、strix `8db295a5b3564be2b430bb3a9afdb4db7850fa24`（与 NOTICE、15 个 SKILL.md、27 篇参考、smoke manifest 一致） |
| 时间 | lint `generatedAt=2026-11-20T01:25:37.150Z`；复验采样 `2026-11-20T01:33Z`（UTC+8 09:25 / 09:33） |
| 证据限制 | 未重跑真实 workflow/smoke、未运行任何白名单配方、未发起网络请求；负向与正向探针使用 node:vm 加载 workflow 胶囊 + stub agent（胶囊本身无 fs/网络/Node API），临时脚本在 `%TEMP%\t26-verify\`（不属于插件交付物） |

## 15.2 命令表（本轮实际执行，命令/退出码/关键证据）

| # | 命令 | 退出码 | 关键证据 |
|---|---|---|---|
| C1 | `node dsh-redblue/tools/sanitize-lint.mjs --strict --json dsh-redblue` | **0** | `checkedFiles=87`、`blockers=0`、`warnings=2`；仅 `skills/purple-verify/SKILL.md:3` 与 `skills/red-exploit/SKILL.md:3`（R11-TERMINOLOGY，已受理） |
| C2 | `node --test dsh-redblue/test/scaffold.test.mjs dsh-redblue/test/sanitize.test.mjs dsh-redblue/test/workflow.test.mjs dsh-redblue/test/tool-runtime.test.mjs` | **0** | `ℹ tests 98 / pass 98 / fail 0`；逐文件：scaffold 9/9、sanitize 24/24、workflow 42/42、tool-runtime 23/23 |
| C3 | 遍历 `find dsh-redblue -name '*.js' -o -name '*.mjs'` 逐个 `node --check` | **0** | 27 个文件（lib 1、workflow 9、tools 2、tools/lib 11、test 4），`checked=27 failures=0` |
| C4 | 契约 smoke 复算（node -e，`recon-captain-*` / `assess-captain-*` 各取最新目录，逐个 artifacts 复算 SHA256） | **0** | `recon-captain- artifacts 7 mismatches 0 status completed exitCode 0`；`assess-captain- artifacts 7 mismatches 0 status completed exitCode 0` |
| C5 | 独立负向/正向沙箱（`%TEMP%\t26-verify\probes.mjs`，node:vm + stub agent） | **0** | 22/22 PASS（17 拒绝 + 5 正向/复核），明细见 §15.3/§15.4 |
| C6 | R1 CLI：`node dsh-redblue/tools/sec.mjs scope check --scope <over-limit.json>` | **1** | `ok=false`、`rejectedBy=["G-CONF-01"]`、2 条 errors（reference 长度 3–200、targets 最多 200） |
| C7 | R1 CLI：`node dsh-redblue/tools/sec.mjs guard --recipe runtime_probe --target app.example.com --scope <over-limit.json> --execute --confirm app.example.com --workdir <tmp>` | **1** | `ok=false`、`rejectedBy=["G-CONF-01"]`；workdir 0 文件（无 evidence 落盘）；进程内 fake-spawn 复核 `spawnCalls=0` |
| C8 | `node dsh-redblue/tools/sec.mjs scope check --scope <boundary-200.json>`（200 字符 reference / 200 targets 边界） | **0** | `ok=true`、`rejectedBy=[]`（边界不误杀） |
| C9 | 指标复算脚本（`%TEMP%\t26-verify\metrics.mjs`，读当前字节） | **0** | 15/9/27/6/10、Jaccard、description、provenance 等，明细见 §15.5 |
| C10 | `test -s dsh-redblue/docs/verification-report.md` | **0** | 追加本章后仍非空（追加前 39,908 B） |

## 15.3 工作流负向独立复跑（node:vm 沙箱，全部 `rejected / exitCode=1 / code=1 / agents=0`）

每个用例均对**当前** `workflow/*.js` 源码重新 `vm.runInNewContext` 加载，调用签名 `(args, phase, log, agent, parallel, pipeline)`，agent 为记录调用的 stub；下表 “agents=0” 指 stub 调用次数为 0（即门禁在任何阶段/任何 agent 之前拒绝）。

| ID | 拒绝类 | 构造（scope/args 关键差异） | workflow | 门禁 | 结果 |
|---|---|---|---|---|---|
| N1 | 缺 scope | 删除 `args.scope` | assess | `G-ARG-01` | rejected/1/0 |
| N2 | 通配目标 | `targets=[{kind:"domain",value:"*.example.com"}]` | assess | `G-TGT-02` | rejected/1/0 |
| N3 | 越界路径（相对 workDir） | `workDir="relative/work"` | assess | `G-PATH-01` | rejected/1/0 |
| N3b | 越界路径（目录穿越） | `workDir="C:/t26/runs/../escape"` | assess | `G-PATH-01` | rejected/1/0 |
| N4 | exclusions 默认端口 | target `https://app.example.com/login`，exclusion `https://app.example.com:443/login` | assess | `G-TGT-04` | rejected/1/0 |
| N5 | exclusions 尾点/大小写 | target `app.example.com`，exclusion `APP.EXAMPLE.COM.` | assess | `G-TGT-04` | rejected/1/0 |
| N6 | mode 不足 | exploit 传入 `scope.mode="active"` | exploit | `G-MODE-02`（同输入另触发 `G-CFM-03`） | rejected/1/0 |
| N7 | 缺 confirm | exploit 删除 `args.confirm` | exploit | `G-CFM-01` | rejected/1/0 |
| N8 | confirm 不符 | exploit `confirm="other.example.com"`（scope 为 app.example.com） | exploit | `G-CFM-02` | rejected/1/0 |
| N9 | activeScan+dryRun 矛盾 | recon `activeScan=true`、`dryRun=true`、mode=passive | recon | `G-MODE-03` | rejected/1/0 |
| N10 | 未知数据源 kind | hunt `dataSources=[{kind:"network",…}]` | hunt | `G-CONF-01` + `G-DS-01` | rejected/1/0 |
| N11 | 超宽 CIDR | `targets=[{kind:"cidr",value:"10.0.0.0/4"}]` | assess | `G-TGT-02` | rejected/1/0 |
| N12 | 授权过期 | `validFrom/validTo=2020-01-01/02` | assess | `G-AUTH-07` | rejected/1/0 |
| N13 | 超限 reference（R1） | `authorization.reference="R"×5000` | assess | `G-CONF-01` | rejected/1/0 |
| N14 | 超限 targets（R1） | 300 个合法 target | assess | `G-CONF-01` | rejected/1/0 |
| N15 | 未声明 args 键 | 注入 `args.unexpectedOption=true` | assess | `G-ARG-01` | rejected/1/0 |
| N16 | 时间窗越界 | window 落在当前时刻之前 | assess | `G-WIN-03` | rejected/1/0 |

覆盖 acceptance 要求的 10 类：缺 scope(N1)、通配(N2)、越界路径(N3/N3b)、exclusions 默认端口(N4)、exclusions 尾点(N5)、mode 不足(N6)、缺 confirm(N7)、confirm 不符(N8)、activeScan(N9)、未知 kind(N10)、超宽 CIDR(N11)；实际执行 17 个拒绝用例，17/17 符合契约。

## 15.4 正向与 R1–R3 复核（同一独立沙箱/CLI）

| ID | 复核项 | 构造与预期 | 实测结果 |
|---|---|---|---|
| P1 | R3 hunt 接受 `pcap` | `dataSources=[{kind:"pcap"}]`，stub agent 完成 plan/report/seal | `status=clean`、`exitCode=0`、`sealed=true`、artifacts 7、agents 11 ✅ |
| P2 | R3 hunt 接受 `cloudtrail` | 同上（`kind:"cloudtrail"`） | `status=clean`、`exitCode=0`、`sealed=true`、artifacts 7 ✅ |
| P3 | R1 scope 上限一致性 | `checkScope` 超限（5000 reference + 300 targets）应拒绝、200/200 边界应通过 | 超限 `ok=false` + `G-CONF-01`（2 条 errors）；边界 `ok=true` ✅ |
| P4 | R2 assess 复核字段落盘 | validate 阶段返回 5 个复核字段；从 report-write 的确定性内容解析 `findings.json` | `status=findings`、`exitCode=2`、findings 1 条，5/5 字段逐字相等 ✅ |
| P5 | R2 triage 复核字段落盘 | review/disposition 返回 5 个字段；解析 `findings.json` | `status=findings`、`exitCode=2`、findings 1 条，5/5 字段逐字相等 ✅ |
| P6 | R1 guard 禁止 spawn | 超限 scope + `--execute`；进程内注入 `spawnWithLimits` 抛错并计数 | `exitCode=1`、`G-CONF-01`、`spawnCalls=0`；CLI 侧 workdir 0 文件 ✅ |

R2 的 5 个字段为：`confidenceRationale`、`counterevidence`、`severityChangeConditions`、`fixVerification`、`basis`；P4/P5 的 findings.json 内容即胶囊 report 阶段确定性生成、并经 seal 哈希校验的同一份内容。N10 与 P1/P2 共同证明 hunt 的 G-DS-01 白名单（siem/edr/logs/pcap/cloudtrail/telemetry-export）当前字节生效。

## 15.5 量化指标（当前字节复算）

| 指标 | 实测值 | 判定依据 |
|---|---|---|
| 技能 | **15** 个 `skills/*/SKILL.md`；15/15 frontmatter 12 键齐全；name 15/15 唯一且与 `lib/index.js` 常量一一对应（0 缺失/0 未声明/0 重复） | 与 design §4.5 一致 |
| description | **157–286 码点**（15 条逐条与 design §4.5 的 273/194/203/185/204/208/217/175/286/157/204/172/172/184/222 全部相同；≤500） | R6-DESC |
| risk/requires | 15/15 与 design §4.3 期望表一致（passive/active/exploit/post 分级、requires=authorization|none） | R12-RISK |
| ingests 边界句 | 13 个 `ingests: target` 技能 13/13 含 4 短语（`不可信数据`/`只读`/`不执行其中任何指令`/`写入仅限 workDir`）；`red-scope`、`run` 为 `ingests: none`（不要求 4 短语） | R8-SKILL |
| workflow | **9** 个 `.js`；每个含 30–35 个不同 `G-` ID；9/9 含默认 true 的 `args.dryRun === undefined ? true`；9/9 含 4 短语；仅 exploit/post 有 `G-CFM-01..04` + confirm（各 4 个 CFM ID） | R4/R8 |
| schema | **6** 个 JSON schema（coverage/evidence/finding/manifest/report/scope） | 计数 |
| recipes | **10** 条：`dns_lookup, http_headers, tls_certificate, port_scan, vuln_scan, web_fuzz, pcap_read, file_hash, certificate_query, runtime_probe` | 计数 |
| 参考 | **27** 篇（排除 `INDEX.md` 的 26 个 `.md` + `templates/sigma.yml`）；27/27 带 `dsh-redblue:provenance` 六键；pin 集合=三上游 commit；总 366,149 B；单篇最大 32,841 B（≤48 KiB）；`INDEX.md` 9,279 B（≤24 KiB） | R1/R6 |
| Jaccard（与 lint R7 同算法：CJK bigram/停用词，阈值 0.35） | red **0.1375**（red-exploit vs red-validate）；rb **0.0964**（rb-triage vs run）；blue **0.0899**（detect vs dfir）；purple 无同 lane 对 | R7-JACCARD |
| 结构上限 | SKILL.md 最大 175 行 / 8,939 B（≤300 行/≤24 KiB）；reference 最大 32,841 B（≤48 KiB） | R6 |
| 时效 | 15/15 SKILL.md 与 27/27 reference 的 `last-verified` 均为 **2026-11-19**（距复验 1 天，≤180 天） | R9 |
| 卫生 | 插件内 `.py` **0**、`.log` **0**、`node_modules` 条目 **0** | 全树遍历 |

## 15.6 E2E 证据只读复核（未重跑真实 workflow）

| 运行 | 目录 | artifacts | mismatch | status | exitCode | dryRun | mode | workflow |
|---|---|---|---|---|---|---|---|---|
| recon | `.work/smoke/recon-captain-20261119-2105` | 7 | **0** | completed | 0 | true | passive | recon |
| assess | `.work/smoke/assess-captain-20261119-2115` | 7 | **0** | completed | 0 | true | passive | assess |

- 合计 **14/14** artifact 哈希按 manifest 逐文件复算一致（含 `findings.json`、`coverage.json`、`report.md`、`exports/results.sarif`、`scope.json`、`recon.json`/`surface.json`）。
- 两段 workDir 的 5 件公共产物（`findings.json`、`coverage.json`、`report.md`、`exports/results.sarif`、`scan-manifest.json`）均存在且非空（5/5 + 5/5）。
- 两段 workDir 的 `scope.json` 实际目标仅 `domain:app.example.com`、`exclusions=[]`、`counts.reportable=0`；manifest `scopeDigest` 与 `scope.json` 的 SHA256 一致（均为 `d6eda1c1…`），且 `upstreamCommits` 三 pin 与 NOTICE 一致。
- 证据目录内 40 处 URL 的 host 仅 `app.example.com`、`dsh.local`（schema `$id`）、`json.schemastore.org`（schema 元数据），无第三方目标；未新增任何发包/工具执行记录。

## 15.7 R1–R12 判定表（当前字节）

| 规则 | 判定 | 本轮证据 |
|---|---|---|
| R1 来源与许可 | PASS | lint R1-*（PROVENANCE/NOTICE/LICENSE）0 finding；15 技能 6 键 provenance 全在；27 参考 6 键齐全；NOTICE 含三 repo/三 commit/Modifications/MIT 全文/Apache-2.0，`LICENSE` 为 Apache-2.0 全文，`package.json license=Apache-2.0`；INDEX 三 pin 齐全 |
| R2 占位符净化 | PASS | lint R2-*（5 项）0 finding；smoke 证据 host 仅保留域/`dsh.local`/schema 权威域 |
| R3 无武器化制品 | PASS | lint R3-*（WEAPON/DESTRUCTIVE/AUTH-BANNER）0 finding |
| R4 授权门禁与安全默认 | PASS | 9 workflow 均 30+ 个 G- 门禁、dryRun 默认 true、无通配目标（lint R4-* 0）；confirm 仅 exploit/post（各 4 个 CFM）；负向 N1–N16 全部执行前拒绝 |
| R5 不制造虚假内容 | PASS | lint R5-*（FAKE/METRIC/CVE）0 finding；E2E/参考无伪造声明（抽样复核） |
| R6 结构上限 | PASS | 15 SKILL.md ≤175 行/≤8,939 B；description ≤286 码点；27 参考 ≤32,841 B；INDEX 9,279 B |
| R7 去重与触发隔离 | PASS | 15 name 唯一且与 lib 常量一致；同 lane Jaccard 最大 0.1375 ≤0.35；lint R7-NEGATIVE 0（每条含触发词/不适用+兄弟技能） |
| R8 提示注入防御 | PASS | 13/13 `ingests: target` 技能含 4 短语；9/9 workflow 含 4 短语（lint R8-* 0） |
| R9 时效标注 | PASS | 42 个对象（15 技能 + 27 参考）`last-verified` 均 2026-11-19（1 天）；lint R9-* 0（无 warning/blocker） |
| R10 机密与隐私 | PASS | lint R10-*（SECRET/PII/INTERNAL-HOST）0 finding |
| R11 语言与术语（warning） | PASS（2 warning 已受理） | 仅 `purple-verify`、`red-exploit` 各 1 条 R11-TERMINOLOGY；由 design §4.2 固定 description 触发，assembly-report §4 已受理，发布门禁仍 0 blocker |
| R12 风险分级与安全默认 | PASS | 15/15 risk/requires 与 design §4.3 一致；exploit/post confirm 门禁；report-only 默认（dryRun=true）；lint R12-* 0 |

## 15.8 非阻塞观察（不影响 0 blocker 判定）

- **O-1（low，文档漂移）**：`docs/design.md` §5.1/§11 仍写 “17 篇派生参考 + INDEX（共 18 个文件）”，当前交付为 27 篇 + INDEX（28 个文件）；README/DETAIL/INDEX 均按 27 篇陈述。design 属冻结范围（out-of-scope），不影响门禁与交付事实。
- **O-2（low，文档漂移）**：design §5.2 写 “单次加载 ≤3 篇”，t6 收紧后的 INDEX/README 写 “每阶段最多 2 篇、合计 ≤120 KiB”；冻结 design 未同步收紧值。
- **O-3（low，设计期数值）**：design §4.4 与 `docs/sanitization-rules.md:443` 记录的 Jaccard 设计期值（red 0.130 / rb 0.090 / blue 0.099）与当前字节复算值（0.1375 / 0.0964 / 0.0899）相差 ≤0.008，系 description 措辞后续修订所致；距 0.35 阈值仍充裕，R7 门禁通过。
- **O-4（low，已受理）**：R11 两条 warning 属 design 固定 description 与 `findings` 字段名冲突，assembly-report §4 已受理并指定责任人；本轮未扩大、未新增 warning。

## 15.9 Blocking 缺陷清单

**空（0 blocker）。** 本轮未发现：门禁绕过（负向 17/17 拒绝且 0 agent）、越界写入（workdir 0 文件/相对路径拒绝）、真实目标或凭据、武器化制品、哈希/封存不一致、指标与 design §4.3/§4.5 不符、E2E manifest mismatch。

## 15.10 总体判定与改动声明

**PASS。** 依据：C1–C10 中除 C6/C7 为预期拒绝（exit 1）外全部 exit 0，4 个测试文件 98/98、27/27 `node --check`、87 文件 strict lint 0 blocker（仅 2 条已受理 R11）、17/17 负向 + 5/5 正向复核、27 参考/10 recipes/15 技能/9 workflow/6 schema 指标与 design 对齐、E2E 14/14 零 mismatch；O-1..O-4 均非阻塞且不改变安全语义。

改动声明：
- 仅追加修改 `dsh-redblue/docs/verification-report.md`（本部分）；未改 `lib/`、`skills/`、`references/`、`workflow/`、`tools/`、`test/`、`schema/`、`policy/`、`package.json`、`README.md`、其它 `docs/`、`.work/**`、`dsh-security/`。
- 临时验证脚本仅在 `%TEMP%\t26-verify\`（probes/metrics/compliance/guard-spawn/debug 脚本与 over-limit/boundary scope JSON），不属于插件；`.work/smoke/**` 仅读取，未写入。
- 未发起网络请求、未运行白名单配方、未重跑真实 workflow；负向与正向均为 stub-agent 沙箱行为。

---

# 第 4 部分：t30 修复增量验证（t31 / verification-round-3）

> 独立验证者：verifier2（未参与 t30 实现）；时间：2026-11-20（UTC+8）；对象：**t30 完成后的当前工作树字节**。只读被验证文件，仅追加本文件；数字均为本轮重新执行/重新计算所得。

## 16. 结论摘要

| 项 | 结果 |
|---|---|
| 总体判定 | **PASS（0 blocker）** |
| t30 修复有效性 | `workflow/hunt.js:1462` scope 阶段目录为 **`run`**；`workflow/*.js` 中 `rb-run` **0** 处；`skills/rb-run` 不存在、`skills/run/SKILL.md` 8,889 B 存在；功能探针 scope prompt 指向 `.../skills/run/SKILL.md`，全部 prompt 无 `rb-run` |
| 阶段目录审计 | 9 个 workflow 共提取 **32 个 stage 调用 + 18 个 prompt 目录引用**，并集 **14 个目录**，逐个 `skills/<dir>/SKILL.md` 存在且非空（missing **0**） |
| 回归 | 9/9 workflow `node --check` exit 0；workflow 测试 **43/43**（含新增用例）；4 文件 **99/99**；lint **87 文件 / 0 blocker / 2 条既有 R11**，exit 0 |
| 改动面 | t30 时间窗（t28 完成之后）仅 **2** 个文件变化：`workflow/hunt.js`、`test/workflow.test.mjs`；t30 完成后至今 **0** 个；team 元数据 `t30.changedPaths` 与之一致 |
| G-* 门禁未弱化 | 9 份 `validateScopeLimits`（limits/G-CONF-01）段哈希全同为 `54f3f88b…`；hunt 共享核与其 6 个未改动的非 confirm workflow 逐字节同哈希 `1dafdeaa…`；hunt 仍 31 个不同 G- ID（与 t26 记录一致），G-DS-01/G-CONF-01/G-MODE-03 在、无 G-CFM |
| Blocking | **空（0）**；非阻塞观察 O-1 见 §16.8 |

## 16.1 环境

| 项 | 值 |
|---|---|
| 主机/运行时 | Windows x64；Node **v24.22.1**（`process.platform=win32`） |
| 工作树 | `C:\dsh-workspace\branch1`；插件 `dsh-redblue` 0.1.0；插件根文件 **118** 个（t27 时为 116，t28 新增 2 个架构 SVG） |
| 时间 | 本轮执行 2026-11-20T02:2xZ（UTC+8 10:2x）；t27 完成 01:58:39Z、t28 完成 02:17:24Z、t30 完成 02:22:30Z |
| 证据限制 | 未重跑真实 workflow/未发包/未运行白名单配方；未改 `.work/`；t30 相关临时脚本在 `%TEMP%\t31-verify\`（stage-audit / gate-parity / hunt-functional / change-surface），不属于插件 |

## 16.2 命令表（本轮实际执行）

| # | 命令 | 退出码 | 关键证据 |
|---|---|---|---|
| C1 | `for f in dsh-redblue/workflow/*.js; do node --check "$f" \|\| exit 1; done` | **0** | 9/9 workflow 语法通过 |
| C2 | `node --test dsh-redblue/test/workflow.test.mjs` | **0** | `ℹ tests 43 / pass 43 / fail 0`；含 `✔ every workflow stage skill directory exists under skills/`（新增用例） |
| C3 | `node --test dsh-redblue/test/scaffold.test.mjs dsh-redblue/test/sanitize.test.mjs dsh-redblue/test/workflow.test.mjs dsh-redblue/test/tool-runtime.test.mjs` | **0** | `ℹ tests 99 / pass 99 / fail 0`；逐文件 scaffold 9、sanitize 24、workflow 43、tool-runtime 23 |
| C4 | `node dsh-redblue/tools/sanitize-lint.mjs --strict --json dsh-redblue` | **0** | `checkedFiles=87`、`blockers=0`、`warnings=2`（仅 `skills/purple-verify/SKILL.md:3`、`skills/red-exploit/SKILL.md:3` 的 R11，assembly-report §4 已受理） |
| C5 | `node %TEMP%\t31-verify\stage-audit.mjs` | **0** | 32 stage 调用 / 18 prompt 引用 / 14 唯一目录 / missing 0；hunt scope=`run`；`rb-run` 在 workflow 下 0 |
| C6 | `node %TEMP%\t31-verify\gate-parity.mjs` | **0** | limits 段 9/9 同哈希；非 confirm 7 个共享核同哈希、exploit/post 同哈希；hunt 31 个 G- ID、无 G-CFM |
| C7 | `node %TEMP%\t31-verify\hunt-functional.mjs` | **0** | `status=clean/exitCode=0/sealed=true/artifacts=7/agents=11`；scope prompt 含 `/skills/run/SKILL.md`、无 `rb-run` |
| C8 | `node %TEMP%\t31-verify\change-surface.mjs` | **0** | 118 文件；t27 后 5 个（3 个属 t28 + 2 个属 t30）；t28 后仅 2 个；t30 后 0 个；team 元数据一致 |

## 16.3 阶段技能目录审计（独立提取，非复用新增测试）

提取规则：`runStage/runFanout(ctx, "<stage>", "<dir>"` 字面量 + 阶段 prompt 中 `ctx.skillDir + "/<dir>/SKILL.md…"` 引用；对每个目录断言 `skills/<dir>/SKILL.md` 存在且字节数 >0。

| workflow | stage→dir（按出现顺序） | prompt 目录引用 | 唯一目录 | missing |
|---|---|---|---|---|
| assess | scope→red-scope, recon→red-recon, surface→red-surface, discover→red-discover, validate→red-validate | 2（rb-report） | 6 | 0 |
| recon | scope→red-scope, recon→red-recon, surface→red-surface | 2（rb-report） | 4 | 0 |
| exploit | scope→red-scope, validate→red-validate, exploit→red-exploit | 2（rb-report） | 4 | 0 |
| post | scope→red-scope, post→red-post | 2（rb-report） | 3 | 0 |
| **hunt** | **scope→run**, hunt→blue-hunt, hunt→blue-hunt | 2（rb-report） | 3 | 0 |
| ir | intake→dfir, triage→dfir, timeline→dfir, containment→dfir | 2（rb-report） | 2 | 0 |
| purple | redActions→purple-verify, detectCoverage→purple-verify, gaps→purple-verify | 2（rb-report） | 2 | 0 |
| triage | finding→rb-triage, review→rb-triage, disposition→rb-triage, write→rb-triage | 2（rb-report） | 2 | 0 |
| harden | baseline→harden, check→harden, gaps→harden, remediation→harden, verify→harden | 2（rb-report） | 2 | 0 |

- 合计 **32 个 stage 调用 / 18 个 prompt 引用 / 14 个唯一目录**，`missing=[]`。
- 并集 14 个目录：`blue-hunt, dfir, harden, purple-verify, rb-report, rb-triage, red-discover, red-exploit, red-post, red-recon, red-scope, red-surface, red-validate, run`；每个 `skills/<dir>/SKILL.md` 均存在且非空。
- **hunt scope = `run`**（`runStage(ctx, "scope", "run", [`，`workflow/hunt.js:1462`）；`workflow/*.js` 中 `rb-run` 出现 **0** 次；`skills/rb-run/` 不存在；`skills/run/SKILL.md` 8,889 B（15 个技能目录之一）。
- 功能探针（node:vm + stub agent 跑 hunt/pcap）：`status=clean`、`exitCode=0`、`sealed=true`、artifacts 7、agent 11；scope 阶段 prompt 含 `/skills/run/SKILL.md`，任何阶段 prompt 均不含 `rb-run` —— 证明修复在运行期生效，而非仅改注释。

## 16.4 G-* 门禁语义/顺序未弱化

| 证据 | 结果 |
|---|---|
| limits 段（`validateScopeLimits`，R1/G-CONF-01） | 9/9 文件同一 SHA256 `54f3f88bbc8623ebeb2da558cdb854465c0e0c1f0b9b7c5437c251511e6fd178`（与 t27 记录的前缀 `54f3f88b…` 一致） |
| 共享核（`return (async () => {` 至各 workflow 专属段前，含 preflight/G-* 检查/finalize） | 非 confirm 7 个（assess/recon/**hunt**/ir/purple/triage/harden）同哈希 `1dafdeaa92d4f8c05c4238e34e188c3924d68d420f10d914cd7d5e7cfbdf37fe`；exploit/post 同哈希 `b668e1ffde03287ff859341edd207f9aca7f901c51524c114e2949e511403528`（两组差异仅为 design 要求的 G-CFM confirm 段）；**hunt 与 6 个未改动 workflow 逐字节相同** |
| preflight 函数段 | 非 confirm 组同哈希 `2f0eb40b…`；confirm 组同哈希 `81bf1fa2…`（exploit/post 的 confirm 门禁为既有设计，t30 未动） |
| 不同 G- ID 数 | assess 30、recon 30、exploit 35、post 34、hunt **31**、ir 31、purple 31、triage 31、harden 30（与 t26 记录的 30–35、hunt 31 一致） |
| hunt 门禁覆盖 | 含 `G-DS-01`、`G-CONF-01`、`G-MODE-03`；不含 `G-CFM-`（hunt 无 confirm 门禁，符合设计） |

结论：t30 的唯一功能改动位于 workflow 专属阶段流（scope 技能目录字面量），hunt 的共享门禁核与 6 个未改动 workflow 逐字节相同，且门禁数量/ID 未变——**未弱化任何 G-* 门禁**。

## 16.5 改动面审计（mtime + SHA256 + team 元数据）

| 文件 | mtime（UTC） | bytes | SHA256 |
|---|---|---|---|
| `workflow/hunt.js` | 2026-11-20T02:19:10.271Z | 74,285 | `1d3222876e694ff958aeff0957658a9b53d83ec8886cfdd1f420227d1cc83529` |
| `test/workflow.test.mjs` | 2026-11-20T02:22:06.382Z | 71,378 | `786ef688300196d6d1b8f08db56762184a99cac5cee8f915b9d51dbfe844086e` |

- 插件根 118 文件全量 mtime 扫描：
  - 自 t27 完成（01:58:39Z）后变化 5 个 = t28 的 3 个架构图文件（`docs/architecture.md` 02:15:29Z、`docs/architecture-plugin.svg` / `docs/architecture-workflow.svg` 02:16:33Z） + **t30 的 2 个文件**；
  - 自 t28 完成（02:17:24Z，即 t30 时间窗）后变化 **仅 2 个**：`workflow/hunt.js`、`test/workflow.test.mjs`；
  - 自 t30 完成（02:22:30Z）后变化 **0 个**。
- 只读核对 `.agent-teams/dsh-redblue/team.json`：`t28.changedPaths` = 3 个架构图文件；`t30.changedPaths` = `dsh-redblue/workflow/hunt.js`、`dsh-redblue/test/workflow.test.mjs` —— 与 mtime/SHA256 审计一致；3 个架构图文件的 mtime 均早于 t30 首个改动（02:19:10Z），**不属 t30 改动面**。
- 结论：t30 实际改动面 = `workflow/hunt.js` + `test/workflow.test.mjs` 两个文件；其余 116 个文件 mtime 早于 t28 完成时刻。注：本报告追加后 `docs/verification-report.md` 的 mtime 会更新（属本报告自身），t30 完成到审计时刻之间无其他变化。

## 16.6 回归结果（当前字节）

| 命令 | 退出码 | 结果 |
|---|---|---|
| 9 个 workflow `node --check` | 0 | 9/9 通过 |
| `node --test test/workflow.test.mjs` | 0 | 43/43；新增用例名 `every workflow stage skill directory exists under skills/`（test/workflow.test.mjs:838）通过 |
| 4 个显式测试文件 | 0 | 99/99（scaffold 9、sanitize 24、workflow 43、tool-runtime 23） |
| `sanitize-lint --strict --json` | 0 | 87 文件、0 blocker、2 warning（R11 既有两处，assembly-report §4 受理） |

## 16.7 新测试内容复核

`test/workflow.test.mjs:838` 的用例（:838–865）实际断言：正则提取 9 个 workflow 的 `runStage/runFanout` 技能目录字面量（每个 workflow ≥2）与 prompt 级 `skillDir + "/<dir>/SKILL.md"`；`stageDirs.size ≥13`、`promptDirs.size ≥1`；显式要求 `run/rb-report/rb-triage/blue-hunt/purple-verify` 至少被引用一次；对 `usedBy` 中每个目录断言 `skills/<dir>/SKILL.md` 存在且 `.trim().length > 0`。当前字节下该用例通过（43/43）。

## 16.8 非阻塞观察

- **O-1（low，报告与字节不一致）**：t30 完成说明含“反向验证：合成 `runStage(ctx, "scope", "rb-run", ...)` 能被提取且存在性检查为 false”。但当前 `test/workflow.test.mjs` 中 `rb-run` 出现 **0** 次（`grep -c "rb-run" test/workflow.test.mjs` → 0），新增用例（:838–865）只做正向存在性断言与覆盖下限，没有该合成负例。影响：当前所有被引用目录均被覆盖，回归能拦截“引用不存在的目录”；缺口是不能自检提取正则失效（例如语法变化导致提取为空时，靠 `stageDirs.size ≥13` 与显式目录要求兜底）。不改变 t30 修复的功能正确性，也不弱化门禁。建议（非本轮 in-scope）：在新增用例中补 1 条合成负例或断言 `usedBy` 覆盖预期目录集合。
- 说明：t30 说明中的“mtime 审计确认仅 2 文件”在 t30 自身时间窗内成立；全树自 t27 起的 5 文件变化已在上表拆分归属（3 个属 t28）。

## 16.9 Blocking 缺陷清单

**空（0 blocker）。** 未发现：hunt scope 仍指向 `rb-run`、任一 workflow 阶段技能目录缺失、`rb-run` 残留、G-* 门禁数量/顺序弱化、回归测试失败、lint blocker 回退、t30 之外的未声明改动。

## 16.10 总体判定与改动声明

**PASS。** 依据：t30 修复在当前字节生效（静态 0 残留 + 功能探针 prompt 指向 `skills/run/SKILL.md`）；32 个 stage 调用 + 18 个 prompt 引用 → 14 个技能目录全部存在；9/9 workflow 语法通过、workflow 43/43、4 文件 99/99、lint 87/0/2；改动面经 mtime/SHA256/team 元数据三方一致确认仅 `workflow/hunt.js` 与 `test/workflow.test.mjs`；G-* 门禁共享核与未改动 workflow 逐字节一致。O-1 为测试自检缺口，非阻塞。

改动声明：
- 仅追加修改 `dsh-redblue/docs/verification-report.md`（本部分）；未改 `lib/`、`skills/`、`references/`、`workflow/`、`tools/`、`test/`、`schema/`、`policy/`、`package.json`、`README.md`、其它 `docs/`、`.work/**`、`dsh-security/`。
- 临时验证脚本仅在 `%TEMP%\t31-verify\`（stage-audit / gate-parity / hunt-functional / change-surface / debug），不属于插件；`.work/**` 仅读取，未写入。
- 未发起网络请求、未运行白名单配方、未重跑真实 workflow；hunt 功能探针为 stub-agent 沙箱（写入仅发生在内存中的 report-write 回执）。
