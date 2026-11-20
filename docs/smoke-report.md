# dsh-redblue assess 端到端 smoke 报告

- 日期：2026-11-19（Asia/Shanghai）
- 执行者：verifier（AgentTeams member "verifier" / 子代理 agent-5，attempt `a909fc58-0654-4019-9e1e-35d632bb1817`，task t12）
- 被测对象：`dsh-redblue/workflow/assess.js`（64,747 B，SHA256 `870df9ee970018a36cb0f165f550876b00213172a513286ebb9deba91ae66957`）
- 执行面：**DSH 原生 `workflow` 工具**（非 node:vm、非 mock、非 dsh CLI）
- **结论：未通过。** 正向 assess 在真实原生工具中完成了脚本解析与全部门禁校验，但在进入第一个阶段（`scope`）时，宿主的 AgentTeams 子代理派发上限（本成员剩余额度 0）拒绝启动任何 stage agent，`failedStage=stage scope`，未产出任何产物；负向（缺 scope）链路在真实工具中通过（`status=rejected`、`exitCode=1`、`rejectedBy=["G-ARG-01"]`、`0 agents`）。**因此本报告不能证明“门禁→阶段→报告→封存”端到端可用**，需由具备派发额度的会话重跑。

## 1. 环境

| 项 | 值 |
|---|---|
| OS / Shell | Windows（win32 x64），MSYS Bash（`/c/dsh-workspace/branch1`） |
| 工作区 | `C:/dsh-workspace/branch1`（非 git work tree） |
| DSH 桌面版 | 0.2.2-rc.5（`runtime/primary-runtime/runtime.json` 的 `desktopVersion`）；Node `v24.22.1`（会话 shell） |
| 会话角色 | AgentTeams 成员 `verifier`（子代理 agent-5，parent=lead）；`subagent`/`subagent_fork` 委派深度 1/1，**剩余 0** |
| 原生 `workflow` 工具 | **存在**（本会话工具面可见并可调用） |
| 调用时间 | 2026-11-19 16:13–16:20 +08:00；授权/窗口 `validFrom=validTo=2026-11-19`，window `2026-11-19T00:00:00+08:00 → 23:59:59+08:00`（运行时刻在窗口内） |

## 2. 工具面自检（执行前）

读取 `dsh-redblue/workflow/assess.js` 全文（1,343 行）并原样提交给原生 `workflow` 工具。提交前用 4 次探针确认工具面契约：

| 探针 | 结果 |
|---|---|
| P1 `meta{name,description,phases}` + 顶层 `return (async()=>{...})()` | 通过：工具会 await 返回值，`phase("probe")` 可用，`args` 原样注入 |
| P2 `script: "@C:/.../assess.js"` | 失败：`workflow script does not parse: SyntaxError: Invalid or unexpected token` → **不支持 @file / 脚本路径引用**，脚本必须逐字内联提交 |
| P3 宿主全局 | 仅 `agent / args / log / parallel / phase / pipeline`；`require / process / module` 均为 `undefined`（脚本内不可能读文件或绕开内联） |
| P4 子代理派发 | **失败**，见 §6（这是本次正向失败的唯一原因） |

产物落盘目录先创建：`C:/dsh-workspace/branch1/.work/smoke/assess-20261119-1610`（正向）、`.work/smoke/neg-20261119-1610`（负向）。

## 3. 正向 smoke（真实工具调用）

### 3.1 调用参数

`meta`：

```json
{
  "name": "dsh-rb-smoke-assess",
  "description": "dsh-redblue assess dry-run end-to-end smoke: native workflow tool executes the shipped assess.js capsule against an RFC-reserved domain with maxConcurrency=1 and zero target-side action.",
  "phases": [
    { "title": "scope", "detail": "authorization and scope normalization, write scope.json" },
    { "title": "recon", "detail": "passive/offline only" },
    { "title": "surface", "detail": "threat hypotheses from collected assets" },
    { "title": "discover", "detail": "8 category fanout, sequential maxConcurrency=1" },
    { "title": "validate", "detail": "independent re-validation of candidates" },
    { "title": "report", "detail": "deterministic artifact generation + verbatim write" },
    { "title": "seal", "detail": "recompute SHA256 and write scan-manifest.json" }
  ]
}
```

`args`（scope 为任务书给定的 smoke scope，target 仅 RFC 保留域 `app.example.com`）：

```json
{
  "scope": {
    "authorization": {
      "type": "written",
      "reference": "SMOKE-2026-11-19",
      "grantedBy": "captain (smoke)",
      "validFrom": "2026-11-19",
      "validTo": "2026-11-19",
      "document": "smoke"
    },
    "targets": [{ "kind": "domain", "value": "app.example.com" }],
    "mode": "passive",
    "window": { "start": "2026-11-19T00:00:00+08:00", "end": "2026-11-19T23:59:59+08:00" },
    "budget": { "maxRequests": 1, "maxMinutes": 30 },
    "dataHandling": { "retain": "findings-only", "secrets": "mask-and-redact", "destruction": "none" }
  },
  "workDir": "C:/dsh-workspace/branch1/.work/smoke/assess-20261119-1610",
  "skillDir": "C:/dsh-workspace/branch1/dsh-redblue/skills",
  "maxConcurrency": 1,
  "dryRun": true
}
```

`script`：`workflow/assess.js` 全文逐字内联（`return (async () => { ... })();`）。工具以 `run_in_background: true` 调用，后台 job id `workflow-89c7573f51b149cc`。

### 3.2 原始返回（逐字，来自 job_output）

```json
{
  "ok": false,
  "status": "error",
  "exitCode": 1,
  "code": 1,
  "error": "stage scope failed: agent 调用失败: agent() could not start a child: Error: AgentTeams member delegation limit (0) reached; report to the captain instead of spawning another agent\n    at bindingFailure (file:///C:/Users/chengyx/AppData/Local/Programs/DeepSeek%20Harness/resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-ptc-runtime-node/lib/process.js:1074:60)\n    at Object.value [as startChild] (file:///C:/Users/chengyx/AppData/Local/Programs/DeepSeek%20Harness/resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-ptc-runtime-node/lib/process.js:1102:12)\n    at process.processTicksAndRejections (node:internal/process/task_queues:104:5)\n    at async Object.startAgent (dsh-workflow-guest.js:1007:31)\n    at async WorkflowExecution.agent (dsh-workflow-guest.js:794:11)",
  "failedStage": "scope",
  "workflow": "assess",
  "runId": "rb_20261119T081634Z_e4d2",
  "workDir": "C:/dsh-workspace/branch1/.work/smoke/assess-20261119-1610",
  "mode": "passive",
  "dryRun": true,
  "rejectedBy": [],
  "errors": [
    {
      "stage": "scope",
      "message": "agent 调用失败: agent() could not start a child: Error: AgentTeams member delegation limit (0) reached; report to the captain instead of spawning another agent\n    at bindingFailure (file:///C:/Users/chengyx/AppData/Local/Programs/DeepSeek%20Harness/resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-ptc-runtime-node/lib/process.js:1074:60)\n    at Object.value [as startChild] (file:///C:/Users/chengyx/AppData/Local/Programs/DeepSeek%20Harness/resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-ptc-runtime-node/lib/process.js:1102:12)\n    at process.processTicksAndRejections (node:internal/process/task_queues:104:5)\n    at async Object.startAgent (dsh-workflow-guest.js:1007:31)\n    at async WorkflowExecution.agent (dsh-workflow-guest.js:794:11)"
    }
  ],
  "warnings": [],
  "counts": { "candidates": 0, "reportable": 0, "bySeverity": { "critical": 0, "high": 0, "medium": 0, "low": 0 } },
  "artifacts": [],
  "sealed": false
}
```

- 工具运行记录：`workflow "dsh-rb-smoke-assess" completed (1 agent)`。
- 耗时：`runId` 时间戳 `2026-11-19T08:16:34Z`（=16:16:34+08:00），首个 `agent()` 派发被拒后立即返回（秒级）。
- 退出码：`exitCode=1`（`status=error`，非门禁拒绝）。

### 3.3 结果解读（能证明什么 / 不能证明什么）

**已验证通过（真实工具内）**

1. 64,747 B 胶囊被原生 `workflow` 工具成功解析并执行（无语法错误）。
2. 授权门禁 `preflight` 全量通过：返回 `rejectedBy=[]`、`mode="passive"`、`dryRun=true`、`workDir` 正确回显，证明 scope/授权有效期/窗口/预算/dataHandling/mode/目标保留域等 G-* 校验在该输入下全部放行。
3. 阶段机进入 `phase("scope")` 并在 `runStage` 内构造 prompt、调用 `agent()` —— 即“门禁→阶段”衔接真实生效。
4. 失败被 `stageErrorResult` 正确归类为 `status=error` + `failedStage="scope"` + `exitCode=1`，错误可诊断。

**未能验证（被环境阻断）**

1. `scope` 及后续 `recon → surface → discover → validate → report → seal` 七个阶段全部未执行（首个 `agent()` 即被拒）。
2. 5 件公共产物（`findings.json`/`coverage.json`/`report.md`/`exports/results.sarif`/`scan-manifest.json`）**均未生成**；`workDir` 为空（0 个文件）。
3. `scan-manifest.json` 的 artifacts 哈希复算（findings/coverage/report/sarif 四件）**无法进行**——manifest 不存在。
4. `report.md` 必需章节、`findings.json` 字段/schema 无法核验。

## 4. 负向 smoke（同脚本、新 workDir、不传 scope）

- `meta.name` = `dsh-rb-smoke-assess-noscope`；`script` 与正向**逐字相同**（同一胶囊文本）。
- `args`（无 `scope`）：

```json
{
  "workDir": "C:/dsh-workspace/branch1/.work/smoke/neg-20261119-1610",
  "skillDir": "C:/dsh-workspace/branch1/dsh-redblue/skills",
  "maxConcurrency": 1,
  "dryRun": true
}
```

- 后台 job id `workflow-1fab35aa192c4e3d`；工具运行记录：`workflow "dsh-rb-smoke-assess-noscope" completed (0 agents)`。
- 原始返回（逐字）：

```json
{
  "ok": false,
  "status": "rejected",
  "exitCode": 1,
  "code": 1,
  "error": "G-ARG-01: scope 必须是对象",
  "workflow": "assess",
  "runId": "rb_20261119T082024Z_2b1d",
  "workDir": "C:/dsh-workspace/branch1/.work/smoke/neg-20261119-1610",
  "mode": "",
  "dryRun": true,
  "rejectedBy": ["G-ARG-01"],
  "errors": [{ "gate": "G-ARG-01", "message": "scope 必须是对象" }],
  "warnings": [],
  "counts": { "candidates": 0, "reportable": 0, "bySeverity": { "critical": 0, "high": 0, "medium": 0, "low": 0 } },
  "artifacts": [],
  "sealed": false
}
```

判定（对照任务期望）：

| 期望 | 实测 | 结果 |
|---|---|---|
| `status=rejected` | `rejected` | ✅ |
| `exitCode=1` | `1` | ✅ |
| `rejectedBy` 非空 | `["G-ARG-01"]` | ✅ |
| 0 agents | 工具记录 `(0 agents)` | ✅ |
| 不写任何产物 | `artifacts=[]`，`neg-20261119-1610/` 0 文件 | ✅ |

负向链路在真实原生工具中完全通过：缺 scope 在**任何 agent 之前**被 `G-ARG-01` 拒绝，未进入任何 stage。

## 5. 产物清单与 SHA256

| 产物 | 正向 | 负向 |
|---|---|---|
| `findings.json` | 未生成 | 不适用（拒绝） |
| `coverage.json` | 未生成 | 不适用 |
| `report.md` | 未生成 | 不适用 |
| `exports/results.sarif` | 未生成 | 不适用 |
| `scan-manifest.json` | 未生成 | 不适用 |
| `scope.json`/`recon.json`/`surface.json` | 未生成 | 不适用 |

- `.work/smoke/assess-20261119-1610/`：0 个文件。
- `.work/smoke/neg-20261119-1610/`：0 个文件。
- 因正向未进入 `finalize()`，脚本的确定性产物与 `sha256Hex` 期望值未产生；**本报告不提供任何 SHA256 复算结论**（无文件可算，宁缺勿造）。

## 6. 根因与最小复现（可诊断）

失败阶段：`scope`（`failedStage="scope"`）。原因（逐字）：`AgentTeams member delegation limit (0) reached; report to the captain instead of spawning another agent`。

最小复现（与胶囊无关，纯工具面探针，0 依赖）：

```js
phase("probe");
try { await agent("Reply with the single JSON object {\"ok\":true}.", { label: "probe-child", phase: "probe" }); }
catch (e) { return { started: false, error: String(e && e.message ? e.message : e) }; }
```

实测返回（同样被拒）：

```json
{
  "outcome": {
    "started": false,
    "error": "agent() could not start a child: Error: AgentTeams member delegation limit (0) reached; report to the captain instead of spawning another agent\n    at bindingFailure (.../dsh-ptc-runtime-node/lib/process.js:1074:60)\n    at Object.value [as startChild] (.../dsh-ptc-runtime-node/lib/process.js:1102:12)\n    at process.processTicksAndRejections (node:internal/process/task_queues:104:5)\n    at async Object.startAgent (dsh-workflow-guest.js:1007:31)\n    at async WorkflowExecution.agent (dsh-workflow-guest.js:794:11)"
  }
}
```

结论：**本会话（AgentTeams worker member，委派深度 1/1 已用尽）无法为 `workflow` 派发任何子代理**；`workflow` 工具本身可用（脚本解析、`phase()`、`args`、返回值、后台 job 均正常），受阻点仅在 `agent()` 的宿主派发授权。该限制与 `assess.js` 内容无关，重试同一调用不会改变结果（未做无意义重试）。

## 7. 结论

1. **未通过**：交付要求的正向端到端 smoke（门禁→阶段→5 件产物→manifest 哈希复算→封存）在本会话**未被证明**，卡在第一个阶段 agent 派发。
2. **不是插件缺陷的证据**：胶囊被真实工具完整解析、全部授权门禁放行、阶段机进入 `scope`、错误分类与 `failedStage` 语义正确；失败来自宿主对“成员子代理派发”的限制。
3. **负向链路通过**：同脚本缺 scope 在真实工具中返回 `status=rejected`/`exitCode=1`/`rejectedBy=["G-ARG-01"]`/`0 agents`，无任何写入。
4. 交付前必须由**具备子代理派发额度**的会话（captain 会话，或提高本成员的委派额度后）重跑正向链路；负向链路可不再重跑（已通过）。

## 8. 重跑步骤（交给 captain）

1. 在具备 `agent()` 派发额度的会话中，读取 `dsh-redblue/workflow/assess.js` 全文（64,747 B，SHA256 `870df9ee…1ae66957`）。
2. 调用原生 `workflow` 工具，`meta`/`args` 与 §3.1 完全一致（`workDir` 换成新目录；`maxConcurrency: 1`、`dryRun: true`、target 仅 `app.example.com`）。
3. 期望返回：`ok=true`、`status ∈ {clean, findings}`、`exitCode ∈ {0,2}`、`sealed=true`、`artifacts` 覆盖 7 件（`findings.json`、`coverage.json`、`report.md`、`exports/results.sarif`、`scope.json`、`recon.json`、`surface.json`）并追加 `scan-manifest.json`。
4. 产物核对（示例命令）：

```bash
cd /c/dsh-workspace/branch1/.work/smoke/<new-assess-dir>
node -e "const fs=require('fs'),c=require('crypto');const m=JSON.parse(fs.readFileSync('scan-manifest.json','utf8'));let bad=0;for(const a of m.artifacts){const h=c.createHash('sha256').update(fs.readFileSync(a.path)).digest('hex');const b=fs.statSync(a.path).size;const ok=(h===a.sha256&&b===a.bytes);if(!ok)bad++;console.log((ok?'OK  ':'BAD '),a.path,b,h);}console.log('manifest.status',m.status,'exitCode',m.exitCode,'mismatches',bad);"
```

5. 核验点：`manifest.status`/`exitCode` 与返回对象一致；四件公共产物哈希与字节数逐条 OK；`report.md` 含 §1–§7 章节；`findings.json` 可解析且 `schemaVersion="dsh-redblue-findings/v1"`、`findings[]` 字段齐全；manifest 含 `dryRun: true` 与 `mode: "passive"`（目标侧零动作可追溯）。

## 9. 约束与改动声明

- **只写本文件**：`dsh-redblue/docs/smoke-report.md`；未修改 `lib/`、`skills/`、`references/`、`workflow/`、`tools/`、`test/`、`package.json`、`policy/`、`docs/verification-report.md`、`docs/requirements.md`、`docs/design.md`，未触及 `dsh-security/`、`.work/sources/`。
- 新增仅临时区：`.work/smoke/assess-20261119-1610/`、`.work/smoke/neg-20261119-1610/`（均为空目录，供 t7 抽查；t9 交付前清理）。
- 目标侧零动作：target 仅为 RFC 确保的保留域 `app.example.com`；`dryRun=true`；未运行任何工具配方、未发包、未访问任何第三方目标（正向在首个 stage agent 前终止，负向在门禁处终止）。
- 未用 `node:vm` 单测或 mock 冒充 smoke；提交给工具的是 `assess.js` 原文，不是重写件。
- **完整性说明（限制）**：本机原生 `workflow` 工具不把脚本副本落盘（`.dsh/workflow-runs/` 下无本次记录），因此无法对“提交给工具的脚本文本”做 SHA256 复核；脚本完整性仅有间接证据（可解析 + 门禁/阶段行为符合源码契约）。若需强证据，建议在重跑时由工具侧落盘脚本副本或对比返回中的 `runId`/`scopeDigest`。

## 10. 真实运行失败分析（49 agents / 7 阶段 / seal 失败）与修复

> 本节由 t16 追加，**不修改 t12 已写的 §1–§9**。证据来自 captain 真实运行目录 `.work/smoke/assess-captain-20261119-1625/`（只读引用，未修改该目录）。该次运行使用原生 `workflow` 工具、`assess.js` 原文、`workDir` 新目录、`maxConcurrency=1`、`dryRun=true`、target 仅 `app.example.com`；49 个 agent 完成 7 个阶段，在 `seal` 阶段失败。

### 10.1 失败现场（原始哈希证据）

`scan-manifest.json` 由旧版 seal 阶段写出：`status="failed"`、`exitCode=1`、`mismatches=[]`（缺陷 C：失败清单无法诊断）。逐件复算（actual = 对磁盘文件重新 SHA256）如下：

| 产物 | 期望 SHA256（manifest） | 实际 SHA256（磁盘） | 期望/实际字节 | 结果 |
|---|---|---|---|---|
| `coverage.json` | `727b62c4d226508405b6e72f874788a3e620e83509c250b2e4e13c11a05d4f06` | `13fda24fc931eefac64b3c86e0fa3a619a98b72711f483637a59e9ab11bee52c` | 49,227 / 49,227 | **BAD** |
| `findings.json` | `a77d2c943fee95e9ce6b0b144de1fb70b5c45ea529a2cd114f6b49a0f0f82b35` | `0c812a7aed11520a8d06736286347d08dc298b150e298c0cb20b6fb30d1757b4` | 254,774 / 254,774 | **BAD** |
| `exports/results.sarif` | `fc0322192c2dd50999123bd085e0cb8587d1d1f7acab1864878fb34d027daead` | 同期望 | 405 / 405 | OK |
| `recon.json` | `dbdaedcd57995e6f2920c934fef4346c4185d31acb3f16be1b063ec72ce5ebd7` | 同期望 | 2,834 / 2,834 | OK |
| `report.md` | `0356b82face22e9fcdd7940d897d6f75a8e26a2890e7bb9897f1f702ed185f12` | 同期望 | 49,188 / 49,188 | OK |
| `scope.json` | `a725dd5648fa551fc89e921fd93a82b233b406de3a5d902a87cd68c800deaf17` | 同期望 | 643 / 643 | OK |
| `surface.json` | `7fa2ad7bd3c60e94e7ff7dbb07ea0cd7b25e37046e4e544d1e68d1012128ac46` | 同期望 | 1,801 / 1,801 | OK |

结论：2/7 产物**字节数完全相同、SHA256 不同**；其余 5 件（含 49 KiB 的 `report.md`）逐字一致。失败不是内容生成错误，而是 JSON 序列化键序/空白被写 agent 静默改写，旧胶囊没有回读校验，直接把偏差留到 seal。

### 10.2 缺陷 A（主因）：report 写入无回读校验与重试

- **根因**：旧 `finalize()` 把 7 件产物拆给独立 `report-write:*` agent，只判断“agent 返回了 JSON 且未报错”，没有让写 agent 回读并返回实际 SHA256/字节数；seal 才发现不一致，整轮作废（实测失败率约 28%）。
- **修复（9 个胶囊一致）**：
  1. 每件产物写入 prompt 明确给出 `expected sha256` 与 `expected bytes`，要求写 agent **写入后回读**并返回 `{ok,path,sha256,bytes}`；
  2. 胶囊比对返回值与期望；不一致时携带 expected/actual 重写同一份确定性内容（**最多 2 次重试**，共 3 次写入），内容始终来自脚本，agent 不得生成/修复/格式化；
  3. 仍不一致时 report 阶段 fail，错误信息列出文件名 + `expectedSha256` + `actualSha256` + bytes；
  4. 无论 report 是否成功，seal 阶段都会只读校验实际文件，并写 manifest；report 失败时写 `status="failed"` manifest（含 mismatches）后返回 `failedStage="report"`。
- **回归**：`report write tamper is detected by readback and retried successfully`（首次篡改、第二次通过，断言 2 次写入）；`persistent report tamper fails and failed manifest lists precise mismatches`（持续篡改 3 次、失败、manifest.mismatches 精确含 findings.json）。

### 10.3 缺陷 B（严重）：scope.json 归档注解被下游误拒

- **根因**：胶囊写出的 `scope.json` = 归一化 scope + `scopeDigest` + `validatedAt`（exploit/post 还有 `confirmedTarget`）；下游 `tools/lib/gate.mjs` 的 `SCOPE_KEYS` 与 `schema/scope.schema.json` 只允许输入 scope 字段，6 个 recipe/guard 调用一律 `G-CONF-01`，`dryRun=false` 时 recon 工具无法执行。
- **修复（in-scope 投影）**：
  1. `scope.json` 改为**纯归一化输入 scope**（不含 `scopeDigest`/`validatedAt`/`confirmedTarget`），直接作为下游 recipe/guard 的 scope 输入；
  2. 归档注解另写 `scope.archive.json`（归一化 scope + `scopeDigest` + `validatedAt` + `confirmedTarget`），只用于审计，不作为 guard 输入；
  3. 首个阶段的 prompt 同时逐字写入 `scope.json` 与 `scope.archive.json`；9 个胶囊一致；
  4. 未修改 `tools/lib/gate.mjs`、`schema/scope.schema.json`、`policy/authorization.md` 的任何硬门禁（均保持原严格白名单），因此不需要放松 `SCOPE_KEYS`。
- **范围说明**：t16 文本建议“让 scope 校验白名单接受注入字段”，但同文把 `tools/`、`schema/`、`policy/` 列为 out-of-scope；本修复选择在 in-scope 的 `workflow/` 内做投影，既消除 `G-CONF-01`，又不放松任何 G-*。归档字段仍完整保存在 `scope.archive.json` 与 findings/coverage/manifest 的 `scopeDigest` 中。
- **回归**：`workflow scope projection passes gate/guard while hard gates remain strict`（从真实 vm 运行的 `scope.json` 解析出纯 scope，`checkScope` ok 且 `guard` dry-run 通过；`scope.archive.json` 含归档注解；缺 authorization/过期/通配仍被拒；带注解对象仍被严格 gate 拒绝）。

### 10.4 缺陷 C（次要）：failed manifest mismatches 恒为 []

- **根因**：旧 `buildManifestDoc` 在 failed 时固定写 `mismatches: []`；seal agent 也无法把实际差异带回脚本。
- **修复**：
  1. `buildManifestDoc` 接受 `options.mismatches`；failed manifest 写入实际清单 `{path, expectedSha256, actualSha256, bytes}`；
  2. seal 阶段改为“只读校验 agent → 脚本汇总 mismatch（report 回读 + seal 实测并集）→ `seal-write` agent 逐字写 manifest”；成功写 completed、失败写 failed；失败 manifest 的 artifacts 仍覆盖全部期望产物；
  3. 失败清单按验收要求写 `{path, expectedSha256, actualSha256, bytes}`；`schema/manifest.schema.json` 本轮未改（out-of-scope），其 mismatches 旧结构对齐列入遗留风险，待允许修改 schema 的任务处理。
- **回归**：持续篡改用例直接解析 `seal-write` prompt 中的 failed manifest，断言 `status=failed`、`exitCode=1`、`mismatches=[{path:"findings.json",expectedSha256,actualSha256,bytes}]` 且 expected≠actual。

### 10.5 共享核心一致性与门禁不改动

- 9 个胶囊的 `finalize()` 核心段完全一致（测试用 SHA256 比对：当前段长 10,482 B，哈希 `23900613dd2741bb809e2953c9dab26582bff4633ea7a8b07c57514d2e3abc98`）；scope 均为“纯 scope.json + scope.archive.json 归档”投影。
- 未改任何 G-* 的判定顺序/语义；拒绝路径（缺 scope、路径、授权、目标、mode、confirm、data source、window/budget/dataHandling）原有 25 个测试全部保留并通过。
- 新增测试后 `test/workflow.test.mjs` 共 **29/29 通过**（原 25 + 4）；`node --check` 9/9 通过。

### 10.6 下一次 smoke 的验收点

由具备派发额度的 captain 重跑同一 meta/args（新 `workDir`、`maxConcurrency=1`、`dryRun=true`、target `app.example.com`）：

1. 返回 `ok=true`、`status ∈ {clean,findings}`、`exitCode ∈ {0,2}`、`sealed=true`；
2. 7 件产物 + `scan-manifest.json` 齐全；manifest 每件 SHA256/字节复算零 mismatch；
3. `report.md` 含 §1–§7；manifest `status="completed"`、`exitCode` 与返回一致、`dryRun=true`、`mode="passive"`；
4. 若再次出现写偏差，report 阶段应自动重试最多 2 次，并在失败时给出文件名 + expected/actual，同时 failed manifest 的 mismatches 非空、可定位。

## 11. 修复后真实运行（recon + assess 全链路）

> 本节由 smoke-runner-2 追加，**不修改 §1–§10**。两段均为原生 `workflow` 工具、脚本原文逐字内联、真实 agent 派发，无 vm/mock 替代；`workDir` 为新目录、`maxConcurrency=1`、`dryRun=true`、target 仅 `app.example.com`。

### 11.1 被测脚本（磁盘当前版本 = t16 修复后）

| workflow | 路径 | 字节 | SHA256 |
|---|---|---|---|
| recon | `dsh-redblue/workflow/recon.js` | 65,983 | `b3f43c3e863643496811d928bb52008ac15f690bdd887b97ddbf51ce2c92bf72` |
| assess | `dsh-redblue/workflow/assess.js` | 70,107 | `52cccaf64c91c2137c0621ab5070d5d911fe56a4fa4fef5c8e9c99178ee7c1a3` |

说明：与 §10 记录的修复前尺寸（60,623 B / 64,747 B）不同，当前两文件为 t16 修复后版本（两个文件均 +5,360 B，即胶囊改动）。内联方式：先整文件读取原文，再逐字作为 `workflow.script` 提交。经 `diff -u recon.js assess.js` 校验，两脚本仅 4 个 hunk 不同（头部注释、CONFIG+`findingList`、阶段图尾部、文件末尾空行），1–1303 行逐行一致；assess 内联文本 = assess 头部 4 行 + recon 第 5–1303 行 + assess 第 1304–1425 行。

### 11.2 第 0 步 委派探针

meta `{"name":"dsh-rb-delegation-probe-2","description":"修复后 smoke 委派探针"}`；script `const r = await agent("只回复 {\"ok\":true}", {label:"delegation-probe"}); return {ok:true, child:r};`。

返回：`workflow "dsh-rb-delegation-probe-2" completed (1 agent)`，`{"ok":true,"child":"{\"ok\":true}"}` → 派发额度可用，未出现 delegation limit。

### 11.3 第 1 步 recon 全链路

meta（逐字）：

```json
{"name":"dsh-rb-smoke-recon","description":"dsh-redblue recon 全链路 dry-run smoke","phases":[{"title":"scope"},{"title":"recon"},{"title":"surface"},{"title":"report"},{"title":"seal"}]}
```

args（逐字）：

```json
{
  "scope": {
    "authorization": {"type":"written","reference":"CAPTAIN-SMOKE-2026-11-19","grantedBy":"captain","validFrom":"2026-11-19","validTo":"2026-11-19","document":"captain smoke"},
    "targets": [{"kind":"domain","value":"app.example.com"}],
    "mode": "passive",
    "window": {"start":"2026-11-19T00:00:00+08:00","end":"2026-11-19T23:59:59+08:00"},
    "budget": {"maxRequests": 1, "maxMinutes": 30},
    "dataHandling": {"retain":"findings-only","secrets":"mask-and-redact","destruction":"none"}
  },
  "workDir": "C:/dsh-workspace/branch1/.work/smoke/recon-captain-20261119-2105",
  "skillDir": "C:/dsh-workspace/branch1/dsh-redblue/skills",
  "maxConcurrency": 1,
  "dryRun": true
}
```

返回关键字段：`runId=rb_20261119T130616Z_29e4`、`status=clean`、`exitCode=0`、`sealed=true`、agents=12、artifacts=7。

产物（7 件）：`coverage.json` 5,345 B、`exports/results.sarif` 404 B、`findings.json` 439 B、`recon.json` 1,656 B、`report.md` 6,168 B、`scope.json` 493 B、`surface.json` 2,764 B；另有 `scan-manifest.json` 1,622 B。`report.md` 含 §1–§7；`findings.json` 的 `schemaVersion=dsh-redblue-findings/v1`、`findings` 为空数组（0 条）。

manifest 复算（任务给定 node 命令，逐字输出）：

```
artifacts 7 mismatches 0 status completed exitCode 0 sealed undefined dryRun true mode passive
```

（输出中 `sealed undefined` 是因为 manifest 文档本身不含 `sealed` 字段；`sealed=true` 见工具返回。）

逐件复算（2026-11-19 对磁盘独立复算，数值与 `docs/verification-report.md` §4.1 完全一致）：

| 产物 | 实际字节 | manifest 字节 | 实际 SHA256 | 结果 |
|---|---|---|---|---|
| `coverage.json` | 5345 | 5345 | `b28d8bda7946037c8a0075f1de8c2d0246c049f4cd0fd05d09823b35ed086746` | OK |
| `exports/results.sarif` | 404 | 404 | `0e155f9cf8c066d49d10a6fc268bc9daf19930b83a4b8a6367fc26b42873bb5c` | OK |
| `findings.json` | 439 | 439 | `c8d29c033bcd00f94e3a5a988a49d6f9b8d577071552861568c674fbbfbe0ac1` | OK |
| `recon.json` | 1656 | 1656 | `19206c1f89eafb8c0d428d9ec6a16a4025dafde351b5af32a1bbba6a221d9273` | OK |
| `report.md` | 6168 | 6168 | `0d770a51a0a2ac060ce6bc675bf63e50070bfe1f29962961c657c5caf39a5050` | OK |
| `scope.json` | 493 | 493 | `d6eda1c1926cabf42e8193ef579b6e8ab9ef6a4b5d0909a4b677c76ac4dfd95c` | OK |
| `surface.json` | 2764 | 2764 | `4733df860cf35dc76993f66613f5c8948b773c70e8e471d205d9cef4ca03bc50` | OK |

mismatch = **0/7**。

### 11.4 第 2 步 assess 全链路（修复后）

meta（逐字）：

```json
{"name":"dsh-rb-smoke-assess-fixed","description":"dsh-redblue assess 全链路 dry-run smoke（修复后）","phases":[{"title":"scope"},{"title":"recon"},{"title":"surface"},{"title":"discover"},{"title":"validate"},{"title":"report"},{"title":"seal"}]}
```

args（逐字，`scope` 与 §11.3 完全相同，仅 `workDir` 不同）：

```json
{
  "scope": {
    "authorization": {"type":"written","reference":"CAPTAIN-SMOKE-2026-11-19","grantedBy":"captain","validFrom":"2026-11-19","validTo":"2026-11-19","document":"captain smoke"},
    "targets": [{"kind":"domain","value":"app.example.com"}],
    "mode": "passive",
    "window": {"start":"2026-11-19T00:00:00+08:00","end":"2026-11-19T23:59:59+08:00"},
    "budget": {"maxRequests": 1, "maxMinutes": 30},
    "dataHandling": {"retain":"findings-only","secrets":"mask-and-redact","destruction":"none"}
  },
  "workDir": "C:/dsh-workspace/branch1/.work/smoke/assess-captain-20261119-2115",
  "skillDir": "C:/dsh-workspace/branch1/dsh-redblue/skills",
  "maxConcurrency": 1,
  "dryRun": true
}
```

返回关键字段：`runId=rb_20261119T132506Z_67b9`、`status=clean`、`exitCode=0`、`sealed=true`、agents=20、artifacts=7。

产物（7 件 + manifest + 归档）：`coverage.json` 37,128 B、`exports/results.sarif` 405 B、`findings.json` 440 B、`recon.json` 1,706 B、`report.md` 37,228 B、`scope.json` 493 B、`surface.json` 3,145 B、`scan-manifest.json` 1,625 B、`scope.archive.json` 643 B。`report.md` 含 §1–§7（`## 1. 概览` … `## 7. 封存`）。

manifest 复算（同一 node 命令，逐字输出）：

```
artifacts 7 mismatches 0 status completed exitCode 0 sealed undefined dryRun true mode passive
```

findings 统计：`candidates=0`、`reportable=0`、`bySeverity` 全 0、`findings` 数组 0 条；`coverage.json` 的 techniques=6、limitations=104、targets=1（`domain:app.example.com`）。`findings.json` 的 `schemaVersion=dsh-redblue-findings/v1`。

**缺陷 A 验证（report 回读校验）**：20 个 agent = 11 个阶段 agent（scope/recon/surface 各 1 + discover 8；`validate` 因 `candidates.length===0` 三元短路未派发）+ 7 个 `report-write:*`（4 件基础产物 + 3 件 extraArtifacts）+ 2 个 seal（校验 + 写 manifest）。每件产物恰好 1 次写入即通过 → **零重试、无“非逐字写入”错误**；`sealed=true` 且 7 件复算零 mismatch，seal PASS。`coverage.json` 的 `phases` 为 `scope/recon/surface/discover`（`validate` 短路未入 phaseLog；report/seal 的 phaseLog 记录发生在 coverage 生成之后，属脚本既有顺序，不影响校验）。

**缺陷 B 验证（scope 投影）**：`scope.json` 键 = `authorization,budget,dataHandling,dataSources,exclusions,mode,targets,window`，无 `scopeDigest`/`validatedAt`/`confirmedTarget`，493 B；归档注解在 `scope.archive.json`（643 B，键含 `scopeDigest`、`validatedAt`）。两段 `scope.json` 的 SHA256 完全一致（`d6eda1c1926cabf42e8193ef579b6e8ab9ef6a4b5d0909a4b677c76ac4dfd95c`），说明纯输入投影在 recon/assess 上行为一致。

**缺陷 C 说明**：本轮两段均成功，只写出 `status="completed"` 的 manifest（按设计不含 `mismatches` 字段），failed manifest 的 mismatches 分支未被触发；其正确性证据沿用 §10.5 的回归测试结论，本轮不以“未发生的事件”充数。

**观察（不影响判定）**：assess 段 recon 阶段 agent 曾在 workDir 写下一个 `schemaVersion="dsh-redblue-evidence/v1"` 的 `scan-manifest.json`（21:29，1,958 B），随后被 seal 阶段正式 manifest 覆盖（1,625 B）。最终文件与工具返回一致、复算零 mismatch；同 run 内首个阶段的 G-OUT-01 检查早于该文件生成，不构成误拒。

逐件复算（2026-11-19 对磁盘独立复算，数值与 `docs/verification-report.md` §4.2 完全一致）：

| 产物 | 实际字节 | manifest 字节 | 实际 SHA256 | 结果 |
|---|---|---|---|---|
| `coverage.json` | 37128 | 37128 | `de4c835fb07d514e29474bc782a26c68950ef555d58116944d2bb70efd51e447` | OK |
| `exports/results.sarif` | 405 | 405 | `e6c11f3e8d5a8956f02474d47234dd76a7e45736fba9d292c217259d9d985601` | OK |
| `findings.json` | 440 | 440 | `468ca1bfff4a64ddff2a68f1ec6cd1cc1ce1f9bf289e149ffb608dffa8c195f7` | OK |
| `recon.json` | 1706 | 1706 | `fd67483d249a577adff63c9e41ebf69d7ddb2a030cabe2b639a80615f49497e9` | OK |
| `report.md` | 37228 | 37228 | `9f45425a98f64dccd05e5c1458060fd1f03fe286eb4c908cff29a30b98eb0edd` | OK |
| `scope.json` | 493 | 493 | `d6eda1c1926cabf42e8193ef579b6e8ab9ef6a4b5d0909a4b677c76ac4dfd95c` | OK |
| `surface.json` | 3145 | 3145 | `9131d9d0983461b08278c3ac8c95c53f2e4688d7d88014f298d184f874db9f7e` | OK |

mismatch = **0/7**。

### 11.5 负路径沿用结论

本轮未重跑负向链路（任务只要求 recon + assess 两段正向）。沿用 t12 §4 结论：同一胶囊文本、不传 `scope` 时在**任何 agent 之前**被 `G-ARG-01: scope 必须是对象` 拒绝（`status=rejected`、`exitCode=1`、`rejectedBy=["G-ARG-01"]`、0 agents、0 产物）。t16 修复未改动任何 G-* 判定顺序/语义，原 25 个拒绝路径测试保留并通过（§10.5）；本轮两段真实运行的 `rejectedBy` 均为 `[]`，未出现 G-* 误拒。

### 11.6 目标侧零动作声明

- 两段 `args` 的 targets 仅 `{"kind":"domain","value":"app.example.com"}`；无其他目标、无通配、无 exclusions。
- 两段 `dryRun=true`、`mode="passive"`，返回中 `dryRun=true`、`mode=passive`；阶段 prompt 明确“dryRun=true 时只做被动/离线步骤，不向目标发包、不主动扫描”。
- discover 阶段落盘的是 `plan/guard-*.json`、`plan/templates-*.json`、`plan/references-loaded.json` 等计划/守卫文件（dry-run 模板），workDir 内无发包回执、无响应抓包、无扫描输出。
- 限制：本声明基于 `dryRun/mode` 与 workDir 证据，未做网络层抓包；不存在对真实第三方目标的访问。

### 11.7 结论

| 项 | recon | assess |
|---|---|---|
| ok | true | true |
| status | clean | clean |
| exitCode | 0 | 0 |
| sealed | true | true |
| artifacts + manifest | 7 + 1 | 7 + 1 |
| manifest 复算 mismatch | 0 | 0 |
| 判定 | **PASS** | **PASS** |

总判定：**PASS**。两段真实全链路完成；缺陷 A、B 已由真实运行验证；缺陷 C 的成功路径行为一致、失败路径不在本轮触发。
