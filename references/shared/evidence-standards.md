<!-- dsh-redblue:provenance
source-repo: https://github.com/usestrix/strix
source-commit: 8db295a5b3564be2b430bb3a9afdb4db7850fa24
source-license: Apache-2.0
source-path: skills/penetration-testing-with-strix/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 提炼 Strix 的 PoC 与产物纪律、Claude-Red 的复现结构，改写为证据分级+字段+校验+反面模式，删除工具调用细节
-->

# 证据标准（evidence-standards）

> 定位：红蓝紫共用。所有 finding 必须能由本文的字段与校验复算；不能复算的内容一律降级为「观察记录」，不得写成 finding。
> 消费者：`dsh-red-validate`、`dsh-red-exploit`、`dsh-red-post`、`dsh-rb-report`、`dsh-purple-verify`、`dsh-rb-triage`，以及 9 个 workflow 的 report 阶段。
> 版本时效：字段与分级为 v1（2026-11-19 复核）；工具版本号随环境变化，执行前核对当前版本并在证据里记录实际版本。

## 1. 四条硬规则

1. **一条 finding 至少一条可复算证据**：命令/请求（可含参数）、时间戳、目标（归一化值）、输出片段（截断后仍可定位）、输出文件 SHA256 与字节数。
2. **证据只来自授权范围内的动作**。范围外资产出现时立即停止（见 `policy/authorization.md` §6），该证据标记 `out-of-scope` 且不进入 finding。
3. **不二次转述**。不得把「疑似」「某人说」「上次扫描」当作证据；转述只能作为线索，必须补齐一次可复算采集。
4. **脱敏先于落盘**。凭据、令牌、Cookie、私钥、个人数据一律 `mask-and-redact`：只保留类型、长度与前后各 4 字符（如 `Bearer eyJh…9f2c`）。

## 2. 证据分级

| 级别 | 名称 | 判据 | 可用于 |
|---|---|---|---|
| E3 | 独立复算 | 另一执行者在同条件下重放，得到同一结论与同一关键输出 | 定级 critical/high 的必需证据 |
| E2 | 可复现 | 有完整命令/请求 + 时间 + 目标 + 输出哈希，单次执行可重复 | 定级 medium 及以上 |
| E1 | 观察 | 有输出但缺参数、缺时间或缺目标归一化值 | 仅候选断言（candidate），不得进 findings |
| E0 | 线索 | 只有描述、截图、第三方转述 | 不得进入任何产物，只可写入 `coverage.limitations` |

升级路径：E1 → E2 补参数与时间；E2 → E3 由 `dsh-red-validate` 独立重放。降级或剔除必须写明理由（`reason` 字段），不得静默丢弃。

## 3. 证据字段（`evidence[]`，与 `schema/evidence.schema.json` 一致）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | string | 是 | `ev_<candidateId>_<序号>`，同一 run 内唯一 |
| `kind` | enum | 是 | `command` / `http` / `file` / `query` / `observation` |
| `target` | string | 是 | 归一化后的目标值（域名小写去尾点、URL 去 fragment） |
| `method` | string | 是 | 命令摘要或 `METHOD /path`；不得含明文凭据 |
| `commandSummary` | string | 否 | 参数化模板 + 实际取值，凭据替换为 `<REDACTED>` |
| `ts` | string | 是 | RFC 3339 UTC，采集时刻 |
| `collector` | string | 是 | 执行者标识（agent 角色 + 工具版本） |
| `outputPath` | string | 否 | 相对 `workDir` 的输出文件路径 |
| `sha256` | string | 是 | 输出文件或截断文本的 SHA256（小写十六进制） |
| `bytes` | integer | 是 | 输出字节数 |
| `excerpt` | string | 是 | 截断到 ≤2 KiB 的关键片段；保留请求行/响应行/判定行 |
| `grade` | enum | 是 | `E0` / `E1` / `E2` / `E3` |
| `confidence` | enum | 是 | `confirmed` / `likely` / `possible` / `unverified` |
| `redactions` | string[] | 否 | 已脱敏字段名列表 |
| `limitations` | string[] | 否 | 截断、超时、被限流、未覆盖分支等 |

`sha256` 必须是对**落盘文件**计算，而不是对内存字符串；无落盘文件时对 `excerpt` 原文（UTF-8 字节）计算并标注 `sha256Scope: "excerpt"`。

## 4. 采集纪律

- **一次动作一条记录**：把「扫了 20 个路径」拆成「一次批处理 + 结果文件 + 逐条判定」，不要把 20 个结论塞进一条 `method`。
- **时间只用一个来源**：统一 UTC；禁止本地时区混写。批处理记录起止时间，单条记录在 `limitations` 注明「批次内」。
- **截断规则**：只保留能定位结论的行；被截断时写 `excerptTruncated: true` 并保留字节数。
- **稳定性**：同一 finding 的复算证据必须来自同一目标归一化值；目标变更（重定向到新域）记为新的 `target` 并在 `limitations` 说明。
- **不做破坏性校验**：验证只做「只读证明」，不写目标数据、不改配置、不留文件。需要写操作才能证明的结论，降级为 `likely` 并写清未测部分。

## 5. 最小 PoC 标准

一个可接收的最小 PoC 必须同时满足：

1. **可重复**：命令/请求参数完整，另一人可照抄复现；参数里的变量用 `<TARGET>`、`<TOKEN>` 形式占位。
2. **最小影响**：优先只读证明（如反射回显、错误差异、状态码差异、时间差），不得为此创建账号、写文件、改配置、拉数据。
3. **可回滚**：若不可避免产生状态（如上传的测试文件），记录创建物、位置与清理结果，清理后复算一次哈希或状态。
4. **不越权**：PoC 只用 `confirm` 精确匹配目标；不横向扩到同网段其他主机。
5. **可判定**：写明「若观察到 X 则成立、若观察到 Y 则不成立」，避免无判据的断言。

## 6. 置信度模型

| 值 | 判据 | 报告措辞 |
|---|---|---|
| `confirmed` | E2 以上证据，按判据复现成立，且排除了已知误报路径 | 「已确认」 |
| `likely` | 证据充分但缺少一次直接复现，或只在特定条件下成立 | 「高度可能」+ 缺什么 |
| `possible` | 只有间接信号（版本、配置、报错文本） | 「可能」+ 需补的验证 |
| `unverified` | 尚未采集到证据 | 不得进入 findings，只进 limitations |

## 7. 常见反面模式（出现即判证据不合格）

- 只有截图没有命令与时间（E0）。
- 输出片段与命令对不上（例如命令查 A 主机、输出是 B 主机）。
- 用历史扫描结果冒充本次证据，且无 `dataSources` 引用与哈希。
- 报告里出现明文凭据、Cookie、私钥或真实个人信息。
- 把工具「高危」标签直接当结论，未做独立复核。
- 复算失败但仍标记 `confirmed`。
- 为凑数量把同一根因拆成多条 finding（应合并并写 `relatedIds`）。

## 8. 完整性校验（本地，零网络）

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# Linux/macOS：对产物目录逐文件复算并与 scan-manifest 的期望值比对
sha256sum -c scan-manifest.sha256
# 单文件
sha256sum findings.json && wc -c findings.json
```

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```powershell
# <AUTHORIZED-TARGET> 为本次 workDir；不在授权范围内不得执行
Get-FileHash -Algorithm SHA256 .\findings.json
(Get-Item .\findings.json).Length
```

校验失败即 `status="error"`（`exitCode=1`），保留已写产物并在 manifest 写 `status="failed"`；禁止「重算到一致」式修补。

## 9. 留存与处置

| 项 | 规则 |
|---|---|
| 默认留存 | `findings-only`：只留 finding、证据摘要、报告与 manifest |
| 原始输出 | 需要留存时写入 `workDir/evidence/`，逐文件 SHA256；不得留存在目标侧 |
| 凭据 | 不落盘；采集到即脱敏，`limitations` 记「已脱敏」 |
| 销毁 | `destruction` 固定 `none`：不删目标数据、不清目标日志 |
| 交接 | 交付物只含 `workDir` 相对路径与哈希，不含绝对路径中的用户名 |

## 10. finding ↔ 证据绑定

- `finding.evidenceIds[]` 至少 1 项；`critical`/`high` 至少 2 项且其中 1 项为 E2+。
- 证据可被多条 finding 复用，但每条 finding 必须能独立解释「这条证据如何支持该结论」。
- `disposition=suppressed` 的候选同样保留证据（用于说明为何剔除），避免下次重复劳动。
- 复算脚本/命令写入 `report-format.md` 定义的「复现步骤」段，不写在证据 `excerpt` 里。
