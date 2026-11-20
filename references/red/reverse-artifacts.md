<!-- dsh-redblue:provenance {"source":"rea-agents@6.9.0","license":"MIT","derived":true,"last-verified":"2026-11-20","rewrite":"REA 62 版路由/证据/生命周期纪律改写压缩；删除安装与样本执行细节，新增授权、降级与报告映射"}
source-repo: https://github.com/morluto/rea
source-commit: d74549e495c58eb4a560279fd9f05508401ea0a0
source-license: MIT
source-path: skills/reverse-engineer-anything/SKILL.md
last-verified: 2026-11-20
rewrite-summary: 保留 REA 62 版的目标路由、证据分层与生命周期纪律；删除安装/运行时细节，新增授权、降级与报告映射
-->

# REA 逆向参考（reverse-artifacts）

> 定位：`dsh-red-reverse` 的配套方法论。回答三件事：**这类制品该用哪族工具**、**最小证据是什么**、**哪些结论不能下**。
> 上游：REA（Reverse Engineering Agent），仓库 `https://github.com/morluto/rea`，tag `rea-agents-6.9.0`，commit `d74549e4…`，许可 MIT，官方技能 `reverse-engineer-anything` v62（255 个 MCP 工具 / 196 个 CLI 命令 / 6 个 guided prompts）。本篇为中文改写压缩，不复制上游原文；上游安装与运行时细节不在本篇范围。
> 消费者：`dsh-red-reverse`、`workflow/reverse.js` 的 inventory/static/runtime/report 阶段、`dsh-red-validate` 的制品类复核。
> 版本时效：工具族、provider 状态与计数按 2026-11-20 本机同一 server 实测；REA 升级（如 6.10.x）或宿主变化后必须重跑 probe 并复核本文，不得沿用旧数字。

## 0. 使用方式与总纪律

1. **先探测再动手**：每个 run 先 `binary_session`，用运行时的 `providers` / `toolAvailability` / `targetKind` 决定路径；本文表格只是候选族，不是可用性断言。
2. **一个 run 一个制品**：`scope.targets` 恰好 1 个 `kind="source"`；多目标拆成多次运行，跨制品比对另开 `compare_*`。
3. **静态优先**：默认 `dryRun=true` 只做探测与计划；执行类动作（Frida/进程捕获/调试/ADB 动作）属于 runtime，必须过 `G-RT-01`/`G-RT-02`。
4. **证据先于结论**：每个结论至少 1 个 `evidence_id`；没有证据的只能进 `limitations` / `deferred`。
5. **不推断格式**：魔数与扩展名冲突时以内容为准；识别不了就 `targetKind="unknown"` 并降级，不猜。
6. **不改目标**：只读文件；不写目标目录、不改时间戳、不删除/重命名样本。
7. **不联网**：不查外部情报、不做链上 RPC、不抓实时流量；只解析本地文件与本地录制。
8. **产物只落 workDir**：证据包、`reverse.json`、报告都在 `workDir`；越界写入按失败处理。

## 1. 目标路由表

表中「工具族」按能力命名；实际工具名以 probe 的 `suggestedTools` 为准，技能正文不枚举 255 个工具。

| targetKind | 首选工具族 | 最小证据（可报告的最低集） | 产物 | 限制与常见误判 |
|---|---|---|---|---|
| `pe` | 引擎族（`open_binary` → `binary_overview`/`analyze_function`）；导入族（`inspect_pe_imports`）；加载配置族（`inspect_pe_load_config`）；资源族（`inspect_pe_resources`）；证书族（`inspect_pe_certificates`）；字符串/引用族（`list_strings`、`xrefs`、`search_bytes`）；批量反编译（`decompile_all`） | 目标 SHA256 + 导入表（DLL/函数/序号）+ 加载配置或资源/证书之一；若声称加固缺口，须给头字段或导入依据 | `reverse.json.route.staticTools`、`evidence/rea-evidence.json` 中的 records | 静态不证明运行时绑定；`inspect_binary_hardening` 在 Windows 有已知缺陷；缺失导入不等于从未动态解析 |
| `elf` | notes 族（`inspect_elf_notes`）；unwind 族（`inspect_elf_unwind_ranges`）；布局族（`inspect_binary_layout`，仅 Linux）；引擎族（`analyze_function`/`read_function_instructions`） | 目标 SHA256 + notes（build-id/ABI）或 unwind 区间；声称布局缺口时给 section/segment 依据 | 同上 | 布局推断依赖 pwntools（Windows 不可用）；`.eh_frame` 缺失不等于无函数 |
| `managed-pe` | 托管族（`inspect_managed_artifact`、`inspect_managed_members`、`inspect_managed_native_boundaries`）；图投影（`project_managed_application_graph`）；边界核验（`verify_managed_native_boundaries`） | 程序集身份（MVID/SHA256）+ 类型/成员/PInvoke 锚点或 CIL 哈希 | `reverse.json`、证据包 | 只读元数据；不加载程序集、不解析依赖、不反编译 C#；token 仅在同一构建内有效 |
| `apk` | 容器族（`inspect_artifact`）；签名族（`inspect_apk_signature`）；JADX 族（`inspect_android_package`/`inspect_android_class`/`inspect_android_method`/`trace_android_references`）；apktool 族（`decode_android_resources`） | 包名/版本/SDK + 签名方案与证书 SHA256 + 成员清单；若做代码结论，须给类/方法证据 | 同上 | 无 JADX 时不做反编译；签名匹配不等于可信；资源解析需 apktool；ADB 动作属 runtime |
| `asar`/`javascript`/`electron` | 应用图族（`analyze_javascript_application`）；fuses（`inspect_electron_fuses`）；目标枚举（`list_electron_targets`）；特征追踪（`trace_application_feature`）；导出形状比对（`compare_javascript_export_shapes`）；源码恢复（`recover_javascript_sources`，仅 Linux） | 应用图摘要 + 入口/模块身份 + fuses 快照（Electron）；若比对版本，给双方 digest | 同上 | 静态图不等于运行时可达；fuses 状态不等于 Inspector 实际启用；源码恢复是派生文本，不是原始工程 |
| `wasm` | WASM 族（`inspect_wasm_artifact`，需 WABT）；容器族（`inspect_artifact`）；接口比对（`compare_wasm_interfaces`） | 模块 SHA256 + 导入/导出签名（WAT 摘要） | 同上 | 不执行 WASM；WAT 不是原始源码；WABT 缺失时只剩字节/清单 |
| `firmware` | 区域族（`inspect_firmware_regions`，需 Binwalk）；提取族（`extract_firmware`，需 Unblob，仅 Linux）；设备树（`inspect_devicetree`）；熵（`inspect_byte_entropy`）；容器族（`inspect_artifact`） | 固件 SHA256 + 区域偏移/类型 + 子镜像清单（若提取） | `workDir/extract/`（若提取）、证据包 | 提取偏移不是原始运行地址；嵌套容器不递归；Windows 无 Binwalk/Unblob |
| `pcap` | 录制摘要（`inspect_pcap_capture`）；字段族（`inspect_packet_capture`/`inspect_packet_fields`）；Web 录制（`inspect_web_network_capture`，HAR/SAZ/mitmproxy/qlog） | 文件 SHA256 + 端点/DNS/SNI 摘要或指定字段行；分页时保留同一 digest | 证据包 | 录制不证明实时流量；不抓包、不重放、不访问记录中的 URL；TShark 字段解析受宿主限制 |
| `evm` | EVM 族（`inspect_evm_interface`，仅 Linux）；熵（`inspect_byte_entropy`） | 载体 SHA256 + 选择器/参数/可变性候选（标注 inferred） | 证据包 | 选择器是候选，不证明链上部署或可调用；不查链、不广播、无 RPC |
| `archive` | 容器族（`inspect_artifact`）；提取族（`extract_artifact`）；比对（`compare_artifacts`）；熵（`inspect_byte_entropy`） | 容器 SHA256 + 成员路径/哈希/大小 | 证据包 + 可选提取目录 | 嵌套容器记录不递归；不执行包内文件；DMG 等平台相关格式受限 |
| `unknown` | 容器族 + 熵（若可用） | 目标 SHA256 + 「格式未识别」+ 降级路径 | `reverse.json.degraded` | 不得猜格式；无任何静态路径时按 G-REA-02 blocked |

**按问题选工具（不是按格式）**

| 要回答的问题 | 首选证据 | 不能直接得出的结论 |
|---|---|---|
| 这个程序依赖哪些系统能力/库 | 导入表、动态符号、托管 PInvoke | 「一定会调用」；导入可能延迟/动态解析 |
| 是否启用加固（ASLR/NX/CFG/栈保护） | PE 加载配置、ELF notes、头字段 | 「安全/不安全」；标记是链接期声明，非运行强制 |
| 是否签名、谁签的 | PE 证书表、APK 签名方案/证书指纹 | 「可信」；只证明声明与自洽性 |
| 有哪些敏感字符串/凭据 | 字符串清单 + 引用 | 「泄露可用」；字符串可能是样例/占位/误报 |
| 某个功能怎么实现 | 函数伪代码、调用图、xref | 「运行时一定走到」；静态是可达性候选 |
| 两个版本改了什么 | `compare_artifacts`/`compare_functions`/`compare_managed_members`/`compare_wasm_interfaces` | 「行为变化」；静态差异不等于运行时变化 |
| 运行时是否真的执行/外联 | 仅 runtime 观察（Frida/捕获/调试/Inspector） | 任何静态工具都不能证明执行 |

规则：表中工具族之外的调用视为越界；REA 版本升级后工具可能改名/增删，以 runtime `tools/list` 与 probe 为准。

## 2. 证据纪律

### 2.1 证据分层（observed / derived / inferred / unknown）

| 层 | 判据 | confidence | 可进候选 | 备注 |
|---|---|---|---|---|
| observed | 工具直接返回的事实（字节、导入项、区段、签名、代码文本） | `high` | 是 | 引用 `evidence_id` + operation |
| derived | 对 observed 做确定性变换（哈希、计数、地址映射、差集） | `medium` | 是 | 写清变换与输入 evidence_id |
| inferred | 分析者推断（意图、行为、可利用性、归属） | `low` | 默认 `deferred` | 不得标成 observed；不得升级 |
| unknown | 工具报 `unknown`/`partial`，或未覆盖 | 不适用 | 否 | 写入 `unknowns[]`/`limitations`，不得当「无问题」 |

### 2.2 Evidence ID 与引用

- REA 每条证据有 `evidence_id`（形如 `ev_<64hex>`）；引用格式固定：`rea:<evidence_id>#<operation>`。
- 不得截断、改写、复用别人的 evidence_id；summary 结果的 `parent_evidence_id` 才是完整记录的 ID。
- 每种事实绑定自己的证据：导入表、加载配置、证书、签名为不同证据，不能用一个 ID 概括。
- 证据分页（`inspect_analysis_view`）不产生新事实；页耗尽不等于「已覆盖全部」，只代表该集合已读。
- 关系/覆盖信息（`relationship_coverage`、`unknowns`）与事实同等重要，必须保留。

### 2.3 证据包与哈希

| 项 | 规则 |
|---|---|
| 导出 | `export_evidence_bundle`，绝对路径指向 `workDir/evidence/rea-evidence.json`；目录必须先创建 |
| 内容 | 顶层 `artifacts/captures/environments/providers/records/scenarios/unknowns`；不裁剪 |
| 哈希 | `reverse.json.evidence.sha256`、`scan-manifest.json` 同一 `path/bytes/sha256`；seal 复算 |
| 记录数 | `records` 是包内记录数，不是结论数；不得把记录数当覆盖度 |
| 敏感性 | 可能含环境变量值、证书字节、原始字符串；报告与 findings 只引用定位与摘要，不引用原文 |
| 保留 | `retain=none` 不写包（`retained=false`）；`findings-only`/`full` 才写；写包则必须登记哈希 |
| 确定性 | `deterministic=false`：不承诺跨运行同字节；同 run 内以 manifest 为准 |
| 回退 | 证据目录不可写/不存在 → 按失败处理并记 `limitations`；不得静默丢弃证据 |

证据记录示例（`evidence` schema 的 `evidence-ref` 形态，字段与 15 字段 schema 一致）：

```json
{
  "kind": "evidence-ref",
  "path": "evidence/rea-evidence.json",
  "sha256": "<bundle-sha256>",
  "locator": "rea:<evidence-id>#inspect_pe_imports",
  "bytes": 0,
  "type": "inspect_pe_imports",
  "acquiredAt": "2026-11-20T00:00:00Z",
  "ts": "2026-11-20T00:00:00Z",
  "source": "rea-agents@6.9.0",
  "sourceSha256": "<target-sha256>",
  "actor": "reverse-static",
  "action": "inspect_pe_imports",
  "object": "<sample-path>",
  "note": "authority=shipped-artifact; operation=inspect_pe_imports; evidence=<evidence-id>; limitations=1 line",
  "confidence": "high"
}
```

### 2.4 不得做的事（证据层）

1. 不把摘要预览当完整 JSON 解析，也不因客户端截断而重复执行同一次分析。
2. 不用「文件名/字符串/布局」推断行为；行为结论必须有代码或 runtime 依据。
3. 不把两次运行的不同 build 拼成一条证据链；跨构建比对必须给双方 digest。
4. 不隐藏 provider 缺失、未覆盖分支、超时与截断；这些必须出现在 `degraded[]`/`limitations[]`。
5. 不在证据包、报告、findings 中保留明文秘密；按 `mask-and-redact` 只留类型/长度/首尾少量字符。

## 3. 平台矩阵（2026-11-20 本机实测）

### 3.1 计数口径

本机 `binary_session`（同一 server，`rea 6.9.0`，SDK `2.3.1`，protocol `2026-07-28`，skill v62）实测：

| 口径 | 数值 |
|---|---|
| 目录 | 255 个 MCP 工具 / 196 个 CLI 命令 / 6 个 guided prompts |
| 工具组 | 88 组 = available 49 + target_required 13 + provider_unavailable 7 + provider_missing 4 + unsupported_host 15 |
| 工具数 | 255 = 133 immediate + 63 target_required + 59 hard unavailable（26 provider_unavailable + 22 unsupported_host + 11 provider_missing） |

口径说明：早前基线曾记录「81 组可用 / 15 组 unsupported_host」，与本轮「88 组 / 49+13+7+4+15」统计口径不同（组 vs 工具、是否计入 `target_required`）。**代码、测试与报告不得固化任何工具数量**；只断言「probe 字段存在」「三类计数之和等于目录数」。

### 3.2 能力矩阵（Windows 宿主）

| 能力 | 状态 | reason | 降级路径 | remediation（由用户执行） |
|---|---|---|---|---|
| PE 静态（导入/资源/加载配置/证书） | 立即可用 | — | — | 无需 |
| ELF 静态（notes/unwind/反编译，Ghidra） | 立即可用 | — | — | 无需 |
| 托管 PE/CLI | 立即可用 | — | — | 无需 |
| ASAR/JS/Electron 静态、fuses、Electron 目标枚举 | 立即可用 | — | — | 无需 |
| APK 容器/包清单/签名 | 立即可用 | — | — | 无需 |
| Frida 设备/进程枚举与 attach/instrument（runtime） | 工具组立即可用 | — | — | 仍需过 `G-RT-01/02` 并实测设备；工具组可用不等于设备可达 |
| PCAP 摘要（capinfos/tshark 摘要，`inspect_pcap_capture`） | 立即可用 | — | 用摘要做端点/DNS/SNI 结论 | 无需 |
| 二进制加固标记（`inspect_binary_hardening`） | 工具组标记可用，Windows 路径调用不可用（已知缺陷 K-1） | 客户端 schema 错误 | 加载配置 + notes + 导入表 + 人工基线 | 等待上游修复或在非 Windows 主机执行 |
| APK 资源解码（apktool） | 不可用 | `provider_unavailable` | 仅包清单/签名 | 指向已安装的 apktool |
| APK 类/方法/JNI（JADX） | 不可用 | `provider_missing` | 仅包清单/签名 | 指向 jadx-headless-mcp 兼容 JAR |
| ADB/设备动作 | 不可用 | `provider_unavailable` | 不做设备侧动作 | 配置 adb 路径或加入 PATH |
| WASM（WABT） | 不可用 | `provider_missing` | 容器清单 + 熵 | 指向 WABT 工具目录 |
| 固件区域/提取（Binwalk/Unblob） | 不可用 | `unsupported_host` | 熵 + 容器清单 | Linux + Binwalk/Unblob + prlimit/procps |
| GDB / rizin 调试 | 不可用 | `unsupported_host` | 静态反编译替代 | Linux + TTY |
| 进程捕获 | 不可用 | `unsupported_host` | 不做进程捕获 | Linux 或 macOS |
| pwntools 布局 / 记录崩溃 | 不可用 | `unsupported_host` | 跳过布局推断 | Linux x64 + pwntools 4.15.0 |
| PCAP/TShark 字段解析（`inspect_packet_capture`/`inspect_packet_fields`） | 不可用 | `unsupported_host` | 用 `inspect_pcap_capture` 摘要替代 | Linux + TShark 4.x + prlimit |
| EVM 接口推断 | 不可用 | `unsupported_host` | 熵（无接口推断） | Linux x64 |
| Wakaru JS 源码恢复 | 不可用 | `unsupported_host` | 仅静态应用图 | Linux x64 + Wakaru |
| 信号/逻辑分析 | 不可用 | `unsupported_host` | 无 | Linux + sigrok-cli |
| macOS 原生（Mach-O/plist/签名/UI） | 不可用 | `unsupported_host` | 仅文件哈希/熵；`targetKind=macho` 降级 | macOS |
| JEB | 不可用 | `provider_missing` | 不做 JEB 反编译 | 启动 JEB MCP 客户端 |
| Hopper | 不可用 | `unsupported_host` | 用 Ghidra | macOS |
| IDA | 不可用 | `not_configured` | 用 Ghidra | 配置 IDA MCP |
| Kuna | 不可用 | `not_configured` | 用 Ghidra | 配置 Kuna 命令 |

可在 Linux/macOS 上补齐的能力：固件提取、GDB/rizin、进程捕获、pwntools、TShark、EVM、Wakaru、信号、macOS 原生；REA 与这些 provider 由宿主 MCP 提供，插件不打包、不安装、不自动配置。

### 3.3 降级规则

1. 仍有 ≥1 条静态路径 → 继续；`status` 仍为 `clean`/`findings`，逐项写 `degraded[] = {capability, reason, remediation, effect}`。
2. 目标完全无可用路径 → `G-REA-02` blocked（0 分析 agent、0 产物）；不得输出「未发现问题」的结论。
3. runtime provider 缺失 → 不 blocked；`runtime.executed=false`，报告显式写「runtime 未执行」，退出码按静态结果。
4. 降级不改变 `confidence`/`authority`；因缺失能力造成的空白写 `limitations`，不得用推测填补。

## 4. 已知缺陷与处置

| # | 缺陷 | 观察（2026-11-20） | 处置 |
|---|---|---|---|
| K-1 | `inspect_binary_hardening` 在 Windows 绝对路径上返回客户端 schema 错误 | 报 `Structured content does not match the tool's output schema: data/normalized_result/artifact/path must match pattern "^\/"`；分析可能已执行但结果不可用 | 不使用；改用加载配置/notes/导入表；`degraded[]` 记录；非 Windows 可重试 |
| K-2 | PE 导入工具默认文件上限 64 MiB | 大 PE（如 93 MB 级宿主程序）报 `resource_constraint` | 显式提高 `max_file_bytes`（有上限）或换较小制品；失败写 `limitations` |
| K-3 | Hopper 在 win32 不可用 | `unsupported_host` | 用 Ghidra |
| K-4 | JADX/ADB/apktool/WABT/JEB 缺失 | `provider_missing`/`provider_unavailable` | 按 §3 降级 + 给 remediation |
| K-5 | 固件/GDB/rizin/EVM/pwntools/TShark/Wakaru/macOS/进程捕获在 Windows 不可用 | `unsupported_host` | 按 §3 降级；不伪造 |
| K-6 | `binary_session.target_support` 在未打开目标时为 `unknown` | 未 open 时无目标事实 | probe 后必须 `open_binary` 验证；失败 → G-REA-02 |
| K-7 | Frida 可用性不由工具组 `available=true` 保证 | 设备探测与工具组分离 | runtime 阶段用设备/进程枚举实测；不可用即降级 |
| K-8 | `export_evidence_bundle` 要求输出目录已存在 | 不存在时报 `Evidence output directory does not exist` | 先创建 `workDir/evidence/`；失败按证据失败处理 |
| K-9 | 证据包可能含秘密/原始字节 | 顶层含 artifacts/captures/environments/records | 按敏感产物处理；报告只引用定位与摘要 |
| K-10 | 引擎/调试会话清理失败可能残留进程 | 清理语义受宿主影响 | 记 `closed=false`/`cleanup.pending`；报告写明「可能仍在运行」 |
| K-11 | 客户端超时不是 REA 停止证据 | 客户端截止 ≠ 服务端停止 | 不重试未变更调用；记 `unknown`，避免重复分析 |
| K-12 | 目标超预算/加密/损坏 | 大文件或异常容器可能失败 | 按 blocked 或降级处理；不猜内容 |

补充：Windows Ghidra 不支持托管/敌意/可变路径目标，且关闭会话会丢弃元数据编辑（原始字节不变）；需要跨进程保留标注时必须先确认宿主配置，否则只做只读结论。

## 5. 与 findings / report 字段映射

### 5.1 REA 事实 → dsh-redblue 字段（不新增 schema）

| REA 事实 | 目标字段 | 规则 |
|---|---|---|
| `evidence_id` | `evidence.locator = rea:<id>#<operation>`；`finding.evidenceRefs[].locator` | 逐条引用；不截断 |
| `confidence`（observed/derived/inferred） | `evidence.confidence`、`finding.confidence`：high/medium/low | 不得升级 |
| `authority` | `finding.basis` 前缀 `authority=…; operation=…; evidence=…`；`evidence.note` 同步 | 不得丢弃；`analyst-inference` 默认 `deferred` |
| `limitations[]` | `finding.counterevidence`、`coverage.limitations`、`report.md` §5 | 原文/要点保留 |
| `subject.digest.sha256`、路径 | `evidence.sourceSha256`、`finding.target`（`kind=source`） | 目标哈希必须与 probe 一致 |
| `provider`/`operation` | `evidence.type`/`evidence.action`、`evidence.source="rea-agents@6.9.0"` | provider 不冒充作者 |
| `locations[]` | `evidence.locator` 补充 + `finding.location.file`（无行号时省略 line） | 不伪造行号 |
| `unknowns`/`relationship_coverage` | `reverse.json.unknowns[]`、`coverage.limitations` | 未解决即未解决 |
| `parameters`/`environment` | `reverse.json.stages.*.parameters`、`reverse.json.runtime.environment` | 可脱敏路径 |

### 5.2 候选与定级

| 观察类型 | `finding.kind` | 默认 disposition | 备注 |
|---|---|---|---|
| 内存安全/逻辑缺陷线索 | `vulnerability` | `deferred`（静态 only） | 需运行时或复现才升级 |
| 暴露的凭据/敏感数据/危险权限 | `exposure` | `deferred` 或 `reportable` | 明文凭据且 authority 足够才考虑 high/critical |
| 缺失 ASLR/CFG/签名/加密 | `hardening-gap` | `reportable`（若有头字段依据） | 加固标记缺陷影响时降级 |
| 依赖/组件元数据 | `vulnerability`/`exposure` | `deferred` | 版本推断需证据，不靠文件名 |
| 证据不足/工具缺失 | 不入 findings | `deferred` | 写 `limitations` |

可报告阈值：`authority ∈ {shipped-artifact, controlled-replay}` 且 `confidence ∈ {high, medium}` 且 limitations 未否定结论。静态 only 最高 `high`；`critical` 仅当 runtime 观察到明确影响，或观察到可直接利用的明文凭据/私钥。`counterevidence` 至少写「为何不是误报」，或明确「无可用反证」。

### 5.3 report / coverage / SARIF

- `report.md` 七段不变；§3 增「路由与 provider 状态」表（targetKind、provider、degraded、evidence 数）；§5 原样列出 limitations 与降级项；§6 写证据包敏感性与数据处置；§7 列 8 件产物哈希。
- `coverage.json`：`phases` 为 scope/inventory/static/runtime/report/seal；runtime 未请求 → `status="skipped"`、`agents=0`；`techniques` 用 REA operation 名；`targets` 为唯一 source target；`dataSources=[]`；`limitations` 合并。
- `results.sarif`：沿用既有转换；制品 finding 的 `physicalLocation` 用制品路径/offset，无行号用 `logicalLocations`；保留 `partialFingerprints.dshRedblueFingerprint`。
- `counts`（candidates/reportable/bySeverity）只由 findings 计算；`degraded` 不改变 counts，但必须出现在报告限制段。

## 6. 明确不能下的结论

1. 静态分析**没有观察执行**；不能说「运行时会做 X」。
2. 摘要/清单完整性不等于全量覆盖；页耗尽 ≠ 已覆盖全部（查无结果不等于不存在）。
3. 签名存在/证书匹配不等于可信、合法或未被篡改（只证明声明与自洽）。
4. 加固标记是链接期声明，不等于运行期强制。
5. 字符串命中不等于凭据可用；需类型、上下文与可用性证据。
6. 版本号/文件名/目录结构推断的依赖不构成漏洞证据。
7. 证据包不含全部目标行为，只含本次调用产生的事实。
8. 降级后的结论不得升级严重度，也不得用「其它平台大概也一样」补洞。

## 7. 许可、维护与边界

- 上游：`https://github.com/morluto/rea`，`rea-agents@6.9.0`，commit `d74549e4…`，MIT；官方技能 v62。本文为改写压缩，保留 MIT 归属；不复制上游 SKILL 原文。
- 不打包 REA：插件 `dependencies`/`devDependencies` 为空；不包含 REA 源码、Ghidra/JADX/ADB/WABT 等二进制或安装脚本；安装/注册由用户完成。
- 升级纪律：REA 升级必须重跑 probe 与本文 §3/§4 复核，更新 `source-commit`、INDEX 头、NOTICE 与本文 `last-verified`；不得静默升级。
- 维护触发：新格式/新 provider、平台矩阵变化、已知缺陷修复、证据字段变化。