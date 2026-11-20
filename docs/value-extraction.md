# 三库价值提炼账（value-extraction）

- 目的：记录 Strix / Anthropic-Cybersecurity-Skills（ACS）/ Claude-Red 三个上游如何被**改写、压缩、净化**为 dsh-redblue 的 15 个技能、9 个 workflow、参考库与工具运行时；给出 keep / merge / drop 数量与代表样例
- 口径：Claude-Red 79 个 `SKILL.md`；ACS 818 个技能 / 809 个 `scripts/agent.py`；Strix 9 个官方 `SKILL.md` + 78 篇内部知识（另 9 篇治理/基准文档不吸收）
- 原则：**能力重写，不搬运脚本**；不打包任何上游 Python/运行时/课程灌水；示例只用保留域与文档网段

## 1. 总账

| 上游 | 采集对象 | keep | merge | drop | 去向 |
|---|---|---|---|---|---|
| Claude-Red `6196ba7…`（MIT） | 79 个技能 | 14 | 49 | 16 | red 7 技能 + rb-report/rb-triage + 红队参考 |
| ACS `54a7988…`（Apache-2.0） | 818 个技能 / 809 个 agent.py | 60 | 672 | 86 | blue 4 技能 + purple + 蓝队参考/模板 |
| Strix `8db295a…`（Apache-2.0） | 9 个官方技能 | 2 | 7 | 0 | run 入口 + validate/exploit 纪律 + workflow 门禁 |
| Strix 内部知识 | 78 篇（治理/基准 9 篇不吸收） | 47 | 29 | 2 | `red/strix-techniques.md` + 台账 |
| **合计** | **984 条** | **123** | **757** | **104** | 15 技能 + 27 参考 + 9 workflow + 工具层 |

> Strix 的 78 + 9 = 87 是内部知识库存口径；9 篇治理/基准不进入价值账（见 `references/red/extraction-ledger.md` §1 与 §8）。

## 2. Claude-Red → 红队方法论（79 → 15 中的 8 个红/横切技能）

### 2.1 处置分布

- **keep 14**：直接保留其方法论骨架、判定标准与证据要求，重写为中文技能/参考（如 `recon/offensive-osint`、`web/`、`api/`、`cloud/`、`container/`、`active-directory/`、`wireless/`、`exploit-dev/offensive-exploit-development`、`post-exploitation/offensive-lateral-movement`、`privesc/`）。
- **merge 49**：多个同族技能压缩合并进同一判定清单（如 web 16 篇 → `discover-web-api.md`；wireless 14 篇 → `discover-wireless.md`；云/容器/AD/供应链 → `discover-cloud-container.md`、`discover-identity-ad.md`）。
- **drop 16**：
  - 4 个课程巨型文件（`offensive-basic-exploitation`、`offensive-crash-analysis`、`offensive-windows-boundaries`、`offensive-windows-mitigations`，合计约 1.9 MiB，占上游 52%），不搬运；
  - 3 个课程式文件（`offensive-exploit-dev-course`、`offensive-fuzzing-course`、`offensive-vuln-classes`，纯教学/大纲，与判定清单重复）；
  - 9 个定位冲突/红线项：**反取证、C2、EDR 规避、键盘记录、shellcode、数据外传、持久化、钓鱼、社工**——逐项理由见 `references/red/extraction-ledger.md` §2（#21/#22/#28/#30/#31/#37/#39/#44/#45）；共同点是 report-only 定位冲突、R3 武器化红线或 R12 授权边界，而非「与 dsh-security 源码审计重叠」或「价值更低」。

### 2.2 代表样例

| 上游 | 处置 | 插件落点 |
|---|---|---|
| `Skills/recon/offensive-osint` | keep + 压缩 | `skills/red-recon` + `references/red/recon-osint.md` |
| `Skills/web/*`（16 篇） | merge | `skills/red-discover` + `references/red/discover-web-api.md` |
| `Skills/api/*` | merge | `references/red/discover-web-api.md`（API 判定清单） |
| `Skills/cloud/*`、`Skills/container/*` | merge | `references/red/discover-cloud-container.md` |
| `Skills/active-directory/*`、`Skills/cicd/*`、`Skills/supply-chain/*` | merge | `references/red/discover-identity-ad.md` |
| `Skills/wireless/*`（14 篇） | merge | `references/red/discover-wireless.md` |
| `Skills/exploit-dev/offensive-exploit-development` | keep（去武器化） | `skills/red-exploit` + `references/red/exploit-controlled.md` |
| `Skills/post-exploitation/offensive-lateral-movement`、`Skills/privesc/*` | merge（只读化） | `skills/red-post` + `references/red/post-readonly.md` |
| 4 个课程巨型文件 | drop | 不打包、不引用 |

完整的 79 行处置（路径/字节数/目标文件/理由）见 `references/red/extraction-ledger.md`。

## 3. ACS → 蓝队/紫队与检测工程（818 技能 + 809 agent.py）

### 3.1 818 个技能的处置

- **keep 60**：蓝队核心方法论直接保留骨架并压缩为中文参考（hunting 37 篇择优、detection 96 篇择优、DFIR/取证、CIS/K8s 基线）。
- **merge 672**：同族技能合并为 5 篇蓝队方法论参考与 12 族工具配方；框架映射（ATT&CK 806、NIST CSF 805、D3FEND 139、NIST AI RMF 97、F3 94、ATLAS 93）作为归类依据。
- **drop 86**：D1 71 个红队执行/武器化前缀 + D2 14 个纯治理/认证/项目管理 + D3 1 个超 48 KiB 单文件（见 `references/blue/extraction-ledger.md` §5 具名清单）。

### 3.2 809 个 `agent.py` → 0 个打包，转为脚本模式库

实测（`references/blue/extraction-ledger.md` §7.3/§7.4）：809 个脚本中 **6 个有 `--dry-run` 开关、590 个有 `--output`/`output_dir`/`--report` 落盘参数**，HTTP 客户端 184（requests）+ 15（urllib）+ 4（httpx/aiohttp），**36 个文件含 `verify=False`（字面量 35）**，大量依赖 pandas/sigma 等第三方库。因此：

- 不打包任何 `.py`；
- 把“遍历/解析/输出/错误处理/证据落盘”的共性提炼为 `references/shared/script-patterns.md`：
  - **S1–S7** 骨架（参数校验、输入枚举、批处理、超时/重试、输出归一、证据/哈希、清理）；
  - **A1–A12** 反模式（无 dry-run、无输出上限、`verify=False`、无界扫描、静默吞错、把目标内容当指令等）。

### 3.3 代表样例

| 上游族 | 处置 | 插件落点 |
|---|---|---|
| `building-threat-hunt-hypothesis-framework`、`hunting-*` | keep + merge | `skills/blue-hunt` + `references/blue/hunt-hypothesis.md` |
| `building-detection-rules-with-sigma`、`building-detection-rule-with-splunk-spl`、`detecting-*` | merge | `skills/detect` + `references/blue/detect-engineering.md` + `references/blue/templates/` |
| `building-incident-timeline-with-timesketch`、`building-super-timelines-with-plaso`、`analyzing-network-traffic-for-incidents`、`conducting-cloud-incident-response` | merge | `skills/dfir` + `references/blue/dfir-playbook.md` |
| `hardening-linux-endpoint-with-cis-benchmark`、`hardening-windows-endpoint-with-cis-benchmark`、`auditing-cloud-with-cis-benchmarks`、`benchmarking-kubernetes-with-kube-bench` | keep + merge | `skills/harden` + `references/blue/harden-baseline.md` |
| 全部 809 个 `agent.py` | drop（不打包） | 能力模式 → `references/shared/script-patterns.md` |

完整的 818 行台账（keep 60 + merge 672 + drop 86）、809 脚本六类统计与 merge 依据见 `references/blue/extraction-ledger.md`。

## 4. Strix → 运行纪律、门禁与深度技术（9 + 78）

### 4.1 9 个官方技能

- **keep 2**：`managed-pentesting-with-strix`（预算/范围/CLI 决策纪律）、`penetration-testing-with-strix`（证据/复现/退出码）；
- **merge 7**：应用安全、云、CI/CD、LLM 等技能的能力点并入 red-discover/red-validate/red-exploit/workflow 阶段 prompt。

### 4.2 78 篇内部知识

- **keep 47**：30 类漏洞验证决策、5 个框架特化、GraphQL/REST 协议、AWS/Azure/GCP/K8s、源码感知、供应链；
- **merge 29**：同类判定合并进 `references/red/strix-techniques.md` 的决策表与误判边界；
- **drop 2**：`tooling/agent_browser.md`（依赖浏览器运行时）、`tooling/python.md`（沙箱代理自动化与零依赖冲突）。
- 治理/基准 9 篇（流程、评分、发布说明等）不吸收，不进入 78 篇技术正文。

### 4.3 代表样例

| Strix 知识 | 处置 | 插件落点 |
|---|---|---|
| `skills/managed-pentesting-with-strix/SKILL.md` | keep | `skills/run`（预算/范围/降级纪律） |
| `skills/penetration-testing-with-strix/SKILL.md` | keep | `skills/red-validate` / `red-exploit` + `references/shared/evidence-standards.md` |
| `vulnerabilities/*`（30 类） | merge | `references/red/strix-techniques.md` §1 决策表 |
| 框架特化（Django/DRF、FastAPI、NestJS、Next.js、Spring Boot） | merge | `strix-techniques.md` §2（每框架 9 要素） |
| 云/容器（AWS/Azure/GCP/K8s） | merge | `strix-techniques.md` §4 |
| 源码感知/供应链 | merge | `strix-techniques.md` §5–§6 |
| 78 篇逐篇台账 | — | `references/red/extraction-ledger.md` §8（I1–I78） |

## 5. 能力形态转化（不是文档搬运）

| 上游能力 | 插件形态 | 数量/规模 |
|---|---|---|
| 79 + 818 + 9 技能的方法论 | 15 个 bundled `SKILL.md`（rb 3 / red 7 / blue 4 / purple 1） | 15 个，107–175 行/个 |
| 命令能力（Claude-Red/Strix/ACS 工具族） | `references/red/tool-recipes.md` F1–F16；`references/blue/tool-recipes.md` B1–B12 | 16 + 12 族，每族 9 要素 |
| 检测规则写法 | `references/blue/templates/{sigma.yml,kql.md,spl.md}` | 3 个模板 |
| 运行时纪律（预算/退出码/封存/门禁） | `workflow/*.js` 9 个胶囊 + `policy/authorization.md` 39 项 G-* | 9 workflow，统一 0/1/2 + seal |
| 809 个 agent.py 的脚本能力 | `references/shared/script-patterns.md` S1–S7 / A1–A12 | 0 个 Python 打包；7 骨架 + 12 反模式 |
| 脚本化命令执行 | `tools/sec.mjs`（scope/evidence/sarif/ioc/log/rule/recipes/guard） | 1 个零依赖入口 + 11 个 lib 模块 |
| 工具族命令模板 | `tools/recipes.json`（10 条白名单配方） | 10 条，argv 数组 + 授权门禁 |
| 证据/报告纪律 | `findings.json` / `coverage.json` / `report.md` / SARIF 2.1.0 / `scan-manifest.json` | 每次运行确定性生成 + SHA256 |

## 6. 与 dsh-security 的边界

- dsh-security 负责**自有代码/PR diff 的静态审计**；本插件负责**授权外部目标 + 运行中蓝队数据**。
- 本账中的 Claude-Red/ACS/Strix 内容只用于方法论改写与门禁设计，不 import 其代码、不共享 node_modules、不读取其目录。
- 上游原始仓库、课程文件、809 个 agent.py、Strix 运行时均未进入本插件（0 个 `.py`、0 个上游脚本副本）。

## 7. 可复算入口

- Claude-Red 台账：`references/red/extraction-ledger.md`（79 行；14/49/16）
- ACS 台账：`references/blue/extraction-ledger.md`（818 行；60/672/86；809 脚本统计）
- Strix 台账：`references/red/extraction-ledger.md` §8（78 行；47/29/2）
- 参考清单与加载预算：`references/INDEX.md`（27 篇 + INDEX，每阶段 ≤2 篇）
- 工具运行时：`docs/tool-runtime.md`、`tools/recipes.json`、`tools/sec.mjs`