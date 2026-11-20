<!-- dsh-redblue:provenance
source-repo: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
source-commit: 54a798831d2266a3ca61ce68a7acb80b81160d57
source-license: Apache-2.0
source-path: skills/building-detection-rules-with-sigma/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 把 ACS 818 技能中蓝队可复用的命令与参数模式压成 12 个工具族配方；保留真实 flag、解析口径与字段映射，删除产品许可、在线调用与攻击视角
-->

# 蓝队工具族配方矩阵（tool-recipes）

> 定位：三库「蓝队技能与脚本参数模式」的价值转化层。每个工具族给出：**用途 / 前置本地数据源 / 命令或查询模板 / 输出解析 / 证据字段 / ATT&CK 或检测映射 / 误报调优要点 / 边界（零网络、只读）/ dry-run 语义**。
> 主要上游（ACS，改写不整篇复制）：`building-detection-rules-with-sigma`、`building-detection-rule-with-splunk-spl`、`analyzing-security-logs-with-splunk`、`analyzing-windows-event-logs-in-splunk`、`performing-alert-triage-with-elastic-siem`、`building-threat-intelligence-enrichment-in-splunk`、`deploying-osquery-for-endpoint-monitoring`、`configuring-windows-event-logging-for-detection`、`detecting-t1055-process-injection-with-sysmon`、`hunting-evtx-with-chainsaw`、`generating-forensic-timelines-with-hayabusa`、`building-incident-timeline-with-timesketch`、`building-super-timelines-with-plaso`、`performing-memory-forensics-with-volatility3`、`analyzing-memory-dumps-with-volatility`、`acquiring-disk-image-with-dd-and-dcfldd`、`analyzing-network-traffic-for-incidents`、`performing-network-traffic-analysis-with-zeek`、`detecting-network-anomalies-with-zeek`、`performing-malware-triage-with-yara`、`performing-yara-rule-development-for-detection`、`analyzing-dns-logs-for-exfiltration`、`analyzing-browser-forensics-with-hindsight`、`analyzing-linux-audit-logs-for-intrusion`、`auditing-cloud-with-cis-benchmarks`、`benchmarking-kubernetes-with-kube-bench`、`hardening-docker-daemon-configuration`、`auditing-kubernetes-cluster-rbac`、`performing-alert-triage-with-elastic-siem`。
> 参数纪律来源：Strix（非交互、预算、退出码 `0/1/2`、产物落盘）；ACS 809 个 `agent.py` 的参数化模式（`argparse` 显式参数、`--output` 落盘、结构化错误；统计见 `references/blue/extraction-ledger.md` §7）。
> 占位符：`<EXPORT>`、`<EVIDENCE>`、`<IMAGE>`、`<MEMORY>`、`<PCAP>`、`<LOG_DIR>`、`<RULES>`、`<RULE_FILE>`、`<SIGMA_DIR>`、`<WORKDIR>`、`<THRESHOLD>`、`<START>`、`<END>`、`<INDEX>`、`<PROFILE>`、`<DATASET>`。示例目标只用保留域与文档网段。
> 版本时效：工具 flag 以 2026-11-19 复核为准；工具大版本升级后重跑模板并更新本文件 `last-verified`（尤其 `--json`/`--output` 输出结构）。

## 0. 蓝队通用纪律（所有族共用）

1. **零网络**：本插件不联网。所有族只处理**本地导出**（日志、遥测、镜像、内存、pcap、云审计、基线文件）；需要联网的富化一律改为「离线导入」，不得在 workflow 里发起请求。
2. **只读**：数据源只读打开，不写回、不改名、不移动；分析产物写 `<WORKDIR>/<phase>/<tool>-<ts>/`。
3. **证据先行**：每个族的输出必须能落到「文件 + 定位 + 哈希」；没有定位的结论不写进 finding。
4. **参数化**：时间窗、阈值、路径、字段名全部占位符化；不在配方里写死环境值。
5. **非交互**：一律加非交互/静默参数（`-quiet`、`--json`、`-nointeractive`、`--force-overwrite` 视工具而定，禁止进 TUI）。
6. **退出码**：`0` 正常完成（含「无命中」）；`1` 执行错误（工具缺失、输入不可读、格式不符）；`2` 有候选结论（仅在工具原生支持时，例如规则命中）。`2` 不等于「已定性」，必须交复核。
7. **去敏**：输出与报告不含明文凭据、令牌、私钥、个人数据；哈希只记录文件哈希，不记录口令哈希。
8. **dry-run 语义**：`dryRun=true` 时只做「读文件 + 出计划 + 出统计」，不写分析产物正文（可写计划与清单）；本插件所有族都无目标侧动作，`dryRun=false` 也只增加本地处理深度。

## B1 检测规则调试（Sigma / pySigma）

- **用途**：把行为断言写成 Sigma 规则，做语法校验、字段规范化与目标引擎转译；是 `dsh-blue-detect` 的第一站。
- **前置本地数据源**：规则文件目录、字段映射表（本地）、目标引擎的字段命名约定（离线文档）；pySigma 与后端**预装在分析机**（不联网安装）。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 语法校验：先看结构与必填字段
sigma check <RULE_FILE>
# 列出可用的转译目标（离线）
sigma list targets
# 转译到 Splunk（注意：使用本地 pipeline 配置，不拉取远端）
sigma convert -t splunk -p <PIPELINE> <RULE_FILE> > <WORKDIR>/detect/<RULE_ID>.spl
# 批量校验目录下的全部规则
sigma check <SIGMA_DIR>
```

- **输出解析**：`sigma check` 逐条给出 error/warning（校验器名 + 位置）；`sigma convert` 输出目标查询文本，需人工核对字段名与时间宏。转译产物按 `<RULE_ID>.<engine>` 命名，便于回溯。
- **证据字段**：`ruleId`、`ruleSha256`、`validatorOutput`（原文）、`convertedQuery`、`engine`、`convertedAt`、`pipelineRef`。
- **ATT&CK 或检测映射**：规则 `tags` 的 `attack.t####[.###]`；映射进覆盖矩阵（`references/purple/coverage-matrix.md` §4）。
- **误报调优要点**：先补 `filter_*` 再收紧 `selection_core`；白名单必须带负责人与复核日期；`level` 用于排序而非信心。
- **边界**：不部署规则、不改目标 SIEM；不联网 `pip install`；不把转译产物当「已验证」（必须跑样例）。
- **dry-run**：`true` → 只跑 `check`，不写转译产物；`false` → 写转译文件与日志。

## B2 SIEM 查询与本地回放（Splunk SPL / KQL / Elastic）

- **用途**：在**已导出的**查询结果或本地索引上重放检测逻辑，产出可复算的命中集；也是 `dsh-blue-hunt` 的查询草稿落地方式。
- **前置本地数据源**：`kind ∈ {siem, logs, telemetry-export}` 的导出文件（JSONL/CSV）；Splunk 侧可用离线 `splunk` 实例的本地索引（若授权方提供）；KQL 侧用本地导出 + 文本/JSON 处理替代在线查询。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 本地回放：对导出的 JSONL 做等价筛选（不连 SIEM）
jq -c 'select(.EventID == <EVENT_ID>) | {ts:.TimeCreated, host:.Computer, user:.SubjectUserName, cmd:.CommandLine}' <EXPORT> > <WORKDIR>/siem/hits.jsonl
# 阈值聚合：按实体与时间桶计数
jq -r '.user' <WORKDIR>/siem/hits.jsonl | sort | uniq -c | sort -rn | head -50
# 时间窗过滤（RFC 3339 字符串可直接比较）
jq -c --arg s "<START>" --arg e "<END>" 'select(.ts >= $s and .ts < $e)' <EXPORT> > <WORKDIR>/siem/window.jsonl
```

```spl
| tstats summariesonly=true count from datamodel=<DATAMODEL> where <FILTER> by _time span=5m <ENTITY_FIELDS>
| where count >= <THRESHOLD>
```

```kql
<TableName>
| where Timestamp between (datetime(<START>) .. datetime(<END>))
| where <Field> <operator> "<VALUE>"
| summarize hits = count() by <EntityField>, bin(Timestamp, 5m)
| where hits >= <THRESHOLD>
```

- **输出解析**：`jq` 输出的 JSONL 每行一条命中，字段即证据；聚合命令给出「实体 → 计数」；SPL/KQL 模板交 SIEM 侧执行时，结果必须导出为文件再回来分析（保证可复算）。
- **证据字段**：`queryText`（含参数）、`dataSourceRef`、`window`、`hitCount`、`sampleLocators`（`L<行号>` 或记录 ID）、`exportSha256`。
- **ATT&CK 或检测映射**：查询对应规则的 `attackIds`；无规则的临时查询需在 `hunt-plan.json` 里挂假设 ID。
- **误报调优要点**：先跑对照窗口取基线量级；实体字段去域名前缀与大小写差异；阈值参数化并在结论阶段按基线定值；避免「计数 > 0」当唯一条件。
- **边界**：不在线调用 SIEM；不导出超过 `scope.dataHandling.retain` 声明的数据；查询结果不含凭据字段（必要时只保留「是否存在」布尔）。
- **dry-run**：`true` → 只输出查询计划与预估命中字段；`false` → 写命中集与聚合结果。

## B3 EDR 与主机遥测（Sysmon / EDR 导出 / osquery）

- **用途**：从进程、文件、网络、注册表遥测里取行为证据；是执行、凭据访问、持久化、横向类检测的主要数据面。
- **前置本地数据源**：`kind="edr"` 的 JSONL 导出、Sysmon 事件导出（XML/JSONL）、`kind="logs"` 的 Windows 事件导出；osquery 仅在**分析机或授权主机**上本地执行。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# EDR JSONL：进程访问 LSASS 的高风险掩码（字段名按导出映射替换）
jq -c 'select(.TargetImage|test("<LSASS_PATTERN>$")) | select(.GrantedAccess|IN("0x1010","0x1038","0x1fffff"))' <EXPORT> > <WORKDIR>/edr/lsass-access.jsonl
# 进程树：按 GUID/父子关系还原（字段名按导出映射替换）
jq -r '[.ProcessGuid, .ParentProcessGuid, .Image, .CommandLine] | @tsv' <EXPORT> | sort > <WORKDIR>/edr/proctree.tsv
# 网络会话：远端地址与端口的分布
jq -r '[.DestinationIp, .DestinationPort] | @tsv' <EXPORT> | sort | uniq -c | sort -rn | head -50
# osquery（仅本机/授权主机，只读表）
osqueryi --json "select pid, name, path, cmdline from processes where name = '<PROCESS_NAME>';"
```

- **输出解析**：JSONL 每行一事件；`proctree.tsv` 用于还原父子链（`ParentProcessGuid` 关联）；`uniq -c` 分布用于标记异常远端；osquery 输出为 JSON 数组，字段名即表列名。
- **证据字段**：`EventID`/`event.type`、`UtcTime`、`ProcessGuid`、`Image`、`ParentImage`、`CommandLine`、`TargetImage`、`GrantedAccess`、`DestinationIp/Port`、`exportSha256`、`locator`。
- **ATT&CK 或检测映射**：T1055（进程注入）、T1003（凭据转储）、T1053/T1543（持久化）、T1021（远程服务）、T1071（应用层 C2）。
- **误报调优要点**：白名单必须含安全代理、备份、监控、补丁分发；`CommandLine` 被裁剪时降级为 `undetermined`；同一 GUID 的多条事件先去重再计数。
- **边界**：不改目标主机状态；osquery 只查不写（禁用 `--enable_*` 之类写操作）；不采集凭据内容，只记录「可访问性」。
- **dry-run**：`true` → 只统计字段可用性与事件量级；`false` → 写命中集与进程树。

## B4 日志解析与规范化（EVTX / JSONL / 正则）

- **用途**：把异构日志统一成时间线可用的行（统一时间、主体、动作、对象），并保留可回溯定位。
- **前置本地数据源**：EVTX 导出目录、JSONL/CSV 导出、应用日志文本；本地签名/规则库（离线）。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# EVTX 批量检索：用 Sigma 规则目录做匹配，输出 JSON 结果
chainsaw hunt <EVIDENCE> -s <SIGMA_DIR> --json --output <WORKDIR>/parse/chainsaw.json
# 快速时间线（EVTX 专用扫描器，输出 CSV）
hayabusa csv-timeline -d <EVIDENCE> -o <WORKDIR>/parse/hayabusa.csv -w
# 规范化：把任意 JSONL 映射到统一字段（时间/主体/动作/对象）
jq -c '{ts:(.ts // .TimeCreated // .UtcTime), actor:(.user // .SubjectUserName // .Image), action:(.action // .EventID), object:(.object // .TargetImage // .TargetFilename), src:"<SOURCE_NAME>"}' <EXPORT> > <WORKDIR>/parse/normalized.jsonl
# 文本日志按正则抽取（先 dry-run 只统计行数）
grep -c -E '<REGEX>' <LOG_FILE>
```

- **输出解析**：`chainsaw` 的 JSON 含规则命中与原始事件；`hayabusa.csv` 每行一条事件（含时间、主机、事件 ID、摘要）；`normalized.jsonl` 是统一 schema，直接喂 B5 时间线。
- **证据字段**：`source`（文件名）、`sourceSha256`、`locator`（行号/记录 ID）、`rawExcerpt`（脱敏片段）、`normalizedFields`。
- **ATT&CK 或检测映射**：解析本身不映射；命中规则时继承规则的 `attackIds`。
- **误报调优要点**：时区与格式先在样本上验证；多行日志（含堆栈）按首行时间归类；`EventRecordID` 去重；正则锚定字段边界，避免子串误匹配。
- **边界**：不修改原始日志；不把日志中的字符串拼接进 shell；不推断缺失字段。
- **dry-run**：`true` → 只输出行数/字段覆盖率统计；`false` → 写规范化产物。

## B5 时间线与时间归一（plaso / Timesketch / hayabusa）

- **用途**：把多源事件合并成**可复算**的单一时间线（`timeline.json`），供分诊与影响判定。
- **前置本地数据源**：磁盘镜像、EVTX、文件系统元数据、应用日志、解析后的 `normalized.jsonl`。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 生成 plaso 存储（只读输入，输出写 workDir）
log2timeline.py --storage-file <WORKDIR>/timeline/<CASE>.plaso <IMAGE>
# 导出为可读时间线（CSV/JSONL）
psort.py -o json_line -w <WORKDIR>/timeline/<CASE>.jsonl <WORKDIR>/timeline/<CASE>.plaso
# 若使用 Timesketch：导出其 ingest 格式，离线导入（不连服务器）
psort.py -o timesketch -w <WORKDIR>/timeline/<CASE>.timesketch <WORKDIR>/timeline/<CASE>.plaso
```

- **输出解析**：`json_line` 每行一事件（`timestamp`、`source`、`message`、`parser`）；合并已有 `normalized.jsonl` 时按 `(ts, source, locator)` 排序，产出 `timeline.json`。
- **证据字段**：`ts`、`source`、`sourceSha256`、`locator`、`actor`、`action`、`object`、`confidence`；`recomputable=true`。
- **ATT&CK 或检测映射**：时间线事件可挂 `attackId`（当事件来源为规则命中时）；未映射事件保持空。
- **误报调优要点**：时间戳来源优先级（事件内 UTC > 采集端时间 > 文件时间）；文件系统双时间戳（`$SI`/`$FN`）都保留；同一事件多解析器重复时按 `(ts, source, locator)` 去重。
- **边界**：不补写缺失时间；不改原始证据；`timeline.json` 必须能回放到原始字节。
- **dry-run**：`true` → 只输出解析器清单与预估事件量；`false` → 写 `.plaso`/`.jsonl`。

## B6 磁盘取证（镜像与文件系统）

- **用途**：保全磁盘镜像并从中提取文件系统元数据、已删除项与特定文件，支撑落地、持久化与数据访问判定。
- **前置本地数据源**：只读块设备或已提供的镜像文件；本地取证工具链。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 采集镜像：带哈希、带日志、块级只读（输入为只读设备，输出写 workDir）
dcfldd if=<DEVICE> of=<WORKDIR>/disk/<CASE>.dd hash=sha256 hashlog=<WORKDIR>/disk/hash.log bs=4M
# 分区视图
mmls <WORKDIR>/disk/<CASE>.dd
# 文件清单（含已删除项 -d）
fls -r -p -o <PART_OFFSET> <WORKDIR>/disk/<CASE>.dd > <WORKDIR>/disk/fls.txt
# 按 inode 取单个文件（写出到 workDir，供离线分析）
icat -o <PART_OFFSET> <WORKDIR>/disk/<CASE>.dd <INODE> > <WORKDIR>/disk/extract-<INODE>.bin
```

- **输出解析**：`mmls` 给分区表偏移；`fls` 输出带 inode、名称、时间与 `(deleted)` 标记；`icat` 取出的文件单独哈希。
- **证据字段**：`imageSha256`、`imageBytes`、`partitionOffset`、`inode`、`path`、`timestamps`（`$SI`/`$FN`）、`extractSha256`。
- **ATT&CK 或检测映射**：T1105（工具落地）、T1547/T1543（持久化文件）、T1070（痕迹清理迹象）、T1486（加密影响）。
- **误报调优要点**：系统更新与安装器会大量创建/改写文件，需对照补丁窗口；`(deleted)` 项不等于恶意，需结合执行痕迹。
- **边界**：绝不写回镜像；不在原始镜像上挂载；不提取与案件无关的个人数据。
- **dry-run**：`true` → 只输出分区与文件系统类型；`false` → 写清单与提取物。

## B7 内存取证（Volatility 3 插件矩阵）

- **用途**：从内存镜像提取进程、命令行、网络连接、注入与模块痕迹；是「运行期行为」的唯一来源。
- **前置本地数据源**：内存镜像（RAW/LiME/崩溃转储）、匹配版本的符号表（离线）。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 先确认镜像与符号可用（不解析全量）
vol -f <MEMORY> windows.<PLUGIN_INFO>   # 镜像信息类插件（windows 前缀族）
# 进程与命令行
vol -f <MEMORY> windows.pslist > <WORKDIR>/mem/pslist.txt
vol -f <MEMORY> windows.cmdline > <WORKDIR>/mem/cmdline.txt
# 网络连接（含已关闭）
vol -f <MEMORY> windows.netscan > <WORKDIR>/mem/netscan.txt
# 注入/异常内存区域
vol -f <MEMORY> windows.malfind > <WORKDIR>/mem/malfind.txt
# Linux 镜像（按需）
vol -f <MEMORY> linux.pslist > <WORKDIR>/mem/linux-pslist.txt
```

- **输出解析**：`pslist` 的 PID/PPID 构建进程树；`cmdline` 对齐 PID 给命令行；`netscan` 给五元组与状态；`malfind` 给可疑内存区（需与签名/路径交叉）。
- **证据字段**：`memorySha256`、`plugin`、`rowLocator`（PID/偏移）、`pid`、`ppid`、`image`、`cmdline`、`remoteAddr`、`protection`。
- **ATT&CK 或检测映射**：T1055（注入）、T1003（内存凭据访问迹象）、T1620（反射式加载）、T1071（C2 会话）。
- **误报调优要点**：符号版本不匹配会漏项——版本不符时结论降级；`malfind` 命中常见于 JIT/加密库，需与模块签名交叉；同一进程多行需按 PID 聚合。
- **边界**：不修改镜像；不提取明文凭据内容（只记录「可访问」）；不把字符串片段当结论。
- **dry-run**：`true` → 只跑 `info` 与插件可用性检查；`false` → 跑全量插件并落盘。

## B8 网络流量（Zeek / Suricata / tshark）

- **用途**：从 pcap 提取会话、DNS、TLS、HTTP 与告警，支撑 C2、隧道、外传与横向判定。
- **前置本地数据源**：pcap/pcapng、本地 Zeek 脚本目录、本地 Suricata 规则集。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# Zeek：批量解析到日志目录（conn/dns/http/tls/ssl）
zeek -r <PCAP> <SCRIPT_DIR> Log::default_logdir=<WORKDIR>/net/zeek
# Suricata：用本地规则离线跑 pcap
suricata -r <PCAP> -l <WORKDIR>/net/suricata -S <RULES> --runmode=single
# 会话统计（不解析载荷）
tshark -r <PCAP> -q -z conv,tcp > <WORKDIR>/net/conv-tcp.txt
# DNS 查询名分布
tshark -r <PCAP> -Y "dns.flags.response==0" -T fields -e dns.qry.name | sort | uniq -c | sort -rn | head -50
```

- **输出解析**：`conn.log` 给五元组、字节数、时长；`dns.log` 给查询名与响应；`tls.log` 给 SNI/证书；`suricata/eve.json` 每行一告警；`conv,tcp` 给会话排行。
- **证据字段**：`pcapSha256`、`flowId`、`firstSeen`、`lastSeen`、`bytesOut/In`、`sni`/`qryName`、`ruleId`（Suricata）、`locator`（包号/行号）。
- **ATT&CK 或检测映射**：T1071（应用层协议）、T1571（非标准端口）、T1048/T1041（外传）、T1071.004（DNS 隧道）、T1021（横向会话）。
- **误报调优要点**：先做会话聚合再判定；识别已知 SaaS/CDN 与备份流量；DNS 高阶子域与长标签是高价值信号但需与字节量结合；证书自签需结合首见时间。
- **边界**：不主动发包、不重放攻击流量；不解析载荷中的凭据；pcap 只读。
- **dry-run**：`true` → 只输出 pcap 元信息与会话数；`false` → 写 Zeek/Suricata 全部日志。

## B9 云审计日志（CloudTrail / 活动日志 / Cloud Audit / K8s audit）

- **用途**：从控制面审计重建「谁、何时、对什么资源、做了什么」，判定凭证滥用、权限提升、存储暴露与横向。
- **前置本地数据源**：云审计导出（JSONL/JSON）、IAM 凭证报告（CSV）、K8s 审计日志（JSONL）。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 控制面高危 API 与主体聚合
jq -r 'select(.eventName|IN("<API_1>","<API_2>")) | [.eventTime, .userIdentity.arn, .eventName, .sourceIPAddress, (.errorCode // "OK")] | @tsv' <EXPORT> > <WORKDIR>/cloud/highrisk.tsv
# 失败后成功：同一主体短窗口内的错误码序列
jq -r 'select(.errorCode != null) | [.userIdentity.arn, .errorCode, .eventTime] | @tsv' <EXPORT> | sort > <WORKDIR>/cloud/errors.tsv
# 源 IP 首见时间（用于与新主体/新地点交叉）
jq -r '[.sourceIPAddress, .eventTime] | @tsv' <EXPORT> | sort -k1,1 -k2,2 | awk '!seen[$1]++ {print}' > <WORKDIR>/cloud/ip-firstseen.tsv
# K8s 审计：敏感 verb 与主体
jq -r 'select(.verb|IN("create","delete","patch")) | [.requestReceivedTimestamp, .user.username, .verb, .objectRef.resource, .objectRef.namespace] | @tsv' <K8S_AUDIT> > <WORKDIR>/cloud/k8s-sensitive.tsv
```

- **输出解析**：TSV 每行一条控制面事件；`ip-firstseen` 用于标记「新源地址」；`errors` 序列用于识别「先失败后成功」；K8s 行给出主体与资源。
- **证据字段**：`eventTime`、`userIdentity`、`eventName`、`resource`、`sourceIPAddress`、`errorCode`、`mfaPresent`、`exportSha256`、`locator`。
- **ATT&CK 或检测映射**：T1078（有效账户滥用）、T1098（账号操纵）、T1530（存储访问）、T1562（防御削弱）、T1610/T1611（容器部署与逃逸迹象）。
- **误报调优要点**：运维自动化账号与 CI 主体先建白名单；重试产生重复事件需去重；控制面事件时间与资源创建时间分离；`sourceIPAddress` 可能是服务端代理地址。
- **边界**：不调用云 API、不读取对象内容；只处理导出文件；主体字段中的账号标识去敏后保留可关联的稳定别名。
- **dry-run**：`true` → 只统计主体与 API 分布；`false` → 写高危清单与首见表。

## B10 容器与 Kubernetes 基线（kube-bench / kube-score / kubectl 只读）

- **用途**：核查集群与容器运行时是否偏离基线（特权、宿主挂载、RBAC 泛绑定、网络策略缺失、镜像来源）。
- **前置本地数据源**：`kubectl get ... -o json` 导出、节点基线扫描结果、Docker/容器运行时配置导出（`daemon.json`）、镜像清单。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 基线扫描（离线运行，结果写文件）
kube-bench --json --outputfile <WORKDIR>/k8s/kube-bench.json
# 工作负载与 RBAC 只读清单
kubectl get pods -A -o json > <WORKDIR>/k8s/pods.json
kubectl get clusterrolebindings -o json > <WORKDIR>/k8s/crb.json
kubectl get networkpolicies -A -o json > <WORKDIR>/k8s/netpol.json
# 静态评分（对已导出的清单，不上传）
kube-score score <WORKDIR>/k8s/pods.json
# 容器运行时配置核查（只读）
jq '.' <WORKDIR>/k8s/daemon.json
```

- **输出解析**：`kube-bench.json` 按控制项给 `PASS/FAIL/WARN/INFO`；`pods.json` 用于查 `securityContext.privileged`、`hostPath`、`hostNetwork`；`crb.json` 查 `cluster-admin` 泛绑定；`netpol.json` 判命名空间覆盖。
- **证据字段**：`controlId`、`status`、`namespace`、`workload`、`container`、`image`、`findingRef`、`exportSha256`。
- **ATT&CK 或检测映射**：T1610（部署容器）、T1611（逃逸）、T1609（容器管理命令）、T1552（容器内凭据暴露）。
- **误报调优要点**：系统命名空间与平台组件常有特权需求，需按命名空间白名单；基线版本与集群版本必须匹配；`WARN` 与 `FAIL` 分开统计。
- **边界**：不创建/修改/删除资源，不 `exec` 进容器；不拉取镜像；只处理导出清单。
- **dry-run**：`true` → 只输出控制项清单与清单文件存在性；`false` → 跑扫描并落盘。

## B11 CIS 加固核查（oscap / lynis / Windows 只读导出）

- **用途**：按基线逐项核对配置与暴露面，产出 `gaps.json` 与 `remediation.json` 的输入。
- **前置本地数据源**：基线文件（SCAP 数据流/XCCDF/厂商基线导出）、主机配置导出、审计策略导出。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# Linux：SCAP 数据流离线评估，结果写 XML（不修复）
oscap xccdf eval --profile <PROFILE> --results <WORKDIR>/cis/results.xml <DATASET>
# 主机快速审计（只读，输出报告）
lynis audit system --quick --no-colors > <WORKDIR>/cis/lynis.txt
# Windows：导出安全策略到 workDir（只读导出，不改策略）
secedit /export /cfg <WORKDIR>\cis\secpol-<HOST>.inf
# 关键注册表项只读查询
reg query "<KEY_PATH>" /v <VALUE_NAME>
```

- **输出解析**：`results.xml` 的 `rule-result` 给 `pass/fail/notchecked`；`lynis.txt` 给 suggestion/warning 分组；`secpol.inf` 与基线期望值逐项比对。
- **证据字段**：`controlId`、`baselineVersion`、`expected`、`observed`、`status`、`evidenceRef`、`lastVerified`。
- **ATT&CK 或检测映射**：加固项对应削弱面（T1562 防御削弱、T1078 账户滥用、T1021 远程服务）；映射到 `gaps.json` 的 `severity` 说明即可。
- **误报调优要点**：基线版本与 OS 版本必须匹配（版本错配会产生大量假 `fail`）；`notchecked` 与 `fail` 分开统计；误报主要来自本地定制策略，需白名单附理由。
- **边界**：不做 `--remediate` 类动作；不改注册表/策略/服务；不重启。
- **dry-run**：`true` → 只输出将执行的命令与基线元信息；`false` → 跑评估并落盘结果。

## B12 威胁情报富化与规则资产（YARA / 离线 TI）

- **用途**：把离线导入的 IOC/规则与本地证据对齐，为 finding 提供上下文（家族、别名、首见、关联技术），并维护 YARA 规则资产。
- **前置本地数据源**：离线 TI 导出（CSV/JSON，STIX 2.1 bundle）、MISP/OpenCTI 导出文件、YARA 规则目录、样本目录（只读）。
- **命令或查询模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# YARA 扫描：只读样本目录，输出命中（不执行样本）
yara -r <RULES> <SAMPLE_DIR> > <WORKDIR>/ti/yara-hits.txt
# IOC 归一化：域名小写去尾点、IP 规范化、哈希小写
jq -r '.indicators[] | [.type, (.value|ascii_downcase), (.firstSeen // ""), (.source // "")] | @tsv' <TI_EXPORT> > <WORKDIR>/ti/iocs.tsv
# 本地证据中的 IOC 命中（示例：DNS 查询名）
jq -r '.qryName' <WORKDIR>/net/zeek/dns.log | sort --unique > <WORKDIR>/ti/dns-names.txt
comm -12 <WORKDIR>/ti/dns-names.txt <(awk -F'\t' '$1=="domain"{print $2}' <WORKDIR>/ti/iocs.tsv | sort --unique) > <WORKDIR>/ti/matches.txt
# 规则质量自检：规则数与语法错误（yara 编译检查）
yara -w <RULES> /dev/null 2> <WORKDIR>/ti/yara-warnings.txt || true
```

- **输出解析**：`yara-hits.txt` 每行「规则名 + 文件路径」；`iocs.tsv` 归一化后可直接做集合运算；`matches.txt` 是交集（命中 IOC 列表）。
- **证据字段**：`indicator`、`type`、`source`、`firstSeen`、`confidence`、`matchedEvidenceRef`、`ruleName`。
- **ATT&CK 或检测映射**：IOC 只能辅助定性，映射写「用于佐证某 `attackId`」，不得用 IOC 命中直接推断技术。
- **误报调优要点**：IOC 有时效（域名/URL 尤其），过期 IOC 只作历史参考；YARA 规则需限定文件类型与大小；`wide`/`nocase` 滥用会放大误报；共享 CDN 域名不可作为单独判定依据。
- **边界**：不联网查询 TI/沙箱/WHOIS；不执行样本；不上传样本哈希到外部服务。
- **dry-run**：`true` → 只统计 IOC 数量与规则编译告警；`false` → 执行扫描与集合运算。

## 附：工具族 → 技能 / 参考 / 模板映射

| 工具族 | 主用技能 | 关联参考 | 模板 |
|---|---|---|---|
| B1 规则调试 | `dsh-blue-detect` | `references/blue/detect-engineering.md` §3/§4 | `templates/sigma.yml` |
| B2 SIEM 查询 | `dsh-blue-detect`、`dsh-blue-hunt` | `detect-engineering.md` §4/§6 | `templates/kql.md`、`templates/spl.md` |
| B3 EDR 遥测 | `dsh-blue-hunt`、`dsh-blue-detect` | `hunt-hypothesis.md` §4 | `templates/sigma.yml` |
| B4 日志解析 | `dsh-blue-dfir` | `dfir-playbook.md` §3 | — |
| B5 时间线 | `dsh-blue-dfir` | `dfir-playbook.md` §3 | — |
| B6 磁盘取证 | `dsh-blue-dfir` | `dfir-playbook.md` §2/§4 | — |
| B7 内存取证 | `dsh-blue-dfir` | `dfir-playbook.md` §4 | — |
| B8 网络流量 | `dsh-blue-dfir`、`dsh-blue-hunt` | `dfir-playbook.md` §5 | — |
| B9 云审计 | `dsh-blue-dfir`、`dsh-blue-harden` | `dfir-playbook.md` §6 | — |
| B10 容器与 K8s | `dsh-blue-harden` | `harden-baseline.md` §5 | — |
| B11 CIS 核查 | `dsh-blue-harden` | `harden-baseline.md` §3/§4 | — |
| B12 TI 富化 | `dsh-purple-verify`、`dsh-blue-detect` | `coverage-matrix.md` §4 | — |