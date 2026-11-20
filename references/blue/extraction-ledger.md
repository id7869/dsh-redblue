<!-- dsh-redblue:provenance
source-repo: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
source-commit: 54a798831d2266a3ca61ce68a7acb80b81160d57
source-license: Apache-2.0
source-path: skills/building-detection-rules-with-sigma/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 818 个 ACS 技能的逐组处置台账与 809 个 agent.py 的模式挖掘统计；只保留统计与改写要点，不搬运任何脚本
-->

# ACS 提取台账（extraction-ledger）

> 目的：证明 `.work/sources/acs` 的 **818 个技能**与其中 **809 个 `scripts/agent.py`** 被逐组处置、无静默遗漏；并给出脚本参数模式的量化底稿，支撑 `references/shared/script-patterns.md` 与 `references/blue/tool-recipes.md`。
> 决策定义：`keep` = 某篇派生参考的主干来源；`merge` = 与同族内容合并吸收（非主干）；`drop` = 不吸收（红队执行与武器化、纯治理认证、超限单文件）。
> 与红队侧台账的关系：`references/red/extraction-ledger.md` 处置 Claude-Red（79）与 Strix（9）；本台账只处置 ACS，二者不重叠。
> 版本时效：技能清单与字节数取自 pin 的 commit（`54a7988…`），2026-11-19 实测；上游新增技能后必须在本账追加行并更新合计。
> 数据边界：ACS 的 `SKILL.md`、`references/` 与 `agent.py` 都是**只读输入**；本插件不打包任何 `agent.py`、不复制其代码，只保留**统计结果**与**改写后的方法论**。

## 1. 库存基线（实测）

| 项 | 数量/数值 | 采集方式 |
|---|---|---|
| 技能目录（`skills/<name>/`） | 818 | `ls .work/sources/acs/skills \| wc -l` |
| 含 `scripts/agent.py` 的技能 | 809 | `find skills -name agent.py \| wc -l` |
| 不含 `agent.py` 的技能 | 9 | 见 §1.1 |
| `references/` 文件总数 | 1,457 | 逐技能统计（含子目录） |
| `references/` 总字节 | 3,466,429 B | 逐技能统计 |
| `SKILL.md` 总字节 | 8,062,052 B | 逐技能统计 |
| `SKILL.md` 单文件范围 | 2,172–52,765 B | 同上（最大者见 §5.3） |
| `agent.py` 总字节 | 6,586,090 B | 逐文件 stat |
| `agent.py` 单文件范围 | 3,614–64,215 B（中位 7,073，P90 9,941） | 同上 |
| `agent.py` 总行数 | 171,017 行（中位 183，P90 261，最大 1569） | 逐文件统计 |

### 1.1 无 `agent.py` 的 9 个技能（纯方法论文本）

`achieving-cmmc-level-2-compliance`、`conducting-cyber-risk-assessment-with-nist-800-30`、`conducting-gdpr-compliance-assessment`、`deploying-cloud-deception-with-decoy-resources`、`designing-adversary-engagement-with-mitre-engage`、`executing-nist-rmf-authorization-to-operate`、`implementing-hipaa-security-rule-safeguards`、`managing-third-party-vendor-risk`、`performing-cloud-native-threat-hunting-with-aws-detective`

> 处置：全部落在 §4 的 merge 组（治理与方法论类），不因缺脚本而特殊处理。

## 2. 判定规则（有序、可复算）

判定按下列顺序**首个命中即定案**，保证同一输入得到同一结果（复算见 §6.2）：

| 序 | 规则 | 条件 | 决策 |
|---:|---|---|---|
| 1 | `K1 keep` | 技能名 ∈ §3「kept 名单」（60 个，逐条指定主干归属） | keep |
| 2 | `D1 drop-red` | 名称匹配红队执行或武器化前缀/关键词：`abusing-`、`attacking-`、`bypassing-`、`coercing-`、`escaping-`、`exploiting-`、`relaying-`、`extracting-credentials`/`extracting-config`、`building-c2-`、`building-red-team-c2-`、`conducting-*penetration`/`red-team`/`social-engineering`/`spearphishing`/`pass-the`/`domain-persistence`/`man-in-the-middle`、`executing-phishing`/`red-team`/`active-directory-attack`、`enumerating-cloud-with-*`、`continuous-llm-red-teaming`、以及 `*with-metasploit`/`with-pacu`/`with-covenant`/`with-certipy`/`with-impacket`/`cobalt-strike-*-config` | drop |
| 3 | `D2 drop-gov` | 名称 ∈ 纯治理/认证/项目管理清单（14 个具名，见 §5.2） | drop |
| 4 | `D3 drop-size` | `SKILL.md` > 48 KiB（等于本插件单篇参考上限，无法整体吸收） | drop |
| 5 | `M merge` | 其余全部 | merge（按 §4 分 7 组） |

判定理由汇总：

- **D1**：这些技能的主干价值是「怎么打」，而本插件的蓝队/紫队消费者只需要「怎么看得见」。执行步骤与武器化内容同时触碰 R3（无武器化制品）与 R12（report-only）；保留其检测视角的成本高于收益，因此不吸收。红队侧能力由 Claude-Red/Strix 的改写参考承载，不在本台账范围。
- **D2**：纯合规认证与项目管理类技能产出流程与文档，不含遥测字段或配置基线；`harden` 只吸收**可核查的控制项**，因此这类技能排除。
- **D3**：本插件单篇参考上限 48 KiB；超限文件只能被压缩改写，按规则不整体吸收（其检测要点已在 `detect-engineering.md` 的 DNS/C2 小节覆盖）。

## 3. kept 名单（60 个主干来源）

`keep` 表示该技能是目标参考文件某一节的**主干来源**；同一参考文件另有多个 `merge` 来源（见 §4）。

| # | ACS 技能 | 目标文件 | 吸收点 |
|---:|---|---|---|
| 1 | `building-threat-hunt-hypothesis-framework` | `references/blue/hunt-hypothesis.md` | §2 五元组假设结构与三态收口 |
| 2 | `hunting-advanced-persistent-threats` | `references/blue/hunt-hypothesis.md` | §8 持久化与隐蔽信道类假设 |
| 3 | `hunting-for-cobalt-strike-beacons` | `references/blue/hunt-hypothesis.md` | §8 心跳与信标假设、§9 周期误判 |
| 4 | `hunting-for-living-off-the-land-binaries` | `references/blue/hunt-hypothesis.md` | §8 系统二进制滥用假设 |
| 5 | `hunting-for-persistence-mechanisms-in-windows` | `references/blue/hunt-hypothesis.md` | §8 持久化假设族 |
| 6 | `fleet-hunting-with-velociraptor` | `references/blue/hunt-hypothesis.md` | §4 批量遥测导出与字段体检 |
| 7 | `performing-threat-hunting-with-elastic-siem` | `references/blue/hunt-hypothesis.md` | §4 SIEM 查询草稿纪律 |
| 8 | `hunting-for-data-exfiltration-indicators` | `references/blue/hunt-hypothesis.md` | §8 外传假设与字节量基线 |
| 9 | `building-detection-rules-with-sigma` | `references/blue/detect-engineering.md` | §3 Sigma 结构规范与 §4 转译差异 |
| 10 | `building-detection-rule-with-splunk-spl` | `references/blue/detect-engineering.md` | §4 SPL 聚合与 tstats 写法 |
| 11 | `implementing-endpoint-detection-with-wazuh` | `references/blue/detect-engineering.md` | §5 EDR 侧规则与日志映射 |
| 12 | `detecting-t1055-process-injection-with-sysmon` | `references/blue/detect-engineering.md` | §5 注入类正例与反例样例 |
| 13 | `detecting-lateral-movement-with-zeek` | `references/blue/detect-engineering.md` | §2 数据源明确与 §6 阈值抑制 |
| 14 | `detecting-credential-dumping-techniques` | `references/blue/detect-engineering.md` | §5 访问掩码高风险集合 |
| 15 | `detecting-container-runtime-threats-with-falco` | `references/blue/detect-engineering.md` | §5 运行时规则与特权判定 |
| 16 | `performing-yara-rule-development-for-detection` | `references/blue/detect-engineering.md` | §6 规则资产质量与误报面 |
| 17 | `detecting-aws-cloudtrail-anomalies` | `references/blue/detect-engineering.md` | §4 云控制面转译口径 |
| 18 | `building-cloud-siem-with-sentinel` | `references/blue/detect-engineering.md` | §4 KQL 聚合与阈值写法 |
| 19 | `building-incident-timeline-with-timesketch` | `references/blue/dfir-playbook.md` | §3 时间线排序键与可复算 |
| 20 | `building-super-timelines-with-plaso` | `references/blue/dfir-playbook.md` | §3 多源时间归一 |
| 21 | `analyzing-network-traffic-for-incidents` | `references/blue/dfir-playbook.md` | §5 网络取证与会话聚合 |
| 22 | `conducting-cloud-incident-response` | `references/blue/dfir-playbook.md` | §6 云 IR 数据源与去重 |
| 23 | `performing-memory-forensics-with-volatility3` | `references/blue/dfir-playbook.md` | §4 内存插件矩阵与符号时效 |
| 24 | `analyzing-memory-dumps-with-volatility` | `references/blue/dfir-playbook.md` | §4 注入与网络连接判定 |
| 25 | `analyzing-linux-audit-logs-for-intrusion` | `references/blue/dfir-playbook.md` | §3 审计日志时间归一 |
| 26 | `hunting-evtx-with-chainsaw` | `references/blue/dfir-playbook.md` | §4 EVTX 检索与规则匹配 |
| 27 | `generating-forensic-timelines-with-hayabusa` | `references/blue/dfir-playbook.md` | §3 快速时间线与字段 |
| 28 | `performing-cloud-forensics-with-aws-cloudtrail` | `references/blue/dfir-playbook.md` | §6 控制面事件时间分离 |
| 29 | `triaging-security-incident-with-ir-playbook` | `references/blue/dfir-playbook.md` | §1 五阶段与完成判定 |
| 30 | `acquiring-disk-image-with-dd-and-dcfldd` | `references/blue/dfir-playbook.md` | §2 镜像采集与哈希 |
| 31 | `implementing-velociraptor-for-ir-collection` | `references/blue/dfir-playbook.md` | §2 采集方式与链式保管 |
| 32 | `hardening-linux-endpoint-with-cis-benchmark` | `references/blue/harden-baseline.md` | §3 Linux 控制项与只读核查 |
| 33 | `hardening-windows-endpoint-with-cis-benchmark` | `references/blue/harden-baseline.md` | §4 Windows 控制项与只读导出 |
| 34 | `auditing-cloud-with-cis-benchmarks` | `references/blue/harden-baseline.md` | §6 云控制项 |
| 35 | `benchmarking-kubernetes-with-kube-bench` | `references/blue/harden-baseline.md` | §5 集群基线扫描 |
| 36 | `performing-kubernetes-cis-benchmark-with-kube-bench` | `references/blue/harden-baseline.md` | §5 控制项映射 |
| 37 | `hardening-docker-daemon-configuration` | `references/blue/harden-baseline.md` | §5 运行时配置核查 |
| 38 | `implementing-rbac-hardening-for-kubernetes` | `references/blue/harden-baseline.md` | §5 RBAC 泛绑定判定 |
| 39 | `auditing-kubernetes-cluster-rbac` | `references/blue/harden-baseline.md` | §5 RBAC 只读清单 |
| 40 | `implementing-application-whitelisting-with-applocker` | `references/blue/harden-baseline.md` | §4 攻击面缩减控制项 |
| 41 | `configuring-windows-defender-advanced-settings` | `references/blue/harden-baseline.md` | §4 端点防护控制项 |
| 42 | `implementing-file-integrity-monitoring-with-aide` | `references/blue/harden-baseline.md` | §3 完整性监控控制项 |
| 43 | `implementing-mitre-attack-coverage-mapping` | `references/purple/coverage-matrix.md` | §1 三态矩阵与 §5 判定细则 |
| 44 | `mapping-mitre-attack-techniques` | `references/purple/coverage-matrix.md` | §3 动作到技术映射 |
| 45 | `performing-purple-team-atomic-testing` | `references/purple/coverage-matrix.md` | §7 补测验收标准 |
| 46 | `performing-purple-team-exercise` | `references/purple/coverage-matrix.md` | §8 只读产物与退出码 |
| 47 | `analyzing-threat-actor-ttps-with-mitre-attack` | `references/purple/coverage-matrix.md` | §4 技术层核对 |
| 48 | `performing-threat-emulation-with-atomic-red-team` | `references/purple/coverage-matrix.md` | §7 重放验证 |
| 49 | `analyzing-security-logs-with-splunk` | `references/blue/tool-recipes.md` | B2 查询模板与解析 |
| 50 | `analyzing-windows-event-logs-in-splunk` | `references/blue/tool-recipes.md` | B2 事件字段映射 |
| 51 | `performing-alert-triage-with-elastic-siem` | `references/blue/tool-recipes.md` | B2 告警分诊与阈值 |
| 52 | `triaging-security-alerts-in-splunk` | `references/blue/tool-recipes.md` | B2 结果聚合与回溯 |
| 53 | `correlating-security-events-in-qradar` | `references/blue/tool-recipes.md` | B2 多源关联口径 |
| 54 | `deploying-osquery-for-endpoint-monitoring` | `references/blue/tool-recipes.md` | B3 主机遥测只读查询 |
| 55 | `configuring-windows-event-logging-for-detection` | `references/blue/tool-recipes.md` | B4 日志配置与字段可用性 |
| 56 | `performing-malware-triage-with-yara` | `references/blue/tool-recipes.md` | B12 规则资产与样本只读 |
| 57 | `analyzing-dns-logs-for-exfiltration` | `references/blue/tool-recipes.md` | B8/B12 DNS 查询名与字节量 |
| 58 | `conducting-memory-forensics-with-volatility` | `references/blue/tool-recipes.md` | B7 插件与证据字段 |
| 59 | `analyzing-browser-forensics-with-hindsight` | `references/blue/tool-recipes.md` | B4 浏览器取证解析 |
| 60 | `building-threat-intelligence-enrichment-in-splunk` | `references/blue/tool-recipes.md` | B12 离线 TI 富化 |

> 60 个 keep 的分配：hunt 8 / detect 10 / dfir 13 / harden 11 / purple 6 / tool-recipes 12。`templates/` 与 `script-patterns.md` 不单独占 keep，它们的输入是这些技能的命令/字段模式与 §7 的脚本统计。

## 4. merge 分组（672 个，按名称主题归类）

| 组 | 主题 | 数量 | 代表技能（每组取样） |
|---|---|---:|---|
| M1 | 检测规则与遥测 | 118 | `analyzing-api-gateway-access-logs`、`analyzing-azure-activity-logs-for-threats`、`analyzing-kubernetes-audit-logs`、`analyzing-network-flow-data-with-netflow` |
| M2 | 威胁狩猎 | 33 | `hunting-bootkits-in-efi-system-partition`、`hunting-credential-stuffing-attacks`、`hunting-for-anomalous-powershell-execution`、`hunting-for-beaconing-with-frequency-analysis` |
| M3 | 事件响应与取证 | 96 | `analyzing-android-malware-with-apktool`、`analyzing-bootkit-and-rootkit-samples`、`analyzing-command-and-control-communication`、`analyzing-disk-image-with-autopsy` |
| M4 | 加固与基线 | 192 | `analyzing-sbom-for-supply-chain-vulnerabilities`、`assessing-vector-and-embedding-weaknesses`、`auditing-aws-s3-bucket-permissions`、`auditing-azure-active-directory-configuration` |
| M5 | 威胁情报与对抗画像 | 32 | `analyzing-campaign-attribution-evidence`、`analyzing-cyber-kill-chain`、`analyzing-indicators-of-compromise`、`analyzing-ransomware-leak-site-intelligence` |
| M6 | 紫队与对抗仿真 | 16 | `analyzing-apt-group-with-mitre-navigator`、`analyzing-threat-actor-ttps-with-mitre-navigator`、`deploying-active-directory-honeytokens`、`deploying-cloud-deception-with-decoy-resources` |
| M7 | 其余防御性控制与平台工程 | 185 | `analyzing-active-directory-acl-abuse`、`analyzing-certificate-transparency-for-phishing`、`analyzing-cloud-storage-access-patterns`、`analyzing-ethereum-smart-contract-vulnerabilities` |
| — | **合计** | **672** | — |

分组依据（按顺序**首命中优先**，全部为名称匹配，可复算）：

| 组 | 判定依据（名称匹配，节选） |
|---|---|
| M2 | `^hunting-`、`threat-hunt`、`hypothesis` |
| M1 | `^detecting-`、`^building-detection`、`detection-rule`；以及含 `log`/`siem`/`splunk`/`elastic`/`qradar`/`wazuh`/`zeek`/`suricata`/`yara`/`falco`/`osquery`/`sysmon`/`evtx`/`netflow`/`snort`/`telemetry`/`alert`/`beaconing` |
| M6 | `purple`、`atomic-red`、`mitre-navigator`、`coverage-map`、`adversary-engagement`、`deception`、`honeypot`/`honeytoken`/`canary`/`decoy`、`tabletop`、`wargam`、`emulating-` |
| M5 | `threat-intel`、`misp`、`opencti`、`stix`/`taxii`、`indicator`、`attribution`、`threat-actor`、`campaign`、`apt-`、`osint`、`diamond-model`、`kill-chain`、`intelligence-feed` |
| M3 | `forensic`、`incident`、`timeline`、`memory`、`disk`、`autopsy`、`plaso`、`timesketch`、`kape`、`chainsaw`、`hayabusa`、`hindsight`、`artifact`、`evidence`、`malware`、`rootkit`/`bootkit`、`intrusion`、`compromise`、`triage`、`containment`、`eradicat`、`recovery`、`breach`、`command-and-control`、`lateral-movement`、`exfiltration`、`ransomware-behavior` |
| M4 | `^hardening-`、`^auditing-`、`^benchmarking-`、`^configuring-`、`^securing-`、`^implementing-`、`^designing-`、`^operating-`、`^orchestrating-`、`^automating-`、`^integrating-`、`^modeling-`、`^validating-`、`^verifying-`、`^assessing-`、`^evaluating-`、`^remediating-`、`^monitoring-`、`^managing-`；以及 `baseline`/`benchmark`/`compliance`/`stig`/`zero-trust`/`segmentation`/`rbac`/`network-polic`/`bitlocker`/`applocker`/`vault`/`kms`/`mfa`/`sso`/`dlp`/`sbom`/`calico`/`patch` 等控制词 |
| M7 | 不命中以上任何规则（余集） |

吸收去向（组 → 目标文件）：

| 组 | 主要吸收到 |
|---|---|
| M1 | detect-engineering.md、templates/ |
| M2 | hunt-hypothesis.md（假设库与遥测矩阵） |
| M3 | dfir-playbook.md（保全/时间线/云 IR） |
| M4 | harden-baseline.md（控制项与复测） |
| M5 | coverage-matrix.md §4、tool-recipes.md B12 |
| M6 | coverage-matrix.md（三态与补测） |
| M7 | tool-recipes.md（数据源族）、harden-baseline.md（可迁移控制项） |

> merge 的含义是「压缩吸收判定要点，不逐条建文件」：每组给可追溯样例，组内其余技能按同一主题口径处理；同名主题冲突时以 `keep` 文件为准。

## 5. drop 名单（86 个）

### 5.1 D1 红队执行与武器化（71 个）

1. `abusing-dpapi-for-credential-access`
2. `abusing-shadow-credentials-for-privesc`
3. `analyzing-cobalt-strike-beacon-configuration`
4. `analyzing-cobaltstrike-malleable-c2-profiles`
5. `attacking-entra-id-with-roadtools`
6. `attacking-oauth-with-device-code-phishing`
7. `building-c2-infrastructure-with-sliver-framework`
8. `building-c2-redirector-infrastructure`
9. `building-red-team-c2-infrastructure-with-havoc`
10. `bypassing-authentication-with-forced-browsing`
11. `coercing-authentication-with-coercer-petitpotam`
12. `conducting-cloud-penetration-testing`
13. `conducting-domain-persistence-with-dcsync`
14. `conducting-external-reconnaissance-with-osint`
15. `conducting-full-scope-red-team-engagement`
16. `conducting-internal-network-penetration-test`
17. `conducting-internal-reconnaissance-with-bloodhound-ce`
18. `conducting-man-in-the-middle-attack-simulation`
19. `conducting-mobile-app-penetration-test`
20. `conducting-network-penetration-test`
21. `conducting-pass-the-ticket-attack`
22. `conducting-social-engineering-penetration-test`
23. `conducting-social-engineering-pretext-call`
24. `conducting-spearphishing-simulation-campaign`
25. `conducting-wireless-network-penetration-test`
26. `continuous-llm-red-teaming-with-promptfoo`
27. `enumerating-cloud-with-cloudfox`
28. `escaping-containers-to-host`
29. `executing-active-directory-attack-simulation`
30. `executing-phishing-simulation-campaign`
31. `executing-red-team-engagement-planning`
32. `executing-red-team-exercise`
33. `exploiting-active-directory-certificate-services-esc1`
34. `exploiting-active-directory-with-bloodhound`
35. `exploiting-adcs-with-certipy`
36. `exploiting-api-injection-vulnerabilities`
37. `exploiting-aws-with-pacu`
38. `exploiting-bgp-hijacking-vulnerabilities`
39. `exploiting-broken-function-level-authorization`
40. `exploiting-broken-link-hijacking`
41. `exploiting-constrained-delegation-abuse`
42. `exploiting-deeplink-vulnerabilities`
43. `exploiting-excessive-data-exposure-in-api`
44. `exploiting-http-request-smuggling`
45. `exploiting-idor-vulnerabilities`
46. `exploiting-insecure-data-storage-in-mobile`
47. `exploiting-insecure-deserialization`
48. `exploiting-ipv6-vulnerabilities`
49. `exploiting-jwt-algorithm-confusion-attack`
50. `exploiting-kerberoasting-with-impacket`
51. `exploiting-mass-assignment-in-rest-apis`
52. `exploiting-ms17-010-eternalblue-vulnerability`
53. `exploiting-nopac-cve-2021-42278-42287`（名称含 CVE 编号，编号内容待核实）
54. `exploiting-nosql-injection-vulnerabilities`
55. `exploiting-oauth-misconfiguration`
56. `exploiting-prototype-pollution-in-javascript`
57. `exploiting-race-condition-vulnerabilities`
58. `exploiting-server-side-request-forgery`
59. `exploiting-smb-vulnerabilities-with-metasploit`
60. `exploiting-sql-injection-vulnerabilities`
61. `exploiting-sql-injection-with-sqlmap`
62. `exploiting-template-injection-vulnerabilities`
63. `exploiting-type-juggling-vulnerabilities`
64. `exploiting-vulnerabilities-with-metasploit-framework`
65. `exploiting-websocket-vulnerabilities`
66. `exploiting-zerologon-vulnerability-cve-2020-1472`（名称含 CVE 编号，编号内容待核实）
67. `extracting-config-from-agent-tesla-rat`
68. `extracting-credentials-from-memory-dump`
69. `performing-cloud-penetration-testing-with-pacu`
70. `performing-red-team-with-covenant`
71. `relaying-ntlm-for-adcs-esc8`

### 5.2 D2 纯治理/认证/项目管理（14 个）

`achieving-cmmc-level-2-compliance`、`building-soc-metrics-and-kpi-tracking`、`building-vulnerability-aging-and-sla-tracking`、`building-vulnerability-dashboard-with-defectdojo`、`building-vulnerability-exception-tracking-system`、`conducting-cyber-risk-assessment-with-nist-800-30`、`conducting-gdpr-compliance-assessment`、`executing-nist-rmf-authorization-to-operate`、`implementing-anti-phishing-training-program`、`implementing-hipaa-security-rule-safeguards`、`managing-third-party-vendor-risk`、`performing-ransomware-tabletop-exercise`、`performing-soc-tabletop-exercise`、`performing-soc2-type2-audit-preparation`

### 5.3 D3 超限单文件（1 个）

`detecting-command-and-control-over-dns`（52,765 B）

> 该文件超过 48 KiB 上限；其 DNS/C2 检测要点已在 `references/blue/detect-engineering.md` §6 与 `references/blue/templates/kql.md` §5（DNS 隧道候选）以改写形式覆盖，原文件不搬运。

## 6. 合计账与复算

### 6.1 合计账

| 决策 | 数量 | 占 818 |
|---|---:|---:|
| keep | 60 | 60/818 |
| merge | 672 | 672/818 |
| drop（D1 71 + D2 14 + D3 1） | 86 | 86/818 |
| **合计** | **818** | **818/818** |

### 6.2 复算方法

```text
# 1) 库存核对（只读输入）
find .work/sources/acs/skills -maxdepth 1 -mindepth 1 -type d | wc -l     # 期望 818
find .work/sources/acs/skills -name agent.py | wc -l                     # 期望 809

# 2) 决策核对：keep 与 §3 表格逐行比对；drop 与 §5 三张清单比对
grep -c '^| [0-9]* | ' references/blue/extraction-ledger.md              # §3 数据行计数

# 3) 算术核对：keep + merge + drop = 818，且 merge = 818 - keep - drop
```

> 本账不做黑盒统计：keep 与 drop 都是**具名清单**，merge 是**余集**，三者天然互斥且穷尽 818。

## 7. 809 个 `agent.py` 的模式挖掘统计

统计口径：对 809 个文件做正则匹配，分别记录**命中文件数**（files）与**出现次数**（occ）。统计脚本是一次性分析工具，不随插件发布；本插件不打包任何脚本源码。

### 7.1 入口与参数化

| 模式 | 命中文件 | 出现次数 | 解读 |
|---|---:|---:|---|
| `if __name__ == "__main__"` 主守卫 | 809 | 809 | 全部脚本都是可独立执行的 CLI |
| `argparse` / `ArgumentParser` | 625 | 626 | 绝大多数用标准库参数解析 |
| `sys.argv`（手写解析） | 166 | 744 | 少数老式脚本手写解析 |
| `add_argument` | 621 | 3322 | 参数声明总数反映可配置面 |
| `required=True` | 335 | 733 | 必填参数比例决定「误用即失败」的程度 |
| `choices=` | 186 | 224 | 枚举约束（模式/格式类参数） |
| 既无 `argparse` 也无 `sys.argv` | 18 | — | 硬编码路径型脚本，复用价值最低 |

### 7.2 安全与授权门禁

| 模式 | 命中文件 | 出现次数 | 解读 |
|---|---:|---:|---|
| 授权语义（authoriz / authoris / written consent / --consent） | 303 | 757 | 多数脚本在文档串里声明「仅授权使用」 |
| 目标类参数（`--target`/`--host`/`--url`/`--domain`/`--scope`） | 144 | 182 | 目标入口普遍参数化 |
| **专用授权或 consent CLI 开关** | **3** | — | 几乎不存在：授权只写在文字里，**没有可机器的门禁** |
| `verify=False`（关闭 TLS 校验） | 36（字面量 `verify=False`：35） | 118 | 反模式：与 G-* 门禁和 R4 冲突，本插件一律禁止 |
| `shell=True` | 3 | 8 | 命令注入面 |
| `os.system(` | 2 | 2 | 同上，且无法捕获结构化输出 |
| `eval(` / `exec(` | 9 | 23 | 动态执行面 |
| `shell=True` 或 `os.system`（任一） | 4 | — | 需要显式参数化替代方案的脚本 |

### 7.3 安全默认（dry-run、限速、超时、重试）

| 模式 | 命中文件 | 出现次数 | 解读 |
|---|---:|---:|---|
| `dry[-_]run` 语义 | 8 | 71 | 几乎不实现安全默认 |
| `--dry-run` 开关 | 6 | 8 | 默认执行而非默认预览 |
| 限速（rate_limit / max_requests / throttle） | 21 | 138 | 大多数脚本不限速 |
| `timeout=` | 480 | 1410 | 超时是唯一普遍存在的保护 |
| `time.sleep` | 46 | 62 | 少量脚本用固定间隔代替限速 |
| 重试或退避 | 8 | 19 | 重试语义稀少且不统一 |
| `dry-run` + 限速 + 超时（同时具备） | 0 | — | 三者齐备的脚本不存在 |

### 7.4 输出与错误处理

| 模式 | 命中文件 | 出现次数 | 解读 |
|---|---:|---:|---|
| `json.dump` / `json.dumps` | 744 | 1275 | 结构化输出是主流 |
| `--output` / `output_dir` / `--report` | 590 | 1377 | 落盘参数普遍 |
| `print(` | 803 | 6438 | 进度靠打印，缺少结构化进度事件 |
| `try:` / `except` | 651 | 1866 | 异常处理普遍存在 |
| `sys.exit(`（其中 `exit(1)`） | 312（221） | 497（291） | 退出码以 0/1 为主，缺少 0/1/2 三态语义 |
| `logging` | 146 | 146 | 少数使用标准日志模块 |
| `raise *Error` | 25 | 47 | 结构化错误类型有限 |
| `@dataclass` | 6 | 7 | 返回结构体模型极少 |

### 7.5 领域语义

| 模式 | 命中文件 | 出现次数 | 解读 |
|---|---:|---:|---|
| 防御语义词（detection/remediat/hardening/forensic 等） | 385 | 1588 | 蓝队技能的脚本确实以防御动词为主 |
| ATT&CK 引用（`T####` 或 attack.mitre.org） | 94 | 713 | 技术编号出现在文档串中，可用于映射 |
| 占位符或示例值（example.com / CHANGEME / 尖括号） | 44 | 67 | 少数脚本已做占位符化 |
| 疑似硬编码凭据 | 7 | 8 | 个别脚本存在，改写时必须删除 |
| `# TODO` / `FIXME` | 0 | 0 | 未命中 |
| HTTP 客户端（requests / urllib / httpx / aiohttp） | 184 + 15 + 4（三项分别计数） | 489 + 46 + 5 | 联网脚本必须先断网，再复用其解析逻辑 |

### 7.6 组合特征（`script-patterns.md` 的骨架设计依据）

| 组合 | 命中文件 | 说明 |
|---|---:|---|
| `argparse` + `json.dump` + `--dry-run` | 5 | 「参数化 + 结构化 + 预览」三件套几乎缺失 |
| `argparse` + `json.dump` + 结构化错误 | 147 | 可作「合格骨架」的下界参考 |
| 授权语义 + 目标参数 | 84 | 有目标参数但无机器门禁 |
| 关闭 TLS 校验的 `verify=False` 且无 `verify=True`（本插件禁止此写法） | 36 | 反模式的完整样本集 |

结论（直接决定 `references/shared/script-patterns.md` 的设计）：ACS 脚本的价值在**领域步骤与解析口径**，不在**工程骨架**。骨架层面的六个缺口（无机器授权门禁、无 dry-run 默认、限速缺失、无三态退出码、无结构化证据、无统一错误模型）由本插件的模式库补齐。

## 8. Strix analysis 技能吸收点（本任务新增）

ACS 之外，本任务还吸收了 Strix 仓库 `strix/skills/analysis/` 的 4 篇分析纪律（与 §3–§5 的 ACS 账互不重叠，属于另一个上游）：

| Strix 文件 | 字节 | 决策 | 吸收到 | 吸收点 |
|---|---:|---|---|---|
| `analysis/counterevidence.md` | 9265 | keep | `references/shared/finding-review.md` §1–§5 | 三关闭态（confirmed / ruled_out / open_proof_gap）、九条「不能作为反证」、可排除条件与负向对照、归档前四步自查、未确认候选的报告门槛 |
| `analysis/severity_calibration.md` | 5620 | merge | `references/shared/finding-review.md` §6 | 先可达性后定级、四档判据、常被高估项、降级不删除、high/critical 验收清单、与 CVSS 冲突时改指标 |
| `analysis/fix_verification.md` | 6003 | merge | `references/shared/finding-review.md` §7 | 六道门（可应用性/安全关闭/绕过复审/行为保留/仓库检查/最小性）、动手前须确立的不变量、八条不合格、withhold 与 gap 记录 |
| `analysis/source_aware_discovery.md` | 10895 | drop | — | 主要服务其代码审计的候选识别流程（红队/代码审计 lane）；本任务蓝队与紫队不吸收，其 source → control → sink 的最小形式已在 §3 引用 |

合计 4 篇 Strix analysis：keep 1 / merge 2 / drop 1。Strix 官方 9 个技能（`skills/*/SKILL.md`）的逐条处置见 `references/red/extraction-ledger.md` §4，不在本账重复。

## 9. 维护规则

1. **上游新增技能**：在 §3/§4/§5 对应位置追加，并同步更新 §6.1 合计；合计不等于 818 时视为台账失败。
2. **上游删除技能**：从本账删除，并在 `rewrite-summary` 记录「上游已移除」。
3. **重新判定**：只允许在同一规则内「keep ↔ merge」「merge ↔ drop」调整；调整必须写明理由与受影响的目标参考文件。
4. **统计更新**：`agent.py` 的统计值随上游 commit 变化；更新时重跑 §7 口径并替换全部数字（禁止部分更新）。
5. **禁止事项**：不把 `agent.py` 或 `references/` 原文复制进插件；不把统计脚本当插件工具发布；不以「上游原文如此」为由绕过 R3/R5。
