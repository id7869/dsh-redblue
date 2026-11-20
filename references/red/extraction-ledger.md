<!-- dsh-redblue:provenance
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: README.md
last-verified: 2026-11-19
rewrite-summary: 逐条登记 79 个 Claude-Red 技能与 9 个 Strix 技能的处置决策与落点，给出合计账与库存核对方法
-->

# 提取台账（extraction-ledger）

> 目的：证明「79 个 Claude-Red 技能 + 9 个 Strix 官方技能」逐条被处置，无静默遗漏；每个决策给出目标文件与理由，供复核与后续增量维护。
> 决策定义：`keep` = 作为目标文件的主干来源；`merge` = 与同族内容合并进目标文件（非主干）；`drop` = 不吸收（课程/武器化/与插件定位冲突/重复）。
> 版本时效：技能清单与文件大小取自 pin 的 commit；上游新增技能后需在本账追加行并更新合计。

## 1. 库存基线

| 仓库 | pin | 单位 | 数量 | 备注 |
|---|---|---|---|---|
| Claude-Red | `6196ba7464662de34e8744d359f175d1a7bca530` | `Skills/**/SKILL.md` | 79 | 本次逐条登记 |
| Strix | `8db295a5b3564be2b430bb3a9afdb4db7850fa24` | `skills/*/SKILL.md` | 9 | 本次逐条写吸收点 |
| Strix 内部知识库（技术正文） | 同上 | `strix/skills/**/*.md` | 78 | **逐条登记于 §8**（30 类漏洞 + 5 框架 + 4 云 + 协议/自定义/分析/技术/工具/侦察/扫描模式），技术正文的主体落点为 `references/red/strix-techniques.md` |
| Strix 内部知识库（治理/基准） | 同上 | `strix/` 下 5 篇工具 README + `.github/` 2 篇 + `docs/` 1 篇 + `benchmarks/` 1 篇 | 9 | 仓库治理、CI 模板与基准说明，无测试技术；不吸收，理由见 §8 尾注（78 + 9 = 87，与本节原口径一致） |
| ACS | `54a798831d2266a3ca61ce68a7acb80b81160d57` | `skills/**/SKILL.md` | 818 | 本任务只按 `design.md` §5 指定的类目择优引用（跨参考文件二级来源），不逐条登记；仓库全部 `.md` 为 2588（含非技能文档，不是技能数） |

## 2. Claude-Red 79 个技能逐条处置

| # | 技能路径（`Skills/…/SKILL.md`） | 字节 | 决策 | 目标文件 | 理由 |
|---:|---|---:|---|---|---|
| 1 | active-directory/offensive-active-directory | 14275 | merge | references/red/discover-identity-ad.md | 保留信任/ACL/委派/ADCS 判定，删除转储与利用链 |
| 2 | active-directory/offensive-netexec | 25496 | merge | references/red/post-readonly.md | 只保留 `--shares/--pass-pol` 等只读用法 |
| 3 | ai/offensive-ai-security | 40733 | merge | references/red/discover-web-api.md | 压缩为 LLM 应用判定（指令/数据边界），去利用链 |
| 4 | api/offensive-api-abuse | 22882 | keep | references/red/discover-web-api.md | API 类目主干（BOLA/BFLA/批量赋值） |
| 5 | api/offensive-api-security | 20326 | merge | references/red/discover-web-api.md | 与 #4 同族，补认证/限流判定 |
| 6 | auth/offensive-jwt | 11644 | merge | references/red/discover-web-api.md | 保留 alg/声明校验判定，去伪造 |
| 7 | auth/offensive-oauth | 15727 | merge | references/red/discover-identity-ad.md | 保留 redirect/state/PKCE 判定 |
| 8 | cicd/offensive-cicd-pipeline | 20712 | merge | references/red/discover-identity-ad.md | 保留流水线权限与令牌范围判定 |
| 9 | cicd/offensive-cicd-secrets | 25660 | merge | references/red/discover-identity-ad.md | 合并进密钥管理检查（gitleaks 只读） |
| 10 | cloud/offensive-cloud | 12987 | keep | references/red/discover-cloud-container.md | 云侧主干（身份/存储/密钥只读） |
| 11 | container/offensive-container-escape | 22411 | merge | references/red/discover-cloud-container.md | 只保留逃逸前置条件识别，删除逃逸步骤 |
| 12 | container/offensive-k8s-attacks | 28297 | keep | references/red/discover-cloud-container.md | K8s 主干（RBAC/工作负载/基线） |
| 13 | crypto/offensive-crypto-attacks | 20903 | merge | references/red/discover-web-api.md | 压成加密姿态判定（弱算法/密钥管理） |
| 14 | crypto/offensive-tls-attacks | 26109 | merge | references/red/discover-web-api.md | 保留 TLS 配置判定，去降级攻击 |
| 15 | exploit-dev/offensive-basic-exploitation | 365412 | drop | — | 课程巨型文件（365 KiB），R6/价值比不符；不搬运 |
| 16 | exploit-dev/offensive-crash-analysis | 422054 | drop | — | 课程巨型文件（422 KiB），崩溃分析课程；不搬运 |
| 17 | exploit-dev/offensive-exploit-dev-course | 20850 | drop | — | 课程式大纲，无独立判定价值 |
| 18 | exploit-dev/offensive-exploit-development | 34875 | keep | references/red/exploit-controlled.md | 受控利用主干（可达性/可靠性/影响阶梯） |
| 19 | exploit-dev/offensive-mitigations | 60427 | keep | references/red/exploit-controlled.md | 缓解措施认知，用于影响与清理判定 |
| 20 | exploit-dev/offensive-toctou | 13202 | merge | references/red/exploit-controlled.md | 竞态判定并入影响阶梯（只读验证） |
| 21 | forensics/offensive-anti-forensics | 19943 | drop | — | 反取证与 report-only/证据完整性冲突 |
| 22 | forensics/offensive-c2-frameworks | 22952 | drop | — | C2 武器化内容，R3 红线 |
| 23 | fuzzing/offensive-bug-identification | 57505 | merge | references/red/discover-web-api.md | 保留缺陷模式与判定信号，去 fuzz 工程细节 |
| 24 | fuzzing/offensive-fuzzing | 12213 | merge | references/red/discover-web-api.md | 并入「差分验证」纪律 |
| 25 | fuzzing/offensive-fuzzing-course | 82859 | drop | — | 课程材料（82 KiB），与判定清单重复 |
| 26 | fuzzing/offensive-vuln-classes | 98041 | drop | — | 课程式漏洞类别枚举（98 KiB），与 CWE 判定表重复 |
| 27 | infrastructure/offensive-advanced-redteam | 28234 | merge | references/red/scope-roe.md | 保留交战组织/沟通/升级，去技战法细节 |
| 28 | infrastructure/offensive-edr-evasion | 86514 | drop | — | 规避检测属于利用与反检测，R3/R12 冲突 |
| 29 | infrastructure/offensive-initial-access | 67427 | merge | references/red/discover-identity-ad.md | 只保留初始访问面的检测视角，删除投递链 |
| 30 | infrastructure/offensive-keylogger-arch | 12077 | drop | — | 恶意软件类制品，R3 红线 |
| 31 | infrastructure/offensive-shellcode | 19360 | drop | — | 武器化制品（shellcode），R3 红线 |
| 32 | infrastructure/offensive-windows-boundaries | 583006 | drop | — | 课程巨型文件（583 KiB）；不搬运 |
| 33 | infrastructure/offensive-windows-mitigations | 545372 | drop | — | 课程巨型文件（545 KiB）；不搬运 |
| 34 | iot/offensive-iot | 14659 | keep | references/red/discover-ot-mobile-iot.md | IoT 主干（固件/协议/接口判定） |
| 35 | mobile/offensive-mobile | 14458 | keep | references/red/discover-ot-mobile-iot.md | 移动端主干（组件/存储/传输） |
| 36 | network/offensive-network-attacks | 20660 | merge | references/red/surface-threat-model.md | 只保留 L2/L3 信任边界与可见性判定 |
| 37 | post-exploitation/offensive-data-exfiltration | 20258 | drop | — | 数据外传配方，R3/R12 冲突 |
| 38 | post-exploitation/offensive-lateral-movement | 16715 | keep | references/red/post-readonly.md | 横向评估主干（改为可达性判定） |
| 39 | post-exploitation/offensive-persistence | 24158 | drop | — | 持久化配方；本插件明确禁止持久化 |
| 40 | privesc/offensive-linux-privesc | 19616 | keep | references/red/post-readonly.md | Linux 提权枚举主干（只读化） |
| 41 | privesc/offensive-windows-privesc | 23160 | keep | references/red/post-readonly.md | Windows 提权枚举主干（只读化） |
| 42 | recon/offensive-osint-methodology | 24119 | keep | references/red/recon-osint.md | OSINT 方法论主干（置信度/溯源） |
| 43 | recon/offensive-osint | 23150 | keep | references/red/recon-osint.md | OSINT 资产测绘主干 |
| 44 | social-engineering/offensive-phishing | 19880 | drop | — | 钓鱼投递链，R3/R12 与授权边界冲突 |
| 45 | social-engineering/offensive-social-engineering | 23509 | drop | — | 社工话术与诱饵，超出报告-only 定位 |
| 46 | supply-chain/offensive-dependency-confusion | 24402 | merge | references/red/discover-identity-ad.md | 保留依赖混淆判定，去投递步骤 |
| 47 | supply-chain/offensive-supply-chain | 19053 | merge | references/red/discover-identity-ad.md | 保留制品/签名/来源判定 |
| 48 | utility/offensive-fast-checking | 24663 | merge | references/red/tool-recipes.md | 快检纪律并入工具族通用纪律 |
| 49 | utility/offensive-reporting | 15091 | merge | references/shared/report-format.md | 报告结构并入固定 7 段与字段表 |
| 50 | web/offensive-business-logic | 13710 | merge | references/red/discover-web-api.md | 业务逻辑判定并入类目表 |
| 51 | web/offensive-deserialization | 23824 | merge | references/red/discover-web-api.md | 只保留解析器判定，去 gadget |
| 52 | web/offensive-file-upload | 31854 | merge | references/red/discover-web-api.md | 保留上传校验判定，去 webshell |
| 53 | web/offensive-graphql | 22698 | merge | references/red/discover-web-api.md | 内省/深度判定 |
| 54 | web/offensive-idor | 26532 | merge | references/red/discover-web-api.md | BOLA/IDOR 判定 |
| 55 | web/offensive-open-redirect | 17099 | merge | references/red/discover-web-api.md | 跳转白名单判定 |
| 56 | web/offensive-parameter-pollution | 17668 | merge | references/red/discover-web-api.md | 同名参数解析判定 |
| 57 | web/offensive-race-condition | 30575 | merge | references/red/discover-web-api.md | 只读并发判定 |
| 58 | web/offensive-rce | 27967 | merge | references/red/discover-web-api.md | 只保留执行上下文判定，去命令 |
| 59 | web/offensive-request-smuggling | 22936 | merge | references/red/discover-web-api.md | 协议层判定，默认跳过 |
| 60 | web/offensive-sqli | 10250 | keep | references/red/discover-web-api.md | SQLi 主干（差分判定/只读证据） |
| 61 | web/offensive-ssrf | 27052 | merge | references/red/discover-web-api.md | SSRF 判定与 OAST 纪律 |
| 62 | web/offensive-ssti | 24371 | merge | references/red/discover-web-api.md | 算术回显判定，去 RCE 链 |
| 63 | web/offensive-waf-bypass | 39771 | merge | references/red/discover-web-api.md | 只保留 WAF 识别，删除绕过链 |
| 64 | web/offensive-xss | 26019 | merge | references/red/discover-web-api.md | 上下文/编码判定，去 payload 库 |
| 65 | web/offensive-xxe | 29769 | merge | references/red/discover-web-api.md | 外部实体解析判定，去读文件 |
| 66 | wireless/offensive-bluetooth-ble | 6888 | merge | references/red/discover-wireless.md | BLE 可见性/配对判定 |
| 67 | wireless/offensive-bluetooth-classic | 5619 | merge | references/red/discover-wireless.md | 经典蓝牙判定 |
| 68 | wireless/offensive-deauth-disassoc | 4753 | merge | references/red/discover-wireless.md | 只写检测视角，不给注入命令 |
| 69 | wireless/offensive-evil-twin | 8313 | merge | references/red/discover-wireless.md | 只写仿冒风险判定 |
| 70 | wireless/offensive-krack-fragattacks | 4656 | merge | references/red/discover-wireless.md | 保留补丁/PMF 判定 |
| 71 | wireless/offensive-lorawan-sub-ghz | 7111 | merge | references/red/discover-wireless.md | 只读嗅探与密钥复用判定 |
| 72 | wireless/offensive-wifi-recon | 7060 | keep | references/red/discover-wireless.md | 空口测绘主干 |
| 73 | wireless/offensive-wifi | 11398 | merge | references/red/discover-wireless.md | 加密/PMF 判定并入 |
| 74 | wireless/offensive-wpa-enterprise | 7894 | merge | references/red/discover-wireless.md | EAP 方法判定，去 Evil Twin |
| 75 | wireless/offensive-wpa2-psk | 6456 | merge | references/red/discover-wireless.md | 只判加密与口令策略 |
| 76 | wireless/offensive-wpa3-sae | 6598 | merge | references/red/discover-wireless.md | 只判 SAE/PMF 姿态 |
| 77 | wireless/offensive-wps | 6040 | merge | references/red/discover-wireless.md | 只判 WPS 启用风险 |
| 78 | wireless/offensive-z-wave | 5546 | merge | references/red/discover-wireless.md | 只读嗅探判定 |
| 79 | wireless/offensive-zigbee-thread-matter | 6586 | merge | references/red/discover-wireless.md | 入网/密钥判定，去注入 |

行数核对（按 Claude-Red 行筛选，避免把 Strix 行算入）：`grep -E '^\| [0-9]+ \| ' extraction-ledger.md | grep -c ' | merge | '` = 49；同法 `keep` = 14、`drop` = 16，合计 79。

## 3. 合计账

| 决策 | 数量 | 占 79 的分数 |
|---|---:|---|
| keep | 14 | 14/79 |
| merge | 49 | 49/79 |
| drop | 16 | 16/79 |
| 合计 | 79 | 79/79 |

drop 的 16 项构成：4 个课程巨型文件（#15/#16/#32/#33，合计约 1.9 MiB）+ 3 个课程式文件（#17/#25/#26）+ 9 个与定位冲突项（反取证、C2、EDR 规避、键盘记录、shellcode、数据外传、持久化、钓鱼、社工）。

## 4. Strix 9 个官方技能吸收点

| # | Strix 技能 | 决策 | 吸收到 | 具体吸收点 |
|---:|---|---|---|---|
| S1 | `api-security-testing` | keep | references/red/discover-web-api.md | §3.5 API 专项（对象级/功能级/批量赋值/限流/WebSocket） |
| S2 | `application-security-testing` | merge | references/red/discover-web-api.md + references/shared/evidence-standards.md | §1 通用纪律（差分/单变量）+ §5 最小 PoC 标准 |
| S3 | `ci-security-scanning-with-strix` | merge | references/red/scope-roe.md + references/red/discover-identity-ad.md | §4 预算/退出码纪律 + §4 CI 权限与制品判定 |
| S4 | `find-security-vulnerabilities-in-code` | merge | references/red/discover-web-api.md | §1 差分纪律与「按类目分配假设」 |
| S5 | `fix-security-vulnerabilities-with-strix` | merge | references/shared/report-format.md | §6 修复建议须含「如何验证已修好」 |
| S6 | `managed-pentesting-with-strix` | merge | references/red/scope-roe.md | §2 授权证据（资产归属验证）+ §5 数据处置/报告下载边界 |
| S7 | `owasp-top-10-testing` | merge | references/red/discover-web-api.md | §2 类目判定表（按 OWASP 类目组织） |
| S8 | `penetration-testing-with-strix` | keep | references/red/scope-roe.md + references/shared/report-format.md | CLI 纪律（非交互/预算/轮次）+ 退出码 `0/1/2` + 产物清单（`strix_runs/<run>/`）映射为 `workDir` 产物 |
| S9 | `web-app-penetration-testing` | merge | references/red/discover-web-api.md | §3.1–§3.4 深入判定（SSRF/走私/竞态/反序列化） |

Strix 技能全部 9 个已处置（0 drop）：其中 2 个 keep、7 个 merge；9 个对外技能偏「怎么跑」（CLI/预算/退出码/产物），真正的测试技术在其内部知识库 78 篇中，逐条处置见 §8，落点为 `references/red/strix-techniques.md`。

## 5. 同族合并结果（避免 79 份碎片）

| 族 | 上游条目 | 合并后文件 | 文件大小 |
|---|---|---|---|
| recon/OSINT | #42、#43 | references/red/recon-osint.md | 8 KiB 级 |
| 威胁建模/网络边界 | #36 + ACS 3 篇 | references/red/surface-threat-model.md | 9 KiB 级 |
| web/api/auth/crypto/ai | #3–#7、#13、#14、#23、#24、#50–#65 | references/red/discover-web-api.md | 12 KiB 级 |
| cloud/container | #10–#12 | references/red/discover-cloud-container.md | 9 KiB 级 |
| ad/identity/supply-chain | #1、#7–#9、#29、#46、#47 | references/red/discover-identity-ad.md | 10 KiB 级 |
| ot/mobile | #34、#35 | references/red/discover-ot-mobile-iot.md | 9 KiB 级 |
| wireless | #66–#79 | references/red/discover-wireless.md | 7 KiB 级 |
| exploit-dev | #18–#20 | references/red/exploit-controlled.md | 10 KiB 级 |
| post-exploitation/privesc | #2、#38、#40、#41 | references/red/post-readonly.md | 11 KiB 级 |
| 工具配方 | #48 + Strix 87 篇 + ACS 脚本参数模式 | references/red/tool-recipes.md | 27 KiB 级 |
| 报告 | #49 + Strix 产物纪律 | references/shared/report-format.md | 9 KiB 级 |
| 证据 | Strix PoC 纪律 + Claude-Red 复现结构 | references/shared/evidence-standards.md | 8 KiB 级 |

## 6. 库存核对方法（可复算）

1. `find .work/sources/claude-red/Skills -name SKILL.md | wc -l` → 79；本表行数应为 79。
2. `grep -E '^\| [0-9]+ \| ' extraction-ledger.md | wc -l` → 79（Claude-Red 行）；`grep -E '^\| S[0-9]+ \| ' extraction-ledger.md | wc -l` → 9（Strix 行）。
3. 决策计数（先按行前缀筛选，再数决策列）：`grep -E '^\| [0-9]+ \| ' extraction-ledger.md | grep -c ' | keep | '` = 14，`merge` = 49，`drop` = 16，三数之和必须等于 79。
4. 目标文件存在性：表中每个 `references/...` 路径都必须实际存在于插件内（除 `—`）。
5. 巨型文件核对：4 个 dropped 课程文件的字节数均 >300 KiB（365412/422054/583006/545372），且插件内不存在同尺寸文件。
6. Strix 侧：`find .work/sources/strix/skills -name SKILL.md | wc -l` → 9；本表 S1–S9 全覆盖。
7. Strix 内部知识：`find .work/sources/strix/strix/skills -name '*.md' | wc -l` → 78；§8 的 `I` 行数必须为 78。
8. §8 决策计数：`grep -E '^\| I[0-9]+ \| ' extraction-ledger.md | grep -c ' | keep | '` = 47，`merge` = 29，`drop` = 2，合计 78；`drop` 仅 `tooling/agent_browser.md` 与 `tooling/python.md`。
9. ACS 库存：`find .work/sources/acs/skills -name SKILL.md | wc -l` → 818；`find .work/sources/acs -name '*.md' | wc -l` → 2588（仓库全部 `.md`，非技能数）。

## 7. 维护规则

- 上游技能改名/新增时：在 §2 追加行（编号续排），更新 §3 合计与 §6 核对结果，不删旧行。
- 任何 `drop` 决策必须写明冲突类型（课程/武器化/定位冲突/重复），禁止「暂不吸收」这类不可复核理由。
- 任何 `merge` 必须指向已存在的目标文件与具体小节；目标文件删除时同步改账。
- 本账与 `docs/sanitization-rules.md` R1（来源与许可）配套：`keep`/`merge` 的目标文件必须带 provenance 头，`drop` 不产生衍生文件。
- §8 的 78 篇按目录顺序编号（`I1`–`I78`），新增/删除上游文件时同步增删行并更新合计数；编号不复用。

## 8. Strix 内部知识（78 篇）逐篇处置

> 口径：`find .work/sources/strix/strix/skills -name '*.md' | wc -l` = 78（pin `8db295a5b3564be2b430bb3a9afdb4db7850fa24`）。这 78 篇才是 Strix 的实战测试技术；9 个对外技能只讲运行方式（见 §4）。
> 落点：除 analysis 的 3 篇关闭/定级/修复纪律落在 `references/shared/finding-review.md`（由 t4 落地，本表只做归属核对）外，其余技术正文全部落 `references/red/strix-techniques.md`（各节见括号）。
> 交叉说明：`references/blue/extraction-ledger.md` §8 已按「ACS 主账」口径登记 analysis 4 篇；本表按「78 篇目录全覆盖」口径再次登记同一批文件，两者是同一批源文件的两种视角，**不重复计数**。

| # | 路径（`strix/skills/…`） | 字节 | 决策 | 目标文件 | 理由 |
|---|---|---:|---|---|---|
| I1 | README.md | 4851 | merge | strix-techniques.md（§0/§7） | 技能索引与路由表，压成使用方式；无独立技术内容 |
| I2 | analysis/counterevidence.md | 9265 | keep | references/shared/finding-review.md | 三关闭态与「什么不能排除」纪律的主干（t4 落地，已核对） |
| I3 | analysis/fix_verification.md | 6003 | merge | references/shared/finding-review.md | 修复验证门并入关闭纪律（t4 落地，已核对） |
| I4 | analysis/severity_calibration.md | 5620 | merge | references/shared/finding-review.md | 严重度判据并入定级节（t4 落地，已核对） |
| I5 | analysis/source_aware_discovery.md | 10895 | keep | strix-techniques.md（§5.2） | 控制点/同族扫描/跨边界输入/收敛门槛的主干 |
| I6 | cloud/aws.md | 10417 | keep | strix-techniques.md（§4.1） | S3/IMDS/IAM 提权/快照的判定主干 |
| I7 | cloud/azure.md | 20611 | keep | strix-techniques.md（§4.2） | 双平面角色/PIM/身份对象的判定主干 |
| I8 | cloud/gcp.md | 7938 | keep | strix-techniques.md（§4.3） | IAM actAs/元数据/GCS 的判定主干 |
| I9 | cloud/kubernetes.md | 12176 | keep | strix-techniques.md（§4.4） | RBAC/kubelet/工作负载的判定主干 |
| I10 | coordination/root_agent.md | 6766 | merge | strix-techniques.md（§0/§7.4） | 任务分解与覆盖核对并入扫描深度与使用方式 |
| I11 | coordination/source_aware_whitebox.md | 2154 | merge | strix-techniques.md（§5.3） | 白盒四件套与「静态即假设」并入源码感知纪律 |
| I12 | custom/api_spec_testing.md | 3233 | keep | strix-techniques.md（§3.2） | spec 驱动测试（base URL/operation 覆盖/双账号对照）主干 |
| I13 | custom/dependency_cve_scanning.md | 20814 | keep | strix-techniques.md（§6.1） | SCA 流程、库龄、传递归因、可达性判定主干 |
| I14 | custom/npx_confusion.md | 16748 | keep | strix-techniques.md（§6.2） | 依赖混淆解析语句与误判清单主干 |
| I15 | custom/source_aware_sast.md | 8350 | keep | strix-techniques.md（§5.1） | opengrep/ast-grep/tree-sitter/秘密/依赖四件套主干 |
| I16 | frameworks/django.md | 10895 | keep | strix-techniques.md（§2.1） | Django/DRF 入口、sink、权限栈、序列化主干 |
| I17 | frameworks/fastapi.md | 8366 | keep | strix-techniques.md（§2.2） | FastAPI 依赖注入缺口、输入处理、代理信任主干 |
| I18 | frameworks/nestjs.md | 12273 | keep | strix-techniques.md（§2.3） | NestJS guard 栈缺口、跨传输鉴权、序列化泄露主干 |
| I19 | frameworks/nextjs.md | 10593 | keep | strix-techniques.md（§2.4） | Next.js 中间件授权、RSC/Server Action、缓存身份主干 |
| I20 | frameworks/springboot.md | 11639 | keep | strix-techniques.md（§2.5） | Spring 过滤链/Actuator/绑定/多态反序列化主干 |
| I21 | protocols/graphql.md | 8923 | keep | strix-techniques.md（§3.1） | introspection/alias/字段级 IDOR/联邦授权主干 |
| I22 | protocols/oauth.md | 9592 | merge | strix-techniques.md（§3.2） | redirect/state/PKCE 判定并入身份协议线，细节由 discover-identity-ad 承载 |
| I23 | reconnaissance/asset_discovery.md | 10436 | merge | strix-techniques.md（§7.3） | CT/SAN/被动 DNS/ASN 与迭代扩展并入侦察小节 |
| I24 | reconnaissance/infrastructure_lifecycle.md | 14500 | merge | strix-techniques.md（§7.3） | 信任消费者图与可声明性等级并入生命周期判定 |
| I25 | scan_modes/deep.md | 7355 | merge | strix-techniques.md（§7.4） | 深度模式覆盖策略并入扫描深度表 |
| I26 | scan_modes/diff.md | 4102 | merge | strix-techniques.md（§7.4） | 变更范围与受影响面并入扫描深度表 |
| I27 | scan_modes/quick.md | 3104 | merge | strix-techniques.md（§7.4） | 快速模式取舍并入扫描深度表 |
| I28 | scan_modes/standard.md | 4024 | merge | strix-techniques.md（§7.4） | 标准模式阶段并入扫描深度表 |
| I29 | technologies/active_directory.md | 16412 | merge | strix-techniques.md（§7.1） | AD 面并入技术专属表，配置枚举细节由 discover-identity-ad 承载 |
| I30 | technologies/auth0.md | 8462 | merge | strix-techniques.md（§7.1） | audience 混用/redirect/MFA 并入技术专属表 |
| I31 | technologies/electron_desktop_apps.md | 10826 | merge | strix-techniques.md（§7.1） | preload/contextBridge/深链判定并入技术专属表 |
| I32 | technologies/firebase.md | 11988 | merge | strix-techniques.md（§7.1） | Firestore rules/RTDB/Storage 判定并入技术专属表 |
| I33 | technologies/grafana_prometheus.md | 17602 | merge | strix-techniques.md（§7.1） | 观测栈默认暴露与插件边界并入技术专属表，CVE 族按版本核对 |
| I34 | technologies/llm_applications.md | 23732 | keep | strix-techniques.md（§7.1 LLM 行） | LLM 六类风险与工具/代理权限判定主干（体量最大、内容独立） |
| I35 | technologies/supabase.md | 11561 | merge | strix-techniques.md（§7.1） | RLS/PostgREST/签名密钥判定并入技术专属表 |
| I36 | tooling/agent_browser.md | 21081 | drop | — | 依赖 agent-browser 运行时且本插件无浏览器工具；仅在 §7.2 标注「不采用」 |
| I37 | tooling/ffuf.md | 3347 | merge | strix-techniques.md（§7.2） | 参数细节已由 tool-recipes F3/F6 承载，此处只留选取条件 |
| I38 | tooling/httpx.md | 3488 | merge | strix-techniques.md（§7.2） | 同上（F1/F3） |
| I39 | tooling/hurl.md | 4832 | merge | strix-techniques.md（§7.2） | 「修复即回归断言」并入工具选取 |
| I40 | tooling/hypothesis.md | 5059 | merge | strix-techniques.md（§7.2） | 不变式差分测试纪律并入工具选取 |
| I41 | tooling/katana.md | 5939 | merge | strix-techniques.md（§7.2） | 爬取纪律并入工具选取（F4） |
| I42 | tooling/naabu.md | 2911 | merge | strix-techniques.md（§7.2） | 快速端口探测并入工具选取（F2） |
| I43 | tooling/nmap.md | 2867 | merge | strix-techniques.md（§7.2） | 版本/脚本约束并入工具选取（F2） |
| I44 | tooling/nuclei.md | 2839 | merge | strix-techniques.md（§7.2） | 模板类别与排除项并入工具选取（F5） |
| I45 | tooling/opengrep.md | 3881 | merge | strix-techniques.md（§5.1/§7.2） | 语义规则首过并入源码感知与工具选取 |
| I46 | tooling/python.md | 4102 | drop | — | 沙箱代理自动化需要网络与包安装，与零依赖本地插件冲突 |
| I47 | tooling/sqlmap.md | 2876 | merge | strix-techniques.md（§7.2） | risk/level 与禁令并入工具选取（F7） |
| I48 | tooling/subfinder.md | 2577 | merge | strix-techniques.md（§7.2） | 被动优先纪律并入工具选取（F1） |
| I49 | vulnerabilities/agentic_system_security.md | 16690 | keep | strix-techniques.md（§1 第 30 行） | 智能体/MCP 授权与参数边界的主干 |
| I50 | vulnerabilities/argument_injection.md | 8823 | keep | strix-techniques.md（§1 第 23 行） | 参数注入/解析边界的主干 |
| I51 | vulnerabilities/authentication_jwt.md | 8447 | keep | strix-techniques.md（§1 第 14 行） | 令牌校验缺失的主干 |
| I52 | vulnerabilities/broken_function_level_authorization.md | 6720 | keep | strix-techniques.md（§1 第 13 行） | 功能级授权缺口的主干 |
| I53 | vulnerabilities/browser_security.md | 13793 | keep | strix-techniques.md（§1 第 29 行） | postMessage/CSP/跨源判定的主干 |
| I54 | vulnerabilities/business_logic.md | 9269 | keep | strix-techniques.md（§1 第 20 行） | 流程/数量/状态绕过的主干 |
| I55 | vulnerabilities/csrf.md | 8681 | keep | strix-techniques.md（§1 第 16 行） | 环境凭据与 token 校验的主干 |
| I56 | vulnerabilities/header_injection.md | 16244 | keep | strix-techniques.md（§1 第 18 行） | 响应头/邮件头注入的主干 |
| I57 | vulnerabilities/http_request_smuggling.md | 12931 | keep | strix-techniques.md（§1 第 17 行） | 前后端边界解释差异的主干 |
| I58 | vulnerabilities/idor.md | 10917 | keep | strix-techniques.md（§1 第 12 行） | 对象级授权的主干 |
| I59 | vulnerabilities/information_disclosure.md | 9355 | keep | strix-techniques.md（§1 第 25 行） | 错误/调试/备份暴露的主干 |
| I60 | vulnerabilities/insecure_deserialization.md | 12454 | keep | strix-techniques.md（§1 第 10 行） | 序列化结构解析判定的主干 |
| I61 | vulnerabilities/insecure_file_uploads.md | 9544 | keep | strix-techniques.md（§1 第 9 行） | 上传校验与回读判定的主干 |
| I62 | vulnerabilities/llm_prompt_injection.md | 11074 | keep | strix-techniques.md（§1 第 28 行） | 指令/数据分离的主干 |
| I63 | vulnerabilities/mass_assignment.md | 6289 | keep | strix-techniques.md（§1 第 15 行） | 序列化层额外字段的主干 |
| I64 | vulnerabilities/nosql_injection.md | 15270 | keep | strix-techniques.md（§1 第 2 行） | 操作符对象注入的主干 |
| I65 | vulnerabilities/open_redirect.md | 6673 | keep | strix-techniques.md（§1 第 19 行） | 跳转白名单与解析差异的主干 |
| I66 | vulnerabilities/path_traversal_lfi_rfi.md | 10965 | keep | strix-techniques.md（§1 第 8 行） | 路径规范化与根限制的主干 |
| I67 | vulnerabilities/prototype_pollution.md | 7424 | keep | strix-techniques.md（§1 第 11 行） | 原型链污染 canary 判定的主干 |
| I68 | vulnerabilities/query_language_injection.md | 10091 | keep | strix-techniques.md（§1 第 3 行） | 过滤表达式三件套基线的主干 |
| I69 | vulnerabilities/race_conditions.md | 7845 | keep | strix-techniques.md（§1 第 21 行） | 并发不变量与持久状态证明的主干 |
| I70 | vulnerabilities/rce.md | 8449 | keep | strix-techniques.md（§1 第 24 行） | 无副作用 oracle 判定的主干 |
| I71 | vulnerabilities/semantic_confusion.md | 15074 | keep | strix-techniques.md（§1 第 22 行） | 校验与消费者理解差异的主干 |
| I72 | vulnerabilities/sql_injection.md | 8477 | keep | strix-techniques.md（§1 第 1 行） | 注入类判定的主干（provenance 代表路径） |
| I73 | vulnerabilities/ssrf.md | 8479 | keep | strix-techniques.md（§1 第 6 行） | 服务端代发请求与元数据可达的主干 |
| I74 | vulnerabilities/ssti.md | 19294 | keep | strix-techniques.md（§1 第 5 行） | 模板源控制与算术求值的主干 |
| I75 | vulnerabilities/subdomain_takeover.md | 8481 | keep | strix-techniques.md（§1 第 26 行） | 悬空记录与可声明性判定的主干 |
| I76 | vulnerabilities/weak_password_detection.md | 10642 | keep | strix-techniques.md（§1 第 27 行） | 限速/策略/锁定判定的主干 |
| I77 | vulnerabilities/xss.md | 9600 | keep | strix-techniques.md（§1 第 4 行） | 上下文编码与回显判定的主干 |
| I78 | vulnerabilities/xxe.md | 7385 | keep | strix-techniques.md（§1 第 7 行） | 外部实体解析判定的主干 |

### 8.1 合计账

| 决策 | 数量 | 占 78 的分数 |
|---|---:|---|
| keep | 47 | 47/78 |
| merge | 29 | 29/78 |
| drop | 2 | 2/78 |
| 合计 | 78 | 78/78 |

- `drop` 仅两篇：`tooling/agent_browser.md`（运行时依赖 + 无浏览器工具，仅在 §7.2 标注不采用）、`tooling/python.md`（沙箱代理自动化需要网络与包安装，与零依赖定位冲突）。
- 未吸收的 9 篇治理/基准文档（`strix/tools/*/README.md` 5 篇、`.github/ISSUE_TEMPLATE/*.md` 2 篇、`docs/README.md`、`benchmarks/README.md`）：CI/贡献模板与基准说明，无测试技术；78 + 9 = 87，与 §1 原「87 篇内部 md」口径一致。
- 与 §2（Claude-Red 79）和 §4（Strix 9 技能）互不重叠：§2 是另一仓库的技能、§4 是运行壳、本节是技术正文。

### 8.2 核对命令

1. `find .work/sources/strix/strix/skills -name '*.md' | wc -l` → 78。
2. `grep -E '^\| I[0-9]+ \| ' references/red/extraction-ledger.md | wc -l` → 78。
3. `grep -E '^\| I[0-9]+ \| ' references/red/extraction-ledger.md | grep -c ' | keep | '` → 47；`merge` → 29；`drop` → 2。
4. 目标文件存在性：`references/red/strix-techniques.md` 与 `references/shared/finding-review.md` 均存在且带 provenance 头。
5. 压缩率：78 篇合计约 904 KB → `strix-techniques.md` 为 30.6 KB 级（约 1/29），未整篇复制；单篇 ≤48 KB。