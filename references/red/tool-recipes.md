<!-- dsh-redblue:provenance
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: Skills/utility/offensive-fast-checking/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 把 Claude-Red 全库命令族与 Strix/ACS 的参数纪律压成 16 个工具族配方矩阵，保留关键 flag 与解析口径，删除利用链与武器化参数
-->

# 工具族配方矩阵（tool-recipes）

> 定位：三库「技能与命令配方」的价值转化层。每个工具族给出：用途 / 前置 / 授权级别 / 参数化命令模板 / 输出解析 / 证据字段 / 检测视角 / 禁止事项 / dry-run 默认。
> 主要上游：Claude-Red 各技能正文的命令与 flag；Strix CLI 纪律（`-n` 非交互、`--max-budget` 预算、`--max-turns` 轮次、退出码 `0/1/2`、产物目录 `strix_runs/<run>/`）；ACS 脚本的参数化模式（`argparse` 式显式参数、`output_dir` 固定、失败返回结构化错误）。
> 占位符约定：`<TARGET_URL>`、`<TARGET_HOST>`、`<TARGET_IP>`、`<USER>`、`<PASSWORD>`、`<TOKEN>`、`<WORDLIST>`、`<IMAGE>`、`<WORKDIR>`。示例目标只用保留域 `*.example.com` 与文档网段 `192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`、`2001:db8::/32`。
> 版本时效：工具 flag 以 2026-11-19 复核为准；工具大版本升级后需重跑模板并更新证据字段（尤其 `--json` 输出结构）。
> 消费者：`dsh-red-recon`、`dsh-red-discover`、`dsh-red-validate`、`dsh-red-exploit`、`dsh-red-post`，以及 `recon`/`assess`/`exploit`/`post` workflow。

## 0. 六个通用纪律（所有族共用）

1. **非交互**：一律加非交互/静默参数（`-silent`、`--batch`、`-n`），禁止进入 TUI；TUI 会阻塞 workflow 阶段。
2. **预算**：每族设速率与超时（`-rate-limit`、`-timeout`、`-retries 1`、`--max-time`），并把请求数计入 `budget.maxRequests`；到额即停。
3. **退出码**：`0` 正常；`1` 执行错误（工具缺失/参数错/网络失败）；`2` 有候选结论（仅在工具支持时，如 Strix `--fail-on`）。`2` 不等于「已确认漏洞」，必须交 `dsh-red-validate`。
4. **输出落盘**：所有输出写入 `<WORKDIR>/<phase>/<tool>-<target>-<ts>/`，同名重跑覆盖并保留旧哈希；脚本/阶段只读该目录。
5. **参数化**：命令模板里的目标、凭据、字典路径全部用占位符；运行时从 scope/args 注入，不写死在文档里。
6. **只读优先**：能用 list/get/describe 就不用 write；能只读证明就不做状态改变。

## F1 资产与子域枚举（DNS / 证书）

- **用途**：从公开数据与 DNS 建立资产清单（域名/子域/IP/URL），供 `recon.json`。
- **前置**：`subfinder`/`dnsx`/`httpx`（ProjectDiscovery 套件）；被动源可用网络，主动解析需 DNS 可达。
- **授权级别**：`passive`（仅公开数据源）/ `active`（对目标 DNS 解析与 HTTP 探活）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 被动：证书透明度 + 多源子域（不触达目标）
subfinder -d example.com -all -recursive -silent -o <WORKDIR>/recon/subs.txt
# 解析：DNS 层（不碰目标 HTTP）
dnsx -l <WORKDIR>/recon/subs.txt -a -resp -silent -o <WORKDIR>/recon/resolved.txt
# 探活 + 指纹：只有此步向目标发包，需 activeScan=true 且 dryRun=false
httpx -l <WORKDIR>/recon/resolved.txt -ports 80,443,8080,8443 -status-code -title -tech-detect -json -o <WORKDIR>/recon/live.json
```

- **输出解析**：`subs.txt` 每行一个 FQDN；`resolved.txt` 形如 `host [A] [ip]`；`live.json` 每行一个 JSON（`url/status_code/title/tech/webserver`）。用 `jq -r 'select(.status_code<400)|.url'` 过滤。
- **证据字段**：`commandSummary`（含 `-d` 值与源集合）、`ts`、`outputPath`、`sha256`/`bytes`、`excerpt`（命中行）、`source`（`ct`/`dns`/`http`）。
- **检测视角**：被动源无目标侧遥测；主动探活看 DNS 查询量、`User-Agent` 特征、短时多 Host 请求。
- **禁止事项**：不对未授权域名枚举；不做 AXFR 除非授权方书面允许；不把 wildcard 解析当资产。
- **dry-run 默认**：`true` → 只跑 passive 三行中的前两行；主动探活必须显式 `dryRun=false` + `activeScan=true`。

## F2 端口与服务识别

- **用途**：确认存活主机与开放服务，产出主机-端口-服务三元组。
- **前置**：`nmap`（需要原始套接字权限时用 `sudo`）；目标必须在 `targets[]` 内且为 `ip/host/cidr`。
- **授权级别**：`active`。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 先 TCP connect 扫（无需 root、速率可控），再对开放端口做版本探测
nmap -Pn -sT --top-ports 200 --max-rate 100 --host-timeout 120s -oX <WORKDIR>/recon/nmap-top.xml <TARGET_IP>
nmap -Pn -sT -sV --version-light -p <PORTS> --max-rate 50 -oX <WORKDIR>/recon/nmap-svc.xml <TARGET_IP>
```

- **输出解析**：XML 里 `host/ports/port[state=open]`，取 `portid/protocol/service@name@product@version`；CSV 化后按服务聚类。UDP 只做授权明确的少量端口。
- **证据字段**：`commandSummary`（含端口集合与速率）、`ts`、`outputPath`（XML 原文）、`sha256`、`excerpt`（`open` 行）。
- **检测视角**：防火墙/IDS 的 SYN 或连接扫描告警、`nmap` 指纹特征、异常端口遍历速率。
- **禁止事项**：禁止 `--script` 攻击类脚本、`-sU` 全端口、`-T4/-T5` 高速、`--script vuln`；禁止扫段外地址、禁止 `--exclude` 外泄式排除。
- **dry-run 默认**：`true` → 只输出命令与端口计划；不实际发包。

## F3 HTTP 指纹与内容发现

- **用途**：识别 Web 技术栈、WAF、目录/文件与默认页面，为类目测试提供入口。
- **前置**：`httpx`/`whatweb`/`wafw00f`/`ffuf`；字典放 `<WORKDIR>/wordlists/`（随插件不携带大字典）。
- **授权级别**：`active`。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
whatweb --no-errors -a 3 <TARGET_URL>
wafw00f <TARGET_URL>
# 目录发现：限速 + 只保留有意义状态码；URL 参数用占位符避免误伤
ffuf -w <WORDLIST> -u <TARGET_URL>/FUZZ -mc 200,204,301,302,401,403 -fs 0 -rate 20 -t 4 -timeout 10 -of json -o <WORKDIR>/discover/ffuf.json
```

- **输出解析**：`ffuf.json.results[]` 取 `status/url/length/words`；同一 `length` 大量命中视为软 404（用 `-fs` 过滤）。`whatweb` 输出取 `Title/Server/X-Powered-By/框架名`。
- **证据字段**：`commandSummary`、`ts`、`outputPath`、`sha256`、`excerpt`（状态码+URL+长度）、`wordlist`（字典名与哈希）。
- **检测视角**：WAF/access log 的 404 洪峰、异常 UA、目录遍历模式；`whatweb` 主动指纹的探测路径。
- **禁止事项**：禁止大字典暴力扫（默认 ≤2000 词、速率 ≤20/s）；禁止 `-recursion` 深递归；禁扫非授权路径前缀。
- **dry-run 默认**：`true` → 只做单请求指纹（whatweb），不做目录爆破。

## F4 爬取与 URL 归集

- **用途**：从页面与历史数据收集 URL/参数，形成测试入口清单。
- **前置**：`katana`/`gau`/`waybackurls`/`arjun`；历史数据源为公开数据集（只读）。
- **授权级别**：`passive`（历史数据）/ `active`（爬取）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 主动爬取：限深、限速、同域
katana -u <TARGET_URL> -d 3 -jc -rate-limit 20 -timeout 10 -silent -o <WORKDIR>/discover/urls-crawl.txt
# 历史 URL（公开数据集，不触达目标）
gau example.com --threads 2 --timeout 15 | head -2000 > <WORKDIR>/discover/urls-history.txt
# 参数发现：对已知端点枚举参数名（只读 GET，限速）
arjun -u <TARGET_URL>/search -m GET --stable -t 4 --timeout 10 -oJ <WORKDIR>/discover/arjun.json
```

- **输出解析**：URL 清单先去重、去静态资源、按 path 模板聚类（`/user/{id}`）；参数清单取 `arjun.json` 的 `params[]`。历史 URL 只保留与授权域同后缀者。
- **证据字段**：`commandSummary`、`ts`、`outputPath`、`sha256`、`excerpt`（前 20 条 URL）、`source`（`crawl`/`history`/`param-mining`）。
- **检测视角**：爬虫 UA、异常请求量、参数探测的 400/200 差异。
- **禁止事项**：禁止跨域爬取、禁止跟随 target 提供的站外链接、禁止对历史 URL 直接发包（历史资产不等于授权资产）。
- **dry-run 默认**：`true` → 只归集历史 URL，不主动爬取。

## F5 漏洞扫描与模板

- **用途**：用成熟模板做已知问题面覆盖，产出候选而非结论。
- **前置**：`nuclei`（模板版本需记录）、`nikto`；扫描目标必须在 scope 内。
- **授权级别**：`active`。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 只跑 info/exposure/misconfig 类模板，避开 intrusive 与 fuzz 类
nuclei -l <WORKDIR>/recon/live-urls.txt -severity info,low,medium,high,critical \
  -tags exposure,misconfig,tech -etags intrusive,fuzz,brute-force \
  -rate-limit 30 -timeout 10 -retries 1 -jsonl -o <WORKDIR>/discover/nuclei.jsonl
nikto -h <TARGET_URL> -Tuning 123b -timeout 10 -maxtime 120s -Format json -output <WORKDIR>/discover/nikto.json
```

- **输出解析**：`nuclei.jsonl` 取 `template-id/info.severity/matched-at/extracted-results`；同一 `template-id` + `host` 去重。`nikto.json` 取 `id/OSVDB/msg/uri`。
- **证据字段**：`commandSummary`（含模板标签与排除项、模板版本）、`ts`、`outputPath`、`sha256`、`excerpt`（模板 id + 匹配位置）。
- **检测视角**：模板指纹（请求路径/参数组合）、扫描速率、`nuclei` 默认 UA 与并发特征。
- **禁止事项**：禁止 `-tags intrusive`/`dos`/`fuzz`；禁止 `-headless` 浏览器模板对生产压测；禁止自动 `-interactsh` 外联（需先获授权）。
- **dry-run 默认**：`true` → 只做模板清单与目标匹配预览（`-validate` 或 `-tl`）。

## F6 Web 模糊与参数测试

- **用途**：验证输入处理差异（反射、类型、边界、编码），支撑 web 类目候选。
- **前置**：`ffuf`（`-w` 小字典）/`curl`；测试载荷必须无害（算术/回显串）。
- **授权级别**：`active`。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 参数值模糊：固定端点，替换参数值；用无害标记串观察反射与状态差异
ffuf -w <WORDLIST> -u '<TARGET_URL>/search?q=FUZZ' -mc all -fs 0 -rate 10 -t 2 -timeout 10 \
  -of json -o <WORKDIR>/discover/fuzz-q.json
# 单点对照：控制值 vs 测试值（只改一个变量）
curl -sS -o /dev/null -w 'ctrl code=%{http_code} size=%{size_download}\n' '<TARGET_URL>/search?q=control123'
curl -sS -o /dev/null -w 'test code=%{http_code} size=%{size_download}\n' '<TARGET_URL>/search?q=7*7'
```

- **输出解析**：对比 `status/length/words` 三列，找「同状态但长度差异显著」或「状态跃迁」；反射判定看响应体是否含输入串。
- **证据字段**：`commandSummary`（含完整 URL 编码后参数）、`ts`、`outputPath`、`sha256`、`excerpt`（响应关键行）、`payloadClass`（`arithmetic`/`marker`/`boundary`）。
- **检测视角**：WAF 规则命中、同一参数高频变异、异常编码序列。
- **禁止事项**：禁止可执行/破坏性载荷（命令、模板执行、文件写入、超大 body）；禁止并发 >4；禁止对同端点做写操作模糊。
- **dry-run 默认**：`true` → 只输出对照请求计划。

## F7 SQL 注入验证

- **用途**：判定参数是否进入 SQL 上下文（只读证据），不做数据导出。
- **前置**：`sqlmap`（或用 `curl` 做布尔/时间差分）；目标必须已获授权且为测试环境优先。
- **授权级别**：`active`（`--risk 1 --level 1` 只读探测）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
sqlmap -u '<TARGET_URL>/item?id=1' --batch --smart --level 1 --risk 1 --technique=BEUST \
  --threads 1 --timeout 10 --retries 1 --output-dir <WORKDIR>/discover/sqlmap --dbs
```

- **输出解析**：`sqlmap` 结果目录的 `log` 与 stdout 关键行（`Parameter: id (GET)`、`Type: boolean-based blind`、`back-end DBMS: ...`）；`--dbs` 只取库名列表作为「可读元数据」证据。
- **证据字段**：`commandSummary`（含 level/risk/technique）、`ts`、`outputPath`、`sha256`、`excerpt`（注入点行）、`payloadClass: arithmetic`（时间/布尔差分参数应写具体秒数）。
- **检测视角**：WAF SQLi 规则、异常 `SLEEP` 型延迟、重复布尔请求、`sqlmap` UA。
- **禁止事项**：禁止 `--os-shell`/`--os-pwn`/`--sql-shell`/`--file-read`/`--file-write`/`--dump-all`/`--passwords`；禁止 `--risk 2+`、`--level 3+`、`--tamper` 绕过链；禁止导出业务数据。
- **dry-run 默认**：`true` → 只做一次无害差分（算术/引号）确认参数反射，不启动 `sqlmap`。

## F8 API / GraphQL 测试

- **用途**：验证 API 认证、对象级授权、批量赋值、GraphQL 内省与限流。
- **前置**：`curl`（或 `httpie`）；`restler`/`schemathesis`（有 OpenAPI 时）；测试账号由授权方提供。
- **授权级别**：`active`。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 认证差异对照（A 账号令牌 vs 匿名）
curl -sS -H "Authorization: Bearer <TOKEN>" -o /dev/null -w 'auth=%{http_code}\n' '<TARGET_URL>/api/v1/users/1001'
curl -sS -o /dev/null -w 'anon=%{http_code}\n' '<TARGET_URL>/api/v1/users/1001'
# GraphQL 内省（只读 schema）
curl -sS -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name kind}}}"}' -o <WORKDIR>/discover/graphql-schema.json
```

- **输出解析**：状态码矩阵（`anon/auth/other-user`）→ 对象级授权差异；`graphql-schema.json` 取 `data.__schema.types[].name`；OpenAPI 用 `restler` 的 `-run` 摘要看 4xx/5xx 聚类。
- **证据字段**：`commandSummary`（含请求方法与路径、是否带令牌）、`ts`、`outputPath`、`sha256`、`excerpt`（状态码 + 响应片段）、`accountRole`（测试账号角色）。
- **检测视角**：API 网关的 401/403 比例、内省请求、异常对象 ID 遍历。
- **禁止事项**：禁止遍历他人对象 ID；禁止批量赋值写库；禁止限流压测（≤10 次阈值观察）；禁止用生产令牌。
- **dry-run 默认**：`true` → 只输出请求矩阵与账号映射，不发请求。

## F9 AD 枚举与利用框架（只读用法）

- **用途**：AD 姿态枚举（信任、ACL、委派、证书模板、策略），为身份类目提供证据。
- **前置**：`nxc`（NetExec）/`impacket` 套件/`bloodhound-python`/`certipy`/`ldapsearch`；凭据由授权方提供。
- **授权级别**：`active`（只读查询）；利用动作不在此族。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 目录与策略只读查询
nxc smb <TARGET_IP> -u <USER> -p <PASSWORD> --pass-pol
nxc ldap <TARGET_IP> -u <USER> -p <PASSWORD> --query "(objectClass=trustedDomain)" "name,trustDirection"
# BloodHound 采集（输出到 workDir，不上传）
bloodhound-python -d example.com -u <USER> -p <PASSWORD> -ns <TARGET_IP> -c All --zip -o <WORKDIR>/discover/bh
# ADCS 模板枚举（只读）
certipy find -u <USER>@example.com -p <PASSWORD> -dc-ip <TARGET_IP> -vulnerable -stdout
```

- **输出解析**：`nxc` 输出行看 `[+]`/`[-]` 与策略字段；BloodHound zip 用本地 ingestor 或直接读 JSON 的 `computers/users/groups/gpos`；`certipy` 输出看 `Template Name`/`Enrollee Supplies Subject`/`Client Authentication`。
- **证据字段**：`commandSummary`、`ts`、`outputPath`（zip/json 哈希）、`sha256`、`excerpt`（对象 DN/模板名，用户名脱敏为角色）、`domain`。
- **检测视角**：4662/5136、LDAP 大量查询、`bloodhound` 特征查询组合、证书模板枚举（CA 审计）。
- **禁止事项**：禁止凭据转储、票据请求后破解、中继、证书申请滥用、ACL 修改；禁止使用域管凭据做枚举。
- **dry-run 默认**：`true` → 只输出查询清单与所需权限，不连接域控。

## F10 云评估（AWS / Azure / GCP）

- **用途**：云侧只读姿态评估（身份、存储、密钥、日志、暴露面）。
- **前置**：对应 CLI 已配置**只读**凭据；账号/订阅/项目 ID 在 scope 中声明。
- **授权级别**：`active`（只读 API）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <IAM_USER>
aws s3api list-buckets --query 'Buckets[].Name'
aws s3api get-bucket-policy --bucket <BUCKET>
az account show && az role assignment list --all --assignee <OBJECT_ID>
gcloud auth list && gcloud projects get-iam-policy <PROJECT_ID>
```

- **输出解析**：`get-caller-identity` 得账号与 principal；IAM 列表看宽泛 `Action:"*"`/`Resource:"*"`；桶策略看 `Principal:"*"` 且无 `Deny`；角色分配看 `Owner/Contributor` 范围。
- **证据字段**：`commandSummary`、`ts`、`outputPath`、`sha256`、`excerpt`（策略片段，资源名脱敏）、`accountId`（哈希后引用）、`region`。
- **检测视角**：CloudTrail/Activity Log/Audit Logs 的 `List*`/`Get*` 洪峰、异常 `AssumeRole` 源、IAM 变更。
- **禁止事项**：禁止写/删资源、禁止读 secret 值、禁止下载对象、禁止创建访问密钥、禁止跨账号枚举。
- **dry-run 默认**：`true` → 只输出「将要调用的只读 API 清单」。

## F11 容器与编排

- **用途**：镜像与集群配置风险判定（漏洞、RBAC、工作负载、基线）。
- **前置**：`trivy`/`syft`/`grype`/`kube-bench`/`kubectl`；镜像可先离线保存。
- **授权级别**：`active`（只读）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
trivy image --severity HIGH,CRITICAL --format json -o <WORKDIR>/discover/trivy.json <IMAGE>
syft <IMAGE> -o cyclonedx-json=<WORKDIR>/discover/sbom.json
kubectl auth can-i --list
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" privileged="}{.spec.containers[*].securityContext.privileged}{"\n"}{end}'
kube-bench --json --outputfile <WORKDIR>/discover/kube-bench.json
```

- **输出解析**：`trivy.json.Results[].Vulnerabilities[]` 取 `VulnerabilityID/Severity/FixedVersion`；SBOM 取组件与版本；`auth can-i --list` 看 `*` 权限；jsonpath 看 `privileged=true` 与 hostPath。
- **证据字段**：`commandSummary`、`ts`、`outputPath`、`sha256`、`excerpt`（CVE/字段值）、`imageDigest`（镜像 digest，替代可变 tag）。
- **检测视角**：镜像扫描报告差异、K8s audit 的 `exec`/`create clusterrolebinding`、异常特权 Pod。
- **禁止事项**：禁止逃逸/宿主操作、禁止改 RBAC/工作负载、禁止推送镜像、禁止用可变 tag 当证据。
- **dry-run 默认**：`true` → 只做本地/离线扫描计划，不连接集群。

## F12 无线与射频

- **用途**：空口测绘与加密/协议姿态判定（被动）。
- **前置**：支持监听模式的适配器、合规管制域、现场授权。
- **授权级别**：`passive`（默认）/`active`（仅限授权信道观察）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
iw dev && iw reg get
sudo airodump-ng <IFACE> --band abg --write <WORKDIR>/wireless/ap --output-format pcap,csv
kismetdb_dump_devices --in <WORKDIR>/wireless/ap.kismet --out <WORKDIR>/wireless/ap.csv
```

- **输出解析**：CSV 列 `BSSID/channel/privacy/cipher/auth/ESSID`；`privacy` 与 `cipher` 组合判定 WEP/TKIP/PSK/SAE；`--band abg` 分批避免丢包。
- **证据字段**：`commandSummary`、`ts`（起止）、`outputPath`（pcap/csv）、`sha256`、`excerpt`（BSSID 脱敏行）、`location`。
- **检测视角**：WIDS 的监听模式设备、去认证/仿冒告警（我们只观察不制造）。
- **禁止事项**：禁止注入/去认证/仿冒 AP/破解/重放；禁止超管制域功率与频段；禁止采集业务流量内容。
- **dry-run 默认**：`true` → 只做适配器与管制域自检。

## F13 IoT / 固件

- **用途**：固件与设备配置的静态风险判定（凭据、服务、OTA）。
- **前置**：`binwalk`/`strings`/`file`；固件为授权获取的样本；分析机隔离。
- **授权级别**：`active`（静态）/`passive`（只读嗅探）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
file firmware.bin && binwalk firmware.bin
binwalk -Me firmware.bin -C <WORKDIR>/iot/fw-out
strings -n 6 firmware.bin | grep -iE 'passwd|secret|token|mqtt|ssid|http' | head -40
mosquitto_sub -h mqtt.example.com -t 'site/<SITE>/#' -C 20 -W 15 -v
```

- **输出解析**：`binwalk` 列表看文件系统类型与偏移；解包后看 `etc/passwd`（哈希类型）、`etc/init.d`（启动服务）、`/etc/config`；`strings` 命中按类型归类（凭据/URL/密钥）。
- **证据字段**：`commandSummary`、`ts`、`outputPath`、`sha256`（固件与解包目录清单）、`excerpt`（偏移 + 脱敏命中）、`firmwareVersion`。
- **检测视角**：设备管理平台的固件版本突变、调试接口开启、OTA 校验失败。
- **禁止事项**：禁止刷写/短接/改板（除书面同意 + 现场）、禁止执行固件内二进制、禁止把命中串当可用口令、禁止订阅非授权主题。
- **dry-run 默认**：`true` → 只做 `file`/`binwalk` 列表，不解包、不 grep 敏感项。

## F14 移动应用

- **用途**：App 静态风险判定（组件、存储、传输、配置）与授权测试机上的只读动态观察。
- **前置**：`apktool`/`jadx`（静态）、`frida-ps`（只读进程）；测试机由授权方提供。
- **授权级别**：`active`（静态）/`active` + 测试机（动态只读）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
apktool d app-release.apk -o <WORKDIR>/mobile/decoded --no-src
jadx -d <WORKDIR>/mobile/src --no-res app-release.apk
grep -nE 'android:exported|intent-filter|uses-permission|scheme' <WORKDIR>/mobile/decoded/AndroidManifest.xml | head -40
frida-ps -U | head -30
```

- **输出解析**：Manifest 看 `exported=true` 且无权限保护的组件、深链 scheme/host；`jadx` 搜 `http://`、`apiKey`、`firebase`、`pin`；`res/values/strings.xml` 看环境地址。
- **证据字段**：`commandSummary`、`ts`、`outputPath`、`sha256`（APK/解包）、`excerpt`（组件/配置行，密钥脱敏）、`appVersion`/`packageName`。
- **检测视角**：后端 API 的异常设备指纹、证书固定失败、深链滥用；App 完整性校验失败。
- **禁止事项**：禁止装到真实用户设备、禁止读取真实用户数据、禁止上传第三方分析平台、禁止绕过生产环境防护做利用。
- **dry-run 默认**：`true` → 只做静态解包与清单检索，不连测试机。

## F15 凭据与提权枚举（只读）

- **用途**：判定「是否存在提权/凭据可得性」，不做利用、不读取凭据内容。
- **前置**：目标主机上的只读枚举命令或授权方提供的枚举报告；枚举脚本需本地副本并核对哈希。
- **授权级别**：`post`（报告-only）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
id && uname -a && sudo -l 2>/dev/null
find / -perm -4000 -type f 2>/dev/null | head -50
getcap -r / 2>/dev/null | head -50
ls -l ~/.ssh 2>/dev/null
```

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```powershell
whoami /priv
whoami /groups
net localgroup administrators
```

- **输出解析**：`sudo -l` 的 `(ALL)`/`NOPASSWD` 行；SUID 名单与 GTFOBins 交叉（只标注，不执行）；`getcap` 的 `cap_setuid`/`cap_dac_*`；`whoami /priv` 的 `SeImpersonate*`；组归属看本地管理员。
- **证据字段**：`commandSummary`、`ts`、`outputPath`、`sha256`、`excerpt`（权限行）、`hostRole`。
- **检测视角**：EDR 的枚举命令链、`sudo` 审计、SUID 批量读取、权限查询频率。
- **禁止事项**：禁止提权利用、令牌冒用、内核利用、凭据转储、读取密钥内容、写 cron/systemd/计划任务。
- **dry-run 默认**：`true` → 只输出枚举计划与命令清单，不落目标主机。

## F16 横向可达性与凭据复用（只读）

- **用途**：评估横向路径的「可达 + 认证可用 + 检测可见」，不执行横向。
- **前置**：已授权的源/目标主机、凭据类型信息（不复制材料）、资产清单。
- **授权级别**：`post`（报告-only）。
- **命令模板**：

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 单主机协议与共享枚举（只读；禁止批量扫段）
nxc smb <TARGET_IP> -u <USER> -p <PASSWORD> --shares
nxc smb <TARGET_IP> -u <USER> -p <PASSWORD> --sessions 2>/dev/null || true
smbclient -L <TARGET_IP> -N 2>/dev/null | head -30
# 服务端 TLS 与证书（只读握手）
openssl s_client -connect <TARGET_HOST>:443 -servername <TARGET_HOST> -brief </dev/null
```

- **输出解析**：`--shares` 的 `READ/WRITE` 列（写权限只标注，不写）；`--sessions` 的会话账号；`smbclient -L` 的共享名；`s_client` 的协议版本与证书主体/有效期。
- **证据字段**：`commandSummary`、`ts`、`outputPath`、`sha256`、`excerpt`（共享名/协议版本）、`fromHost`/`toHost`（角色名脱敏）。
- **检测视角**：登录日志（4624/4625、Kerberos）、SMB 会话建立、共享访问审计。
- **禁止事项**：禁止实际远程执行/会话复用/隧道、禁止批量扫段、禁止口令喷洒、禁止写共享、禁止读业务文件。
- **dry-run 默认**：`true` → 只输出可达性判定矩阵（协议 × 认证类型 × 可见性），不发起连接。

## 附：工具族 → 技能/参考映射

| 族 | 主要使用阶段 | 加载参考 |
|---|---|---|
| F1–F4 | recon | `recon-osint.md` |
| F5–F8 | discover（web/api） | `discover-web-api.md` |
| F9 | discover（identity） | `discover-identity-ad.md` |
| F10–F11 | discover（cloud/container） | `discover-cloud-container.md` |
| F12 | discover（wireless） | `discover-wireless.md` |
| F13–F14 | discover（ot/mobile/iot） | `discover-ot-mobile-iot.md` |
| F15–F16 | post | `post-readonly.md` |
| 全部 | validate / exploit / report | `evidence-standards.md`、`report-format.md` |