# dsh-redblue 净化规则书（sanitization-rules）

- 策略版本：`R1-R12/v1`（2026-11-19 定稿）
- 机器实现：`tools/sanitize-lint.mjs`（零依赖）；人读规范：`policy/sanitization.md`（必须与本文件逐条一致）
- 适用对象：`skills/**/SKILL.md`、`references/**/*.md`、`workflow/*.js`、`lib/*.js`、`policy/*.md`、`schema/*.json`、`package.json`、`NOTICE`
- 不适用：`docs/`（规范本身）、`test/fixtures/`（故意含反例）、`.work/`（上游只读输入）、上游仓库副本（不得存在于插件内）
- 本文档是 R1–R12 的**唯一规范源**；`docs/requirements.md` §11 与 `docs/design.md` §9 引用本文件的检查 ID

---

## 1. 术语与失败级别

| 术语 | 含义 |
|---|---|
| `blocker` | 阻断发布：`--strict` 下 lint 退出码 1，任何任务不得声称"净化通过" |
| `warning` | 不阻断，但必须记录在 `docs/verification.md` 并由人工评审确认 |
| `check` | 一条可运行检查，ID 形如 `R2-RESERVED`，可单独用 `--check` 选择 |
| `fixture` | 测试用正/反例文件；lint 不扫描 `test/fixtures/` |
| `lane` | 技能分组：`rb`/`red`/`blue`/`purple`（由 name 前缀决定） |
| `POLICY` | lint 内嵌的白名单/正则/阈值常量集合，版本 `R1-R12/v1` |

失败级别约定：

- R1–R10、R12 的核心检查为 **blocker**（含少数明确标注的 warning 子检查）；
- R11 全部为 **warning**（人工评审项）；
- 单条检查可能因上下文不同而升级/降级，规则内逐条写明，未写明一律按 check 表的级别执行（§7）。

## 2. 适用范围与扫描根

| 扫描根 | 默认扫描 | 说明 |
|---|---|---|
| `skills/` | 是 | 15 个 `SKILL.md`；R6/R7/R8/R12 主要对象 |
| `references/` | 是 | 27 篇派生参考 + `INDEX.md`；R1/R2/R3/R5/R9/R10 主要对象 |
| `workflow/` | 发布门禁 | 9 个 `.js`；R4/R8/R12 静态检查 |
| `lib/` | 发布门禁 | provider；R4/R12 静态检查 |
| `policy/` | 发布门禁 | 人读规范；R2/R3/R10 文本检查 |
| `schema/` | 发布门禁 | JSON Schema；R2 白名单域检查（`$id` 使用 `dsh.local`） |
| 根目录 asset（`*.yml`/`*.yaml`/`*.svg`/`*.txt`） | 是 | `R1`（仅声明 provenance 头的资产）/`R2`/`R10`；如 `icon.svg`、`cordis.patch.yml` |
| `package.json`、`NOTICE` | 发布门禁 | R1 许可与归属检查 |

忽略：`docs/**`、`test/fixtures/**`、`node_modules/**`、`.work/**`、任何 `*.bak`/临时文件。

## 3. 工具契约

```bash
# 默认门禁（与 handoff §6 一致；无路径参数 = PLUGIN_ROOT）
node tools/sanitize-lint.mjs --strict --json

# 发布门禁（完整；同上，插件根）
node tools/sanitize-lint.mjs --strict --json

# 单条检查
node tools/sanitize-lint.mjs --strict --check R2-RESERVED,R2-DENYLIST --json skills references
# 列出全部检查 ID 与级别
node tools/sanitize-lint.mjs --list-checks
```

CLI 参数：

| 参数 | 语义 |
|---|---|
| `--strict` | 存在任一 blocker 即退出码 1；缺省时只报告不阻断（退出码 0） |
| `--json` | 输出 JSON（默认文本）；JSON 结构见下 |
| `--check <ID[,ID…]>` | 只运行指定检查；未知 ID → 用法错误（退出码 2） |
| `--list-checks` | 打印检查注册表并退出 0 |
| `--policy <path>` | 指定 POLICY 常量文件（默认内嵌 `R1-R12/v1`）；**仅测试可用**：需 `NODE_ENV=test` 或显式 `--allow-policy-override`，否则用法错误（exit 2）；发布门禁**不得**携带该参数 |
| `--allow-policy-override` | 测试用显式确认：允许 `--policy` 覆盖内嵌 POLICY；不改变发布门禁的默认路径 |
| `--allow-empty` | 空目录/无匹配扩展名时默认 exit 2；显式允许空扫描才返回 0 |

JSON 输出结构：

```json
{
  "version": "dsh-redblue-sanitize/v1",
  "policy": "R1-R12/v1",
  "generatedAt": "2026-11-19T06:10:00.000Z",
  "strict": true,
  "checks": [
    {"id": "R2-RESERVED", "rule": "R2", "level": "blocker", "status": "fail", "file": "skills/red-recon/SKILL.md", "line": 42, "message": "non-reserved domain: acme-corp.io", "evidence": "curl https://acme-corp.io/…"}
  ],
  "summary": {"blockers": 1, "warnings": 0, "checkedFiles": 15}
}
```

退出码：`0` 无 blocker 或未加 `--strict`；`1` `--strict` 下存在 blocker；`2` 用法/内部错误。

> **R7 保证性说明（2026-11-20，t22）**：`--policy` 以 `{...DEFAULT_POLICY, ...raw}` 覆盖白名单/阈值；为防止发布命令误用导致 R1–R12 被弱化，CLI 默认拒绝该参数（仅 `NODE_ENV=test` 或显式 `--allow-policy-override` 放行）。发布门禁必须使用 §9 的无 `--policy` 命令，默认使用内嵌 POLICY。

## 4. 全局白名单（POLICY v1）

### 4.1 保留域名（RFC 2606 / RFC 6761）

`example.com`、`example.net`、`example.org`（含任意子域）；保留 TLD：`.test`、`.example`、`.invalid`、`.localhost`（含任意子域）。匹配规则：host 完全等于条目，或以 `.` + 条目结尾。

### 4.2 文档网段与回环（RFC 5737 / RFC 3849）

| 网段 | 用途 |
|---|---|
| `192.0.2.0/24` | TEST-NET-1 |
| `198.51.100.0/24` | TEST-NET-2 |
| `203.0.113.0/24` | TEST-NET-3 |
| `2001:db8::/32` | IPv6 文档前缀 |
| `127.0.0.0/8`、`::1` | 本机回环（仅作本地示例） |
| `0.0.0.0`、`::`、`0.0.0.0/0`、`::/0` | **仅允许出现在"禁止/拒绝"语境或门禁 ID 说明中**（R4-WILDCARD 例外），不得作为示例目标 |

### 4.3 保留邮箱与 OAST

- 邮箱仅允许：`*@example.com`、`*@example.net`、`*@example.org`、`*@*.test`、`*@*.invalid`、`*@*.localhost`。
- OAST/OOB 仅允许：`*.oast.example.test`、`*.oast.test`、`*.interact.test`（均落在保留 TLD 下）。
- 严禁真实姓名 + 真实域名的邮箱；严禁真实个人手机号（§4.8）。

### 4.4 权威引用域（链接与引用，host 匹配含子域）

| # | 域 | 用途 |
|---|---|---|
| 1 | `github.com` | 上游仓库、检测规则仓库、项目主页 |
| 2 | `raw.githubusercontent.com` | 原始文件引用 |
| 3 | `nvd.nist.gov` | CVE/NVD 查询 |
| 4 | `cve.org` | CVE Program |
| 5 | `cve.mitre.org` | CVE 旧域（兼容引用） |
| 6 | `cwe.mitre.org` | CWE |
| 7 | `capec.mitre.org` | CAPEC |
| 8 | `attack.mitre.org` | ATT&CK |
| 9 | `owasp.org` | OWASP 方法论/Cheat Sheet |
| 10 | `first.org` | CVSS/EPSS 规范 |
| 11 | `nist.gov` | NIST 出版物（含 csrc.nist.gov） |
| 12 | `cisa.gov` | CISA 公告/基线 |
| 13 | `sans.org` | 检测/DFIR 公开资料 |
| 14 | `sigmahq.io` | Sigma 规则与规范 |
| 15 | `mitre.org` | MITRE 其他公开资料 |
| 16 | `msrc.microsoft.com` | 微软安全公告 |
| 17 | `learn.microsoft.com` | 微软产品文档（版本时效内容） |
| 18 | `docs.aws.amazon.com` | AWS 文档 |
| 19 | `cloud.google.com` | GCP 文档 |
| 20 | `kubernetes.io` | Kubernetes 文档 |
| 21 | `docs.docker.com` | Docker 文档 |
| 22 | `rfc-editor.org` | RFC 全文 |
| 23 | `datatracker.ietf.org` | IETF 草案/状态 |
| 24 | `ietf.org` | IETF 首页 |
| 25 | `json-schema.org` | JSON Schema 规范 |
| 26 | `json.schemastore.org` | SARIF schema |
| 27 | `schemastore.org` | schema 目录 |
| 28 | `spdx.org` | SPDX 许可标识 |
| 29 | `semver.org` | 版本语义 |
| 30 | `dsh.local` | 插件内部 schema `$id` 占位域（不解析） |

### 4.5 工具/平台引用域（只允许"产品/文档引用"，不得作为示例目标）

`crt.sh`、`shodan.io`、`censys.io`、`urlscan.io`、`virustotal.com`、`portswigger.net`、`projectdiscovery.io`。

> 与 §4.4 相同匹配规则；若出现在代码块/JSON 的目标字段（`target`/`targets`/`-u`/`--url`/`--target`），由 `R2-EXAMPLE-TARGET` 判 blocker。

### 4.6 显式 denylist（即使可注册也禁止出现）

`attacker.com`、`evil.com`、`malware.com`、`phishing.com`、`badguy.com`、`evil.test`、`attacker.test`。

> denylist 优先于保留域规则；命中即 blocker，错误信息注明"禁止使用攻击者风格域名"。

### 4.7 私有网段（仅在 lab-only 块内允许）

`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`100.64.0.0/10`、`fc00::/7`、`fe80::/10`。

允许条件：出现在 fenced code block 中，且 info string 含 `lab-only`（例如 ```` ```text lab-only ````）。否则 `R2-PRIVATE` 判 blocker（避免泄露真实内网拓扑）。

### 4.8 禁止的真实标识

- 真实第三方组织/客户域名：**任何不在 §4.1/§4.4/§4.5 的域名** → blocker（这是白名单制，不是黑名单制）。
- 真实邮箱（非保留域）、中国大陆手机号（`1[3-9]\d{9}`，前后非数字）、美式 SSN（`\d{3}-\d{2}-\d{4}`）→ blocker（R10-PII）。
- 内网主机名后缀 `.internal`/`.corp`/`.lan`/`.local`/`.home`/`.intranet`（`dsh.local`、`localhost` 例外）→ blocker（R10-INTERNAL-HOST）。
- 真实密钥/令牌/私钥（模式见 R10）→ blocker。

### 4.9 文件/标识符误报排除

以下 token 不作为域名/IP 检查对象：

- 含 `/` 或 `\` 的路径片段（`lib/index.js`、`a/b`）；
- 以常见文件扩展名结尾：`.md .json .jsonl .js .mjs .cjs .ts .tsx .yml .yaml .txt .svg .sarif .log .csv .pcap .zip .sha256 .schema.json`；
- 纯版本号（`2.1.0`、`v1.2`，末段非 TLD 字母）；
- `localhost`、`dsh.local`；
- SPDX 许可标识（`Apache-2.0`、`MIT`）。

域名识别的 TLD 判定使用 `TLD_POLICY v1` 常见 TLD 列表（com/net/org/io/dev/ai/co/cn/uk/de/jp/ru/in/br/fr/nl/se/no/fi/dk/pl/it/es/ca/au/ch/at/be/cz/pt/gr/tr/kr/tw/hk/sg/my/id/th/vn/ph/nz/za/mx/ar/cl/il/ae/sa/ir/pk/bd/lk/np/site/xyz/info/me/tech/security/sh/run/top/online/store/edu/gov/mil/us）；`.zip`、`.mov` 等与文件名冲突的 TLD 不纳入，属已知覆盖限制。

## 5. 术语表（R11 判定依据）

| 概念 | 规范写法 | 说明 |
|---|---|---|
| 安全发现对象 | `finding` | 不译；中文行文可用"该 finding" |
| 发现阶段 | 发现阶段（流程名） | 与对象 `finding` 区分 |
| 判定结论 | `disposition`（`reportable`/`suppressed`/`not_applicable`/`deferred`） | 枚举值不译 |
| 授权范围对象 | `scope` | 首次出现可写"scope（授权范围对象）" |
| 交战规则 | `RoE` | 首次出现写"RoE（交战规则）" |
| 目标 | `target`（字段/JSON）、"目标"（正文） | 代码与字段名一律英文 |
| 证据 | `evidence`（字段）、"证据"（正文） | — |
| 试运行 | `dryRun` | 不译 |
| 封存 | `seal` / "封存" | 首次出现写"seal（封存）" |
| 覆盖 | `coverage` / "覆盖" | — |
| 标准格式 | `SARIF`、`manifest`、`ATT&CK`、`CVE`、`CWE` | 不译、不改大小写 |

## 6. 规则 R1–R12

### R1 来源与许可（provenance + NOTICE）

- **定义**：每个派生技能与每篇派生参考都必须可追溯（repo/commit/license/path/last-verified/rewrite-summary）；插件根 `NOTICE` 必须列全三个上游、各自许可与修改声明；`package.json` 许可必须为 Apache-2.0，`LICENSE` 必须是 Apache-2.0 全文。
- **判定方法**：解析 `SKILL.md` frontmatter 与 `references/**/*.md` 的 provenance 注释块（`INDEX.md` 用 `dsh-redblue:index` 头），逐键校验；`source-commit` 必须 ∈ 三个 pin；`source-license` 必须与仓库匹配；`NOTICE` 必须同时包含三仓库 URL、三 commit、`Modifications:`、MIT 许可文本与版权行（大小写不敏感）、`Apache-2.0`。
- **可运行检查**：
  - `R1-PROVENANCE`（blocker）：
    `node dsh-redblue/tools/sanitize-lint.mjs --strict --check R1-PROVENANCE --json dsh-redblue/skills dsh-redblue/references`
  - `R1-NOTICE`（blocker）：
    `node dsh-redblue/tools/sanitize-lint.mjs --strict --check R1-NOTICE --json dsh-redblue/NOTICE`
  - `R1-LICENSE`（blocker）：
    `node dsh-redblue/tools/sanitize-lint.mjs --strict --check R1-LICENSE --json dsh-redblue/package.json dsh-redblue/LICENSE`
- **例外白名单**：`references/INDEX.md` 使用 `<!-- dsh-redblue:index -->` 头（允许不含 `source-path`，但必须列三 commit）；`docs/`、`test/fixtures/` 不扫描；`NOTICE` 内引用的 MIT 全文段落不参与文本检查。
- **覆盖范围（2026-11-20，t22）**：`skills/**/SKILL.md`（frontmatter）、`references/**/*.md`（provenance/index 注释块）；**声明了 `dsh-redblue:provenance` 头的 asset（`*.yml`/`*.yaml`/`*.svg`/`*.txt`）同样按 reference 六键校验**（`R1-PROVENANCE`，消息前缀 `asset `）。未声明 provenance 的资产（如 `icon.svg`、`cordis.patch.yml`）不是 R1 对象，由 R2/R10 覆盖。
- **失败级别**：三项均 blocker。

### R2 占位符净化（目标与引用）

- **定义**：示例与占位符只允许保留域、文档网段、回环与 OAST；引用链接只允许权威/工具白名单域；禁止真实第三方域名/IP/邮箱与攻击者风格域名；私有网段仅允许出现在 `lab-only` 代码块。
- **判定方法**：
  1. 提取文本中的 host/IP/邮箱 token（排除 §4.9）；
  2. 域名按 §4.1/§4.4/§4.5 白名单匹配，其余 → fail；denylist 优先；
  3. IP 按 §4.2 判定；私有网段按 §4.7（检查所在 fenced block info string）；
  4. Markdown 链接 `[x](url)` 与裸 URL 的 host 按 §4.4/§4.5 判定；相对路径与锚点链接放行；
  5. 代码块/JSON 中目标字段（`target`/`targets`/`-u`/`--url`/`--target`）的取值必须为保留域/文档 IP/`<TARGET>` 占位符。
- **可运行检查**：
  - `R2-RESERVED`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R2-RESERVED --json dsh-redblue/skills dsh-redblue/references`
  - `R2-AUTHORITY-LINK`（blocker）：`… --check R2-AUTHORITY-LINK … dsh-redblue/skills dsh-redblue/references`
  - `R2-PRIVATE`（blocker；`lab-only` 块内 pass）：`… --check R2-PRIVATE … dsh-redblue/skills dsh-redblue/references`
  - `R2-DENYLIST`（blocker）：`… --check R2-DENYLIST … dsh-redblue/skills dsh-redblue/references`
  - `R2-EXAMPLE-TARGET`（blocker）：`… --check R2-EXAMPLE-TARGET … dsh-redblue/skills dsh-redblue/references`
- **例外白名单**：§4.1/§4.2/§4.3/§4.4/§4.5 全部条目；`lab-only` 块内的 §4.7 私有网段；本地相对链接（`./x.md`、`../references/…`）；占位符 `<TARGET>`、`<AUTHORIZED-TARGET>`；`dsh.local` schema `$id`；`NOTICE`/`LICENSE` 不扫描（许可文本含版权人域名）。
- **失败级别**：五项均 blocker。

### R3 无武器化制品

- **定义**：禁止 webshell、反弹 shell 一行流、C2/木马配置、凭据 dump 配方、真实密钥、破坏性命令、持久化配方进入技能与参考；确需示例（检测规则/教学）必须带授权横幅且不得是可一键执行的完整利用链。
- **判定方法**：
  1. 扫描 fenced code block 与行内 code 的武器化正则（webshell/反弹 shell/C2/凭据 dump/持久化）；
  2. 全文本扫描破坏性命令正则（不区分代码块）；
  3. 含攻击性命令（info string ∈ `bash|sh|powershell|pwsh|cmd|python|http|sql|javascript`）的代码块，其前 3 行内必须出现规范授权横幅原文：
     `> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。`
  4. 检测签名块（info string 含 `sigma|kql|spl|eql|yara`）豁免 R3-WEAPON，但不豁免 R3-DESTRUCTIVE 与 R2。
- **武器化正则（POLICY v1 子集，大小写不敏感）**：
  - webshell：`eval\s*\(\s*\$_P(OST|GET|REQUEST)`、`assert\s*\(\s*\$_`、`aspxspy|c99shell|b374k`、`Runtime\.getRuntime\(\)\.exec\(\s*request\.getParameter`
  - 反弹 shell：`bash\s+-i\s*>&\s*/dev/tcp/`、`nc\s+(-[a-z]*e|.*\s-e\s)`、`ncat\s+.*-e\s`、`socat\s+.*EXEC:`、`python[23]?\s+-c\s+['"]import\s+socket`、`IEX\s*\(\s*New-Object\s+Net\.WebClient`、`msfvenom\s+-p\s+`
  - C2/凭据 dump：`mimikatz\s+sekurlsa::`、`procdump.*lsass`、`comsvcs\.dll.*MiniDump`、`secretsdump(\.py)?\s+`、`cobalt\s*strike\s+.*(beacon|powershell)`、`meterpreter`
  - 持久化：`schtasks\s+/create`、`New-Service\s+`、`reg\s+add\s+.*\\Run`、`crontab\s+-e`、`systemctl\s+enable\s+`、`>>\s*.*authorized_keys`
- **破坏性正则（全文本）**：`rm\s+-rf\s+/(\s|$|\*)`、`dd\s+.*of=/dev/(sd|nvme|vd)`、`:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:`、`mkfs\.`、`chmod\s+-R\s+777\s+/`、`vssadmin\s+(delete|resize)\s+shadows`、`bcdedit\s+/set`、`cipher\s+/w`、`format\s+[A-Za-z]:`、`DROP\s+DATABASE`、`SHUTDOWN`
- **可运行检查**：
  - `R3-WEAPON`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R3-WEAPON --json dsh-redblue/skills dsh-redblue/references`
  - `R3-DESTRUCTIVE`（blocker）：`… --check R3-DESTRUCTIVE … dsh-redblue/skills dsh-redblue/references dsh-redblue/workflow`
  - `R3-AUTH-BANNER`（blocker）：`… --check R3-AUTH-BANNER … dsh-redblue/skills dsh-redblue/references`
- **例外白名单**：检测签名块（`sigma/kql/spl/eql/yara`）豁免 R3-WEAPON；散文里点名工具（如"检测 Mimikatz 的 sekurlsa 行为"）不算代码，不触发 R3-WEAPON；`<PAYLOAD>`、`<TARGET>` 占位符；`NOTICE`/`docs/` 不扫描。
- **失败级别**：三项均 blocker。

### R4 授权门禁与安全默认

- **定义**：进攻性技能/workflow 必须声明并校验 scope；workflow 缺 scope 必须直接拒绝；禁止 `verify=False`；禁止无界扫描与全网目标；workflow 默认 `dryRun=true`；门禁必须覆盖授权/目标/模式/时间窗/预算/数据处置。
- **判定方法**：
  1. 文本（skills/references/workflow/lib）出现 `verify=False`（行内 code 或代码块）且同行无否定词 → fail；
  2. 文本出现 `--target *`、`--cidr 0.0.0.0/0`、`"targets": [{"value":"0.0.0.0/0"}]` 等无界目标（代码/JSON 语境）→ fail；
  3. 每个 `workflow/*.js` 必须包含默认 true 的 dryRun 表达式（固定写法见 design §7.1）→ 缺失 fail；
  4. 每个 `workflow/*.js` 必须包含 ≥8 个不同 `G-` 门禁 ID 字面量，且覆盖 `G-AUTH-`、`G-TGT-` 或 `G-DS-`、`G-MODE-`、`G-WIN-`、`G-BUD-`、`G-DH-` 前缀；`exploit.js`/`post.js` 还必须含 `G-CFM-01..04`；
  5. `test/workflow.test.mjs` 必须存在并断言"缺 scope → rejected"（由实现任务保证，lint 只检查文件存在性与关键词）。
- **可运行检查**：
  - `R4-VERIFY-DISABLED`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R4-VERIFY-DISABLED --json dsh-redblue/skills dsh-redblue/references dsh-redblue/workflow dsh-redblue/lib`
  - `R4-WILDCARD`（blocker）：`… --check R4-WILDCARD … dsh-redblue/skills dsh-redblue/references dsh-redblue/policy`
  - `R4-DRYRUN-DEFAULT`（blocker）：`… --check R4-DRYRUN-DEFAULT … dsh-redblue/workflow`
  - `R4-SCOPE-GATE`（blocker）：`… --check R4-SCOPE-GATE … dsh-redblue/workflow`
- **例外白名单**：散文/门禁说明中"禁止 `verify=False`"、"拒绝 `0.0.0.0/0`"（同行含 `禁止|不得|拒绝|never|forbidden`）不算命中；`test/fixtures/` 不扫描；`docs/` 不扫描。
- **失败级别**：四项均 blocker。

### R5 不制造虚假内容

- **定义**：禁止 `simulated/fake/mock/dummy` 结果生成器；效能数字（检出率/准确率/成功率/覆盖率）必须有可溯源引用；CVE 必须符合 `CVE-YYYY-NNNN` 并标注"已核实/待核实"。
- **判定方法**：
  1. `(simulated|synthetic|fake|mock|dummy)\s+(finding|result|scan|output|data|evidence)` → 若同句无否定词则 fail；
  2. `\d+(\.\d+)?\s*%` 与效能词（检出率/准确率/成功率/覆盖率/误报率/detection rate/accuracy）同现：±3 行内无 `source:`/`来源：`/权威域链接 → fail；仅数字百分比无效能词 → warning；
  3. `CVE-\d{4}-\d{4,7}` 格式校验（格式不符 → fail）；命中 CVE 但同一行/相邻行无 `已核实`/`待核实` → warning。
- **可运行检查**：
  - `R5-FAKE`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R5-FAKE --json dsh-redblue/skills dsh-redblue/references`
  - `R5-METRIC`（blocker + warning）：`… --check R5-METRIC … dsh-redblue/skills dsh-redblue/references`
  - `R5-CVE`（blocker + warning）：`… --check R5-CVE … dsh-redblue/skills dsh-redblue/references`
- **例外白名单**：带 `source:`/权威链接的数字；`N/A`、`<=1%` 之类的约束表述（无效能词）；`CVE-YYYY-NNNN` 规范占位（在术语表/格式说明中，`docs/` 不扫描）；`test/fixtures/` 不扫描。
- **失败级别**：R5-FAKE blocker；R5-METRIC 效能数字无来源 blocker、其他百分比 warning；R5-CVE 格式 blocker、缺核验标记 warning。

### R6 结构上限

- **定义**：`SKILL.md` ≤300 行且 ≤24 KiB；`description` ≤500 Unicode 码点（平台硬限 1024，本插件不依赖硬限）；必须有 `whenToUse`；每篇 reference ≤48 KiB；严禁整篇课程/培训材料。
- **判定方法**：
  1. 行数 = 按 `\r?\n` 分割后去掉末尾空行；字节 = UTF-8；
  2. description 长度按 Unicode 码点（`[...str].length`）；
  3. `whenToUse` 非空且不是占位词（如 `N/A`、"待定"、"占位"）——占位词直接 fail；
  4. reference 字节 >48 KiB fail；`references/INDEX.md` >24 KiB warning。
- **可运行检查**：
  - `R6-SKILL-SIZE`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R6-SKILL-SIZE --json dsh-redblue/skills`
  - `R6-DESC`（blocker）：`… --check R6-DESC … dsh-redblue/skills`
  - `R6-WHEN`（blocker）：`… --check R6-WHEN … dsh-redblue/skills`
  - `R6-REF-SIZE`（blocker）：`… --check R6-REF-SIZE … dsh-redblue/references`
- **例外白名单**：无。上限不因"内容重要"放宽；超限内容必须拆分或压缩（这也是剔除课程灌水的确定性手段：上游单文件 >48 KiB 只能被改写压缩，不能整篇搬运）。
- **失败级别**：`R6-REF-SIZE`/`R6-SKILL-SIZE`/`R6-DESC`/`R6-WHEN` blocker；`INDEX.md` 超 24 KiB 为 warning。

### R7 去重与触发隔离

- **定义**：15 个技能名唯一且与目录一致；同一 lane 内任意两技能 description 的 CJK bigram Jaccard ≤0.35；每条 description 必须含 `触发词：`（≥2 项）与 `不适用：`（点名至少一个兄弟技能）。
- **判定方法**：
  1. 名称集合 = `lib/index.js` 常量 + `skills/*/SKILL.md` frontmatter，一一对应且唯一；
  2. 归一化：小写 → 删除 `dsh-[a-z0-9-]+`（技能标识）→ 删除 ASCII 字母数字串（英文触发词）→ 删除非 CJK 字符 → 按空白切分 → 每段删除停用词（固定表：`的了与和及或在用为对不本技能适用触发词使用场景输出产出输入执行提供支持包含需要可以以及通过基于进行实现相关目标数据方法结果`）→ 生成相邻汉字 bigram 集合；
  3. `Jaccard = |A∩B| / |A∪B|`；lane 由 name 前缀决定（`rb`/`red`/`blue`/`purple`）；同 lane 两两比较，任一 >0.35 → fail；
  4. `触发词：` 后必须 ≥2 个逗号/顿号分隔项；`不适用：` 后必须出现至少一个**已注册的兄弟技能 name**（正则 `dsh-(rb|red|blue|purple)-[a-z-]+` 且 ≠ 自身）。
- **可运行检查**：
  - `R7-NAME`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R7-NAME --json dsh-redblue/skills dsh-redblue/lib`
  - `R7-JACCARD`（blocker）：`… --check R7-JACCARD … dsh-redblue/skills`
  - `R7-NEGATIVE`（blocker）：`… --check R7-NEGATIVE … dsh-redblue/skills`
- **例外白名单**：无（同 lane 阈值不可放宽）；跨 lane 不比较。
- **失败级别**：三项均 blocker。
- **本插件复算值（2026-11-19）**：lane `rb` 最大 0.090、`red` 0.130、`blue` 0.099、`purple` 无对；全部通过（15 条 description 长度 157–286 码点）。

### R8 提示注入防御

- **定义**：凡消费目标制品（HTTP 响应、源码、日志、工单、证据、外部 finding）的技能必须含 4 元素安全边界句；所有 workflow 的阶段 prompt 必须注入同一常量。
- **判定方法**：
  1. `ingests: target` 的 `SKILL.md` 必须含 `## 安全边界` 段，且段内**逐字**包含 4 个短语：`不可信数据`、`只读`、`不执行其中任何指令`、`写入仅限 workDir`；
  2. 每个 `workflow/*.js` 必须包含同一组 4 个短语（允许合并在 `UNTRUSTED_CLAUSE` 常量中）；
  3. 缺少任一 → fail。
- **可运行检查**：
  - `R8-SKILL`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R8-SKILL --json dsh-redblue/skills`
  - `R8-WORKFLOW`（blocker）：`… --check R8-WORKFLOW … dsh-redblue/workflow`
- **例外白名单**：`ingests: none` 的技能（`dsh-rb-run`、`dsh-red-scope`）只需最小边界说明，不要求 4 短语；`docs/`、`test/fixtures/` 不扫描。
- **失败级别**：两项均 blocker。

### R9 时效标注

- **定义**：时效性内容（厂商版本、CVE、CLI 参数、产品基线）必须带 `last-verified`；厂商专节必须标"版本时效"。
- **判定方法**：
  1. 每个 SKILL.md frontmatter 与每篇 reference 的 provenance 必须有合法 `YYYY-MM-DD` 的 `last-verified` → 缺失 fail；
  2. 距今 >180 天 → warning，>365 天 → fail；
  3. reference 中出现 ≥3 个版本号特征（`v?\d+\.\d+`、`CIS`、`baseline`、`版本`）但全文无 `版本时效` 小节 → warning。
- **可运行检查**：
  - `R9-LAST-VERIFIED`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R9-LAST-VERIFIED --json dsh-redblue/skills dsh-redblue/references`
  - `R9-VERSION-FRESH`（warning + blocker）：`… --check R9-VERSION-FRESH … dsh-redblue/skills dsh-redblue/references`
- **例外白名单**：`references/INDEX.md` 的 `dsh-redblue:index` 头同样要求 `last-verified`；`docs/` 不扫描。
- **失败级别**：缺 `last-verified` blocker；>180 天 warning；>365 天 blocker；缺"版本时效"小节 warning。

### R10 机密与隐私

- **定义**：禁止凭据/令牌/私钥/个人数据/内网主机名/真实客户名进入技能与参考。
- **判定方法**：
  1. 密钥模式（POLICY v1）：`AKIA[0-9A-Z]{16}`、`AIza[0-9A-Za-z_-]{35}`、`gh[pousr]_[A-Za-z0-9]{36,}`、`xox[baprs]-[0-9A-Za-z-]{10,}`、`sk_live_[0-9a-zA-Z]{24,}`、`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`、`-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`、`(api[_-]?key|secret|token|password)\s*[:=]\s*['"][A-Za-z0-9_\-]{16,}['"]`（`example/changeme/<...>` 占位放行）；
  2. PII：非保留域邮箱、`(?<!\d)1[3-9]\d{9}(?!\d)`（中国大陆手机号）、`\d{3}-\d{2}-\d{4}`（美式 SSN）；
  3. 内网主机名：`\b[a-z0-9-]+\.(internal|corp|lan|local|home|intranet)\b`（`dsh.local`、`localhost` 例外）；
  4. 真实客户名：机器无法枚举 → 由 `R10-PII` 的"非白名单组织域名"与人工评审共同覆盖（§8）。
- **可运行检查**：
  - `R10-SECRET`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R10-SECRET --json dsh-redblue/skills dsh-redblue/references`
  - `R10-PII`（blocker）：`… --check R10-PII … dsh-redblue/skills dsh-redblue/references`
  - `R10-INTERNAL-HOST`（blocker）：`… --check R10-INTERNAL-HOST … dsh-redblue/skills dsh-redblue/references`
- **例外白名单**：保留域邮箱（§4.3）；`example`/`changeme`/`<API_KEY>` 等明显占位；`dsh.local`、`localhost`；`docs/` 与 `test/fixtures/` 不扫描（本文件的模式串即在此列）。
- **失败级别**：三项均 blocker。

### R11 语言与术语

- **定义**：正文中文、技术标识符英文；术语按 §5 表统一；禁止半翻译病句与混用。
- **判定方法**：启发式 + 人工评审：
  1. 同一文件同时出现对象 `finding` 与中文"发现"作名词（`发现(?!阶段|到|了|的|漏洞|问题)` ≥1）→ warning；
  2. 同一文件混用 `scope` 与"范围对象"、"disposition" 与"处置/判定结论" → warning；
  3. 代码块与行内标识符不参与判定。
- **可运行检查**：`R11-TERMINOLOGY`（warning）：`node dsh-redblue/tools/sanitize-lint.mjs --check R11-TERMINOLOGY --json dsh-redblue/skills dsh-redblue/references dsh-redblue/policy`
- **例外白名单**：`docs/` 不扫描；术语表所在段落（§5）不计；引用上游原文标题（如 "When to Use"）不译。
- **失败级别**：全部 warning；发布前必须由人工评审在 `docs/verification.md` 记录"术语一致"签字。

### R12 风险分级与安全默认

- **定义**：每个技能 frontmatter 必须声明 `risk` 与 `requires`，并与技能名 lane 的期望表一致；默认 report-only；exploit/post workflow 必须实现 confirm 与 mode 门禁；不得存在自动修改目标状态的默认行为。
- **判定方法**：
  1. 按 design §4.3 期望表逐技能比对 `risk`/`requires`（缺失或不符 → fail）；
  2. `exploit.js`/`post.js` 必须含 `G-CFM-01`、`G-CFM-02`、`G-CFM-03`、`G-CFM-04` 字面量与 `confirm` 变量；其他 workflow 出现 `G-CFM` → warning（可能误加确认门禁）；
  3. 全文扫描自动变更模式：`autoRemediate\s*[:=]\s*true`、`autoExecute\s*[:=]\s*true`、`自动执行(修复|遏制|利用)`、`--force` 作为默认（同行无"禁止/需显式"否定）→ fail；
  4. 默认 report-only：每个 workflow 必须存在默认 true 的 dryRun 表达式（同 R4-DRYRUN-DEFAULT）。
- **可运行检查**：
  - `R12-RISK`（blocker）：`node dsh-redblue/tools/sanitize-lint.mjs --strict --check R12-RISK --json dsh-redblue/skills`
  - `R12-CONFIRM`（blocker）：`… --check R12-CONFIRM … dsh-redblue/workflow`
  - `R12-REPORT-ONLY`（blocker）：`… --check R12-REPORT-ONLY … dsh-redblue/skills dsh-redblue/references dsh-redblue/workflow`
- **例外白名单**：`test/fixtures/` 与 `docs/` 不扫描；散文里说明"禁止自动执行"（同行否定词）不算命中；`verify=False` 不在此规则内（见 R4）。
- **失败级别**：三项均 blocker；"其他 workflow 出现 G-CFM"为 warning。

## 7. 检查矩阵

| Check ID | 规则 | 级别 | 主要对象 |
|---|---|---|---|
| `R1-PROVENANCE` | R1 | blocker | skills, references, assets（带 provenance 头） |
| `R1-NOTICE` | R1 | blocker | NOTICE |
| `R1-LICENSE` | R1 | blocker | package.json, LICENSE |
| `R2-RESERVED` | R2 | blocker | skills, references, policy |
| `R2-AUTHORITY-LINK` | R2 | blocker | skills, references |
| `R2-PRIVATE` | R2 | blocker | skills, references |
| `R2-DENYLIST` | R2 | blocker | skills, references |
| `R2-EXAMPLE-TARGET` | R2 | blocker | skills, references |
| `R3-WEAPON` | R3 | blocker | skills, references |
| `R3-DESTRUCTIVE` | R3 | blocker | skills, references, workflow |
| `R3-AUTH-BANNER` | R3 | blocker | skills, references |
| `R4-VERIFY-DISABLED` | R4 | blocker | skills, references, workflow, lib |
| `R4-WILDCARD` | R4 | blocker | skills, references, policy |
| `R4-DRYRUN-DEFAULT` | R4 | blocker | workflow |
| `R4-SCOPE-GATE` | R4 | blocker | workflow |
| `R5-FAKE` | R5 | blocker | skills, references |
| `R5-METRIC` | R5 | blocker/warning | skills, references |
| `R5-CVE` | R5 | blocker/warning | skills, references |
| `R6-SKILL-SIZE` | R6 | blocker | skills |
| `R6-DESC` | R6 | blocker | skills |
| `R6-WHEN` | R6 | blocker | skills |
| `R6-REF-SIZE` | R6 | blocker (INDEX warning) | references |
| `R7-NAME` | R7 | blocker | skills, lib |
| `R7-JACCARD` | R7 | blocker | skills |
| `R7-NEGATIVE` | R7 | blocker | skills |
| `R8-SKILL` | R8 | blocker | skills |
| `R8-WORKFLOW` | R8 | blocker | workflow |
| `R9-LAST-VERIFIED` | R9 | blocker | skills, references |
| `R9-VERSION-FRESH` | R9 | warning/blocker | skills, references |
| `R10-SECRET` | R10 | blocker | skills, references, policy |
| `R10-PII` | R10 | blocker | skills, references |
| `R10-INTERNAL-HOST` | R10 | blocker | skills, references |
| `R11-TERMINOLOGY` | R11 | warning | skills, references, policy |
| `R12-RISK` | R12 | blocker | skills |
| `R12-CONFIRM` | R12 | blocker | workflow |
| `R12-REPORT-ONLY` | R12 | blocker | skills, references, workflow |

合计 36 条检查（R1 3 + R2 5 + R3 3 + R4 4 + R5 3 + R6 4 + R7 3 + R8 2 + R9 2 + R10 3 + R11 1 + R12 3）。

## 8. 例外与策略变更

- 白名单/正则/阈值不允许运行时逐条豁免；变更 = `POLICY` 版本升级（`v1 → v2`），必须同时更新：本文件、`policy/sanitization.md`、`tools/sanitize-lint.mjs` 常量、`test/sanitize.test.mjs`，并在 `docs/verification.md` 记录差异与理由。
- `--policy` 运行期覆盖是**测试专用**能力（`NODE_ENV=test` 或 `--allow-policy-override` 才放行）；发布门禁不得携带该参数，默认路径始终使用内嵌 POLICY（见 §3 R7 说明）。
- 人工评审（R11 与真实客户名）签字是发布前置条件；签字记录写入 `docs/verification.md`。
- 上游内容触碰 R2/R3/R5 时，处置顺序：**删除 > 改写 > 标注**；不得以"上游原文如此"为由豁免。

## 9. 复测与门禁记录（期望值）

| 项 | 命令 | 期望 |
|---|---|---|
| 技能/参考门禁 | `node tools/sanitize-lint.mjs --strict --json skills references` | 退出码 0，`blockers=0` |
| 发布门禁 | `node tools/sanitize-lint.mjs --strict --json skills references workflow lib policy schema package.json NOTICE` | 退出码 0，`blockers=0` |
| R7 复算 | `node tools/sanitize-lint.mjs --strict --check R7-JACCARD --json skills` | 最大同 lane Jaccard ≤0.35（设计期实测 0.130） |
| R6 体积 | `node tools/sanitize-lint.mjs --strict --check R6-SKILL-SIZE,R6-REF-SIZE --json skills references` | 全部 ≤300 行/≤24 KiB、≤48 KiB |
| 反例回归 | `node --test test/sanitize.test.mjs` | 每个检查 ID 的 fail fixture 命中、pass fixture 不命中 |

> 上述期望值是验收判据；实际执行结果由实现任务写入 `docs/verification.md`，本文件不复述未执行的输出。

## 10. 追踪矩阵

| 规则 | 需求（requirements） | 设计落点（design） | 实现落点 |
|---|---|---|---|
| R1 | SAN-1、§13 | §12 | `NOTICE`、frontmatter、references 头 |
| R2 | SAN-2 | §4.2/§9 | lint `R2-*`、`references/**` |
| R3 | SAN-3、LC-5 | §9/§12.1 | lint `R3-*`、技能示例块 |
| R4 | SAN-4、LC-1..LC-4 | §7、§10 | lint `R4-*`、`workflow/*.js` |
| R5 | SAN-5 | §8、§10 | lint `R5-*`、报告生成 |
| R6 | SAN-6、IR-9 | §3/§4 | lint `R6-*`、15 个 SKILL.md |
| R7 | SAN-7、BD-4 | §4.2/§4.4 | lint `R7-*`、frontmatter description |
| R8 | SAN-8 | §3.1、§13 | lint `R8-*`、`UNTRUSTED_CLAUSE` |
| R9 | SAN-9、SCN-B3 | §3/§8.7 | lint `R9-*`、baseline `lastVerified` |
| R10 | SAN-10、LC-8 | §13 | lint `R10-*`、证据脱敏 |
| R11 | SAN-11 | §4.2 | lint `R11-*`、人工评审 |
| R12 | SAN-12、LC-6 | §4.3、§7 | lint `R12-*`、workflow 门禁 |
