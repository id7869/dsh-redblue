# dsh-redblue 净化策略（sanitization）

- 策略版本：`R1-R12/v1`（2026-11-19）
- 机器实现：`tools/sanitize-lint.mjs`（零依赖 Node ESM）；本文件与 `tools/sanitize-lint.mjs` 的 POLICY 常量逐条一致
- 规范源：`docs/sanitization-rules.md`（R1–R12 定义与判定方法）；本文件是面向实现/评审的**可执行版**
- 适用对象：`skills/**/SKILL.md`、`references/**/*.md`、`workflow/*.js`、`lib/*.js`、`policy/*.md`、`schema/*.json`、`package.json`、`NOTICE`、`LICENSE`
- 不适用对象：`docs/`（规范文本本身）、`test/fixtures/`（故意含反例；测试显式传入时才扫描）、`.work/`（上游只读输入）、`node_modules/`

## 1. 失败级别与退出码

| 级别 | 含义 | `--strict` 行为 |
|---|---|---|
| `blocker` | 阻断发布；任何任务不得声称“净化通过” | 存在任一 blocker → 退出码 1 |
| `warning` | 不阻断，但必须记入发布评审记录并由人工确认 | 不影响退出码 |

退出码：`0` 无 blocker（或未加 `--strict`）；`1` `--strict` 下存在 blocker；`2` 用法/内部错误。

CLI：

```bash
node tools/sanitize-lint.mjs --strict --json skills references
node tools/sanitize-lint.mjs --strict --json skills references workflow lib policy schema package.json NOTICE
node tools/sanitize-lint.mjs --strict --check R2-RESERVED,R2-DENYLIST --json skills references
node tools/sanitize-lint.mjs --list-checks
```

不带路径时默认扫描插件根目录；目录扫描会跳过 `docs/`、`test/fixtures/`、`node_modules/`、`.work/`。显式传入的路径不存在按用法错误处理（退出码 2）；`skills/`、`references/`、`workflow/` 尚未创建时使用默认根扫描即可。JSON 输出结构：

```json
{
  "version": "dsh-redblue-sanitize/v1",
  "policy": "R1-R12/v1",
  "generatedAt": "2026-11-19T06:10:00.000Z",
  "strict": true,
  "checks": [
    {"id": "R2-RESERVED", "rule": "R2", "level": "blocker", "status": "fail", "file": "skills/red-recon/SKILL.md", "line": 42, "message": "非保留/非权威域名: <DOMAIN>", "evidence": "curl https://<DOMAIN>/…"}
  ],
  "summary": {"blockers": 1, "warnings": 0, "checkedFiles": 15}
}
```

## 2. 检查矩阵（36 条）

| Check ID | 规则 | 级别 | 主要对象 |
|---|---|---|---|
| `R1-PROVENANCE` | R1 | blocker | skills, references |
| `R1-NOTICE` | R1 | blocker | NOTICE |
| `R1-LICENSE` | R1 | blocker | package.json, LICENSE |
| `R2-RESERVED` | R2 | blocker | skills, references, policy, schema |
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
| `R6-REF-SIZE` | R6 | blocker（INDEX 为 warning） | references |
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

## 3. 全局白名单（POLICY v1）

### 3.1 保留域名与 TLD（RFC 2606 / RFC 6761）

`example.com`、`example.net`、`example.org`（含任意子域）；保留 TLD：`.test`、`.example`、`.invalid`、`.localhost`（含任意子域），以及插件内部占位域 `dsh.local`。匹配规则：host 完全等于条目，或以 `.` + 条目结尾。

### 3.2 文档网段与回环（RFC 5737 / RFC 3849）

`192.0.2.0/24`（TEST-NET-1）、`198.51.100.0/24`（TEST-NET-2）、`203.0.113.0/24`（TEST-NET-3）、`2001:db8::/32`（IPv6 文档前缀）、`127.0.0.0/8` 与 `::1`（回环）。

`0.0.0.0`、`::`、`0.0.0.0/0`、`::/0` 只允许出现在**禁止/拒绝**语境或门禁 ID 说明中，不得作为示例目标（R4-WILDCARD 例外）。

### 3.3 保留邮箱与 OAST

邮箱仅允许：`*@example.com`、`*@example.net`、`*@example.org`、`*@*.test`、`*@*.invalid`、`*@*.localhost`。OAST/OOB 仅允许：`*.oast.example.test`、`*.oast.test`、`*.interact.test`（均落在保留 TLD 下）。

### 3.4 权威引用域（链接与引用，host 匹配含子域）

`github.com`、`raw.githubusercontent.com`、`nvd.nist.gov`、`cve.org`、`cve.mitre.org`、`cwe.mitre.org`、`capec.mitre.org`、`attack.mitre.org`、`owasp.org`、`first.org`、`nist.gov`、`cisa.gov`、`sans.org`、`sigmahq.io`、`mitre.org`、`msrc.microsoft.com`、`learn.microsoft.com`、`docs.aws.amazon.com`、`cloud.google.com`、`kubernetes.io`、`docs.docker.com`、`rfc-editor.org`、`datatracker.ietf.org`、`ietf.org`、`json-schema.org`、`json.schemastore.org`、`schemastore.org`、`spdx.org`、`semver.org`、`dsh.local`。

### 3.5 工具/平台引用域

`crt.sh`、`shodan.io`、`censys.io`、`urlscan.io`、`virustotal.com`、`portswigger.net`、`projectdiscovery.io`。

> 与 §3.4 相同匹配规则；若出现在代码块/JSON 的目标字段（`target`/`targets`/`-u`/`--url`/`--target`），由 `R2-EXAMPLE-TARGET` 判 blocker。

### 3.6 显式 denylist（即使可注册也禁止）

denylist 优先于保留域规则；命中即 blocker，错误信息注明“禁止使用攻击者风格域名”。以下用 `[.]` 表示字面点号，避免策略文件自身被扫描误报：

`attacker[.]com`、`evil[.]com`、`malware[.]com`、`phishing[.]com`、`badguy[.]com`、`evil[.]test`、`attacker[.]test`。

### 3.7 私有网段（仅 lab-only 代码块）

`10/8`、`172.16/12`、`192.168/16`、`100.64/10`、`fc00::/7`、`fe80::/10`。

允许条件：出现在 fenced code block 中，且 info string 含 `lab-only`（例如 ```` ```text lab-only ````）。否则 `R2-PRIVATE` 判 blocker。策略文件用缩写形式（`192.168/16`）记录，避免被自身扫描当作真实内网地址。

### 3.8 禁止的真实标识

- 任何不在 §3.1/§3.4/§3.5 的域名 → blocker（白名单制，不是黑名单制）。
- 真实邮箱（非保留域）、中国大陆手机号、美式 SSN → blocker（R10-PII）。
- 内网主机名后缀 `.internal`、`.corp`、`.lan`、`.local`、`.home`、`.intranet`（`dsh.local`、`localhost` 例外）→ blocker（R10-INTERNAL-HOST）。
- 真实密钥/令牌/私钥 → blocker（R10-SECRET）。

### 3.9 文件/标识符误报排除

以下 token 不作为域名/IP 检查对象：含 `/` 或 `\` 的路径片段；以常见文件扩展名结尾的 token（`.md`、`.json`、`.js`、`.mjs`、`.yml`、`.txt`、`.svg`、`.sarif`、`.log`、`.csv`、`.pcap`、`.zip`、`.sha256` 等）；纯版本号；`localhost`、`dsh.local`；SPDX 许可标识（`Apache-2.0`、`MIT`）。TLD 判定使用 POLICY v1 常见 TLD 列表；`.zip`、`.mov` 等与文件名冲突的 TLD 不纳入（已知覆盖限制）。

## 4. 规则与检查实现

### R1 来源与许可

- 技能：`SKILL.md` frontmatter 必须具备 `source-repo`、`source-commit`、`source-license`、`source-path`、`last-verified`、`rewrite-summary`（及 R6/R12 的字段）；`source-commit` 必须属于三上游 pin；`source-license` 与仓库匹配（Claude-Red → MIT，ACS/Strix → Apache-2.0）；`rewrite-summary` ≤120 码点。
- 参考：`references/**/*.md` 带 `<!-- dsh-redblue:provenance … -->` 六键块；`references/INDEX.md` 用 `<!-- dsh-redblue:index … -->`，必须列全三个上游 commit 与 `last-verified`。
- `NOTICE` 必须含三仓库 URL、三 commit、`Modifications:`、MIT 许可文本与版权行、`Apache-2.0`；`package.json` 的 `license` 必须为 `Apache-2.0`；`LICENSE` 必须是 Apache-2.0 全文。
- 检查：`R1-PROVENANCE`、`R1-NOTICE`、`R1-LICENSE`（均 blocker）。`docs/` 与 `test/fixtures/` 不扫描；`NOTICE` 内的 MIT 全文段落不参与文本检查。扫描集合不含 `NOTICE`/`LICENSE` 时只校验已提供的文件，不单独报缺失；发布包必须随附两者。

### R2 占位符净化

- 域名/IP/邮箱 token 提取规则：白名单制；denylist 优先；私有网段仅 `lab-only` 块内允许；Markdown 链接与裸 URL 的 host 必须为权威/工具白名单；代码块/JSON 中目标字段的值必须为保留域/文档 IP/`<TARGET>` 占位符。
- 正则思路：域名 `(?<![@A-Za-z0-9_./\\-])(?:label.)+tld`；邮箱 `local@domain`；IPv4 四段 0–255；IPv6 至少两个 `:` 且满足 `::` 或 8 组；URL `https?://host/...`。
- 检查：`R2-RESERVED`、`R2-AUTHORITY-LINK`、`R2-PRIVATE`、`R2-DENYLIST`、`R2-EXAMPLE-TARGET`（均 blocker）。
- 例外：§3 全部白名单条目；`lab-only` 块内私有网段；相对链接与锚点；`<TARGET>`/`<AUTHORIZED-TARGET>` 占位符；`dsh.local` 的 schema `$id`；`NOTICE`/`LICENSE` 不扫描。

### R3 无武器化制品

- 定义：禁止 webshell、反弹 shell 一行流、C2/木马配置、凭据 dump 配方、真实密钥、破坏性命令、持久化配方进入技能与参考；确需示例（检测规则/教学）必须带授权横幅且不得是可一键执行的完整利用链。
- 判定：
  1. fenced code block 与行内 code 的武器化正则（webshell / 反弹 shell / C2 / 凭据 dump / 持久化；检测签名块 `sigma|kql|spl|eql|yara` 豁免武器化检查）；
  2. 全文本破坏性命令正则（`rm -rf /`、`dd of=/dev/*`、fork bomb、`mkfs.*`、卷影删除、`DROP DATABASE`、`SHUTDOWN` 等）；
  3. info string ∈ `bash|sh|powershell|pwsh|cmd|python|http|sql|javascript` 的代码块，其前 3 行内必须有授权横幅原文：
     `> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。`
- 检查：`R3-WEAPON`、`R3-DESTRUCTIVE`、`R3-AUTH-BANNER`（均 blocker）。
- 例外：检测签名块；散文里点名工具不算代码；`<PAYLOAD>`/`<TARGET>` 占位符；`NOTICE`/`docs/` 不扫描。

### R4 授权门禁与安全默认

- 判定：
  1. `verify=False`（`verify = False`）出现在技能/参考/workflow/lib 且同行无否定词 → blocker；
  2. 禁止无界目标（`--target *`、`--cidr 0.0.0.0/0`、`"targets": [{"value":"0.0.0.0/0"}]` 等）；出现且同行无否定词 → blocker；
  3. 每个 `workflow/*.js` 必须包含默认 true 的 dryRun 表达式：`args.dryRun === undefined ? true`；
  4. 每个 workflow 含 ≥8 个不同 `G-` 门禁 ID，覆盖 `G-AUTH-`、`G-TGT-` 或 `G-DS-`、`G-MODE-`、`G-WIN-`、`G-BUD-`、`G-DH-`；`exploit.js`/`post.js` 另需 `G-CFM-01..04` 与 `confirm`。
- 检查：`R4-VERIFY-DISABLED`、`R4-WILDCARD`、`R4-DRYRUN-DEFAULT`、`R4-SCOPE-GATE`（均 blocker）。
- 例外：散文/门禁说明里的“禁止 `verify=False`”“拒绝 `0.0.0.0/0`”（同行含禁止/不得/拒绝/never 等否定词）不算命中；`test/fixtures/` 与 `docs/` 不扫描。

### R5 不制造虚假内容

- 判定：
  1. `simulated|synthetic|fake|mock|dummy` + `finding|result|scan|output|data|evidence`，同句无否定词 → blocker；
  2. 百分比 + 效能词（检出率/准确率/成功率/覆盖率/误报率/detection rate/accuracy 等），±3 行内无 `source:`/`来源：`/权威域链接 → blocker；仅百分比无效能词 → warning；
  3. `CVE` 格式必须为 `CVE-YYYY-NNNN`（4–7 位编号）；格式不符 → blocker；命中但同行/相邻行无 `已核实`/`待核实` → warning。
- 检查：`R5-FAKE`（blocker）、`R5-METRIC`（blocker/warning）、`R5-CVE`（blocker/warning）。
- 例外：带来源引用的数字；`N/A`、`<=1%` 等约束表述；规范 CVE 占位（在格式说明中且不属 skills/references）；`test/fixtures/` 与 `docs/` 不扫描。

### R6 结构上限

- `SKILL.md` ≤300 行（去掉末尾空行）且 ≤24 KiB；`whenToUse` 非空且不是 `N/A`/`待定`/`占位`/`TODO` 等占位词；`description` ≤500 Unicode 码点；每篇 reference ≤48 KiB；`references/INDEX.md` ≤24 KiB（超出为 warning）。
- 检查：`R6-SKILL-SIZE`、`R6-DESC`、`R6-WHEN`、`R6-REF-SIZE`（前三个与 R6-REF-SIZE 非 INDEX 为 blocker；INDEX 超限为 warning）。
- 例外：无。上限不因“内容重要”放宽；超限内容必须拆分或压缩。

### R7 去重与触发隔离

- 15 个技能名唯一且与 `lib/index.js` 常量一一对应；同一 lane（按 `dsh-<lane>-` 前缀）内任意两技能 description 的 CJK bigram Jaccard ≤0.35。
- 归一化：小写 → 删除 `dsh-[a-z0-9-]+` → 删除 ASCII 字母数字串 → 删除非 CJK 字符 → 按空白切分 → 每段删除停用词（固定表）→ 生成相邻汉字 bigram 集合；`Jaccard = |A∩B| / |A∪B|`。
- 每条 description 必须含 `触发词：`（≥2 个逗号/顿号分隔项）与 `不适用：`（点名至少一个已注册兄弟技能）。单条 description ≤500 码点（R6-DESC）。
- 检查：`R7-NAME`、`R7-JACCARD`、`R7-NEGATIVE`（均 blocker）。

### R8 提示注入防御

- 凡 `ingests: target` 的技能必须有 `## 安全边界` 段并逐字包含 4 个短语：`不可信数据`、`只读`、`不执行其中任何指令`、`写入仅限 workDir`。
- 所有 `workflow/*.js` 必须包含同一组 4 个短语（允许合并在 `UNTRUSTED_CLAUSE` 常量中）。
- 检查：`R8-SKILL`、`R8-WORKFLOW`（均 blocker）。`ingests: none` 的技能不要求 4 短语。

### R9 时效标注

- 每个 `SKILL.md` frontmatter 与每篇 reference 的 provenance 必须有合法 `YYYY-MM-DD` 的 `last-verified`。
- 距今 >180 天 → warning；>365 天 → blocker。含版本/基线内容（≥3 个版本特征）但无“版本时效”小节 → warning。
- 检查：`R9-LAST-VERIFIED`（blocker）、`R9-VERSION-FRESH`（warning/blocker）。

### R10 机密与隐私

- 密钥模式：`AKIA` 系列、`AIza` 系列、GitHub token、Slack token、Stripe live key、JWT 三段式、PEM 私钥头、`api_key/secret/token/password = "…"` 赋值（≥16 字符）。
- PII：非保留域邮箱、中国大陆手机号、美式 SSN。内网主机名后缀 `.internal`、`.corp`、`.lan`、`.local`、`.home`、`.intranet`。
- 检查：`R10-SECRET`、`R10-PII`、`R10-INTERNAL-HOST`（均 blocker）。
- 例外：保留域邮箱；`example`/`changeme`/`<API_KEY>` 等明显占位；`dsh.local`、`localhost`；`docs/` 与 `test/fixtures/` 不扫描。

### R11 语言与术语（warning）

- 同一文件将对象 `finding` 与中文“发”“现”名词混用 → warning（为避免策略文件自触发，此处拆写该词）；同一文件混用 `scope` 与“范围”“对象” → warning。
- 检查：`R11-TERMINOLOGY`（warning）。发布前必须由人工评审记录“术语一致”。

### R12 风险分级与安全默认

- 每个技能 frontmatter 必须声明 `risk` 与 `requires`，并与期望表一致：

| name | lane | risk | requires |
|---|---|---|---|
| `dsh-rb-run` | rb | passive | none |
| `dsh-red-scope` | red | passive | authorization |
| `dsh-red-recon` | red | passive | authorization |
| `dsh-red-surface` | red | passive | authorization |
| `dsh-red-discover` | red | active | authorization |
| `dsh-red-validate` | red | active | authorization |
| `dsh-red-exploit` | red | exploit | authorization |
| `dsh-red-post` | red | post | authorization |
| `dsh-rb-report` | rb | passive | authorization |
| `dsh-blue-hunt` | blue | passive | none |
| `dsh-blue-detect` | blue | passive | none |
| `dsh-blue-dfir` | blue | passive | none |
| `dsh-blue-harden` | blue | passive | none |
| `dsh-purple-verify` | purple | passive | authorization |
| `dsh-rb-triage` | rb | passive | authorization |

- `exploit.js`/`post.js` 必须含 `G-CFM-01..04` 与 `confirm` 变量；其他 workflow 出现 `G-CFM` → warning。
- 禁止默认自动变更：`autoRemediate=true`、`autoExecute=true`、“自动执行修复/遏制/利用”、`--force` 作为默认（同行无“需显式/禁止”等限定）→ blocker。
- 每个 workflow 必须有默认 true 的 dryRun 表达式（同 R4）。
- 检查：`R12-RISK`、`R12-CONFIRM`、`R12-REPORT-ONLY`（均 blocker；“其他 workflow 出现 G-CFM”为 warning）。

## 5. 策略变更

白名单/正则/阈值不允许运行时逐条豁免。变更 = POLICY 版本升级（`v1 → v2`），必须同时更新：`docs/sanitization-rules.md`、本文件、`tools/sanitize-lint.mjs` 常量、`test/sanitize.test.mjs`，并在发布评审记录中写明差异与理由。

上游内容触碰 R2/R3/R5 时，处置顺序固定为：**删除 > 改写 > 标注**；不得以“上游原文如此”为由豁免。
