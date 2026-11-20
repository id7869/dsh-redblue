# dsh-redblue 工具运行时（tool-runtime）

- 版本：`tool-runtime/v1`（2026-11-19）
- 入口：`node tools/sec.mjs`
- 依赖：**零第三方依赖**（只使用 Node ≥20 内建模块）；Windows/MSYS 可用
- 定位：把红/蓝队方法论中的**命令能力**做成插件自带的离线分析工具 + 白名单化、授权门禁化、默认 dry-run 的受控执行封装；不打包、不复制上游 Python 脚本，也不提供自由命令行入口

## 1. 快速开始

```bash
node tools/sec.mjs --help
node tools/sec.mjs recipes list
node tools/sec.mjs scope check --scope C:/work/scope.json
```

退出码：`0` 成功；对 `guard` 而言，dry-run 下 scope 文件不可读时无法生成计划，命令自身返回 `0` 并输出 `ok:false`（不 spawn）；`1` 其他门禁拒绝或执行/校验失败；`2` 用法错误。所有命令向 stdout 输出单个 JSON 对象（`--help` 为文本）。

## 2. 子命令

### 2.1 `scope check`

```bash
node tools/sec.mjs scope check --scope C:/work/scope.json [--now 2026-11-19T08:00:00Z]
```

按 `policy/authorization.md` 校验 scope（与 workflow 的 preflight 同源）：

- `G-AUTH-01..07`：authorization 对象、reference、type、grantedBy、validFrom/validTo、生效/过期；
- `G-TGT-01..04`：targets 非空、通配/全网拒绝、kind/value 合法、exclusions 命中拒绝；
- `G-PATH-03`：`source` target 与 dataSources 必须是 Windows 绝对路径且不含 `..`；
- `G-MODE-01`：mode 枚举；
- `G-WIN-01..03`：RFC 3339、`end > start`、当前时刻在窗口内；
- `G-BUD-01`：预算范围；
- `G-DH-01..03`：retain/secrets/destruction；
- `G-CONF-01`：未知字段（含嵌套字段）。

输出：

```json
{
  "ok": true,
  "rejectedBy": [],
  "errors": [],
  "warnings": [],
  "mode": "passive",
  "normalized": { "authorization": {}, "targets": [], "mode": "passive", "window": {}, "budget": {}, "dataHandling": {}, "dataSources": [] }
}
```

`--now` 仅用于确定性测试/回放；默认使用当前时间。`scope check` 本身不访问网络。

### 2.2 `evidence hash` / `evidence verify`

```bash
node tools/sec.mjs evidence hash --dir C:/work/rb-run-001 --out C:/work/manifest.json
node tools/sec.mjs evidence verify --manifest C:/work/manifest.json --dir C:/work/rb-run-001
```

- `hash` 递归登记目录内**普通文件**（跳过符号链接），按 POSIX 相对路径排序，输出 `schemaVersion: dsh-redblue-evidence/v1` 与 `files[]`（`path/bytes/sha256`）。
- `verify` 按清单复算：`missing`、`mismatched` 任一即 `ok=false`、退出码 1；`extra` 仅提示（清单文件自身不计入 extra）。
- 所有哈希为小写 SHA256；文件内容不写入清单。

### 2.3 `sarif convert`

```bash
node tools/sec.mjs sarif convert --findings C:/work/findings.json --out C:/work/results.sarif
```

- 输出 SARIF 2.1.0（`version`、`$schema`、`runs[0].tool.driver{name,version,informationUri,rules}`）。
- 仅 `disposition=reportable`（或未写 disposition）的 finding 进入 `results[]`；`ruleId` 为 `category` slug；`level`：critical/high→error、medium→warning、low→note。
- `locations`：url→`physicalLocation.artifactLocation.uri`；source→路径 + `startLine`；domain/ip/host/cidr→`logicalLocations`。
- `partialFingerprints.dshRedblueFingerprint` 保留 finding 指纹。

### 2.4 `ioc extract`

```bash
node tools/sec.mjs ioc extract --input C:/work/export.txt            # 默认 defang
node tools/sec.mjs ioc extract --input C:/work/export.txt --no-defang
```

提取 URL、域名、IPv4/IPv6、MD5/SHA1/SHA256（32/40/64 位 hex）。默认 defang：

- URL：`https://` → `hxxps://`，域名点号 → `[.]`；
- 域名 / IPv4 / IPv6：点号（IPv6 冒号）→ `[.]` / `[:]`；
- 哈希保持不变（哈希本身不是可点击目标）。

输出 `{ok,defanged,counts,urls,domains,ips,hashes}`。仅做本地文本分析，不查询任何外部情报源。

### 2.5 `log normalize`

```bash
node tools/sec.mjs log normalize --input C:/work/logs.jsonl --format jsonl --out C:/work/normalized.jsonl
node tools/sec.mjs log normalize --input C:/work/logs.csv   --format csv   --out C:/work/normalized.jsonl
node tools/sec.mjs log normalize --input C:/work/syslog.txt --format syslog --out C:/work/normalized.jsonl
```

- 支持 JSONL、CSV（带表头、基础引号转义）、syslog（RFC 5424 与 RFC 3164）。
- 时间戳归一为 UTC ISO-8601：支持 `ts/timestamp/time/@timestamp/datetime/date/_time`、epoch 秒/毫秒、RFC 3164 `Nov 19 07:00:00`（无年份按最近一次出现推断）。
- 字段映射：`host/hostname/computer`、`user/actor/principal`、`action/event/operation`、`object/target/resource`、`message/msg/description`；其余标量放入 `fields`。
- 输出每行 `{ts, source, line, host?, actor?, action?, object?, message?, fields?}`；命令摘要含 `total/normalized/badLines`。坏行只计数，不中断。

### 2.6 `rule lint`

```bash
node tools/sec.mjs rule lint --file C:/work/rules/example.yml
```

不依赖 YAML 库的结构检查：`title`、`id`、`status`（stable/test/experimental/deprecated/unsupported）、`detection`（必须有 `condition` 与至少一个 selection/filter 子键）、`logsource`（product/category/service 至少一个）、`level`（informational/low/medium/high/critical）。缺键或非法值 → `ok=false`、退出码 1；UUID 形式、YAML 锚点等只给 warning。

### 2.7 `recipes list|show`

```bash
node tools/sec.mjs recipes list
node tools/sec.mjs recipes show dns_lookup
```

`recipes.json` 是 guard 的**唯一**可执行白名单；加载时校验：至少 8 条、id 唯一、binary 非 shell、argv 为数组且不含 shell 元字符、只允许 `{target}` 占位符、`targetKind`/`requiredMode` 合法、timeout/outputLimit 有界、解释器（node/python 等）只允许固定安全 argv。

## 3. 配方清单

| id | lane | binary | targetKind | 最低 mode | timeout | 用途 |
|---|---|---|---|---|---|---|
| `dns_lookup` | recon | `nslookup` | domain | passive | 30s | 被动 DNS 查询（示例 `example.com`） |
| `http_headers` | recon | `curl` | url | active | 30s | 读取响应头（示例 `https://app.example.com/`） |
| `tls_certificate` | recon | `openssl` | domain | active | 30s | TLS 证书/握手信息 |
| `port_scan` | recon | `nmap` | host | active | 120s | TCP connect 前 100 端口、限速 50 |
| `vuln_scan` | discover | `nuclei` | url | active | 120s | 模板漏洞扫描、限速 20 |
| `web_fuzz` | discover | `ffuf` | url | active | 120s | 路径模糊（需本机 wordlist） |
| `pcap_read` | blue | `tshark` | source | passive | 60s | 读取本地 PCAP 前 200 包 |
| `file_hash` | blue | `certutil` | source | passive | 60s | SHA256 文件哈希 |
| `certificate_query` | blue | `openssl` | source | passive | 30s | 本地证书主题/签发者/有效期 |
| `runtime_probe` | blue | `node` | host | passive | 15s | 固定 `node --version` 自检，不接触目标 |

配方中的示例目标只使用保留域（`example.com`、`*.example.com`）与文档网段（`192.0.2.0/24`）；新增/修改配方必须走策略评审，禁止加入真实客户目标、凭据或真实 IOC。

## 4. `guard`：受控执行

```bash
# 默认 dry-run：只打印计划，不启动进程、不写 evidence
node tools/sec.mjs guard --recipe dns_lookup --target example.com --scope C:/work/scope.json

# 显式执行：必须提供与 target 完全相等的 confirm
node tools/sec.mjs guard --recipe runtime_probe --target app.example.com --scope C:/work/scope.json \
  --execute --confirm app.example.com --workdir C:/work/rb-tool
```

### 4.1 执行前置（`--execute` 时任一不满足：退出码 1、不 spawn、不写 evidence）

dry-run 下同样会做这些检查且绝不 spawn；除“scope 文件不可读”（无法生成计划，命令返回 0 并输出 `ok:false`）外，门禁拒绝退出码 1；`--execute` 下所有拒绝退出码 1。

1. **scope 可读且通过 `scope check`**；
2. `authorization.type="written"`（`internal-mandate` 不能执行命令）；
3. `scope.mode` 的等级 ≥ recipe.requiredMode（`passive < active < exploit < post`）；
4. `--target` 命中 `scope.targets` allowlist（归一化后精确匹配），且通过配方 `targetKind` 格式校验；含 shell 元字符、控制字符、`..` 或 `-` 前缀的 target 一律拒绝。guard 的 target 校验比 `scope check` 更严格：即使 URL 查询串中的 `&` 也会被拒绝，以免任何拼接歧义。
5. `--execute` 时必须 `--confirm === --target`（逐字符相等）；
6. 目标二进制存在（PATH 或绝对路径；`node` 解析为当前运行时）。

### 4.2 argv 与 shell

- recipe 的 `argv` 是字符串数组，只有 `{target}` 占位符；guard 逐元素替换后直接 `spawn(binary, argv, {shell:false})`，**绝不经 shell 拼接**。
- 不提供 `--command`、`--args` 或任何自由命令参数；不能执行白名单外的二进制。
- 拒绝 shell 二进制（sh/bash/cmd/powershell/pwsh 等）；解释器配额受限（如 `node` 仅固定 `--version`）。

### 4.3 超时与输出上限

- timeout 取 recipe.timeoutMs（默认 120s）；超时标记 `timedOut=true` 并终止子进程。
- stdout+stderr 合并计入 recipe.outputLimitBytes（默认 1MiB）；超限标记 `truncated=true` 并终止。
- 只保存输出**哈希/字节数**，不落 stdout/stderr 原文；`stdoutSha256`/`stderrSha256` 针对已捕获（可能已截断）的输出计算。

### 4.4 evidence JSONL

执行时追加到 `<workdir>/guard-evidence.jsonl`（`workdir` 默认当前目录，自动创建）：

```json
{
  "schemaVersion": "dsh-redblue-guard/v1",
  "ts": "2026-11-19T08:00:00.000Z",
  "recipe": "runtime_probe",
  "lane": "blue",
  "target": "app.example.com",
  "argv": ["--version"],
  "binary": "node",
  "binaryPath": "C:/Program Files/nodejs/node.exe",
  "mode": "passive",
  "requiredMode": "passive",
  "authorizationReference": "ROE-TEST-001",
  "exitCode": 0,
  "signal": null,
  "timedOut": false,
  "truncated": false,
  "durationMs": 39,
  "stdoutBytes": 10,
  "stderrBytes": 0,
  "stdoutSha256": "<64 hex>",
  "stderrSha256": "<64 hex>",
  "spawnError": null
}
```

- 不写目标响应原文、凭据或 PII；需要时由操作者按 `evidence hash` 对 workDir 产物做整目录封存。
- `--execute` 被拒绝时**不写** evidence；dry-run 也不写。

## 5. 可选二进制依赖

离线子命令（scope/evidence/sarif/ioc/log/rule/recipes）不依赖任何外部二进制。`guard` 执行按配方需要可选安装：

| 配方 | 可选二进制 | 缺失行为 |
|---|---|---|
| dns_lookup | `nslookup` | `--execute` 拒绝（G-EXEC-01），dry-run 仅提示 `binaryAvailable=false` |
| http_headers / tls_certificate | `curl` / `openssl` | 同上 |
| port_scan | `nmap` | 同上 |
| vuln_scan | `nuclei` | 同上 |
| web_fuzz | `ffuf` + 本机 wordlist | 同上 |
| pcap_read | `tshark` | 同上 |
| file_hash | `certutil`（Windows） | 同上 |
| certificate_query | `openssl` | 同上 |
| runtime_probe | `node`（当前运行时） | 始终可用 |

不安装亦可完成全部离线分析与门禁校验；guard 默认 dry-run 不会因为缺少二进制而启动任何进程。

## 6. 与 workflow 的关系

- workflow 阶段只产出**命令建议**（`commandSummary`、参数化模板、证据字段），不直接调用 guard，也不联网；保持 report-only。
- 操作者在获得书面授权后，从 workflow 产物中取出建议，映射到 `recipes.json` 的配方 id，再用 `guard` 执行；执行结果只能作为**新证据**回填（哈希/字节数/退出码），不得改写 workflow 已封存的产物。
- 执行前置与 workflow 的 scope/mode/confirm 门禁同源（`policy/authorization.md`），guard 是“人审后执行”的最后一公里，不是自动攻击入口。

## 7. 安全边界与限制

- 离线命令不联网；`guard --execute` 是否联网取决于配方二进制（例如 DNS/HTTP/扫描工具），因此必须通过书面授权 + mode + allowlist + confirm 门禁。
- 不提供自由命令行、`--command`、shell 字符串或 `eval`；配方是静态审查过的 argv 模板。
- 证据仅记录哈希/字节数/退出码/argv；目标输出原文不落盘。
- 示例只用保留域/文档网段；本文件与 `recipes.json` 不含真实目标、凭据或真实 IOC。
- 已知限制：`guard` 的超时/输出限制只作用于直接子进程；配方二进制若自行派生后台进程，需要由操作者在授权环境中清理。
