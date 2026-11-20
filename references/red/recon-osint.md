<!-- dsh-redblue:provenance
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: Skills/recon/offensive-osint/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 保留 OSINT 资产测绘步骤与置信度标注、证书/DNS/代码/云存储探针，删除扫描器攻击参数与真实目标，压缩为被动优先清单
-->

# 被动优先的信息收集（recon-osint）

> 定位：红队 lane 第 2 步。默认零目标侧发包；只有在 `activeScan=true` 且 `mode≥active`、`dryRun=false` 时才允许主动探测（G-MODE-03）。
> 主要上游：Claude-Red `recon/offensive-osint`、`recon/offensive-osint-methodology`；ACS `conducting-external-reconnaissance-with-osint`、`performing-osint-with-spiderfoot`（均已改写）。
> 消费者：`dsh-red-recon`、`dsh-red-surface`、`recon`/`assess` workflow 的 recon 阶段。
> 版本时效：工具参数与数据源以 2026-11-19 复核为准；工具大版本升级后重跑本文命令并更新证据字段。

## 1. 原则

1. **被动优先**：先只用公开数据与本地已有文件；主动扫描是「另一档能力」，不是默认动作。
2. **可溯源**：每个资产记录 `source`（哪个数据源/哪条命令）、`confidence`、`passive` 标记、`firstSeen`。
3. **可复算**：资产清单落盘为 `recon.json`，附命令摘要与输出哈希；禁止只给「我查到一堆子域」。
4. **不做归属推断**：没有证据（证书 SAN、DNS 委派、页面指纹）就不把资产标成「某组织所有」。
5. **不越界**：任何重定向、CNAME 指向、第三方 SaaS 托管都要按 scope 校验；命中排除项即丢弃并记录。

## 2. 资产分类（统一 taxonomy）

| kind | 示例值 | 判定依据 | 典型来源 |
|---|---|---|---|
| `domain` | `app.example.com` | DNS 存在或证书 SAN 出现 | 证书透明度、被动 DNS |
| `url` | `https://app.example.com/login` | 页面可访问且状态码稳定 | 爬取、历史 URL |
| `ip` | `192.0.2.10` | A/AAAA 解析结果 | DNS、证书 |
| `cidr` | `198.51.100.0/24` | ASN/托管段（需授权覆盖） | whois、云厂商段 |
| `repo` | `github.com/example-org/app` | 组织下公开仓库 | 代码托管搜索 |
| `bucket` | `example-assets` | 云存储桶名可列举 | 页面引用、JS 配置 |
| `mobile` | `com.example.app` | 应用商店包名/Bundle ID | 商店搜索 |
| `certificate` | `sha256:…` | 证书指纹 | CT 日志 |

归一化：域名小写去尾点；URL 去 fragment 与默认端口；IP 去前导零。同一资产多来源时合并为一条并累加 `sources[]`。

## 3. 被动情报（零发包到目标）

### 3.1 证书透明度（CT）

- 查 `crt.sh`（JSON 输出）拿历史证书与 SAN：适合发现遗留子域与已下线资产。
- 判定：SAN 里出现但当前不解析 → `confidence: possible`，标 `status: historical`，不得直接当攻击目标。
- 通配符证书（`*.example.com`）只说明根域覆盖范围，不等于子域存在。

### 3.2 被动 DNS 与解析

- 数据源：被动 DNS 服务、CT、公开解析记录、历史 URL 数据集。
- 记录：`A/AAAA/CNAME/MX/TXT/NS/SOA`；`TXT` 里的验证串、SPF include、DMARC 策略常暴露第三方托管。
- CNAME 指向第三方（SaaS/CDN）时，按 scope 判断是否属于授权资产；不属于则丢弃并写 `limitations`。

### 3.3 公开代码与配置

- 在代码托管平台按组织/域名/包名检索（只读 API，不做克隆后大规模扫描）。
- 关注：硬编码的 staging 域名、内部 API 路径、云存储桶名、移动端 Bundle ID、CI 配置里的环境名。
- 命中任何凭据形态（密钥、令牌）时**不落盘原文**：只记类型、长度、位置，并按 `mask-and-redact` 处理。

### 3.4 云存储与第三方暴露面

- 桶名/项目名可从页面静态资源、JS、移动端配置、错误页推断。
- 只做「是否存在 + 是否公开可读」的最小判定，不列举内容、不下载数据；命中即停并记录。

### 3.5 OSINT 辅助（对人/对组织）

- 只收集与本任务授权范围直接相关的信息（域名、技术栈、公开联系人角色）。
- 禁止：个人隐私挖掘、社交工程话术准备、绕过平台访问控制、购买泄露数据。
- 所有结论必须标注来源与获取时间；无来源的推断写 `confidence: unverified`。

## 4. 主动探测（需 `activeScan=true` + `mode≥active` + `dryRun=false`）

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 1) 被动子域枚举（不触达目标）
subfinder -d example.com -all -recursive -silent -o subs.txt
# 2) 解析存活（对 DNS，不碰目标 HTTP 服务）
dnsx -l subs.txt -a -resp -silent -o resolved.txt
# 3) HTTP 存活与指纹（这一步才会向目标发包，必须先通过 activeScan 门禁）
httpx -l resolved.txt -ports 80,443,8080 -status-code -title -tech-detect -json -o live.json
```

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# Web 指纹与服务器细节（限速、单目标、只读）
whatweb --no-errors -a 3 https://app.example.com
# 站点地图/robots 只取声明，不跟随外链
curl -sS --max-time 10 https://app.example.com/robots.txt
```

命令纪律（来自 Strix CLI 纪律的迁移）：

| 纪律 | 落地 |
|---|---|
| 无界面/非交互 | 所有工具加非交互参数（如 `-silent`、`--batch`），禁止进入 TUI |
| 预算硬上限 | 每类工具设 `-timeout`/`-rate-limit`/最大请求数；超预算即停 |
| 退出码语义 | `0` 成功、`1` 执行错误、`2` 有候选结论；`2` 不等于「确认漏洞」 |
| 幂等输出 | 输出到 `workDir/recon/` 固定文件名，重跑覆盖并保留旧哈希 |
| 只读 | 不写目标、不上传文件、不改配置、不触发写接口 |

## 5. 置信度模型（资产级）

| confidence | 判据 | 后续动作 |
|---|---|---|
| `confirmed` | 本次被动数据 + 本次主动探测都成立（解析 + 页面指纹一致） | 可进入 surface 建模 |
| `likely` | 两个独立被动源一致，未做主动验证 | 进入 surface，标注「未探活」 |
| `possible` | 单一被动源或历史数据 | 仅作线索，需补验证 |
| `unverified` | 无来源或来源不可复算 | 不得进入 `recon.json.assets` |

## 6. 输出（`recon.json`）

```json
{
  "schemaVersion": "dsh-redblue-recon/v1",
  "runId": "rb_20261119T055500Z_1a2b",
  "activeScan": false,
  "assets": [
    {
      "kind": "domain",
      "value": "app.example.com",
      "source": "ct:crt.sh",
      "sources": ["ct:crt.sh", "passive-dns"],
      "confidence": "likely",
      "passive": true,
      "firstSeen": "2026-10-02"
    }
  ],
  "counts": {"assets": 1, "byKind": {"domain": 1}},
  "limitations": ["未做主动探活（activeScan=false）"]
}
```

字段要求：`kind/value/source/confidence/passive` 必填；`firstSeen` 有历史源时填；`sources[]` 合并多来源。

## 7. 证据字段（recon 版）

| 字段 | 说明 |
|---|---|
| `commandSummary` | 参数模板 + 实际取值；凭据替换 `<REDACTED>` |
| `ts` | UTC 采集时刻 |
| `outputPath` | `recon/<tool>-<target>.txt` 或 `.json` |
| `sha256` / `bytes` | 输出文件哈希与字节数 |
| `excerpt` | 命中行（≤2 KiB），保留工具原始行格式 |
| `source` | 数据源标识（`ct:crt.sh`、`dns:<resolver>`、`code:<platform>`） |

## 8. 禁止事项与反模式

- 禁止把「子域存在」当「漏洞」；recon 只产出资产，不下结论。
- 禁止对未在 `targets[]` 的资产发包（含 CNAME 指向的第三方）。
- 禁止用搜索引擎缓存/第三方存档冒充本次证据（无 `dataSources` 引用即降级）。
- 禁止大规模目录爆破式「顺便扫一下」；主动扫描必须单独走 active 档并计入预算。
- 反模式：只交截图；只交一行域名列表无来源；把 wildcard DNS 解析结果全当好资产；把 CDN 边缘 IP 当目标主机。