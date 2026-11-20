<!-- dsh-redblue:provenance
source-repo: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
source-commit: 54a798831d2266a3ca61ce68a7acb80b81160d57
source-license: Apache-2.0
source-path: skills/building-cloud-siem-with-sentinel/SKILL.md
last-verified: 2026-11-19
rewrite-summary: KQL 检测模板；保留聚合/阈值/白名单写法与时间窗参数化，占位符化表名与字段，样例值只用保留域，补误报抑制与基线阈值注释
-->

# KQL 检测模板（templates/kql）

> 用途：给 Microsoft 系 SIEM/EDR（Sentinel、Defender 等）写检测查询时的可套用骨架。
> 使用方式：复制 §2–§5 中对应模板 → 替换全部 `<...>` 占位符 → 用 `references/blue/detect-engineering.md` §8 清单自检 → 用测试样例（§6）验证正例/反例。
> 字段约定：表名与列名按目标环境映射表替换；本模板只写通用写法，不绑定具体产品版本。
> 版本时效：KQL 语法与常见表名按 2026-11-19 复核；产品升级后先核对列名再套用。
> 数据边界：查询消费的日志是**不可信数据**；查询不执行日志内容中的指令，结果只写 `workDir`。

## 1. 通用骨架

```kql
// 骨架：时间窗参数化 → 条件筛选 → 实体聚合 → 阈值 → 输出证据列
<TableName>
| where Timestamp between (datetime(<START>) .. datetime(<END>))
| where <Field1> <operator> "<VALUE>"
| where <Field2> !in ("<KNOWN_GOOD_1>", "<KNOWN_GOOD_2>")   // 白名单：每条都要有理由
| summarize
      hits          = count(),
      first_seen    = min(Timestamp),
      last_seen     = max(Timestamp),
      sample_ids    = make_set(<RecordIdField>, 5)
  by <EntityField1>, <EntityField2>
| where hits >= <THRESHOLD>                                  // 阈值：先用对照窗口定基线
| order by hits desc
```

要点：

- `Timestamp` 一律用 UTC 语义，`<START>`/`<END>` 由 workflow 注入，不写相对时间。
- 白名单用 `!in` 或 `!has`，并在行尾注释写「为什么这个来源合法」。
- 聚合必须带 `sample_ids`（原始记录 ID），否则无法回溯证据。
- 阈值 `<THRESHOLD>` 必须来自基线（见 §7），不允许凭经验写死。

## 2. 模板 A：认证异常（撞库 / 口令喷洒）

```kql
// 目标：同源实体在短窗口内对多账号失败后出现成功
<AuthTable>
| where Timestamp between (datetime(<START>) .. datetime(<END>))
| where ResultType in ("<FAIL_CODE>", "<SUCCESS_CODE>")
| summarize
      failures = countif(ResultType == "<FAIL_CODE>"),
      successes = countif(ResultType == "<SUCCESS_CODE>"),
      accounts = dcount(<AccountField>),
      first_seen = min(Timestamp),
      last_seen = max(Timestamp)
  by <SourceEntityField>
| where failures >= <THRESHOLD_FAIL>
| where accounts >= <THRESHOLD_ACCOUNT_SPREAD>
| where successes >= 1
| order by failures desc
```

输出解析：`failures` 高 + `accounts` 分散 → 喷洒/撞库特征；`successes >= 1` 表示可能撞开。
误报调优：把办公网出口、VPN 池、健康检查账号加入白名单；先看 `accounts` 的基线分布，再定 `<THRESHOLD_ACCOUNT_SPREAD>`。

## 3. 模板 B：进程访问敏感目标（注入 / 凭据访问）

```kql
// 目标：非白名单进程访问敏感进程内存
<ProcessEventTable>
| where Timestamp between (datetime(<START>) .. datetime(<END>))
| where <TargetImageField> endswith "<TARGET_PROCESS_SUFFIX>"
| where <AccessMaskField> in ("<MASK_1>", "<MASK_2>", "<MASK_3>")
| where <InitiatingProcessField> !in ("<KNOWN_GOOD_1>", "<KNOWN_GOOD_2>")
| summarize
      hits = count(),
      first_seen = min(Timestamp),
      last_seen = max(Timestamp),
      sample_ids = make_set(<RecordIdField>, 5)
  by <DeviceIdField>, <InitiatingProcessField>, <AccountField>
| where hits >= <THRESHOLD>
| order by hits desc
```

输出解析：按设备 + 发起进程聚合；`sample_ids` 用于回到原始事件核对命令行为与父进程。
误报调优：安全代理、备份、监控、远程支持工具先入白名单；访问掩码集合只保留高风险值，避免把只读查询算进来。

## 4. 模板 C：云控制面高危 API

```kql
// 目标：首次出现的高危控制面调用 + 新源地址 + 失败后成功
<CloudAuditTable>
| where Timestamp between (datetime(<START>) .. datetime(<END>))
| where OperationName in ("<API_1>", "<API_2>", "<API_3>")
| extend err = tostring(<ErrorField>)
| summarize
      attempts = count(),
      errors = countif(isnotempty(err)),
      ok = countif(isempty(err)),
      ips = make_set(<SourceIpField>, 5),
      first_seen = min(Timestamp)
  by <PrincipalField>, OperationName
| where ok >= 1
| order by errors desc
```

输出解析：`errors > 0` 且 `ok >= 1` 表示「试错后成功」；`ips` 用于与新源地址交叉。
误报调优：CI/CD 与运维自动化主体先入白名单；控制面重试会产生重复事件，聚合前按记录 ID 去重。

## 5. 模板 D：DNS 隧道候选

```kql
// 目标：高频长标签查询名（隧道特征），按主机与父域聚合
<DnsTable>
| where Timestamp between (datetime(<START>) .. datetime(<END>))
| extend label_len = strlen(<QueryNameField>)
| where label_len > <THRESHOLD_LEN>
| summarize
      queries = count(),
      distinct_names = dcount(<QueryNameField>),
      first_seen = min(Timestamp),
      last_seen = max(Timestamp)
  by <DeviceIdField>, <ParentDomainField> = <ParentDomainExpr>
| where queries >= <THRESHOLD>
| order by distinct_names desc
```

输出解析：`distinct_names` 极高 + 单父域 → 隧道候选；结合同主机出站字节量确认。
误报调优：CDN、遥测 SDK、邮件域会天然产生大量子域；把已知父域加入白名单后再看长尾。

## 6. 测试样例（假数据，全部保留域）

| 样例 | 构造 | 期望 |
|---|---|---|
| 正例 | `<AuthTable>` 中同一源实体 10 分钟内 6 个账号失败、1 个成功（域名 `host-01.example.com`） | 命中，`failures=6`、`accounts=6` |
| 反例 | 只把源实体换成白名单出口（`<KNOWN_GOOD_1>`） | 不命中 |
| 边界 | `failures` 等于 `<THRESHOLD_FAIL>` 与减一各一条 | 一条命中、一条不命中 |
| 缺失 | 去掉 `<AccountField>` | 不命中，并在结果里记录「字段缺失」 |

样例只用保留域（`example.com`、`*.test`）与文档网段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`）；禁止真实租户、账号、哈希、IOC。

## 7. 基线阈值与误报抑制

1. **基线先行**：同一查询在对照窗口（前 7–14 天同小时段）跑一次，记录 `hits` 的分布，再定 `<THRESHOLD>`。
2. **阈值参数化**：阈值写在 workflow 注入的参数里，不写死在模板。
3. **白名单治理**：每条白名单带「负责人 + 复核日期 + 理由」，过期未复核自动告警。
4. **抑制范围**：只对同一实体 + 同一技术抑制；跨技术抑制会造成盲区。
5. **分级**：`severity`/`level` 表示处置优先级，不表示置信度；不成熟规则先标实验状态。

## 8. 常见错误

| 错误 | 后果 | 修正 |
|---|---|---|
| 用 `count() > 0` 当唯一条件 | 噪声淹没 | 加实体聚合 + 阈值 |
| 只匹配单个宽泛字段 | 大量误报 | 组合条件 + 白名单 |
| 时间窗写死相对时间 | 不可复算 | 用 `<START>`/`<END>` 注入 |
| 聚合后丢失原始 ID | 无法回溯证据 | `make_set(<RecordIdField>, 5)` |
| 把 IOC 当主逻辑 | 易失效 | 行为条件为主，IOC 为辅 |