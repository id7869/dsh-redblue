<!-- dsh-redblue:provenance
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: Skills/web/offensive-sqli/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 合并 web 16 篇/api 2 篇/auth 2 篇/crypto 2 篇与 fuzzing 判定纪律，压缩为类目判定清单，删除可利用载荷与绕过链
-->

# Web / API 漏洞测试判定清单（discover-web-api）

> 定位：`dsh-red-discover` 的 web 与 API 类目判定依据。只产出**候选断言**（candidate），不产出结论、不执行利用。
> 主要上游：Claude-Red `web/`（16 篇）、`api/`（2 篇）、`auth/`（2 篇）、`crypto/`（2 篇）、`fuzzing/`（2 篇，仅判定纪律）、`ai/`；ACS `owasp-top-10-testing`、`web-app-penetration-testing`、`api-security-testing`。
> 消费者：`dsh-red-discover`、`assess` workflow 的 discover 阶段、`dsh-red-validate`（复核本清单产出的候选）。
> 版本时效：CWE 映射与判定信号以 2026-11-19 复核为准；框架行为随版本变化，执行前核对目标框架版本。

## 1. 通用纪律（所有类目共用）

1. **差分而非猜测**：每条候选必须有一次「对照请求 + 测试请求」的差异，差异点写清（状态码、长度、时间、错误文本、结构）。
2. **最小无害载荷**：用算术（`7*7` 期望 `49`）、随机回显串、路径穿越到只读文件等**可判定且无副作用**的载荷；禁止写入、禁止读业务数据、禁止执行命令。
3. **一次只改一个变量**：同一候选的多变量变化分开记录，避免无法归因。
4. **可重复**：同一请求重复两次结论一致；不稳定（缓存/负载均衡）时标 `confidence: possible` 并写 `limitations`。
5. **不越权目标**：只测 `scope.targets[]` 内目标；重定向到外部域即停，记录 `redirect-out` 并丢弃。
6. **范围外数据不落地**：响应里出现个人数据/凭据，截断并脱敏后再写证据。

## 2. 类目判定表（先查表，再按 §3 深入）

| 类目 | CWE | 判定信号（差分点） | 最小只读验证 | 常见误报 |
|---|---|---|---|---|
| SQL 注入 | CWE-89 | 布尔差异、时间差、错误文本差异 | 算术/布尔对（`7*7`、恒真/恒假），只读结果集 | WAF 拦截页、ORM 缓存、参数未生效 |
| 反射型 XSS | CWE-79 | 输入在 HTML 上下文原样回显且未编码 | 输出编码观察（`<`→`&lt;` 与否） | 只在 JSON 中回显、CSP 阻断、富文本白名单 |
| 存储型 XSS | CWE-79 | 二次读取时仍原样回显 | 提交→读取同一条目观察编码 | 读取端已编码、仅自己可见的预览 |
| SSRF | CWE-918 | 服务端代发请求的可观察副作用 | 指向文档网段/回环的回调与响应差异 | 客户端跳转、CDN 缓存、前端代理 |
| XXE | CWE-611 | XML 解析器解析外部实体 | 只有外部实体声明是否被解析（不读文件） | 解析器已禁用 DTD、JSON 入口 |
| SSTI | CWE-1336 | 模板表达式被求值 | 算术表达式回显（`7*7`→`49`） | 前端模板、文档示例回显 |
| 请求走私 | CWE-444 | 前后端对同一请求边界解释不一致 | 定时/连接复用下的响应错位观察 | 连接池复用、健康检查干扰 |
| 文件上传 | CWE-434 | 类型/内容校验缺失且可回读 | 上传无害文本并回读，随后删除 | 只校验前端、对象存储直传 |
| 不安全反序列化 | CWE-502 | 可控序列化数据进入解析器 | 结构解析报错差异（不构造 gadget） | 签名校验、类型白名单 |
| IDOR/BOLA | CWE-639 | 换对象标识后可读到他人对象 | 同账号下两个对象 ID 的交叉读取（仅测试账号） | 对象本就公开、ID 为 UUID 不可枚举 |
| BFLA（功能级越权） | CWE-285 | 低权角色可调用高权端点 | 用低权测试账号调用只读管理端点 | 前端隐藏但后端已校验 |
| 业务逻辑 | CWE-840 | 流程顺序/数量/状态可绕过 | 只读地重复提交同一查询、跳过步骤观察 | 幂等设计、服务端会话绑定 |
| 竞争条件 | CWE-362 | 并发下限额/唯一性被突破 | 两并发只读请求的计数差异 | 队列串行化、分布式锁 |
| 开放重定向 | CWE-601 | 跳转参数接受外部域 | 参数指向保留域观察 `Location` | 白名单跳转、前端路由 |
| HTTP 参数污染 | CWE-235 | 同名参数解析取第一/最后一个不一致 | 同名参数双写观察生效值 | 框架显式取首个 |
| 缓存欺骗/投毒 | CWE-525 | 缓存键与实际内容不匹配 | 只读观察响应头与后续读取一致性 | CDN 按 Cookie 分键 |
| GraphQL | CWE-200 | 内省开放、深度/批量无限制 | 内省查询（只读 schema）与深度限制观察 | 内省已关闭、网关限流 |
| JWT | CWE-347 | 算法/声明校验缺失 | 观察 `alg` 处理与过期校验（不改签名密钥） | 网关已验签、时钟偏移 |
| OAuth/OIDC | CWE-863 | `redirect_uri`/`state`/`scope` 校验缺失 | 用保留域做回调观察是否被接受 | 严格白名单、PKCE 强制 |
| TLS/加密 | CWE-326 | 弱协议/套件、证书链问题 | 握手观察（版本/套件/证书） | 中间设备终结、扫描器误判 |
| LLM 应用 | CWE-1426 | 模型输出被下游当指令执行 | 只读的指令边界测试（不改系统状态） | 输出过滤、人工复核 |

## 3. 深入判定（易误判类目）

### 3.1 SSRF

- 先判定「服务端是否代发」：用只属于自己的 OAST/回调域名（`<OAST_HOST>`）做唯一标记，观察回调时间与源。
- 盲 SSRF 只看「有没有回调」，不尝试内网端口批量探测；确需判断内网可达性时，一次只测一个回环或文档网段地址。
- 证据：请求参数、回调日志（含时间与源）、响应差异；缺回调日志则 `confidence: possible`。
- 禁止：用 SSRF 读取云元数据并落盘凭据；命中即停，按 §6 记录。

### 3.2 请求走私

- 只在授权明确包含「协议层测试」时做；默认跳过并写 `limitations`。
- 判定用「响应错位 + 连接复用」的观察，不用实际投毒他人请求。
- 需要两次以上一致观察才能升 `likely`，否则只作 `possible`。

### 3.3 竞争条件

- 只做「限额/唯一性」的只读验证（两个并发读请求的计数差），不触发写操作。
- 需要写操作才能证明时，降级为 `deferred` 并说明「需授权写窗口」。

### 3.4 反序列化

- 只观察「解析器是否接受可控结构」（错误文本、类型报错），不构造 gadget、不投递序列化对象。
- 一旦确认解析器接受外部结构，写候选并交给 `dsh-red-validate` 判定影响，不在 discover 阶段深入。

### 3.5 API 专项

- **对象级**：同一低权测试账号下交叉读取两个对象（自己的两个资源），不做他人数据读取。
- **功能级**：低权账号调用只读管理端点（GET/HEAD），观察 200/403 差异。
- **批量赋值**：只读地提交额外字段并观察响应是否回显该字段（不写库）。
- **速率限制**：只测「有限次（≤10）」的阈值观察，禁止压力测试。
- **GraphQL**：内省查询是只读的；深度/别名批量只做小规模（≤5）验证。
- **WebSocket**：只验证握手鉴权与消息鉴权是否一致，不发送滥用消息。

### 3.6 身份与会话

- JWT：观察 `alg` 与声明校验（`exp`/`aud`/`iss`），不尝试伪造密钥；`none` 算法只观察是否被接受。
- OAuth/OIDC：检查 `redirect_uri` 精确匹配、`state` 绑定、PKCE；用保留域做回调验证。
- SAML：检查签名校验与受众限制；不构造断言。
- 会话：Cookie 属性（`HttpOnly/Secure/SameSite`）、会话固定、并发会话策略。

### 3.7 LLM/AI 应用

- 判定「指令与数据是否分离」：把无害标记放进用户输入，观察是否被下游当指令（如改变输出格式、泄露系统提示词）。
- 不尝试让模型执行工具调用去改动外部系统；工具调用类风险只做「权限边界是否存在」的静态判定。
- 证据：请求、响应、复现步骤；提示词注入结论必须有「数据被当指令」的具体证据。

## 4. 命令模板（HTTP 差分）

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 对照请求：只读，记录状态码/长度/时间（-w 输出可判定字段）
curl -sS -o /dev/null -w 'code=%{http_code} size=%{size_download} time=%{time_total}\n' \
  https://app.example.com/search?q=control123
# 测试请求：只改一个变量（无害算术载荷），其余完全相同
curl -sS -o /dev/null -w 'code=%{http_code} size=%{size_download} time=%{time_total}\n' \
  https://app.example.com/search?q=7*7
```

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 认证差异对照（令牌来自授权方提供，禁止落盘明文）
curl -sS -H "Authorization: Bearer <TOKEN>" -o /dev/null -w 'auth code=%{http_code}\n' \
  https://app.example.com/api/v1/orders/1001
curl -sS -o /dev/null -w 'anon code=%{http_code}\n' \
  https://app.example.com/api/v1/orders/1001
```

记录要求：两条命令的 `commandSummary` 都要进证据；差异值（code/size/time）写进 `claim` 的判据。

## 5. 候选断言字段（discover 输出）

```json
{
  "candidateId": "cand_web_001",
  "hypothesisId": "th_1",
  "category": "sql-injection",
  "target": "app.example.com",
  "claim": "q 参数进入 SQL 拼接：恒真/恒假对照返回不同结果集",
  "cwe": "CWE-89",
  "attack": ["T1190"],
  "observed": "control=0 行，7*7=49 行；错误文本含 SQL 关键字",
  "evidenceRefs": ["ev_cand_web_001_1", "ev_cand_web_001_2"],
  "confidence": "likely",
  "limitations": ["未做时间盲注；未验证写权限（禁止）"]
}
```

要求：`hypothesisId` 必须能回指 `surface.json`；`evidenceRefs` ≥2（对照 + 测试）；`category` 用 kebab-case，决定 SARIF ruleId。上面的 `target` 用简写值（完整结构为 `{kind, value}`，见 `schema/finding.schema.json`），落在 JSON 时按 schema 展开。

## 6. 禁止事项与升级路径

- 禁止：命令执行、文件写入、上传 webshell、反弹连接、批量拉取数据、密码喷洒、拒绝服务、绕过第三方平台访问控制。
- 命中「疑似凭据/个人数据」立即停止该类目，脱敏记录并通知授权方（`policy/authorization.md` §6）。
- 需要写操作或利用链才能推进的类目，写 `deferred` 并交给 `dsh-red-exploit`（受控利用，需 `confirm` 与 `mode≥exploit`）。
- 判定不稳定或只有单一信号时，交 `dsh-red-validate` 独立复核，不自行升级为 `reportable`。
- 反模式：把扫描器告警原文当候选；没有对照请求；用真实用户数据做 IDOR；一次改多个参数无法归因。