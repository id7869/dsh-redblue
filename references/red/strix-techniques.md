<!-- dsh-redblue:provenance
source-repo: https://github.com/usestrix/strix
source-commit: 8db295a5b3564be2b430bb3a9afdb4db7850fa24
source-license: Apache-2.0
source-path: strix/skills/vulnerabilities/sql_injection.md
last-verified: 2026-11-19
rewrite-summary: 聚合 78 篇内部知识为 30 类决策表与框架/协议/云/源码/SCA 矩阵，改写为假设→验证→证据→误判边界→检测视角，删利用链与真实目标
-->

# Strix 实战测试技术矩阵（strix-techniques）

> 定位：把 Strix 内部知识库（`strix/skills/**`，78 篇 / 约 904 KB）压成红队可执行判定矩阵，补齐「9 个对外技能只讲怎么跑、不讲怎么测」的缺口。
> 差异说明：`references/red/tool-recipes.md` 回答「用哪个工具、参数怎么给」；本篇回答「针对这类面，假设是什么、最小验证怎么做、证据要什么、什么情况不算」。两篇配合使用，不重复。
> 关闭纪律（confirmation / ruled_out / proof_gap 三态）见 `references/shared/finding-review.md`；证据字段见 `references/shared/evidence-standards.md` §3。
> 版本时效：矩阵按 pin 的 2026-11-19 版本复核；框架/云厂商/扫描器版本会改变判定条件，执行前核对目标版本与厂商 advisory。

## 0. 使用方式与通用口径

1. **每条结论必须有对照**：至少一对「基线请求 + 测试请求」，只改一个变量；差异写在 `claim` 的判据里。
2. **最小可证**：优先只读证明（回显、状态码、长度、时间、外部回调）；不写目标、不导出数据、不执行命令。
3. **误判边界优先**：先读对应行的「误判边界」列，命中任一条就必须追加反证或降级为 `deferred`。
4. **静态只是假设**：源码/配置/版本信号一律是假设，必须落到运行时验证（见 §5）。
5. **证据字段**（沿用 evidence-standards）：`commandSummary`、`ts`（UTC）、目标归一化值、`outputPath`、`sha256`/`bytes`、`excerpt`（≤2 KiB）、`grade`（E2 起才可进 findings）。
6. **不做的事**：不做破坏性验证、不横向扩面、不关闭日志、不留持久化；命中凭据/个人数据即停并脱敏。

## 1. 30 类漏洞验证决策表

| # | 类目 | 攻击假设 | 最小验证 | 所需证据 | 误判边界 | 检测视角 |
|---:|---|---|---|---|---|---|
| 1 | SQL 注入 | 用户输入拼进查询语句 | 布尔/时间/错误差分，再取版本与当前用户 | 成对请求 + 元数据行 + 仅注入片段的差异 | 参数化已确认、静态长度、网络抖动、WAF 页 | WAF SQLi 规则、错误率突增、异常延迟 |
| 2 | NoSQL 注入 | 操作符对象进入查询过滤器 | `$ne`/`$gt`/`$regex` 与字符串值对照 | 401→200 对照、两种操作符均生效 | 框架强转 `[object Object]`、校验先拦截 | 异常 JSON 结构、查询解析错误 |
| 3 | 查询语言注入 | 过滤表达式拼接输入 | known-match / known-no-match 基线 + 放宽表达式 | 成对结果集摘要（对象 ID 或规范化摘要） | 合法通配/模糊语法、分页排序变化、缓存 | 查询语法错误、过滤深度异常 |
| 4 | XSS | 输入进入 HTML/属性/JS/URL 上下文未编码 | 无害标记在对应上下文回显并观察编码 | 响应片段 + 编码前后对照 | JSON 回显、CSP 阻断、富文本白名单 | WAF XSS 规则、CSP 违规上报 |
| 5 | SSTI | 用户输入进入模板源而非变量 | 两个不同算术表达式求值（`7*7`→49、`7*8`→56） | 两次表达式结果 + 引擎指纹 | 字面回显（即 XSS 形态）、客户端模板、构建期渲染 | 模板错误、异常渲染耗时 |
| 6 | SSRF | 服务端代发可控 URL | 先 OAST 回调，再判内网/元数据可达 | 回调时间与源、内网响应差异 | 仅客户端跳转、回调源是测试机、全出口阻断 | 出站连接、异常 DNS 查询 |
| 7 | XXE | XML 解析器解析外部实体 | 外部实体声明是否被解析（不读文件） | 解析错误差异 / 受控回显 | DTD 已禁用、JSON 入口、解析前校验 | XML 解析错误、异常出站请求 |
| 8 | 路径穿越 / LFI / RFI | 路径拼接未规范化或未限制根 | 出根读取最小文件 + 同端点根内对照 | 前后路径、内容哈希/长度、精确请求 | 虚拟路径不落盘、规范化后白名单 | 文件访问审计、异常路径字符 |
| 9 | 文件上传 | 类型/内容校验缺失且可回读 | 上传无害文本并回读，随后删除 | 上传响应、回读状态、清理记录 | 仅前端校验、对象存储直传、不可回读 | 上传体积/类型异常、Web 目录新文件 |
| 10 | 不安全反序列化 | 可控序列化结构进入解析器 | 观察结构/类型报错差异（不投递对象） | 解析器响应差异 + 版本/格式 | 签名校验、类型白名单、仅解析 JSON | 反序列化异常、类加载异常 |
| 11 | 原型污染 | merge 把用户对象写入原型链 | 注入无害 canary 键，观察是否影响无关对象 | canary 键 + 后续请求行为变化 | 解析器剥离 `__proto__`、`Object.create(null)` | 异常 JSON 键、运行时类型错误 |
| 12 | IDOR / BOLA | 对象标识未做归属校验 | 同一测试账号下两个对象的交叉读取 | 双对象/双账号对照 + 对象 ID | 对象本就公开、UUID 不可枚举、前端过滤 | 横向对象访问模式、越权拒绝率 |
| 13 | 功能级授权（BFLA） | 低权角色可调用高权端点 | 低权账号调用只读管理端点 | 200/403 对照 + 角色矩阵 | 前端隐藏但后端已校验、网关拦截 | 管理端点访问、权限拒绝分布 |
| 14 | 认证 / JWT | 签名、`alg`、声明或受众校验缺失 | 过期/错误受众/异常 alg 令牌的拒绝行为 | 令牌声明（脱敏）+ 响应 | 网关已验签、时钟偏移、缓存身份 | 验签失败、异常 alg、异常受众 |
| 15 | 批量赋值 | 序列化层接受额外字段 | 只读提交额外字段并观察是否回显/生效 | 请求字段 vs 响应字段差异 | DTO 白名单、只读字段、序列化忽略 | 异常字段名、越权字段变更 |
| 16 | CSRF | 依赖环境凭据且无 token 校验 | 跨站表单/JSON 请求能否改变状态（只读观察） | 状态变化前后 + 请求头/来源 | SameSite=Lax、仅 Bearer 无环境凭据 | 跨站来源、无 token 的状态变更 |
| 17 | 请求走私 | 前后端对请求边界解释不一致 | 连接复用下的响应错位（需协议层授权） | 两次一致观察 + 拓扑证据 | 连接池复用、健康检查干扰 | 代理 400/502 异常、队列错位 |
| 18 | 头注入 | 输入进入响应头或邮件头 | CR/LF 与空白变体，观察原始响应头 | 原始响应头（含编码形式） | 框架过滤、编码后仍被拒 | 异常响应头、邮件头异常 |
| 19 | 开放重定向 | 跳转参数未做严格校验 | 参数指向保留域，观察 `Location` | 完整 URL + `Location` + 合法对照 | 相对路径、精确白名单、终端二次确认 | 异常 302 目标域、OAuth 回调异常 |
| 20 | 业务逻辑 | 流程顺序/数量/状态可绕过 | 只读地重复提交、跳过步骤、边界值 | 状态机前后差异（订单/额度/角色） | 幂等设计、服务端会话绑定、审计补偿 | 异常流程序列、重复提交峰值 |
| 21 | 竞争条件 | 并发窗口内不变量被破坏 | 两个并发只读请求的计数差 | 并发请求集 + 持久状态变化 | 串行化事务、分布式锁、原子限流 | 并发峰值、重复扣减/重复发券 |
| 22 | 语义混淆 | 校验组件与消费者对同一输入理解不同 | 成对输入在边界两侧产生不同解释 | 原始字节 + 校验方表示 + 消费方表示 | 仅日志差异、无安全决策、双方最终一致 | 规范化差异日志、双解析告警 |
| 23 | 参数注入 | 输入拼进命令行参数而非命令串 | 无害 flag/文件名注入观察行为差异 | 命令上下文 + 输出/错误差异 | 参数化调用、固定参数集、shell 关闭 | 异常子进程、异常参数组合 |
| 24 | RCE | 输入到达命令/求值 sink | 无副作用 oracle（OAST 或时间差） | oracle 结果 + 执行上下文 | 仅崩溃/超时、受限解释器无 IO | 子进程创建、异常命令、异常 DNS |
| 25 | 信息泄露 | 错误/调试/备份/映射暴露敏感面 | 只读观察状态码与内容类别（不下载批量） | 响应片段 + 路径 + 大小 | 通用错误页、蜜罐、公开静态资源 | 404 洪峰、敏感路径访问、错误页比例 |
| 26 | 子域接管 | 悬空 CNAME 指向可被声明的资源 | DNS 链 + 第三方指纹 + 可声明性判定 | 解析链、指纹、资源可注册状态 | 保留域、已声明、CDN 占位、托管保留 | DNS 变更、第三方资源声明事件 |
| 27 | 弱口令 | 认证端点缺限速/策略/锁定 | 少量（≤5）错误尝试 + 策略读取 | 响应差异 + 锁定/限速行为 | 通用错误、WAF 前置、账号锁定策略 | 失败登录分布、锁定事件 |
| 28 | LLM 提示注入 | 指令与数据未分离；输出进入 sink | 无害标记是否被当指令（格式改变/系统提示泄露） | 请求 + 响应 + 影响面 | 输出过滤、仅影响本人会话、无工具权限 | 异常提示模式、工具调用序列 |
| 29 | 浏览器安全 | postMessage/CSP/跨源读取存在缺口 | 只读观察 origin 校验、消息处理、CSP | 消息结构 + 处理结果 + CSP 头 | 客户端无敏感数据、已校验 origin | CSP 违规上报、异常 postMessage |
| 30 | 智能体 / MCP | 工具授权、参数边界或租户隔离缺失 | 只读工具清单 + 参数边界探测 | 工具清单（含 schema/权限）+ 调用边界 | 只读工具、沙箱、无跨租户数据 | 工具调用审计、越权工具使用 |

### 1.1 需要成对/三方对照的类目（否则不算证据）

- **查询语言注入（#3）与语义混淆（#22）**：必须有「基线命中/基线不命中/放宽表达」三件套，且兄弟字段与凭据保持不变。只有错误文本或响应体长度变化 → 记 `open_proof_gap`，不得写成数据访问。
- **SSRF（#6）**：回调源必须能证明是**服务端**发出（对比测试机出口 IP/时间线）；只有客户端跳转不算。
- **竞争条件（#21）**：必须有持久状态差异（额度、库存、唯一性），纯前端「看起来成功」不算。
- **请求走私（#17）**：两次以上一致观察 + 拓扑证据；不稳定就写 `possible` 并注明「需协议层授权与复现窗口」。
- **原型污染（#11）**：canary 必须影响**无关对象**的行为；只在回显 JSON 里看到键不算。

### 1.2 高频误判（跨类目通用）

- 把「扫描器告警」当候选：模板命中只说明特征匹配，必须补对照。
- 把「403 变成 200」当授权绕过：需同对象/同动作的身份对照，且排除缓存与路由差异。
- 把「版本匹配 advisory」当可利用：版本只提供线索，必须在执行端点上证明影响。
- 把「客户端行为」当服务端问题：SSRF、XSS 存储、CSRF 都要确认请求发起方。
- 把「错误信息差异」当注入成功：先排除校验层、框架层与代理层产生的差异。

## 2. 框架特化攻击面（5 个）

### 2.1 Django / DRF

- **入口点**：`urls.py` 路由、DRF `ViewSet`/`APIView`、Channels consumer、admin、管理命令。
- **危险 sink**：`raw()`/`extra()`/`RawSQL` 拼接、`mark_safe`/`|safe`、`Template(user_input)`、`pickle` 会话/缓存、`FileField` 写入路径、`os.system` 类管理命令。
- **认证/授权陷阱**：视图缺 `permission_classes`、有 `queryset` 无 `get_queryset` 过滤（对象级越权）、`AllowAny` 误用、`simplejwt` 未校验受众/黑名单。
- **批量赋值**：`ModelSerializer` 的 `fields = "__all__"` 或未设 `read_only_fields`；关注 `is_staff`/`owner`/`tenant` 字段。
- **SSRF**：`requests`/`urllib` 拉取用户给的 URL；图片/PDF 生成器的远程抓取。
- **模板注入**：用户输入作为模板**源**（不是变量）；邮件/报表模板。
- **反序列化**：`pickle` 会话/缓存、`yaml.load`、签名未校验的 session 序列化、上游 JSON 直接构造对象。
- **CSRF/其他**：`csrf_exempt` 滥用、`DEBUG=True` 的 settings 泄露、`ALLOWED_HOSTS` 宽泛导致 Host 头攻击、密码重置链接 Host 拼接。
- **常见 CVE 族**：Django/DRF 本体与依赖组件（文件上传、模板、序列化、管理后台），按版本核对 advisory，版本命中只作线索。
- **高价值目标**：admin、DRF 可浏览 API、文件下载/导出、WebSocket consumer、定时任务入口。

### 2.2 FastAPI / Starlette

- **入口点**：`APIRouter`、`Depends` 依赖链、`BackgroundTasks`、WebSocket、挂载的静态/子应用。
- **危险 sink**：`subprocess`/`os.system`、`eval`/`exec`、Jinja2 模板、`pickle`/`yaml.load`、路径参数直接拼文件、`StreamingResponse` 读任意文件。
- **认证/授权陷阱**：**部分路由漏挂依赖**（依赖只在 router 级或方法级）、`OAuth2PasswordBearer` 缺受众校验、scope 校验写在错误层级、依赖缓存导致身份串用。
- **输入处理**：Pydantic 版本/严格度差异（`extra` 是否忽略）、Content-Type 切换（JSON ↔ 表单）、重复参数与数组/对象混淆、路径参数未转义。
- **批量赋值**：模型 `extra="allow"` 或直接把 `dict()` 写入 ORM；`id/owner/role` 等字段未设只读约束。
- **SSRF**：`httpx`/`requests` 拉用户 URL、Webhook 回调、图片/文档转换器、`BackgroundTasks` 内的外联。
- **反序列化**：`pickle`、`yaml.load`、JWT 无验签解码、上游服务返回的不可信 JSON 直接建对象。
- **CORS/CSRF**：`allow_origins=["*"]` 与 `allow_credentials=True` 组合、Cookie 会话下无 CSRF。
- **代理与 Host 信任**：`X-Forwarded-*` 未校验、可信 Host 列表缺失、重定向拼接 Host。
- **常见 CVE 族**：Starlette/FastAPI/Pydantic 与模板、序列化依赖，按版本核对 advisory。
- **高价值目标**：`/docs`、`/openapi.json`（枚举全量路由）、后台任务触发端点、文件下载、WebSocket 鉴权。

### 2.3 NestJS

- **入口点**：`@Controller` 路由、`@Resolver`（GraphQL）、`@WebSocketGateway`、微服务 `@MessagePattern`/`@EventPattern`、CRUD 生成器、`@nestjs/schedule` 任务、健康检查。
- **危险 sink**：`@Body` 直传 ORM/查询构造器、原生 SQL、模板渲染、文件拦截器（`FileInterceptor`）、动态 `require`。
- **认证/授权陷阱**：**guard 装饰器栈缺口**（全局 → 控制器 → 方法；方法漏 `@UseGuards` 是头号问题）、`@Public()` 元数据过宽、DTO 校验未启用（无 `ValidationPipe` 或 no whitelist）、跨传输鉴权不一致（HTTP 有、WS/微服务无）。
- **批量赋值**：`class-transformer` 未 `excludeExtraneousValues`、`plainToInstance` 后直接持久化。
- **序列化泄露**：实体直接返回（密码哈希、内部字段）；`@Exclude` 未生效。
- **SSRF / 反序列化**：`HttpModule`/`axios` 拉用户 URL、Webhook、文件/图片处理流水线；`class-transformer` 对不可信 JSON 的 `plainToInstance`、动态 `require` 视为反序列化面。
- **常见面**：Express/Fastify 适配器差异（查询解析器、schema 强制）、版本相关的路由/中间件行为。
- **常见 CVE 族**：Nest 本体、Express/Fastify 适配器、class-validator/transformer 与模板依赖，按版本核对 advisory。
- **高价值目标**：微服务 handler、WebSocket 事件、CRUD 自动端点、`/health`、`/metrics`、Swagger。

### 2.4 Next.js

- **入口点**：App Router `route.ts`、Server Actions、Pages `api/*`、`middleware.ts`、`/_next/image`、`next/og`、ISR/revalidate 端点。
- **危险 sink**：RSC/flight 解码、图片优化器（远程取图 + 原生解码）、SVG 处理、`eval` 型动态导入、自定义 loader。
- **认证/授权陷阱**：**仅靠 middleware 做授权**（可被特制头/路径变体绕过）、Server Action 缺鉴权（可绕过 UI 直接调用）、Edge 与 Node 运行时策略不一致、App Router 与 Pages Router 鉴权不一致。
- **缓存与身份**：缓存键未区分身份（缺 `Vary`/Cookie 参与）、ETag/ISR 跨用户命中、`__NEXT_DATA__` 泄露他人/内部字段。
- **批量赋值 / 反序列化**：Server Action 与 Route Handler 的入参未按白名单取字段（`...body` 直接落库）；RSC/flight 与 `next/og` 解析不可信结构化输入视为反序列化面。
- **SSRF**：图片优化器与 `next/og` 远程取图、自定义 loader、草稿预览回源。
- **模板注入面**：`next/og`、邮件/通知模板把用户字符串当模板片段；React SSR 的转义边界与 `dangerouslySetInnerHTML` 是相邻风险面（按注入上下文判定，不套用服务端模板引擎结论）。
- **路径与代理**：路径规范化差异（尾斜杠/编码/大小写）、`x-middleware-rewrite` 与 307 行为、图片域名白名单不等于内容可信。
- **常见 CVE 族**：RSC/图片优化器/中间件/路由缓存/缓存键相关，按部署版本核对框架与宿主平台 advisory。
- **高价值目标**：中间件保护的 admin/geo 路由、草稿/预览、revalidate、Server Actions、图片优化器。

### 2.5 Spring Boot

- **入口点**：`@RestController`/`@RequestMapping`、Actuator（`/env`、`/heapdump`、`/mappings`、`/beans`）、Spring Data REST 根、H2 console、`@JsonTypeInfo` DTO、remember-me/logout。
- **危险 sink**：SpEL 表达式、Jackson 多态反序列化、模板引擎、JPA 原生 SQL 拼接、文件上传/解压、`ProcessBuilder`。
- **认证/授权陷阱**：过滤链顺序与 `permitAll` 范围、方法级 `@PreAuthorize` 缺失、CSRF 关闭（`csrf.disable()`/宽泛 `ignoringRequestMatchers`）、Actuator 端点暴露、默认用户/生成口令。
- **批量赋值**：`@ModelAttribute`/实体直接绑定，`@JsonIgnore` 未覆盖敏感字段。
- **SSRF**：`RestTemplate`/`WebClient` 拉用户 URL、图片/文档转换、报表回源、Webhook 出站。
- **模板与反序列化**：SpEL 表达式求值、模板引擎把输入当模板源、Jackson 多态类型受输入控制。
- **兼容面**：MVC vs WebFlux、Servlet 容器解析差异、依赖版本对应的历史 CVE 族（按版本核对 advisory，不凭版本直接定级）。
- **常见 CVE 族**：Spring 本体与 Spring Security/Data、Jackson、模板引擎、文件解析依赖，按版本核对 advisory。
- **高价值目标**：Actuator、H2 console、Spring Data REST 导出、文件下载/导出、记住我令牌。

## 3. 协议特化

### 3.1 GraphQL

| 面 | 假设 | 最小验证 | 证据 | 误判边界 |
|---|---|---|---|---|
| introspection | schema 全量暴露便于枚举 | 只读 introspection 查询 | schema 类型/字段清单 | 内省已关闭但字段可推断（仍可测） |
| 字段级 IDOR | 父对象校验、子字段未校验 | 同一请求用 alias 并行取 own/foreign | 双 alias 结果对照 | 两者都返回空/错误（非越权） |
| 批量与 alias | 批量放大枚举/绕过限流 | 单请求少量 alias 对照 | 请求体积与结果数 | 网关限流/复杂度限制已生效 |
| 授权绕过 | 传输层鉴权不一致 | HTTP 与 WebSocket 同操作对照 | 两传输响应差异 | WS 未启用/需额外握手鉴权 |
| 联邦 | `_entities`/`_service` 绕过子图鉴权 | 只读查询 `_service` 与 `_entities` | 子图 schema 与跨子图数据 | 联邦未启用、子图已校验 |
| 输入操纵 | 变量类型/数组/对象混淆绕过校验 | 类型变体请求对照 | 校验错误 vs 成功 | 严格类型校验、输入白名单 |

- 方法：先指纹（端点/传输/栈/GraphiQL），再建 schema 图，再按「无认证 / 用户 / 管理员」三身份逐 resolver 测；同一请求内用 alias 做对照，避免跨请求噪声。
- 验证要求：成对请求（owner vs 非 owner）、resolver 路径、传输一致性；`_entities` 类要有跨子图数据证明。

### 3.2 REST + OpenAPI / Postman spec 驱动

- **spec 是授权目标清单**：base URL 与每个 operation 都是测试对象；用 `{param}` 模板代入基线值。
- **覆盖表**：每个 operation 一行（method/path/认证要求/输入 schema/测试状态），避免漏测；`coverage.techniques` 与之对齐。
- **输入变异**：额外字段、错误类型、null、数组/对象互换、超长/空值、重复参数、Content-Type 切换。
- **认证矩阵**：无认证 / 普通用户 / 高权用户 × 每个 operation；差异写进 claim。
- **示例值陷阱**：Postman collection 的 example 与 environment 变量可能是过期或他人数据，只作起点，不作为证据。
- **验证要求**：同一请求换令牌的成对对照；越权结论必须包含「另一账号的数据」或「高权动作成功」的直接证据。

## 4. 云与容器

### 4.1 AWS

- **凭据来源**：代码/环境变量、CI 配置、EC2/ECS 元数据、SSRF 链；先 `get-caller-identity` 确认主体与账号。
- **IMDS**：v1 直接可读；v2 需先取 token 再带 token 头——判定「sink 是否能设 header/method」决定可达性；ECS 任务凭据走专用相对路径。
- **IAM 提权路径**：`iam:PassRole` + 创建/更新计算资源、策略版本覆盖、角色信任策略过宽、`iam:CreateAccessKey`/`UpdateAssumeRolePolicy`；**必须核对权限边界与 SCP**，否则是误判。
- **存储暴露**：public ACL/策略（`Principal:"*"`）、`ListBucket` 公开、对象键可猜（备份/配置/日志）、快照与 AMI 共享、签名 URL 过长 TTL。
- **验证要求**：对象键 + ETag/大小；提权的精确 API 调用与结果权限；元数据凭据只记范围不落原文；根因写 ARN + 策略语句。

### 4.2 Azure

- **双平面**：Entra 目录角色（全局管理员/应用管理员等）与 Azure 资源角色（Owner/Contributor/User Access Admin）分别枚举，注意组继承与管理组范围。
- **身份对象**：应用注册/服务主体/托管身份的所有者、凭据（密码/证书/联邦凭据）、API 权限与同意状态。
- **策略门**：条件访问、认证方法、PIM（eligible/active）、Azure Policy、拒绝分配、网络限制——它们决定「路径是否真的可用」。
- **高价值**：`User Access Administrator` + 角色分配、应用凭据追加、Key Vault 访问策略、存储 SAS、Graph 授权。
- **验证要求**：租户/订阅、主体与对象 ID、角色定义/范围/继承/条件/PIM 状态、精确 Graph 或 ARM 动作与目标资源。

### 4.3 GCP

- **IAM 路径**：`iam.serviceAccounts.actAs`、`setIamPolicy`、SA 密钥创建、Cloud Functions/Cloud Run 部署权限 → 以 SA 身份执行。
- **元数据**：工作负载内可取默认 SA token 与 scope；判定 token 的实际 scope（只读单桶 ≠ 全面失陷）。
- **存储**：`allUsers`/`allAuthenticatedUsers` 绑定、禁用统一桶级访问后的旧 ACL、签名 URL、可列举桶的对象键。
- **验证要求**：项目 ID、资源名、IAM 绑定根因；GCS 读/列的对象键与 URL；元数据 token 只记 scope。

### 4.4 Kubernetes

- **RBAC**：通配 verbs/resources、`cluster-admin` 绑给 SA、`system:anonymous`/未认证组、`escalate`/`bind`/`impersonate`、SA token 自动挂载。
- **控制面**：API server 匿名访问、kubelet 只读端口与 10250 鉴权、etcd 暴露、dashboard、admission webhook（如 ingress 控制器）可达性与权限。
- **工作负载**：`privileged`、`hostPath`/`hostPID`/`hostNetwork`、挂载容器运行时 socket、Secret 以环境变量暴露、镜像可变 tag。
- **网络**：NetworkPolicy 缺失或 CNI 默认行为、跨命名空间可达、元数据端点可达。
- **验证要求**：跨命名空间读/exec 的直接证据；SA token → 更高权限的完整链路；宿主可见性用非破坏性读取；`kubectl auth can-i yes` 需排除准入控制器/OPA 拦截。

## 5. 源码感知（static → runtime）

### 5.1 工具栈与首过

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 四件套：语义规则 → 结构模式 → 秘密 → 依赖/配置（全部离线，输出到 workDir）
opengrep scan --config auto --json --output <WORKDIR>/sast/opengrep.json .
sg --pattern 'eval($ARG)' --lang js src/ | head -50
gitleaks detect --source . --report-format json --report-path <WORKDIR>/sast/gitleaks.json --no-banner
trivy fs --scanners vuln,misconfig --list-all-pkgs --format json --output <WORKDIR>/sast/trivy.json .
```

- 先用语义规则（opengrep）做安全首过；慢或噪声大时按栈收窄规则集。
- 再用结构模式（ast-grep/`sg`）做「同族扫描」：同一危险调用在仓储/服务/子包里的复制点。
- tree-sitter 只用于提符号/路由/挂载点，产出确定性目标清单（不猜路径）。
- 秘密检测双跑（工作树 + 历史），互相补盲。

### 5.2 source-aware discovery 纪律

| 纪律 | 含义 | 落地 |
|---|---|---|
| 真正的控制点 | 解析器/allowlist/guard 可能在「上游中间件」而非业务函数 | 从路由入口向下追，确认校验发生在 sink 之前 |
| 同族扫描 | 同一过滤器在 core/server/cli 重复实现 | 逐副本比对，找漏改的那一份 |
| 跨边界输入 | 队列、定时任务、CLI、webhook 也是输入面 | 把非 HTTP 入口加入测试矩阵 |
| 收敛门槛 | 只有「输入→控制→sink→影响」四段都有证据才进报告 | 缺一段记 proof_gap |

### 5.3 静态信号 → 运行时验证映射

| 静态信号 | 运行时验证动作 | 证据 |
|---|---|---|
| 路由 handler 附近缺鉴权 | 无认证/低权请求同一 operation | 状态码 + 数据差异 |
| 动态命令/查询构造 | 无副作用 oracle（时间/回调/错误差异） | oracle 结果 + 上下文 |
| 模板执行/不安全反序列化 | 结构或类型解析差异 | 解析响应 + 版本 |
| 路径/文件操作受用户影响 | 出根读取 + 根内对照 | 路径 + 内容哈希 |
| 命令 runner 从 PATH/注册表回退 | 解析顺序与可写性判定（供应链，见 §6） | 解析链 + 可写性 |
| 插件/模板/模块搜索路径可写 | 低权可写性判定 + 加载顺序 | 权限 + 加载证据 |

- 白盒纪律：一次 opengrep + 一次 AST + 一次秘密 + 一次 `trivy fs` 构成基线覆盖；静态结论必须动态验证后才可报告；扫描输出要去重并映射到具体代码位置。

## 6. 供应链（SCA 与依赖混淆）

### 6.1 依赖 CVE 扫描（SCA）

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
trivy fs --scanners vuln --list-all-pkgs --format json --output <WORKDIR>/sca/trivy.json .
```

- **先看库龄**：记录漏洞库更新时间（如 `.VulnerabilityDB` 的 UpdatedAt/NextUpdate）；库过期时的「干净」是假信号。
- **`--list-all-pkgs`** 保留依赖图（Relationship/DependsOn），用于把传递依赖的 CVE 归因到引入它的直接依赖（`introduced_by`）。
- **可达性判定**：对每条 CVE 回答「本仓库是否调用受影响函数/路径」；可达性是代码路径结论，不是严重度结论。
- **报告字段**：`VulnerabilityID`（CVE 优先）、`PkgName` + `InstalledVersion`、`FixedVersion`、`Target`（lockfile 路径）、生态类型、CVSS、`PrimaryURL`、`introduced_by`。
- **误判边界**：仅开发依赖、未打包进产物、已固定到修复版本、受影响特性未启用。

### 6.2 npx 依赖混淆

- **完整解析语句**（缺一段不算）：目标侧调用 → 预期可执行不存在 → 公共源同名包被选中 → 该包可注册/可发布 → 执行触发器与继承权限。
- **判定顺序**：找命令调用点（脚本/CI/文档/agent 运行时）→ 确认本地/声明依赖是否满足 → 查公共源同名包状态 → 评估执行环境权限。
- **误判边界**：声明依赖已提供该二进制、`--package <pkg>` 显式绑定、版本化 spec 指向预期发布者、registry 策略阻止争议注册、仅出现在生成文本里无调用点。
- **影响分级**：按执行环境（开发者机器 > 发布流水线 > CI > 容器构建 > 文档）而非按包名。

## 7. 技术指纹、工具选取与扫描深度

### 7.1 平台/技术专属面（可迁移要点）

| 面 | 高价值目标 | 判定要点 |
|---|---|---|
| Auth0 | 应用配置、audience、Rules/Actions、组织（B2B）、MFA | 令牌 audience 混用（A 的令牌打 B 的 API）、redirect 白名单、MFA 策略缺口 |
| Firebase | Firestore rules、Realtime DB、Storage、Auth token | rules 是否按用户/租户限制、读写路径、公开读、自定义声明 |
| Supabase | RLS、PostgREST、签名密钥 | RLS 未启用或策略过宽、跨租户行数对照、写路径校验 |
| Grafana/Prometheus | 未授权面板、快照、插件、Alertmanager | 观测栈默认无认证即暴露；历史 CVE 族按版本核对；插件/MCP 边界 |
| Electron | preload/contextBridge、nodeIntegration、自定义协议、更新 | 渲染进程能力边界、深链参数、更新签名校验 |
| AD | Kerberos roasting 面、委派、ACL、ADCS | 配置枚举为主，判定「是否存在路径」而非执行 |
| LLM 应用 | 提示注入、敏感信息泄露、过度代理、供应链、无界消耗 | 指令/数据分离、工具权限、输出 sink、成本限制 |

### 7.2 工具选取（一句话对应场景）

| 场景 | 工具 | 关键约束 |
|---|---|---|
| 子域/资产 | subfinder → dnsx → httpx | 被动优先；主动需 activeScan |
| 端口/服务 | naabu（快速）→ nmap（版本/脚本） | 限速、限端口、禁攻击脚本 |
| 爬取/URL | katana | 同域、限深、限速 |
| 目录/参数 | ffuf | 小字典、软 404 过滤 |
| 模板扫描 | nuclei | 只用 info/exposure/misconfig 类，排除 intrusive |
| SQL 验证 | sqlmap | `--risk 1 --level 1`，禁文件/命令/导出 |
| 语义 SAST | opengrep | 规则集按栈收窄 |
| 结构模式 | ast-grep / tree-sitter | 只做定位，不做利用 |
| 秘密 | gitleaks + trufflehog | 历史 + 工作树 |
| 依赖/配置 | trivy fs / syft / grype | 记录库龄与 SBOM |
| 回归验证 | hurl | 把「已修复」写成可重放断言 |
| 差分测试 | hypothesis 风格 | 从不变式出发，可复现最小反例 |
| 沙箱代理自动化 | （不采用） | 依赖运行时且引入网络/凭据面，与零依赖本地插件冲突 |
| 浏览器自动化 | （不采用） | 本插件无浏览器工具；只吸收「先取外部状态再判定」的思路 |

### 7.3 侦察与基础设施生命周期

- **资产测绘**：证书透明度（CT）→ SAN/CN → 被动 DNS → ASN/IP 段 → 迭代种子扩展（从已知资产再推导）。
- **基础设施生命周期**：先画「信任消费者图」（谁信任这个域名/包/证书/邮件记录），再判「可声明性等级」（可注册/可接管/可伪造/已保留）；重点类：更新与代码分发、命名与包解析、邮件与身份、遥测与控制面。
- **迁移要点**：把「悬空记录 + 可声明资源」作为子域接管的核心判据（§1 #26），不要只看 CNAME。

### 7.4 扫描深度选择

| 模式 | 适用 | 覆盖策略 | 预算 |
|---|---|---|---|
| quick | 时间紧、先看高价值面 | 指纹 + 高影响入口 + 单点验证 | 低（一次预算内） |
| standard | 常规评估 | 侦察 → 业务逻辑 → 系统类目 → 验证 | 中 |
| deep | 重要目标、允许长窗口 | 全量侦察 + 链式利用 + 持续测试 | 高（需显式授权） |
| diff | PR/变更审查 | 只看变更文件 + 受影响调用面 | 低（按变更集） |

- 四模式共用同一门禁与产物格式；深度只改变覆盖面，不改变「最小影响/不持久化」底线。

## 8. 与现有参考的分工

| 需要 | 加载 |
|---|---|
| 工具参数、各族禁令与 dry-run 默认 | `references/red/tool-recipes.md` |
| web/api 类目判定与误报列 | `references/red/discover-web-api.md` |
| 云/容器姿态评估口径 | `references/red/discover-cloud-container.md` |
| 身份/供应链评估口径 | `references/red/discover-identity-ad.md` |
| 证据字段与分级 | `references/shared/evidence-standards.md` |
| 关闭纪律/定级/修复验证 | `references/shared/finding-review.md` |
| 本篇 | 30 类决策表、框架/协议/云特化、源码感知、SCA 与工具选取 |

单次加载 ≤3 篇、合计 ≤120 KiB；本篇不替代 `dsh-red-discover` 的类目清单，而是其「按技术栈深挖」的补充层。
