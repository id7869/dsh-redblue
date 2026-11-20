<!-- dsh-redblue:provenance
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: Skills/active-directory/offensive-active-directory/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 合并 AD/netexec/oauth/jwt/cicd/supply-chain/initial-access 七类身份与供应链内容，改为只读姿态评估，删除中继/转储/投递链
-->

# 身份、AD 与供应链发现判定清单（discover-identity-ad）

> 定位：`dsh-red-discover` 的 ad/auth/cicd/supply-chain 类目判定依据。只做**只读姿态评估**：枚举、读取配置、比对基线；不做凭据转储、不做中继、不做投递。
> 主要上游：Claude-Red `active-directory/offensive-active-directory`、`active-directory/offensive-netexec`、`auth/offensive-jwt`、`auth/offensive-oauth`、`cicd/offensive-cicd-pipeline`、`cicd/offensive-cicd-secrets`、`supply-chain/offensive-dependency-confusion`、`supply-chain/offensive-supply-chain`、`infrastructure/offensive-initial-access`（仅检测视角）。
> 消费者：`dsh-red-discover`、`dsh-red-post`（可达性评估）、`dsh-purple-verify`（身份侧覆盖）。

## 1. 只读边界（先读再动）

| 允许 | 禁止 |
|---|---|
| 目录查询（LDAP/SAMR）、组与 ACL 读取 | 凭据转储（LSA/SAM/NTDS）、票据伪造 |
| Kerberos 相关**配置**枚举（SPN、委派、策略） | 请求可离线破解的票据、喷洒口令 |
| 证书服务模板枚举（`certipy find`） | 申请/滥用证书、中继认证 |
| 会话与登录策略读取 | 会话劫持、令牌窃取 |
| CI 配置与依赖清单静态阅读 | 篡改流水线、污染依赖、投递恶意包 |
| 供应链元数据（SBOM、签名、来源） | 伪造签名、劫持构建 |

一旦发现可离线破解材料（哈希、票据、私钥），**不复制、不落盘**，只记录「存在可得性」与位置，转 `dsh-red-post` 做影响评估。

## 2. AD 姿态枚举（只读）

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 目录与信任关系（只读采集；不改对象、不写 ACL）
ldapsearch -x -H ldap://192.0.2.10 -s base -b "" "(objectclass=*)" defaultNamingContext
ldapsearch -x -H ldap://192.0.2.10 -D "<BIND_DN>" -w "<PASSWORD>" -b "<BASE_DN>" "(objectClass=group)" cn
# 密码策略与登录限制（SMB 只读查询）
nxc smb 192.0.2.10 -u <USER> -p <PASSWORD> --pass-pol
# BloodHound 采集（只读；输出到 workDir）
bloodhound-python -d example.com -u <USER> -p <PASSWORD> -ns 192.0.2.10 -c All
```

判定要点（每条都可写成候选）：

| 检查 | 判定信号 | 风险表述 |
|---|---|---|
| 域/林信任 | 存在双向或宽松信任、SID 过滤关闭 | 跨域提权路径 |
| 特权组规模 | Domain Admins/Enterprise Admins 人数过多 | 权限过度集中 |
| ACL 异常 | 普通用户对高权对象有 `GenericAll/WriteDacl/WriteOwner` | 可提权路径 |
| Kerberos 配置 | 存在可 Kerberoast 的服务账号（SPN 多、口令策略弱） | 离线口令风险 |
| 委派 | 非约束委派主机、协议转换 | 身份冒用路径 |
| ADCS | 模板允许 enrollee supplies subject、无审批、HTTP 注册端点 | 证书滥用路径 |
| 会话暴露 | 高权账号登录低权主机 | 凭据暴露面 |
| 保护措施 | 未启用 LAPS、Credential Guard、Protected Users | 横向成本低 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# ADCS 模板枚举（只读，输出漏洞模板清单）
certipy find -u <USER>@example.com -p <PASSWORD> -dc-ip 192.0.2.10 -vulnerable -stdout
```

## 3. 身份协议（OIDC / OAuth / JWT / SAML）

| 检查 | 判定信号 | 只读验证 |
|---|---|---|
| `redirect_uri` 校验 | 接受保留域或通配子域 | 用保留域构造回调观察是否被接受 |
| `state` / PKCE | 缺失或未绑定 | 观察授权码流程是否强制 |
| 令牌校验 | `alg` 接受 `none`、未校验 `aud/iss/exp` | 用过期/错误受众令牌观察拒绝行为 |
| 刷新与撤销 | 刷新令牌长期有效、无撤销端点 | 观察是否可重复使用（不实际滥用） |
| 设备码流程 | 缺少用户确认或速率限制 | 观察提示与限制 |
| SAML | 未验签、受众/时效未校验 | 只读检查配置与元数据 |
| 作用域 | 过宽 scope、缺最小权限 | 对比应用申请与实需 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 令牌声明只读解码（不验证签名、不修改令牌）
curl -sS -H "Authorization: Bearer <TOKEN>" https://app.example.com/api/v1/me -o me.json
jq -r '.sub, .aud, .iss, .exp' <(cut -d. -f2 <(printf '%s' "<TOKEN>") | base64 -d 2>/dev/null) 2>/dev/null || true
```

令牌原文不落盘：只保留脱敏后声明字段与判定结论。

## 4. CI/CD 与供应链

| 检查 | 判定信号 | 只读手段 |
|---|---|---|
| 流水线权限 | `pull_request_target` + 检出不可信代码、宽泛 token 权限 | 静态阅读 workflow 文件 |
| 密钥管理 | 明文密钥、长期云密钥、无 OIDC 联合 | 静态扫描 + 密钥扫描报告 |
| 依赖混淆 | 内部包名在公共源可注册/可发布 | 比对内部包清单与公共源（只读查询） |
| 依赖完整性 | 无 lockfile、无 hash 校验、版本漂移 | 清单比对 |
| 制品来源 | 未签名制品、无 provenance | `cosign verify`、SLSA 元数据 |
| 构建隔离 | 共享 runner、缓存跨项目复用 | 配置阅读 |
| Action/插件固定 | 使用 `@main` 等浮动引用 | 逐条检查引用形式 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 本地仓库密钥扫描（离线，报告写 workDir）
gitleaks detect --source . --report-format json --report-path gitleaks.json --no-banner
# 依赖清单与 SBOM（离线）
syft dir:. -o cyclonedx-json=sbom.json
```

CI 类候选的证据要求：给出**具体行号/文件路径 + 配置片段 + 影响链一句话**，不接受「配置不规范」这种泛化结论。

## 5. 初始访问面（只判检测视角，不给投递链）

| 面 | 判定信号 | 只读验证 |
|---|---|---|
| 邮件认证 | SPF/DKIM/DMARC 缺失或 `p=none` | DNS TXT 只读查询 |
| 外部暴露的登录面 | 无 MFA、无速率限制、无异常登录告警 | 配置与策略阅读 |
| VPN/远程接入 | 旧协议、无证书绑定、共享账号 | 配置阅读 |
| 第三方集成 | 过宽 OAuth 授权、长期令牌 | 授权清单比对 |
| 物理/近场 | 未授权 USB/蓝牙外设策略缺失 | 策略阅读 |

不写钓鱼话术、不写投递步骤、不准备诱饵文件；此表只为「蓝队是否有可见性」与「红队是否可评估」提供判定点。

## 6. 身份侧检测视角（供 purple/report）

| 风险类别 | 遥测 | 典型检测点 |
|---|---|---|
| 目录枚举 | 域控 4662/5136、LDAP 查询日志 | 短时大量对象读取、异常 bind |
| ACL 篡改 | 5136、AD 审计 | 高权对象 ACL 变更 |
| 证书滥用 | ADCS 日志、4768/4769 | 异常模板申请、无审批签发 |
| Kerberos 异常 | 4769、4624/4625 | 大量 SPN 请求、异常加密类型 |
| 令牌异常 | IdP 日志 | `aud/iss` 异常、异常 IP 刷新 |
| CI 滥用 | 流水线运行日志、SCM 审计 | 权限变更、密钥新增、制品未签名 |
| 依赖投递 | 包管理器审计、构建日志 | 新包首次出现、版本突变 |

## 7. 候选断言字段（身份版）

| 字段 | 说明 |
|---|---|
| `category` | `ad-acl` / `ad-kerberos` / `ad-cs` / `identity-oauth` / `identity-jwt` / `cicd` / `supply-chain` |
| `claim` | 「谁 → 对什么 → 能做什么」的可判定句式 |
| `observed` | 对象 DN/组名/模板名（脱敏用户名为角色名） |
| `attack` | T1078、T1558、T1649（证书）、T1195（供应链）等 |
| `evidenceRefs` | 查询命令 + 输出片段哈希 |
| `limitations` | 未覆盖域、缺失审计、权限不足 |

## 8. 禁止事项与反模式

- 禁止：凭据转储、票据请求后离线破解、口令喷洒、NTLM 中继、证书申请滥用、会话劫持。
- 禁止：修改目录对象、组、ACL、模板、CI 配置、依赖清单。
- 禁止：投递恶意包/镜像、污染构建缓存、篡改制品。
- 禁止输出可复制的凭据材料（哈希、票据、私钥、NTLM 响应）。
- 反模式：把「发现 SPN」直接等同于「可提权」；把 BloodHound 图直接当结论；把公网包名可注册当已投递。