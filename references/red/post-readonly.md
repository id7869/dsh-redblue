<!-- dsh-redblue:provenance
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: Skills/post-exploitation/offensive-lateral-movement/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 合并横向/提权/AD 三篇并只读化：提权改为项枚举信号、凭据改为可得性判定、横向改为可达性评估，删除持久化与转储配方
-->

# 后渗透只读评估（post-readonly）

> 定位：`dsh-red-post` 的判定依据。**报告-only**：只评估「能不能、代价多大、风险多高」，不执行提权、不抓凭据、不横向、不驻留。
> 主要上游：Claude-Red `post-exploitation/offensive-lateral-movement`、`privesc/offensive-linux-privesc`、`privesc/offensive-windows-privesc`、`active-directory/offensive-active-directory`、`active-directory/offensive-netexec`（均只保留枚举与判定，**不吸收** `offensive-persistence`、`offensive-c2-frameworks`、`offensive-data-exfiltration` 的配方）。
> 消费者：`dsh-red-post`、`post` workflow 的 post 阶段、`dsh-rb-report`、`dsh-purple-verify`。
> 版本时效：枚举项与判定信号以 2026-11-19 复核为准；OS 与补丁版本会改变信号含义，结论需标注所测版本。

## 1. 边界（先读再动）

| 允许 | 禁止 |
|---|---|
| 只读枚举本机/已授权主机的权限与配置 | 利用提权缺陷拿更高权限 |
| 判定凭据「是否存在、是否可读」 | 读取、复制、导出凭据内容 |
| 评估横向「协议可达 + 认证可用」 | 实际执行横向登录/远程执行 |
| 读取授权范围内的只读数据面 | 导出业务数据、建隧道、留后门 |
| 记录检测可见性 | 关闭/规避日志与告警 |

所有动作的默认等级是 `passive`（本地只读）或 `active`（已授权目标的只读枚举）；**不存在**「后渗透阶段可以顺手写」的例外。

## 2. 门禁

- `mode="post"`（G-CFM-03）；`confirm` 与精确目标归一化后完全相等（G-CFM-01/02）；`written` 授权（G-AUTH-03）。
- 前置输入：已验证 finding（`exploit` workflow 的 `dataSources`）或前序 post 结论；无输入不得凭空「评估提权」。
- `dryRun` 默认 true：只输出评估计划与只读枚举结果；如需把枚举下到目标主机，必须显式 `false` 且已在 scope 中声明主机。
- 任一动作若需要写目标（上传枚举脚本、改配置、建会话），先停下并改写为「建议由客户方执行」。

## 3. 权限提升评估（只枚举信号，不利用）

### 3.1 Linux/Unix

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 身份与 sudo 规则（只读）
id && uname -a
sudo -l 2>/dev/null
# 提权信号枚举：SUID/SGID、capabilities、可写关键路径
find / -perm -4000 -type f 2>/dev/null | head -50
getcap -r / 2>/dev/null | head -50
```

判定信号（每条都能写成候选）：

| 信号 | 风险表述 | 不做的动作 |
|---|---|---|
| `sudo -l` 允许某个可执行文件以 root 运行 | 提权路径存在 | 不实际执行该命令 |
| SUID 二进制可被滥用（GTFOBins 类） | 提权路径存在 | 不执行、不复制 |
| capability 异常（如 `cap_setuid`） | 提权路径 | 不利用 |
| 可写 cron/systemd/服务脚本 | 提权/持久化风险 | 不写入任何脚本 |
| 内核/内核模块版本过期 | 已知缺陷面（需核实） | 不加载模块、不编译 |
| 容器内特权/宿主挂载 | 逃逸前置条件 | 不执行逃逸 |

### 3.2 Windows

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```powershell
whoami /priv
whoami /groups
# 本地管理员组成员与服务配置（只读）
net localgroup administrators
Get-Service | Where-Object {$_.StartType -eq 'Auto'} | Select-Object -First 20 Name,Status
```

判定信号：`SeImpersonate*`/`SeAssignPrimaryToken*`（服务账号常见）、可写服务二进制路径、未加引号服务路径、AlwaysInstallElevated、可写 PATH 目录、UAC 级别、补丁缺失（需核实）。**只判定存在性，不做令牌冒用、不替换二进制、不触发安装器。**

## 4. 凭据可得性评估（只判「有没有、谁可读」）

| 位置 | 只读判定 | 禁止 |
|---|---|---|
| 配置文件/环境变量 | `ls -l`、权限位、键名（不打印值） | 输出值、复制文件 |
| SSH 私钥/known_hosts | 存在与权限（600/644） | 读取内容、使用私钥 |
| 浏览器/密码库/Keychain | 存在性 + 是否受保护 | 解密、导出 |
| 凭据管理/secret 存储 | 访问策略与角色绑定 | 读取 secret 值 |
| 内存/LSA/DPAPI | **不做**（属转储） | 任何转储动作 |
| 共享文件 | 共享名与权限（`--shares` 只读） | 遍历内容、下载 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 只读：本机凭据载体存在性与权限（不打印内容）
ls -l ~/.ssh 2>/dev/null
find / -maxdepth 3 -name '*.kdbx' -o -name 'id_rsa' 2>/dev/null | head -20
# 只读：SMB 共享枚举（仅授权主机）
nxc smb 192.0.2.10 -u <USER> -p <PASSWORD> --shares
```

结论写法：「存在可读的部署密钥（路径与权限），可导致横向」——不写密钥内容、不写哈希、不给可用材料。

## 5. 横向可达性评估（只判可达，不执行）

| 维度 | 只读判定 | 数据来源 |
|---|---|---|
| 网络可达 | 目标端口/协议是否可达（限授权主机，禁批量扫段） | 现有资产清单或单主机连接测试 |
| 认证可用 | 是否存在可用凭据类型（口令/证书/票据） | 凭据可得性结论（不复制材料） |
| 协议安全 | SMB 签名、LDAP 签名/通道绑定、NTLM 限制 | 只读查询配置 |
| 权限路径 | 本地管理员组、委派、ACL | AD 只读枚举 |
| 会话暴露 | 高权账号在低权主机登录 | 只读会话/登录记录 |
| 检测可见性 | 是否有登录/横向检测规则 | 蓝队规则清单比对 |

横向动作（远程执行、会话复用、隧道）**不在本技能范围**：只输出「路径 + 前提 + 影响 + 建议检测点」。若授权方要求验证，转入 `dsh-red-exploit`（`mode≥exploit` + 逐目标 `confirm`）并按最小影响阶梯执行。

## 6. 数据面与影响评估（不导出）

- 只判定「该权限下可访问什么类别」，不实际读取业务数据；需要证明时用「元数据/计数/表名」级证据。
- 影响分级：单用户数据 → 部门数据 → 全租户数据；每级写清「需要什么权限 + 是否需要额外步骤」。
- 任何个人数据一律不落盘；证据只保留字段名与类别。

## 7. 检测视角（供 purple/report）

| 行为 | 遥测 | 检测点 |
|---|---|---|
| 本机提权枚举 | 进程审计/EDR | `sudo -l`、SUID 枚举、`getcap` 批量调用 |
| 凭据载体访问 | 文件审计/EDR | 敏感路径访问、密钥文件读取 |
| 横向尝试 | 登录日志/EDR | 异常 NTLM/Kerberos、远程服务创建 |
| 会话异常 | IdP/DC 日志 | 同一账号多源登录、异常时段 |
| 权限变更 | AD/本机审计 | 组变更、服务修改 |

## 8. `post.json`

```json
{
  "schemaVersion": "dsh-redblue-post/v1",
  "runId": "rb_20261119T055500Z_1a2b",
  "confirmedTarget": "app.example.com",
  "paths": [
    {
      "from": "低权应用账号",
      "to": "本机 root",
      "technique": "T1548",
      "prerequisites": ["sudo 允许某二进制以 root 运行"],
      "credentialAvailability": "none-needed",
      "impact": "可读取本机全部配置（未验证，仅评估）",
      "evidenceRefs": ["ev_post_1_1"],
      "persistenceUsed": false
    }
  ],
  "limitations": ["未做提权验证（报告-only）", "未读取任何凭据内容"]
}
```

硬约束：`persistenceUsed` 必须为 `false`；`credentialAvailability` 只写 `none-needed`/`available-not-used`/`unknown`；`paths[]` 全部脱敏。

## 9. 停止条件与清理

- 停止条件同 `policy/authorization.md` §6；额外一条：一旦枚举动作可能导致服务重载/重启（如修改服务配置的只读尝试），立即停止。
- 清理：本阶段不应产生目标侧变更；若产生临时文件（枚举输出），删除并记录；本地临时文件按 `dataHandling` 处理。
- 结束前自检：无持久化、无凭据材料、无业务数据、无目标侧写入、`post.json` 全部脱敏。

## 10. 禁止事项（红线）

- 禁止：提权利用、令牌冒用、内核利用、容器逃逸。
- 禁止：凭据转储（LSA/SAM/NTDS/DPAPI/浏览器库）、票据请求后破解、口令喷洒。
- 禁止：持久化（账号/服务/计划任务/启动项/密钥/后门）、隧道/C2、数据外传。
- 禁止：横向登录与远程执行；禁止关闭或清理目标日志。
- 反模式：把「存在 SUID」直接写成「已 root」；把「共享可读」写成「数据已泄露」；把评估结论当已验证影响。