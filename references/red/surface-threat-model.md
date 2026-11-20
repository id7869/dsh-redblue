<!-- dsh-redblue:provenance
source-repo: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
source-commit: 54a798831d2266a3ca61ce68a7acb80b81160d57
source-license: Apache-2.0
source-path: skills/implementing-attack-surface-management/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 合并 ACS 攻击面与 MITRE ATT&CK 威胁建模、Threat Dragon 方法，改写为 asset→边界→入口→假设的可验证流水线
-->

# 攻击面与威胁假设建模（surface-threat-model）

> 定位：红队 lane 第 3 步。把 `recon.json` 的资产清单变成**可验证的威胁假设**，并排优先级；本步不下漏洞结论。
> 主要上游：ACS `implementing-attack-surface-management`、`implementing-threat-modeling-with-mitre-attack`、`performing-threat-modeling-with-owasp-threat-dragon`；Claude-Red `Skills/network/`（L2/L3 位置与信任边界，仅保留建模视角）。
> 消费者：`dsh-red-surface`、`surface` 阶段、`dsh-red-discover`（按假设分配类目）。
> 版本时效：优先级模型与 ATT&CK 映射以 2026-11-19 复核为准；ATT&CK 技术与检测覆盖随版本更新，引用前核对当前版本。

## 1. 输入契约

- `recon.json.assets[]`：只接受 `confidence ∈ {confirmed, likely}` 的资产进入建模；`possible` 只作为背景。
- `recon.json.limitations`：未探活、未覆盖类目必须继承进 `surface.json`，不得在建模时「消失」。
- scope：`targets[]` 与 `exclusions[]` 是边界：排除项即使出现在资产清单里也不建模。
- 已有 `surface.json`（增量运行）时先读旧假设，保留 id 并追加新假设，不重排。

## 2. 五步流水线

1. **资产归一**：按 `kind` 聚类（域名/URL/IP/仓库/桶/移动端/证书），合并同一实体多来源。
2. **划信任边界**：标出「谁信任谁」。边界至少覆盖：互联网→边缘、边缘→应用、应用→数据、应用→第三方、办公网→生产、容器→宿主、租户→租户。
3. **列入口点**：每个边界上列出可被外部触达的入口（登录、上传、回调、Webhook、管理口、API、CI runner、消息队列、DNS 委托）。
4. **写威胁假设**：每条假设一句「若…则…」，绑定 ATT&CK 技术，写明需要的证据。
5. **排优先级**：按 §4 的四因子打分，同分按「能否最快被 validate 判真伪」排序。

## 3. 假设字段（`surface.json.hypotheses[]`）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `id` | string | 是 | `th_<序号>`，增量运行保持不变 |
| `title` | string | 是 | 一句话假设（≤120 字符） |
| `entryPoint` | string | 是 | 具体入口（URL/主机:端口/仓库路径/队列名） |
| `trustBoundary` | string | 是 | 跨越的边界（如「互联网→边缘 WAF」） |
| `preconditions` | string[] | 否 | 成立所需条件（凭据类型、网络位置、租户角色） |
| `attackIds[]` | string[] | 是 | ATT&CK 技术 ID（`Txxxx` 或 `Txxxx.yyy`），至少 1 个 |
| `dataFlow` | string | 否 | 数据从哪到哪（含存储落点） |
| `validationPlan` | string | 是 | 如何判真伪（哪类观察、用什么证据） |
| `priority` | enum | 是 | `P1/P2/P3`（见 §4） |
| `rationale` | string | 是 | 为什么值得先测（结合可达性/影响/覆盖） |
| `status` | enum | 是 | `open/validated/refuted/deferred` |
| `evidenceRefs` | string[] | 否 | 支撑该假设的 recon 资产或证据 id |

`validationPlan` 是硬门槛：写不出「若观察到 X 则成立」的假设，降级为 `P3` 或不写。

## 4. 优先级模型（四因子，各 0–3 分）

| 因子 | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| 可达性 | 需内网+凭据 | 需内网 | 公网但需认证 | 公网匿名可达 |
| 影响 | 信息性 | 低（局部信息） | 中（越权读/配置） | 高（执行/管理面/批量数据） |
| 数据敏感度 | 公开 | 内部 | 机密 | 受监管（个人/支付/健康） |
| 检测与防护 | 有 WAF+EDR+告警 | 有其一 | 弱防护 | 无可见防护 |

- 总分 9–12 → `P1`；5–8 → `P2`；0–4 → `P3`。
- 任一项为 3 且影响为 3 → 强制 `P1`（例如公网匿名可达的管理接口）。
- 打分必须写进 `rationale`（如「可达 3/影响 3/数据 2/防护 1 → P1」），禁止只给结论。

## 5. 边界清单（按环境类型）

| 环境 | 必查边界 | 典型入口 |
|---|---|---|
| Web/API | 互联网→边缘→应用→数据 | 登录、注册、上传、回调、Webhook、GraphQL、管理后台 |
| 云（IaaS/PaaS） | 租户→资源、CI→生产、跨账号信任 | 元数据服务、对象存储、函数触发器、IAM 角色链 |
| 容器/K8s | 容器→宿主、命名空间→命名空间、CI→集群 | kubelet、API server、ServiceAccount、admission webhook |
| 身份/AD | 用户→域、域→域（信任）、应用→目录 | LDAP、Kerberos、证书服务、同步账号 |
| 网络（L2/L3） | 接入层→核心、VLAN→VLAN、访客→办公 | 802.1X、DHCP、DNS、路由协议、无线 SSID |
| OT/ICS | IT→OT DMZ、现场网→控制网 |  Historian、HMI、PLC 编程口、远程维护通道 |
| 移动/IoT | App→后端、设备→云、配网→账号 | 深度链接、证书固定、MQTT、配网协议 |
| 供应链 | 上游包→构建→发布 | 依赖源、CI 凭据、制品仓库、签名环节 |

## 6. ATT&CK 映射纪律

- 只映射到**技术/子技术**，不映射到战术层当结论；子技术（`Txxxx.yyy`）需有具体证据支撑，否则用父技术。
- 一条假设可对应多个技术，但必须有一个「主技术」写进 `attackIds[0]`。
- 引用格式：`https://attack.mitre.org/techniques/T1190/`（权威域，可出现在报告）。
- 不得用 ATT&CK 编号替代判定：编号只表达「这类行为」，成立与否由 `validationPlan` 决定。
- 与检测侧对齐时，把 `attackIds` 交给 `dsh-purple-verify` 做覆盖矩阵，不在本步评估检测覆盖。

## 7. 输出（`surface.json`）

```json
{
  "schemaVersion": "dsh-redblue-surface/v1",
  "runId": "rb_20261119T055500Z_1a2b",
  "hypotheses": [
    {
      "id": "th_1",
      "title": "边缘 WAF 后的管理接口可被匿名枚举",
      "entryPoint": "https://app.example.com/admin",
      "trustBoundary": "互联网→边缘",
      "preconditions": ["无"],
      "attackIds": ["T1190"],
      "validationPlan": "若匿名请求返回 200 且页面含管理菜单则成立；403/302 到登录则否",
      "priority": "P1",
      "rationale": "可达 3/影响 3/数据 2/防护 1 → P1",
      "status": "open"
    }
  ],
  "boundaries": ["互联网→边缘", "边缘→应用", "应用→数据"],
  "limitations": ["未做主动探活，管理口可达性待 validate 复核"]
}
```

## 8. 与下游的接口

- `dsh-red-discover`：按 `hypotheses[]` 的 `entryPoint` 与 `attackIds` 选择类目（web/api/cloud/container/ad/ot/mobile/wireless），每条候选断言必须回指一个 `hypothesisId`。
- `dsh-red-validate`：按 `validationPlan` 判真伪，`status` 回写 `validated/refuted`。
- `dsh-purple-verify`：用 `attackIds` 做覆盖矩阵，用于定位检测缺口。
- `dsh-rb-report`：报告 §3 引用 `boundaries` 与 `techniques` 覆盖状态。

## 9. 反模式（出现即退回重做）

- 把扫描器输出清单当威胁模型（没有边界、没有假设）。
- 把 CVE 列表当攻击面（版本号 ≠ 可利用）。
- 假设写成「可能存在漏洞」——不可判真伪。
- 跳过信任边界直接列入口点，导致优先级全靠感觉。
- 用「全部资产都重要」回避排序。
- 把未授权资产（CNAME 到第三方、CDN 边缘）建模为入口。
- 引用真实客户拓扑或内网主机名（脱敏为角色名，如「办公网→生产」）。