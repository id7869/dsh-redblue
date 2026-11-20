<!-- dsh-redblue:provenance
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: Skills/iot/offensive-iot/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 合并 Claude-Red iot/mobile/network 三篇与 ACS OT 评估类技能，保留固件与移动端静态分析口径，删除现场破坏性操作与绕过后门
-->

# OT / 移动 / IoT 发现判定清单（discover-ot-mobile-iot）

> 定位：`dsh-red-discover` 的 ot/mobile/iot 类目判定依据。**安全优先**：OT 侧默认只被动观察；移动与 IoT 侧以静态分析为主，动态分析只在授权测试设备上进行。
> 主要上游：Claude-Red `iot/offensive-iot`、`mobile/offensive-mobile`、`network/offensive-network-attacks`（只取分段与可见性判定）；ACS OT 类目择优（`performing-ot-network-security-assessment`、`performing-ics-asset-discovery-with-claroty`、`implementing-network-segmentation-for-ot`、`performing-plc-firmware-security-analysis` 等）。
> 消费者：`dsh-red-discover`、`dsh-red-post`（可达性）、`dsh-rb-report`（安全影响说明）。
> 版本时效：协议字段与工具参数以 2026-11-19 复核为准；固件与 App 会随版本更新，结论需标注所测版本。

## 1. 安全第一（OT/ICS 特有）

| 规则 | 说明 |
|---|---|
| 默认被动 | 只读 PCAP、只读导出、只读配置；不主动扫描、不探测 PLC/HMI 端口 |
| 不写寄存器 | 禁止读写线圈/寄存器、禁止下发控制命令、禁止改设定值 |
| 不打断 | 任何可能导致 PLC 重连、超时、重启的动作都不做 |
| 时间窗限制 | 只在工艺允许的维护窗口内做，且需授权方现场确认 |
| 影响优先 | 一旦观察到工艺参数波动，立即停止并通知（`policy/authorization.md` §6） |

需要主动探测才能推进的结论 → 写 `deferred`，交授权方与其自动化团队评估。

## 2. OT 资产与分段（只读）

| 检查 | 只读手段 | 判定信号 | 风险表述 |
|---|---|---|---|
| 资产清单 | 只读 PCAP / 现有资产库导出 | 未知设备、无资产台账 | 影子资产 |
| 协议识别 | PCAP 分析（Modbus/DNP3/S7comm/BACnet/OPC-UA） | 明文无认证协议、功能码越界 | 协议无认证 |
| 分段 | 路由/ACL 导出、Purdue 模型比对 | IT 直连控制网、无 DMZ | 分段缺失 |
| 远程维护 | 配置阅读 | 永久 VPN、共享账号、无 MFA | 远程通道风险 |
| 补丁与固件 | 版本清单比对 | 过期固件、停服组件 | 已知缺陷面 |
| 日志可见性 | SIEM 接入清单 | OT 网段无遥测 | 检测盲区 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 离线 PCAP 的协议与端点统计（不产生任何网络流量）
tshark -r ot-capture.pcap -q -z io,phs
tshark -r ot-capture.pcap -Y "modbus || dnp3 || s7comm || bacnet" -T fields -e ip.src -e ip.dst -e _ws.col.Protocol | head -50
```

## 3. IoT / 嵌入式（静态优先）

| 阶段 | 手段 | 判定信号 | 边界 |
|---|---|---|---|
| 固件获取 | 厂商下载、OTA 包、授权只读转储 | 无签名校验、明文 OTA | 只在授权设备上做 |
| 固件解包 | `binwalk -Me`、`file`、熵分析 | 可写文件系统、硬编码凭据 | 不执行固件内二进制 |
| 凭据与密钥 | `strings` + 规则匹配（只记类型/位置） | 硬编码口令、私钥、云令牌 | 原文不落盘 |
| 服务面 | 配置/证书/默认端口阅读 | 默认口令、调试接口、Telnet | 不爆破、不登录 |
| 无线协议 | 只读嗅探（Zigbee/BLE/Z-Wave/LoRa/Sub-GHz） | 明文配对、固定密钥、无重放保护 | 不注入、不重放 |
| 云对接 | 移动端配置与流量阅读 | 共享 MQTT 凭据、无设备身份 | 不订阅他人主题 |
| 物理接口 | UART/JTAG/SWD 识别（现场授权） | 调试控制台开放、无读保护 | 不刷写、不短接 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 固件静态分析（离线，不执行目标代码）
file firmware.bin
binwalk firmware.bin
binwalk -Me firmware.bin -C firmware-out
strings -n 6 firmware.bin | grep -iE 'passwd|secret|token|api|mqtt|ssid' | head -40
```

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# MQTT 只读订阅（仅授权 broker，限定主题前缀与条数）
mosquitto_sub -h mqtt.example.com -t 'site/<SITE>/#' -C 20 -W 15 -v
```

`strings` 命中的疑似凭据只保留「类型 + 偏移 + 前后各 4 字符」，用于报告引用，不复制原文。

## 4. 移动应用（Android / iOS）

| 检查 | 手段 | 判定信号 | 边界 |
|---|---|---|---|
| 组件暴露 | `apktool d`、`jadx` 静态阅读 | 导出组件无权限、Intent 重定向 | 不实际调用生产接口 |
| 深度链接 | 清单/配置阅读 | 未校验 host/scheme、可被任意应用唤起 | 只读验证 |
| 数据存储 | 静态阅读 + 授权测试机检查 | 明文令牌、外部存储、备份允许 | 不读真实用户数据 |
| 传输安全 | 静态阅读 | 明文 HTTP、证书固定缺失/可绕过 | 不做中间人劫持生产 |
| 凭据与密钥 | 静态阅读 | 硬编码密钥、云服务凭据 | 原文脱敏 |
| 后端配置 | 静态阅读 | 测试环境地址、调试开关 | 不访问非授权环境 |
| 动态分析 | `frida`/`objection`（授权测试机） | 运行时校验、绕过点 | 只在测试机、只读 hook |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 静态反编译（离线；输出到 workDir，避免污染仓库）
apktool d app-release.apk -o app-decoded --no-src
jadx -d app-src --no-res app-release.apk
# 清单关键项（导出组件、权限、深链）
grep -nE 'android:exported|intent-filter|uses-permission|scheme' app-decoded/AndroidManifest.xml | head -40
```

动态分析前置：使用授权方提供的测试机/模拟器与测试账号；不安装到生产用户设备；hook 只用于观察，不改业务数据。

## 5. 网络层边界（只判定，不投毒）

| 检查 | 只读手段 | 判定信号 |
|---|---|---|
| 接入认证 | 交换机/无线控制器配置阅读 | 无 802.1X、MAC 白名单可绕过 |
| 分段 | VLAN/ACL 导出 | 访客与办公同段、控制网与办公直通 |
| 名称解析信任 | 配置阅读 | 依赖 LLMNR/NBT-NS、无 DNSSEC |
| 广播域暴露 | 只读 PCAP | 明文协议凭据、可嗅探服务通告 |

MITM、投毒、中继、去认证等动作属于利用档，本清单不提供命令；只在 `dsh-red-exploit`（`mode≥exploit` + `confirm`）中按最小影响原则评估。

## 6. 检测视角（供 purple/report）

| 类别 | 遥测 | 检测点 |
|---|---|---|
| OT 异常 | 工控防火墙/IDS、PLC 日志 | 未授权功能码、异常写入、非工作时段操作 |
| 固件/设备 | 设备管理平台 | 固件版本突变、调试接口开启 |
| 移动端 | 后端 API 日志、App 完整性 | 异常设备指纹、深链滥用、证书固定失败 |
| 无线 | WIDS/WIPS | 非法 AP、去认证风暴、异常探针 |
| IoT 云 | Broker/云平台日志 | 异常订阅、共享凭据多源使用 |

## 7. 候选断言字段（OT/移动/IoT 版）

| 字段 | 说明 |
|---|---|
| `category` | `ot-segmentation` / `ot-protocol` / `iot-firmware` / `iot-credential` / `mobile-storage` / `mobile-component` / `mobile-transport` / `wireless-config` |
| `claim` | 具体事实 + 影响（例：固件内硬编码 MQTT 口令，同一批设备共用） |
| `observed` | 脱敏后的位置（偏移/文件/组件名）与类型 |
| `attack` | T0840（OT 网络连接）、T0886（远程服务）、T1402（移动端）等按 ATT&CK/ICS 对应 |
| `evidenceRefs` | 静态输出片段 + 文件哈希 |
| `limitations` | 未做动态验证、未覆盖设备型号、无现场权限 |

## 8. 禁止事项与反模式

- 禁止：对 PLC/HMI/RTU 主动扫描、写寄存器、下发控制命令、重启设备。
- 禁止：刷写固件、短接/改板、拆机（除非授权方书面同意并有现场人员）。
- 禁止：安装到真实用户设备、读取真实用户数据、把 App 上传第三方平台。
- 禁止：无线注入/去认证/仿冒 AP、重放、破解口令。
- 禁止：订阅非授权 MQTT 主题、访问非授权云环境。
- 反模式：把固件里的字符串直接当可用口令；把「MQTT 无 TLS」直接当可劫持；把 OT 设备指纹当已知漏洞。