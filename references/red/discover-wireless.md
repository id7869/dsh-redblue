<!-- dsh-redblue:provenance
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: Skills/wireless/offensive-wifi-recon/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 合并 wireless 14 篇，保留空口测绘/频段/加密与协议判定与证据口径，删除去认证/仿冒/破解等主动攻击
-->

# 无线空口发现判定清单（discover-wireless）

> 定位：`dsh-red-discover` 的 wireless 类目判定依据。默认**被动空口测绘**；任何注入、去认证、仿冒、破解动作都不在本清单范围。
> 主要上游：Claude-Red `wireless/offensive-wifi-recon`、`wireless/offensive-wifi`、`wireless/offensive-bluetooth-ble`、`wireless/offensive-bluetooth-classic`、`wireless/offensive-krack-fragattacks`、`wireless/offensive-wpa-enterprise`、`wireless/offensive-wpa2-psk`、`wireless/offensive-wpa3-sae`、`wireless/offensive-wps`、`wireless/offensive-deauth-disassoc`、`wireless/offensive-evil-twin`、`wireless/offensive-zigbee-thread-matter`、`wireless/offensive-z-wave`、`wireless/offensive-lorawan-sub-ghz`（均只保留判定与检测视角）；ACS `conducting-wireless-network-penetration-test`。
> 消费者：`dsh-red-discover`、`dsh-rb-report`、`dsh-purple-verify`。
> 版本时效：空口参数与工具行为以 2026-11-19 复核为准；驱动与固件版本会改变监听/解码表现，执行前核对。

## 1. 前置与合法边界

| 项 | 要求 |
|---|---|
| 授权 | `written`，并写明**物理位置**与时段（射频测试必须现场/近场授权） |
| 频段合规 | 遵守当地法规与 `iw reg get` 的管制域；不越权使用受限频段/功率 |
| 适配器 | 支持监听模式；注入能力只在授权明确允许时启用 |
| 不干扰 | 不发送管理帧、不做去认证、不做仿冒 AP、不做拒绝服务 |
| 数据 | 只记录 BSSID/SSID/加密类型等元数据；不抓取用户业务流量内容 |

## 2. 空口测绘（被动）

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 适配器与监听能力自检
iw dev
iw list | grep -A 8 "Supported interface modes"
iw reg get
# 被动扫描：2.4/5/6 GHz 全频段写盘（pcap+csv）
sudo airodump-ng wlan0mon --band abg --write recon --output-format pcap,csv
```

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# 结构化空口清单（Kismet，可导出 CSV 供资产库比对）
sudo kismet -c wlan0mon
kismetdb_dump_devices --in capture.kismet --out devices.csv
```

判定字段：`BSSID / ESSID / 信道 / 频段 / 加密套件 / PMF（802.11w）/ WPS / 厂商 OUI / 首次与最后出现时间`。

## 3. Wi-Fi 判定要点

| 检查 | 判定信号 | 风险表述 | 备注 |
|---|---|---|---|
| 加密套件 | 开放、WEP、WPA-TKIP、WPA2-PSK | 弱加密/共享口令 | WPA3-SAE 视为较强 |
| PMF | 未启用 802.11w | 管理帧可被伪造 | 只判定，不验证 |
| WPS | 启用且 PIN 可达 | PIN 暴力风险 | 不尝试 PIN |
| 企业认证 | EAP 方法弱（LEAP/EAP-MD5）、无证书校验 | 凭据暴露面 | 不做 Evil Twin |
| 访客隔离 | 访客与内网同段 | 横向风险 | 配置/空口结合判定 |
| 隐藏 SSID | 仅隐藏不等于安全 | 安全假象 | 隐藏 SSID 仍可被动观察 |
|  rogue AP | 同 SSID 多 BSSID、异常 OUI | 仿冒风险 | 只记录，不连接 |
| 覆盖外溢 | 办公区外可收到信号 | 物理边界风险 | 现场记录位置 |

## 4. 蓝牙 / BLE

| 检查 | 判定信号 | 只读手段 |
|---|---|---|
| 可发现性 | 常开可发现、无配对要求 | `bluetoothctl --timeout 10 scan on` |
| 配对模式 | Just Works、无 MITM 保护 | 空口观察配对特征 |
| 服务暴露 | 暴露 GATT 写特征、无认证 | 只读枚举特征（不写入） |
| 经典蓝牙 | 旧版本、可配对无 PIN | 被动观察 |

禁止：配对劫持、密钥提取、重放、注入、批量连接。

## 5. Zigbee / Thread / Z-Wave / LoRa / Sub-GHz

| 协议 | 判定信号 | 只读手段 | 禁止 |
|---|---|---|---|
| Zigbee/Thread | 明文传输、默认信任中心密钥、允许入网 | 只读嗅探（授权信道） | 入网、发命令、重放 |
| Z-Wave | S0 配对、无 S2 | 只读嗅探 | 注入、破解读写 |
| LoRa/LoRaWAN | ABP 固定密钥、无帧计数校验 | 只读嗅探 | 伪造上行、拒绝服务 |
| Sub-GHz | 固定码、无滚动码 | `rtl_433 -f 433.92M -A` 只解码 | 重放、录制回放 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# Sub-GHz 只读解码（不发送）
rtl_433 -f 433.92M -A -F json -T 60
```

## 6. 证据字段（无线版）

| 字段 | 说明 |
|---|---|
| `commandSummary` | 采集命令 + 适配器 + 频段/信道 |
| `ts` | UTC 起止时间（空口采集按批次记录） |
| `outputPath` | `wireless/<capture>.pcap`、`<capture>.csv` |
| `sha256` / `bytes` | 采集文件哈希与大小 |
| `excerpt` | 关键行（BSSID 脱敏为 `aa:bb:…:01` 形式可保留可判定性） |
| `location` | 采集位置（楼层/房间号，按授权方要求脱敏） |

采集文件可能含第三方设备元数据：按 `dataHandling.retain` 最小化保留，交付前只保留与授权范围相关的行。

## 7. 检测视角（供 purple/report）

| 行为 | 遥测 | 检测点 |
|---|---|---|
| 空口测绘 | WIDS/WIPS | 监听模式设备、异常探针请求 |
| 去认证/仿冒 | WIDS | 管理帧异常、同 SSID 多 BSSID |
| 弱加密使用 | 控制器日志 | 关联到开放/WEP/PSK 的事件 |
| 蓝牙异常 | 终端/网关日志 | 异常配对、服务枚举 |
| Zigbee/ZWave 异常 | 网关日志 | 未授权入网、异常命令 |

## 8. 禁止事项与反模式

- 禁止：去认证/解关联、仿冒 AP（Evil Twin）、WPS PIN 尝试、握手抓取后离线破解、注入/重放。
- 禁止：连接真实用户设备、读取其流量内容、破解任意口令。
- 禁止在未获现场授权的区域做射频测试；禁止超出管制域功率与频段。
- 反模式：把「能收到信号」当「可攻破」；把 WPS 启用当「已破解」；把 WPA2-PSK 一律当高风险而不看口令策略与隔离。