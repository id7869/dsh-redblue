# dsh-redblue 安装与运维手册（v0.2.0）

> 适用版本：`dsh-redblue 0.2.0`（Apache-2.0；含可选 REA 逆向 lane）
> 实测环境：Windows 11 + DeepSeek Harness Desktop `0.2.2-rc.5` + Node `v24.22.1` + `rea-agents 6.9.0`（可选）
> 实测时间：2026-11-20（v0.2.0 刷新安装）
> 本文所有“实测”段落为本机真实命令与输出；未实测的动作会明确标注“未实测”。

本文覆盖：**desktop profile 的 link 安装/刷新、安装验证、重启生效、可选 REA 逆向依赖、升级与回滚、跨 profile 逐个安装、故障排查、安全前置**。
能力总览见 [`README.md`](../README.md)，详情页正文见 [`DETAIL.md`](DETAIL.md)，架构见 [`architecture.md`](architecture.md)。

---

## 0. 安全前置（安装前必须确认）

dsh-redblue 是**授权**红/蓝/紫安全测试插件，默认 report-only（`dryRun=true`）。安装与使用前请确认：

1. **书面授权**：红队/紫队/triage 要求 `authorization.type="written"`；蓝队可用 `internal-mandate`。口头同意、聊天承诺、推定同意一律不构成授权。
2. **scope 是唯一授权载体**：目标、排除项、mode、时间窗、预算、数据处置都写在 `scope` 对象里；缺项、过期、越窗、越预算、全网段/通配目标一律拒绝（44 项 `G-*`）。
3. **默认不产生目标侧动作**：`dryRun=true` 时零发包；只有显式 `activeScan=true`（需 `mode≥active` 且 `dryRun=false`）或 `guard --execute`（需 written + mode + allowlist + `--confirm` 全等）才会触达目标。
4. **逆向 lane 默认只读**：`reverse` 工作流默认 `runtime=false`，只做本地制品静态分析；任何启动/附加/注入/调试目标进程的动作都要 `G-RT-01`（`mode≥active` 且 `dryRun=false`）+ `G-RT-02`（`confirm` 与唯一 source target 完全相等）。
5. **REA 是外部软件**：REA（Reverse Engineering Agent）由**宿主 MCP 注册**，不是插件依赖（不打包、不安装、不自动执行安装脚本）；其许可/权限/环境由使用者负责。
6. **证据包敏感**：reverse 的证据包可能包含样本片段/路径/寄存器等敏感内容（`deterministic=false`）；`retain=none` 时不导出。
7. **只安装到需要的 profile**：插件注册 16 个技能 + 10 个工作流；不需要的 profile（如 `qqbot`）不要安装。
8. **改动 profile 前先备份**：`package.json` 是 profile 的权威清单；升级/卸载/回滚都依赖它。
9. **数据处置固定**：`secrets="mask-and-redact"`、`destruction="none"`；插件不落原始凭据、不删除证据。
10. **本插件零网络**：除 `guard --execute` 执行授权配方外，技能/workflow/工具运行时均不联网；安装命令本身由 pnpm 执行（见 §3）。

---

## 1. 安装前检查

```bash
dsh --version          # 本机实测：0.2.2-rc.5
node --version         # 本机实测：v24.22.1
```

- DSH 桌面版已至少启动过一次，`C:/Users/<you>/.dsh/profiles/desktop/package.json` 已存在（Desktop 首次启动会初始化）。
- 插件源码目录已就位且版本正确：

```bash
cd C:/dsh-workspace/branch1/dsh-redblue
node -e "console.log(require('./package.json').version)"    # 期望 0.2.0
node --test test/scaffold.test.mjs                          # 期望 16/16
node tools/sanitize-lint.mjs --strict --json .              # 期望 0 blocker
```

- 可选：若要用 `reverse` 工作流，先确认 REA 是否已可用（见 §7）：

```bash
rea --version                       # 期望 6.9.0
rea doctor --client dsh --skill     # 期望 dsh=aligned；provider 缺口按 §7.4 降级
```

> 建议完全退出 Desktop（托盘 → 退出，而不是只关窗口）后再改 profile，避免与 HMR/profile 写入竞争。

---

## 2. 备份（回滚前提）

profile 目录：`C:/Users/<you>/.dsh/profiles/desktop`。

```bash
cd C:/Users/<you>/.dsh/profiles/desktop
cp -p package.json package.json.bak-dsh-redblue-v020-<YYYYMMDD-HHMMSS>
sha256sum package.json package.json.bak-dsh-redblue-v020-<YYYYMMDD-HHMMSS>
```

> `sha256sum` 为 Git Bash/MSYS 用法；PowerShell 用 `Get-FileHash -Algorithm SHA256 package.json`。

本机 v0.2.0 刷新时实际记录（2026-11-20）：

| 文件 | 大小 | SHA256 | 备份文件 |
|---|---|---|---|
| `package.json` | 1,192 B | `c49334cc1bc31f6d6845e9960a8fcf53d8fc24506286158a0682d751c8fc7add` | `package.json.bak-dsh-redblue-v020-20261120-170500` |
| `cordis.patch.yml` | 3,299 B | `6924dedb4a3b620490f248c4f4637b2687480651dc84fc3fcddd377bec9b84b9` | 安装/刷新前后未变，无需回滚 |

说明：安装命令只改 `package.json`（`dependencies` + `dsh.profile.bundles`）与 `node_modules`/`pnpm-lock.yaml`；**不会改** profile 的 `cordis.patch.yml`（REA 的 MCP 注册在 `~/.dsh/cordis.patch.yml`，不属于 profile，也不由本插件修改）。

---

## 3. Desktop link 安装 / 刷新（v0.2.0 实测）

```bash
dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue
```

本机 v0.2.0 刷新实测（2026-11-20 16:56）：

- **退出码 `0`**；`Done in 8.7s using pnpm v11.28.5`（DSH 安装自带的 pnpm；系统 `pnpm -v` 为 11.22.0，不作为执行路径）。
- 依赖已存在且仍是同一 link 时，pnpm 不再打印 `dependencies:` 汇总行；它仍会跑全量 lockfile 供应链校验（376 entries，7.3s）、重算 node_modules（`Packages: +1 -56`）并重试可选依赖构建。
- 可选依赖 `cpu-features`（ssh2 传递依赖）的 build script 失败并打印 `Failed`：该失败与 dsh-redblue 无关（插件零依赖、无 install script），pnpm 仍以 exit 0 结束。
- `dsh plugin` 的两步语义（已由 DSH 源码 `@deepseek-ai/dsh-plugin` 与 `@deepseek-ai/dsh-plugin-manager` 行为确认）：
  1. 在 profile 目录执行 pnpm（`link:` 依赖 → `node_modules/dsh-redblue` 是指向源码目录的符号链接，**不复制源码**）；
  2. 重新读取 profile 清单，对声明了 `dsh.bundle.patch` 的依赖确保其在 `dsh.profile.bundles` 中（本机 v0.2.0 刷新后仍在）。
- 首次全新安装时 pnpm 会打印 `+ dsh-redblue 0.2.0 <- ..\..\..\..\..\dsh-workspace\branch1\dsh-redblue`（格式按此前全新安装实录推断；本机 v0.2.0 为刷新安装，未走全新安装路径）。
- 如果安装失败（非 0 退出）：不要重试到成功为止，先按 §8 回滚，再按 §10 排查。

> **link 安装的版本显示口径（重要）**：pnpm 11 的 `dsh plugin list` 对 `link:` 依赖显示 `dsh-redblue@link:../../…`（link 目标），**不显示 0.2.0 版本号**。要确认版本，读链接解析后的 `package.json`（§4.3）。这是 pnpm 的显示行为，不代表安装失败。

---

## 4. 安装验证（5 层，v0.2.0 全部实测）

### 4.1 CLI 列表

```bash
dsh plugin --profile desktop list 2>&1 | grep -i dsh-redblue
```

实测输出（exit 0）：

```text
├── dsh-redblue@link:../../../../../dsh-workspace/branch1/dsh-redblue
```

列表末尾 `13 packages`。JSON 形态可看到 link 解析路径（不是版本）：

```bash
dsh plugin --profile desktop list --json 2>/dev/null \
  | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const j=JSON.parse(s);console.log(JSON.stringify(j[0].dependencies['dsh-redblue'],null,2))})"
# → { "from": "dsh-redblue", "version": "link:../../../../../dsh-workspace/branch1/dsh-redblue", "path": "C:\\dsh-workspace\\branch1\\dsh-redblue" }
```

### 4.2 profile 清单（dependencies + bundles 都必须在）

```bash
grep -n "dsh-redblue" C:/Users/<you>/.dsh/profiles/desktop/package.json
```

实测输出：

```text
14:    "dsh-redblue": "link:C:/dsh-workspace/branch1/dsh-redblue",
34:        "dsh-redblue",
```

- 第 14 行在 `dependencies`：证明 pnpm 包安装成功。
- 第 34 行在 `dsh.profile.bundles`：证明 Cordis 层已选中；缺任一条都不算装好。

### 4.3 版本解析（link 安装确认 0.2.0）

```bash
node -e "console.log(require(process.env.USERPROFILE+'/.dsh/profiles/desktop/node_modules/dsh-redblue/package.json').version)"
# 实测：0.2.0
node -e "console.log(require('./dsh-redblue/package.json').version)"
# 实测：0.2.0
```

### 4.4 provider 冒烟（证明 16 项技能可加载，含逆向技能）

```bash
node --input-type=module -e '
import { pathToFileURL } from "node:url";
const m = await import(pathToFileURL("C:/dsh-workspace/branch1/dsh-redblue/lib/index.js").href);
let f; m.apply({ skills: { registerProvider(x) { f = x; } } });
const p = f({ signal: new AbortController().signal, invalidate() {} });
const l = await p.list({});
console.log(m.name, JSON.stringify(m.inject), p.name, "count=" + l.length,
  "ranks=" + JSON.stringify([...new Set(l.map(s => s.rank))]),
  "reverse=" + l.some(s => s.name === "dsh-red-reverse"),
  l[0].name, "…", l.at(-1).name);
if (l.length !== 16) process.exit(1);
'
```

实测输出：

```text
dsh-redblue [ "skills" ] dsh-redblue count=16 ranks=[600] reverse=true dsh-rb-run … dsh-red-reverse
```

- `apply()` 只注册 1 个 provider，`inject=["skills"]`，rank 均为 600、`source="bundled"`。
- `dsh-red-reverse` 的 `resourceBase.path` 指向 `…/skills/red-reverse/`。

### 4.5 node_modules 符号链接指向源码

```bash
node -e "const fs=require('fs');const p=process.env.USERPROFILE+'/.dsh/profiles/desktop/node_modules/dsh-redblue';console.log(fs.existsSync(p),fs.lstatSync(p).isSymbolicLink(),fs.realpathSync(p))"
```

实测：`true true C:\dsh-workspace\branch1\dsh-redblue`。

### 4.6 REA 可用性（仅 reverse lane 需要，可选）

```bash
rea --version                        # 实测 6.9.0
rea doctor --client dsh --skill      # 本机 2026-11-20 实测 dsh=aligned
```

会话内确认 `mcp__rea__binary_session` 可见（REA 工具名前缀 `mcp__rea__`）。REA 不可用**不影响插件加载**，只影响 `reverse` 工作流（见 §7.5）。

### 4.7 运行会话观察（不作为生效证明）

安装/刷新后，运行中的 DSH 会话技能目录会热更新出 16 个 `dsh-*` 技能（本机实测已出现）。这只能说明 host 侧已读取到 bundle，**不能**替代 §5 的完整重启验证（Cordis patch 图层、工具面、插件详情页以重启后为准）。

---

## 5. 重启生效（必做）

1. 完全退出 Desktop：托盘图标 → 退出（确认进程结束）；只关闭窗口不算。
2. 重新启动 DeepSeek Harness Desktop。
3. 生效判定（三条都满足才算生效）：
   - 插件/设置页可看到 `dsh-redblue 0.2.0`（`docs/DETAIL.md` 为详情正文、`icon.svg` 为图标、`docs/preview.svg` 为预览图）；
   - 技能列表出现 16 个技能，包括新增的 `dsh-red-reverse`（以及 `dsh-rb-run` 入口）；
   - 在会话里说“红蓝对抗/授权渗透测试/威胁狩猎/紫队对齐/逆向分析/二进制分析”等触发词，能命中 `dsh-rb-run` / `dsh-red-reverse`。
4. 也可以在 Desktop 的插件管理器里查看/启停 `dsh-redblue`（它读写同一份 profile 清单；CLI 与 UI 以最后一次写入为准，改完同样需要重启才能完整生效）。
5. 若重启后仍不可见：回到 §8 回滚，再按 §10 排查；不要在未生效状态下去跑 workflow。

> 本手册不声称安装已在本机生效：§3–§4 只证明“包已安装、清单已选中、版本 0.2.0、provider 可解析 16 项”。完整生效以重启后为准。

---

## 6. 触发与首次使用

### 6.1 触发示例（均需已有授权）

| 意图 | 入口技能 | 对应 workflow |
|---|---|---|
| 授权红队评估（先建 scope） | `dsh-red-scope` → `dsh-rb-run` | `workflow/assess.js` |
| 被动信息收集 + 威胁假设 | `dsh-red-recon` + `dsh-red-surface` | `workflow/recon.js` |
| 候选漏洞独立复核与最小 PoC | `dsh-red-validate` | `workflow/assess.js`（validate 阶段） |
| 受控利用（需 `mode≥exploit`、`confirm`、`dryRun=false`） | `dsh-red-exploit` | `workflow/exploit.js` |
| 后渗透只读评估（需 `mode=post`、`confirm`） | `dsh-red-post` | `workflow/post.js` |
| 威胁狩猎（本地遥测） | `dsh-blue-hunt` | `workflow/hunt.js` |
| 事件响应与时间线 | `dsh-blue-dfir` | `workflow/ir.js` |
| 红蓝对齐/检测缺口 | `dsh-purple-verify` | `workflow/purple.js` |
| 外部 finding 复核入库 | `dsh-rb-triage` | `workflow/triage.js` |
| 加固基线核查与复测 | `dsh-blue-harden` | `workflow/harden.js` |
| 本地制品逆向/二进制分析（可选 REA） | `dsh-red-reverse` | `workflow/reverse.js` |

### 6.2 运行 workflow 的方式（原生 `workflow` 工具）

1. 读取 `C:/dsh-workspace/branch1/dsh-redblue/workflow/<script>.js` 全文；
2. 交给 DSH 原生 `workflow` 工具执行（脚本已含 `meta`：name/description/phases）；
3. `args` 传 `scope`（对象）、`workDir`（Windows 绝对路径）、`skillDir`（必须是 `<插件根>/skills`）、`maxConcurrency`（1–8）、`dryRun`（默认 true）；`exploit`/`post` 还要 `confirm`，`recon` 可选 `activeScan`，`reverse` 可选 `runtime`（默认 false）与 `confirm`；
4. 按返回对象 `status`/`exitCode` 转述，产物在 `workDir`。`reverse` 的 `maxConcurrency` 实现默认 **1**（1–8 可调）。

### 6.3 最小可用 scope（红队通用，已用 `scope check` 实测通过）

保存为 `C:/work/scope.json`（Windows 绝对路径、无 `..`）：

```json
{
  "authorization": {
    "type": "written",
    "reference": "ACME-RoE-2026-001",
    "grantedBy": "Security Office",
    "validFrom": "2026-11-01",
    "validTo": "2026-12-31"
  },
  "targets": [{ "kind": "domain", "value": "app.example.com", "label": "web" }],
  "exclusions": ["staging.app.example.com"],
  "mode": "passive",
  "window": { "start": "2026-11-20T00:00:00Z", "end": "2026-11-21T00:00:00Z" },
  "budget": { "maxRequests": 200, "maxMinutes": 60 },
  "dataHandling": { "retain": "findings-only", "secrets": "mask-and-redact", "destruction": "none" },
  "dataSources": [],
  "notes": "example only"
}
```

### 6.4 逆向 lane 的最小 scope（恰好一个 `kind="source"` 目标，已实测 `scope check` 通过）

```json
{
  "authorization": {
    "type": "written",
    "reference": "ACME-RE-2026-001",
    "grantedBy": "Security Office",
    "validFrom": "2026-11-01",
    "validTo": "2026-12-31"
  },
  "targets": [{ "kind": "source", "value": "C:/work/samples/app.exe", "label": "sample" }],
  "exclusions": [],
  "mode": "passive",
  "window": { "start": "2026-11-20T00:00:00Z", "end": "2026-11-21T00:00:00Z" },
  "budget": { "maxRequests": 50, "maxMinutes": 60 },
  "dataHandling": { "retain": "findings-only", "secrets": "mask-and-redact", "destruction": "none" },
  "dataSources": [],
  "notes": "reverse example"
}
```

自检：

```bash
cd C:/dsh-workspace/branch1/dsh-redblue
node tools/sec.mjs scope check --scope C:/work/scope.json
# 实测：{ "ok": true, "rejectedBy": [], "mode": "passive", ... }，exit 0
```

> **注意**：输入 scope 只接受九个白名单键（`authorization`/`targets`/`exclusions`/`mode`/`window`/`budget`/`dataHandling`/`dataSources`/`notes`），未知键 → `G-CONF-01`。
> `workDir/scope.json` 是 workflow 生成的产物，额外含 `schemaVersion`/`scopeDigest`/`validatedAt`；**不要把它当输入回灌**，否则同样触发 `G-CONF-01`（产物用于审计与复算，不是输入）。

### 6.5 产物与退出码

- 通用产物：`findings.json`、`coverage.json`、`report.md`、`exports/results.sarif`、`scan-manifest.json` + 阶段产物。
- `reverse` 另产 `reverse.json` 与 `evidence/rea-evidence.json`（REA 导出，`deterministic=false`，按 SHA256 封存）。
- 退出码：`0` 干净/计划、`2` 有 reportable、`1` 拒绝或错误；`reverse` 的 `blocked`（REA 不可用/目标不可读）也是 exit 1，但 `status="blocked"`、0 分析 agent、0 产物，并返回 `remediation`。

---

## 7. 可选 REA 逆向 lane 依赖

### 7.1 定位与版本

| 项 | 值 |
|---|---|
| 上游 | Reverse Engineering Agent（REA），`https://github.com/morluto/rea` |
| npm 包 | `rea-agents@6.9.0`（MIT） |
| 固定 commit | `d74549e495c58eb4a560279fd9f05508401ea0a0`（tag `rea-agents-6.9.0`，skill v62） |
| 运行身份 | server `rea 6.9.0` / SDK `2.3.1` / protocol `2026-07-28`；目录 255 MCP 工具 / 196 CLI / 6 prompts（probe 不写死数字） |
| 与插件关系 | **不是插件依赖**：`dsh-redblue` 的 `dependencies`/`devDependencies` 为空，不打包 REA 运行时/二进制/安装脚本 |

### 7.2 安装与 MCP 注册（由用户执行）

```bash
# 1) 安装 REA（全局）
npm install -g rea-agents@6.9.0
#    或临时运行：npx -y rea-agents@6.9.0

# 2) 注册到 DSH（本机 2026-11-20 实测 rea doctor 状态 dsh=aligned）
rea setup --client dsh
rea doctor --client dsh --skill

# 3) 验证与重启
rea --version                                  # 6.9.0
#    重启 Desktop 后确认会话中可见 mcp__rea__binary_session
```

宿主侧注册形态（只读参考，`~/.dsh/cordis.patch.yml`）：条目 `rea-mcp` 使用 `@deepseek-ai/dsh-mcp-client`，`transport: stdio`，命令 `node <rea-agents>/scripts/rea.mjs mcp`，按需注入 `GHIDRA_INSTALL_DIR` / `JAVA_HOME`。**插件不写这个文件、不自动执行上述命令。**

### 7.3 `REA_*` 环境变量（可选，由宿主环境提供）

插件**不设置、不读取**这些变量；REA 自行读取：

| 变量 | 用途 |
|---|---|
| `REA_JADX_MCP_JAR` | JADX headless MCP JAR（APK 类/方法/JNI） |
| `REA_ADB_PATH` | adb 可执行文件（ADB 设备动作） |
| `REA_APKTOOL_COMMAND` | apktool（APK 资源解码） |
| `REA_WABT_BIN_DIRECTORY` | WABT 1.0.42 工具目录（WASM） |
| `REA_BINWALK_COMMAND` / `REA_UNBLOB_COMMAND` | 固件区域/提取（Linux） |
| `REA_TSHARK_COMMAND` / `REA_CAPINFOS_COMMAND` | PCAP 字段解析/摘要 |
| `REA_IDA_MCP_CONFIG` / `REA_KUNA_COMMAND` | IDA / Kuna 静态引擎 |
| `REA_JEB_MCP_URL` | JEB MCP 客户端 |
| `GHIDRA_INSTALL_DIR` / `JAVA_HOME` | Ghidra 反编译依赖 |

### 7.4 Windows 宿主能力矩阵（本机实测，2026-11-20）

**立即可用**（无需额外配置）：

| 能力 | 说明 |
|---|---|
| PE 静态 | 导入/资源/加载配置/证书 |
| ELF 静态 | notes/unwind/反编译（Ghidra） |
| 托管 PE/CLI | 程序集/成员/IL |
| ASAR/JS/Electron 静态 | 应用图/fuses/Electron 目标枚举 |
| APK 容器/包清单/签名 | 不依赖 JADX/apktool |
| Frida 设备/进程枚举与 attach/instrument | 工具组可用；仍需 `G-RT-01/02` 与真实设备 |
| PCAP 摘要 | `inspect_pcap_capture`（端点/DNS/SNI 摘要） |

**Windows 上缺失/降级**（缺什么就降级什么，并在 `degraded[]` 给出 remediation）：

| 能力 | 状态 | 降级路径 | 恢复方式（用户执行） |
|---|---|---|---|
| 二进制加固标记 `inspect_binary_hardening` | 工具组可用，**Windows 绝对路径调用报客户端 schema 错误**（已知缺陷 K-1） | 加载配置 + notes + 导入表 + 人工基线 | 等上游修复或在非 Windows 主机执行 |
| APK 资源解码（apktool） | `provider_unavailable` | 仅包清单/签名 | `REA_APKTOOL_COMMAND` 指向 apktool |
| APK 类/方法/JNI（JADX） | `provider_missing` | 仅包清单/签名 | `REA_JADX_MCP_JAR` 指向兼容 JAR |
| ADB/设备动作 | `provider_unavailable` | 不做设备侧动作 | `REA_ADB_PATH` 或 PATH 中 adb |
| WASM（WABT） | `provider_missing` | 容器清单 + 熵 | `REA_WABT_BIN_DIRECTORY` 指向 WABT |
| 固件区域/提取（Binwalk/Unblob） | `unsupported_host` | 熵 + 容器清单 | Linux + 对应工具 + prlimit/procps |
| GDB / rizin 调试、进程捕获、pwntools、TShark 字段、EVM、Wakaru、信号分析、macOS 原生 | `unsupported_host` | 静态反编译/摘要替代 | 对应 Linux/macOS 环境 |
| JEB | `provider_missing` | 不做 JEB 反编译 | 启动 JEB MCP 客户端 |
| Hopper | `unsupported_host` | 用 Ghidra | macOS |
| IDA / Kuna | `not_configured` | 用 Ghidra | 配置对应 MCP/命令 |

### 7.5 未装 REA / provider 缺失时的行为（降级语义）

| 情形 | 结果 | 退出码 | 证据/产物 |
|---|---|---|---|
| REA 不可用（无 `mcp__rea__*`、`binary_session` 启动/连接失败、无身份） | `status="blocked"`、`blockedBy=["G-REA-01"]`、0 分析 agent | `1` | `artifacts=[]`、`sealed=false`、含 install/register/verify `remediation` |
| target 不可读/空文件/无法算 SHA256/无可用路径（`G-REA-02`） | `blocked` 同上 | `1` | 0 分析 agent、0 产物 |
| REA 可用但某 provider 缺失（如 JADX） | **不 blocked**：`status` 仍为 `clean`/`findings`，`degraded[]` 逐项记录 | 按静态结果 | 产物照常，`limitations` 写明缺口 |
| `runtime=false`（默认） | 不启动/附加/注入/调试目标进程 | — | 静态只读产物 |
| `runtime=true` 但 `mode<active` 或 `dryRun!=false` | 拒绝（`G-RT-01`），0 agent | `1` | 无产物 |
| `runtime=true` 但 `confirm` 缺失/不等/`runtime=false` 却给 confirm | 拒绝（`G-RT-02`），0 agent | `1` | 无产物 |

- **其余 workflow 不受 REA 影响**：只有 `reverse` 走这条可选 lane。
- 降级不得把缺失当“未发现问题”；`G-REA-02` 时不得输出“未发现问题”的结论。

### 7.6 证据包

`evidence/rea-evidence.json` 由 REA `export_evidence_bundle` 导出并经 SHA256 封存；`deterministic=false`（含时间戳/会话状态），不得声称跨运行字节相同；`retain=none` 时不导出。反向复算可用 `node tools/sec.mjs evidence verify --manifest <workDir>/scan-manifest.json --dir <workDir>`。

---

## 8. 升级与回滚

### 8.1 升级到 v0.2.0（本次实测路径）

```bash
# 先备份（§2）
dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue   # 刷新 link；exit 0
# 或精确版本（registry 发布后，必须写明确版本，不用 latest/^）
dsh plugin --profile desktop add dsh-redblue@0.2.0
```

- 升级后重启 Desktop（§5），重跑 §4 的 5 层验证与 `node --test dsh-redblue/test/scaffold.test.mjs`。
- link 安装的源码更新即生效（symlink），但仍需重启才能应用到运行中的进程。
- 若要固定版本而不跟随目录：改用 §8.1 的精确版本安装，或把 link 路径固定到发布目录。

### 8.2 回滚

```bash
# A) 恢复备份清单（推荐）
cd C:/Users/<you>/.dsh/profiles/desktop
cp package.json package.json.bak-dsh-redblue-v020-20261120-170500 package.json
dsh plugin --profile desktop install
dsh plugin --profile desktop list | head -5

# B) 卸载（保留源码目录）
dsh plugin --profile desktop remove dsh-redblue
dsh plugin --profile desktop list 2>&1 | grep -i dsh-redblue    # 期望无输出、exit 1
grep -n "dsh-redblue" C:/Users/<you>/.dsh/profiles/desktop/package.json  # 期望无输出
```

- `remove` 语义（DSH 源码确认，本机未实测执行卸载）：`pnpm remove` 后 reconcile 会把不再是依赖的 `dsh-redblue` **从 `dsh.profile.bundles` 自动移除**；`node_modules/dsh-redblue` 符号链接删除；源码目录不受影响；重启后技能消失。
- 回滚到上一版源码（v0.1 基线）：在插件目录用版本库基线提交检出（`dsh-redblue/.git` 基线 commit `277ec2e`），重新 `add link:` 并重启；若 registry 已发布旧版本，直接用精确版本安装。
- 只回滚 bundle 选择（保留包、停止加载）：从 `dsh.profile.bundles` 移除 `dsh-redblue`（保留 `dependencies`），重启；下次 `dsh plugin` 操作会自动 reconcile。

### 8.3 兼容性与版本豁免

```bash
dsh plugin --profile desktop version-exemptions
```

- DSH 会在安装时检查插件与运行时版本；不兼容时会打印：
  `dsh: to accept the risk, run: dsh plugin --profile desktop allow-version <name>@<version> --dsh-version <version> --accept-risk`
- **默认不要接受风险**：版本豁免可能导致崩溃或数据损坏；只有确认差异可接受时才执行，并记录原因与回滚路径。

### 8.4 升级失败的处理

1. 恢复 §2 的 `package.json` 备份；
2. `dsh plugin --profile desktop install`；
3. 重启并验证；
4. 把失败输出（含退出码）记入变更单；不要连续重试覆盖现场。

---

## 9. 跨 profile 逐个安装

profile 彼此独立（各自的 `package.json`、`node_modules`、`pnpm-lock.yaml`、`cordis.patch.yml`）。本机现状（2026-11-20 刷新时）：

| profile | 目录 | 依赖数 | bundles 数 | 用途 | 是否建议安装 dsh-redblue |
|---|---|---|---|---|---|
| `desktop` | `~/.dsh/profiles/desktop` | 13 | 15 | 桌面 App | ✅ 已安装（0.2.0） |
| `web` | `~/.dsh/profiles/web` | 9 | 10 | `dsh web` 浏览器运行时 | 按需 |
| `headless` | `~/.dsh/profiles/headless` | 0 | 2（base + headless） | CI/无头运行 | 按需 |
| `qqbot` | `~/.dsh/profiles/qqbot` | 1（qqbot） | 2 | QQ 机器人 | ❌ 不建议 |

逐个安装（同一条命令，只换 `--profile`）：

```bash
# desktop（本机已完成 0.2.0）
dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue

# web
dsh plugin --profile web add link:C:/dsh-workspace/branch1/dsh-redblue

# headless（CI：建议精确版本而不是 link）
dsh plugin --profile headless add dsh-redblue@0.2.0

# qqbot：通常不安装（技能面与机器人场景无关）
```

要点：

- 非 `desktop` profile 若 `package.json` 不存在，`dsh plugin --profile <name> ...` 会先初始化（DSH 源码行为）；`desktop` 必须由 Desktop 首次启动初始化。
- 每个 profile 安装后都要重复 §4 验证 + §5 重启对应运行时。
- 不要在 profile 之间复制 `node_modules`、`pnpm-lock.yaml` 或 `package.json`；link 用绝对路径最稳。
- DSH 版本必须与插件要求一致（`engines.node >= 20`；DSH 版本兼容性见 §8.3）。

---

## 10. 故障排查

| 症状 | 原因 | 处置 |
|---|---|---|
| `dsh: pnpm was not found; install pnpm and make it available on PATH.` | CLI 找不到 pnpm | 使用 Desktop 安装自带的 pnpm 路径（`dsh` 会注入）；或安装 pnpm 后重试 |
| `Open DeepSeek Harness Desktop once to initialize its profile, then fully quit it before running dsh plugin --profile desktop.` | desktop profile 未初始化 | 启动一次 Desktop 再完全退出，然后重试 |
| `list` 显示 `dsh-redblue@link:…` 而不是 `0.2.0` | pnpm 对 link 依赖显示 link 目标（正常行为） | 用 §4.3 读解析后的 `package.json` 确认 0.2.0；这不是安装失败 |
| `list` 有包但 bundles 没有 | 依赖未声明 `dsh.bundle.patch` 或平台不匹配 | 检查 `dsh-redblue/package.json` 的 `dsh.bundle.patch` 与 `cordis.patch.yml`；重跑 `add` 并核对 `bundles` |
| `dsh: warning: <name> declares no dsh.bundle — installed as a plain dependency, not a profile layer` | 安装的是无 bundle 元数据的包 | 确认安装名是 `dsh-redblue`（不是旧别名/其它包） |
| 重启后技能不出现 | 未完全退出重启 / profile 选错 / bundles 未含 | 按 §5 判定；`grep dsh-redblue` 检查清单；确认技能列表已刷新 |
| 技能列表有 16 个但 `dsh-red-reverse` 不在 | 源码不完整/旧版本 | 读 `skills/red-reverse/SKILL.md` 与 `lib/index.js`；重装 link 并重跑 §4.4 |
| `Cannot find module '@deepseek-ai/...'`（插件加载） | 源码被移动/删除，或 link 路径失效 | `fs.realpathSync` 检查链接；重新 `add link:<现路径>` |
| provider 冒烟不是 16 项 | 源码不完整/被改动 | 重新获取源码；跑 `node --test test/scaffold.test.mjs`；对照 `git` 记录 |
| `reverse` 返回 `blocked` + `G-REA-01` | REA 未安装/未注册/工具不可见 | 按 §7.2 安装注册（`npm install -g rea-agents@6.9.0` → `rea setup --client dsh` → 重启）；确认 `mcp__rea__binary_session` |
| `reverse` 返回 `blocked` + `G-REA-02` | target 不可读/空/哈希不符/无可用路径 | 检查 `targets[0].value` 是 Windows 绝对路径且可读；重新计算哈希 |
| `reverse` 被 `G-TGT-05` 拒绝 | `targets` 不是恰好一个 `kind="source"` | 只保留一个 source 目标（本地制品） |
| `reverse` 被 `G-RT-01`/`G-RT-02` 拒绝 | runtime 门禁不满足 | `runtime=true` 需 `mode≥active`、`dryRun=false`、`confirm` 与唯一 source target 完全相等；不需要 runtime 就设 `runtime=false` 且不传 confirm |
| `reverse` 有 `degraded[]`（如 jadx `provider_missing`） | 宿主 provider 缺口 | 按 §7.4 的 remediation 配置对应 `REA_*` 变量；缺失能力不能当“无问题” |
| `inspect_binary_hardening` 报 schema 错误 | REA 已知缺陷 K-1（Windows 绝对路径） | reverse 已改用加载配置/notes/导入表/人工基线；或换非 Windows 主机 |
| workflow 返回 `rejected` / `exitCode=1` | 门禁命中（`rejectedBy` 给出 G-*） | 按 `policy/authorization.md` §4 修 scope/args；不要绕过门禁 |
| `exitCode=2` | 完成且有 reportable finding（不是错误） | 读 `findings.json` 与 `report.md`；按处置建议跟进 |
| `exitCode=1` 且 `status="error"` | 执行期错误/封存哈希不符 | 检查 `workDir` 产物与 `scan-manifest.json`，用 `evidence verify` 复算 |
| `guard` 缺 `--scope` 返回 2 | usage 语义（已知限制 W1） | 补 `--scope`；这不是门禁绕过 |
| `guard --execute` 被拒 | 缺 written/mode/allowlist/confirm/二进制 | 对照 [`README.md`](../README.md) §3.1 的 guard 六条件；缺二进制时先装工具或用 dry-run |
| `rule lint` 对自带 sigma 模板 exit 1 | 行内 `#` 注释未剥离（已知限制 W2/R10） | 预期行为；正式规则把注释移到独立行 |
| `node --test dsh-redblue/test/` 失败 | Node 24 不接受目录形式（已知限制 W3） | 用 `node --test dsh-redblue/test/*.test.mjs` 或 `npm test` |
| 安装时 `cpu-features` install Failed | ssh2 可选依赖的 build script（与插件无关） | 可忽略（exit 0）；若其它插件异常，恢复备份并 `dsh plugin --profile desktop install` |
| 安装/升级后其它插件异常 | pnpm 重算 node_modules | 立即按 §8.2 回滚；记录输出；必要时 `pnpm rebuild`（在 profile 目录） |

---

## 11. 安装记录（v0.2.0 刷新，本机实测 2026-11-20）

| 步骤 | 命令 | 退出码 | 关键输出 |
|---|---|---|---|
| 环境 | `dsh --version` / `node -v` | 0 | `0.2.2-rc.5` / `v24.22.1` |
| 备份 | `cp -p package.json package.json.bak-dsh-redblue-v020-20261120-170500` | 0 | sha256 `c49334cc…`（§2 表） |
| 刷新 link | `dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue` | **0** | `Done in 8.7s using pnpm v11.28.5`；`Packages: +1 -56` |
| 版本 | `require(<profile>/node_modules/dsh-redblue/package.json).version` | 0 | `0.2.0` |
| 清单 | `grep -n dsh-redblue package.json` | 0 | 14（dependencies）/34（bundles） |
| 列表 | `dsh plugin --profile desktop list \| grep -i dsh-redblue` | 0 | `dsh-redblue@link:../../../../../dsh-workspace/branch1/dsh-redblue` |
| provider 冒烟 | `node --input-type=module -e ...` | 0 | `count=16 ranks=[600] reverse=true dsh-rb-run … dsh-red-reverse` |
| REA（可选） | `rea --version` / `rea doctor --client dsh --skill` | 0 | `6.9.0` / `dsh=aligned` |

未执行（避免破坏性验证）：`remove` 卸载、registry 版本升级、跨 profile 实装、版本豁免。本文对应命令的语义来自 DSH CLI 源码与 `@deepseek-ai/dsh-plugin-manager` 行为说明，已在文中标注“未实测”。

---

## 12. 相关文档

- [`README.md`](../README.md) — 能力总览、16 技能、10 workflow 与快速安装
- [`DETAIL.md`](DETAIL.md) — 插件详情页正文（能力/门禁/限制）
- [`architecture.md`](architecture.md) — 装载链、执行架构与逆向 lane（含两张 SVG）
- [`tool-runtime.md`](tool-runtime.md) — 工具运行时与 guard 六条件
- [`assembly-report.md`](assembly-report.md) — 装配、偏差与受理（§11 为 v0.2.0 记录）
- [`design-addendum-v0.2-reverse.md`](design-addendum-v0.2-reverse.md) — 逆向 lane 设计基线（内部文档，不入包）
- [`policy/authorization.md`](../policy/authorization.md) — 44 项 G-* 注册表
- [`NOTICE`](../NOTICE) / [`LICENSE`](../LICENSE) — 四上游归属与许可
