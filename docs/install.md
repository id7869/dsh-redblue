# dsh-redblue 安装与运维手册

> 适用版本：`dsh-redblue 0.1.0`（Apache-2.0）
> 实测环境：Windows 11 + DeepSeek Harness Desktop `0.2.2-rc.5` + Node `v24.22.1`
> 实测时间：2026-11-20；本文所有“实测”段落均为本机真实命令与输出，未实测的动作会明确标注“未实测”。

本文覆盖：**desktop profile 的 link 安装、安装验证、重启生效、升级、卸载与回滚、跨 profile 逐个安装、故障排查、安全前置**。
快速版安装步骤另见 [`README.md`](../README.md) §6 与 [`DETAIL.md`](DETAIL.md) §4；本文是完整、可回滚的运维口径。

---

## 0. 安全前置（安装前必须确认）

dsh-redblue 是**授权**红/蓝/紫安全测试插件，默认 report-only（`dryRun=true`）。安装与使用前请确认：

1. **书面授权**：任一红队/紫队/triage 工作流都要求 `authorization.type="written"`；蓝队可用 `internal-mandate`。口头同意、聊天承诺、推定同意一律不构成授权。
2. **scope 是唯一授权载体**：目标、排除项、mode、时间窗、预算、数据处置都写在 `scope` 对象里；缺项、过期、越窗、越预算、全网段/通配目标一律拒绝（39 项 `G-*`）。
3. **只安装到需要的 profile**：插件注册 15 个技能 + 9 个工作流；不需要的 profile（如 `qqbot`）不要安装。
4. **改动 profile 前先备份**：`package.json` 是 profile 的权威清单；升级/卸载/回滚都依赖它。
5. **默认不产生目标侧动作**：`dryRun=true` 时零发包；只有显式 `activeScan=true`（需 `mode≥active` 且 `dryRun=false`）或 `guard --execute`（需 written + mode + allowlist + `--confirm` 全等）才会触达目标。
6. **数据处置固定**：`secrets="mask-and-redact"`、`destruction="none"`；插件不落原始凭据、不删除证据。
7. **本插件零网络**：除 `guard --execute` 执行授权配方外，技能/workflow/工具运行时均不联网；安装命令本身由 pnpm 执行（见 §3 输出说明）。
8. **不要把真实凭据/内网主机/客户名写进 scope 或技能**：净化门禁 R10 视其为 blocker。

---

## 1. 安装前检查

```bash
dsh --version          # 本机实测：0.2.2-rc.5
node --version         # 本机实测：v24.22.1
```

- DSH 桌面版已至少启动过一次，`C:/Users/<you>/.dsh/profiles/desktop/package.json` 已存在（Desktop 首次启动会初始化）。
- 插件源码目录已就位：`C:/dsh-workspace/branch1/dsh-redblue`（含 `package.json`、`cordis.patch.yml`、`lib/index.js`）。
- 自检插件完整性（可选，推荐）：

```bash
cd C:/dsh-workspace/branch1/dsh-redblue
node --test test/scaffold.test.mjs        # 9/9
node tools/sanitize-lint.mjs --strict --json .   # 0 blocker
```

> 建议完全退出 Desktop（托盘 → 退出，而不是只关窗口）后再改 profile，避免与 HMR/profile 写入竞争。
> 本机实测时 Desktop 正在运行且命令成功，但这不作为推荐流程。

---

## 2. 备份（回滚前提）

profile 目录：`C:/Users/<you>/.dsh/profiles/desktop`。

```bash
cd C:/Users/<you>/.dsh/profiles/desktop
cp -p package.json package.json.bak-dsh-redblue-<YYYYMMDD-HHMMSS>
sha256sum package.json package.json.bak-dsh-redblue-<YYYYMMDD-HHMMSS>
```

> `sha256sum` 为 Git Bash/MSYS 用法；PowerShell 用 `Get-FileHash -Algorithm SHA256 package.json`。

本机实际记录（2026-11-20）：

| 文件 | 大小 | SHA256 | 备份文件 |
|---|---|---|---|
| `package.json` | 1,105 B | `7f327a33ec22af55a883bf3a9ad63bc23cbecc0f8231bf294fa69ed878a0336b` | `package.json.bak-dsh-redblue-20261120-103600` |
| `cordis.patch.yml` | 3,299 B | `6924dedb4a3b620490f248c4f4637b2687480651dc84fc3fcddd377bec9b84b9` | `cordis.patch.yml.bak-dsh-redblue-20261120-103600` |

说明：安装命令只改 `package.json`（`dependencies` + `dsh.profile.bundles`）与 `node_modules`/`pnpm-lock.yaml`；**不会改** profile 的 `cordis.patch.yml`。备份它是为了在 HMR/手工改动后才需要回滚的场景。

---

## 3. Desktop link 安装（实测）

```bash
dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue
```

本机实测（2026-11-20 10:37）：

- **退出码 `0`**；耗时 `Done in 33s using pnpm v11.28.5`（DSH 安装自带的 pnpm；系统 `pnpm -v` 为 11.22.0，不作为执行路径）。
- 关键输出：`dependencies: + dsh-redblue 0.1.0 <- ..\..\..\..\..\dsh-workspace\branch1\dsh-redblue`
- `dsh plugin` 的两步语义（已由 DSH 源码 `@deepseek-ai/dsh-plugin` 与 `@deepseek-ai/dsh-plugin-manager` 行为确认）：
  1. 在 profile 目录执行 pnpm（`link:` 依赖 → `node_modules/dsh-redblue` 是指向源码目录的符号链接，**不复制源码**）；
  2. 重新读取 profile 清单，对声明了 `dsh.bundle.patch` 的新依赖**自动追加**到 `dsh.profile.bundles`（本机 `package.json` 实测由 14 → 15 个 bundle，且 `dependencies` 新增一行）。
- 安装过程中 pnpm 还会：校验 lockfile 供应链策略（376 entries，24.1s，访问了 registry 元数据）；清理 node_modules 中不在图内的旧包（本机 `+1 -56`）；尝试构建可选依赖 `cpu-features`（ssh2 传递依赖）失败并打印 `Failed` —— 该失败是**可选 build script**，pnpm 仍以 exit 0 结束，与 dsh-redblue 无关（插件零依赖、无 install script）。
- 如果安装失败（非 0 退出）：不要重试到成功为止，先按 §8 回滚，再按 §9 排查。

> `dsh plugin` 是唯一受支持的 profile 包管理入口；不要手写 `node_modules`、不要 `npm install`、不要把源码拷进 profile。

---

## 4. 安装验证（4 层，全部实测）

### 4.1 CLI 列表

```bash
dsh plugin --profile desktop list 2>&1 | grep -i dsh-redblue
```

实测输出：

```text
├── dsh-redblue@link:../../../../../dsh-workspace/branch1/dsh-redblue
```

退出码 `0`；列表末尾 `13 packages`（安装前 12）。

### 4.2 profile 清单（dependencies + bundles 都必须在）

```bash
grep -n "dsh-redblue" C:/Users/<you>/.dsh/profiles/desktop/package.json
```

实测输出：

```text
14:    "dsh-redblue": "link:C:/dsh-workspace/branch1/dsh-redblue",
36:        "dsh-redblue"
```

- 第 14 行在 `dependencies`：证明 pnpm 包安装成功。
- 第 36 行在 `dsh.profile.bundles`：证明 Cordis 层已选中；缺任一条都不算装好。

### 4.3 provider 冒烟（证明 link 可解析、15 项技能可加载）

```bash
node --input-type=module -e '
import { pathToFileURL } from "node:url";
const mod = await import(pathToFileURL("C:/dsh-workspace/branch1/dsh-redblue/lib/index.js").href);
let f; mod.apply({ skills: { registerProvider(x) { f = x; } } });
const p = f({ signal: new AbortController().signal, invalidate() {} });
const list = await p.list({});
console.log(mod.name, mod.inject, p.name, list.length, list[0].name, list[14].name);
'
```

实测输出：

```text
dsh-redblue [ 'skills' ] dsh-redblue 15 dsh-rb-run dsh-rb-triage
```

- `apply()` 只注册 1 个 provider，`inject=["skills"]`，rank 均为 600、`source="bundled"`。
- 可再取一个技能正文：`await p.get({ name: "dsh-rb-run", ... })` 返回内容（实测 7,770 B，来自 `skills/run/SKILL.md`）。

### 4.4 node_modules 符号链接指向源码

```bash
node -e "const fs=require('fs');const p=process.env.USERPROFILE+'/.dsh/profiles/desktop/node_modules/dsh-redblue';console.log(fs.existsSync(p),fs.lstatSync(p).isSymbolicLink(),fs.realpathSync(p))"
```

实测：`true true C:\dsh-workspace\branch1\dsh-redblue`。

### 4.5 运行会话观察（不作为生效证明）

安装后本会话的技能目录出现了 15 个 dsh-rb-* 技能（DSH 对 profile 变更做了热更新）。这只能说明 host 侧已读取到 bundle，**不能**替代 §5 的完整重启验证（Cordis patch 图层、工具面、插件详情页以重启后为准）。

---

## 5. 重启生效（必做）

1. 完全退出 Desktop：托盘图标 → 退出（确认进程结束）；只关闭窗口不算。
2. 重新启动 DeepSeek Harness Desktop。
3. 生效判定（三条都满足才算生效）：
   - 插件/设置页可看到 `dsh-redblue`（`docs/DETAIL.md` 为详情正文、`icon.svg` 为图标）；
   - 技能列表出现 `dsh-rb-run` 等 15 个技能；
   - 在会话里说“红蓝对抗/授权渗透测试/威胁狩猎/紫队对齐”等触发词，能命中 `dsh-rb-run`。
4. 也可以在 Desktop 的插件管理器里查看/启停 `dsh-redblue`（它读写同一份 profile 清单；CLI 与 UI 以最后一次写入为准，改完同样需要重启才能完整生效）。
5. 若重启后仍不可见：回到 §8 回滚，再按 §9 排查；不要在未生效状态下去跑 workflow。

> 本手册不声称安装已在本机生效：§3–§4 只证明“包已安装、清单已选中、provider 可解析”。完整生效以重启后为准。

---

## 6. 首次使用与触发

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

### 6.2 运行 workflow 的方式（原生 `workflow` 工具）

1. 读取 `C:/dsh-workspace/branch1/dsh-redblue/workflow/<script>.js` 全文；
2. 交给 DSH 原生 `workflow` 工具执行（脚本已含 `meta`：name/description/phases）；
3. `args` 传 `scope`（对象）、`workDir`（Windows 绝对路径）、`skillDir`（必须是 `<插件根>/skills`）、`maxConcurrency`（1–8，默认 2）、`dryRun`（默认 true）；`exploit`/`post` 还要 `confirm`，`recon` 可选 `activeScan`；
4. 按返回对象 `status`/`exitCode` 转述，产物在 `workDir`。

### 6.3 最小可用 scope（已用 `scope check` 实测通过）

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

自检：

```bash
cd C:/dsh-workspace/branch1/dsh-redblue
node tools/sec.mjs scope check --scope C:/work/scope.json
```

实测返回 `{ "ok": true, "rejectedBy": [], "mode": "passive", ... }`，退出码 `0`。

> **注意**：输入 scope 只接受 9 个白名单键（`authorization`/`targets`/`exclusions`/`mode`/`window`/`budget`/`dataHandling`/`dataSources`/`notes`），未知键 → `G-CONF-01`。
> `workDir/scope.json` 是 workflow 生成的产物，额外含 `schemaVersion`/`scopeDigest`/`validatedAt`；**不要把它当输入回灌**，否则同样触发 `G-CONF-01`（产物用于审计与复算，不是输入）。

### 6.4 产物与退出码

- 产物：`findings.json`、`coverage.json`、`report.md`、`exports/results.sarif`、`scan-manifest.json` + 阶段产物。
- 退出码：`0` 干净/计划、`2` 有 reportable、`1` 拒绝或错误；拒绝时 `status="rejected"`、`rejectedBy=[...]`、不写产物、0 个 agent 启动。

---

## 7. 显式版本升级

### 7.1 升级到明确版本（registry 发布后）

```bash
# 先备份（见 §2）
dsh plugin --profile desktop add dsh-redblue@0.2.0      # 精确版本，不带范围
dsh plugin --profile desktop list 2>&1 | grep dsh-redblue
```

- 必须写**精确版本**（`0.2.0`），不要 `latest`/`^` 范围，便于审计与回滚。
- 升级会重写 `dependencies` 为 registry 版本；`dsh.profile.bundles` 保持选中。
- 升级后重启 Desktop（§5），重跑 §4.3 provider 冒烟与插件自带测试。

### 7.2 源码 link 方式的“升级”

`link:` 安装没有副本：源码目录更新即生效（但仍需重启 Desktop 才能应用到运行中的进程）。

```bash
cd C:/dsh-workspace/branch1/dsh-redblue
git status 2>/dev/null || true       # 若源码来自版本库，先确认干净
node --test test/scaffold.test.mjs   # 装前自检
```

- 记录升级前基线：`sha256sum` 全树或 `git rev-parse HEAD`；
- 更新后用 §4 四层验证 + 重启；
- 若要固定版本而不是跟随目录，改用 §7.1 的精确版本安装，或移除后重新 `add link:` 到固定路径。

### 7.3 兼容性与版本豁免

```bash
dsh plugin --profile desktop version-exemptions
```

- DSH 会在安装时检查插件与运行时版本；不兼容时会打印：
  `dsh: to accept the risk, run: dsh plugin --profile desktop allow-version <name>@<version> --dsh-version <version> --accept-risk`
- **默认不要接受风险**：版本豁免可能导致崩溃或数据损坏；只有确认差异可接受时才执行，并记录原因与回滚路径。

### 7.4 升级失败的处理

1. 恢复 §2 的 `package.json` 备份；
2. `dsh plugin --profile desktop install`；
3. 重启并验证；
4. 把失败输出（含退出码）记入变更单；不要连续重试覆盖现场。

---

## 8. 卸载与回滚

### 8.1 标准卸载（推荐）

```bash
# 备份（§2）
dsh plugin --profile desktop remove dsh-redblue
dsh plugin --profile desktop list 2>&1 | grep -i dsh-redblue   # 期望无输出、退出码 1
grep -n "dsh-redblue" C:/Users/<you>/.dsh/profiles/desktop/package.json  # 期望无输出
```

语义（DSH 源码确认，本机未实测执行卸载）：

- `remove` 在 profile 目录执行 `pnpm remove dsh-redblue`；
- 随后 reconcile 会把不再是依赖的 `dsh-redblue` **从 `dsh.profile.bundles` 自动移除**；
- `node_modules/dsh-redblue` 符号链接被删除；源码目录不受影响；
- 重启 Desktop 后 15 个技能消失。

### 8.2 手工回滚（安装失败/升级失败/需要完全复原）

```bash
cd C:/Users/<you>/.dsh/profiles/desktop
cp package.json package.json.bak-dsh-redblue-20261120-103600
dsh plugin --profile desktop install
dsh plugin --profile desktop list | head -5
```

- 恢复的 `package.json` 同时去掉 `dependencies` 与 `bundles` 中的 `dsh-redblue`；
- `dsh plugin --profile desktop install` 按恢复后的清单重建 `node_modules`；
- 若还改过 `cordis.patch.yml`，一并恢复 `cordis.patch.yml.bak-dsh-redblue-20261120-103600`；
- 重启 Desktop 完成回滚。

### 8.3 只回滚 bundle 选择（保留包、停止加载）

```bash
# 仅从 dsh.profile.bundles 移除 dsh-redblue（保留依赖）
node -e "const fs=require('fs');const p=process.env.USERPROFILE+'/.dsh/profiles/desktop/package.json';const m=JSON.parse(fs.readFileSync(p,'utf8'));m.dsh.profile.bundles=m.dsh.profile.bundles.filter(n=>n!=='dsh-redblue');fs.writeFileSync(p,JSON.stringify(m,undefined,2)+'\n')"
```

> 手工编辑 profile 清单属于运维兜底，改完仍需重启；下次 `dsh plugin` 操作会自动 reconcile。

---

## 9. 跨 profile 逐个安装

profile 彼此独立（各自的 `package.json`、`node_modules`、`pnpm-lock.yaml`、`cordis.patch.yml`）。本机现状（2026-11-20 安装前）：

| profile | 目录 | 依赖数 | bundles 数 | 用途 | 是否建议安装 dsh-redblue |
|---|---|---|---|---|---|
| `desktop` | `~/.dsh/profiles/desktop` | 12（安装后 13） | 14（安装后 15） | 桌面 App | ✅ 已安装（本任务） |
| `web` | `~/.dsh/profiles/web` | 9 | 10 | `dsh web` 浏览器运行时 | 按需 |
| `headless` | `~/.dsh/profiles/headless` | 0 | 2（base + headless） | CI/无头运行 | 按需 |
| `qqbot` | `~/.dsh/profiles/qqbot` | 1（qqbot） | 2 | QQ 机器人 | ❌ 不建议 |

逐个安装（同一条命令，只换 `--profile`）：

```bash
# desktop（本机已完成）
dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue

# web
dsh plugin --profile web add link:C:/dsh-workspace/branch1/dsh-redblue

# headless（CI：建议精确版本而不是 link）
dsh plugin --profile headless add dsh-redblue@0.1.0

# qqbot：通常不安装（技能面与机器人场景无关）
```

要点：

- 非 `desktop` profile 若 `package.json` 不存在，`dsh plugin --profile <name> ...` 会先初始化（DSH 源码行为）；`desktop` 必须由 Desktop 首次启动初始化。
- 每个 profile 安装后都要重复 §4 验证 + §5 重启对应运行时。
- 不要在 profile 之间复制 `node_modules`、`pnpm-lock.yaml` 或 `package.json`；不要跨 profile 引用 `link:` 相对路径以外的绝对路径（link 用绝对路径最稳）。
- DSH 版本必须与插件要求一致（`engines.node >= 20`；DSH 版本兼容性见 §7.3）。

---

## 10. 故障排查

| 症状 | 原因 | 处置 |
|---|---|---|
| `dsh: pnpm was not found; install pnpm and make it available on PATH.` | CLI 找不到 pnpm | 使用 Desktop 安装自带的 pnpm 路径（`dsh` 会注入）；或安装 pnpm 后重试 |
| `Open DeepSeek Harness Desktop once to initialize its profile, then fully quit it before running dsh plugin --profile desktop.` | desktop profile 未初始化 | 启动一次 Desktop 再完全退出，然后重试 |
| `list` 有包但 bundles 没有 | 依赖未声明 `dsh.bundle.patch` 或平台不匹配 | 检查 `dsh-redblue/package.json` 的 `dsh.bundle.patch` 与 `cordis.patch.yml`；重跑 `add` 并核对 `bundles` |
| `dsh: warning: <name> declares no dsh.bundle — installed as a plain dependency, not a profile layer` | 安装的是无 bundle 元数据的包 | 确认安装名是 `dsh-redblue`（不是旧别名/其它包） |
| 重启后技能不出现 | 未完全退出重启 / profile 选错 / bundles 未含 | 按 §5 判定；`grep dsh-redblue` 检查清单；确认技能列表已刷新 |
| `Cannot find module '@deepseek-ai/...'`（插件加载） | 源码被移动/删除，或 link 路径失效 | `node -e "fs.realpathSync(...)"` 检查链接；重新 `add link:<现路径>` |
| provider 冒烟不是 15 项 | 源码不完整/被改动 | 重新获取源码；跑 `node --test test/scaffold.test.mjs`；对照 `git` 记录 |
| workflow 返回 `rejected` / `exitCode=1` | 门禁命中（`rejectedBy` 给出 G-*） | 按 `policy/authorization.md` §4 修 scope/args；不要绕过门禁 |
| `exitCode=2` | 完成且有 reportable finding（不是错误） | 读 `findings.json` 与 `report.md`；按处置建议跟进 |
| `exitCode=1` 且 `status="error"` | 执行期错误/封存哈希不符 | 检查 `workDir` 产物与 `scan-manifest.json`，用 `evidence verify` 复算 |
| `guard` 缺 `--scope` 返回 2 | usage 语义（已知限制 W1） | 补 `--scope`；这不是门禁绕过 |
| `guard --execute` 被拒 | 缺 written/mode/allowlist/confirm/二进制 | 对照 [`README.md`](../README.md) §3.1 的 guard 六条件（scope 通过检查 + written + mode + allowlist + confirm 全等 + 二进制存在）；缺二进制时先装工具或用 dry-run |
| `rule lint` 对自带 sigma 模板 exit 1 | 行内 `#` 注释未剥离（已知限制 W2/R10） | 预期行为；正式规则请把注释移到独立行 |
| `node --test dsh-redblue/test/` 失败 | Node 24 不接受目录形式（已知限制 W3） | 用 `node --test dsh-redblue/test/*.test.mjs` 或 `npm test` |
| 安装时 `cpu-features` install Failed | ssh2 可选依赖的 build script（与插件无关） | 可忽略（exit 0）；若其它插件异常，恢复备份并 `dsh plugin --profile desktop install` |
| 安装/升级后其它插件异常 | pnpm 重算 node_modules | 立即按 §8.2 回滚；记录输出；必要时 `pnpm rebuild`（在 profile 目录） |

---

## 11. 安装记录（本机实测，2026-11-20）

| 步骤 | 命令 | 退出码 | 关键输出 |
|---|---|---|---|
| 环境 | `dsh --version` / `node -v` | 0 | `0.2.2-rc.5` / `v24.22.1` |
| 备份 | `cp -p package.json package.json.bak-dsh-redblue-20261120-103600` | 0 | sha256 与 §2 表一致 |
| 安装 | `dsh plugin --profile desktop add link:C:/dsh-workspace/branch1/dsh-redblue` | **0** | `+ dsh-redblue 0.1.0`；`Done in 33s using pnpm v11.28.5` |
| 清单 | `grep -n dsh-redblue ~/.dsh/profiles/desktop/package.json` | 0 | 14（dependencies）/36（bundles） |
| 列表 | `dsh plugin --profile desktop list \| grep -i dsh-redblue` | 0 | `dsh-redblue@link:../../../../../dsh-workspace/branch1/dsh-redblue` |
| 冒烟 | `node --input-type=module -e ...` | 0 | `15 dsh-rb-run dsh-rb-triage` |
| 安装后清单 | `sha256sum package.json` | 0 | `8f57f31d5cb18f6d23370ece66d618dfb7eb90309bd38017e448d703f6ac6682` |

未执行（避免破坏性验证）：`remove` 卸载、registry 版本升级、跨 profile 实装、版本豁免。本文对应命令的语义来自 DSH CLI 源码与 `@deepseek-ai/dsh-plugin-manager` 行为说明，已在文中标注“未实测”。

---

## 12. 相关文档

- [`README.md`](../README.md) — 能力总览与快速安装
- [`DETAIL.md`](DETAIL.md) — 插件详情页正文（能力/门禁/限制）
- [`architecture.md`](architecture.md) — 装载链与执行架构（含两张 SVG）
- [`tool-runtime.md`](tool-runtime.md) — 工具运行时与 guard 六条件
- [`assembly-report.md`](assembly-report.md) — 装配、偏差与受理记录
- [`policy/authorization.md`](../policy/authorization.md) — 39 项 G-* 注册表
- [`NOTICE`](../NOTICE) / [`LICENSE`](../LICENSE) — 上游归属与许可
