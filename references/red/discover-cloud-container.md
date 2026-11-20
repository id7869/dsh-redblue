<!-- dsh-redblue:provenance
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: Skills/container/offensive-k8s-attacks/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 合并 Claude-Red cloud/container/k8s 三篇与 ACS 云评估、CIS 基线类技能，只保留只读评估口径，删除逃逸与凭据滥用链
-->

# 云与容器发现判定清单（discover-cloud-container）

> 定位：`dsh-red-discover` 的 cloud/container/IaaS/编排类目判定依据。全部为**只读评估**：只调用 list/get/describe 类接口，不创建、不写入、不导出凭据。
> 主要上游：Claude-Red `cloud/offensive-cloud`、`container/offensive-k8s-attacks`、`container/offensive-container-escape`（只取「风险配置识别」）；ACS `conducting-cloud-penetration-testing`、`auditing-cloud-with-cis-benchmarks`、`benchmarking-kubernetes-with-kube-bench`。
> 消费者：`dsh-red-discover`、`dsh-red-validate`、`dsh-purple-verify`（云侧检测覆盖）。
> 版本时效：云 API 参数、K8s 字段与扫描器参数以 2026-11-19 复核为准；厂商 API 与基线版本会变，执行前核对当前版本。

## 1. 授权与前置

| 项 | 要求 |
|---|---|
| 授权类型 | 云侧必须 `written`，并写明账号/订阅/项目 ID 与区域清单 |
| 凭据 | 由授权方提供的最小权限只读凭据；禁止使用生产管理员凭据做枚举 |
| 数据面 | 只看元数据与管理面配置；不读对象内容、不下载日志、不查询业务表 |
| 网络 | 只调用厂商官方 API；不扫云厂商网段、不打第三方托管资产 |
| 输出 | 只记录配置事实与风险判定，不记录资源里的业务数据 |

凭据本身按 `mask-and-redact`：证据只写「使用了授权方提供的只读凭据」，不写 ARN/AccessKey 原文。

## 2. 身份与权限（先确认「我是谁」）

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# AWS：调用身份与挂载策略（全部只读）
aws sts get-caller-identity
aws iam list-attached-user-policies --user-name <IAM_USER>
aws iam list-attached-role-policies --role-name <IAM_ROLE>
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument!=null]'
# 组织级可见性（需组织只读权限）
aws organizations list-accounts
```

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
# Azure / GCP：登录态与角色
az account show
az role assignment list --all --assignee <OBJECT_ID>
gcloud auth list
gcloud projects get-iam-policy <PROJECT_ID>
```

判定要点：

- 是否可跨账号/跨订阅扮演角色（信任策略里是否有宽泛 principal）。
- 是否存在长期静态密钥（对比是否存在 workload identity / OIDC 联合）。
- 权限是否集中在单一高权角色（无明显职责分离）。
- 组织/租户级审计日志是否开启（CloudTrail / Activity Log / Cloud Audit Logs）。

## 3. 存储与密钥（只看元数据）

| 检查 | 命令要点 | 判定信号 | 禁止 |
|---|---|---|---|
| 桶/容器清单与策略 | `aws s3api list-buckets`、`aws s3api get-bucket-policy` | 策略含公开读、缺 `Deny` 条件 | 列举或下载对象内容 |
| 静态加密与版本 | `aws s3api get-bucket-encryption`、`get-bucket-versioning` | 未加密、无版本 | 关闭或改动配置 |
| 密钥/密管清单 | `aws secretsmanager list-secrets`、`az keyvault secret list`、`gcloud secrets list` | 命名暴露用途、无访问策略 | 读取 secret 值 |
| 数据库暴露 | 安全组/防火墙规则、公网可达性 | 管理端口对公网开放 | 连接数据库 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
aws s3api list-buckets --query 'Buckets[].Name'
aws s3api get-bucket-policy --bucket <BUCKET>   # 只读策略文档
aws s3api get-bucket-encryption --bucket <BUCKET>
```

命中「可公开读」只写候选并立即停止深入：不下载、不列目录；证据只保留策略 JSON 的关键片段（脱敏资源名）。

## 4. 容器镜像与制品

| 检查 | 命令 | 判定信号 |
|---|---|---|
| 镜像漏洞与 SBOM | `trivy image --format json -o trivy.json <IMAGE>`、`syft <IMAGE> -o json`、`grype <IMAGE> -o json` | 高危组件、过期基础镜像、无 SBOM |
| Dockerfile 风险 | 人工/静态规则检查 | root 运行、`latest` 标签、ADD 远程 URL、密钥写入层 |
| 镜像签名与来源 | `cosign verify <IMAGE>`（如有） | 未签名、来源不可信 |
| 仓库权限 | 只读查询 registry 配置 | 匿名可推、无内容信任 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
trivy image --severity HIGH,CRITICAL --format json -o trivy.json <IMAGE>
syft <IMAGE> -o cyclonedx-json=sbom.json
grype <IMAGE> -o json -o grype.json
```

本地离线评估优先（镜像先 `docker save` 到 `workDir` 再扫），避免现场拉取引入网络与供应链风险。

## 5. Kubernetes / 编排面

| 检查 | 命令 | 判定信号 |
|---|---|---|
| 我的权限 | `kubectl auth can-i --list`、`kubectl auth can-i --list -n <NS>` | 宽泛 `*` 权限、可读 secret、可 exec |
| RBAC 绑定 | `kubectl get clusterrolebindings -o json`、`kubectl get rolebindings -A` | 绑定给 `system:masters`、匿名组、过宽 subject |
| Secret 暴露面 | `kubectl get secrets -A`（只看名称与类型） | 明文 Secret 挂载、Secret 进环境变量 |
| 工作负载风险 | `kubectl get pods -A -o json`（看 `securityContext`/`hostPath`） | `privileged: true`、`hostPID/hostNetwork`、挂载 `docker.sock`、`hostPath: /` |
| 基线核查 | `kube-bench`（集群内或离线报告） | API server 弱配置、无审计策略 |
| 准入与网络策略 | `kubectl get networkpolicies -A`、PSA 标签 | 无网络策略、无 Pod Security 限制 |

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```bash
kubectl auth can-i --list
kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}{"/"}{.metadata.name}{" privileged="}{.spec.containers[*].securityContext.privileged}{" hostPath="}{.spec.volumes[*].hostPath.path}{"\n"}{end}'
kubectl get networkpolicies -A
```

判定纪律：**只判定「是否存在逃逸前置条件」**（privileged、hostPath、hostPID、docker.sock、可 exec 的 RBAC），不执行逃逸动作、不进入宿主、不读宿主文件。命中即写成候选并交 `dsh-red-exploit`（需 `confirm` 与 `mode≥exploit`）评估最小影响。

## 6. 云侧检测视角（供 purple/report 使用）

| 风险类别 | 云侧可见日志 | 典型检测点 |
|---|---|---|
| 权限枚举 | CloudTrail / Activity Log / Audit Logs | 短时间内大量 `List*`/`Get*` 调用 |
| 角色链滥用 | 同上 + IAM 变更事件 | `AssumeRole` 异常源、跨账号扮演 |
| 存储探测 | 数据面审计（若开） | 桶策略读取、枚举行为 |
| 容器逃逸前置 | 节点审计、K8s audit | `privileged` 创建、hostPath 挂载、`exec` 到 pod |
| RBAC 提权 | K8s audit | clusterrolebinding 创建、SA token 滥用 |
| 镜像供应链 | registry 审计、CI 日志 | 未签名镜像上线、基础镜像突变 |

## 7. 候选断言字段（云/容器版）

| 字段 | 说明 |
|---|---|
| `category` | `cloud-iam` / `cloud-storage` / `cloud-secret` / `container-image` / `k8s-rbac` / `k8s-workload` / `k8s-baseline` |
| `claim` | 具体配置事实 + 风险判定（例：桶策略允许匿名读且无 Deny） |
| `observed` | 关键字段值（脱敏后的资源标识） |
| `attack` | 参考 ATT&CK：T1078（有效账号）、T1530（云存储）、T1610/T1611（容器） |
| `evidenceRefs` | 命令输出片段（≤2 KiB）+ 文件哈希 |
| `limitations` | 缺失权限、未覆盖区域/命名空间 |

## 8. 禁止事项

- 禁止创建/修改/删除云资源、IAM 策略、桶策略、K8s 对象、Secret。
- 禁止读取对象内容、下载日志、导出数据库、打印 Secret 值、导出 SA token。
- 禁止使用 `--force`/自动修复式参数；禁止压力测试与配额耗尽。
- 禁止容器逃逸、宿主挂载写入、`docker.sock` 操作、特权容器启动。
- 禁止跨租户/跨账号横向、禁止使用从目标环境取得的凭据继续枚举（越权即停）。
- 反模式：把「镜像有高危 CVE」直接当可利用；把 `kubectl auth can-i '*' '*'` 当已提权；把公网桶当已泄露。