<!-- dsh-redblue:provenance
source-repo: https://github.com/usestrix/strix
source-commit: 8db295a5b3564be2b430bb3a9afdb4db7850fa24
source-license: Apache-2.0
source-path: skills/penetration-testing-with-strix/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 保留证据标准与复现结构，删除运行时依赖与真实目标
-->

# 证据标准

- 证据文件记录 SHA256 与字节数，路径相对 `workDir`。
- 复现步骤只写授权目标与最小影响，不写真实凭据。
- 引用外部结论时标注来源与核验状态。
- 无法复现或证据不足时，结论写 `deferred`，不得编造。
