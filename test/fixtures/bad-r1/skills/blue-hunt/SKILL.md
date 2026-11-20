---
name: dsh-blue-hunt
description: 假设驱动的威胁狩猎：从 ATT&CK 技术假设出发核对遥测覆盖并给出可判定结论。触发词：威胁狩猎、threat hunting、狩猎假设、遥测覆盖。不适用：检测规则编写用 dsh-blue-detect；本技能不编造遥测数据。
whenToUse: 当用户要求验证 ATT&CK 假设且能提供本地遥测导出时使用。
risk: passive
requires: none
ingests: none
source-repo: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
source-license: Apache-2.0
source-path: skills/hunting-threats/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 保留假设驱动狩猎步骤与遥测需求，删除扫描器参数与真实目标
---

# 威胁狩猎（缺 source-commit 的反例）

本文件用于触发 R1-PROVENANCE：frontmatter 缺少 `source-commit`。

## 过程

- 记录假设与判定标准。
