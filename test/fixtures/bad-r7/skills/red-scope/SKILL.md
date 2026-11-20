---
name: dsh-red-scope
description: 授权范围与威胁假设核对：把授权、目标、时间窗与威胁假设逐项核对。触发词：授权范围、威胁假设、目标核对、时间窗。不适用：情报收集用 dsh-red-surface；本技能只做核对。
whenToUse: 当用户要求定义或校验测试范围时使用。
risk: passive
requires: authorization
ingests: none
source-repo: https://github.com/usestrix/strix
source-commit: 8db295a5b3564be2b430bb3a9afdb4db7850fa24
source-license: Apache-2.0
source-path: skills/penetration-testing-with-strix/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 保留范围与授权步骤，删除运行时依赖与真实目标
---

# 授权范围（Jaccard 反例 A）

本文件与 `dsh-red-recon` 使用同一 description，用于触发 R7-JACCARD。