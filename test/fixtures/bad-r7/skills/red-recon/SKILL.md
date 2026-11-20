---
name: dsh-red-recon
description: 授权范围与威胁假设核对：把授权、目标、时间窗与威胁假设逐项核对。触发词：授权范围、威胁假设、目标核对、时间窗。不适用：情报收集用 dsh-red-surface；本技能只做核对。
whenToUse: 当用户要求核对授权范围与资产清单时使用。
risk: passive
requires: authorization
ingests: none
source-repo: https://github.com/SnailSploit/Claude-Red
source-commit: 6196ba7464662de34e8744d359f175d1a7bca530
source-license: MIT
source-path: Skills/recon/offensive-osint/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 保留范围与情报收集步骤，删除扫描器参数与真实目标
---

# 情报收集（Jaccard 反例 B）

本文件与 `dsh-red-scope` 使用同一 description，用于触发 R7-JACCARD。