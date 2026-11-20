---
name: dsh-blue-hunt
description: 假设驱动的威胁狩猎：从 ATT&CK 技术假设出发核对遥测覆盖并给出可判定结论。触发词：威胁狩猎、threat hunting、狩猎假设、遥测覆盖。不适用：检测规则编写用 dsh-blue-detect；本技能不编造遥测数据。
whenToUse: 当用户要求验证 ATT&CK 假设且能提供本地遥测导出时使用。
risk: passive
requires: none
ingests: none
source-repo: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
source-commit: 54a798831d2266a3ca61ce68a7acb80b81160d57
source-license: Apache-2.0
source-path: skills/hunting-threats/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 保留假设驱动狩猎步骤与遥测需求，删除扫描器参数与真实目标
---

# TLS 校验关闭反例

本文件用于触发 R4-VERIFY-DISABLED；授权横幅必须出现在攻击性代码块之前。

> 授权要求：scope.mode ≥ active 且已获书面授权；仅限授权目标；执行前先 dry-run。

```python
import requests
response = requests.get("https://app.example.com/health", verify=False)
```
