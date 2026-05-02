# skill-inject 来源记录

| 字段 | 值 |
| --- | --- |
| benchmark | SKILL-INJECT Benchmark |
| 来源仓库 | `git@github.com:aisa-group/skill-inject.git` |
| 本地路径 | `../../skill-inject` |
| 分支 | `main` |
| 当前 commit | `bf9fa1febff69e8f6bba50a439b204c5394a1ac3` (`bf9fa1f`) |
| commit 日期 | `2026-04-08T03:05:52+02:00` |
| 上游状态 | `git -C benchmarks/skill-inject status --short --branch` 显示 `## main...origin/main`，另有本地未跟踪 `paper.pdf`。 |
| 本地策略 | 保持上游 clone 干净；长期说明、适配结论和运行记录放在 `benchmarks/notes/skill-inject/` 与 `benchmarks/results/skill-inject/`。 |

## 本地数据快照

2026-05-01 只读统计：

| 文件/目录 | 本地条目数 | 说明 |
| --- | ---: | --- |
| `data/contextual_injections.json` | 48 | contextual/dual-use injection 定义；其中 script 9、direct 39；合计关联 task 139。 |
| `data/obvious_injections.json` | 36 | obvious malicious injection 定义；其中 script 7、direct 29；每条 5 个 task，合计关联 task 180。 |
| `data/tasks.json` | 58 | clean task 定义。 |
| `data/skills/**/SKILL.md` | 49 | 当前本地可扫描 skill package/skill file 数。 |

上游 README 中仍写有较早数字（例如 41 contextual、30 obvious、44 skill、66 task）。本地文档以当前 JSON/目录统计为准，并在正式 run artifact 中记录实际选择的 injection/task/skill 数。

## ClawSentry 适配说明

本文件只记录来源与本地数据快照；ClawSentry 适配结论分别见同目录 `BENCHMARK_NOTES.md`、`RUNBOOK.md` 与 `EVALUATION.md`。

## 运行入口

- contextual：`python experiments/contextual.py --agent <claude|codex|gemini|vibe>`
- obvious：`python experiments/obvious.py --agent <claude|codex|gemini|vibe>`
- utility baseline：`python experiments/utility_baseline.py --agent <agent>`
- smoke：`python scripts/smoke_test_all.py --agent <agent> --model <model> --dry-run`

## 敏感文件

正式运行需要 `docker/.env`（由 `docker/.env.example` 复制）提供 API keys。不要把 `docker/.env` 或容器内 agent credentials 写入长期文档或公开结果。
