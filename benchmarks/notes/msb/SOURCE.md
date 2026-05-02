# MSB 来源记录

| 字段 | 值 |
| --- | --- |
| benchmark | MCP Security Bench (MSB) |
| 来源仓库 | `https://github.com/dongsenzhang/MSB.git` |
| 本地路径 | `../../MSB` |
| 分支 | `main` |
| 当前 commit | `c1d6a70171e4d2c44c87a2ae909d13df00c6aa8d` (`c1d6a70`) |
| commit 日期 | `2026-03-24T20:12:36+08:00` |
| 上游状态 | `git -C benchmarks/MSB status --short --branch` 显示 `## main...origin/main`，另有本地未跟踪 `paper.pdf`。 |
| 本地策略 | 保持上游 clone 干净；长期说明、适配结论和运行记录放在 `benchmarks/notes/msb/` 与 `benchmarks/results/msb/`。 |

## 本地数据快照

2026-05-01 只读统计：

| 文件 | 本地条目数 | 说明 |
| --- | ---: | --- |
| `data/attack_type.jsonl` | 1 行 / 12 个 attack type | 包含 8 个单类攻击与 4 个 mixed attack。 |
| `data/attack_task.jsonl` | 5 | 远程控制权限、数据获取、数据修改、kill process、agent 交互数据获取。 |
| `data/agent_task.jsonl` | 10 agent 场景 / 64 task-tool 对 | 覆盖 26 个唯一 MCP/tool server 名称。 |

上游 README 声称完整 benchmark 有 `>2,000` attack instances。当前本地仓库以 JSONL 配置与 tool server 模板动态组合 case；正式运行前应把本地生成的实际实例数写入 run artifact，而不是只引用论文数字。

## ClawSentry 适配说明

本文件只记录来源与本地数据快照；ClawSentry 适配结论分别见同目录 `BENCHMARK_NOTES.md`、`RUNBOOK.md` 与 `EVALUATION.md`。

## 运行入口

- 生成/运行：`python agent_attack.py --cfg_path config/all.yml`
- 统计指标：`python metrics.py --attack_type all --attack_task all --llm all --agent all --mode llm`

## 敏感文件

`benchmarks/MSB/.env` 存在于本地 clone 中，可能包含 provider 配置。不要把其中的 key、endpoint 或 token 写入文档、日志或提交记录。
