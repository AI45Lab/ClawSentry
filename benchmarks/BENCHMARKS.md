# Benchmark 总登记表

| bench_slug | 来源仓库 | 本地路径 | 上游 commit | 当前状态 | 主要文档 | 当前入口 | 备注 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `skills-safety-bench` | `git@github.com:jinchang1223/skills-safety-bench.git` | `./skills-safety-bench` | `148133b` | 已 clone；历史 dry-run 已验证；计划更新远端 HEAD 失败（SSH 22 连接关闭，HTTPS 需要凭据）；真实 Codex 单 case 仍需稳定 provider/Node 22 链路 | `README.md`、`benchmark/readme.md`、`notes/skills-safety-bench/*` | `scripts/start_codex_batch.sh`、本地 wrapper `scripts/skills_safety_bench_codex.sh` | 6 个 RD，155 个 case；当前自动 runner 只确认 Codex；case 自带 Docker 环境并通过 Harbor 执行 |
| `agentdog-atbench` | `https://github.com/AI45Lab/AgentDoG.git` | `./AgentDoG` | `09adfb8` | 已 clone；converter + ClawSentry L2 real-API sample smoke 已跑通；labeled manifest batch replay 入口已实现；真实 ATBench 标签评测待准备数据 | `README.md`、`examples/trajectory_sample.json`、`prompts/`、`notes/agentdog-atbench/*` | 本地 runner `scripts/agentdog_atbench_clawsentry.py`（`--trajectory` / `--manifest`） | 轨迹级安全评测；上游不自带 Docker/Harbor 环境；下一步准备真实 `5 safe + 5 unsafe` manifest 跑 L1/L2，再做 live runners |
| `MSB` | `https://github.com/dongsenzhang/MSB.git` | `./MSB` | `c1d6a70` | 已 clone；本地数据已统计；可用于 ClawSentry MCP/tool-use 评估；待实现 gateway/MCP adapter 与 raw-vs-protected smoke | `README.md`、`config/all.yml`、`data/*.jsonl`、`notes/msb/*` | `python agent_attack.py --cfg_path config/all.yml`；`python metrics.py ...` | 本地快照：12 attack type、5 attack task、10 agent 场景、64 task-tool 对；上游 README 称完整集 `>2,000` instances |
| `skill-inject` | `git@github.com:aisa-group/skill-inject.git` | `./skill-inject` | `bf9fa1f` | 已 clone；本地数据已统计；可用于 ClawSentry skill injection 评估；待实现容器内 hooks/gateway 与 static scan | `README.md`、`config.py`、`data/*.json`、`notes/skill-inject/*` | `python experiments/contextual.py ...`、`python experiments/obvious.py ...`、`python scripts/smoke_test_all.py --dry-run` | 本地快照：48 contextual、36 obvious、58 clean tasks、49 个 `SKILL.md`；README 数字较旧，正式 run 以 JSON 统计为准 |

## 状态说明

- `已 clone`：源码已经存在于本地。
- `dry-run 已验证`：manifest 解析、case 选择、runner 计划生成已验证，不代表模型和 Docker 真实执行已完成。
- `sample smoke 已跑通`：至少一个非正式样本完成端到端 smoke；不代表正式 benchmark 分数。
- `待适配`：需要接入 ClawSentry gateway、hook、AHP、MCP adapter 或 static scan 才能进行 raw-vs-protected 对照。
- `完整真实运行已验证`：至少一个 case 经过 agent 执行和攻击验证 replay。
- `阻塞`：缺少运行时依赖、凭据、适配器或外部服务。

## 框架支持状态

| 框架 | 裸执行当前状态 | 加 ClawSentry 当前状态 | 依据 |
| --- | --- | --- | --- |
| Codex | `skills-safety-bench` 可通过 Harbor runner 执行；`skill-inject` 支持 Codex 容器 runner；真实 provider 链路仍需复测 | 可测，前提是 endpoint/hooks 指到 ClawSentry；hook 必须使用临时 `CODEX_HOME` 或容器内 home | SSB 上游脚本硬编码 `harbor run -a codex`；skill-inject `config.py` 支持 codex |
| Claude Code | `skill-inject` 支持 Claude container runner；SSB/MSB 没有现成 Claude 批量入口 | 需要 Claude Code container hook/gateway 接入后验证 | skill-inject `AGENT_MODELS`；SSB 当前仓库未发现 Claude Code 批量入口 |
| Gemini CLI | `skill-inject` 支持 Gemini container runner；其他 benchmark 需额外 runner | 需要 Gemini hooks/gateway 接入后验证 | skill-inject `AGENT_MODELS` |
| OpenClaw | 未发现现成 benchmark 批量 runner | 需要 OpenClaw runner/adapter 接入 ClawSentry 后再验证 | 当前 benchmark clone 未提供 OpenClaw 批量入口 |
| A3S-Code | 未发现现成 benchmark 批量 runner | 需要 A3S-Code runner/adapter 接入 ClawSentry 后再验证 | 当前 benchmark clone 未提供 A3S-Code 批量入口 |

## ClawSentry 统一接入结论

推荐优先级：

1. `agentdog-atbench`：先做 offline labeled replay，低风险验证检测/审计能力。
2. `skill-inject`：先做 static scan + Codex/Claude/Gemini 小样本，评估 skill injection runtime 防护与误报。
3. `MSB`：先做 MCP tool metadata/pre_action/post_action adapter 设计，再做 12 attack type smoke。
4. `skills-safety-bench`：远端更新和 Codex/provider 链路稳定后复测 dry-run/单 case；正式 Codex runner 继续受 provider/CLI 稳定性影响。

统一方案见 [notes/clawsentry-evaluation-plan.md](notes/clawsentry-evaluation-plan.md)。
