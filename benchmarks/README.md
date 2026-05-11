# Benchmarks 工作区

这个目录用于集中管理安全评测 benchmark，目标是评估 agent 框架在被攻击任务中的表现，以及 ClawSentry 等防御系统的检测、拦截和审计效果。

约定：上游 benchmark 仓库尽量保持干净，不直接在 clone 目录里写本地说明、实验记录和长期结果。外层 `benchmarks/` 负责统一索引、运行规范和结果归档。

## 目录结构

```text
benchmarks/
  BENCHMARKS.md                 # benchmark 总登记表
  RUNBOOK.md                    # 跨 benchmark 的通用运行规范
  RESULTS.md                    # 跨 benchmark 的结果索引
  scripts/                      # 本地便捷运行脚本
  notes/<bench-slug>/           # 每个 benchmark 的本地说明
  results/<bench-slug>/         # 长期保存的运行结果，默认不入库
  skills-safety-bench/          # 上游 clone
  AgentDoG/                     # 上游 clone
  MSB/                          # 上游 clone
  skill-inject/                 # 上游 clone
```

## 当前已 clone 的 Benchmark

| bench | 来源 | 本地路径 | 当前用途 |
| --- | --- | --- | --- |
| `skills-safety-bench` | `git@github.com:jinchang1223/skills-safety-bench.git` | `skills-safety-bench/` | Harbor/Codex 静态攻击任务；6 个 RD / 155 case。 |
| `skill-inject` | `git@github.com:aisa-group/skill-inject.git` | `skill-inject/` | skill/package prompt injection benchmark；适合评估 skill static scan 与容器内 runtime hook/gateway 防护。 |
| `MSB` | `https://github.com/dongsenzhang/MSB.git` | `MSB/` | MCP/tool-use 攻击 benchmark；第三阶段评估 tool metadata/parameter/result/retrieval injection 防护。 |
| `agentdog-atbench` | `https://github.com/AI45Lab/AgentDoG.git` | `AgentDoG/` | trajectory-level safety replay；第三阶段与 MSB 并行做 offline labeled detection/audit。 |

详细登记见 [BENCHMARKS.md](BENCHMARKS.md)。统一 ClawSentry 评测方案见 [notes/clawsentry-evaluation-plan.md](notes/clawsentry-evaluation-plan.md)。

当前预期实验路线：`skills-safety-bench -> skill-inject -> MSB + ATBench`。优先从 `skills-safety-bench` 开始，因为它已有物化 case、manifest、Harbor/Codex runner 和历史 dry-run 证据，最方便先做直接 agent 执行实验。

## 本地说明文档

- [BENCHMARK_USER_GUIDE.md](BENCHMARK_USER_GUIDE.md) — 用户视角会议参考：作用、测试对象、case 结构、流程、指标和实例数。
- [notes/skills-safety-bench/SOURCE.md](notes/skills-safety-bench/SOURCE.md)
- [notes/skills-safety-bench/BENCHMARK_NOTES.md](notes/skills-safety-bench/BENCHMARK_NOTES.md)
- [notes/skills-safety-bench/RUNBOOK.md](notes/skills-safety-bench/RUNBOOK.md)
- [notes/skills-safety-bench/EVALUATION.md](notes/skills-safety-bench/EVALUATION.md)
- [notes/agentdog-atbench/SOURCE.md](notes/agentdog-atbench/SOURCE.md)
- [notes/agentdog-atbench/BENCHMARK_NOTES.md](notes/agentdog-atbench/BENCHMARK_NOTES.md)
- [notes/agentdog-atbench/RUNBOOK.md](notes/agentdog-atbench/RUNBOOK.md)
- [notes/msb/SOURCE.md](notes/msb/SOURCE.md)
- [notes/msb/BENCHMARK_NOTES.md](notes/msb/BENCHMARK_NOTES.md)
- [notes/msb/RUNBOOK.md](notes/msb/RUNBOOK.md)
- [notes/msb/EVALUATION.md](notes/msb/EVALUATION.md)
- [notes/skill-inject/SOURCE.md](notes/skill-inject/SOURCE.md)
- [notes/skill-inject/BENCHMARK_NOTES.md](notes/skill-inject/BENCHMARK_NOTES.md)
- [notes/skill-inject/RUNBOOK.md](notes/skill-inject/RUNBOOK.md)
- [notes/skill-inject/EVALUATION.md](notes/skill-inject/EVALUATION.md)

## 现在能确认什么

已确认：

- `skills-safety-bench` 当前本地 commit 为 `148133b`，本地 manifest 统计仍是 6 个风险域、30 个 category、155 个 case；历史 dry-run 已验证 RD1-RD6。计划中的远端更新未完成：SSH fetch 被 22 端口连接关闭，HTTPS fetch 需要凭据。
- `AgentDoG` 当前 commit 为 `09adfb8`，本地 ClawSentry offline replay runner 已有 sample smoke；正式分数仍需 labeled ATBench manifest。
- `MSB` 当前 commit 为 `c1d6a70`，本地数据包含 12 attack type、5 attack task、10 agent 场景、64 task-tool 对；可用于 ClawSentry MCP/tool boundary 评估，但需 adapter。
- `skill-inject` 当前 commit 为 `bf9fa1f`，本地数据包含 48 contextual injection、36 obvious injection、58 clean tasks、49 个 `SKILL.md`；可用于 ClawSentry skill injection 评估，但需容器内 hook/gateway 与 static scan。

当前路线判断：

- 第一阶段：`skills-safety-bench`，先做 dry-run / 单 case / 单 RD raw-vs-protected。
- 第二阶段：`skill-inject`，先做 static scan 和容器内 Codex 小样本。
- 第三阶段：`MSB` 与 `ATBench` 并行；MSB 补 MCP adapter，ATBench 补 labeled manifest。

尚未确认：

- skill-inject、MSB 与 ATBench 还没有运行 raw-vs-protected 或 labeled ClawSentry 正式样本。
- skills-safety-bench 的完整真实执行仍未拿到有效业务输出；当前阻塞与 Codex/provider 真实执行链路稳定性有关。
- Claude Code、OpenClaw、A3S-Code 的跨 benchmark 自动化 runner 仍需要对应框架的运行适配层。

## 快速入口

### skills-safety-bench dry-run

```bash
bash benchmarks/scripts/skills_safety_bench_codex.sh \
  --rd 1 \
  --case travel_planning_skill_name_decoy_singular_alias
```

### skill-inject 干跑预览

```bash
cd benchmarks/skill-inject
python scripts/smoke_test_all.py --agent codex --model gpt-5.2-codex --dry-run
```

### MSB 最小配置 smoke（后续执行阶段）

```bash
cd benchmarks/MSB
python agent_attack.py --cfg_path /tmp/msb-smoke.yml
python metrics.py --attack_type prompt_injection --attack_task obtain_agent_interaction_data --llm openai/gpt-4o-mini --agent llm_enhancement --mode llm
```

### AgentDoG / ATBench offline replay smoke（后续执行阶段）

```bash
python benchmarks/scripts/agentdog_atbench_clawsentry.py \
  --trajectory benchmarks/AgentDoG/examples/trajectory_sample.json \
  --output /tmp/agentdog-clawsentry-events.jsonl \
  --framework agentdog-atbench \
  --print-summary
```

## 安全边界

- 不修改当前开发者 `~/.codex`、当前 `CODEX_HOME` 或 OMX/user hooks。
- ClawSentry hooks 只安装到临时 `CODEX_HOME`、容器内 home 或 benchmark 专用配置目录。
- 上游 clone 内不写本地长期说明。
- `.env`、`docker/.env`、agent stdout、provider endpoint 和 API key 必须 redaction。
- `benchmarks/RESULTS.md` 不伪造分数；未跑正式样本只登记为“待正式运行/未出分”。
