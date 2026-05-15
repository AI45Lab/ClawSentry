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
  skills-safety-bench/          # 上游 clone/submodule
  AgentDoG/                     # 上游 clone/submodule
  MSB/                          # 上游 clone/submodule
  skill-inject/                 # 上游 clone/submodule
```

## 当前已 clone 的 Benchmark

| bench | 来源 | 本地路径 | 当前用途 |
| --- | --- | --- | --- |
| `skills-safety-bench` | `git@github.com:jinchang1223/skills-safety-bench.git` | `skills-safety-bench/` | Harbor/Codex 静态攻击任务；6 个 RD / 155 case。 |
| `skill-inject` | `git@github.com:aisa-group/skill-inject.git` | `skill-inject/` | skill/package prompt injection benchmark；适合评估 skill static scan 与容器内 runtime hook/gateway 防护。 |
| `MSB` | `https://github.com/dongsenzhang/MSB.git` | `MSB/` | MCP/tool-use 攻击 benchmark；第三阶段评估 tool metadata/parameter/result/retrieval injection 防护。 |
| `agentdog-atbench` | `https://github.com/AI45Lab/AgentDoG.git` | `AgentDoG/` | trajectory-level safety replay；第三阶段与 MSB 并行做 offline labeled detection/audit。 |

详细登记见 [BENCHMARKS.md](BENCHMARKS.md)。统一 ClawSentry 评测方案见 [notes/clawsentry-evaluation-plan.md](notes/clawsentry-evaluation-plan.md)。私有实验 API/CLI 配置基线保存在开发仓库本地材料中，不同步到公开仓库。

当前预期实验路线：`skills-safety-bench -> skill-inject -> MSB + ATBench`。优先从 `skills-safety-bench` 开始，因为它已有物化 case、manifest、Harbor/Codex runner 和历史 dry-run 证据，最方便先做直接 agent 执行实验。

正式实验默认使用私有开发环境中验证过的 provider 配置。具体 endpoint、key 来源、隔离方式和排查结论只保存在私有材料中，不同步到公开仓库。

## 新开发机恢复

私有开发仓库允许保存 benchmark 复现所需的本地 agent 配置和环境模板。另一台开发机 clone 后，先恢复 submodule，再在私有环境跑 provider connectivity smoke：

```bash
git clone git@github.com:Elroyper/A3S-Monitor.git
cd A3S-Monitor
git submodule update --init --recursive
# Run the private connectivity smoke used by your development environment.
```

注意：`skill-inject` 与 `skills-safety-bench` 使用私有 SSH URL，clone 机器的 GitHub 账号需要对应访问权限。公开仓库同步仍排除这些上游源码、raw results 和所有真实 key/token。

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
- 2026-05-15 已取得一个私有 protected real-run 单 case readiness 结果，业务输出和 ClawSentry evidence 均有效；该证据不作为全量 sweep 或 leaderboard 结论。
- 2026-05-15 已生成一个单 case protected-vs-pinned-raw aggregate，并通过 `skills_safety_bench_e2e_verify.py`。该结果只证明单 case readiness，不是 RD/CV12 sweep。
- `AgentDoG` 当前 commit 为 `09adfb8`，本地 ClawSentry offline replay runner 已有 sample smoke；正式分数仍需 labeled ATBench manifest。
- `MSB` 当前 commit 为 `c1d6a70`，本地数据包含 12 attack type、5 attack task、10 agent 场景、64 task-tool 对；可用于 ClawSentry MCP/tool boundary 评估，但需 adapter。
- `skill-inject` 当前 commit 为 `bf9fa1f`，本地数据包含 48 contextual injection、36 obvious injection、58 clean tasks、49 个 `SKILL.md`；可用于 ClawSentry skill injection 评估，但需容器内 hook/gateway 与 static scan。

当前路线判断：

- 第一阶段：`skills-safety-bench`，先做 dry-run / 单 case / 单 RD raw-vs-protected。
- 第二阶段：`skill-inject`，先做 static scan 和容器内 Codex 小样本。
- 第三阶段：`MSB` 与 `ATBench` 并行；MSB 补 MCP adapter，ATBench 补 labeled manifest。

尚未确认：

- skill-inject、MSB 与 ATBench 还没有运行 raw-vs-protected 或 labeled ClawSentry 正式样本。
- skills-safety-bench 的完整真实执行仍未完成；当前只有一个 protected 单 case 有有效业务输出和 e2e aggregate。更多 pairings/RD、完整 raw-vs-protected、默认 profile 选择仍未闭环。
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

### AHP policy replay / gate smoke

这些命令是离线 policy-regression gate，不是端到端 ASR/TSR/TFR 正式分数。它们用于在真实 benchmark sweep 前检查 replay schema、fallback、evidence coverage、unsafe-pass proxy 和 false-positive proxy。

```bash
python benchmarks/scripts/ahp_policy_replay.py \
  benchmarks/fixtures/ahp-policy-regression/skills_safety_bench_smoke.jsonl \
  /tmp/clawsentry-ssb-smoke-replay

python benchmarks/scripts/skills_safety_bench_config_sweep.py \
  /tmp/clawsentry-ssb-smoke-sweep \
  /tmp/clawsentry-ssb-smoke-raw.json \
  /tmp/clawsentry-ssb-smoke-protected.json

python benchmarks/scripts/skills_safety_bench_e2e_verify.py \
  /tmp/clawsentry-ssb-e2e-summary.json \
  /tmp/clawsentry-ssb-e2e-verify
```

当前 fixture pack 覆盖 safe read false-positive guard、remote fetch -> interpreter、sensitive source -> network sink、skill alias/provenance conflict。`skills_safety_bench_config_sweep.py` 只选择满足 `raw_normalized_TSR >= 0.90`、`TFR <= 0.10`、`evidence_coverage=1.0`、`schema_sync_coverage=1.0` 的 protected profile。

2026-05-15 v0.7.2 replay evidence uses the
same fixture pack with 18 cases and now covers remote fetch -> interpreter,
sensitive source -> network sink, archive extract -> execute, bulk destructive
chain, persistence entrypoint write, and benign archive/find false-positive
guards. Replay metrics: `decision_match_rate=1.0`, `unsafe_pass_proxy=0.0`,
`overblock_proxy=0.0`, `evidence_coverage=1.0`, `schema_sync_coverage=1.0`.
These are offline policy-regression metrics, not ASR/TSR/TFR.

2026-05-15 v0.7.3 targeted feedback-loop evidence verifies a
critical-block feedback summary with `unsafe_retry_drop_rate=0.833333`,
`canonical_retry_success_rate=1.0`, supported-host feedback delivery, and
unsupported-host audit fallback. The config sweep carries those fields into
leaderboard/default selection.
This is a targeted integration/replay gate, not full CV12.

2026-05-15 v0.8.x targeted traceability evidence verifies
that policy-drift metric cells can be traced to request ids, registry states,
rule evidence, fallback paths, and adapter effect result ids. The targeted
gate reports `coverage=1.0` and `passed=true`. This is replay/report
traceability evidence, not the full UI/productization scope.

## 安全边界

- 不修改当前开发者 `~/.codex`、当前 `CODEX_HOME` 或 OMX/user hooks。
- ClawSentry hooks 只安装到临时 `CODEX_HOME`、容器内 home 或 benchmark 专用配置目录。
- 上游 clone 内不写本地长期说明。
- 私有开发仓库 `origin` 可以保存根目录 `agent.hcl` / `.env.clawsentry` 以复现实验；公开仓库、公开文档、raw stdout/transcript 和长期结果摘要仍必须 redaction。
- `.env`、`docker/.env`、agent stdout、provider endpoint 和 API key 不进入 `clawsentry-public`。
- `benchmarks/RESULTS.md` 不伪造分数；未跑正式样本只登记为“待正式运行/未出分”。
