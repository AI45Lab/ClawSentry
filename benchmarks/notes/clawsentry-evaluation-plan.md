# ClawSentry Benchmark 统一评测方案

## 目标

用统一、可复现、隔离的 benchmark 流水线回答两个问题：

1. ClawSentry 是否能发现或阻断 agent/skill/tool-use 安全风险？
2. ClawSentry 是否在降低攻击成功率的同时保持正常任务可用性？

本方案覆盖四个本地 benchmark：`skills-safety-bench`、`agentdog-atbench`、`MSB`、`skill-inject`。

## Benchmark 定位

| benchmark | 主要价值 | 当前状态 | ClawSentry 接入结论 | 推荐优先级 |
| --- | --- | --- | --- | ---: |
| `agentdog-atbench` | 轨迹级 offline labeled replay；验证检测/审计能力 | converter + ClawSentry sample replay 已跑通；正式 labeled 样本待准备 | 可先离线评估，不证明 runtime prevention | 1 |
| `skill-inject` | skill/package prompt injection 与 runtime CLI 防护 | 已 clone；本地 notes 已登记；未跑正式样本 | 可评估，但需容器内 hooks/gateway 与 static scan | 2 |
| `MSB` | MCP tool metadata/parameter/result/retrieval injection | 已 clone；本地 notes 已登记；未跑正式样本 | 可评估，但需 MCP adapter 才能完整覆盖 tool boundary | 3 |
| `skills-safety-bench` | 静态 Harbor/Codex 攻击任务，含 6 RD / 155 case | local commit `148133b`；远端更新尝试被 SSH/HTTPS 访问阻塞；历史 dry-run 已验证 | 可评估 Codex 路径；真实 runner 仍受 provider/CLI/Node 稳定性影响 | 4 |

## 统一指标

### Benchmark 原生指标

- `skills-safety-bench`：attack success、task output missing、evaluator error、基础任务完成率。
- `agentdog-atbench`：safe/unsafe label、judge verdict、trajectory taxonomy。
- `MSB`：ASR、PUA、NRP、mixed attack metrics、stage/tool split。
- `skill-inject`：ASR / attack_success、task completion、technical failure、LLM judge verdict。

### ClawSentry 防御指标

- `block_rate`、`defer_rate`、`modify_rate`、`allow_rate`。
- `unsafe_recall`：ground truth unsafe/attack-success 实例中，被 block/defer/high-risk 标记的比例。
- `safe_false_positive_rate`：ground truth safe/clean-success 实例中，被 block/defer/high-risk 标记的比例。
- `pre_action_coverage`、`post_action_coverage`、`pre_prompt/post_response coverage`。
- risk-level distribution：low/medium/high/critical。
- static scan recall（仅 skill/package benchmark）。

### 运行质量指标

- timeout、retry、technical failure。
- latency p50/p95。
- L2/L3 request count、token/cost。
- artifact completeness：events、decisions、summary、raw logs、redaction report 是否齐全。

## raw-vs-protected 对照规范

每个正式 run 必须有同一 case selection 的两组：

| 模式 | 说明 |
| --- | --- |
| `raw` | 目标 framework/agent 直接访问模型和工具，不经过 ClawSentry 防护。 |
| `clawsentry` | 同一 framework/agent 经 ClawSentry gateway、hook、AHP 或 MCP adapter。 |

控制变量：

- 相同 benchmark commit。
- 相同 case manifest / sample ids。
- 相同模型、temperature、timeout、parallelism。
- 相同容器 image 或 sandbox build artifact。
- 相同 judge model 与 judge prompt。

禁止把 technical failure 当作防御成功；必须单列 technical failure rate。

## 隔离与敏感信息要求

- 不改当前开发者 `~/.codex`、当前 `CODEX_HOME` 或 OMX/user hooks。
- ClawSentry hooks 只安装到临时 `CODEX_HOME`、容器内 home 或 benchmark 专用配置目录。
- 上游 clone 内不写本地说明；长期文档放 `benchmarks/notes/<bench-slug>/`。
- API keys、provider endpoint、`.env`、`docker/.env`、agent stdout 中的敏感值必须 redaction。
- 每次 run 都保留 `config.json/yml`，但只保存 redacted provider 信息。

## 推荐执行顺序

### 1. AgentDoG / ATBench offline labeled replay

目的：低风险验证 ClawSentry 轨迹检测与审计能力。

最小样本：`5 safe + 5 unsafe` labeled trajectories。

输出：unsafe recall、safe false-positive rate、pre/post coverage、L2/L3 latency/cost。

### 2. skill-inject small sample

目的：评估 skill injection static scan 与容器内 runtime 防护。

最小样本：`5 obvious + 5 contextual`，先 Codex，再 Claude/Gemini。

输出：static scan recall、runtime ASR 降幅、task completion、technical failure。

### 3. MSB 12 attack type smoke

目的：验证 MCP adapter 能覆盖 tool metadata、parameters、response、retrieval injection。

最小样本：每个 attack type 1 个实例，raw/protected 对照。

输出：ASR/PUA/NRP、pre_action/post_action coverage、risk distribution。

### 4. skills-safety-bench dry-run 与单 case 复测

目的：在上游 clone 可更新且 Codex/provider 链路稳定后复测 Harbor/Codex case。

当前注意：`git@github.com:jinchang1223/skills-safety-bench.git` fetch 因 SSH 22 端口连接关闭失败；HTTPS fetch 又需要凭据，未能更新到计划中提到的远端 HEAD。不要在未更新成功时伪造 commit 或结果。

## 结果目录模板

```text
benchmarks/results/<bench-slug>/<YYYY-MM-DD>_<model>_<framework>_<defense>_<scope>_<commit>/
  run.md
  config.json
  selected_cases.json
  raw_logs/
  events.jsonl
  decisions.jsonl
  summary.json
  summary.md
  redaction_report.md
```

`benchmarks/RESULTS.md` 只登记已完成或明确待运行的 run，不伪造 benchmark 分数。
