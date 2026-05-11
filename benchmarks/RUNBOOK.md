# Benchmark 通用运行规范

## 基本原则

- 上游 clone 尽量保持干净，本地说明放在 `notes/<bench-slug>/`。
- 长期运行结果放在 `results/<bench-slug>/<run-id>/`。
- 每次运行必须记录源码 commit、模型、框架、防御状态、命令、选择的 case 范围和环境说明。
- 根目录 `agent.hcl` / `.env.clawsentry` 可提交到私有开发仓库 `origin`，用于跨开发机复现实验。
- 不要把 API key、`.envrc` 密钥、完整模型 transcript 或外部服务凭据提交到公开仓库、公开文档、raw result 摘要或 benchmark 上游仓库。
- 先跑小范围 smoke，再跑整个 risk domain 或全量 benchmark。

## 结果目录命名

建议格式：

```text
results/<bench-slug>/<YYYY-MM-DD>_<model>_<framework>_<defense>_<scope>_<short-commit>/
```

示例：

```text
results/skills-safety-bench/2026-04-20_gpt-5.4_codex_raw_rd1_7be1e1d/
results/skills-safety-bench/2026-04-20_gpt-5.4_codex_clawsentry_rd1_7be1e1d/
results/agentdog-atbench/2026-04-27_gpt-5.5_offline_clawsentry_sample_09adfb8/
```

完整运行后，理想情况下至少保留：

```text
run.md
batch_config.json
selected_cases.json
summary.md
summary.json
summary.csv
attack_results.md
attack_results.json
attack_results.csv
logs/
artifacts/
```

## 运行前检查清单

1. `git -C <bench-dir> status --short` 确认源码状态。
2. `git -C <bench-dir> rev-parse HEAD` 记录源码版本。
3. 检查运行时依赖。
4. 在私有开发仓库中读取本地 API/CLI 配置基线，优先使用 2026-05-11 已验证的用户指定 CLI/API 搭配。
5. 需要长实验前，复跑 `python benchmarks/scripts/api_connectivity.py --chat --target <name>`，确认目标 provider 仍可用。
6. dry-run 或 manifest parse。
7. 小范围 smoke case。
8. 将结果归档到 `results/<bench-slug>/`。
9. 在 [RESULTS.md](RESULTS.md) 记录摘要。

## 默认 CLI/API 搭配

后续实验默认使用以下已验证配置，除非实验目标明确要求换模型或换 provider：

| CLI | API 来源 | Model | 配置要点 | 证据 |
| --- | --- | --- | --- | --- |
| Codex | ailab 本地 MiniMax | `MiniMax-2.7-w8a8` | 临时 `CODEX_HOME`；`wire_api="responses"`；`OPENAI_API_KEY=dummy` | `results/api-connectivity/2026-05-11-requested-cli-smoke.md` |
| Codex | ailab 本地 GLM | `glm-5` | 临时 `CODEX_HOME`；`wire_api="responses"`；`OPENAI_API_KEY=dummy` | `results/api-connectivity/2026-05-11-requested-cli-smoke.md` |
| Claude Code | ailab 本地 MiniMax | `MiniMax-2.7-w8a8` | `--setting-sources project`；`ANTHROPIC_BASE_URL` 指向私有开发配置中的 provider root URL | `results/api-connectivity/2026-05-11-requested-cli-smoke.md` |
| Claude Code | ailab 本地 GLM | `glm-5` | `--setting-sources project`；`ANTHROPIC_BASE_URL` 指向私有开发配置中的 provider root URL | `results/api-connectivity/2026-05-11-requested-cli-smoke.md` |
| Kimi CLI | ailab 本地 Kimi | `kimi-k2.5` | 显式追加 ailab host 到 `NO_PROXY/no_proxy` | `results/api-connectivity/2026-05-11-requested-cli-smoke.md` |
| Gemini CLI | 博越 Gemini relay | `gemini-3-flash-preview` | `GEMINI_API_KEY=<redacted>`；`GOOGLE_GEMINI_BASE_URL` 指向私有开发配置中的 relay root URL | `results/api-connectivity/2026-05-11-requested-cli-smoke.md` |

排查结论：

- Codex 0.130 不再支持 `wire_api="chat"`；ailab MiniMax/GLM 必须走 Responses。
- Claude Code 用户级 `~/.claude/settings.json` 可能覆盖临时 env；第三方 provider smoke 用 `--setting-sources project`。
- 当前 shell 代理会让 Kimi CLI 访问 ailab Kimi 返回 502；显式 `NO_PROXY/no_proxy` 后通过。
- Gemini CLI 可通过底层 `@google/genai` 的 `GOOGLE_GEMINI_BASE_URL` 指向私有 relay；公开文档不得记录真实 endpoint。

## 裸执行 vs 加防御

裸执行：

- agent 框架直接访问模型 endpoint。
- 结果用于得到 baseline ASR。

加 ClawSentry：

- agent 框架访问 ClawSentry gateway。
- ClawSentry 再转发到真实模型 endpoint。
- 结果用于观察 ASR 是否下降，以及是否产生误拦截、任务失败或成本变化。

关键是保持 benchmark、case 范围、模型、超时和重试参数一致，只替换“模型访问路径”和防御开关。

## AgentDoG / ATBench offline replay

按当前总路线，ATBench 放在第三阶段，与 MSB 并行推进；它不再是最先启动的 benchmark。进入 ATBench 阶段后，AgentDoG lane 的第一步不跑真实 agent，而是先把已有 trajectory 转换为 ClawSentry event JSONL：

```bash
python benchmarks/scripts/agentdog_atbench_clawsentry.py \
  --trajectory benchmarks/AgentDoG/examples/trajectory_sample.json \
  --output /tmp/agentdog-clawsentry-events.jsonl \
  --framework agentdog-atbench \
  --print-summary
```

这个模式用于验证检测收益：unsafe recall、safe false-positive rate、pre-action coverage、post-action coverage、taxonomy-to-D1-D6 correlation、latency 和 L2/L3 cost。live runner 稳定前，不要把 offline replay 结果表述为“已证明真实框架可阻止动作”。

## 五框架单 case ingress smoke

在开发真实 live runner 前，可以先用统一 smoke 验证五个框架的
ClawSentry ingress path 都能把同一个危险 shell case 送到 Gateway，并得到
阻断类决策：

```bash
python benchmarks/scripts/framework_single_case_smoke.py \
  --result-dir /tmp/clawsentry-framework-single-case \
  --print-summary
```

覆盖路径：

- `a3s-code`：AHP JSON-RPC event -> `A3SGatewayHarness` -> UDS Gateway
- `claude-code`：Claude Code `PreToolUse` hook shape -> harness -> UDS Gateway
- `codex`：HTTP `POST /ahp/codex`
- `gemini-cli`：Gemini `BeforeTool` / `run_shell_command` hook shape -> harness -> UDS Gateway
- `openclaw`：OpenClaw `exec.approval.requested` adapter -> UDS Gateway

产物：

```text
/tmp/clawsentry-framework-single-case/
  summary.json
  summary.md
```

边界：这个 smoke 不启动真实 Claude Code、Codex、Gemini CLI、a3s-code 或
OpenClaw 进程，也不作为 raw-vs-protected baseline。它只证明当前仓库内五个
framework ingress path 可达，并能对同一个危险单 case 产生 block/defer/deny。
