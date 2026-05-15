# Benchmark 结果索引

这里记录可以公开复现或公开描述的 benchmark 验证摘要。私有 provider、endpoint、凭据、完整 transcript、raw run 目录和未脱敏结果只保存在私有开发环境，不同步到公开仓库。

| 日期 | benchmark | 范围 | 命令 | 状态 | 公开结论 |
| --- | --- | --- | --- | --- | --- |
| 2026-05-15 | `ahp-policy-replay` | compound / taint fixture pack | `python benchmarks/scripts/ahp_policy_replay.py benchmarks/fixtures/ahp-policy-regression/skills_safety_bench_smoke.jsonl /tmp/clawsentry-ssb-smoke-replay --fail-under-decision-match 1.0 --max-unsafe-pass 0.0 --max-overblock 0.0` | 通过 | 18 cases；`decision_match_rate=1.0`、`unsafe_pass_proxy=0.0`、`overblock_proxy=0.0`、`evidence_coverage=1.0`、`schema_sync_coverage=1.0`。这是 offline policy-regression gate，不是 ASR/TSR/TFR 正式分数。 |
| 2026-05-15 | `skills-safety-bench` | targeted feedback-loop verifier | `python benchmarks/scripts/skills_safety_bench_e2e_verify.py benchmarks/fixtures/skills-safety-bench-v073-feedback-loop-summary.json /tmp/clawsentry-ssb-e2e-verify` | 通过 | targeted summary gate：`ASR=0.0`、`TSR=1.0`、`TFR=0.0`、`unsafe_retry_drop_rate=0.833333`、`canonical_retry_success_rate=1.0`。不是完整 CV/RD sweep。 |
| 2026-05-15 | `skills-safety-bench` | targeted config sweep | `python benchmarks/scripts/skills_safety_bench_config_sweep.py /tmp/clawsentry-ssb-config-sweep benchmarks/fixtures/skills-safety-bench-v073-config-sweep-raw.json benchmarks/fixtures/skills-safety-bench-v073-config-sweep-protected.json` | 通过 | protected profile 满足 gate，保留 raw-normalized task success、unsafe retry drop、canonical retry success、evidence coverage 和 schema coverage 字段。 |
| 2026-05-15 | `ahp-policy-replay` | policy-drift metric-cell traceability | `python benchmarks/scripts/ahp_policy_replay.py benchmarks/fixtures/ahp-policy-regression/v08_metric_cell_traceability.jsonl /tmp/clawsentry-traceability-replay --fail-under-decision-match 1.0 --max-unsafe-pass 0.0 --max-overblock 0.0` | 通过 | `metric_cell_traceability.passed=true`、2 cells、`coverage=1.0`；每个 metric cell 可追溯到 request id、registry state、rule evidence、fallback path 和 adapter effect result id。 |

## 边界

- 上表是 v0.7.0 发布使用的可公开 targeted replay/readiness evidence，不代表完整 leaderboard 或全 benchmark 排名。
- 私有真实 provider 配置、模型路由、运行目录、失败 transcript 和 raw artifacts 不进入公开仓库。
- 公开仓库只保留可脱敏复现的 fixture、脚本和 summary-level 结论。
- 完整 raw-vs-protected sweep、更多框架真实运行和第三方 benchmark adapter 仍按后续里程碑推进。
