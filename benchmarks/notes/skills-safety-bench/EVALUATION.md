# skills-safety-bench 评估记录

## 2026-04-20 初次探索

源码 commit：

```text
7be1e1d6be65ac2ed4c81051937e91b6eb8efbe8
```

已确认：

- 仓库已 clone 到 `benchmarks/skills-safety-bench`。
- clone 后工作树干净。
- `benchmark/risk-domain-*/manifest.json` 下存在 6 个 manifest。
- manifest 统计共 155 个 case、6 个风险域、30 个 category。
- 上游批量入口可以 dry-run RD1-RD6。
- 代表性 case 具备预期的 `attacked_task/instruction.md` 和 `eval/verify_attack.py`。
- 上游自动化 runner 当前硬编码 Codex：`harbor run -a codex`。

dry-run 命令：

```bash
bash skills-safety-bench/scripts/start_codex_batch.sh --rd 1 --case travel_planning_skill_name_decoy_singular_alias --jobs-dir /tmp/ssb-dry-run-rd1-case --dry-run --skip-api-preflight
bash skills-safety-bench/scripts/start_codex_batch.sh --rd 1 --jobs-dir /tmp/ssb-dry-run-rd1 --dry-run --skip-api-preflight
bash skills-safety-bench/scripts/start_codex_batch.sh --rd 2 --jobs-dir /tmp/ssb-dry-run-rd2 --dry-run --skip-api-preflight
bash skills-safety-bench/scripts/start_codex_batch.sh --rd 3 --jobs-dir /tmp/ssb-dry-run-rd3 --dry-run --skip-api-preflight
bash skills-safety-bench/scripts/start_codex_batch.sh --rd 4 --jobs-dir /tmp/ssb-dry-run-rd4 --dry-run --skip-api-preflight
bash skills-safety-bench/scripts/start_codex_batch.sh --rd 5 --jobs-dir /tmp/ssb-dry-run-rd5 --dry-run --skip-api-preflight
bash skills-safety-bench/scripts/start_codex_batch.sh --rd 6 --jobs-dir /tmp/ssb-dry-run-rd6 --dry-run --skip-api-preflight
```

dry-run 结果：

| 范围 | 选中 case 数 | 状态 |
| --- | ---: | --- |
| RD1 单 case | 1 | 通过 |
| RD1 | 25 | 通过 |
| RD2 | 25 | 通过 |
| RD3 | 26 | 通过 |
| RD4 | 27 | 通过 |
| RD5 | 26 | 通过 |
| RD6 | 26 | 通过 |

真实执行阻塞项：

- `harbor` 不在 `PATH`。
- 当前 shell Node 版本是 `v20.18.1`；上游 README 建议 Node 22。nvm 中已有 `v22.22.2`。
- `.envrc` 包含看起来是真实的 API 配置，需按敏感信息处理。

## 当前结论

这个 benchmark 已经可以作为四框架安全评测的数据集和任务集使用。按当前实验路线，它是第一阶段优先启动项，因为 case、manifest、Harbor/Codex runner 和 dry-run 证据最完整，最方便先做直接 agent 执行实验；但目前仓库内开箱即用的自动化执行路径只确认支持 Codex。要完成 Claude Code、OpenClaw、A3S-Code 以及它们加 ClawSentry 的统一测试，需要补齐对应框架的 runner/adapter，并让结果输出仍能被 `eval/verify_attack.py` replay。


## 2026-05-01 状态补充

本地 `skills-safety-bench` 当前 commit 为 `148133b9db931419a72d203a78b7c17d8bbfea70`。计划中的远端更新未完成：SSH fetch 被 22 端口连接关闭，HTTPS fetch 需要凭据。当前文档和索引均按本地 commit 记录，不声明已更新到远端 HEAD。
