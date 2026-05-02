# skills-safety-bench 说明

`skills-safety-bench` 是一个已经物化好的静态 benchmark。它不是用来动态生成攻击 case 的框架，而是直接提供可执行的攻击任务集合。

## 目录结构

```text
skills-safety-bench/
  README.md
  benchmark/
    readme.md
    risk-domain-1-.../
      manifest.json
      summary.md
      category.../
        <case_id>/
          metadata.json
          rationale.md
          attacked_task/
          eval/verify_attack.py
    ...
    risk-domain-6-.../
  scripts/
    start_codex_batch.sh
    run_manifest_codex_batch.py
    verify_replay.py
  .envrc
```

## 覆盖范围

| 风险域 | case 数 | category 数 |
| --- | ---: | ---: |
| RD1 上下文信任与提示操纵风险 | 25 | 5 |
| RD2 代理权限、授权与任务范围风险 | 25 | 5 |
| RD3 执行、运行时、框架与协议风险 | 26 | 5 |
| RD4 数据边界、输出与外发风险 | 27 | 5 |
| RD5 记忆、恢复、审计与持久化风险 | 26 | 5 |
| RD6 知识、模型、供应链与运行风险 | 26 | 5 |
| 合计 | 155 | 30 |

## 单个 case 的形态

每个 case 都遵循这个结构：

```text
benchmark/<risk-domain>/<category>/<case>/
  metadata.json
  rationale.md
  attacked_task/
    instruction.md
    task.toml
    environment/
    solution/solve.sh
    tests/test.sh
    tests/test_outputs.py
  eval/verify_attack.py
```

含义：

- `attacked_task/`：交给目标 agent 执行的任务。
- `attacked_task/tests/test_outputs.py`：检查基础任务是否完成。
- `eval/verify_attack.py`：检查攻击行为是否被诱导出来。
- `metadata.json`：机器可读的 case 元数据。
- `rationale.md`：人工可读的 case 设计说明。

## 当前 runner 行为

上游主要入口：

```bash
bash skills-safety-bench/scripts/start_codex_batch.sh --rd <1-6>
```

常用筛选参数：

```bash
--case <case_id>
--category <category_id>
--manifest <path/to/manifest.json>
--jobs-dir <path>
--model <provider/model>
--network-mode host
--dry-run
--skip-api-preflight
```

重要限制：当前上游 runner 会逐个 case 调用 `harbor run -a codex`，所以已确认的自动化路径是 Codex。Claude Code、OpenClaw、A3S-Code 需要额外 runner 或 Harbor agent backend 才能做到同等自动化。

runner 完成后会 replay 每个 case 的 `eval/verify_attack.py`，并生成 `attack_results.json`、`attack_results.csv`、`summary.json`、`summary.md` 等结果文件。
