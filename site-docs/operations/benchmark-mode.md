---
title: Benchmark 模式
description: 以非交互、可复现、不会污染用户 CODEX_HOME 的方式运行 ClawSentry 安全评测
---

# Benchmark 模式

Benchmark 模式面向 CI、安全评测和可复现实验。它和日常 `normal` 模式最大的区别是：**不会等待人工审批**。

- pre-action 如果本来会进入 `DEFER`，benchmark 默认确定性转成 `block`
- 返回/记录的元数据会包含 `auto_resolved=true`、`auto_resolve_mode=benchmark`、`original_verdict=defer`
- Codex hook 安装必须使用临时 `CODEX_HOME`；CLI 默认拒绝修改正在使用的 `~/.codex`

!!! warning "不要在自动化评测里使用真实 `~/.codex`"
    `clawsentry benchmark enable/run` 要求显式传入 `--codex-home`，并会拒绝默认用户目录，除非你手动加 `--force-user-home`。CI 和测试脚本应始终使用 `mktemp -d`。

---

## 最短可运行流程 {#quick-run}

```bash
export CS_CODEX_HOME="$(mktemp -d)"

clawsentry benchmark env --framework codex --mode guarded > .clawsentry.benchmark.env
clawsentry benchmark enable --dir . --framework codex --codex-home "$CS_CODEX_HOME"
clawsentry benchmark run --dir . --framework codex --codex-home "$CS_CODEX_HOME" -- \
  bash benchmarks/scripts/skills_safety_bench_codex.sh
clawsentry benchmark disable --dir . --framework codex --codex-home "$CS_CODEX_HOME"
```

如果只想准备环境、不立刻运行评测命令：

```bash
clawsentry benchmark run --dir . --framework codex --codex-home "$CS_CODEX_HOME"
```

---

## 什么时候使用 benchmark 模式？ {#when-to-use}

| 场景 | 推荐 | 原因 |
|---|---|---|
| 本地第一次体验 | `normal` | 先看清 Gateway/Web UI/日志，不需要特殊 hook 隔离 |
| 团队日常开发 | `normal` 或 `strict` | 可保留人工 DEFER 审批 |
| CI 安全回归 | `benchmark` | 不能卡在人工审批队列 |
| 论文/报告中的安全评测 | `benchmark` | 每次运行都能复现同一决策路径 |
| 想临时测试 Codex hook | `benchmark` + 临时 `CODEX_HOME` | 避免污染正在使用的 Codex 配置 |

---

## 决策语义 {#decision-semantics}

| 原始情况 | normal 模式 | benchmark 默认 |
|---|---|---|
| L1/L2/L3 返回 `allow` | 放行 | 放行 |
| L1/L2/L3 返回 `block` | 阻断 | 阻断 |
| L1/L2/L3 返回 `defer` | 进入人工审批队列 | 自动转为 `block` 并标记 auto-resolved |
| SC-4 persistence-write 命中 | `auto` 默认同步 `force_l3`；也可显式 audit/defer/block | `auto` 解析为 `block`；safe-shell allowlist 不覆盖 SC-4 |
| DEFER bridge 不可用 | 等待或按超时策略处理 | 不等待；按 benchmark policy 处理 |
| Gateway 不可达 | 依框架 fallback 策略 | 依框架 fallback 策略；仍记录诊断 |

SC-4 记录的是未来自动执行/重入入口写入风险。benchmark 结果里可能只有 guard verdict 和 telemetry，而没有最终 task artifact；这不是触发前提，也不应被误读为 benchmark 专用规则。

Benchmark 模式不会让“需要人确认”的操作静默通过。默认策略是 `block`，这样评测结果更保守、更容易审计。

## 实验结果口径 {#experiment-metrics}

安全评测报告应把模型/CLI 运行失败和 ClawSentry 策略效果分开记录。推荐至少同时报告：

- ASR：非技术失败 safety cases 中的 attack success 比例。
- TSR：非 infra/agent/evaluator 技术失败 cases 中的 task success 比例。若
  agent 已运行且缺输出是策略阻断或模型未完成造成，应计入 TSR 分母。
- TFR：所有 attempted cases 中的 infra/agent/evaluator technical failure 比例。
- Raw-normalized TSR：protected TSR / matching raw TSR。
- Split failure rates：`infra_tfr`、`agent_tfr`、`evaluator_tfr`、
  `policy_task_failure_rate`、`model_task_failure_rate`。

当 TFR 高于实验门槛时，不应把最低 ASR 配置直接选为默认配置。先拆分
`infra_tfr`、`agent_tfr` 与 `evaluator_tfr`：它们包括 harness setup、依赖安装、
Docker/socket、CLI/provider timeout、verifier/artifact 权限等基础设施问题。
策略阻断、DEFER 自动处理或 hook 行为导致的 task output missing 不应伪装成
technical failure；应记录为 `policy_task_failure_rate` 并进入 TSR 分母。模型
已运行但未写输出则记录为 `model_task_failure_rate`。

---

## CLI 命令说明 {#commands}

### 生成 benchmark env

```bash
clawsentry benchmark env --framework codex --mode guarded > .clawsentry.benchmark.env
```

生成内容包括：

```bash
CS_MODE=benchmark
CS_BENCHMARK_PROFILE=guarded
CS_BENCHMARK_AUTO_RESOLVE_DEFER=true
CS_DEFER_BRIDGE_ENABLED=false
CS_DEFER_TIMEOUT_ACTION=block
CS_DEFER_TIMEOUT_S=1
# Older wrappers may also emit CS_FRAMEWORK=codex for harness compatibility.
```

### 启用 hooks

```bash
clawsentry benchmark enable --dir . --framework codex --codex-home "$CS_CODEX_HOME"
```

该命令会在临时 Codex home 下写入 `.codex/hooks.json` 等 benchmark 所需配置。已有 hook 文件会备份，重复运行不会重复追加 ClawSentry entries。

### 包裹一次评测命令

```bash
clawsentry benchmark run --dir . --framework codex --codex-home "$CS_CODEX_HOME" -- <your-command>
```

`run` 会设置 `CODEX_HOME` 和 benchmark 环境变量，执行命令后自动清理；如果需要保留现场用于排障，使用 `--keep-artifacts`。

### 禁用并清理

```bash
clawsentry benchmark disable --dir . --framework codex --codex-home "$CS_CODEX_HOME"
```

---

## 验证清单 {#checklist}

- [ ] `CODEX_HOME` 指向临时目录，不是 `~/.codex`
- [ ] `clawsentry config show --effective` 显示 `mode=benchmark` 或 benchmark env 已加载
- [ ] 评测命令不会打开交互式审批界面
- [ ] DEFER 事件在结果中带有 `auto_resolved=true`
- [ ] 运行结束后执行 `clawsentry benchmark disable`

相关页面：

- [配置模板：CI / benchmark](../configuration/templates.md#ci-benchmark-operator)
- [Codex 集成](../integration/codex.md)
- [CLI 命令：benchmark](../cli/index.md#clawsentry-benchmark)
