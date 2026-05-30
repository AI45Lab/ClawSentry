---
title: Benchmark 模式
description: 以非交互、可复现、不会污染用户 CODEX_HOME 的方式运行 ClawSentry 安全评测
---

<section class="cs-doc-hero cs-doc-hero--ops" markdown>
<div class="cs-eyebrow">ClawSentry 评测运维</div>
## Benchmark 模式
以非交互、可复现、不会污染用户 CODEX_HOME 的方式运行 ClawSentry 安全评测。
<div class="cs-actions" markdown>
[快速开始](#quick-run){ .md-button .md-button--primary }
[框架支持矩阵](#framework-matrix){ .md-button }
[Codex 集成](../integration/codex.md){ .md-button }
</div>
</section>

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
  <your-command>
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
| DEFER bridge 不可用 | 等待或按超时策略处理 | 不等待；按 benchmark policy 处理 |
| Gateway 不可达 | 依框架 fallback 策略 | 依框架 fallback 策略；仍记录诊断 |

Benchmark 模式不会让“需要人确认”的操作静默通过。默认策略是 `block`，这样无人值守运行更保守、更容易审计。

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

## 支持的无人值守框架 {#framework-matrix}

Benchmark 模式用于 CI、安全回归和临时沙箱运行。当前公开文档只说明可用框架和运行边界，不承诺任何内部评测矩阵或结果。

| 框架 | 支持状态 | 说明 |
|---|---|---|
| Codex | 支持 | 原生 hook 隔离；使用临时 `CODEX_HOME` |
| Claude Code | 支持 | `UserPromptSubmit` prompt hook 阻断语义 |
| Kimi CLI | 支持 | Skill Trust runtime metadata 接线统一 |
| Gemini CLI | 支持 | Skill Trust runtime metadata 接线统一 |
| a3s-code | 参考集成 | 适合显式 SDK transport 验证；是否纳入某个外部评测由对应 runner 决定 |

---

## L3 Multi-turn 配置说明 {#l3-multi-turn}

从 v0.7.4 起，L3 AgentAnalyzer **默认**启用多轮审查模式。无人值守 benchmark profile 建议显式设置 `CS_L3_MULTI_TURN=true`，与公开运行时默认模式一致。

```bash
# 无人值守 benchmark / CI 环境中建议显式设置：
CS_L3_MULTI_TURN=true
```

如果需要回退到 legacy 单轮模式（仅用于对比测试），可显式设置：

```bash
CS_L3_MULTI_TURN=false  # 或 0 / no / off
```

!!! note "默认行为"
    生产环境和 benchmark 环境都应使用默认多轮模式。只有在需要复现 v0.7.3 及更早行为时才关闭。

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
