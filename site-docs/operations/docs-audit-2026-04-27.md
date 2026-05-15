---
title: Docs audit：recent feature coverage
排除: false
description: 2026-04-27 ClawSentry 在线文档优化的源证据、覆盖矩阵与后续检查清单
---

# Docs audit：recent feature coverage（2026-04-27）

本页是本轮 docs-only 优化的可追溯清单：每一项 recent feature 都映射到源码/验证材料、当前文档入口、API/UI/CLI surface 与本轮动作。它用于防止在线文档只改首页而漏掉近期交付能力。

!!! note "范围边界"
    本轮只更新文档、MkDocs 导航与共享 CSS。不会实现 `clawsentry setup` 或新的交互式 CLI 向导；相关行为只能在单独 CLI lane 中实现并测试。

## 覆盖矩阵 {#coverage-matrix}

| Feature / capability | Source evidence | Docs page(s) | Surface | Status | 本轮动作 |
|---|---|---|---|---|---|
| L3 advisory jobs / full-review | `site-docs/decision-layers/l3-advisory.md`; Gateway report/L3 endpoints in `site-docs/api/reporting.md` | [L3 咨询审查](../decision-layers/l3-advisory.md), [报表与监控](../api/reporting.md) | Web UI Session Detail、`clawsentry l3 full-review`、`/report/l3/*` | Covered | 保持 advisory-only 边界；移除 page-local CSS，改用共享 `.cs-*` 组件。 |
| Heartbeat / idle aggregate queueing | `decision-layers/l3-advisory.md` queued-job sections; validation docs under `docs/validation/l3-advisory-heartbeat-drain-*` | [L3 咨询审查](../decision-layers/l3-advisory.md) | CLI jobs list/run-next/drain、watch/SSE | Covered | 确认在矩阵中显式列出，避免只在正文深处出现。 |
| Gemini CLI hooks | `site-docs/integration/gemini-cli.md`; `mkdocs.yml` integration nav | [Gemini CLI 集成](../integration/gemini-cli.md), [CLI 命令](../cli/index.md) | Native command hooks prompt/model/tool | Covered | 首页/Quickstart 框架卡继续链接；本轮不改 runtime。 |
| Benchmark mode | `site-docs/operations/benchmark-mode.md`; benchmark commands in CLI docs | [Benchmark 模式](benchmark-mode.md), [配置模板](../configuration/templates.md#ci-benchmark-operator) | `clawsentry benchmark *`, temporary `CODEX_HOME` | Covered | 配置模板重写为无人值守路径，强调 DEFER auto-resolve 和临时 Codex home。 |
| Metric/window fields | `src/clawsentry/gateway/session_registry.py`, `server.py`, UI types/pages | [指标字典](../api/metric-dictionary.md), [Web 仪表板](../dashboard/index.md) | `/report/sessions`, `/report/session/{id}/risk`, Dashboard/Sessions/Session Detail | Updated | 增加 canonical/alias/legacy 表、D1-D6、UI/API 读取示例。 |
| Web UI L3 surfaces | `src/clawsentry/ui/src/pages/SessionDetail.tsx`; v0.5.10 validation doc | [Web 仪表板](../dashboard/index.md), [L3 咨询审查](../decision-layers/l3-advisory.md) | Session Detail advisory card/action summary | Covered | 保持 Dashboard 说明；矩阵记录 L3 surfaces。 |
| Token budget / LLM usage | CLI config/test-llm docs; `configuration/llm-config.md`; UI token usage copy | [LLM 配置](../configuration/llm-config.md), [配置模板](../configuration/templates.md#team-l2-budgeted) | `clawsentry test-llm --json`, Web UI token usage | Updated | 模板按 L2 budgeted / strict L3 拆分，并说明 provider/key 来源。 |
| Multi-framework startup | `site-docs/getting-started/quickstart.md`; integration pages | [快速开始](../getting-started/quickstart.md), integration pages | `clawsentry start --framework <name>` | Updated | Quickstart 改为“观察路径 + L2/L3-ready 路径”，框架能力表保留。 |
| Latch integration | `site-docs/integration/latch.md`; homepage card | [Latch 集成](../integration/latch.md), [首页](../index.md) | Mobile monitoring / remote approval | Covered | 保持可选增强定位；不把它写成必需组件。 |
| OpenClaw managed setup boundaries | `site-docs/integration/openclaw.md`; API webhook docs | [OpenClaw 集成](../integration/openclaw.md), [Webhook API](../api/webhooks.md) | WebSocket approval events / webhook receiver | Covered | 矩阵明确 OpenClaw 是集成边界；本轮不改 adapter 行为。 |
| Codex managed setup boundaries | `site-docs/integration/codex.md`; CLI docs managed native hooks | [Codex CLI 集成](../integration/codex.md), [快速开始](../getting-started/quickstart.md) | Session log monitoring + optional native hooks | Covered | Quickstart 继续说明 Codex 默认监控、可选 Bash preflight/approval gate。 |
| Current config wizard behavior | `src/clawsentry/cli/main.py`, `src/clawsentry/cli/config_command.py` | [快速开始](../getting-started/quickstart.md), [配置模板](../configuration/templates.md) | `clawsentry config wizard` | Updated | 明确它是确定性配置生成器，不承诺丰富交互向导。 |

## 页面处理清单 {#page-checklist}

| Page | 本轮状态 | 检查点 |
|---|---|---|
| `getting-started/quickstart.md` | Updated | 默认旅程不再只推 L1-only；提供 observation 与 L2/L3-ready 两条路径。 |
| `configuration/templates.md` | Rewritten | 按 L3 延迟、启用方式、部署时长、严格度、预算/provider 组织。 |
| `api/metric-dictionary.md` | Rewritten | canonical/alias/legacy、D1-D6、API/UI 示例齐全。 |
| `decision-layers/l2-semantic.md` | Updated | 顶部增加 L1/L2/L3/operator summary。 |
| `decision-layers/l3-agent.md` | Updated | 顶部增加同步 L3 vs advisory L3 对照。 |
| `decision-layers/l3-advisory.md` | Updated | 移除 page-local CSS，使用共享 `.cs-*` 组件。 |
| `stylesheets/clawsentry-docs.css` | Updated | 增加 reusable component contract、pill、flow、operator-path、before/after/API blocks。 |
| `dashboard/index.md` | Verified unchanged | 已有 metric fallback、Web UI session reading、L3 advisory 自然语言说明。 |
| `api/reporting.md` | Verified unchanged | 已覆盖 report/session/SSE/L3 advisory endpoint 参考；本轮通过 metric dictionary 交叉链接补充语义。 |
| `integration/*` | Verified unchanged | 框架入口已在 nav 和 Quickstart 连接；无需行为变更。 |

## 后续风险与建议 {#follow-up}

- 若产品决定提供 `clawsentry setup` 或真正的交互式 guide，需要单独 PRD/test-spec，覆盖 help output、非交互确定性、TTY prompt fallback 与 CI 稳定性。
- 若未来让 `risk_points_sum` 或 `system_security_posture` 参与判决，必须新增配置开关并更新指标字典的“默认行为不变清单”。
- 若 D4 标准化或 D6 embedding backend 默认开启，需要更新 D1-D6 表中的范围、来源和降级语义。
