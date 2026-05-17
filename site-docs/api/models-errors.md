---
title: 模型与错误码
description: ClawSentry API 常见数据模型、判决枚举、错误响应和排障提示
---

<section class=”cs-doc-hero cs-doc-hero--api” markdown>
<div class=”cs-eyebrow”>ClawSentry 模型与错误码</div>
## 模型与错误码
API Reference 中最常见的数据结构、判决枚举和错误响应快速参考，方便集成时判断字段含义。
<div class=”cs-actions” markdown>
[API 概览](overview.md){ .md-button .md-button--primary }
[决策端点](decisions.md){ .md-button }
[Metric Dictionary](metric-dictionary.md){ .md-button }
</div>
</section>

本页把 API Reference 中最常见的数据结构抽出来解释，方便你在写集成代码时快速判断”字段代表什么”。

## CanonicalDecision

`CanonicalDecision` 是 Gateway 对一次事件的安全判决。

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `decision` | enum | `allow`、`block`、`defer`、`modify` |
| `reason` | string | 人类可读的判决理由 |
| `risk_level` | enum | `low`、`medium`、`high`、`critical` |
| `policy_id` | string | 触发策略或规则标识 |
| `decision_latency_ms` | number | 决策耗时 |
| `final` | boolean | 是否为最终判决；`defer` 可能需要后续审批 |

## CanonicalEvent

`CanonicalEvent` 是不同 Agent 框架进入 ClawSentry 后的统一事件形态。二次开发者接入新框架时，应尽量把原始事件映射为这些语义。

| 字段 | 说明 |
| --- | --- |
| `schema_version` | AHP schema 版本，例如 `ahp.1.0` |
| `event_id` / `trace_id` | 单事件与跨组件追踪标识 |
| `event_type` | `pre_action`、`post_action`、`session` 等 |
| `source_framework` | `claude-code`、`a3s-code`、`openclaw`、`codex` 等 |
| `tool_name` | 工具名，例如 `bash`、`exec` |
| `payload` | 框架原始载荷或归一化后的命令信息 |

## HTTP 错误

| 状态码 | 常见原因 | 处理方式 |
| --- | --- | --- |
| `400` | 请求 JSON 格式错误、参数越界、未知 action | 修正请求体或 query 参数 |
| `401` | Bearer token 或 query token 不正确 | 检查 `CS_AUTH_TOKEN` / URL token |
| `403` | 功能未启用，例如 pattern evolution disabled | 检查对应环境变量 |
| `404` | snapshot、job、review、alert 不存在 | 检查 ID 是否来自当前 Gateway |
| `409` | Webhook idempotency key 被不同 payload 重用 | 保证同一 key 对应同一请求体 |
| `429` | Gateway 速率限制 | 等待 `retry_after_ms` 后重试 |
| `500` | 运行时内部错误 | 查看 Gateway 日志和 watch/UI 告警 |

## JSON-RPC 错误

`/ahp` 和部分 AHP transport 使用 JSON-RPC 2.0 包装。常见 `rpc_error_code`：

- `INVALID_REQUEST`
- `EVENT_SCHEMA_MISMATCH`
- `VERSION_NOT_SUPPORTED`
- `DEADLINE_EXCEEDED`
- `ENGINE_UNAVAILABLE`
- `ENGINE_INTERNAL_ERROR`
- `RATE_LIMITED`

## 排障顺序

1. 先访问 `GET /health` 确认服务在线。
2. 再检查认证：Gateway 看 `CS_AUTH_TOKEN`，Webhook 看 `OPENCLAW_WEBHOOK_TOKEN` 和 HMAC 配置。
3. 对 JSON-RPC 请求，检查 `rpc_version`、`request_id`、`deadline_ms` 和 `event.schema_version`。
4. 对 SSE，请确认 token 传入方式：浏览器 `EventSource` 通常使用 `?token=`。
5. 如果是 L3 advisory，请确认它是 advisory-only，不会改写历史 CanonicalDecision。
