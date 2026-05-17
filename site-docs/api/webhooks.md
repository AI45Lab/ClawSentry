---
title: Webhook API
description: OpenClaw Webhook receiver 的认证、签名、幂等性和错误处理
---

<section class="cs-doc-hero cs-doc-hero--api" markdown>
<div class="cs-eyebrow">ClawSentry Webhook API</div>
## Webhook API
OpenClaw Webhook receiver 接收外部事件并归一化到 ClawSentry Gateway，完成安全校验、签名验证和幂等去重。
<div class="cs-actions" markdown>
[API 概览](overview.md){ .md-button .md-button--primary }
[认证与安全](authentication.md){ .md-button }
[模型与错误码](models-errors.md){ .md-button }
</div>
</section>

OpenClaw Webhook receiver 是独立的 FastAPI 服务面，和 Gateway HTTP API 分开部署/监听。文档与覆盖矩阵使用 `service: openclaw-webhook` 区分它和 Gateway 端点。

## POST /webhook/openclaw {#post-webhook-openclaw}

接收 OpenClaw Webhook 事件，完成安全校验、幂等去重、事件归一化，然后把事件提交给 ClawSentry Gateway。

### 认证与安全检查

请求会按配置执行以下检查：

| 检查 | 说明 |
| --- | --- |
| Token | `Authorization: Bearer <OPENCLAW_WEBHOOK_TOKEN>` 或等价 token。 |
| HMAC | 当配置 `OPENCLAW_WEBHOOK_SECRET` 时启用；strict 模式下缺失或错误签名返回 `401`。未配置 secret 时跳过 HMAC。 |
| Timestamp | 使用 `X-AHP-Timestamp` 防止重放。 |
| Content-Type | 必须是 JSON 请求体。 |
| IP allowlist | 如配置 `AHP_WEBHOOK_IP_WHITELIST`，仅允许白名单来源。 |
| Idempotency | `idempotencyKey` 在 TTL 内重复提交同一 payload 会返回缓存结果；同 key 不同 payload 返回 `409`。 |

### 请求示例

```bash
curl -X POST http://127.0.0.1:8081/webhook/openclaw \
  -H "Authorization: Bearer $OPENCLAW_WEBHOOK_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-AHP-Timestamp: $(date +%s)" \
  -d '{
    "type": "exec.approval.requested",
    "idempotencyKey": "openclaw-demo-001",
    "sessionKey": "sess-001",
    "agentId": "agent-001",
    "payload": {
      "command": "rm -rf /tmp/demo",
      "approval_id": "apr-001"
    }
  }'
```

### 响应示例

```json
{
  "decision": "block",
  "reason": "destructive command pattern detected",
  "risk_level": "high",
  "failure_class": "none",
  "final": true
}
```

### 常见错误

| 状态码 | 原因 |
| --- | --- |
| `400` | JSON 无效、请求体不是对象、必填字段缺失 |
| `401` | token 缺失/错误/过期，timestamp 缺失/格式错误/超出窗口，或 HMAC 签名缺失/错误 |
| `403` | 非 localhost HTTP 被 HTTPS 策略拒绝，或来源 IP 不在 allowlist |
| `409` | idempotency key 被不同 payload 重用 |
| `413` | 请求体超过 `max_body_bytes` |
| `415` | `Content-Type` 不是 JSON |
| `422` | 事件类型无法映射为 CanonicalEvent |
| `500` | Gateway 客户端或归一化过程异常 |

## GET /health {#webhook-health}

Webhook receiver 的本地健康检查，返回：

```json
{"status": "healthy", "component": "openclaw-webhook-receiver"}
```

!!! note "为什么它没有进入共享 OpenAPI path"
    Gateway 也有 `GET /health`。为了避免两个 service-local `/health` 在同一个 OpenAPI `paths` 对象里互相覆盖，Webhook health 在 `api-coverage.json` 中作为显式 excluded entry 记录，并在本页说明。
