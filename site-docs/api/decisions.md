---
title: 决策端点
description: ClawSentry 决策相关 API 端点完整参考，包括 Webhook、HTTP 传输、DEFER 代理和 UDS 传输
---

<section class="cs-doc-hero cs-doc-hero--api" markdown>
<div class="cs-eyebrow">ClawSentry 决策 API</div>

## 决策端点

ClawSentry 网关接收 AI Agent 运行时事件，并返回统一的 `CanonicalDecision`。本页列出所有决策相关端点。

<div class="cs-actions" markdown>
[API 概览](overview.md){ .md-button .md-button--primary }
[报表与监控](reporting.md){ .md-button }
[认证](authentication.md){ .md-button }
</div>
</section>

## 决策模型概览

所有端点最终返回统一的 **CanonicalDecision**：

```json
{
  "decision": "allow | block | defer | modify",
  "reason": "human-readable explanation",
  "policy_id": "L1-D1-destructive-tool",
  "risk_level": "low | medium | high | critical",
  "decision_source": "policy | manual | system",
  "policy_version": "1.0",
  "decision_latency_ms": 12.5,
  "modified_payload": null,
  "retry_after_ms": null,
  "failure_class": "none",
  "final": true
}
```

| 判决 | 含义 | `final` |
|------|------|---------|
| `allow` | 允许执行 | 必须为 `true` |
| `block` | 拒绝执行 | 必须为 `true` |
| `defer` | 需人工审批 | 可选 |
| `modify` | 允许执行但修改参数 | 可选，需附带 `modified_payload` |

---

## POST /ahp — OpenClaw Webhook 决策 {#post-ahp}

接收 OpenClaw Webhook 事件（JSON-RPC 2.0 封装），归一化为 AHP 协议并返回安全决策。

### 认证

- **Bearer Token**: `Authorization: Bearer <CS_AUTH_TOKEN>`
- 详见 [认证文档](authentication.md)

### 请求格式

请求体为 JSON-RPC 2.0 封装的 `SyncDecisionRequest`：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "ahp/sync_decision",
  "params": {
    "rpc_version": "sync_decision.1.0",
    "request_id": "req-abc-123",
    "deadline_ms": 100,
    "decision_tier": "L1",
    "event": {
      "schema_version": "ahp.1.0",
      "event_id": "evt-001",
      "trace_id": "trace-001",
      "event_type": "pre_action",
      "session_id": "session-001",
      "agent_id": "agent-001",
      "source_framework": "openclaw",
      "occurred_at": "2026-03-23T10:30:00+00:00",
      "event_subtype": "exec.approval.requested",
      "tool_name": "bash",
      "risk_hints": ["shell_execution", "destructive_pattern"],
      "payload": {
        "command": "rm -rf /important-data",
        "approval_id": "apr-001"
      },
      "source_protocol_version": "1.0",
      "mapping_profile": "openclaw@abc1234/protocol.v1/profile.v1"
    },
    "context": {
      "caller_adapter": "openclaw-adapter.v1"
    }
  }
}
```

**关键字段说明：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `rpc_version` | string | :material-check: | 必须为 `sync_decision.1.0` |
| `request_id` | string | :material-check: | 请求唯一标识，用于幂等性缓存 |
| `deadline_ms` | int | :material-check: | 决策超时（1-5000 ms） |
| `decision_tier` | enum | :material-check: | 决策层级：`L1`（规则引擎）或 `L2`（含 LLM 分析） |
| `event` | object | :material-check: | AHP CanonicalEvent |
| `context` | object | :material-close: | 可选决策上下文 |

`context` 可携带 Gateway evidence，例如 `session_scope_profile`、
`skill_trust` 与 `mcp_context`。这些字段只提供策略输入和审计线索；
adapter 不得通过它们直接产出最终 `decision`、`policy_id` 或 `final`。

### 成功响应

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "rpc_version": "sync_decision.1.0",
    "request_id": "req-abc-123",
    "rpc_status": "ok",
    "decision": {
      "decision": "block",
      "reason": "D1: destructive tool pattern detected (rm -rf)",
      "policy_id": "L1-D1-destructive-tool",
      "risk_level": "high",
      "decision_source": "policy",
      "policy_version": "1.0",
      "decision_latency_ms": 2.3,
      "failure_class": "none",
      "final": true
    },
    "actual_tier": "L1",
    "served_at": "2026-03-23T10:30:00.002+00:00"
  }
}
```

### 错误响应

当请求校验失败、超时、版本不支持或引擎不可用时，返回 JSON-RPC 2.0 错误：

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Unsupported rpc_version: 'sync_decision.2.0'",
    "data": {
      "rpc_version": "sync_decision.1.0",
      "request_id": "req-abc-123",
      "rpc_status": "error",
      "rpc_error_code": "VERSION_NOT_SUPPORTED",
      "rpc_error_message": "Unsupported rpc_version: 'sync_decision.2.0'",
      "retry_eligible": false,
      "retry_after_ms": null,
      "fallback_decision": null
    }
  }
}
```

**错误码一览：**

| `rpc_error_code` | 含义 | `retry_eligible` |
|-------------------|------|-----------------|
| `INVALID_REQUEST` | 请求格式错误 | `false` |
| `EVENT_SCHEMA_MISMATCH` | 事件 Schema 不匹配 | `false` |
| `VERSION_NOT_SUPPORTED` | RPC 版本不支持 | `false` |
| `DEADLINE_EXCEEDED` | 决策超时（附 `fallback_decision`） | `true` |
| `ENGINE_UNAVAILABLE` | 引擎启动中 | `true` |
| `ENGINE_INTERNAL_ERROR` | 引擎内部错误 | `true` |
| `RATE_LIMITED` | 速率限制 | `true` |

### 幂等性

同一 `request_id` 在 TTL 窗口内（与 `deadline_ms` 关联）重复请求，直接返回缓存的决策结果。缓存自动定期清理（间隔 10 秒）。

### curl 示例

```bash
curl -X POST http://127.0.0.1:8080/ahp \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "ahp/sync_decision",
    "params": {
      "rpc_version": "sync_decision.1.0",
      "request_id": "test-001",
      "deadline_ms": 500,
      "decision_tier": "L1",
      "event": {
        "schema_version": "ahp.1.0",
        "event_id": "evt-test-001",
        "trace_id": "trace-test-001",
        "event_type": "pre_action",
        "session_id": "sess-test",
        "agent_id": "agent-test",
        "source_framework": "a3s-code",
        "occurred_at": "2026-03-23T10:00:00+00:00",
        "event_subtype": "PreToolUse",
        "tool_name": "bash",
        "payload": {"command": "echo hello"}
      }
    }
  }'
```

---

## POST /ahp/a3s — a3s-code HTTP 传输 {#post-ahp-a3s}

为 a3s-code 提供直接 HTTP 接入，支持 `handshake`（握手）和 `event`（事件）两种消息类型。

### 认证

- **Bearer Token**: `Authorization: Bearer <CS_AUTH_TOKEN>`

### 协议流程

```
Client                             Gateway
  |                                   |
  |--- handshake ------------------>  |
  |<-- handshake result -----------  |
  |                                   |
  |--- event (pre_action) --------->  |
  |<-- decision -------------------  |
  |                                   |
  |--- event (post_action) -------->  |
  |<-- decision -------------------  |
```

### 握手请求（`handshake`）

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "ahp/handshake",
  "params": {}
}
```

### 握手响应（`handshake`）

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocol_version": "2.0",
    "harness_info": {
      "name": "a3s-gateway-harness",
      "version": "1.0.0",
      "capabilities": [
        "pre_action",
        "post_action",
        "pre_prompt",
        "session",
        "error"
      ]
    }
  }
}
```

### 事件请求

发送 AHP 事件以获取安全决策：

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "ahp/event",
  "params": {
    "event_type": "pre_action",
    "session_id": "session-001",
    "agent_id": "agent-001",
    "payload": {
      "tool": "bash",
      "command": "rm -rf /tmp/data",
      "arguments": {
        "command": "rm -rf /tmp/data"
      }
    }
  }
}
```

### 事件响应

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "action": "block",
    "decision": "block",
    "reason": "D1: destructive tool pattern detected",
    "metadata": {
      "source": "clawsentry-gateway-harness",
      "policy_id": "L1-D1-destructive-tool",
      "risk_level": "high",
      "decision_source": "policy",
      "final": true
    }
  }
}
```

**`action` 字段映射：**

| AHP Decision | a3s-code Action |
|-------------|-----------------|
| `allow` | `continue` |
| `block` | `block` |
| `defer` | `defer` |
| `modify` | `modify`（附带 `modified_payload`） |

### 支持的 `event_type` 值

```
pre_action, pre_tool_use, post_action, post_tool_use,
pre_prompt, generate_start, session_start, session_end, error
```

### curl 示例

```bash
# 握手
curl -X POST http://127.0.0.1:8080/ahp/a3s \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"ahp/handshake","params":{}}'

# 提交事件
curl -X POST http://127.0.0.1:8080/ahp/a3s \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "params": {
      "event_type": "pre_action",
      "session_id": "test-session",
      "agent_id": "test-agent",
      "payload": {
        "tool": "bash",
        "command": "ls -la /home"
      }
    }
  }'
```

---

## POST /ahp/codex — Codex CLI HTTP 传输 {#post-ahp-codex}

为 OpenAI Codex CLI 提供简化的 HTTP 接入端点。无需 JSON-RPC 封装，直接提交事件获取安全决策。

### 认证

- **Bearer Token**: `Authorization: Bearer <CS_AUTH_TOKEN>`

### 请求格式（v0.7.5 公开 HTTP contract）

`event_type` 字段位于顶层（不嵌套在 event 对象内）：

```json
{
  "event_type": "pre_action",
  "session_id": "sess-abc123",
  "tool_name": "bash",
  "payload": {
    "command": "ls -la"
  }
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `event_type` | string | :material-check: | 事件类型（见下表映射） |
| `payload` | object | :material-check: | 工具调用负载 |
| `session_id` | string | :material-close: | 会话 ID（缺省自动生成） |
| `tool_name` | string | :material-close: | 工具名称（如 `bash`、`exec`） |
| `agent_id` | string | :material-close: | Agent ID（缺省自动生成） |

### 事件类型映射

| `event_type` 输入值 | 归一化 EventType | 说明 |
|-------------|-----------------|------|
| `pre_action` | `pre_action` | 工具调用前（阻塞决策，推荐直接使用） |
| `function_call` | `pre_action` | 旧 Codex hook 映射兼容 |
| `post_action` | `post_action` | 工具调用后（异步审计） |
| `function_call_output` | `post_action` | 旧 Codex hook 映射兼容 |
| `session_meta` | `session` | 会话元数据 |
| `session_end` | `session` | 会话结束 |

### 成功响应（v0.7.5 公开 HTTP contract）

响应包裹在 `{"result": ...}` 中：

```json
{
  "result": {
    "decision": "allow",
    "reason": "Low-risk read operation",
    "risk_level": "low",
    "policy_id": "l1-default-allow"
  }
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `decision` | string | 判决：`allow` / `block` / `defer` / `modify` |
| `reason` | string | 人类可读的判决原因 |
| `risk_level` | string | `low` / `medium` / `high` / `critical` |
| `policy_id` | string | 触发该判决的策略或规则标识 |

!!! info "格式说明"
    该格式与 `/ahp` 主端点（JSON-RPC 2.0 格式）不同；`/ahp/codex` 使用简化的 REST-style 格式，适合 Codex 原生 hook 集成。

### 安全默认

当网关内部发生异常时，Codex 端点返回 **`block`**（fail-closed），而不是继续放行（`continue`）：

```json
{
  "result": {
    "action": "block",
    "reason": "evaluation error (fail-closed)"
  }
}
```

### curl 示例

```bash
curl -X POST http://127.0.0.1:8080/ahp/codex \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "function_call",
    "payload": {
      "name": "bash",
      "arguments": {"command": "ls -la"}
    },
    "session_id": "test-session"
  }'
```

---

## POST /ahp/resolve — DEFER 决策代理 {#post-ahp-resolve}

代理 DEFER 决策的操作员确认——将允许/拒绝指令转发到 OpenClaw WebSocket 客户端。

### 认证

- **Bearer Token**: `Authorization: Bearer <CS_AUTH_TOKEN>`

### 请求

```json
{
  "approval_id": "apr-abc-123",
  "decision": "allow-once",
  "reason": "Operator approved after manual review"
}
```

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `approval_id` | string | :material-check: | 审批请求 ID（来自 OpenClaw 事件） |
| `decision` | string | :material-check: | `allow-once` 或 `deny` |
| `reason` | string | :material-close: | 可选的决策原因说明 |

### 成功响应

```json
{
  "status": "ok",
  "approval_id": "apr-abc-123"
}
```

### 错误响应

**无 OpenClaw 连接（503）：**

```json
{
  "error": "resolve not available (no OpenClaw enforcement)"
}
```

**请求参数错误（400）：**

```json
{
  "error": "approval_id and decision are required"
}
```

**无效 decision 值（400）：**

```json
{
  "error": "decision must be one of ['allow-once', 'deny']"
}
```

**上游解析失败（502）：**

```json
{
  "error": "resolve failed: <error detail>"
}
```

### 优雅降级

当 OpenClaw 不支持 `reason` 字段（由于 `additionalProperties: false` 限制）时，resolve 端点会自动重试——先带 `reason` 发送，失败后去掉 `reason` 再次发送。

### curl 示例

```bash
# 允许执行
curl -X POST http://127.0.0.1:8080/ahp/resolve \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approval_id": "apr-001", "decision": "allow-once"}'

# 拒绝执行
curl -X POST http://127.0.0.1:8080/ahp/resolve \
  -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approval_id": "apr-001", "decision": "deny", "reason": "suspicious operation"}'
```

---

## UDS 传输（Unix Domain Socket） {#uds-transport}

UDS 是 ClawSentry 的**主传输通道**，提供最低延迟的进程间通信；a3s-code harness 默认通过它连接网关。

### 连接信息

| 项目 | 值 |
|------|------|
| Socket 路径 | `/tmp/clawsentry.sock`（或 `CS_UDS_PATH`） |
| 协议 | JSON-RPC 2.0 |
| 方法 | `ahp/sync_decision` |
| 帧格式 | 4 字节大端序长度前缀 + JSON Payload |
| 权限 | `chmod 0600`（仅所有者可读写） |

### 帧格式

```
+------------------+--------------------+
| 4 bytes (uint32) | N bytes (JSON)     |
| big-endian       | UTF-8 encoded      |
| = N              | JSON-RPC 2.0 body  |
+------------------+--------------------+
```

### 请求示例

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "ahp/sync_decision",
  "params": {
    "rpc_version": "sync_decision.1.0",
    "request_id": "uds-req-001",
    "deadline_ms": 100,
    "decision_tier": "L1",
    "event": {
      "schema_version": "ahp.1.0",
      "event_id": "evt-uds-001",
      "trace_id": "trace-uds-001",
      "event_type": "pre_action",
      "session_id": "session-001",
      "agent_id": "agent-001",
      "source_framework": "a3s-code",
      "occurred_at": "2026-03-23T10:00:00+00:00",
      "event_subtype": "PreToolUse",
      "tool_name": "bash",
      "payload": {
        "command": "cat /etc/passwd"
      }
    },
    "context": {
      "caller_adapter": "a3s-adapter.v1"
    }
  }
}
```

### 响应示例

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "rpc_version": "sync_decision.1.0",
    "request_id": "uds-req-001",
    "rpc_status": "ok",
    "decision": {
      "decision": "defer",
      "reason": "D2: sensitive path (/etc/passwd) access detected",
      "policy_id": "L1-D2-sensitive-path",
      "risk_level": "medium",
      "decision_source": "policy",
      "policy_version": "1.0",
      "decision_latency_ms": 0.8,
      "failure_class": "none",
      "final": false
    },
    "actual_tier": "L1",
    "served_at": "2026-03-23T10:00:00.001+00:00"
  }
}
```

### 安全限制

| 限制 | 值 |
|------|------|
| 最大帧大小 | 10 MB |
| Socket 文件权限 | `0600` |
| 超时 | 由请求方 `deadline_ms` 控制 |

### Python 客户端示例

```python
import asyncio
import json
import struct

async def send_uds_request(uds_path: str, request: dict) -> dict:
    """发送 JSON-RPC 2.0 请求到 ClawSentry UDS。"""
    reader, writer = await asyncio.open_unix_connection(uds_path)
    try:
        body = json.dumps(request).encode("utf-8")
        # 写入 4 字节长度前缀 + JSON payload
        writer.write(struct.pack("!I", len(body)))
        writer.write(body)
        await writer.drain()

        # 读取响应
        length_bytes = await reader.readexactly(4)
        resp_length = struct.unpack("!I", length_bytes)[0]
        resp_data = await reader.readexactly(resp_length)
        return json.loads(resp_data)
    finally:
        writer.close()
        await writer.wait_closed()
```

---

## 三层决策模型 {#decision-layers}

所有决策端点共享同一个三层决策引擎：

| 层级 | 名称 | 典型延迟 | 说明 |
|------|------|----------|------|
| **L1** | 规则引擎 | < 1 ms | D1-D5 五维风险评分 + 短路规则 |
| **L2** | LLM 语义分析 | < 3 s | 调用 LLM 进行上下文感知的语义分析 |
| **L3** | 审查 Agent | < 30 s | 多轮工具调用的深度安全审查 |

### D1-D5 风险维度

| 维度 | 范围 | 说明 |
|------|------|------|
| D1 | 0-3 | 工具类型危险度 |
| D2 | 0-3 | 目标路径敏感度 |
| D3 | 0-3 | 命令模式危险度 |
| D4 | 0-2 | 上下文风险累积 |
| D5 | 0-2 | Agent 信任等级 |

综合风险分 = max(D1, D2, D3) + D4 + D5，范围 0-7。

### 风险等级映射

| 综合分 | 风险等级 |
|--------|----------|
| 0-1 | `low` |
| 2-3 | `medium` |
| 4-5 | `high` |
| 6-7 | `critical` |

## AHP 效果生命周期 —— 请求、执行、回写分离 {#decision-effects-lifecycle}

从 v0.5.4 开始，`CanonicalDecision` 在保持顶层
`allow / block / defer / modify` 判决稳定的同时，可以携带
`decision_effects`。它只表达 **网关请求了哪类额外效果**，
不声明宿主已经执行成功。

!!! important "请求意图不等于实际执行"
    `decision_effects` 是网关的请求意图；真实宿主行为由 adapter 后续用
    `adapter_effect_result` 回写。这样可以区分“策略要求隔离 session / 改写命令”和
    “Codex、a3s-code、OpenClaw 等宿主实际支持、降级或不支持的效果”。

### 什么时候会看到它？

| 场景 | 顶层判决 | effect 字段 | 处理方式 |
| --- | --- | --- | --- |
| 会话被判定为受损（compromised session） | `block` 或 `defer` | `session_effect.mode=mark_blocked`、`action_scope=session` | 后续同 session 的 `pre_action` 会被阻断；operator 可查询并释放 quarantine。 |
| 人工审批改写命令 / `tool_input` | `modify` | `rewrite_effect` + `modified_payload` | adapter 使用 `modified_payload` 的替换内容执行；轨迹与 watch 只展示 hash / redacted preview。 |
| 宿主不支持某个 effect | 原判决不变 | adapter 回写 `degraded` 或 `unsupported` | 查看 `degrade_reason`，决定是否升级到人工处置或改用支持该 effect 的接入方式。 |

示例响应：

```json
{
  "decision": "modify",
  "modified_payload": {"command": "rm -ri /tmp/example"},
  "decision_effects": {
    "effect_version": "cs.decision_effects.v1",
    "effect_id": "eff-rewrite-001",
    "action_scope": "action",
    "rewrite_effect": {
      "requested": true,
      "target": "command",
      "approval_id": "apr-001",
      "original_hash": "sha256:old",
      "original_preview_redacted": "rm -rf …",
      "replacement_hash": "sha256:new",
      "replacement_preview_redacted": "rm -ri …",
      "rewrite_source": "operator_resolution"
    }
  }
}
```

### 适配器处理步骤

1. 先按顶层判决处理 `allow / block / defer / modify`。
2. 有 `modified_payload` 时，只使用允许的 `command` 或 `tool_input`
   替换内容；`prompt` rewrite 不在 v1 范围内。
3. 读取 `decision_effects.effect_id`，把本次宿主执行结果回写到
   `POST /ahp/adapter-effect-result`。
4. 如果无法执行效果，不要伪装成功；写入 `degraded` 或 `unsupported`，
   并提供 `degrade_reason`。

### 期望输出与恢复路径

| 确认项 | 查看位置 | 恢复 / 后续动作 |
| --- | --- | --- |
| adapter 是否执行了 effect | `adapter_effect_result` SSE / replay / Session Detail summary | 若 `degraded` 或 `unsupported`，查看 `degrade_reason`，并切换接入方式或人工处置。 |
| session 是否处于 quarantine | `GET /report/session/{session_id}/quarantine` | 人工确认风险解除后，用 `POST /report/session/{session_id}/quarantine` 释放。 |
| rewrite 是否泄露完整 payload | replay / SSE / watch | 正常情况下只保留 `replacement_hash` 与 `replacement_preview_redacted`；完整替换内容只用于实时 adapter 响应。 |

相关参考：

- [会话 quarantine 查询与释放](reporting.md#get-report-session-quarantine)
- [L3 advisory 与 SSE 事件流](reporting.md#l3-advisory-endpoints)
- [a3s-code 对 `modify` / `modified_payload` 的接入说明](../integration/a3s-code.md)

## POST /ahp/adapter-effect-result — 适配器效果结果回写 {#post-ahp-adapter-effect-result}

该端点用于在宿主侧完成效果翻译后，回写**实际观测结果**。它只记录适配器最终执行状态（`enforced` / `degraded` / `unsupported`），不会反向改写原始 `CanonicalDecision`。同一个 `effect_id + adapter + event/tool/session + result_kind` 会形成幂等键；重复写回会返回既有结果。

```json
{
  "effect_id": "eff-rewrite-001",
  "framework": "codex",
  "adapter": "codex-native-hook",
  "requested": ["command_rewrite"],
  "degraded": ["command_rewrite"],
  "degrade_reason": "codex_pretool_updated_input_unsupported",
  "event_id": "evt-001",
  "session_id": "sess-001"
}
```

响应示例：

```json
{
  "created": true,
  "idempotency_key": "eff-rewrite-001:codex-native-hook:evt-001:degraded"
}
```

说明：

- `decision_effects` 表示网关的**请求意图**；`adapter_effect_result` 表示宿主侧**实际观测结果**。
- 当结果是 `degraded` 或 `unsupported` 时，必须提供 `degrade_reason`。
- 重复回写会命中幂等键（`idempotency_key`），并返回已存在结果。
- 该端点不需要完整 rewrite 替换载荷，不应发送敏感替换正文。

## POST /ahp/scope/preview — Session scope 预览 {#post-ahp-scope-preview}

该端点用于在启用 session scope 前，预览一个 deterministic
`SessionScopeProfile` 对单个 `CanonicalEvent` 的判定。profile 字段说明与 CLI 调试流程见 [Session scope 配置](../configuration/session-scope.md)。它是用户友好的
dry-run/API 入口：默认只解释 `scope_allow` / `scope_defer` /
`scope_deny` reason codes，不会声称已经阻断动作。只有请求显式传入
`"confirm": true` 时，响应才会把该预览标记为 confirmed/non-dry-run。

请求示例：

```json
{
  "profile": {
    "profile_id": "docs-only",
    "confirmed": false,
    "dry_run": true,
    "base_rules": {"denied_paths": ["~/.ssh"]},
    "task_rules": {"allowed_tools": ["read_file"]}
  },
  "event": {
    "event_id": "evt-scope-docs",
    "trace_id": "trace-scope-docs",
    "event_type": "pre_action",
    "session_id": "sess-scope-docs",
    "agent_id": "agent-scope-docs",
    "source_framework": "test",
    "occurred_at": "2026-05-02T00:00:00+00:00",
    "tool_name": "read_file",
    "payload": {"path": "~/.ssh/id_rsa"}
  }
}
```

响应示例：

```json
{
  "valid": true,
  "mode": "dry_run_only",
  "profile_id": "docs-only",
  "scope_evaluation": {
    "profile_id": "docs-only",
    "source": "operator",
    "confirmed": false,
    "dry_run": true,
    "enforced": false,
    "verdict": "deny",
    "reason_codes": ["scope_deny:path ~/.ssh"]
  },
  "protection_statement": "Protected today: scope preview validates rules and explains the decision that would apply. Not protected today: dry-run scope profiles do not block or defer actions until explicitly confirmed."
}
```

用户保护边界：

- **Protected today:** confirmed non-dry-run scope profiles can tighten Gateway
  decisions to `defer` or `block` through the existing AHP policy path.
- **Not protected today:** dry-run previews do not enforce, and ClawSentry does
  not infer scopes automatically from LLM output in this phase.
