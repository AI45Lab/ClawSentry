---
title: 自定义 Adapter
description: 为新的 AI Agent 框架编写适配器，将框架事件归一化为 AHP 标准事件
---

<div class="cs-doc-hero" markdown>
<div class="cs-eyebrow">Advanced · Framework Integration</div>

## 自定义 Adapter

为新的 AI Agent 框架编写适配器，将框架原生事件归一化为 AHP 标准 `CanonicalEvent`，接入 ClawSentry Gateway 的统一安全决策链。

<div class="cs-pill-row" markdown>
<span class="cs-pill">6 个已支持框架</span>
<span class="cs-pill">鸭子类型接口</span>
<span class="cs-pill">UDS / HTTP / WebSocket</span>
<span class="cs-pill">fail-closed fallback</span>
</div>
</div>

# 自定义 Adapter

Adapter（适配器）是 ClawSentry 连接不同 AI Agent 框架的桥梁。每个 Adapter 负责将特定框架的原生事件**归一化**为 AHP 协议定义的 `CanonicalEvent`，然后交给 Gateway 的 PolicyEngine 进行统一的安全评估。

如果你使用的 AI Agent 框架不在 ClawSentry 已支持的列表中，可以通过编写自定义 Adapter 来完成接入。

---

## Adapter 的角色

在 ClawSentry 架构中，Adapter 处于以下位置：

```
AI Agent 框架                ClawSentry
┌──────────────┐            ┌──────────────────────────┐
│              │   原生事件   │ Adapter                  │
│  a3s-code    │ ─────────→ │  ├─ 归一化 → CanonicalEvent │
│  OpenClaw    │            │  └─ 发送 → Gateway        │
│  自定义框架   │            │                          │
│              │ ←───────── │ Gateway                  │
│              │ 决策(allow/ │  ├─ PolicyEngine          │
│              │  block/    │  ├─ L1 规则引擎           │
│              │  defer)    │  ├─ L2 语义分析           │
│              │            │  └─ L3 审查 Agent         │
└──────────────┘            └──────────────────────────┘
```

### 核心职责

1. **事件归一化** -- 将框架的原生事件格式映射为 `CanonicalEvent`
2. **元数据保留** -- 通过 `framework_meta` 保留框架特有的元信息
3. **Risk Hints 提取** -- 从原生事件中识别并标注风险提示
4. **Gateway 通信** -- 将归一化事件发送到 Gateway 并接收决策

### 设计原则

!!! warning "关键原则：Adapter 不做最终决策"
    Adapter 的职责是**归一化**和**传递**，最终的安全决策**只由 PolicyEngine 产生**。Adapter 只能生成 `CanonicalEvent`，不能直接返回 `CanonicalDecision`。

    唯一的例外是**本地降级 (fallback)**：当 Gateway 不可达时，Adapter 可以调用 `make_fallback_decision()` 生成保守的降级决策。

其他设计原则：

- **归一化失败优雅处理** -- 遇到无法映射的事件类型时返回 `None`，不抛出异常
- **缺失字段使用 Sentinel 值** -- session_id、agent_id 缺失时使用标准 sentinel 值（如 `unknown_session:framework-name`）
- **双通道处理** -- `pre_action` 事件同步阻塞等待决策，`post_action` 事件异步审计

---

## 现有 Adapter 参考

ClawSentry 目前为 **6 个框架**提供官方 Adapter 和 native hook/transport 支持：

| 框架 | Adapter / 接入方式 | Hook 类型 |
|---|---|---|
| a3s-code | `A3SCodeAdapter`，stdio harness + `POST /ahp/a3s` | StdioTransport / HttpTransport |
| OpenClaw | `OpenClawAdapter`，WebSocket 实时事件 + Webhook | WebSocket + HMAC webhook |
| Claude Code | `ClaudeCodeAdapter`，native hook harness | `PreToolUse`（阻塞）+ `PostToolUse`/`UserPromptSubmit`（异步）|
| Codex | `CodexAdapter`，managed hook + `POST /ahp/codex` | `PreToolUse`（阻塞）+ `PermissionRequest`/`PostToolUse`（异步）|
| Gemini CLI | `GeminiAdapter`，`BeforeTool` native hook | `BeforeTool`（阻塞）|
| Kimi CLI | `KimiAdapter`，native `PreToolUse`/`UserPromptSubmit` hook | `PreToolUse`（阻塞）+ `UserPromptSubmit`/`PostToolUse`（异步）|

如果你使用的 AI Agent 框架不在以上列表中，可以通过编写自定义 Adapter 来完成接入。

### A3SCodeAdapter

**文件**: `src/clawsentry/adapters/a3s_adapter.py`

将 a3s-code 的 Hook 事件归一化为 CanonicalEvent。

**事件映射**:

| a3s-code Hook 类型 | AHP EventType | 阻塞? |
|---------------------|---------------|-------|
| `PreToolUse` | `pre_action` | 是 |
| `PostToolUse` | `post_action` | 否 |
| `PrePrompt` | `pre_prompt` | 是 |
| `GenerateStart` | `pre_prompt` | 是 |
| `PostResponse` | `post_response` | 否 |
| `SessionStart` | `session` | 否 |
| `SessionEnd` | `session` | 否 |
| `OnError` | `error` | 否 |

**关键特性**:

- PostResponse 再分类规则：根据 payload 字段签名判断是 `post_action` 还是 `post_response`
- 稳定的 event_id 生成：基于 SHA-256 哈希
- UDS 通信：使用长度前缀帧的 JSON-RPC 2.0
- 重试逻辑：可配置的最大重试次数和退避时间
- 本地降级：Gateway 不可达时的 fail-closed / fail-open 策略

**通信方式**:

- 主通道：Unix Domain Socket (UDS)
- 备用通道：HTTP（通过 `InProcessA3SAdapter`）

### OpenClawAdapter

**文件**: `src/clawsentry/adapters/openclaw_adapter.py` 及相关模块

将 OpenClaw Gateway 的 WebSocket 事件归一化为 CanonicalEvent。

**模块组成**:

| 文件 | 职责 |
|------|------|
| `openclaw_adapter.py` | 主适配器，组合 normalizer + state machine + gateway client |
| `openclaw_normalizer.py` | 事件归一化核心逻辑 |
| `openclaw_ws_client.py` | WebSocket 客户端，连接 OpenClaw Gateway |
| `openclaw_webhook_receiver.py` | Webhook 接收器（HTTP 回调方式） |
| `openclaw_approval.py` | 审批状态机（Approval lifecycle） |
| `openclaw_bootstrap.py` | OpenClaw 启动引导配置 |
| `webhook_security.py` | Webhook 安全验证（签名、IP 白名单） |

**关键特性**:

- WebSocket 实时事件监听
- 审批状态机：`requested` → `pending` → `resolved`/`no_route`
- 自动决策执行：收到 Gateway 决策后通过 WS 回传 allow/deny
- mapping_profile 版本化：`openclaw@<sha>/protocol.v<ver>/profile.v<n>`

---

## 编写新 Adapter

### 接口模式

ClawSentry 没有定义严格的 Adapter 基类（采用鸭子类型），但所有 Adapter 应该提供以下方法：

```python
class CustomAdapter:
    """自定义 Agent 框架适配器的推荐接口。"""

    SOURCE_FRAMEWORK: str = "custom-agent"
    """框架标识符，用于 CanonicalEvent.source_framework 字段。"""

    CALLER_ADAPTER_ID: str = "custom-adapter.v1"
    """适配器标识符，用于 DecisionContext.caller_adapter 字段。"""

    def normalize(
        self,
        event_type: str,
        payload: dict,
        session_id: str | None = None,
        agent_id: str | None = None,
        **kwargs,
    ) -> CanonicalEvent | None:
        """
        将框架原生事件归一化为 CanonicalEvent。

        Returns:
            CanonicalEvent 或 None（不可映射的事件）
        """
        ...

    def is_blocking(self, event_type: str) -> bool:
        """判断事件类型是否需要同步决策（阻塞 Agent 直到收到决策）。"""
        ...

    async def request_decision(
        self,
        event: CanonicalEvent,
        context: DecisionContext | None = None,
        deadline_ms: int | None = None,
    ) -> CanonicalDecision:
        """
        将归一化事件发送到 Gateway 并返回决策。

        包含重试逻辑和本地降级。
        """
        ...
```

### CanonicalEvent 字段映射指南

以下是将框架事件映射到 CanonicalEvent 时的关键字段说明：

```python
from clawsentry.gateway.models import (
    CanonicalEvent,
    EventType,
    FrameworkMeta,
    NormalizationMeta,
    extract_risk_hints,
    utc_now_iso,
)
```

#### 必需字段

| CanonicalEvent 字段 | 来源 | 说明 |
|---------------------|------|------|
| `schema_version` | 常量 | 固定为 `"ahp.1.0"` |
| `event_id` | 生成 | 稳定的唯一标识符，建议基于 SHA-256 |
| `trace_id` | 框架或生成 | 请求跟踪 ID，用于关联同一请求链 |
| `event_type` | 映射 | 框架事件类型 → AHP EventType 枚举 |
| `session_id` | 框架 | 框架的会话标识符 |
| `agent_id` | 框架 | 框架的 Agent 标识符 |
| `source_framework` | 常量 | Adapter 的 `SOURCE_FRAMEWORK` |
| `occurred_at` | 时间戳 | UTC ISO8601 格式 |
| `payload` | 框架 | 事件载荷字典 |

#### 建议字段

| CanonicalEvent 字段 | 来源 | 说明 |
|---------------------|------|------|
| `event_subtype` | 映射 | 框架事件的具体子类型（a3s-code/openclaw 必需） |
| `tool_name` | 框架 | 工具名称，从 payload 提取 |
| `risk_hints` | 提取 | 风险提示列表，使用 `extract_risk_hints()` 工具函数 |
| `framework_meta` | 构造 | 包含归一化元数据和框架特有信息 |
| `depth` | 框架 | Agent 调用栈深度 |
| `run_id` | 框架 | 框架的运行/任务标识符 |
| `approval_id` | 框架 | 审批请求标识符（如果适用） |

---

### 完整示例：CustomAgent 适配器

```python title="custom_agent_adapter.py"
"""
假设的 CustomAgent 框架适配器示例。

CustomAgent 是一个虚构的 AI Agent 框架，通过 HTTP Webhook
发送事件通知。事件格式如下：

{
    "type": "tool_call" | "tool_result" | "user_input" | "error",
    "session": "sess-abc123",
    "agent": "agent-1",
    "tool": "file_write",
    "args": {"path": "/etc/passwd", "content": "..."},
    "timestamp": "2026-03-23T10:00:00Z"
}
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any, Optional

from clawsentry.gateway.models import (
    CanonicalEvent,
    CanonicalDecision,
    DecisionContext,
    DecisionTier,
    EventType,
    FrameworkMeta,
    NormalizationMeta,
    extract_risk_hints,
    utc_now_iso,
)
from clawsentry.gateway.policy_engine import make_fallback_decision

logger = logging.getLogger("custom-agent-adapter")


# ---------------------------------------------------------------------------
# 事件类型映射
# ---------------------------------------------------------------------------

_EVENT_MAPPING: dict[str, tuple[EventType, bool]] = {
    "tool_call":   (EventType.PRE_ACTION, True),    # 工具调用前 → 阻塞
    "tool_result": (EventType.POST_ACTION, False),   # 工具调用后 → 审计
    "user_input":  (EventType.PRE_PROMPT, True),     # 用户输入前 → 阻塞
    "error":       (EventType.ERROR, False),          # 错误 → 审计
}


# ---------------------------------------------------------------------------
# event_id 生成
# ---------------------------------------------------------------------------

def _generate_event_id(
    framework: str,
    session_id: str,
    event_type: str,
    occurred_at: str,
    payload: dict[str, Any],
) -> str:
    """基于事件内容生成稳定的 event_id。"""
    payload_digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]
    raw = f"{framework}:{session_id}:{event_type}:{occurred_at}:{payload_digest}"
    return hashlib.sha256(raw.encode()).hexdigest()[:24]


# ---------------------------------------------------------------------------
# Adapter 主类
# ---------------------------------------------------------------------------

class CustomAgentAdapter:
    """CustomAgent 框架的 AHP 适配器。"""

    SOURCE_FRAMEWORK = "custom-agent"
    CALLER_ADAPTER_ID = "custom-agent-adapter.v1"

    def __init__(
        self,
        gateway_client=None,  # Gateway 客户端（UDS 或 HTTP）
        default_deadline_ms: int = 200,
    ) -> None:
        self._gateway_client = gateway_client
        self.default_deadline_ms = default_deadline_ms

    def normalize(
        self,
        raw_event: dict[str, Any],
    ) -> Optional[CanonicalEvent]:
        """
        将 CustomAgent 原生事件归一化为 CanonicalEvent。

        Returns:
            CanonicalEvent 或 None（不可映射的事件）
        """
        raw_type = raw_event.get("type", "")

        # 查找映射
        mapping = _EVENT_MAPPING.get(raw_type)
        if mapping is None:
            logger.warning("Unknown event type: %s", raw_type)
            return None

        event_type, _ = mapping

        # 提取字段
        session_id = raw_event.get("session") or CanonicalEvent.sentinel_session_id(
            self.SOURCE_FRAMEWORK
        )
        agent_id = raw_event.get("agent") or CanonicalEvent.sentinel_agent_id(
            self.SOURCE_FRAMEWORK
        )
        tool_name = raw_event.get("tool")
        occurred_at = raw_event.get("timestamp") or utc_now_iso()

        # 构建 payload
        payload = dict(raw_event.get("args", {}))
        if tool_name:
            payload["tool"] = tool_name
            payload["tool_name"] = tool_name

        # 提取命令文本（用于 risk_hints）
        command = str(payload.get("command", ""))
        if not command and "path" in payload:
            command = str(payload["path"])

        # 追踪缺失字段
        missing_fields: list[str] = []
        if not raw_event.get("session"):
            missing_fields.append("session_id")
        if not raw_event.get("agent"):
            missing_fields.append("agent_id")

        # 构建归一化元数据
        norm_meta = NormalizationMeta(
            rule_id="custom-agent-direct-map",
            inferred=False,
            confidence="high",
            raw_event_type=raw_type,
            raw_event_source=self.SOURCE_FRAMEWORK,
            missing_fields=missing_fields,
            fallback_rule="sentinel_value" if missing_fields else None,
        )

        # 生成稳定的 event_id
        event_id = _generate_event_id(
            self.SOURCE_FRAMEWORK,
            session_id,
            raw_type,
            occurred_at,
            payload,
        )

        # 提取 risk_hints
        risk_hints = extract_risk_hints(tool_name, command)

        return CanonicalEvent(
            event_id=event_id,
            trace_id=str(uuid.uuid4()),
            event_type=event_type,
            session_id=session_id,
            agent_id=agent_id,
            source_framework=self.SOURCE_FRAMEWORK,
            occurred_at=occurred_at,
            payload=payload,
            event_subtype=raw_type,
            tool_name=tool_name,
            risk_hints=risk_hints,
            framework_meta=FrameworkMeta(normalization=norm_meta),
        )

    def is_blocking(self, raw_type: str) -> bool:
        """判断事件类型是否需要同步决策。"""
        mapping = _EVENT_MAPPING.get(raw_type)
        return mapping[1] if mapping else False

    async def handle_event(
        self,
        raw_event: dict[str, Any],
    ) -> Optional[CanonicalDecision]:
        """
        处理一个原生事件：归一化 → 发送到 Gateway → 返回决策。

        对于非阻塞事件，发送后返回 None。
        """
        # 1. 归一化
        event = self.normalize(raw_event)
        if event is None:
            return None

        # 2. 非阻塞事件：异步发送，不等待决策
        raw_type = raw_event.get("type", "")
        if not self.is_blocking(raw_type):
            # 可选：异步发送到 Gateway 用于审计
            logger.debug("Non-blocking event %s: audit only", event.event_id)
            return None

        # 3. 阻塞事件：发送到 Gateway 等待决策
        if self._gateway_client is None:
            logger.warning("No gateway client; using fallback decision")
            return make_fallback_decision(
                event,
                risk_hints_contain_high_danger=bool(
                    set(event.risk_hints) & {"destructive_pattern", "shell_execution"}
                ),
            )

        try:
            context = DecisionContext(
                caller_adapter=self.CALLER_ADAPTER_ID,
            )
            decision = await self._gateway_client.request_decision(
                event, context=context, deadline_ms=self.default_deadline_ms,
            )
            return decision
        except Exception as e:
            logger.error("Gateway request failed: %s", e)
            return make_fallback_decision(
                event,
                risk_hints_contain_high_danger=bool(
                    set(event.risk_hints) & {"destructive_pattern", "shell_execution"}
                ),
            )
```

---

## Gateway 通信方式

Adapter 与 Gateway 通信有三种方式，选择取决于部署模式：

### 1. Unix Domain Socket (UDS)

**最推荐**，用于同一主机上的 Sidecar 部署：

```python
# A3SCodeAdapter 的 UDS 通信示例
reader, writer = await asyncio.open_unix_connection("/tmp/clawsentry.sock")
# 发送 4 字节长度前缀 + JSON-RPC 2.0 body
writer.write(struct.pack("!I", len(body)))
writer.write(body)
```

- 延迟极低（无网络开销）
- 自动继承 Unix 文件权限控制
- UDS 路径默认 `chmod 600`

### 2. HTTP API

用于跨主机部署或作为 UDS 的备用通道：

```python
# 使用 InProcessA3SAdapter 的进程内路由
response = await gateway.handle_jsonrpc(jsonrpc_body)
```

- 通过 `POST /ahp/a3s` 端点（a3s-code HTTP Transport）
- 或直接使用 JSON-RPC 2.0 over HTTP
- 支持 Bearer Token 认证

### 3. WebSocket

用于需要实时双向通信的框架（如 OpenClaw）：

```python
# OpenClaw WS 客户端示例
async with websockets.connect(ws_url, extra_headers=headers) as ws:
    async for message in ws:
        event = json.loads(message)
        await adapter.handle_ws_approval_event(event["payload"])
```

---

## 注册 Adapter 到 Gateway

### 方式 1: 修改 stack.py

如果你的 Adapter 需要在 `clawsentry gateway` 启动时自动加载：

```python
# 在 stack.py 中添加自定义 Adapter 的初始化逻辑
if os.getenv("CUSTOM_AGENT_ENABLED"):
    from my_adapter import CustomAgentAdapter
    adapter = CustomAgentAdapter(gateway_client=gateway)
    # 注册事件接收端点等
```

### 方式 2: 独立进程

Adapter 也可以作为独立进程运行，通过 UDS 或 HTTP 与 Gateway 通信：

```bash
# 终端 1: 启动 Gateway
clawsentry gateway

# 终端 2: 启动自定义 Adapter
python my_adapter_service.py
```

这种方式的优势是 Adapter 和 Gateway 可以独立部署、升级和重启。

---

## 降级策略

当 Gateway 不可达时，Adapter 必须能够独立做出保守的安全决策。ClawSentry 提供了 `make_fallback_decision()` 工厂函数：

```python
from clawsentry.gateway.policy_engine import make_fallback_decision
```

| 事件类型 | 降级行为 |
|----------|----------|
| `pre_action` + 高危标记 | **BLOCK**（fail-closed） |
| `pre_action` + 无高危标记 | **DEFER**（等待重试） |
| `pre_prompt` | **ALLOW**（fail-open） |
| `post_action` / `post_response` / `error` / `session` | **ALLOW**（观察型事件） |

!!! tip "高危标记判断"
    ```python
    has_high_danger = bool(
        set(event.risk_hints) & {"destructive_pattern", "shell_execution"}
    )
    ```
    `risk_hints` 中包含 `destructive_pattern` 或 `shell_execution` 时视为高危。
