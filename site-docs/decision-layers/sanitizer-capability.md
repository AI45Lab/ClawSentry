---
title: Sanitizer 能力边界
description: 解释 ClawSentry 对 command、tool input 和 tool output 能做什么、不能做什么，以及用户如何阅读 would_sanitize/advisory_only
---

# Sanitizer 能力边界

ClawSentry 的 sanitizer 目标不是制造“已经全部净化”的错觉，而是把三件事分清楚：**检测到了什么、能否生成安全替代内容、当前 adapter 是否真的能在宿主记录前改写。**

!!! warning "最重要的边界"
    对 `tool_output`，当前通用能力是 `would_sanitize` + redacted preview + 审计证据。除非某个 adapter 能证明 rewrite-before-history，否则 ClawSentry 不声称已经强制改写了工具输出。

## 三类目标能力

| 目标 | 当前能力 | 是否可声称强制改写 |
|------|----------|--------------------|
| `command` | 可生成 sanitize/rewrite 请求；可附带 replacement payload | 仅当 adapter 支持 `MODIFY` 并执行替换时 |
| `tool_input` | 可生成 sanitize/rewrite 请求；可附带 replacement payload | 仅当 adapter 支持 `MODIFY` 并执行替换时 |
| `tool_output` | 检测敏感内容、生成 redacted preview、记录 hash/type/count、发出 `would_sanitize` | 默认不能；当前是 `advisory_only` |

换句话说：

- **执行前输入**：有机会改写，但要看 adapter 能不能接住 `MODIFY`。
- **执行后输出**：可以发现和安全展示，但不能普遍保证它没有进入 agent history。

## watch/report 里会看到什么

如果 post-action 输出里出现疑似 secret，ClawSentry 会把原始内容转换成 capability-honest advisory：

```json
{
  "target": "tool_output",
  "would_sanitize": true,
  "original_preview_redacted": "[REDACTED:api_key]",
  "sanitized_preview_redacted": "[REDACTED:api_key]",
  "redaction_types": ["api_key"],
  "redaction_counts": {
    "api_key": 1
  },
  "adapter_outcome": "would_sanitize",
  "enforcement": "advisory_only"
}
```

用户应该这样读：

1. `would_sanitize: true`：ClawSentry 识别到如果要安全展示，需要 redact。
2. `redaction_types/counts`：告诉你命中了哪些类型、各多少个。
3. `*_preview_redacted`：给 operator 看安全摘要，不直接泄露原文。
4. `enforcement: advisory_only`：这是审计/提示，不是跨所有框架的强制历史改写。

## 为什么 tool output 不能直接说“已净化”

很多 Agent 框架的流程是：工具返回结果后，宿主框架先把 output 放进自己的上下文或历史，再通知外部观察者。若 ClawSentry 位于观察侧，它可以发现泄露并在报告里 redact，但不能证明原始 output 没进过宿主历史。

因此当前实现强制了两个规则：

- `tool_output` sanitizer 不允许携带 replacement payload。
- `tool_output` sanitizer 自动标记为 `advisory_only`，outcome 为 `tool_output_would_sanitize`。

这避免了误导用户。

## command / tool input 什么时候可以改写

执行前输入与输出不同。对 command 或 tool input，如果 Gateway 生成 `MODIFY` 决策，并且 adapter 支持修改 payload，ClawSentry 可以请求替换内容：

```json
{
  "decision": "modify",
  "decision_effects": {
    "sanitize_effect": {
      "target": "tool_input",
      "original_preview_redacted": "token=[REDACTED:api_key]",
      "sanitized_preview_redacted": "token=[REDACTED:api_key]",
      "replacement_payload": {
        "args": {"token": "[REDACTED:api_key]"}
      }
    }
  }
}
```

但用户仍要看 adapter capability：如果 adapter 只支持 allow/block，那么 ClawSentry 会退化为 degraded/unsupported，而不是假装已经改写。

## 用户应该怎么处理 sanitizer 事件

| 看到的状态 | 含义 | 推荐动作 |
|------------|------|----------|
| `would_sanitize + advisory_only` | 输出里有敏感内容，但当前只做报告/审计 redaction | 检查工具输出来源；必要时 rotate secret；调整规则或 adapter |
| `command_sanitize` / `tool_input_sanitize` | 执行前输入可被请求净化 | 确认 adapter 是否返回 observed effect result |
| `degraded` / `unsupported` | 该框架能力不足 | 不要依赖强制改写；使用 block/defer 或更强 adapter |
| redaction count 增加 | 泄露数量上升 | 优先调查 session、workspace、工具参数来源 |

## 与 scope 的关系

Session scope 管“这次任务允许做什么”；sanitizer 管“内容里是否携带不该暴露的信息”。两者可以同时出现：

- scope 可以因为访问 `.env` 或 `~/.ssh` 直接 deny。
- sanitizer 可以在工具输出已经包含 secret 时给出 `would_sanitize` 与 redacted preview。
- 如果 adapter 不能强制改写输出，sanitizer 仍然保持 advisory-only。

完整配置示例见 [Session scope 配置](../configuration/session-scope.md)。
