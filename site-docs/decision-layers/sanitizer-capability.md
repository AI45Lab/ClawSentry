---
title: Sanitizer 当前能力
description: ClawSentry 当前是否有 sanitizer、它能做什么、在哪里看到结果、以及哪些场景不要依赖它
---

# Sanitizer 当前能力

先给结论：**ClawSentry 现在有 sanitizer，但它不是一个“自动清洗所有内容”的独立开关。**

当前 sanitizer 主要做两件事：

1. **对工具输出做泄露识别和安全展示**：发现 secret / token / 私钥等内容时，在 watch/report/SSE 里给出 redacted preview、命中类型和数量。
2. **为执行前输入改写保留决策协议**：当某个 adapter 明确支持修改输入时，Gateway 可以请求改写 command 或 tool input；否则会显示 degraded/unsupported，而不是假装已经改写成功。

如果你只是日常使用 ClawSentry，最需要理解的是第一项：它会告诉你“工具输出里出现了本应被净化的敏感内容”，并用安全摘要展示给 operator。

## 对 a3s-code：到底能不能改写？

**能，但只限执行前输入：command / tool input。不能强制改写已经返回的 tool output。**

| 接入路径 / 目标 | 现在能否改写 | 用户该怎么理解 |
|-----------------|--------------|----------------|
| `a3s-code` 显式 AHP transport：command | **能** | Gateway 返回 `decision=modify` + `modified_payload`，a3s-code 按 `modified_payload.command` 执行替换后的命令。 |
| `a3s-code` 显式 AHP transport：tool input | **能** | Gateway 返回 `decision=modify` + `modified_payload`，a3s-code 使用替换后的 tool input。 |
| `a3s-code` 显式 AHP transport：tool output | **不能强制改写** | ClawSentry 只在报告/监控里显示 `would_sanitize`、redacted preview 和 redaction counts。 |
| Codex native hook path | **当前不能按 ClawSentry effect 强制改写** | 会记录为 degraded/unsupported，而不是声称执行了 rewrite。 |
| Kimi native hook path | **不能** | Kimi 当前没有 native modify/defer parity；`modify` 不会改写工具输入。 |
| Gemini `BeforeTool` path | **可以表达 tool input 修改** | ClawSentry 会把 `modified_payload.tool_input` 映射到 Gemini hook output；是否实际替换由 Gemini hook 执行结果决定。 |

所以，如果你问的是 **a3s-code reference / AHP 显式接入**：答案是 **可以改写执行前的 command/tool input**。如果你问的是 **工具已经输出了 secret 以后能不能把宿主 history 里的输出改掉**：答案是 **不能统一保证，当前只做 would-sanitize 报告和安全展示**。

## 我应该启用它吗？

**不需要单独启用。**

Sanitizer 的输出泄露识别属于 post-action 分析的一部分。只要你的 ClawSentry Gateway 正在接收工具输出事件，`clawsentry watch`、report/SSE 和相关审计视图就会在命中时显示 sanitizer 摘要。

典型使用方式：

```bash
clawsentry start --framework codex
clawsentry watch --interactive
```

当工具输出里出现疑似 secret 时，你会看到类似：

```text
Sanitizer: would_sanitize tool_output
Redactions: api_key=1
Preview: [REDACTED:api_key]
```

这表示：ClawSentry 发现了需要净化展示的内容，并已经在报告/监控输出里用 redacted preview 展示；你不需要从日志里复制原始 secret 才能判断问题。

## 当前能检测哪些内容？

当前 post-action sanitizer 主要针对工具输出里的常见敏感信息，例如：

| 类型 | 示例场景 |
|------|----------|
| API key / token | OpenAI-style key、GitHub token、Bearer token |
| 云凭证 | AWS access key / secret access key |
| 私钥 | RSA / EC / OpenSSH / PGP private key block |
| 数据库连接串 | 带用户名密码的 `DATABASE_URL` |
| 协作平台 token | Slack token、Lark/Feishu access token |
| 钱包私钥形态 | 带 `private_key` / `wallet_key` 上下文的 64 位 hex key |

命中后，ClawSentry 会记录：

```json
{
  "target": "tool_output",
  "would_sanitize": true,
  "redaction_types": ["api_key"],
  "redaction_counts": {"api_key": 1},
  "original_preview_redacted": "[REDACTED:api_key]",
  "sanitized_preview_redacted": "[REDACTED:api_key]",
  "adapter_outcome": "would_sanitize",
  "enforcement": "advisory_only"
}
```

## 看到 sanitizer 事件后该怎么做？

| 你看到的内容 | 它说明什么 | 你应该做什么 |
|--------------|------------|--------------|
| `would_sanitize: true` | 工具输出里有疑似敏感内容，报告中已安全展示 | 检查该工具为什么输出 secret |
| `redaction_types/counts` | 命中了哪些敏感类型、数量是多少 | 判断影响范围，必要时 rotate secret |
| `Preview: [REDACTED:...]` | 这是安全摘要，不是原文 | 用它排障，不要要求系统打印原始 secret |
| `advisory_only` | 这是观察和报告，不是跨框架强制改写历史 | 若需要强约束，使用 block/defer/scope 或支持改写的 adapter |
| `degraded` / `unsupported` | 当前 adapter 不支持某个 sanitizer effect | 不要依赖自动改写；改用阻断、审批或换接入方式 |

## 它会不会阻止 secret 进入 Agent history？

**不能统一保证。**

很多 Agent 框架的顺序是：工具返回 output 后，宿主框架先把 output 放进自己的上下文或历史，再把事件交给外部观察者。ClawSentry 在观察侧可以发现泄露并安全展示，但不能对所有框架承诺“原始输出从未进入 history”。

因此当前 ClawSentry 对 `tool_output` 的表述是：

- 会显示 `would_sanitize`；
- 会给出 redacted preview、hash、类型和数量；
- 默认是 `advisory_only`；
- 不会携带 `replacement_payload`；
- 不声称已经强制改写工具输出。

如果你的目标是**阻止动作发生**，优先使用：

- L1/L2/L3 风险决策的 `block` / `defer`；
- [Session scope 配置](../configuration/session-scope.md) 限制本次任务可访问的路径、域名、工具和命令前缀；
- 支持输入修改的 adapter 能力，而不是依赖 tool-output sanitizer。

## command / tool input 能不能被改写？

可以，但这是 **adapter 能力相关** 的功能，不是所有接入方式都有。

当 Gateway 决策为 `modify`，并且 adapter 支持修改执行前输入时，ClawSentry 可以请求替换 command 或 tool input。审计面会保留 hash 和 redacted preview，避免把完整 replacement payload 展示到 replay/watch/report 中。

用户判断标准很简单：

| 情况 | 可以怎么理解 |
|------|--------------|
| adapter 回写 `enforced` | 该 adapter 报告它实际执行了 sanitizer/rewrite effect |
| adapter 回写 `degraded` | 它尝试处理但降级了，需要看 `degrade_reason` |
| adapter 回写 `unsupported` | 该接入方式不支持，不要依赖自动改写 |
| 没有 adapter effect result | 只能说明 Gateway 发出了请求，不能证明宿主执行了改写 |

## 一句话总结

ClawSentry 当前 sanitizer **有用，但要按正确用途使用**：

- 对工具输出：用于发现 secret 泄露、生成安全摘要、提醒 operator 处理。
- 对执行前输入：只有 adapter 明确支持修改时，才可作为实际改写能力使用。
- 对强制防护：不要把 sanitizer 当成万能清洗器；需要阻断时用 block/defer/scope。
