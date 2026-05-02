---
title: Sanitizer 当前能力
description: 用代码证据说明 ClawSentry sanitizer 当前能做什么、不能做什么，以及 operator 应如何解读 redacted preview 与 adapter effect
---

# Sanitizer 当前能力

<div class="cs-doc-hero" markdown>
<p class="cs-eyebrow">CAPABILITY-HONEST SANITIZER</p>

## 先识别泄露，再按 adapter 能力改写

ClawSentry 当前的 sanitizer **不是“自动清洗所有历史内容”的总开关**。它最稳定、最可依赖的能力是：在 tool output 进入观察/报告链路后，识别疑似 secret，生成 redacted preview、hash 与数量摘要；如果要改写执行前输入，必须看具体 adapter 是否真的支持并回写 `adapter_effect_result`。

<div class="cs-pill-row" markdown>
<span class="cs-pill">tool_output：advisory-only</span>
<span class="cs-pill">command/tool_input：需 adapter 支持</span>
<span class="cs-pill">审计面只展示 hash / redacted preview</span>
</div>
</div>

## 一眼判断：它保护什么，不保护什么

<div class="cs-before-after" markdown>
<div markdown>

### 当前已保护

- 工具输出里出现疑似 token、私钥、密码、Bearer、云凭证等内容时，报告中只展示 redacted preview。
- post-action finding 会记录 `would_sanitize`、`redaction_counts`、`redaction_types`、`original_hash`、`sanitized_hash`。
- `decision_effects.sanitize_effect` 可以表达 command / tool_input 的清洗请求，但真实执行要看 adapter 回写。

</div>
<div markdown>

### 当前不承诺

- 不承诺所有框架都能在宿主 history 写入前改写 tool output。
- 不把 `tool_output` sanitizer 伪装成 `decision=modify`。
- 不展示完整替换 payload；replay/watch/report 默认只保留安全摘要。

</div>
</div>

!!! note "用户视角的关键区别"
    `would_sanitize` 的意思是“ClawSentry 发现并安全展示了本应净化的内容”；它不是“已经把宿主框架里的原始输出强制替换掉”。如果目标是阻止动作发生，应优先使用 `block` / `defer` / [Scope 限制](scope-restrictions.md)。

## 当前链路怎么工作

<div class="cs-flow" markdown>
工具返回 output → Post-action analyzer 识别 secret → 生成 redacted preview / hash / counts → watch、report、SSE、trajectory 展示安全摘要 → operator 决定是否 rotate secret、阻断后续动作或收紧 scope
</div>

当工具输出里出现疑似敏感内容时，你会看到类似：

```text
Sanitizer: would_sanitize tool_output
Redactions: secret=1
Preview: [REDACTED:secret]
```

这表示：ClawSentry 已经在观察面把敏感片段替换成安全摘要；你不需要、也不应该要求系统打印原始 secret 来排障。

## 能检测哪些 secret 形态

当前实现用一组正则模式识别常见凭证形态，命中后统一按 `secret` 类别计数与展示。

| 检测形态 | 当前实现覆盖的示例 |
|---------|-------------------|
| 云凭证 | `AWS_ACCESS_KEY_ID=...`、`AWS_SECRET_ACCESS_KEY=...`、`AKIA...` |
| GitHub token | `ghp_...`、`ghs_...`、`ghu_...`、`github_pat_...` |
| 私钥块 | RSA / EC / OpenSSH / DSA / PGP private key header |
| 密码/API token | `password=...`、`api_key=...`、`secret_key=...`、`access_token=...` |
| Bearer token | `Authorization: Bearer ...` 或相同形态文本 |
| 数据库连接串 | `DATABASE_URL=scheme://user:pass@...` |
| 协作平台 token | Slack `xox...`、Lark/Feishu `tenant_access_token=t-...` 等 |
| 钱包私钥上下文 | `private_key=0x...`、`wallet_key=0x...` |

!!! warning "不要误读 redaction_types"
    当前 post-action sanitizer 的 `redaction_types` 不是细分的 `api_key` / `github_token` / `aws_secret`，而是统一的 `secret`。文档和 UI 示例应使用 `secret=1` 这类事实一致的表达。

## 报告字段怎么读

```json
{
  "target": "tool_output",
  "would_sanitize": true,
  "redaction_types": ["secret"],
  "redaction_counts": {"secret": 1},
  "original_preview_redacted": "[REDACTED:secret]",
  "sanitized_preview_redacted": "[REDACTED:secret]",
  "adapter_outcome": "would_sanitize",
  "enforcement": "advisory_only"
}
```

| 字段 | 用户该怎么理解 |
|------|----------------|
| `would_sanitize: true` | 输出里有疑似敏感内容；报告面已安全展示。 |
| `redaction_counts` / `redaction_types` | 当前按 `secret` 统一计数，可用于估算影响范围。 |
| `original_hash` / `sanitized_hash` | 保留取证关联，不暴露原文。 |
| `original_preview_redacted` | “原始输出的安全预览”，不是原始 secret。 |
| `sanitized_preview_redacted` | 清洗后的安全预览；当前通常与 redacted original preview 一致。 |
| `adapter_outcome: would_sanitize` | 观察面发现了需要清洗的内容。 |
| `enforcement: advisory_only` | 没有声称已跨框架改写宿主 history。 |

## 哪些 adapter 能改写

| 接入路径 / 目标 | 当前事实 | 用户该怎么用 |
|-----------------|----------|--------------|
| AHP / a3s-code 显式 transport：`modified_payload` | Gateway result 会带出 `action=modify` 与 `modified_payload`；是否执行替换取决于宿主/adapter。 | 用 `adapter_effect_result` 判断是否 `enforced`，不要只看 Gateway 请求。 |
| command / tool_input sanitizer effect | 模型支持 `command_sanitize` / `tool_input_sanitize`，带 `replacement_payload` 时要求 `decision=modify`。 | 适合执行前输入改写；审计面隐藏完整 replacement payload。 |
| tool output sanitizer effect | 模型强制 `advisory_only=true`，默认 outcome 为 `tool_output_would_sanitize`，且不能携带 `replacement_payload`。 | 用于发现与展示，不作为跨框架 history rewrite 证明。 |
| Codex native hook path | 当前 harness 把 PreTool effect 记录为 unsupported/degraded；hook 输出主要支持 block/defer。 | 不依赖它做 ClawSentry sanitizer rewrite。 |
| Kimi native hook path | Kimi hook 只表达 allow/block；`modify` fail-open。 | 不依赖自动改写；必要时改用 block/defer。 |
| Gemini `BeforeTool` path | `modify` 可映射为 `hookSpecificOutput.tool_input`。 | 只对 BeforeTool 输入替换有意义，不代表 tool output 已改写。 |

## 看到 sanitizer 事件后该做什么

<div class="cs-operator-path" markdown>
<div class="cs-path-option cs-path-option--recommended" markdown>

### 1. 先判定影响

看 `redaction_counts`、命中事件、工具名和 session，确认是一次偶发输出，还是 Agent 正在持续读取/打印 secret。

</div>
<div class="cs-path-option" markdown>

### 2. 再处理凭证

如果是有效凭证，优先 rotate secret、撤销 token、检查下游日志，不要通过 watch/report 取回原始值。

</div>
<div class="cs-path-option" markdown>

### 3. 最后收紧边界

用 `block` / `defer` 阻止高风险动作；用 [Scope 限制](scope-restrictions.md) 把本次任务可访问的路径、域名、工具和命令前缀缩小。

</div>
</div>

## 代码级核查证据

| 结论 | 代码证据 |
|------|----------|
| tool output sanitizer 是 post-action advisory | `src/clawsentry/gateway/post_action_analyzer.py:151-166` 构造 `SanitizeAdvisory`，`target=tool_output`，`adapter_outcome=would_sanitize`，`enforcement=advisory_only`。 |
| 当前 redaction 统一计为 `secret` | `src/clawsentry/gateway/post_action_analyzer.py:179-186` 遍历 `_SECRET_PATTERNS` 后统一替换为 `[REDACTED:secret]` 并累加 `counts["secret"]`。 |
| secret 模式覆盖范围 | `src/clawsentry/gateway/post_action_analyzer.py:91-110` 定义 AWS、GitHub、private key、password/API/access token、Bearer、DATABASE_URL、OpenAI key、Slack、Feishu/Lark、钱包私钥上下文等模式。 |
| analyzer 只在命中时把 advisory 放进 finding | `src/clawsentry/gateway/post_action_analyzer.py:441-443` 仅当 `would_sanitize` 为真时写入 `details["sanitize_advisory"]`。 |
| tool output 不能声明 canonical modify | `src/clawsentry/gateway/models.py:409-417` 对 `target=tool_output` 禁止 `replacement_payload`、设置 `advisory_only=true`；`src/clawsentry/gateway/models.py:662-668` 禁止 `tool_output sanitize_effect` 与 `decision=modify` 组合。 |
| 输入 sanitizer 带替换 payload 时必须是 modify | `src/clawsentry/gateway/models.py:669-676` 要求 command/tool_input sanitizer 的 `replacement_payload` 只能配合 `decision=modify`。 |
| adapter enforcement 是独立证据 | `src/clawsentry/gateway/models.py:448-508` 定义 `AdapterEffectResult` 的 `enforced` / `degraded` / `unsupported` 与 `degrade_reason`。 |
| AHP result 会携带 `modified_payload` / `decision_effects` | `src/clawsentry/adapters/a3s_gateway_harness.py:246-270` 将 canonical decision 转成 AHP result，并透出 `modified_payload` 与 `decision_effects`。 |
| Kimi 不支持 native modify | `src/clawsentry/adapters/kimi_adapter.py:248-264` 说明 Kimi hook allow/block-only，`modify` 返回 `None`。 |
| Gemini BeforeTool 可表达输入替换 | `src/clawsentry/adapters/gemini_adapter.py:247-257` 把 `modified_payload.tool_input` 映射到 `hookSpecificOutput.tool_input`。 |
| 当前行为有测试锁定 | `src/clawsentry/tests/test_post_action_analyzer.py:958-984` 验证 advisory redaction 与 advisory-only；`src/clawsentry/tests/test_decision_effects.py:379-507` 验证 tool output advisory、禁止 output modify、输入 sanitize 约束与 summary 去 payload。 |

## 一句话总结

ClawSentry sanitizer 当前适合做 **泄露发现、安全展示和可审计输入改写请求**；它不是跨所有 Agent 框架的万能输出改写器。判断“是否真的改写”时，请看 adapter effect 的 `enforced` / `degraded` / `unsupported`，而不是只看 Gateway 的 sanitizer 请求。
