---
title: Scope 限制
description: 用最小权限 profile 让 ClawSentry 在每次工具执行前自动检查任务边界
---

# Scope 限制

<div class="cs-doc-hero" markdown>
<p class="cs-eyebrow">AUTOMATIC TASK BOUNDARY</p>

## 配置一次，之后每次工具执行前自动检查

Scope 限制的作用很简单：告诉 ClawSentry **这个任务允许 Agent 碰哪些工具、路径、域名和命令**。配置好默认 scope profile 后，启动 ClawSentry 期间，每个 `pre_action` 工具调用都会自动经过 scope 检查；越界动作会被解释、要求审批或直接阻断。

<div class="cs-pill-row" markdown>
<span class="cs-pill">先配置 profile</span>
<span class="cs-pill">clawsentry start 后自动检查</span>
<span class="cs-pill">越界 block / defer</span>
<span class="cs-pill">不会降低原有风险阻断</span>
</div>
</div>

## 这个功能是什么？

你可以把 Scope 限制理解成 **“本次任务的安全围栏”**。

例如你只想让 Agent 改文档：

- ✅ 可以读写 `site-docs/`、`docs/`
- ✅ 可以运行 `git status`、`python -m pytest`
- ⚠️ 访问未列入的域名先让人确认
- ⛔ 永远不碰 `~/.ssh`、`.env`、`sudo`、`rm -rf`

Scope 不取代 L1/L2/L3 风险引擎。它是在原有风险判断之外，再加一层“这个动作是不是属于当前任务”的检查。

## 开启后是不是自动进行？

**是，但前提是你配置了默认 scope profile。**

<div class="cs-before-after" markdown>
<div markdown>

### 已配置默认 profile

```bash
CS_SESSION_SCOPE_PROFILE_FILE=scope.json clawsentry start --framework codex
```

之后 ClawSentry 收到每个 `pre_action` 决策请求时，都会自动加载这份 profile 做 scope 检查。

</div>
<div markdown>

### 没配置默认 profile

```bash
clawsentry start --framework codex
```

ClawSentry 仍会做普通 L1/L2/L3 风险判断，但不会凭空知道“这次任务允许访问哪里”。

</div>
</div>

!!! info "自动检查不是自动猜任务范围"
    当前 ClawSentry 不会从一句自然语言任务里自动推断 scope。你需要提供一份 profile；一旦提供，Gateway 会在运行期间自动把它应用到没有显式 scope 的决策请求上。

## 大概底层原理

<div class="cs-flow" markdown>
Agent 要执行工具 → Adapter 发 `pre_action` 给 ClawSentry → Gateway 自动附加默认 `SessionScopeProfile` → Scope evaluator 产出 `allow/defer/deny/neutral` → Policy engine 把越界动作收紧为 `defer` 或 `block` → watch/report 显示 reason code
</div>

### 它会检查哪些东西？

| 检查对象 | 你能配置什么 | 例子 |
|---------|--------------|------|
| 工具 | 允许/禁止哪些 tool name | 只允许 `read_file`、`write_file` |
| 路径 | 允许路径前缀、禁止敏感路径 | 允许 `site-docs/`，禁止 `~/.ssh` |
| 域名 | 允许/禁止访问哪些域名 | 允许 `github.com`，禁止 `pastebin.com` |
| 命令 | 允许/禁止命令前缀 | 允许 `python -m pytest`，禁止 `sudo` |
| 网络写入 | 未明确允许时要求审批 | `curl -d ...` 触发 `scope_defer:network_write` |

### 四种结果怎么理解？

| 结果 | 意思 | 自动执行效果 |
|------|------|--------------|
| `allow` | 动作在任务范围内 | 继续交给 L1/L2/L3 风险判断，不代表一定放行所有高危动作。 |
| `defer` | 动作可能越界，需要人确认 | 如果 profile 已 enforce，原本允许的动作会变成 `defer`。 |
| `deny` | 动作命中底线禁止项 | 如果 profile 已 enforce，动作会变成 `block`。 |
| `neutral` | 没有 scope 规则命中 | 回到普通风险判断。 |

## 如何配置：最小可用 profile

创建 `scope.json`：

```json
{
  "scope_version": "cs.session_scope.v1",
  "profile_id": "docs-only",
  "source": "operator",
  "confirmed": true,
  "dry_run": false,
  "base_rules": {
    "denied_paths": ["~/.ssh", ".env"],
    "denied_domains": ["pastebin.com", "file.io"],
    "denied_command_prefixes": ["sudo", "rm -rf"]
  },
  "task_rules": {
    "allowed_tools": ["read_file", "write_file", "bash"],
    "allowed_path_prefixes": ["site-docs/", "docs/", "README.md"],
    "allowed_domains": ["github.com"],
    "allowed_command_prefixes": ["git status", "python -m pytest", "mkdocs build"]
  }
}
```

字段只需要记住三点：

| 字段 | 用户视角 |
|------|----------|
| `confirmed: true` | 这份规则已经确认过，可以用于真实决策。 |
| `dry_run: false` | 不只是预览；越界时可以真的 `defer` / `block`。 |
| `base_rules.denied_*` | 底线禁止项，任务规则不能覆盖。 |
| `task_rules.allowed_*` | 本次任务允许范围。 |

!!! warning "第一次配置建议先 dry-run"
    如果你担心误伤，把 `confirmed` 设为 `false`、`dry_run` 设为 `true`，先看 watch/report 里的 reason codes；确认没问题后再改成 `confirmed: true`、`dry_run: false`。

## 如何使用：推荐流程

<div class="cs-operator-path" markdown>
<div class="cs-path-option cs-path-option--recommended" markdown>

### 1. 写 profile

把上面的 JSON 保存成 `scope.json`，根据你的任务修改允许路径、域名和命令前缀。

</div>
<div class="cs-path-option" markdown>

### 2. 校验 profile

```bash
clawsentry scope validate --profile scope.json
```

这一步只检查格式和字段，不会启动防护。

</div>
<div class="cs-path-option" markdown>

### 3. 启动自动检查

```bash
CS_SESSION_SCOPE_PROFILE_FILE=scope.json clawsentry start --framework codex
```

启动后，后续进入 ClawSentry 的 `pre_action` 决策都会自动套用这份默认 profile。

</div>
</div>

## 如何看效果

开另一个终端观察：

```bash
clawsentry watch --interactive
```

如果 Agent 尝试访问 `~/.ssh/id_rsa`，你会看到类似：

```text
Scope: enforced profile=docs-only verdict=deny
Reasons: scope_deny:path ~/.ssh
Decision: block
```

如果 Agent 访问了没列入允许范围的域名，可能看到：

```text
Scope: enforced profile=docs-only verdict=defer
Reasons: scope_defer:unknown_domain unknown.example
Decision: defer
```

## 常见问题

### 只要开了 ClawSentry，就一定有 scope 吗？

不是。普通 `clawsentry start` 会启用风险引擎，但 **scope 需要一份任务范围 profile**。推荐通过 `CS_SESSION_SCOPE_PROFILE_FILE=scope.json` 配置默认 profile，让它在 Gateway 里自动应用。

### 我每次任务都要改 profile 吗？

取决于你的使用方式：

- 固定项目/固定目录：可以长期使用一份项目 profile。
- 不同任务边界差别很大：建议每个任务换一份 profile。
- 只想先观察：用 `dry_run: true`，不真实阻断。

### scope 会不会把高风险动作放行？

不会。Scope 只会收紧，不会降低 L1/L2/L3 已经给出的高风险阻断。

### 上游 AHP 请求自己带了 scope 怎么办？

上游请求里的 `context.session_scope_profile` 优先级更高。默认 profile 只在请求没有显式 scope 时自动补上。

## 代码级依据

| 结论 | 代码证据 |
|------|----------|
| 默认 profile 可通过环境变量加载 | `src/clawsentry/gateway/server.py` 的 `_load_default_session_scope_profile()` 读取 `CS_SESSION_SCOPE_PROFILE_FILE` / `CS_SESSION_SCOPE_PROFILE` 并验证为 `SessionScopeProfile`。 |
| Gateway 会给无 scope 的请求自动补默认 profile | `src/clawsentry/gateway/server.py` 的 `_context_with_default_session_scope()` 在请求 context 缺少 `session_scope_profile` 时补上默认 profile。 |
| 只检查 `pre_action` | `src/clawsentry/gateway/policy_engine.py:324-336` 只在工具执行前决策中应用 scope。 |
| enforced 条件 | `src/clawsentry/gateway/session_scope.py:43-56` 使用 `confirmed and not dry_run` 判定是否真实执行。 |
| deny/defer 如何收紧决策 | `src/clawsentry/gateway/policy_engine.py:354-381` 把 enforced `deny` 收紧为 `block`，把 enforced `defer` 收紧为人工审批。 |

## 继续阅读

- 详细字段参考：[Session scope 配置](../configuration/session-scope.md)
- API 预览端点：[POST /ahp/scope/preview](../api/decisions.md#post-ahp-scope-preview)
- Sanitizer 与 scope 的边界：[Sanitizer 当前能力](sanitizer-capability.md)
