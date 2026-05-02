---
title: Scope 限制
description: 安全决策引擎如何用 SessionScopeProfile 为单次任务限制工具、路径、域名和命令前缀
---

# Scope 限制

<div class="cs-doc-hero" markdown>
<p class="cs-eyebrow">TASK-BOUNDARY ENFORCEMENT</p>

## 把“这次任务能碰什么”写进安全决策

Scope 限制让安全决策引擎不只回答“这个动作危险吗”，还回答：**这个动作是否属于本次任务允许的工具、路径、域名和命令范围？** 它是 L1/L2/L3 风险判断之外的任务边界层：高风险动作仍会被阻断；低风险动作如果越界，也可以被解释、延迟或阻断。

<div class="cs-pill-row" markdown>
<span class="cs-pill">工具 allow/deny</span>
<span class="cs-pill">路径前缀</span>
<span class="cs-pill">域名边界</span>
<span class="cs-pill">命令前缀</span>
<span class="cs-pill">dry-run → enforced</span>
</div>
</div>

## 适合解决什么问题

<div class="cs-card-grid" markdown>
<div class="cs-card" markdown>

### 文档任务不该碰 SSH key

把 `site-docs/`、`docs/` 放进允许路径，把 `~/.ssh`、`.env` 放进底线禁止路径。即使读取命令本身低风险，也会因为越界被标记。

</div>
<div class="cs-card" markdown>

### 修 bug 不该外传数据

为任务声明允许域名；未列入的域名访问会出现 `scope_defer:unknown_domain`，网络写入会出现 `scope_defer:network_write`。

</div>
<div class="cs-card" markdown>

### 自动化脚本不该升级权限

`sudo`、递归删除、格式化设备等 destructive command 会触发底线 deny，即使 profile 作者忘了手写对应 command prefix。

</div>
</div>

## 决策顺序

<div class="cs-flow" markdown>
CanonicalEvent + DecisionContext.session_scope_profile → deterministic evaluator → `allow` / `defer` / `deny` / `neutral` reason codes → policy engine 只在 confirmed 且非 dry-run 时收紧 ALLOW → 最终 decision 进入 watch/report/SSE
</div>

### 四种 verdict 怎么读

| verdict | 典型 reason code | 对真实决策的影响 |
|---------|------------------|------------------|
| `deny` | `scope_deny:path ~/.ssh`、`scope_deny:domain pastebin.com`、`scope_deny:destructive_command` | enforced 时把动作收紧为 `block`。 |
| `defer` | `scope_defer:unknown_path ...`、`scope_defer:unknown_domain ...`、`scope_defer:network_write` | enforced 且原决策不是 block/defer 时，收紧为 `defer`。 |
| `allow` | `scope_allow:path_prefix site-docs/`、`scope_allow:tool read_file` | 只说明在任务范围内，仍需叠加 L1/L2/L3 风险判断。 |
| `neutral` | `scope_neutral:no_applicable_rule` | 没有适用 scope 规则，回到普通风险判断。 |

!!! tip "默认先 dry-run"
    推荐先在 `dry_run: true` 下运行 `clawsentry scope validate/preview` 或 `POST /ahp/scope/preview`。只有 profile 被 operator 确认，并且 `dry_run: false` 后，scope 才会真实收紧 Gateway 决策。

## 最小示例：文档维护范围

```json
{
  "scope_version": "cs.session_scope.v1",
  "profile_id": "docs-only",
  "source": "operator",
  "confirmed": false,
  "dry_run": true,
  "base_rules": {
    "denied_paths": ["~/.ssh", ".env"],
    "denied_domains": ["pastebin.com", "file.io"],
    "denied_command_prefixes": ["sudo", "rm -rf"]
  },
  "task_rules": {
    "allowed_tools": ["read_file", "write_file"],
    "allowed_path_prefixes": ["site-docs/", "docs/"],
    "allowed_domains": ["github.com"],
    "allowed_command_prefixes": ["git status", "python -m pytest"],
    "queued_categories": ["network"]
  }
}
```

预览一个访问 `~/.ssh/id_rsa` 的事件：

```bash
clawsentry scope preview --profile scope.json --event event.json --json
```

典型结果：

```json
{
  "mode": "dry_run_only",
  "scope_evaluation": {
    "profile_id": "docs-only",
    "confirmed": false,
    "dry_run": true,
    "enforced": false,
    "verdict": "deny",
    "reason_codes": ["scope_deny:path ~/.ssh"]
  }
}
```

这说明 profile 的规则可以解释“如果正式启用会阻断什么”，但 dry-run 阶段不会真的 block/defer。

## 从预览到真实收紧

<div class="cs-operator-path" markdown>
<div class="cs-path-option cs-path-option--recommended" markdown>

### 1. Validate

先校验 profile schema：

```bash
clawsentry scope validate --profile scope.json
```

</div>
<div class="cs-path-option" markdown>

### 2. Preview

用代表性事件调试 reason codes：

```bash
clawsentry scope preview --profile scope.json --event event.json --json
```

</div>
<div class="cs-path-option" markdown>

### 3. Enforce

确认不会误伤后，把 profile 放进 AHP 决策上下文，且设置：

```json
{"confirmed": true, "dry_run": false}
```

</div>
</div>

## 它和 L1/L2/L3 的关系

<div class="cs-before-after" markdown>
<div markdown>

### Scope 不会降低风险

如果 L1/L2/L3 已经因为 high/critical 风险决定 block，scope 不会把它改回 allow。

</div>
<div markdown>

### Scope 只会收紧边界

当原决策允许动作继续时，enforced scope 的 `deny` 可收紧为 block，`defer` 可收紧为人工审批。

</div>
</div>

## 代码级核查证据

| 结论 | 代码证据 |
|------|----------|
| Profile schema 支持 base/task 两层规则 | `src/clawsentry/gateway/models.py:201-246` 定义 `SessionScopeBaseRules`、`SessionScopeTaskRules`、`SessionScopeProfile`，字段包括 denied/allowed tools、paths、domains、command prefixes、`confirmed`、`dry_run`。 |
| verdict 和报告摘要是固定模型 | `src/clawsentry/gateway/models.py:83-93` 定义 source/verdict 枚举；`src/clawsentry/gateway/models.py:258-269` 定义 `SessionScopeEvaluationSummary`。 |
| evaluator 是 deterministic 且只读 context profile | `src/clawsentry/gateway/session_scope.py:75-116` 从 `DecisionContext.session_scope_profile` 读取 profile，返回 deny/defer/allow/neutral 和 reason codes。 |
| enforced 条件是 confirmed 且非 dry-run | `src/clawsentry/gateway/session_scope.py:43-56` 的 `enforced` 属性与 summary 输出使用 `confirmed and not dry_run`。 |
| base deny 覆盖工具、命令前缀、路径、域名与破坏性命令 | `src/clawsentry/gateway/session_scope.py:153-178` 生成 `scope_deny:*` reason codes。 |
| task allow/defer 覆盖工具、命令前缀、路径、域名、网络写入/未声明网络 | `src/clawsentry/gateway/session_scope.py:181-237` 生成 `scope_allow:*` 与 `scope_defer:*` reason codes。 |
| policy engine 只在 pre_action 上应用 scope | `src/clawsentry/gateway/policy_engine.py:324-336` 非 `pre_action` 直接返回原 decision。 |
| dry-run 只附加解释，不收紧决策 | `src/clawsentry/gateway/policy_engine.py:338-352` 在 `enforced=false` 时只追加 `scope_evaluation` 与 reason suffix。 |
| enforced deny/defer 会收紧决策 | `src/clawsentry/gateway/policy_engine.py:354-381` 将 `deny` 转成 `block`，将可收紧的 `defer` 转成人工审批。 |
| CLI preview/validate 已实现 | `src/clawsentry/cli/scope_command.py:16-81` 提供 `scope validate` 与 `scope preview`，并输出 protection statement。 |
| HTTP preview endpoint 已实现 | `src/clawsentry/gateway/server.py:3526-3565` 暴露 `POST /ahp/scope/preview`，支持 `confirm=true` 转 enforced preview。 |
| 当前行为有测试锁定 | `src/clawsentry/tests/test_scope_command.py:57-112` 验证 CLI dry-run/enforced preview；`src/clawsentry/tests/test_gateway.py:2444-2479` 验证 HTTP preview；`src/clawsentry/tests/test_watch_command.py:1493-1517` 验证 watch 展示 scope boundary。 |

## 继续阅读

- 配置字段与完整示例：[Session scope 配置](../configuration/session-scope.md)
- API 预览端点：[POST /ahp/scope/preview](../api/decisions.md#post-ahp-scope-preview)
- 与 sanitizer 的边界：[Sanitizer 当前能力](sanitizer-capability.md)
