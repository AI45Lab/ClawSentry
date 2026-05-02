---
title: Session scope 配置
description: 使用 SessionScopeProfile 为单次任务设置最小权限范围，并在启用前预览 allow/defer/deny 结果
---

# Session scope 配置

Session scope 用来回答一个更贴近用户的问题：**这次任务里，Agent 到底应该能碰哪些工具、路径、域名和命令前缀？**

它不是替代 L1/L2/L3 风险判断，而是在风险判断之外增加一层任务范围约束：高危动作仍会被阻断；低风险动作如果越过本次任务范围，也可以被解释、延迟或阻断。

!!! tip "推荐工作流"
    先用 `dry_run: true` 写 profile，再用 `clawsentry scope validate/preview` 调规则。只有确认不会误伤后，才把 `confirmed: true` 与 `dry_run: false` 用到真实决策上下文里。

## 最小可用 profile

下面这个 profile 表示“本次只做文档维护”：

```json
{
  "scope_version": "cs.session_scope.v1",
  "profile_id": "docs-only",
  "source": "operator",
  "confirmed": false,
  "dry_run": true,
  "base_rules": {
    "denied_tools": ["shell"],
    "denied_paths": ["~/.ssh", ".env"],
    "denied_domains": ["pastebin.com", "file.io"],
    "denied_command_prefixes": ["sudo", "rm -rf"]
  },
  "task_rules": {
    "allowed_tools": ["read_file", "write_file"],
    "allowed_path_prefixes": ["README.md", "site-docs/", "docs/"],
    "allowed_domains": ["github.com"],
    "allowed_command_prefixes": ["git status", "python -m pytest"],
    "queued_categories": ["network"]
  },
  "provenance": {
    "generated_by": "operator-runbook",
    "confirmed_by": null
  }
}
```

### 字段怎么理解

| 字段 | 用途 | 用户视角 |
|------|------|----------|
| `profile_id` | 给这份 scope 起名字 | watch/report 会显示它，便于排障 |
| `confirmed` | operator 是否确认过 | 未确认时不要当成真实收紧依据 |
| `dry_run` | 是否只预览 | `true` 时不会真的 block/defer |
| `base_rules.denied_*` | 不可覆盖的底线 | 例如永远不碰 `~/.ssh` / `.env` |
| `task_rules.allowed_*` | 本次任务允许范围 | 例如文档任务只允许 `site-docs/` |
| `task_rules.queued_categories` | 需要人工复核的类别提示 | 例如未明确 allow 的网络写入先 defer |
| `provenance` | 审计来源 | 记录是谁生成/确认的 profile |

## 本地预览：先看会发生什么

准备一个事件文件 `event.json`：

```json
{
  "event_id": "evt-scope-demo",
  "trace_id": "trace-scope-demo",
  "event_type": "pre_action",
  "session_id": "sess-docs",
  "agent_id": "agent-docs",
  "source_framework": "test",
  "occurred_at": "2026-05-02T00:00:00+00:00",
  "tool_name": "read_file",
  "payload": {
    "path": "~/.ssh/id_rsa"
  }
}
```

验证 profile：

```bash
clawsentry scope validate --profile scope.json
```

预览一次决策：

```bash
clawsentry scope preview --profile scope.json --event event.json --json
```

典型输出会包含：

```json
{
  "mode": "dry_run_only",
  "scope_evaluation": {
    "profile_id": "docs-only",
    "dry_run": true,
    "enforced": false,
    "verdict": "deny",
    "reason_codes": ["scope_deny:path ~/.ssh"]
  },
  "protection_statement": "Protected today: scope preview validates rules and explains the decision that would apply. Not protected today: dry-run scope profiles do not block or defer actions until explicitly confirmed."
}
```

这表示：如果正式启用，这个动作会因为访问 `~/.ssh` 被 deny；但现在仍是 dry-run，所以只是解释，不会真实阻断。

## 确认后如何影响真实决策

当 profile 进入真实决策上下文时，只有下面两个条件同时满足才会收紧 Gateway 决策：

```json
{
  "confirmed": true,
  "dry_run": false
}
```

此时：

- `scope_deny:*` 可以把原本允许的动作收紧为 `block`。
- `scope_defer:*` 可以把原本允许的动作收紧为 `defer`，交给 operator 审批。
- scope 不会降低原本已经是 high/critical 的阻断决策。
- ClawSentry 不会自动从 LLM 任务描述里推断 scope；profile 需要由 operator、项目模板或上游集成显式提供。

AHP / Gateway 集成可以在 `SyncDecisionRequest.context.session_scope_profile` 中传入 profile；CLI 的 `scope preview` 只负责离线校验和预览。

## 常见 reason codes

| reason code | 含义 | 用户下一步 |
|-------------|------|------------|
| `scope_deny:path <path>` | 命中禁止路径 | 改任务范围或拒绝该动作 |
| `scope_deny:domain <domain>` | 命中禁止域名 | 检查是否存在外传风险 |
| `scope_deny:destructive_command` | 命中破坏性命令兜底 | 通常不应放行 |
| `scope_defer:unknown_path <path>` | 路径不在允许前缀内 | 让 operator 判断是否属于本次任务 |
| `scope_defer:unknown_domain <domain>` | 域名不在允许列表 | 检查是否需要网络访问 |
| `scope_defer:network_write` | 发现网络写入行为 | 通常需要人工确认 |
| `scope_allow:path_prefix <prefix>` | 路径在允许前缀内 | 可以继续结合 L1/L2/L3 风险判断 |
| `scope_neutral:no_applicable_rule` | 没有 scope 规则命中 | 回到普通风险判断 |

## 何时不要启用 enforced scope

先保持 dry-run，如果出现以下情况：

- profile 是从自然语言任务自动生成但没人确认；
- 允许路径/域名还没有覆盖实际工作目录；
- 多框架 session 中不同 adapter 传入的 tool name 不一致；
- 你只是想做审计观察，而不是阻断或审批。

此时推荐只使用 preview/report，把 reason codes 作为调参依据。
