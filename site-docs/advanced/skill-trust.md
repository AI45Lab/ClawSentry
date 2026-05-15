---
title: Skill Trust / Registry
description: 用 Skill Trust registry、preflight scan 和 first-use action 管理 agent skill 供应链风险
---

# Skill Trust / Registry

Skill Trust 用来把本地 skill 包的身份、来源、hash、别名和安全扫描结果变成 Gateway 可审计的运行时上下文。它解决的是 skill 供应链与 metadata trust 问题：低信任 skill 不能只靠文档声称自己是 canonical，也不能通过近名、改名或 provenance label 绕过策略。

!!! note "发布状态"
    v0.7.0 提供 registry/preflight、first-use action 和审计 metadata。该功能面向运行时 skill 供应链治理，默认保持 audit-only，便于逐步接入。

## 工作流

1. 对一个 skill 根目录运行 deterministic scan。
2. 把通过 review 的 skill 写入 registry，并生成 Gateway-owned runtime metadata。
3. Gateway 在 `pre_action` 决策中解析请求携带的 skill raw metadata，与 registry 做 identity/provenance/hash 匹配。
4. 首次使用、unknown、unbound、greylist、blacklist、disabled 或 invariant violation 会按 profile 动作进入 audit、L2/L3、DEFER 或 BLOCK。

## CLI

```bash
clawsentry skill-trust scan \
  --skill-root ~/.codex/skills/travel_planning \
  --json
```

```bash
clawsentry skill-trust register \
  --skill-root ~/.codex/skills/travel_planning \
  --registry .clawsentry/skill-trust-registry.json \
  --framework codex \
  --scope workspace \
  --list-state allowlist \
  --operator-override review-2026-05-16 \
  --json
```

```bash
clawsentry skill-trust register-dir \
  --skills-dir ~/.codex/skills \
  --registry .clawsentry/skill-trust-registry.json \
  --metadata .clawsentry/skill-trust-runtime.json \
  --framework codex \
  --scope workspace \
  --json
```

## Runtime 配置

```bash
CS_SKILL_TRUST_REGISTRY_PATH=.clawsentry/skill-trust-registry.json
CS_SKILL_TRUST_METADATA_PATH=.clawsentry/skill-trust-runtime.json

CS_SKILL_TRUST_FIRST_USE_NORMAL_ACTION=audit
CS_SKILL_TRUST_FIRST_USE_BENCHMARK_ACTION=block
CS_SKILL_TRUST_FIRST_USE_STRICT_ACTION=defer
CS_SKILL_TRUST_FIRST_USE_PERMISSIVE_ACTION=audit
```

动作含义：

| 动作 | 含义 |
|---|---|
| `audit` | 记录 evidence，不改变当前判决 |
| `force_l2` | 要求语义分析参与复核 |
| `force_l3` | 要求 L3 review agent 参与复核 |
| `defer` | 进入 operator approval / DEFER path |
| `block` | 直接阻断首次或不可信 skill 使用 |

## Trust States

| 状态 | 典型含义 |
|---|---|
| `allowlist` | 已登记并经 operator 或 policy 认可 |
| `greylist` | 已知但需要复核或更严格 profile |
| `blacklist` | 禁用或明确不可信 |
| `revoked` | 之前可信但已撤销 |
| `local_unreviewed` | 本地存在，但缺少 registry review |
| `unknown` / `unbound` | 请求侧 metadata 无法绑定到 registry |

## Redaction Boundary

Gateway 不信任请求侧 raw skill metadata。请求 raw 字段会被降级/清洗，只保留 presented name、framework、scope、registry status、invariant violations 等审计所需字段；不会把任意 raw package content 当作 operator-approved metadata。

## 与 Capability Narrowing 的关系

Skill Trust 是 identity/provenance evidence；capability narrowing 是后续能力收紧。启用 `CS_CAPABILITY_NARROWING_ENABLED=true` 后，高会话风险可自动应用更窄的 `SessionScopeProfile`，限制不可信 skill state、MCP server/tool 或外部域名。它不会静默改写历史 canonical decision。
