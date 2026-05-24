---
title: 配置模板
description: 按功能块复制 ClawSentry dotenv 配置：L1、L2、L3、Anti-bypass、DEFER、Benchmark、生产部署
---

# 配置模板

本页是**唯一推荐复制配置片段的页面**。所有片段都是 dotenv `KEY=VALUE` 格式，可放入 `.clawsentry.env.example`、`.clawsentry.env.local`、CI secret/env 或 systemd `EnvironmentFile=`。不要在 ClawSentry env file 里使用 section、数组或嵌套表。

> **规则**：可提交文件只放非密钥策略；密钥和本机端口放进进程/部署环境或显式 `--env-file .clawsentry.env.local`。
> **使用方式**：`.clawsentry.env.example` 只是模板，启动不会自动读取。日常本机使用时先 `cp .clawsentry.env.example .clawsentry.env.local`，填入本机值后再显式 `--env-file .clawsentry.env.local`。

```bash
cp .clawsentry.env.example .clawsentry.env.local
clawsentry config show --effective --env-file .clawsentry.env.local
clawsentry start --env-file .clawsentry.env.local --framework codex --open-browser
```

---

## 该选哪个模板？ {#choose-template}

| 你的目标 | 复制哪些块 | 下一步 |
|---|---|---|
| 先跑起来看 Gateway / Web UI | [基础骨架](#base-skeleton) + [L1 only](#template-l1-only) | `clawsentry start --framework codex`；如已有本机 env 文件则加 `--env-file .clawsentry.env.local` |
| 团队共享 L2 语义分析 | [基础骨架](#base-skeleton) + [L2 + token budget](#template-l2-budgeted) | 配本机 `CS_LLM_API_KEY` |
| 高风险操作同步审查 | [严格 L3](#template-l3-strict) + [DEFER 审批](#template-defer-bridge) | 先小仓库试运行 |
| 防重试/绕过 | [Anti-bypass Guard](#template-anti-bypass) | 先记录命中，再按审计结果调整动作 |
| Skill 供应链治理 | [Skill Trust / roadmap controls](#template-skill-trust-roadmap) | 先 `clawsentry skill-trust register-dir` 生成 registry |
| 处理工具输出泄露/外部指令 | [Post-action / trajectory](#template-runtime-detectors) | 观察 SSE/UI finding |
| CI / benchmark | [CI / benchmark](#template-benchmark) | 使用临时 `CODEX_HOME` |
| systemd / Docker 常驻 | [生产环境变量骨架](#template-production-env) | `service validate --env-file` |

---

## 基础骨架 {#base-skeleton}

```bash title=".clawsentry.env.example — 可提交基础策略"
CS_FRAMEWORK=codex
CS_ENABLED_FRAMEWORKS=codex
CS_MODE=normal                  # normal | strict | permissive | benchmark
CS_PRESET=medium                # low | medium | high | strict

CS_HTTP_HOST=127.0.0.1
CS_HTTP_PORT=8080
CS_TRAJECTORY_DB_PATH=/tmp/clawsentry-trajectory.db

CS_DEFER_BRIDGE_ENABLED=true
CS_DEFER_TIMEOUT_S=86400
CS_DEFER_TIMEOUT_ACTION=block
CS_DEFER_MAX_PENDING=0
```

```bash title=".clawsentry.env.local — 不提交，本机密钥/覆盖"
CS_AUTH_TOKEN=replace-with-local-token
# CS_HTTP_PORT=9100
# CS_LLM_API_KEY=<api-key>
```

---

## L1 only：零外部依赖观察模式 {#template-l1-only}

适合首次体验、开发测试、成本为零的审计观察。

```bash
CS_LLM_PROVIDER=
CS_LLM_MODEL=
CS_L2_ENABLED=false
CS_L3_ENABLED=false
CS_ENTERPRISE_ENABLED=false
CS_LLM_TOKEN_BUDGET_ENABLED=false
CS_LLM_DAILY_TOKEN_BUDGET=0
```

验证：

```bash
clawsentry config show --effective --env-file .clawsentry.env.local
clawsentry start --env-file .clawsentry.env.local --framework codex --open-browser
```

---

## L2 + token budget：团队语义分析 {#template-l2-budgeted}
<span id="team-l2-budgeted"></span>


共享策略文件只写 provider/model/预算，真实 API key 放本机或部署环境。

```bash title="可提交策略"
CS_LLM_PROVIDER=openai
CS_LLM_MODEL=gpt-4o-mini
CS_LLM_BASE_URL=
CS_L2_ENABLED=true
CS_L3_ENABLED=false

CS_LLM_TOKEN_BUDGET_ENABLED=true
CS_LLM_DAILY_TOKEN_BUDGET=200000
CS_LLM_TOKEN_BUDGET_SCOPE=total
CS_L2_TIMEOUT_MS=60000
CS_HARD_TIMEOUT_MS=600000
```

```bash title="本机/部署密钥（不要提交）"
CS_LLM_API_KEY=<api-key>
# 或 provider 原生命名：OPENAI_API_KEY / ANTHROPIC_API_KEY
```

验证：

```bash
clawsentry test-llm --env-file .clawsentry.env.local --json
clawsentry config show --effective --env-file .clawsentry.env.local
```

---

## 严格 L3：高风险事件同步审查 {#template-l3-strict}
<span id="strict-l3-review"></span>


适合敏感仓库、发布前窗口或需要 high/critical 事件进入深度审查的团队。L3 会增加模型成本和 10s+ 延迟；先在小仓库试运行。

```bash
CS_MODE=strict
CS_PRESET=strict
CS_LLM_PROVIDER=anthropic
CS_LLM_MODEL=claude-3-5-sonnet-latest
CS_L2_ENABLED=true
CS_L3_ENABLED=true
CS_L3_MULTI_TURN=true
CS_L3_TIMEOUT_MS=300000
CS_HARD_TIMEOUT_MS=600000

CS_LLM_TOKEN_BUDGET_ENABLED=true
CS_LLM_DAILY_TOKEN_BUDGET=500000
CS_LLM_TOKEN_BUDGET_SCOPE=total
```

```bash title="密钥"
CS_LLM_API_KEY=<anthropic-api-key>
```

运行态读数：

| 读数 | 含义 |
|---|---|
| `l3_state=completed` | L3 实际参与本次高风险事件审查 |
| `l3_reason_code=local_l3_unavailable` | 请求 L3，但本地 runtime 没有可用 L3 能力 |
| `budget_exhaustion_event` | token/time budget 用尽，按降级语义阅读结果 |

---

## Anti-bypass Guard：防重试/绕过机制 {#template-anti-bypass}

Anti-bypass follow-up guard 用于检测 `PRE_ACTION` 中对 prior final risky decision 的重复、规范化等价或跨工具近似绕过。默认关闭；下面按“只记录”“要求复核”“本地阻断 exact repeat”给出可复制配置。完整机制见 [Anti-bypass Guard](../decision-layers/anti-bypass-guard.md)，字段详表见 [DetectionConfig](detection-config.md#anti-bypass-guard)。

### Observe only：只记录，不改变 verdict

```bash
CS_ANTI_BYPASS_GUARD_ENABLED=true
CS_ANTI_BYPASS_MEMORY_TTL_S=86400
CS_ANTI_BYPASS_MEMORY_MAX_RECORDS_PER_SESSION=256
CS_ANTI_BYPASS_MIN_PRIOR_RISK=high
CS_ANTI_BYPASS_PRIOR_VERDICTS=block,defer
CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=observe
CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=observe
CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=observe
CS_ANTI_BYPASS_SIMILARITY_THRESHOLD=0.92
CS_ANTI_BYPASS_SAME_TOOL_SIMILARITY_THRESHOLD=0.88
CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED=false
CS_ANTI_BYPASS_RECORD_ALLOW_DECISIONS=false
```

### Review：exact/normalized 进入人工确认，cross-tool 请求 L3

```bash
CS_ANTI_BYPASS_GUARD_ENABLED=true
CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=defer
CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=defer
CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=force_l3
CS_ANTI_BYPASS_SIMILARITY_THRESHOLD=0.92
CS_ANTI_BYPASS_SAME_TOOL_SIMILARITY_THRESHOLD=0.88
CS_ANTI_BYPASS_MIN_PRIOR_RISK=high
CS_ANTI_BYPASS_PRIOR_VERDICTS=block,defer
```

### Review + LLM-assisted cross-tool 候选识别

`CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED` 可以省略；只要 guard 已启用且共享 `CS_LLM_PROVIDER` + API key 有效，recognizer 会自动启用。benchmark / dry-run / no-network 模式不会自动启用外部 LLM recognition，除非显式 `true`。保留显式 `true` 适合模板化 rollout；显式 `false` 可强制关闭。

```bash
CS_ANTI_BYPASS_GUARD_ENABLED=true
CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=force_l3
CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED=true
CS_ANTI_BYPASS_LLM_CANDIDATE_THRESHOLD=0.55
CS_ANTI_BYPASS_LLM_CONFIDENCE_THRESHOLD=0.75
CS_ANTI_BYPASS_LLM_TIMEOUT_MS=800
CS_ANTI_BYPASS_LLM_MAX_PRIORS=3
CS_ANTI_BYPASS_LLM_ACTION=force_l3
```

### Enforce：只对 exact repeat 本地阻断

```bash
CS_ANTI_BYPASS_GUARD_ENABLED=true
CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=block
CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=defer
CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=force_l3
CS_ANTI_BYPASS_SIMILARITY_THRESHOLD=0.92
```

!!! warning "cross-tool/script 不本地 hard-block"
    `CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=block` 无效，会回退到 `force_l3`。跨工具近似匹配可选 `observe` / `force_l2` / `force_l3` / `defer`。LLM recognizer 自动启用仍需要 guard、有效 provider、跨工具候选、至少两个弱证据信号、非 `non-destructive` 当前动作和可用 budget；它只接收 sanitized capsules，不能产生本地 `block`。

---

## Skill Trust / roadmap controls {#template-skill-trust-roadmap}

适合 benchmark、敏感仓库和团队共享 skill registry。先生成 registry/runtime metadata，再通过 env 启用 Gateway 解析。完整说明见 [Skill Trust / Registry](../advanced/skill-trust.md)。

!!! warning "SkillsSafetyBench balanced default"
    下面的策略块是严格 supply-chain 模板。SkillsSafetyBench 平衡主跑应使用
    `CS_SKILL_TRUST_FIRST_USE_BENCHMARK_POLICY=scan_sync`，并把
    `CS_CAPABILITY_NARROWING_ENABLED` / `CS_AGENT_SAFETY_FEEDBACK_ENABLED`
    留给单独消融，除非该批实验明确在测试这些反馈/收紧机制。

```bash
clawsentry skill-trust register-dir \
  --skills-dir ~/.codex/skills \
  --registry .clawsentry/skill-trust-registry.json \
  --metadata .clawsentry/skill-trust-runtime.json \
  --framework codex \
  --scope workspace \
  --json
```

```bash title=".clawsentry.env.example — 可提交策略"
CS_SKILL_TRUST_REGISTRY_PATH=.clawsentry/skill-trust-registry.json
CS_SKILL_TRUST_METADATA_PATH=.clawsentry/skill-trust-runtime.json

CS_SKILL_TRUST_FIRST_USE_NORMAL_POLICY=audit_only
CS_SKILL_TRUST_FIRST_USE_BENCHMARK_POLICY=scan_sync
CS_SKILL_TRUST_FIRST_USE_STRICT_POLICY=defer_for_review
CS_SKILL_TRUST_FIRST_USE_PERMISSIVE_POLICY=audit_only

CS_CAPABILITY_NARROWING_ENABLED=true
CS_AGENT_SAFETY_FEEDBACK_ENABLED=true
```

!!! note "边界"
    Agent safety feedback 只在 supported host hooks 上进入 response；不支持交互反馈的框架会保留 audit-only metadata。Capability narrowing 会收紧后续 scope，不回写历史 canonical decision。

---

## DEFER 审批桥接 {#template-defer-bridge}

```bash
CS_DEFER_BRIDGE_ENABLED=true
CS_DEFER_TIMEOUT_S=86400
CS_DEFER_TIMEOUT_ACTION=block
CS_DEFER_MAX_PENDING=0
```

交互审批：

```bash
# 终端 1
clawsentry start --env-file .clawsentry.env.local --framework codex

# 终端 2
clawsentry watch --interactive --token "$CS_AUTH_TOKEN"
```

---

## Post-action / trajectory 运行时检测器 {#template-runtime-detectors}

这组配置控制工具执行后的输出检查、轨迹告警以及高预设下的后续执法。

```bash
CS_POST_ACTION_MONITOR=0.3
CS_POST_ACTION_ESCALATE=0.6
CS_POST_ACTION_EMERGENCY=0.9
CS_POST_ACTION_WHITELIST=^https://internal\.corp\.example\.com,^data:image/
CS_POST_ACTION_FINDING_ACTION=broadcast   # broadcast | defer | block

CS_TRAJECTORY_MAX_EVENTS=50
CS_TRAJECTORY_MAX_SESSIONS=10000
CS_TRAJECTORY_ALERT_ACTION=broadcast       # broadcast | defer | block

CS_EXTERNAL_CONTENT_D6_BOOST=0.3
CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER=1.3
```

---

## D4 频率异常检测 {#template-d4-frequency}

```bash
CS_D4_FREQ_ENABLED=true
CS_D4_FREQ_BURST_COUNT=10
CS_D4_FREQ_BURST_WINDOW_S=5
CS_D4_FREQ_REPETITIVE_COUNT=20
CS_D4_FREQ_REPETITIVE_WINDOW_S=60
CS_D4_FREQ_RATE_LIMIT_PER_MIN=60
```

---

## 自进化模式库 {#template-evolving-patterns}

```bash
CS_EVOLVING_ENABLED=true
CS_EVOLVED_PATTERNS_PATH=/var/lib/clawsentry/evolved_patterns.yaml
# 可选：替换核心攻击模式库
# CS_ATTACK_PATTERNS_PATH=/etc/clawsentry/attack_patterns.yaml
```

---

## L3 advisory：只读 full-review，不改历史判决 {#template-advisory-review}

```bash
CS_L3_ADVISORY_ASYNC_ENABLED=true
CS_L3_HEARTBEAT_REVIEW_ENABLED=true
```

```bash
clawsentry l3 full-review --session sess-001 --token "$CS_AUTH_TOKEN"
clawsentry l3 full-review --session sess-001 --queue-only --json
clawsentry l3 jobs run-next --runner deterministic_local --json
```

边界：advisory review 冻结证据、排队/运行 job、生成 review；不会修改已经发生的 canonical allow/block/defer 判决。

---

## CI / benchmark：无人值守且可审计 {#template-benchmark}
<span id="ci-benchmark-operator"></span>


```bash
CS_MODE=benchmark
CS_PRESET=high
CS_FRAMEWORK=codex
CS_ENABLED_FRAMEWORKS=codex
CS_BENCHMARK_AUTO_RESOLVE_DEFER=true
CS_BENCHMARK_DEFER_ACTION=block
CS_BENCHMARK_PERSIST_SCOPE=project
CS_DEFER_BRIDGE_ENABLED=true
CS_DEFER_TIMEOUT_ACTION=block
```

Codex benchmark 必须使用临时 `CODEX_HOME`，不要复用正在工作的 `~/.codex`。

```bash
TMP_CODEX_HOME="$(mktemp -d)"
CODEX_HOME="$TMP_CODEX_HOME" clawsentry benchmark run -- codex --approval-policy untrusted
rm -rf "$TMP_CODEX_HOME"
```

---

## 生产环境变量骨架 {#template-production-env}

```bash title="/etc/clawsentry/gateway.env"
CS_HTTP_HOST=0.0.0.0
CS_HTTP_PORT=8080
CS_AUTH_TOKEN=replace-with-high-entropy-token
CS_TRAJECTORY_DB_PATH=/var/lib/clawsentry/trajectory.db
AHP_TRAJECTORY_RETENTION_SECONDS=7776000

CS_RATE_LIMIT_PER_MINUTE=300
CS_MODE=strict
CS_PRESET=high

CS_LLM_PROVIDER=openai
CS_LLM_MODEL=gpt-4o-mini
CS_LLM_API_KEY=<api-key>
CS_L2_ENABLED=true
CS_L3_ENABLED=false
CS_LLM_TOKEN_BUDGET_ENABLED=true
CS_LLM_DAILY_TOKEN_BUDGET=1000000
CS_LLM_TOKEN_BUDGET_SCOPE=total

CS_DEFER_BRIDGE_ENABLED=true
CS_DEFER_TIMEOUT_S=86400
CS_DEFER_TIMEOUT_ACTION=block

CS_ANTI_BYPASS_GUARD_ENABLED=true
CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=block
CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=defer
CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=force_l3
```

验证：

```bash
clawsentry service validate --env-file /etc/clawsentry/gateway.env
clawsentry config show --effective --env-file /etc/clawsentry/gateway.env
```
