---
title: Anti-bypass Follow-up Guard
description: 默认关闭的前置反绕过保护层 — 记住高风险最终判决的紧凑指纹，识别同会话里的重复、变形和跨工具重试
---

# Anti-bypass Follow-up Guard

<div class="cs-doc-hero" markdown>
<div class="cs-eyebrow">Decision Engine · PRE_ACTION Follow-up Defense</div>

## 拦截一次后，继续盯住“换个形式再试一次”

Anti-bypass Follow-up Guard 是 ClawSentry 的**同会话防重试保护层**。它默认关闭；启用后，Gateway 会记住已经产生最终高风险判决的操作指纹。后续如果 Agent 把同一个危险动作改写成相似命令、脚本包装或另一个工具调用，Guard 会在普通策略判断前先识别这次 follow-up，并按你的配置观察、复核、人工确认或阻断。

<div class="cs-pill-row" markdown>
<span class="cs-pill">默认关闭</span>
<span class="cs-pill">只处理 PRE_ACTION</span>
<span class="cs-pill">同 session 记忆</span>
<span class="cs-pill">只存紧凑指纹</span>
<span class="cs-pill">Cross-tool 不本地 block</span>
</div>
</div>

!!! tip "一句话理解"
    L1/L2/L3 判断“这次操作本身危险吗”；Anti-bypass Guard 判断“这是不是刚刚被拦截或延后后，又换个形式重试”。

## 先看结论 {#overview}

<div class="cs-card-grid" markdown>

<div class="cs-card" markdown>
<p class="cs-card-title">解决什么问题</p>

Agent 可能在一次高风险操作被 `block` / `defer` 后，马上换命令、换工具或包一层脚本继续尝试。Guard 把这些 follow-up 关联到上一次最终判决。
</div>

<div class="cs-card" markdown>
<p class="cs-card-title">记录什么信息</p>

只记录 hash、fingerprint、risk、verdict、policy id、record id、tool label 和时间戳；不保存 raw command、raw payload、secret 或 L3 trace。
</div>

<div class="cs-card" markdown>
<p class="cs-card-title">如何上线最稳</p>

从 `observe` 开始看命中率，再切到 `defer` / `force_l3`，最后只对明确的 exact repeat 使用 `block`。
</div>

</div>

---

## 适用场景 {#when-to-use}

Guard 适合处理“已经有一次高风险最终判决，随后又出现相似尝试”的场景。它不是新的单次风险评分器，也不替代 L1/L2/L3。

<div class="cs-scenario-grid" markdown>

<div class="cs-scenario" markdown>
<p class="cs-card-title">1. 原样重复</p>

第一次 `rm -rf /important` 已经被 `block` 或 `defer`，Agent 又用同一工具、同一 canonical payload 提交一次。

**Match type:** `exact_raw_repeat`
</div>

<div class="cs-scenario" markdown>
<p class="cs-card-title">2. 改写但意图相同</p>

第一次是直接删除；第二次改成变量、别名或轻微格式变化，但归一化后仍是同一个破坏性动作。

**Match type:** `normalized_destructive_repeat`
</div>

<div class="cs-scenario" markdown>
<p class="cs-card-title">3. 换工具或脚本包装</p>

第一次 shell 调用被拦；第二次换成脚本、另一个工具或相似 feature 集合继续做同类动作。

**Match type:** `cross_tool_script_similarity`
</div>

</div>

!!! warning "重要边界"
    `cross_tool_script_similarity` 不允许本地 hard-block。跨工具相似度更依赖上下文，配置成 `block` 会被校验拒绝并回退到 `force_l3`。需要更强控制时，用 `defer` 交给 operator。

---

## 它在决策链路里的位置 {#pipeline-position}

Anti-bypass Guard 只参与 `PRE_ACTION`，位置在 quarantine / session enforcement 之后、normal policy 之前。因此更高优先级的隔离和会话强制策略仍然先执行；Guard 命中后，后续 L1/L2/L3 仍可继续参与复核。

<div class="cs-step-flow" markdown>
<div markdown>
<span>1</span>
<strong>PRE_ACTION</strong>
Agent 准备调用工具
</div>
<div markdown>
<span>2</span>
<strong>Quarantine / Session</strong>
最高优先级先执行
</div>
<div markdown>
<span>3</span>
<strong>Anti-bypass Guard</strong>
查同 session compact memory
</div>
<div markdown>
<span>4</span>
<strong>Normal policy</strong>
未阻断则继续 L1 / L2 / L3
</div>
<div markdown>
<span>5</span>
<strong>Decision record</strong>
最终判决后再写入 memory
</div>
</div>

<div class="cs-flow-strip" markdown>
**顺序保证：** quarantine / session enforcement → anti-bypass guard → normal policy → trajectory / benchmark finalization → decision record → final-only memory update
</div>

---

## 工作原理 {#how-it-works}

Guard 的逻辑可以拆成两步：**先记住上一次最终高风险判决的安全指纹，再用当前 PRE_ACTION 和这些指纹做匹配**。

<div class="cs-before-after" markdown>

<div markdown>
<p class="cs-card-title">1. 写入 compact memory</p>

只有最终判决、达到风险阈值、verdict 在允许列表里的 `PRE_ACTION` 才会被记录。默认只记 `block,defer`，且风险至少是 `high`。
</div>

<div markdown>
<p class="cs-card-title">2. 检查 follow-up</p>

新的 `PRE_ACTION` 到达时，Gateway 先查同 session 的 compact memory。命中后会附带 match type、prior record id 和建议动作。
</div>

</div>

### 什么时候写入记忆？ {#memory-write}

一次事件必须同时满足这些条件，才会进入 anti-bypass memory：

1. Guard 已启用：`CS_ANTI_BYPASS_GUARD_ENABLED=true`
2. 事件类型是 `PRE_ACTION`
3. 判决是最终判决：`decision.final=true`
4. verdict 在可记忆列表里：默认 `block,defer`
5. 风险等级达到阈值：默认 `high` 或 `critical`
6. 如果 verdict 是 `allow`，必须显式开启 `CS_ANTI_BYPASS_RECORD_ALLOW_DECISIONS=true`

!!! note "final decision 的含义"
    Guard 记录 Gateway 已生成并持久化的 final canonical decision，写入发生在 `_record_decision_path` 之后。若该 final decision 是 `defer`，后续 operator / timeout resolution 可能再产生审批结果；当前 memory 不等待该后续结果，也不会回溯删除已记录的 compact fingerprint。

### 记住哪些指纹？ {#fingerprints}

| 记忆字段 | 用途 | 是否含原文 |
|----------|------|------------|
| `raw_payload_hash` | 判断同一工具、同一 canonical payload 是否原样重复 | 否 |
| `normalized_action_fingerprint` | 判断格式变化后是否仍是同一破坏性动作 | 否 |
| `destructive_intent_fingerprint` / label | 判断删除、外传、提权、远程执行等意图类别 | 否 |
| `normalized_feature_hashes` | 用 Jaccard similarity 判断跨工具/脚本相似度 | 否 |
| `prior_event_id` / `prior_record_id` / `policy_id` | 帮审计人员追溯 prior final decision | 否 |

### 如何匹配 follow-up？ {#match-types}

| Match type | 什么时候命中 | 默认动作 | 可否本地 `block` |
|------------|--------------|----------|------------------|
| `exact_raw_repeat` | 同一 session、同一 tool、同一 raw payload hash | `block` | 可以 |
| `normalized_destructive_repeat` | 同一 tool，归一化后是同一破坏性动作 | `defer` | 可以，建议先灰度 |
| `cross_tool_script_similarity` | 换工具/脚本包装，但意图或 feature 集合相似 | `force_l3` | 不可以 |

---

## 决策动作怎么理解？ {#actions}

把动作分成三类会更容易配置：

<div class="cs-config-map" markdown>

<div markdown>
<p class="cs-card-title">只观察</p>

`observe` 只写 metadata / counters，不改变当前判决。适合第一阶段上线和误报评估。
</div>

<div markdown>
<p class="cs-card-title">要复核</p>

`force_l2` / `force_l3` 让 normal policy 必须进入对应复核层；`defer` 则把当前 follow-up 交给 operator 确认。
</div>

<div markdown>
<p class="cs-card-title">直接拦</p>

`block` 会本地阻断当前 follow-up。建议只用于 `exact_raw_repeat`，或已经观察过的 normalized repeat。
</div>

</div>

| 动作 | 效果 | 适合阶段 |
|------|------|----------|
| `observe` | 只记录命中信息，不改变 verdict | 观察期、误报评估 |
| `force_l2` | 继续走 normal policy，但要求 L2 参与 | 低成本语义复核 |
| `force_l3` | 继续走 normal policy，但要求 L3 深度审查 | 高风险灰区 |
| `defer` | 当前 follow-up 进入人工确认 | 生产灰度、operator 判断 |
| `block` | 当前 follow-up 本地阻断 | 明确重复、低误报场景 |

---

## 快速启用 {#quickstart}

推荐使用三段式 rollout。先确认命中是否符合预期，再逐步提高动作强度。

=== "1. Observe only"

    第一阶段：只记录命中，不改变任何 verdict。

    ```bash title=".clawsentry.env.local"
    CS_ANTI_BYPASS_GUARD_ENABLED=true
    CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=observe
    CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=observe
    CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=observe
    ```

=== "2. Review mode"

    第二阶段：exact / normalized 进入人工确认；跨工具相似请求 L3 复核。

    ```bash title=".clawsentry.env.local"
    CS_ANTI_BYPASS_GUARD_ENABLED=true
    CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=defer
    CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=defer
    CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=force_l3
    ```

=== "3. Focused enforce"

    第三阶段：只对 exact repeat 本地阻断，其他变体仍进入 review。

    ```bash title=".clawsentry.env.local"
    CS_ANTI_BYPASS_GUARD_ENABLED=true
    CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=block
    CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=defer
    CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=force_l3
    ```

验证配置是否生效：

```bash
clawsentry config show --effective --env-file .clawsentry.env.local
clawsentry start --env-file .clawsentry.env.local --framework codex
```

!!! tip "模板入口"
    如果你想直接复制完整 dotenv 块，请使用 [配置模板：Anti-bypass Guard](../configuration/templates.md#template-anti-bypass)。本页重点解释机制与调参思路。

---

## 配置速查 {#configuration}

先调这三个动作变量；其余变量只在你需要改变记忆范围或相似度灵敏度时调整。

| 变量 | 默认值 | 什么时候改 |
|------|--------|------------|
| `CS_ANTI_BYPASS_EXACT_REPEAT_ACTION` | `block` | 想把原样重复从观察切到人工确认或阻断时 |
| `CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION` | `defer` | 想控制“改写但意图相同”的处理强度时 |
| `CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION` | `force_l3` | 想把跨工具相似尝试改成 observe / force_l2 / defer 时；不可为 `block` |

### 记忆范围

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_ANTI_BYPASS_GUARD_ENABLED` | `false` | 总开关；默认不改变现有行为 |
| `CS_ANTI_BYPASS_MEMORY_TTL_S` | `86400` | compact memory 保留秒数 |
| `CS_ANTI_BYPASS_MEMORY_MAX_RECORDS_PER_SESSION` | `256` | 每个 session 最多保留多少条 prior final decision |
| `CS_ANTI_BYPASS_MIN_PRIOR_RISK` | `high` | 只有达到该风险等级的 prior decision 才参与匹配 |
| `CS_ANTI_BYPASS_PRIOR_VERDICTS` | `block,defer` | 哪些 prior verdict 会被记住 |
| `CS_ANTI_BYPASS_RECORD_ALLOW_DECISIONS` | `false` | 是否也记录 allow 决策的 compact fingerprints；通常保持关闭 |

### 相似度

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_ANTI_BYPASS_SIMILARITY_THRESHOLD` | `0.92` | cross-tool/script similarity 阈值，范围 `0.0..1.0`；越低越敏感 |

完整字段说明见 [DetectionConfig：Anti-bypass Follow-up Guard](../configuration/detection-config.md#anti-bypass-guard) 和 [环境变量参考](../configuration/env-vars.md#anti-bypass-guard-env)。

---

## 可观测性与审计 {#observability}

命中后，decision metadata / SSE / replay buffer 会包含 `anti_bypass` 字段。它只暴露审计所需的紧凑信息：

```json
{
  "anti_bypass": {
    "matched": true,
    "match_type": "exact_raw_repeat",
    "action": "block",
    "prior_event_id": "evt-previous",
    "prior_record_id": 42,
    "prior_policy_id": "anti-bypass-exact-repeat",
    "prior_risk_level": "critical",
    "raw_payload_hash": "sha256:...",
    "normalized_action_fingerprint": "sha256:...",
    "destructive_intent_fingerprint": "sha256:...",
    "similarity": 1.0
  }
}
```

!!! success "Redaction contract"
    `anti_bypass` metadata 不包含 `command`、raw payload、secret、环境变量值或 L3 trace。`defer_pending` SSE 不携带 anti-bypass fingerprints；当命中 anti-bypass 时，它会把 retry `command` 字段降级为 tool name，避免把 secret-bearing retry command 推送到 operator UI。

---

## 与其他决策层的关系 {#relationship}

| 功能 | 关注点 | 是否同步影响当前判决 | 是否记忆历史 |
|------|--------|----------------------|--------------|
| L1 规则引擎 | 当前事件的工具、路径、命令、D1-D6 分数 | 是 | D4 有会话计数 |
| L2 语义分析 | 当前事件的语义风险 | 是 | 否 |
| L3 审查 Agent | 当前高风险事件的上下文证据 | 是 | 可写 trace，但 Guard 不保存 trace |
| Trajectory Analyzer | 多事件攻击链告警 | 通常异步告警 | 滑动窗口 |
| Anti-bypass Guard | prior final risky decision 后的重复/变形 follow-up | 是，仅 `PRE_ACTION` | compact per-session memory |

---

## 边界与注意事项 {#boundaries}

- **默认关闭**：升级不会自动改变你的阻断策略。
- **进程内记忆**：当前 memory 是 Gateway process-local volatile memory；重启后清空。
- **同 session 范围**：匹配按 session 隔离，不做跨 session 用户画像。
- **不替代 L1/L2/L3**：Guard 是 follow-up detector，不是独立风险评分器。
- **不新增 `AHP_*` anti-bypass 变量**：配置统一使用 `CS_ANTI_BYPASS_*`。
- **先 observe 再 enforce**：第一次启用建议先观察，再逐步切到 `defer` / focused `block`。

---

## 代码位置 {#source-code}

| 模块 | 路径 | 职责 |
|------|------|------|
| Guard | `src/clawsentry/gateway/anti_bypass_guard.py` | compact memory、fingerprints、match types、metadata redaction |
| DetectionConfig | `src/clawsentry/gateway/detection_config.py` | `CS_ANTI_BYPASS_*` 解析与校验 |
| Gateway | `src/clawsentry/gateway/server.py` | 决策链路集成、forced tier / defer / block、SSE metadata |
| Tests | `src/clawsentry/tests/test_anti_bypass_guard.py` | 配置、匹配、redaction、final-only memory 回归测试 |

## 相关页面 {#related}

- [配置模板](../configuration/templates.md#template-anti-bypass) — 可直接复制的 rollout dotenv 块
- [检测管线配置](../configuration/detection-config.md#anti-bypass-guard) — 完整参数参考
- [环境变量](../configuration/env-vars.md#anti-bypass-guard-env) — 部署时可用的 `CS_ANTI_BYPASS_*` 变量
- [L1 规则引擎](l1-rules.md) — 单次事件的确定性风险评分
- [L2 语义分析](l2-semantic.md) — 语义升级与 LLM / RuleBased analyzer
- [L3 审查 Agent](l3-agent.md) — 高风险事件的只读深度审查
