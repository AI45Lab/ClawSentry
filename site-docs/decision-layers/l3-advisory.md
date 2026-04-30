---
title: L3 咨询审查
description: 用一份只读、可追溯、不改写历史判决的 L3 安全复盘报告，帮助 operator 处理高风险 session
---


# L3 咨询审查

<div class="cs-doc-hero" markdown>

## 高风险 session 的只读复盘报告

当 ClawSentry 发现一个 session 风险很高时，L3 咨询审查会把当时已记录的证据固定下来，生成只读复盘报告，帮助 operator 判断：**发生了什么、风险为什么高、下一步该 inspect / escalate / pause 还是继续观察**。

它不是新的拦截器，也不会重判历史事件；它只是基于固定证据做一次可追溯复盘，辅助后续处置。

<div class="cs-pill-row" markdown>
<span class="cs-pill">只读复盘</span>
<span class="cs-pill">不改写 allow/block/defer</span>
<span class="cs-pill">可在 Web UI 点击触发</span>
<span class="cs-pill">CLI / API 可自动化</span>
</div>

</div>

---

## 先看一个场景

你在 Web UI 里看到一个 session 变成 **high risk**：

1. 这个 agent 先读取了 `.env` 或 SSH key；
2. 后面又执行了 `curl` / `scp` / archive packaging；
3. Dashboard 和 `clawsentry watch` 都提示风险升高；
4. 你想知道：这到底是正常部署，还是准备外传？

这时可以在 Session Detail 点 **Request L3 full review**，也可以运行：

```bash
clawsentry l3 full-review --session sess-001 --token "$CS_AUTH_TOKEN"
```

ClawSentry 会生成一份结果，例如：

```text
review:   l3adv-... (completed, risk=high)
action:   inspect
boundary: advisory only; canonical decision unchanged
```

意思是：系统已经基于固定证据做完复盘，建议 operator 进一步检查；但它没有把过去的判决改掉。

---

## Operator 合同：它会做什么、不会做什么 {#operator-contract}

| 问题 | L3 咨询审查当前行为 |
|------|----------------------|
| 什么时候用 | 你已经有一个值得复盘的 session：Web UI 手动 full-review、CLI/API 显式请求，或在 feature gate 下自动冻结 high/critical evidence delta。 |
| 输入是什么 | frozen trajectory record range。报告基于固定 records，不读取不断变化的 live workspace。 |
| 输出是什么 | `snapshot_id`、`job_id`、`review_id`、`risk_level`、recommended `Action`、可选 `analysis_summary` / `analysis_points` / `operator_next_steps`。 |
| 会不会重判 allow/block/defer | 不会。响应和 action payload 必须保持 `advisory_only=true`、`canonical_decision_mutated=false`。 |
| 会不会自动联网 | 默认 runner 是 `llm_provider`；配置了有效 `CS_LLM_*` 和 API key 时会执行真实 LLM 复盘。缺少配置时生成明确 `degraded` review，不静默 fallback 到本地 runner。 |
| 会不会后台扫所有 session | 不会。queued job drain 是有界 one-shot；heartbeat/idle aggregate 只自动冻结/排队，不启动 scheduler。 |
| 在哪里查询 | Web UI Session Detail、`clawsentry l3 full-review` / `l3 jobs`、`/report/*/l3-advisory/*`、SSE/watch、[报表 API](../api/reporting.md#l3-advisory-endpoints)。 |

## 它解决什么问题？

<div class="cs-card-grid" markdown>

<div class="cs-card" markdown>
### 1. 证据固定
高风险 session 还在继续产生事件时，审查输入必须稳定。L3 咨询审查会冻结一段 record range，例如 `Records 4–8`。
</div>

<div class="cs-card" markdown>
### 2. 结果可追溯
每次复盘都有 `snapshot_id`、`job_id`、`review_id`。你可以在 UI、SSE、API、日志里追踪同一份报告。
</div>

<div class="cs-card" markdown>
### 3. 不改历史判决
报告始终是 `advisory_only=true`。full-review 响应会明确返回 `canonical_decision_mutated=false`。
</div>

<div class="cs-card" markdown>
### 4. 可按需升级
默认用本地确定性 runner；需要时才显式打开 provider runner。不会因为配置了同步 LLM 就自动联网。
</div>

</div>

---

## 工作流程

<div class="cs-flow-strip" markdown>

**高风险 session** → **冻结证据 Snapshot** → **排队 Job** → **运行 Runner** → **生成 Review** → **展示结果**

</div>

```mermaid
graph LR
    A[High-risk session] --> B[Freeze snapshot<br/>bounded records]
    B --> C[Queue advisory job]
    C --> D{Runner}
    D -->|default| E[llm_provider]
    D -->|explicit local support| F[deterministic_local]
    D -->|missing CS_LLM_*| G[degraded review]
    E --> H[Advisory review]
    F --> H
    G --> H
    H --> I[UI / watch / API]
    H --> J[canonical decision unchanged]
```

### 三个对象

| 对象 | 普通理解 | 典型 ID | 你会在哪里看到 |
|------|----------|---------|----------------|
| Snapshot | 固定下来的证据包 | `l3snap-...` | Session Detail、SSE、API |
| Job | 这次复盘任务 | `l3job-...` | `watch` 里的 queued/running/completed |
| Review | 最终咨询报告 | `l3adv-...` | Session Detail 的 L3 advisory review 卡片 |

---

## 在 Web UI 里怎么用

1. 打开 **Sessions**，进入一个 high / critical session；
2. 在 **Session Detail** 点击 **Request L3 full review**；
3. 等待状态从 queued / running 变成 completed；
4. 查看 L3 advisory review 卡片：

| 字段 | 你该怎么看 |
|------|------------|
| `Risk` | 复盘后的风险等级 |
| `Action` | 建议动作：`Inspect` / `Escalate` / `Pause` / `None` |
| `Runner` | 这次报告由哪个 runner 生成 |
| `Records 4–8` | 本次复盘只看了这段固定证据 |
| `Analysis summary` | 可选自然语言摘要，帮助 operator 快速理解“为什么值得看” |
| `Analysis points` | 可选 2–5 条关键依据，来自 frozen evidence，不读取 live workspace |
| `Next steps` | 可选 1–3 条操作建议，例如 inspect / pause / escalate |
| `canonical decision unchanged` | 原始判决没有被修改 |

!!! tip "建议的值守路径"
    先看 `Action`，再看 frozen record boundary，最后根据 `review_id` 去 API / replay 里查细节。不要把 advisory review 当成新的 block/allow 判决。

!!! note "v0.5.10 自然语言字段"
    `analysis_summary`、`analysis_points`、`operator_next_steps` 都是 review/action payload 的可选扩展字段。它们会经过长度和条数限制，用于解释和交接；它们不会改写 canonical decision，也不会触发新的 enforcement。

---

## 在 CLI 里怎么用

### 默认：立即生成一份 LLM-backed 咨询报告

```bash
clawsentry l3 full-review --session sess-001 --token "$CS_AUTH_TOKEN"
```

典型输出：

```text
L3 advisory full review requested
snapshot: l3snap-...
job:      l3job-... (completed)
review:   l3adv-... (completed, risk=high)
advisory_only: true
canonical_decision_mutated: false
```

如果 Gateway 没有解析到有效的 `CS_LLM_PROVIDER`、API key 或 `CS_LLM_MODEL`，命令仍会完成，但 review 会标记为 `l3_state=degraded`，并带 `provider_disabled` / `provider_missing_key` / `provider_missing_model` 等 reason code，提示补齐 LLM 配置。

### 只排队，不运行

```bash
clawsentry l3 full-review \
  --session sess-001 \
  --queue-only \
  --json
```

适合先冻结证据，再由另一个流程决定何时运行 worker。

### 查看并有界执行 queued jobs {#queued-jobs}

这个能力提供 **bounded one-shot execution**，不是 daemon。你可以查看当前 queued jobs：

```bash
clawsentry l3 jobs list --state queued --json
```

执行最旧的一条 queued job：

```bash
clawsentry l3 jobs run-next \
  --runner deterministic_local \
  --json
```

或一次最多 drain N 条（硬上限 10）：

```bash
clawsentry l3 jobs drain \
  --runner deterministic_local \
  --max-jobs 2
```

这些命令只选择 `job_state=queued` 的 job；`running` / `completed` / `failed` 不会被 rerun。省略 `--runner` 时默认执行 `llm_provider`。

### Heartbeat / idle aggregate queueing {#heartbeat-idle-aggregate-queueing}

当同时启用：

```bash
CS_L3_ADVISORY_ASYNC_ENABLED=true
CS_L3_HEARTBEAT_REVIEW_ENABLED=true
```

并且同一 session 在最新 terminal heartbeat review 后出现新的 high/critical evidence delta 时，`heartbeat` / `idle` / `success` / `rate_limit` 兼容事件可以创建一份 `trigger_reason=heartbeat_aggregate` 的 frozen snapshot，并排队一个 advisory job。

安全边界：

- 不启动 background scheduler / daemon；
- 不自动运行 job；
- 同一 `(session_id, runner)` 同时最多一个 queued/running `heartbeat_aggregate` job；
- 输出始终标记 `advisory_only=true` 和 `canonical_decision_mutated=false`。

### 固定审查范围

```bash
clawsentry l3 full-review \
  --session sess-001 \
  --from-record-id 4 \
  --to-record-id 8 \
  --runner deterministic_local
```

适合你已经看到关键事件，只想复盘那一段。

---

## Runner 怎么选？

| Runner | 是否联网 | 适合谁 | 说明 |
|--------|----------|--------|------|
| `llm_provider` | 是；使用共享 `CS_LLM_*` provider 配置 | 默认 full-review / queued job | 继承 `CS_LLM_PROVIDER`、API key、`CS_LLM_MODEL`、`CS_LLM_BASE_URL`、`CS_LLM_TEMPERATURE`、`CS_LLM_PROVIDER_TIMEOUT_MS`；缺配置时写入 `degraded` review |
| `deterministic_local` | 否 | 离线调试 / 审计管道验证 | 只有显式传入 `runner=deterministic_local` 或 `--runner deterministic_local` 时运行 |

!!! warning "无 LLM 配置时会显式降级"
    `llm_provider` 不会静默改跑本地 deterministic review。没有有效 `CS_LLM_*` / API key 时，full-review 会生成 `degraded` review/action，并建议配置 LLM provider。

    ```bash
    CS_LLM_PROVIDER=openai        # 或 anthropic
    CS_LLM_MODEL=<model>
    OPENAI_API_KEY=<key>          # 或 CS_LLM_API_KEY
    ```

### 手动 readiness / smoke 验证

先用随包 devtools 模块验证 provider runner 配置，避免直接在真实 session 上试。
它会构造 frozen snapshot、排队一个 `llm_provider` job、执行一次受闸门保护的 review，并输出 Markdown 证据。

```bash
python -m clawsentry.devtools.l3_advisory_provider_smoke \
  --output-report artifacts/l3-provider-smoke.md \
  --json
```

预期边界：

- 缺少 `CS_LLM_PROVIDER`、API key 或 `CS_LLM_MODEL` 时，结果应安全降级为 `degraded`，并说明 provider/config 问题；
- 需要把真实 provider smoke 作为发布 gate 时，再加 `--require-completed`，让未完成的 review 以失败退出；
- readiness check 不启动 scheduler，不修改 canonical decision，仍只写 `advisory_only=true` 的 review 证据。

---

## API 速查

最常用端点：

```http
POST /report/session/{session_id}/l3-advisory/full-review
```

请求：

```json
{
  "trigger_detail": "operator_requested_full_review",
  "from_record_id": 4,
  "to_record_id": 8,
  "max_records": 100,
  "max_tool_calls": 0,
  "runner": "llm_provider",
  "run": true
}
```

响应：

```json
{
  "snapshot": {"snapshot_id": "l3snap-..."},
  "job": {"job_id": "l3job-...", "job_state": "completed"},
  "review": {"review_id": "l3adv-...", "l3_state": "completed"},
  "advisory_only": true,
  "canonical_decision_mutated": false
}
```

更多端点：

- 创建 snapshot：`POST /report/session/{id}/l3-advisory/snapshots`
- 创建 job：`POST /report/l3-advisory/snapshot/{snapshot_id}/jobs`
- 运行本地 job：`POST /report/l3-advisory/job/{job_id}/run-local`
- 运行 worker：`POST /report/l3-advisory/job/{job_id}/run-worker`
- 更新 review lifecycle：`PATCH /report/l3-advisory/review/{review_id}`

完整字段见 [报表与监控端点](../api/reporting.md#l3-advisory-endpoints)。

---

## `clawsentry watch` 里会看到什么？

```text
L3 ADVISORY SNAPSHOT  l3snap-...  Range=4->8
L3 ADVISORY JOB       l3job-...   State=Completed Runner=Deterministic local
L3 ADVISORY REVIEW    l3adv-...   State=Completed Action=Inspect
```

这三行对应：证据已冻结、任务已运行、报告已生成。

---

## 边界与常见误解

| 误解 | 实际行为 |
|------|----------|
| “它会重新决定 allow/block 吗？” | 不会。它只生成 advisory review。 |
| “它会自动联网调用 LLM 吗？” | 不会。provider runner 默认 dry-run，必须显式打开。 |
| “它会一直后台扫描所有 session 吗？” | 不会。full review 是 operator 显式触发；自动 snapshot 也不会自动运行后台 review。 |
| “它会读取最新 live 文件吗？” | 默认只读 frozen trajectory records；范围由 snapshot 固定。 |
| “失败会伪装成成功吗？” | 不会。配置缺失或 provider 不可用会显示 `degraded` / `failed`。 |

---

## 和同步 L3 Agent 有什么区别？

| 能力 | 同步 L3 Agent | L3 咨询审查 |
|------|---------------|--------------|
| 触发时机 | 在实时决策链中按策略触发 | operator 手动触发，或只自动冻结 snapshot |
| 目标 | 帮助当前事件得出安全评估 | 对已记录 session 做复盘报告 |
| 输入 | 当前事件 + bounded context | frozen trajectory record range |
| 输出 | 决策路径中的 L3 结果 / trace | advisory review / recommended operator action |
| 延迟模型 | 同步路径预算内返回，超时/失败降级 | job/review 生命周期，可排队、手动 run-next/drain |
| LLM 配置 | 继承同步 L2/L3 provider：`CS_LLM_PROVIDER`、`CS_LLM_MODEL` 等 | 同样继承 `CS_LLM_*`；无有效配置时 loud degraded |
| 是否改历史判决 | 不适用 | 明确不改，`canonical_decision_mutated=false` |

## 最近功能覆盖状态 {#recent-feature-coverage}

本页覆盖 L3 advisory jobs/full-review、heartbeat/idle aggregate queueing、provider smoke gates、Web UI L3 surfaces 与 action summary。完整跨页面覆盖矩阵见 [最近功能文档覆盖矩阵](../operations/recent-feature-coverage.md)。

如果你想了解同步决策链里的 L3 审查器，继续看 [L3 审查 Agent](l3-agent.md)。
