---
title: 指标字典
description: ClawSentry 报表、Dashboard、SSE 与 Enterprise OS 风险指标的 canonical 合同
---

<section class="cs-doc-hero cs-doc-hero--api" markdown>
<div class="cs-eyebrow">ClawSentry Metric Dictionary</div>
## Metric Dictionary（报表 / Dashboard / Enterprise OS）
ClawSentry 风险指标的 canonical 合同。本文是所有报表、Dashboard、SSE 和 Enterprise OS 展示字段的唯一公开字典。
<div class="cs-actions" markdown>
[API 概览](overview.md){ .md-button .md-button--primary }
[报表端点](reporting.md){ .md-button }
[决策端点](decisions.md){ .md-button }
</div>
</section>

本文是 ClawSentry 风险展示指标的唯一公开字典。它回答三个问题：字段是什么意思、公式是什么、能不能影响 `allow / block / defer`。

!!! note "默认决策语义不变"
    本页字段属于 report / API / SSE / Dashboard / Enterprise OS 展示合同。除非未来配置显式打开策略消费，这些字段不直接改变 L1/L2/L3 判决。

## 命名原则

- **只对新消费者推荐 canonical 字段**：新 UI、文档和集成代码只读取本文列出的 canonical 字段。
- **窗口指标必须带边界**：窗口聚合必须与 `window_seconds`、`event_count` 和 `generated_at` 一起解释。
- **展示指标不是策略阈值**：`session_risk_sum`、`session_risk_ewma`、`risk_points_sum`、`risk_velocity` 默认只解释趋势和暴露压力。
- **D1-D6 是解释维度**：维度分解释单次风险快照，不是窗口聚合，也不单独代表最终 verdict。

## Canonical 字段速查 {#canonical-fields}

| 字段 | 类型 / 单位 | 公式或来源 | 空值语义 | 决策影响 | 主要位置 |
|---|---|---|---|---|---|
| `latest_composite_score` | float，`>=0` | 窗口内最新 `RiskSnapshot.composite_score`；无窗口时为 session 最新事件分 | 无事件时为 `0.0` 或缺失，consumer 可显示为空状态 | 否 | `/report/sessions`、`/report/session/{id}/risk`、SSE、Dashboard 当前风险 |
| `session_risk_sum` | float，`>=0` | `sum(risk_timeline[*].composite_score)`，四舍五入到 4 位 | 无窗口事件为 `0.0` | 否 | session 风险详情、窗口摘要、Enterprise summary |
| `session_risk_ewma` | float，`>=0` | EWMA，`alpha=0.3`：首个分数作为种子，之后 `0.3 * score + 0.7 * previous` | 无窗口事件为 `0.0` | 否 | Sessions 主展示分、Dashboard 态势、Enterprise session score |
| `latest_post_action_score` | float，`0.0..3.0` | 最新一次 post-action 安全围栏分析的 `score` | 无 post-action 输出分析时为 `0.0` | 否 | `/report/session/{id}/post-action`、`/report/session/{id}/risk`、`/report/sessions` |
| `post_action_score_ewma` | float，`0.0..3.0` | post-action 安全围栏分 EWMA，`alpha=0.3` | 无 post-action 输出分析时为 `0.0` | 否 | Enterprise OS session 安全态势、Dashboard 辅助分 |
| `post_action_score_summary` | object | post-action score 的窗口聚合容器 | 正常返回对象；无事件时计数为 0 | 否 | `/report/session/{id}/post-action`、session 风险详情 |
| `risk_points_sum` | int，`>=0` | 风险等级点数求和：`low=0`、`medium=1`、`high=2`、`critical=3` | 无窗口事件为 `0` | 否 | L3 解释、Session Detail 辅助指标、Enterprise audit payload |
| `risk_velocity` | enum | 比较窗口内首尾 composite：差值 `>0.25` 为 `up`，`<-0.25` 为 `down`，否则 `flat`；样本不足为 `unknown` | 少于 2 个样本为 `unknown` | 否 | Sessions row、Session Detail、Dashboard trend labels |
| `high_or_critical_count` | int，`>=0` | 窗口内 `risk_level` 为 `high` 或 `critical` 的事件数 | 无窗口事件为 `0` | 否 | `window_risk_summary`、Dashboard high-risk count |
| `window_risk_summary` | object | 同一窗口内的权威聚合容器，包含本表窗口字段 | 正常返回对象；无事件时计数为 0 | 否 | `/report/session/{id}/risk`、`/report/sessions`、Dashboard cards |
| `score_range` / `score_semantics` | tuple/object | 对应分数字段的范围和空数据语义 | `event_count/post_action_event_count == 0` 时 `0.0` 表示“无数据”，不是“确认低风险” | 否 | Reporting API、Enterprise OS contract |
| `system_security_posture` | object | Enterprise/Dashboard 对多个 session 的窗口聚合态势 | 数据源不可用时返回 degraded 对象 | 否 | Enterprise overview、Dashboard 顶层态势、SSE overview refresh |
| `composite_score` | float，`0.0..100.0`（展示） | 内部 `0.0..3.0` 评分线性映射到 0-100 的展示分；`score_0_100 = round(raw / 3.0 * 100, 1)` | 无事件时为 `0.0` 或缺失 | 否 | Dashboard 顶层展示分、`system_security_posture.score_0_100`、Enterprise OS 概览 |
| `risk_level` | enum | `low / medium / high / critical`；由 `composite_score`（内部 0-3 scale）阈值映射：`0..0.5→low`、`0.5..1.5→medium`、`1.5..2.5→high`、`>2.5→critical` | 无事件时为 `null` 或缺失 | 否 | 全部 report 端点、SSE event payload、Dashboard risk badge、`window_risk_summary` |
| `decision_latency_ms` | int，`>=0` | 单次 L1→L2→L3 决策链完整耗时，毫秒 | 决策链超时或异常中断时为 `null` | 否 | `/report/session/{id}`、audit log、Enterprise OS session detail |
| `trinityguard_classification` | object | Enterprise OS 的单条 event/session 最新 20 类风险分类 | 未匹配时 `mapped=false`、`subtype=unmapped` | 否 | `/enterprise/report/sessions`、`/enterprise/report/session/{id}`、`/enterprise/report/session/{id}/risk`、Enterprise SSE |
| `by_trinityguard_subtype` / `by_trinityguard_tier` | object | 当前活跃 session 最新分类的 20 类风险 / RT1-RT3 计数 | 无映射时为空对象；同时读 `mapped_active_sessions` | 否 | `/enterprise/report/live`、`live_risk_overview` |
| `trinityguard.by_subtype` / `trinityguard.by_tier` | object | 指定窗口内 trajectory records 的 20 类风险 / RT1-RT3 计数 | 无映射时为空对象；同时读 `unmapped_records` | 否 | `/enterprise/report/summary` |

## 核心字段解释 {#core-fields}

| 字段 | 普通含义 | 计算公式 | 读取建议 |
|---|---|---|---|
| `latest_composite_score` | 最近一次事件的连续风险分，适合解释“刚才发生的这一步有多危险”。 | `risk_timeline[-1].composite_score`。 | 没有 EWMA 时可作为当前风险展示分。不要把它当窗口总量。 |
| `session_risk_sum` | 当前窗口内的风险暴露总量，适合解释“这一段时间累计压力有多大”。 | `round(sum(composite_score), 4)`。 | 用于趋势/容量/审计解释，不直接替代判决阈值。 |
| `session_risk_ewma` | 平滑后的当前 session 态势，减少单个尖峰对 UI 的影响。 | `ewma_0 = score_0`，`ewma_n = 0.3 * score_n + 0.7 * ewma_(n-1)`。 | 新 UI 的首选 session score；缺失时回退 `latest_composite_score`。 |
| `latest_post_action_score` | 最近一次工具输出事后安全分析分，适合解释“工具结果本身是否携带注入/外传/泄密/混淆风险”。 | `post_action_scores[-1].score`，范围 `0.0..3.0`。 | 与 pre-action `latest_composite_score` 分开展示；不要混为同一个风险源。 |
| `post_action_score_ewma` | session 级 post-action 安全围栏滑动平均分，减少单个输出尖峰对企业 OS 指标的影响。 | `ewma_0 = score_0`，`ewma_n = 0.3 * score_n + 0.7 * ewma_(n-1)`。 | Enterprise OS 可与 `session_risk_ewma` 一起派生双通道安全指标。 |
| `post_action_score_summary` | 同一时间窗口的 post-action score 事实容器。 | 由窗口内 `post_action_scores` 聚合出 latest/sum/avg/EWMA。 | 默认展示/观测用途，不改变 allow/block/defer。 |
| `risk_points_sum` | 离散风险等级累计点数，便于解释 high/critical 的压力。 | `sum({"low":0,"medium":1,"high":2,"critical":3}[risk_level])`。 | 适合 L3 evidence summary 和 operator 排查，不是新 verdict。 |
| `risk_velocity` | 风险走势方向。 | `last_score - first_score` 映射为 `up/down/flat/unknown`。 | 只说明方向，不说明绝对风险高低。 |
| `window_risk_summary` | 同一时间窗口的风险事实容器。 | 由窗口内 timeline 聚合出 score、点数、速度和高危计数。 | API consumer 应优先读该对象，再读顶层同名展示字段。 |
| `system_security_posture` | 系统级安全态势快照。 | 由多 session 的 high/critical 分布、风险总量、缓存状态和数据可用性聚合。 | 顶层态势必须显示 degraded/stale，不要把缺数据当 healthy。 |
| `trinityguard_classification` | Enterprise OS 风险 taxonomy 分类结果。 | 由企业规则映射生成，企业模式启用时可使用 LLM fallback；输出 `tier/subtype/label/confidence/signals`。 | 用于展示/统计，不改变 Gateway canonical decision。 |

## Enterprise OS 20 类风险 taxonomy 指标 {#enterprise-taxonomy-metrics}

Enterprise OS 的 20 类风险统计字段来自 `trinityguard_classification`。它和 ClawSentry 决策层 `L1/L2/L3` 是两套不同概念：

- `RT1` / `RT2` / `RT3`：风险 taxonomy 三大层，用于 Enterprise OS 统计与展示。
- `L1` / `L2` / `L3`：Gateway 判决实际经过的决策层，用于解释规则/语义/审查 Agent 路径。

| 统计目标 | API 字段 | 推荐接口 | 说明 |
|---|---|---|---|
| 当前活跃 session 的 20 类风险数 | `by_trinityguard_subtype` | `GET /enterprise/report/live?cached=true` | 每个活跃 session 取最新 record 分类后聚合。 |
| 当前活跃 session 的三大风险层数 | `by_trinityguard_tier` | `GET /enterprise/report/live?cached=true` | 键为 `RT1` / `RT2` / `RT3`。 |
| 历史窗口内 20 类风险 record 数 | `trinityguard.by_subtype` | `GET /enterprise/report/summary?window_seconds=3600` | 按 trajectory record 计数，不是去重 session 数。 |
| 历史窗口内三大风险层 record 数 | `trinityguard.by_tier` | `GET /enterprise/report/summary?window_seconds=3600` | 审计/报表口径。 |
| 单 session 分类明细 | `risk_timeline[].trinityguard_classification` + `trinityguard_summary` | `GET /enterprise/report/session/{id}/risk` | 用于 session 详情页和 drilldown。 |

20 类 subtype 的 authoritative 列表见 [报表与监控：Enterprise OS 20 类风险统计](reporting.md#enterprise-os-risk-taxonomy-query)。

## `window_risk_summary` 最低字段集 {#window-risk-summary}

| 字段 | 状态 | 说明 |
|---|---|---|
| `window_seconds` | required | 本次聚合窗口；`null` 表示未按时间窗口限制。 |
| `generated_at` | required for report API | 服务端生成该摘要的 UTC 时间。 |
| `event_count` | required | 窗口内事件数。 |
| `high_or_critical_count` | required | 窗口内 high 或 critical 事件数。 |
| `latest_composite_score` | required | 窗口内最新 composite score；无事件为 `0.0`。 |
| `session_risk_sum` | required | 窗口内 composite score 总和。 |
| `session_risk_ewma` | required | 窗口内 EWMA 当前态势值。 |
| `risk_points_sum` | required | 同窗口离散风险点数累计。 |
| `risk_velocity` | required | `up/down/flat/unknown`。 |
| `score_range` | required | 固定为 `[0.0, 3.0]`。 |
| `score_semantics` | required | 说明空窗口 `0.0` 是 no-data sentinel，不是确认低风险。 |
| `decision_affecting` | required | 当前为 `false`，提醒 consumer 这些字段默认不改判决。 |

## `post_action_score_summary` 最低字段集 {#post-action-score-summary}

| 字段 | 状态 | 说明 |
|---|---|---|
| `window_seconds` | required | 本次聚合窗口；`null` 表示未按时间窗口限制。 |
| `generated_at` | required for report API | 服务端生成该摘要的 UTC 时间。 |
| `event_count` | required | 窗口内 post-action 输出分析次数。 |
| `latest_post_action_score` | required | 窗口内最新 post-action score；无事件为 `0.0`。 |
| `post_action_score_sum` | required | 窗口内 post-action score 总和。 |
| `post_action_score_avg` | required | 窗口内 post-action score 算术均值。 |
| `post_action_score_ewma` | required | 窗口内 post-action score EWMA 当前态势值。 |
| `score_range` | required | 固定为 `[0.0, 3.0]`。 |
| `score_semantics` | required | 说明无 post-action 输出分析时 `0.0` 是 no-data sentinel，并提醒不要与 `session_risk_ewma` 裸值相加。 |
| `decision_affecting` | required | 当前为 `false`，post-action score 默认只用于报告、告警和后续 session 指标派生。 |

## D1-D6 风险维度 {#d1-d6}

D1-D6 来自最新 `RiskSnapshot.dimensions`，解释单个事件为什么被评为某个风险等级。它们不会像 EWMA 一样跨窗口平滑，也不应被单独当作最终 verdict。

| 维度 | 代码键 | 范围 | 含义 | 高分常见信号 |
|---|---|---:|---|---|
| D1 | `d1` | `0..3` | 工具类别危险度。 | shell、sudo、权限修改、进程控制、网络外联工具。 |
| D2 | `d2` | `0..3` | 目标路径或资源敏感度。 | `.env`、SSH key、token、系统路径、凭证目录。 |
| D3 | `d3` | `0..3` | 命令模式危险度。 | `rm -rf`、远程脚本管道执行、force push、日志清理、反连模式。 |
| D4 | `d4` | `0..2` | 会话上下文累积风险。 | 同一 session 多次中高风险、secret 读取后网络动作、可疑序列。 |
| D5 | `d5` | `0..2` | agent / workspace 信任等级。 | 未知 adapter、低信任 agent、缺少可信身份。 |
| D6 | `d6` | `0.0..3.0` | 注入、越权指令或恶意语义风险。 | jailbreak、ignore-policy 指令、凭证请求、隐藏恶意文本。 |

## API / UI 读取示例 {#examples}

### Session 风险

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/sess-001/risk?window_seconds=3600"
```

```json
{
  "session_id": "sess-001",
  "current_risk_level": "high",
  "latest_composite_score": 2.4,
  "session_risk_sum": 6.7,
  "session_risk_ewma": 1.9,
  "latest_post_action_score": 1.0,
  "post_action_score_ewma": 0.72,
  "risk_points_sum": 5,
  "risk_velocity": "up",
  "window_risk_summary": {
    "window_seconds": 3600,
    "generated_at": "2026-03-23T10:31:00+00:00",
    "event_count": 9,
    "high_or_critical_count": 2,
    "latest_composite_score": 2.4,
    "session_risk_sum": 6.7,
    "session_risk_ewma": 1.9,
    "risk_points_sum": 5,
    "risk_velocity": "up",
    "decision_affecting": false
  }
}
```

Recommended UI precedence:

```text
primary_session_score = session_risk_ewma
  ?? latest_composite_score

secondary_post_action_score = post_action_score_ewma
  ?? latest_post_action_score
```

### Post-action 安全围栏分

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  "http://127.0.0.1:8080/report/session/sess-001/post-action?window_seconds=3600"
```

```json
{
  "session_id": "sess-001",
  "latest_post_action_score": 1.0,
  "post_action_score_sum": 2.4,
  "post_action_score_avg": 0.8,
  "post_action_score_ewma": 0.72,
  "post_action_event_count": 3,
  "score_range": [0.0, 3.0],
  "score_semantics": {
    "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
    "decision_affecting": false,
    "aggregation": "latest, sum, avg, and EWMA are separate from session_risk_ewma; do not add raw channels"
  },
  "decision_affecting": false,
  "post_action_score_summary": {
    "window_seconds": 3600,
    "event_count": 3,
    "latest_post_action_score": 1.0,
    "post_action_score_sum": 2.4,
    "post_action_score_avg": 0.8,
    "post_action_score_ewma": 0.72,
    "score_range": [0.0, 3.0],
    "score_semantics": {
      "zero_with_no_events": "no_post_action_data_not_confirmed_low_risk",
      "decision_affecting": false
    },
    "decision_affecting": false
  }
}
```

### 系统态势

```json
{
  "system_security_posture": {
    "level": "elevated",
    "score_0_100": 72.5,
    "window_seconds": 3600,
    "generated_at": "2026-04-25T12:00:05Z",
    "decision_affecting": false,
    "drivers": [
      {"key": "high_sessions", "label": "High-risk sessions", "value": 3}
    ]
  }
}
```

## Consumer 迁移建议 {#migration}

| Consumer | 推荐读取 | 备注 |
|---|---|---|
| Sessions list | `session_risk_ewma`、`latest_composite_score`、`post_action_score_ewma`、`risk_velocity`、`high_or_critical_count` | 列表用于扫描和排序；必须显示窗口边界。 |
| Session detail | `window_risk_summary`、`post_action_score_summary`、`dimensions_latest.d1..d6`、L3 evidence summary | 窗口解释、post-action 输出风险和单事件维度分开展示。 |
| Alerts details | `latest_composite_score`、`risk_points_sum`、触发 reason | 告警文案应解释来源，不把展示分写成策略原因。 |
| Enterprise OS | `session_risk_ewma` + `post_action_score_ewma` + `system_security_posture` + `by_trinityguard_subtype` / `by_trinityguard_tier` | 企业 OS 可用两个 session 级滑动平均派生自有指标；20 类风险统计走 Enterprise taxonomy 字段，并必须处理 degraded/stale/unmapped 状态。 |
| L3 解释 | `risk_points_sum` + D1-D6 + evidence summary | 用于解释，不默认替代 trigger policy。 |

## 默认行为不变清单 {#no-behavior-change}

- 新字段默认只出现在 report/API/SSE/dashboard/enterprise payload，不改变 allow/block/defer。
- `risk_points_sum` 的外显值不自动替换 L3 trigger 内部阈值。
- `risk_velocity` 只描述趋势方向，不是风险等级或策略阈值。
- `post_action_score_ewma` 与 `session_risk_ewma` 默认均为展示/观测字段；企业 OS 派生指标不回写 Gateway 判决。
- D4/D6 任何重标定都必须先作为 shadow/default-off 语义说明。
