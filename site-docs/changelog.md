---
hide:
  - navigation
---

# 更新日志

本页只保留公开使用者需要看到的发布摘要。详细开发记录和内部进度说明保留在开发仓库文档中。

## v0.8.4 {#v084}

*2026-05-24*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">FSPR Agentic Default</span>
<span class="cs-pill cs-pill--test">4026 public tests passed</span>
</div>

### 改进

- **FSPR 默认路线切到 agentic-readonly** — First-Use Skill Package Review 默认先走 deterministic inventory 与 agentic evidence digest，本地证据不足时才进入只读 provider loop。
- **final-only 保留备用** — 可用 `CS_SKILL_TRUST_FSPR_REVIEW_MODE=final-only` 显式切回单次 final adjudicator 路线；legacy `CS_SKILL_TRUST_FSPR_ROLE_SET=final-only` 仍兼容。
- **旧 full MAS 配置面移除** — `metadata-only`、`reduced`、`full` 这些早期顺序多 reviewer role-set 不再作为生产路线；误传时 fail closed。

### 验收

- 72-case real toxic corpus 复测中 hardened `agentic-readonly` detection / healthy / minimum-quality 均为 `0.958333`、degraded `0`；同 provider `final-only` healthy detection 为 `0.777778`、degraded `6`。
- 该结果按 execution path 解释：59 deterministic floor / 5 digest floor / 8 provider path，不包装成纯模型能力提升。

### 文档

- Skill Trust、环境变量、DetectionConfig、Benchmark 配置和发布进度页已更新到 v0.8.4 口径。

---

## v0.8.3 {#v083}

*2026-05-21*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">FSPR Contextual Recovery Routing</span>
<span class="cs-pill cs-pill--test">775 focused tests passed</span>
</div>

### 改进

- **Contextual recovery routing** — FSPR 阻断 toxic / inconsistent skill 后，后续安全 recovery 写入、执行和验证不再只被高会话风险粗粒度拦截；Gateway 会生成 `ReviewRoutingIntent(source="contextual_review")`，交由 L2/L3 对具体 effect 做精确复核。
- **Authority-bound L2/L3 clearance** — L2/L3 只能清除与当前安全 recovery effect 精确绑定的上下文风险，不能清除 blocked skill lineage、runtime binding violation、FSPR package inconsistency 或 anti-bypass denied-effect repeat。
- **Blocked skill lineage boundary** — 被 FSPR 阻断的 skill lineage 会作为 session boundary 保留；同 lineage、同效果或等价绕过仍按 hard block 处理。
- **Replay-safe protected evidence** — SkillsSafety / SKILL-INJECT protected runner 记录脱敏 evidence、hash、decision metadata 和稳定 artifact snapshot，不保存原始 skill root path，也不依赖 host network。

### 验收

- Focused regression gate：`775 passed in 17.89s`。
- Focused policy replay 和 selected protected recovery rerun 均通过，覆盖 contextual recovery、blocked lineage 和 anti-bypass 边界。详细指标保留在开发仓库验证记录中。

### 文档

- 新增 [发布进度](operations/release-progress.md) 页面，记录本版本实现范围、验收结果和剩余边界。
- Skill Trust、Benchmark 模式和配置发布状态已更新到 v0.8.3 口径。

### 边界

- 本版本发布的是 FSPR block 后安全恢复路径的路由与证据边界，不声明新的全量公开评测排名。
- 原始 `rerun3` 结果目录在当前工作树缺失，E2E case selection 来自已有项目交接文档并通过新鲜 rerun 重建验证。

---

## v0.8.2 {#v082}

*2026-05-20*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">Provenance Validator Removal</span>
<span class="cs-pill cs-pill--test">focused regression passed</span>
</div>

### 移除

- **Post-action provenance validator** — 移除 artifact label 与 `skill_use_ledger` 的事后对账模块、配置项、post-action 接线和 session report 字段。Post-action 输出风险评分继续保留。

### 保留边界

- **Runtime mirror verification remains** — `verified_mirror` 仍按 Gateway-owned mirror content hash 或 trusted runner contract 校验；`CS_SKILL_TRUST_MIRROR_HASH_*` 预算配置不变。

### 文档

- Skill Trust、env vars、detection config、API reference / models 和 benchmark 配置页已移除 post-action provenance validator 当前功能口径。

---

## v0.8.1 {#v081}

*2026-05-20*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">First-Use Review Routing</span>
<span class="cs-pill cs-pill--test">focused regression passed</span>
</div>

### 改进

- **FSPR evidence-only contract** — First-Use Skill Package Review 只输出包级证据和 `admission_recommendation`；provider 返回 action / tier 这类可执行路由字段时会被视为合同漂移并降级处理。
- **Gateway-owned routing intents** — first-use、runtime binding hard evidence 和 post-action evidence 现在通过 `ReviewRoutingIntent` 进入 policy engine；最终 allow / defer / block / L2 / L3 路由由 Gateway policy 统一生成。
- **First-use policy naming** — 配置项统一为 `skill_trust_first_use_*_policy` / `CS_SKILL_TRUST_FIRST_USE_*_POLICY`，减少 FSPR provider 建议和 Gateway admission policy 之间的歧义。

### 文档

- 新增 first-use 链路材料，说明 skill 第一次被查看或使用时，从 raw evidence、Gateway-owned metadata、first-use scan、FSPR、risk snapshot、routing intent、policy decision 到 ledger/replay 的完整链条。
- Skill Trust、env vars、detection config、L1/L2/L3 和 API 模型页已更新到 first-use/FSPR routing split 口径。

### 验收边界

- 本版本修正 first-use/FSPR 路由合同与文档，不声明新的公开综合评测结论。

---

## v0.8.0 {#v080}

*2026-05-19*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">Skill Trust Runtime Binding</span>
<span class="cs-pill cs-pill--test">3645 passed, 16 skipped</span>
</div>

### 新增

- **Runtime skill binding** — Skill Trust 现在把真实运行时 skill path / native skill name / mirror root 与 Gateway-owned metadata 绑定成显式状态，阻止同名不同源、路径片段和伪造 metadata 静默继承 trust。
- **Skill-use ledger and provenance validator** — Gateway 会记录 replay-safe skill-use ledger；post-action provenance validator 将产物声明的 skill labels 与 ledger 比对，但不会反向创造 runtime invocation 或改写已完成判决。
- **FSPR and lifecycle API** — First-Use Skill Package Review 默认作为 evidence-only 审查结果输出；allowlist、greylist、blacklist、revoke、disable、restore 和 operator override 通过 auditable lifecycle API/CLI 管理。
- **Capability narrowing and feedback** — 高风险会话后可按 tool permission groups、skill trust state 和 MCP scope 收窄能力；critical block 可返回脱敏 agent-facing feedback。

### 验收边界

- 新增六框架 surface acceptance：A3S、Codex、Claude Code、Kimi、Gemini、OpenClaw 均覆盖 Gateway UDS + adapter/harness path 的 critical block 和 runtime-path-disallowed 证据。
- 该验收不是外部 CLI binary harbor smoke，也不发布公开综合评测结论。

---

## v0.7.5 {#v075}

*2026-05-17*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">Cross-CLI Skill Trust</span>
<span class="cs-pill cs-pill--test">3456 passed, 16 skipped</span>
</div>

### 修复

- **Cross-CLI Skill Trust runtime binding** — Kimi CLI、Claude Code、Gemini CLI、Codex 与 a3s-code 的 Skill Trust runtime metadata 接线统一到真实 skill 路径和运行时上下文；metadata env 路径缺失时会继续回退到项目 `.clawsentry/skill-trust-runtime.json`。
- **Claude Code prompt hook parity** — `UserPromptSubmit` 现在按 prompt hook 语义阻断，避免把 prompt block 错写成 tool preflight 专用响应。
- **Replay metadata hardening** — session replay 只保留 replay-safe Skill Trust labels/hash，过滤 path-like canonical identity、framework/scope 注入值和原始 skill root path。

### 改进

- **Benchmark matrix compatibility** — SkillsSafety/SKILL-INJECT 当前 live matrix 明确覆盖 Codex、Claude Code、Kimi CLI、Gemini CLI；`a3s-code` 在这两组 benchmark runner 中保持 unsupported rationale。

### 文档

- `/ahp/codex` 在线 API 文档、OpenAPI 和 coverage inventory 对齐 top-level `event_type` public contract。

---

## v0.7.4 {#v074}

*2026-05-16*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">L3 Multi-turn Default</span>
<span class="cs-pill cs-pill--test">3446 passed, 16 skipped</span>
</div>

### 改进

- **L3 default multi-turn mode** — L3 AgentAnalyzer 现在默认使用 multi-turn review；只有显式设置 `CS_L3_MULTI_TURN=false`、`0`、`no` 或 `off` 才会进入 legacy single-turn。
- **Benchmark protected profile alignment** — Protected SkillsSafetyBench Docker sweep 固定环境改为 `CS_L3_MULTI_TURN=true`，与公开默认模式一致。

### 文档

- 配置页、L3 决策层文档和 README 已刷新到多轮默认口径。

---

## v0.7.3 {#v073}

*2026-05-16*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">L2 Evidence Capsule</span>
<span class="cs-pill cs-pill--test">3444 passed, 16 skipped</span>
</div>

### 改进

- **L2 semantic evidence capsule** — L2 现在输出结构化、脱敏的 semantic evidence capsule，L3 审查可以复用同一份动作、证据、skill context 和 redaction metadata。
- **L3 triggered review prompt** — L3 Agent 审查提示词按 trigger reason、policy intent、review skill manifest 和 operator next steps 组织，并对只读工具结果使用统一 envelope。
- **Review skill manifest extension** — review skills 扩展到 prompt-injection transcript、data-staging exfil chain、dependency supply-chain、persistence 与 skill-trust audit。

---

## v0.7.2 {#v072}

*2026-05-16*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">Anti-bypass L1</span>
<span class="cs-pill cs-pill--test">3419 passed, 16 skipped</span>
</div>

### 新增

- **Anti-bypass L1 capability-equivalence enforcement** — Anti-bypass L1 现在把高风险动作归一为脱敏 effect summary，并用 denied / pending effect ledger 追踪同一 session 内的等价绕过尝试。
- **Approval effect binding** — Defer approval 绑定被审批的 effect；缺失 binding、binding 不完整或审批后效果漂移时失败关闭。
- 新增 14-case anti-bypass L1 replay fixture，decision match、evidence、fallback、rule、schema-sync coverage 均为 `1.0`。

---

## v0.7.1 {#v071}

*2026-05-16*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">Public Release Metadata</span>
<span class="cs-pill cs-pill--test">3357 passed, 16 skipped</span>
</div>

### 修复

- 公开发布面与公开仓库可复验内容对齐，在线文档、PyPI 主页和 GitHub README 使用一致的版本与测试计数。

### 文档

- API 文档、配置页和首页刷新到当前公开版本。Benchmark 模式的用户说明保留在 [Benchmark 模式](operations/benchmark-mode.md)。

---

## v0.7.0 {#v070}

*2026-05-16*

<div class="cs-pill-row">
<span class="cs-pill cs-pill--release">Skill Trust Registry</span>
<span class="cs-pill cs-pill--test">3468 passed, 15 skipped</span>
</div>

### 新增

- **Skill Trust registry / preflight** — 新增 `clawsentry skill-trust scan/register/register-dir`，支持 capability narrowing、agent safety feedback 和 policy drift traceability 配置面。
- **Framework integrations** — Codex、OpenClaw、Gemini CLI、Kimi CLI、Claude Code、a3s-code 等集成说明继续按可阻断范围、监控范围和 fallback 行为组织。
- **Benchmark mode** — 作为无人值守安全测试入口保留 CLI、配置与运行方式说明。

---

## 更早版本

更早版本的用户入口仍在各功能页面中维护；需要排查某个具体命令或配置时，优先使用站内搜索。
