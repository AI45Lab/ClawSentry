---
hide:
  - navigation
---

# 更新日志

本页只保留公开使用者需要看到的发布摘要。详细开发记录和内部进度说明保留在开发仓库文档中。

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
- 该验收不是外部 CLI binary harbor smoke，也不发布 benchmark leaderboard、ASR/TSR/TFR 或 raw-vs-protected 结论。

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
