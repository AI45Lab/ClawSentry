# 更新日志

本文件记录 ClawSentry 各版本的重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

### 待办

- 下一轮用户反馈与回归验证后补充。

## [0.6.8] — 2026-05-11

### 新增

- **Anti-bypass LLM-assisted recognition** — 新增隐私边界内的跨工具候选识别路径，只向 LLM 发送脱敏 capsule，且只作为 `observe` / `force_l2` / `force_l3` / `defer` 的复核信号，不触发本地 hard block。
- **LLM probe observability** — Gateway 在安全 metadata 中补充紧凑的 `anti_bypass_probe` 状态，覆盖候选数量、provider unavailable、timeout / invalid JSON / low confidence、budget skipped 等降级原因，不包含原始命令、payload、secret、环境值或确定性 token hash。
- **Shared LLM key indirection** — `resolve_llm_settings()` 现在支持 `CS_LLM_API_KEY_ENV`，operator 可用自定义环境变量承载 provider key，同时保留显式 provider 配置边界。

### 改进

- **Anti-bypass matching precedence** — recent-prior 检测改为先收集候选再按确定性排序，优先级为 exact raw repeat、same-tool normalized、same-tool Jaccard、cross-tool normalized、operation+scope、intent+support、cross-tool Jaccard，避免新的弱 cross-tool 命中遮住更早的精确重复。
- **LLM candidate gate tightened** — LLM recognition 只接收跨工具候选，必须至少具备两个弱证据信号；仅有 target scope overlap 不会进入 LLM；当前动作非 destructive 时不会触发 LLM-assisted force review。
- **Similarity metadata corrected** — `similarity` 只在真实 Jaccard 路径写入，其他路径使用准确的 `similarity_mode`（如 `raw_hash`、`normalized_hash`、`operation_scope`、`intent_label`、`llm_capsule`）。
- **User-facing docs refreshed** — Anti-bypass 在线文档、配置模板、环境变量页和进度文档改为按使用场景、动作边界和安全 metadata 解释行为，移除口号式表述。

### 测试与验证

- Anti-bypass / DetectionConfig 聚焦回归：`python -m pytest src/clawsentry/tests/test_anti_bypass_guard.py src/clawsentry/tests/test_detection_config.py -q --tb=short` → `115 passed`。
- Gateway / public docs contract 聚焦回归：`python -m pytest src/clawsentry/tests/test_gateway.py src/clawsentry/tests/test_public_docs_contract.py -q --tb=short` → `193 passed`。
- LLM settings regression：`python -m pytest src/clawsentry/tests/test_llm_settings.py -q --tb=short` → `9 passed`。
- Python 完整回归：`python -m pytest src/clawsentry/tests/ -q --tb=short` → 开发仓库 `3207 passed, 5 skipped`；公开仓库 `3199 passed, 6 skipped`。
- Web UI regression：`npm test -- --run` → `55 passed`。
- Docs API inventory：`python scripts/docs_api_inventory.py validate` → PASS。
- Docs/package build：`mkdocs build --strict` 与 `python -m build` → PASS。
- Compile/check：`python -m compileall -q src/clawsentry` 与 `git diff --check` → PASS.

## [0.6.7] — 2026-05-11

### 新增

- **Codex CLI 0.130 managed hook trust** — Codex installer now computes the host `currentHash` identity for ClawSentry-managed command hooks and writes matching trust state, so `codex exec` dispatches the managed `PreToolUse` gate instead of silently treating it as an untrusted host hook.
- **One-command Codex start path** — `clawsentry start --framework codex` now installs or refreshes managed Codex hooks by default, creates the session-log directory, enables the Codex watcher for the Gateway child process, and prints the exact uninstall command.

### 改进

- **Codex hook coverage refreshed** — Codex managed hooks cover current non-Bash tool matcher forms, `PermissionRequest`, session start observation, compact lifecycle events, and doctor diagnostics for missing trust state.
- **Uninstall safety tightened** — Codex uninstall removes only ClawSentry-owned hook/trust sections and prunes stale ClawSentry trust entries from the same hooks source; Gemini and Kimi now have explicit regression tests proving user-managed hook config is preserved.
- **Public Codex docs simplified** — Codex integration docs, README quickstart, compatibility matrix, and release-status pages now describe the default managed-hook path first, with manual `init codex --setup` kept as an advanced/repair path.

### 测试与验证

- Python 完整回归：`python -m pytest src/clawsentry/tests/ -q --tb=short` → 开发仓库 `3171 passed, 5 skipped`；公开仓库 `3170 passed, 6 skipped`。
- Codex focused regression：`python -m pytest src/clawsentry/tests/test_start_command.py src/clawsentry/tests/test_codex_initializer.py src/clawsentry/tests/test_codex_doctor.py src/clawsentry/tests/test_benchmark_command.py src/clawsentry/tests/test_gemini_initializer.py src/clawsentry/tests/test_kimi_initializer.py src/clawsentry/tests/test_codex_gateway_e2e_smoke.py src/clawsentry/tests/test_public_docs_contract.py -q` → `79 passed`。
- Real Codex CLI E2E：`python scripts/run_codex_gateway_e2e_smoke.py --output-report docs/validation/codex-gateway-daemon-e2e-smoke-2026-05-11.md` → PASS on Codex CLI `0.130.0` with workspace-write sandbox and host `PreToolUse` block evidence.
- Web UI regression：`npm test -- --run` → `55 passed`。
- Docs API inventory：`python scripts/docs_api_inventory.py validate` → PASS。
- Docs/package build：`mkdocs build --strict` 与 `python -m build` → PASS（setuptools license deprecation warnings only）。
- Compile/check：`python -m compileall -q src/clawsentry` 与 `git diff --check` → PASS.

## [0.6.6] — 2026-05-02

### 新增

- **默认 Session scope profile** — 新增 `CS_SESSION_SCOPE_PROFILE_FILE`（兼容别名 `CS_SESSION_SCOPE_PROFILE`），Gateway 启动时可加载默认 `SessionScopeProfile` JSON，并自动应用到没有显式 scope 的 `pre_action` 决策。
- **Scope 配置模板入口** — `.clawsentry.env.example` 与在线环境变量文档加入默认 scope profile 示例，方便 operator 把 dry-run 后确认的任务边界纳入启动配置。

### 改进

- **Scope tightening covers composed decisions** — 外部/异步路径组合出的 Gateway decision 如果缺少 `scope_evaluation`，会在持久化、SSE 与 benchmark auto-resolution 前补做 scope 收紧，避免 confirmed non-dry-run profile 被后续路径绕过。
- **Web UI 风险图表口径修正** — Session Detail 的风险雷达与趋势图改用文档化 D1-D6 评分范围（D1/D2/D3/D6 为 0..3，D4/D5 为 0..2），不再按 0..1 归一化轴展示。
- **Web UI 登录与 API 请求细节** — 缺失 token 时不再展示误导性的 invalid-token 文案；sessions/alerts API 查询为空时不拼接裸 `?`。
- **Sanitizer 能力页刷新** — 在线文档进一步区分 `would_sanitize` 观察面、adapter effect result 与真正 rewrite-before-history 能力，避免把 advisory-only tool-output sanitizer 说成强制改写。

### 测试与验证

- Focused config/Gateway regression：`python -m pytest src/clawsentry/tests/test_env_config.py src/clawsentry/tests/test_config_command.py src/clawsentry/tests/test_gateway.py::TestHttpTransport::test_default_scope_profile_file_applies_to_sync_decisions src/clawsentry/tests/test_gateway.py::TestHttpTransport::test_default_scope_profile_tightens_anti_bypass_defer_before_auto_allow -q --tb=short` → `25 passed`。
- Python 完整回归：`python -m pytest src/clawsentry/tests/ -q --tb=short` → 开发仓库 `3156 passed, 5 skipped`；公开仓库 `3155 passed, 6 skipped`。
- Web UI 回归：`npm test -- --run` → `55 passed`。
- Docs API inventory：`python scripts/docs_api_inventory.py validate` → PASS。
- Python lint：`git diff --name-only -- '*.py' | xargs -r python -m ruff check` → PASS。
- Compile check：`python -m compileall -q src/clawsentry` → PASS。
- Package build：`python -m build` → PASS（setuptools license deprecation warnings only）。
- Docs strict build：`mkdocs build --strict` → PASS。

## [0.6.5] — 2026-05-02

### 新增

- **Session scope preview surface** — 新增 `clawsentry scope validate/preview` 与 `POST /ahp/scope/preview`，可在启用前预览 deterministic `SessionScopeProfile` 的 allow/defer/deny 结果、dry-run/enforced 状态和 readable reason codes。
- **Scope-aware watch/report output** — `clawsentry watch` 会显示 scope profile、dry-run/enforced 边界和 reason codes，帮助 operator 判断预览与真实收紧的差异。

### 改进

- **Capability-honest sanitizer UX** — sanitizer 摘要使用 `would_sanitize`、redacted preview、redaction type/count 和 adapter degraded/unsupported wording；tool-output sanitizer 仍保持 advisory-only，除非 adapter 能证明 rewrite-before-history。
- **Opt-in OpenClaw hardening boundary** — OpenClaw hardened profile 继续保持 opt-in、dry-run-first、marker-managed、可恢复，并明确 wrappers 只转发到 AHP Gateway，不复制策略逻辑。
- **API/docs inventory refresh** — API coverage、OpenAPI、validity report 与在线决策端点文档同步到新的 scope preview 入口。

### 决策边界

- Skill/plugin first-use preflight 暂不作为 runtime enforcement 发布：当前 adapters 没有稳定的执行前 identity + content hash/version + source path + first-use/update timing 合同。
- Root-wide panic mode 暂不发布：当前支持 session-scoped quarantine/enforcement；全局模式需要单独的 operator UX 与 blast-radius 设计。

### 测试与验证

- Python 完整回归：`pytest src/clawsentry/tests -q` → `3152 passed, 5 skipped`。
- Docs API inventory：`python scripts/docs_api_inventory.py validate` → PASS。
- Python lint：`git diff --name-only -- '*.py' | xargs -r python -m ruff check` → PASS。
- Compile check：`python -m compileall -q src/clawsentry` → PASS。
- Package build：`python -m build` → PASS（setuptools license deprecation warnings only）。
- Web UI 回归：`npm test -- --run` → `53 passed`。
- Docs strict build：`mkdocs build --strict` → PASS。
- Architect verification：APPROVED after post-publish smoke。

## [0.6.4] — 2026-04-30

### 改进

- **Env-file UX 提示** — `start` / `config show --effective` 在发现 `.clawsentry.env.local`、旧 `.env.clawsentry` 或 `.clawsentry.env.example` 但未显式加载时，输出可复制的下一步提示；仍不自动读取本地 env file。
- **自动检测失败恢复路径** — 未能自动识别 framework 时，会先提示可用的 explicit `--env-file` / `CLAWSENTRY_ENV_FILE` 路径，再要求用户显式传入 `--framework`。
- **公开文档口径收口** — README、PyPI README、在线配置页、recent feature coverage、API metadata 与进度文档更新到 v0.6.4，强调“发现即提示，不等于加载”的严格来源模型。

### 测试与验证

- Python 完整回归：`python -m pytest src/clawsentry/tests/ -q --tb=short` → `3118 passed, 5 skipped`。
- Web UI 回归：`npm test -- --run` → `53 passed`。
- Focused env-file UX / docs contract regression：`python -m pytest src/clawsentry/tests/test_dotenv_loader.py src/clawsentry/tests/test_start_command.py src/clawsentry/tests/test_config_command.py src/clawsentry/tests/test_cli_main.py src/clawsentry/tests/test_public_docs_contract.py -q --tb=short` → `71 passed`。
- Docs API inventory：`python scripts/docs_api_inventory.py validate` → PASS。
- 文档构建：`mkdocs build --strict` → PASS。
- 包构建：`python -m build` → PASS（setuptools license deprecation warnings only）。
- `git diff --check` → PASS。
- Public publish smoke is tracked in `docs/validation/v0.6.4-env-file-hints-release-2026-04-30.md`.

## [0.6.3] — 2026-04-30

### 改进

- **配置参考 env-first 收口** — 配置概览、模板、环境变量、检测管线、策略调优、CLI、Quickstart、集成与运维页面统一为 `CS_*` / `AHP_*` dotenv 参数口径，移除正常 runtime 路径仍使用项目 TOML 的过时说法。
- **阅读路径去重** — 明确“环境变量”是参数目录，“检测管线配置”是 L1/L2/L3 runtime 层级图，“策略调优”是按场景取舍的调参指南，减少多个页面看不出差别的问题。
- **可复制模板块补齐** — 配置模板新增/整理 L1、L2、严格 L3、Anti-bypass observe/review/enforce、DEFER、post-action / trajectory、D4 频率、benchmark 与生产部署块，可直接复制到部署环境或显式 env-file。
- **公开发布面刷新** — README、PyPI README、包内 README、在线文档与发布状态页更新到 v0.6.3，公开仓库 release 不再停留在早期口径。

### 修复

- 修复配置文档中的 env-template 路径误写、错误代码块语言和 fake section header 等 stale wording。
- 修复 `init --setup` 相关测试仍断言 `.clawsentry.toml` framework blocks 的旧契约，改为验证 env-first 输出与不落盘 secret/config。

### 测试与验证

- Python 完整回归：`python -m pytest src/clawsentry/tests/ -q --tb=short` → `3113 passed, 5 skipped`。
- Web UI 回归：`npm test -- --run` → `53 passed`。
- 文档构建：`mkdocs build --strict` PASS。
- Docs/config contract：新增 stale TOML/env-template/release freshness 回归，防止配置参考再次漂移。

## [0.6.2] — 2026-04-29

### 新增

- **Kimi CLI 一等 native-hook 支持** — 新增 `kimi-cli` adapter、harness 分发路径、initializer、readiness 报告、测试与公开集成文档。Kimi `PreToolUse` 和 `UserPromptSubmit` 会把 Gateway deny 决策映射为 Kimi `hookSpecificOutput.permissionDecision=deny`，post/session/subagent/compact/notification hooks 提供异步观测。
- **安全的 Kimi 配置管理** — `clawsentry init kimi-cli --setup` 会向 `$KIMI_SHARE_DIR/config.toml` 或 `~/.kimi/config.toml` 写入 marker-managed `[[hooks]]` 条目，保留非 ClawSentry 用户 hooks；`--uninstall` 只移除受管条目。

### 改进

- **Kimi 能力边界显式化** — Kimi native hooks 现在明确为 native allow/block 支持，不提供 `a3s-code` AHP transport 对等能力。Native `modify` 与真实 `defer` 会报告为 unsupported/degraded，而不是被宣传为已支持。
- **六框架文档覆盖** — README、PyPI README、quickstart、CLI 文档、FAQ、兼容矩阵、recent feature coverage 与在线文档现在都把 Kimi CLI 与 a3s-code、Claude Code、Codex、Gemini CLI、OpenClaw 并列说明。

### 测试与验证

- Kimi 聚焦回归：`python -m pytest src/clawsentry/tests/test_kimi_adapter.py` → `11 passed`；`python -m pytest src/clawsentry/tests/test_kimi_harness.py` → `4 passed`；`python -m pytest src/clawsentry/tests/test_kimi_initializer.py` → `5 passed`。
- 包含 Kimi 就绪状态的 start/status 回归：`python -m pytest src/clawsentry/tests/test_integrations_command.py src/clawsentry/tests/test_start_command.py` → `73 passed`。
- Python 完整回归：`python -m pytest src/clawsentry/tests/ -q --tb=short` → 开发仓库 `3221 passed, 5 skipped`；公开仓库 `3220 passed, 6 skipped`。
- 文档构建：`mkdocs build --strict` PASS。
- VPN no-key `kimi-k2.5` endpoint 下的真实 Kimi CLI E2E：prompt 放行、prompt 拒绝、安全 Shell 放行 + `PostToolUse`、危险 Shell 在 `PreToolUse` 阶段拒绝，以及 marker-hook uninstall 均已验证。

## [0.6.1] — 2026-04-29

### 改进

- **配置来源严格拆分** — `CS_*` / `AHP_*` 运行时值来自 process/deployment environment，或显式 `--env-file` / `CLAWSENTRY_ENV_FILE`；`.clawsentry.env.example` 是可提交 dotenv 模板，`.env.clawsentry` 仅用于 legacy/migration，不会在正常 `init` / `start` 流程中生成或自动加载。
- **框架启用状态 env-first 化** — framework 状态使用 `CS_FRAMEWORK` 与 `CS_ENABLED_FRAMEWORKS` 表达；`init` 输出这些 env 建议而不写入 secret/runtime 文件。
- **env-file 来源显式化** — env-file 解析不修改进程环境，并报告隔离值与来源标签；最终解析顺序为 `CLI > process env > explicit env-file > legacy aliases > defaults`。
- **本地 fresh start UX** — 未提供 token 时，`clawsentry start` 会生成临时内存态 `CS_AUTH_TOKEN`，不会把 secret 写入磁盘；对 ephemeral-token session，`start --no-watch` 现在会打印可复制的 `clawsentry watch --token ...` 命令。
- **Readiness UX 对齐** — `start` 与 `integrations status` readiness 检查现在使用 effective process-env + explicit-env-file 视图，避免 runtime 值来自 shell/deployment env 时误报 “not configured”。

### 文档

- 围绕 env-first + explicit env-file 模型，重写配置概览、env-vars、templates、CLI、quickstart、deployment、troubleshooting、integration pages、README 文案与相关在线文档。
- 新增生产配置分层指引、env-file 迁移排障说明、可复制 dotenv templates，以及更清晰的 a3s-code / ephemeral-token 说明。

### 测试与验证

- 新增回归覆盖：`clawsentry test-llm` 中的 explicit env-file L3 行为、非变异 env-file 解析、env 优先级、framework enablement、来自 process env 的 readiness，以及 init/start 流程不生成 `.env.clawsentry`。

## [0.6.0] — 2026-04-29

### 新增

- **Setup / config truth matrix** — 新增配置真值矩阵，逐项记录 `.clawsentry.toml`、`.env.clawsentry` 与 process env 的支持状态、runtime-effective path、验证测试和最终暴露决策，避免把 parse-only 或 env-only 设置误包装成 wizard 可见能力。
- **真实 L3 Agent 行为回归** — 新增 `replace_l2` 与 `eager` 的 failing-first 行为测试；即使首个 L2 结果已经达到 decisive confidence，`CS_L3_ROUTING_MODE=replace_l2` 仍会真实运行同步 L3，并将 `actual_tier=L3`、`l3_state=completed` 和 trace summary 持久化。
- **可选真实 provider L3 E2E** — 新增默认跳过的 `CS_L3_RUN_REAL_E2E=true` 测试，用 OpenAI-compatible / Anthropic provider 证明真实 LLM 调用可以完成 L3 执行和 trace 持久化；CI 默认不消耗额度。
- **Sanitized demo template** — 为 a3s_demo 提供 allowlist 生成的 `.clawsentry.toml.example`，保留 OpenAI-compatible base URL / model / L3 eager / replace-L2 / anti-bypass 等安全占位，不复制原始 `.env.clawsentry` 或任何 token/key。

### 改进

- **交互式配置向导 UX** — `clawsentry config wizard --interactive` 改为编号选择、TTY-safe 进度提示和无新依赖终端 polish；非 TTY、`NO_COLOR`、CI/non-interactive 路径保持 deterministic。
- **配置优先级文档** — 在线文档明确 `.clawsentry.toml` 是可共享非 secret 项目默认/策略意图，`.env.clawsentry` 是本地启动便利文件且不覆盖已设置 process env，process env 是最高优先级和 secret/deployment override surface。
- **Reporting API schema 明确化** — OpenAPI 的 `/report/sessions`、`/report/session/{id}/risk`、Enterprise 对应 endpoints 现在在 response schemas/properties 中声明 `session_risk_ewma`，不再只依赖 examples；指标字典补充 alpha=0.3、no-data 语义、分数范围和 non-decision-affecting 边界。
- **L3 trace report 可观测性** — `/report/session/{id}` 与 `/report/session/{id}/risk` 暴露 compact L3 state/trace summary，便于验证 trigger reason、skill/mode、turns、final verdict 与 evidence summary。

### 修复

- **`replace_l2` / `eager` parse-only 风险** — 修复同步 runtime 只解析 `CS_L3_ROUTING_MODE` / `CS_L3_TRIGGER_PROFILE`、但 decisive L2 结果可能跳过 L3 follow-up 的行为缺口。
- **API docs drift** — 更新 API inventory traceability、schema tests 和 docs contract，防止 `session_risk_ewma`、`high_or_critical_count` 等 canonical 字段继续漂移。
- **Secret-safety boundary** — demo template 和测试加入 secret-safety guardrail，避免高熵 secret、`CS_AUTH_TOKEN`、`OPENAI_API_KEY` 或 provider token 进入 docs/artifacts。

### 测试与验证

- Python 完整回归：开发仓库 `3251 passed, 5 skipped`；公开仓库 `3250 passed, 6 skipped`。
- 真实 provider L3 E2E（显式启用）：`CS_L3_RUN_REAL_E2E=true python -m pytest src/clawsentry/tests/test_l3_real_provider_e2e.py -q` → `1 passed`。
- 必跑 setup/docs/L3 contract 套件：`529 passed`。
- Gateway / advisory / Codex E2E 聚焦套件：`171 passed` + `19 passed` + `10 passed` + `6 passed, 1 skipped` + `7 passed` + `4 passed`。
- Docs API 清单 + 严格文档构建：PASS。
- 新增真实 provider E2E fixture/template 的敏感信息扫描：PASS（未发现真实 API key/token 模式）。

## [0.5.14] — 2026-04-28

### 新增

- **Anti-Bypass Follow-up Guard（默认关闭）** — 新增 `PRE_ACTION` follow-up guard，在显式启用 `CS_ANTI_BYPASS_GUARD_ENABLED=true` 后，可基于 prior final risky decision 的 compact fingerprints 检测 exact raw repeat、normalized destructive repeat 与 cross-tool/script similarity。
- **`CS_ANTI_BYPASS_*` 配置合同** — `DetectionConfig` 新增 TTL、per-session cap、eligible prior risk/verdict、exact/normalized/cross-tool action、similarity threshold 与 allow-decision recording 开关；未引入新的 anti-bypass `AHP_*` 环境变量。

### 改进

- **Gateway precedence 明确化** — anti-bypass guard 位于 quarantine/session enforcement 之后、normal policy 之前；memory update 仅在 trajectory / benchmark auto-resolution 与 `_record_decision_path` 完成后记录最终 verdict/record id。
- **Redacted observability** — anti-bypass metadata、decision SSE 与 defer-pending SSE 使用 hashes / fingerprints / ids / labels / tool name，不暴露 raw payload、raw command、secret 或 L3 trace。
- **在线配置文档** — DetectionConfig、env vars、recent feature coverage 与 a3s-code 集成文档补充 observe / review / enforce rollout 示例。

### 修复

- **Cross-tool hard-block boundary** — `anti_bypass_cross_tool_similarity_action=block` 会被拒绝/回退到 `force_l3`，确保 cross-tool/script similarity 不能本地 hard-block。
- **Final-only memory** — non-final approval-pending `DEFER` 不再写入 anti-bypass memory，避免用未最终确认的 pending decision 作为后续阻断依据。

### 测试与验证

- Anti-bypass 聚焦回归：`14 passed`。
- guard/config/gateway 聚焦回归：`256 passed`。
- Python 完整回归：开发仓库 `3239 passed, 4 skipped`；公开仓库 `3238 passed, 5 skipped`。
- Web UI 完整回归：`53 passed`；Vite 构建 PASS。
- Docs API 清单 + 严格文档构建：PASS。
- 包构建：PASS（仅 setuptools license deprecation warnings）。
- guard/config/gateway 聚焦回归：`256 passed`。
- 架构审查：已通过；安全审查：已通过。
- 架构审查：已通过；安全审查：已通过。

## [0.5.13] — 2026-04-27

### 新增

- **Post-action Enterprise OS contract** — `/report/sessions`、`/report/session/{id}/risk` 与 `/report/session/{id}/post-action` 暴露 `score_range` / `score_semantics`，明确 `0.0..3.0` 分数范围、空数据 `0.0` 语义，以及 `session_risk_ewma` 与 `post_action_score_ewma` 不应裸值相加。
- **AgentDoG / ATBench labeled replay adapter** — runner 支持 labeled manifest batch replay、safe/unsafe 聚合、per-record artifacts、unsafe recall、safe false-positive、coverage 与 tier 分布指标。
- **Five-framework ingress smoke** — 新增单 case smoke，覆盖 a3s-code、Claude Code、Codex、Gemini CLI 与 OpenClaw 的本地 adapter/harness/Gateway ingress path。

### 改进

- **Post-action scoring severity floors** — 保留 additive `0.0..3.0` numeric score，同时对明显外传、秘密泄露和混淆组合设置严重性 floor，避免低分低估高危工具输出。
- **Gateway whitelist propagation** — post-action 分析优先从 `_clawsentry_meta.file_path`，再从 payload `file_path/path/target_path` 传入 whitelist 匹配。
- **Dashboard Sessions score semantics** — Sessions 主分优先 `session_risk_ewma`，ScoreBar 按 `0..3` 归一化，并显示 post-action EWMA 辅助分。
- **Anthropic provider base URL** — AgentDoG runner、LLM factory、`clawsentry test-llm` 与 enterprise fallback 保留 Anthropic base URL，支持 native Claude-compatible endpoint smoke。

### 修复

- **Session EWMA zero seed** — reporting helper 现在用首个分数初始化 EWMA，修复 `[0.0, 3.0]` 被错误计算为 `3.0` 的问题；正确值为 `0.9`。
- **Post-action threshold validation** — 负阈值抛出 `ValueError`，`>3.0` 阈值记录 unreachable warning。
- **Post-action docs drift** — 修正 SSE 示例字段名、tier 小写、默认阈值与 `0.5+0.5=1.0 -> emergency` 口径。

### 测试与验证

- post-action / config / gateway / docs contract 聚焦回归：`366 passed`。
- Web UI Sessions 回归：`3 passed`。
- Web UI 构建：PASS。
- Docs API 清单：PASS。
- 完整发布验证：`3225 passed, 4 skipped` Python 回归、`53 passed` Web UI 回归、严格文档构建与包构建 PASS；详见 `docs/validation/v0.5.13-post-action-enterprise-release-2026-04-27.md`。

## [0.5.12] — 2026-04-27

### 新增

- **交互式配置向导升级** — `clawsentry config wizard --interactive` 现在提供明确的 5 步 TTY 配置流程，覆盖 framework、mode、LLM provider、L2/L3 与 token budget；非 TTY 的显式交互请求会失败并给出可执行提示，`--non-interactive` 保持 CI/模板可复现路径。
- **AgentDoG / ATBench replay 基建** — 新增 `benchmarks/scripts/agentdog_atbench_clawsentry.py`，支持 AgentDoG trajectory 转 ClawSentry canonical events、读取 `agent.hcl` 的 OpenAI-compatible API 配置、执行 L1/L2/L3 replay，并输出 `events.jsonl`、`decisions.jsonl`、`risk_report.json`、`summary.json` 与 `summary.md`。
- **OpenAI-compatible LLM 参数覆盖** — `CS_LLM_TEMPERATURE` 与 `CS_LLM_PROVIDER_TIMEOUT_MS` 可用于兼容只接受特定 temperature 或需要更长 provider timeout 的模型；AgentDoG runner 暴露 `--llm-temperature` 与 `--llm-provider-timeout-ms`。

### 改进

- **Metric Dictionary canonical 化** — 在线指标字典收敛为单一 canonical 字段集，移除旧同义/legacy 指标混排，补齐 `session_risk_sum`、`session_risk_ewma`、`risk_points_sum`、`risk_velocity`、`window_risk_summary`、`system_security_posture` 与 D1-D6 的公式、窗口语义和消费边界。
- **Reporting API 示例对齐后端合同** — `/report/sessions`、`/report/session/{id}/risk` 与 Enterprise posture 示例补齐 `generated_at`、`decision_affecting`、D1-D6、`score_0_100` / `level` / `drivers` 等实际字段，避免 consumer 继续依赖旧 `posture` / `score` / D1-D5 口径。
- **配置向导 UX 语义收敛** — framework 选择现在明确是下一步启动命令提示，不再暗示 wizard 已安装 framework hooks；provider 为 `none` 时 L2/L3 强制关闭，避免写出不可用配置。

### 修复

- **会话风险趋势算法统一** — `session_registry` 的 `risk_velocity` 与 reporting helper 统一为窗口首尾 composite score 差值，阈值 `0.25`；单样本返回 `unknown`。
- **窗口风险摘要字段统一** — `window_risk_summary` 不再输出旧 alias `composite_score_sum`，统一使用 `session_risk_sum`，并补齐 `generated_at` 与 `decision_affecting=false`。

### Benchmark / 交接

- AgentDoG 上游已 clone 到 `benchmarks/AgentDoG`（commit `09adfb8`，目录已 gitignore）。
- 使用 `agent.hcl` 的 provider/base_url/API key 与 `openai/kimi-k2.5` 跑通 sample 端到端 smoke：3 events / 3 L2 decisions / max risk `medium`；结果目录为 `benchmarks/results/agentdog-atbench/2026-04-27_kimi-k2.5_agenthcl_temp1_clawsentry_sample_09adfb8`。
- 该 sample 没有 ground-truth label，因此只作为基建 smoke；下一窗口继续推进 labeled ATBench 最小样本集、raw vs ClawSentry 对照、a3s-code / Codex / Claude Code / Gemini CLI / OpenClaw runner 设计。

### 测试与验证

- Python 完整回归：开发仓库 `python -m pytest src/clawsentry/tests/ -q --tb=short` → `3196 passed, 4 skipped`；公开仓库预期 `3189 passed, 11 skipped` benchmark-only 测试跳过后。
- 发布聚焦回归：`python -m pytest src/clawsentry/tests/test_llm_factory.py src/clawsentry/tests/test_config_command.py src/clawsentry/tests/test_benchmark_wrapper_contract.py src/clawsentry/tests/test_public_docs_contract.py -q` → `51 passed`。
- Gateway core 回归：`python -m pytest src/clawsentry/tests/test_gateway.py::TestGatewayCore -q` → `55 passed`。
- docs/config/benchmark/LLM 聚焦检查：`31 passed`；Gateway metric contract 检查：`4 passed`。
- `python scripts/docs_api_inventory.py validate` → PASS。
- `mkdocs build --strict` → PASS。
- `git diff --check` → PASS。

## [0.5.11] — 2026-04-26

### 修复

- **WebUI replay label 产物同步** — 重新构建 `src/clawsentry/ui/dist`，确保已实现的 `Prompt` / `Response` / `Tool request` / `Tool result` 会话详情标签进入新版本静态产物，避免录屏时继续看到旧 bundle 的 `unknown`。
- **a3s_demo workspace 绑定收敛** — 手动写入的 PrePrompt / PostResponse 对话 marker 现在与真实 a3s-code session 使用同一个 ClawSentry workspace root（demo root），测试数据仍保留在 `workspace/` 子目录，避免 WebUI 出现额外工作区分组。

### 测试与验证

- Python 完整回归：`conda run -n a3s_code python -m pytest src/clawsentry/tests/ -q --tb=short` → 开发仓库 `3183 passed, 4 skipped`；公开仓库 `3180 passed, 7 skipped`。
- 聚焦回归：`python -m pytest demostation_projects/tests/test_a3s_demo_recording.py src/clawsentry/tests/test_ui_build_contract.py -q --tb=short` → `11 passed`。
- 公开文档/版本合同：`python -m pytest src/clawsentry/tests/test_public_docs_contract.py -q --tb=short` → `10 passed`。
- Web UI 回归：`npm test -- --run` → `53 passed`。
- Web UI 构建：`npm run build` → PASS。

## [0.5.10] — 2026-04-26

### 新增

- **L3 advisory 自然语言分析** — `llm_provider`、fake/local advisory worker 与 full-review action payload 现在可携带 bounded `analysis_summary`、`analysis_points`、`operator_next_steps`，Web UI Session Detail 会展示“分析摘要 / 关键依据 / 操作员下一步”，同时保持 `advisory_only=true` 与 `canonical_decision_mutated=false`。
- **a3s_demo 录屏输出同步** — demo runner 的 L3 full-review 摘要会打印自然语言 analysis、next steps 与 token 用量，并在 README 中明确 v0.5.10 不需要重装 a3s-code 或修改 `agent.hcl`。

### 改进

- **Web UI token-first governance** — LLM 使用、状态栏、Runtime Feed、Dashboard 与 Session Detail 统一优先展示 input/output/total tokens、token limit / evidence quota；legacy USD 字段保留为兼容数据但不再作为主治理文案。
- **Workspace fallback 与分组稳定性** — 缺少 workspace root 的 session 现在按 framework / adapter 进入稳定 “Unbound workspace / 未绑定工作区” 分组，避免用 session id 形成重复 `Unknown Workspace`。
- **Dashboard 与 Session Detail 操作员阅读路径** — 首页第一屏突出当前处置优先级、风险队列、L3 evidence 与 token pressure；Session Detail 决策时间线默认最新优先，风险构成移除误导性灰色 radar 轴并补充维度 mini bars。
- **中英文 UI 文案补齐** — Dashboard、Sessions、Session Detail、Runtime Feed、StatusBar 与 LLM drilldown 的本轮触达标签转入 locale key，减少中文模式下的非必要英文 chrome。
- **在线文档同步** — Dashboard、L3 advisory、Reporting API 与配置文档补充 token-first、unbound workspace、L3 narrative payload 与 demo 环境口径。

### 测试与验证

- Web UI 回归：`50 passed`。
- Python 聚焦回归：`263 passed`。
- TypeScript 诊断：PASS。
- Web UI 构建：PASS。
- `git diff --check`：PASS。
- 架构验证：已通过。
- 浏览器截图：Dashboard / Sessions / Session Detail desktop + mobile 截图保存在 `output/playwright/clawsentry-l3-ux/`。

## [0.5.9] — 2026-04-26

### 修复

- **Web UI 风险图表显示** — Session Detail 的“风险构成”和“风险分数趋势”图表现在为 Recharts `ResponsiveContainer` 提供明确宽高，避免真实布局中高度测量为 0 导致图表不渲染。
- **项目配置运行时生效** — Gateway、stack 与 `test-llm` 在构建检测/LLM 配置前会读取项目级 `.clawsentry.toml` 并导出 canonical `CS_*` 环境变量，同时保留显式环境变量优先级。
- **Benchmark 模式配置语义** — `clawsentry benchmark env` 输出 canonical `CS_MODE=benchmark`，Gateway benchmark 自动解析会在持久化/SSE 前应用，并尊重 `benchmark_defer_action`。
- **CLI 配置写入一致性** — `config wizard --llm-provider none` 与 `--write-project-config` 可直接使用文档中的复制命令；`config set/enable/disable` 保留无关 section 并正确写入 bool/int/float。

### 改进

- **在线文档从 0 到可用的阅读路径** — 首页、快速开始、配置概览、配置模板、benchmark-mode、Codex/Gemini 集成、Dashboard 与 CLI 文档改为用户/二次开发者口径，减少开发进度式表述。
- **配置模板可复制性** — 增补个人、团队 L2 token budget、严格 L3、CI/benchmark 与生产环境模板，并明确 env > project config > defaults 的优先级。
- **公开口径对齐** — README、包内 README、安装页、首页指标与 changelog 更新到 v0.5.9 发布口径。

### 测试与验证

- Python 完整回归：开发仓库 `3177 passed, 4 skipped`。
- Web UI 回归：`50 passed`。
- Web UI 构建：PASS。
- UI static/build contract 聚焦回归：`10 passed`。
- `python -m ruff check <changed Python files>`：PASS。
- `python -m compileall`：PASS。
- `python scripts/docs_api_inventory.py validate`：PASS。
- `mkdocs build --strict`：PASS。
- `python -m build`：PASS（仅 setuptools license deprecation warnings）。

## [0.5.8] — 2026-04-26

### 新增

- **有效配置与启动向导** — `clawsentry config show --effective` 现在展示项目配置、环境变量、默认值与 legacy alias 的来源信息，并对 LLM key / token 等敏感字段做稳定脱敏；配置向导与 canonical `.clawsentry.toml` section 覆盖项目模式、LLM、features、budgets、defer 与 benchmark。
- **Token budget enforcement** — LLM budget 现在以 provider-reported input/output/total tokens 为执行依据，保留 legacy USD 字段为兼容/展示信息；缺失 usage 的 provider 调用会计入 `unknown_usage_calls`，不会伪造 token 用量触发拦截。
- **Benchmark 模式 CLI** — 新增 `clawsentry benchmark env|enable|disable|run`，为 Codex benchmark/autonomous runs 生成显式 no-human env、安装/清理临时 managed hooks，并默认拒绝修改当前用户真实 `~/.codex`。

### 改进

- **部署 UX 与 service validate** — systemd / Docker env 模板改用 canonical token-budget 与 timeout 变量，`clawsentry service validate` 输出脱敏摘要、legacy warning、缺失 auth / 非法 token budget / timeout 错误，并在成功时给出明确 PASS 信号。
- **Bounded-large timeout defaults** — L2 / L3 / DEFER 默认从短探索窗口调整为更适合本地/持久部署的大窗口，同时保持 hard timeout cap；L2 路径不会因为默认 L3 timeout 变长而继承 5 分钟等待。
- **在线文档配置旅程** — 新增/更新配置概览、模板、env vars、部署与 benchmark-mode 文档，并把 quickstart / CLI 文档改为 canonical config + effective config 的用户路径。

### 测试与验证

- Python 完整回归：开发仓库 `3173 passed, 4 skipped`；公开仓库 `3170 passed, 7 skipped`。
- UX/config/benchmark/service 聚焦回归：`175 passed`。
- `python -m ruff check <changed Python files>`：PASS。
- `python -m compileall`：PASS。
- `python scripts/docs_api_inventory.py validate`：PASS。
- `mkdocs build --strict`：PASS。
- `python -m build`：PASS（仅 setuptools license deprecation warnings）。
- `git diff --check`：PASS。

## [0.5.7] — 2026-04-25

### 新增

- **报表风险指标合同刷新** — `/report/*`、SSE、Dashboard 与 Enterprise OS 现在统一暴露 `latest_composite_score`、`session_risk_sum`、`session_risk_ewma`、`risk_points_sum`、`window_risk_summary` 与 `system_security_posture`，并明确这些字段默认只用于展示/观测，不改变 L1/L2/L3 判决。
- **Metric Dictionary 在线文档** — 新增公开指标字典，逐字段说明单位、范围、窗口语义、可空性、legacy 状态、消费面与示例 payload，避免把 `cumulative_score` 误读为新窗口累计分。
- **Enterprise OS posture API** — 企业概览新增系统态势、缓存 fresh/stale/degraded 状态与窗口汇总字段，供外部运营面板读取全局健康状态。

### 改进

- **Dashboard / Sessions / Session Detail / Runtime Feed 指标展示** — Web UI 现在优先展示 EWMA / latest composite / system posture，并在旧 payload 下回退到 legacy `cumulative_score`，同时保留 framework、workspace 与 session 三层扫描路径。
- **watch 输出与 decision diagnostics** — CLI watch、测试诊断与 API payload 对齐新指标名称，使 terminal、API 与 Web UI 使用同一套解释字段。
- **API 有效性产物刷新** — coverage、OpenAPI、validity report 与 docs contract 同步更新，确保源码 route、Markdown anchor 与在线文档引用继续可追踪。

### 测试与验证

- Python 完整回归：`3135 passed, 4 skipped`。
- Web UI 回归：`49 passed`。
- Web UI 构建：PASS。
- `python scripts/docs_api_inventory.py validate`：PASS。
- `mkdocs build --strict`：PASS。
- `git diff --check`：PASS。

## [0.5.6] — 2026-04-25

### 新增

- **Gemini CLI native hook support** — 新增 `GeminiAdapter`、Gemini hook decision translator、`clawsentry harness --framework gemini-cli`、`clawsentry init gemini-cli --setup/--uninstall`、status/doctor readiness 输出与在线集成文档。默认写项目级 `.gemini/settings.json`，不会修改真实用户 `~/.gemini`。
- **Gemini real BeforeTool deny 支持** — 真实 Gemini CLI 的 `run_shell_command` 会规范化为 policy-facing `bash`，同时保留 raw Gemini tool identity；真实 provider smoke 已证明 `rm -rf` 类危险命令在 `BeforeTool` 阶段被 deny。
- **Codex bounded native defense 扩展** — managed Codex hooks 现在新增同步 `PermissionRequest(Bash)` approval gate，并保留 `PreToolUse(Bash)` 同步 preflight；harness 补齐 Codex `PermissionRequest` allow/deny、`PostToolUse` containment、`UserPromptSubmit` block 与 `Stop` continuation 响应翻译。默认仍不改写当前开发会话 hooks，真实 Codex hook 实验必须使用临时 `CODEX_HOME` / 临时工作目录隔离执行。

### 文档与交接

- **Gemini CLI 在线文档与兼容矩阵** — 新增 Gemini CLI 集成指南，更新首页、公开 README、包内 README、framework compatibility 与 doctor/status 文案，统一标记 `real_beforetool_block_supported`。
- **API handoff artifacts 可追踪化补齐** — 强化 `site-docs/api/*` 的 coverage/validity/openapi 与 overview/reference 导航，降低交接时 API 证据定位成本。
- **AHP/L3 文档路径澄清** — 更新 `site-docs/api/decisions.md` 与 `site-docs/decision-layers/l3-advisory.md`，让操作员能更快定位 full-review、advisory-only 与边界语义。
- **企业 OS DEFER 弹窗交接资产** — 新增并保留企业 OS DEFER 弹窗交接材料，用于下游系统接入人工审批弹窗最小信息合同。

### 测试与验证

- Python 完整回归：`3126 passed, 4 skipped`。
- `mkdocs build --strict`：PASS。
- Gemini CLI 真实 provider smoke：`gemini-2.5-flash` + Gemini relay 证明真实 `BeforeTool` deny；Kimi/OpenAI-compatible endpoint 不属于 Gemini CLI 直连支持。
- **UI 浏览器验证 fixture 补齐企业 DEFER 场景样本** — `build_runtime_replay_events` 新增 openclaw `defer_pending` rollout 命令样本，并补充契约测试，确保弹窗接入所需关键字段持续可用。

## [0.5.5] — 2026-04-23

### 新增

- **L3 advisory automation Phase 3** — 新增 feature-gated heartbeat/idle/success/rate-limit aggregate snapshot queueing：仅在 `CS_L3_ADVISORY_ASYNC_ENABLED=true` 且 `CS_L3_HEARTBEAT_REVIEW_ENABLED=true`、存在 high/critical evidence delta、且同 session/runner 无 queued/running `heartbeat_aggregate` job 时冻结 snapshot 并排队 job；不启动 scheduler、不自动执行 provider。
- **Bounded L3 job drain** — 新增 `GET /report/l3-advisory/jobs`、`POST /report/l3-advisory/jobs/run-next`、`POST /report/l3-advisory/jobs/drain` 与 `clawsentry l3 jobs list|run-next|drain`，使用 queued-only claim 语义，默认 `max_jobs=1`、硬上限 `10`，running/completed/failed job 不会被 rerun。
- **L3 advisory action summaries** — high/critical completed review 与 degraded provider review 现在会生成 compact `l3_advisory_action`，在 report/session risk、SSE、watch、RuntimeFeed 与 Session Detail 中体现 `advisory_only=true` / `canonical_decision_mutated=false` 与 snapshot/job/review IDs。

### 测试与验证

- backend / CLI / watch / UI / docs 聚焦验证记录见 `docs/validation/l3-advisory-phase3-heartbeat-drain-2026-04-23.md`。

## [0.5.4] — 2026-04-23

### 新增

- **AHP decision effects v1** — 在保持 `allow/block/modify/defer` 顶层 verdict 稳定的前提下，新增 request-only `decision_effects` envelope，用于表达 session quarantine / mark-blocked 与 command/tool-input rewrite 请求。
- **Adapter effect result trail** — 新增独立 `adapter_effect_result` 记录与 `/ahp/adapter-effect-result` 写回路径，区分 policy 请求和 host adapter 实际 enforced/degraded/unsupported 结果，并提供幂等写入。
- **Session quarantine / mark-blocked** — `block + action_scope=session` 现在可标记 compromised session；v1 后续阻断范围限定为同 session `pre_action`，释放路径与旧 session-enforcement cooldown 分离。
- **Audited rewrite lifecycle** — DEFER/confirmation resolve 可携带经过校验的 command/tool-input replacement payload，生成 `modify + modified_payload + rewrite_effect`；trajectory/replay/SSE/watch 默认只保留 hash 和 redacted preview。
- **Public API docs inventory** — 在线 API Reference/OpenAPI/coverage artifacts 补齐 adapter-effect-result 与 quarantine endpoints，并继续用契约测试校验 source routes 与文档覆盖一致性。

### 测试与验证

- Python 回归：开发仓库 `3057 passed, 4 skipped`；公开仓库 `3054 passed, 7 skipped`
- AHP action expansion / gateway / watch 聚焦回归：`374 passed`
- Web UI 回归：`40 passed`
- Web UI 构建：PASS
- `mkdocs build --strict`：PASS
- `git diff --check`：PASS

## [0.5.3] — 2026-04-22

### 新增

- **WebUI/watch L3 状态可读化** — 新增 operator-readable L3 状态/原因/runner 标签层，WebUI RuntimeFeed、Sessions、Session Detail 与 `clawsentry watch` 在保留底层 ID/边界语义的同时显示更易扫描的状态文案；L3 advisory job 现在同时展示 frozen snapshot / explicit-run-only 边界，不改变 JSON 输出、Gateway 判决、scheduler 或 canonical decision。
- **L3 full-review operator visibility** — Session Detail 现在在 full-review action 之外持续展示最新 advisory review/job/snapshot ID、frozen record boundary 与 “canonical decision unchanged” 口径，根 README / 状态页同步到 `v0.5.3` 基线并增加版本一致性契约测试。
- **L3 咨询审查在线文档** — 在线文档新增独立 L3 咨询审查页面，面向使用者解释 full review、snapshot/job/review、runner 选择、Web UI/CLI/API 路径和 advisory-only 边界；Codex 集成页新增 hook 安装验证说明，规则治理页补充 CI artifact 与 sample events 覆盖范围。
- **L3 advisory real-provider smoke hardening** — `llm_provider` advisory worker 的 provider completion budget 从 1024 提升到 4096 tokens，避免 reasoning-heavy OpenAI-compatible 模型在 reasoning 阶段耗尽输出预算而返回空 content；`openai/kimi-k2.5` 已重新通过 `--require-completed` 真实 smoke，证据见 `docs/validation/l3-advisory-provider-real-smoke-rerun-2026-04-21.md`。

### 测试与验证

- Python 回归：开发仓库 `3025 passed, 4 skipped`；公开仓库 `3022 passed, 7 skipped`
- Web UI 回归：`39 passed`
- `mkdocs build --strict`：PASS
- `python -m build`：PASS

## [0.5.2] — 2026-04-21

### 新增

- **Codex -> Gateway daemon 真实 E2E smoke** — 新增 `scripts/run_codex_gateway_e2e_smoke.py` 与 `clawsentry.devtools.codex_gateway_e2e_smoke`，可在临时 `CODEX_HOME` 下安装 managed native hooks、启动本地 Gateway daemon，并验证真实 Codex CLI `PreToolUse(Bash)` 经 ClawSentry harness/Gateway 判定后返回 host deny；验证记录见 `docs/validation/codex-gateway-daemon-e2e-smoke-2026-04-21.md`。
- **CODEX_NATIVE_HOOKS doctor 明细输出** — `clawsentry doctor` 现在在 PASS/WARN detail 中逐项显示 managed Codex native hooks 的实际形态，例如 `PreToolUse(Bash): sync`、`PostToolUse(Bash): async`、`UserPromptSubmit: async`、`Stop: async`、`SessionStart(startup|resume): async`。
- **Rules governance CI template actions 升级** — `examples/ci/rules-governance.yml` 已升级到 Node 24-compatible action majors（`checkout@v6`、`setup-python@v6`、`upload-artifact@v6`），并固定 `retention-days: 30`，用于后续同步公开仓库时避开 GitHub Actions Node 20 deprecation 警告并保留规则治理 artifact。
- **Rules governance markdown release dashboard** — `clawsentry rules report` 新增 `--summary-markdown`，可在 JSON report 之外写出人类可读的规则治理 rollout dashboard；CI template 同步上传 `rules-dashboard.md`，便于 release / policy-change review 直接审阅状态、finding 数与 sample event 覆盖。
- **L3 advisory snapshot and review workflow** — 新增 Rank2 frozen evidence snapshot / advisory review 契约：可在 bounded trajectory record range 上创建 `l3_evidence_snapshot`，再附加 `advisory_only=true` 的 `l3_advisory_review`；`CS_L3_ADVISORY_ASYNC_ENABLED=true` 时 high/critical decision 或 high+ trajectory alert 会自动创建 frozen snapshot；report/session/replay payload 与 SSE/watch/UI 类型现在能追溯 snapshot/review ID，同时不改变 canonical decision。
- **L3 advisory review lifecycle** — `l3_advisory_review` 支持 `pending` / `running` / `completed` / `failed` / `degraded` 状态更新，并通过 `PATCH /report/l3-advisory/review/{review_id}` 与 `l3_advisory_review` SSE 暴露 lifecycle 变化，为后续真实 async worker 接入预留稳定契约。
- **L3 deterministic local advisory runner** — 新增 `POST /report/l3-advisory/snapshot/{snapshot_id}/run-local-review`，可显式对 frozen snapshot 运行 deterministic local review，验证 `snapshot -> pending/running/completed review` 全链路；runner 只读取 snapshot record range，不接 LLM、不启动 scheduler、不改变 canonical decision。
- **L3 advisory job queue** — 新增 `l3_advisory_jobs` 与 `POST /report/l3-advisory/snapshot/{snapshot_id}/jobs` / `POST /report/l3-advisory/job/{job_id}/run-local`，使 auto snapshot 后可以只排队 `queued` job，后续由显式调用推进到 `running/completed`，为真实 worker 队列预留契约。
- **L3 advisory worker adapter interface** — 新增 `l3_advisory_worker` adapter 契约与 `fake_llm` dry-run worker，可通过 `POST /report/l3-advisory/job/{job_id}/run-worker` 显式运行，验证 worker 只消费 frozen snapshot records 并写入 review patch；仍不调用真实 LLM、不启动 scheduler。
- **L3 advisory provider safety gates** — 新增 provider-neutral request/response schema、OpenAI / Anthropic provider shell，以及显式 `llm_provider` worker runner；`CS_L3_ADVISORY_PROVIDER_ENABLED=false` 默认关闭真实 provider 路径，`CS_L3_ADVISORY_PROVIDER` / `CS_L3_ADVISORY_MODEL` 不继承同步 `CS_LLM_*` 配置，`CS_L3_ADVISORY_PROVIDER_DRY_RUN=true` 默认保持不联网，未启用、缺 key、缺 model、不支持 provider 或未实现真实调用时统一降级为 `l3_state=degraded`，测试中不发网络请求。
- **L3 advisory provider smoke readiness** — 新增 `clawsentry.devtools.l3_advisory_provider_smoke` 与 `scripts/run_l3_advisory_provider_smoke.py`，可通过显式 env opt-in 构造 frozen snapshot、排队 `llm_provider` job、执行一次手动 smoke 并输出 markdown/JSON 证据；当前 smoke 验证 provider path 安全降级为 `provider_not_implemented`，不启动 scheduler、不联网、不修改 canonical decision。验证记录见 `docs/validation/l3-advisory-provider-smoke-readiness-2026-04-21.md`。
- **L3 full-review Web UI action** — Session Detail 现在提供 `Request L3 full review` 操作按钮，可从 operator console 显式触发 deterministic advisory full review，并显示 review/job 状态；仍保持 advisory-only、不改 canonical decision、不启动 scheduler。
- **L3 full-review CLI surface** — 新增 `clawsentry l3 full-review --session ...`，operator 可从命令行调用 full-review endpoint，支持 `--queue-only`、`--runner deterministic_local|fake_llm|llm_provider`、record range、JSON 输出与 bearer token；默认仍走 deterministic local / no scheduler。
- **Operator-triggered L3 full review** — 新增 `POST /report/session/{session_id}/l3-advisory/full-review`，operator 可显式冻结 session evidence、排队 advisory job，并选择 queue-only 或执行一次 deterministic/fake/provider worker；结果保持 `advisory_only=true`，返回 `canonical_decision_mutated=false`，不启动 scheduler、不做 enforcement。
- **L3 advisory real-provider bridge** — `llm_provider` runner 现在可在 `CS_L3_ADVISORY_PROVIDER_DRY_RUN=false` 且 provider/key/model 都显式配置时桥接到现有 OpenAI / Anthropic LLM provider 抽象；默认仍 dry-run，不进入后台调度，mock-backed 回归覆盖 completed review 解析路径，并兼容 fenced JSON provider responses；真实网络 smoke 仅在 `CS_L3_ADVISORY_RUN_REAL_SMOKE=true` 时运行，否则默认跳过；OpenAI-compatible Kimi 端点已通过 `--require-completed` real smoke。
- **Benchmark wrapper proxy hygiene** — `benchmarks/scripts/skills_safety_bench_codex.sh` 真实执行时默认过滤 proxy env 并使用临时干净 `DOCKER_CONFIG`，避免 Harbor/Docker build 继承宿主不可达代理配置。
- **Rules governance sample events expansion** — `examples/sample-events.jsonl` 现在覆盖 safe-read、credential upload、download-and-execute 三类代表事件，使 rules dry-run/report artifact 更适合作为 rollout smoke。

### 测试与验证

- Python 回归：完整测试 `3020 passed, 4 skipped`
- L3 advisory provider path 聚焦回归：`36 passed, 169 deselected`
- 真实 provider smoke gate：默认 `1 skipped`
- 真实 provider smoke：`openai/kimi-k2.5` 已完成，证据 `docs/validation/l3-advisory-provider-real-smoke-2026-04-21.md`
- `mkdocs build --strict`：PASS

## [0.5.1] — 2026-04-21

### 新增

- **Rules governance reporting artifact** — `clawsentry rules report --output ...` 现在可以把规则治理 `lint` 与可选 `dry-run` 结果合并写入稳定 JSON 工件，提供 `status`、`exit_code`、per-check summary、deterministic fingerprint 与完整 payload，便于 CI / release checklist 保存 rollout 证据。
- **Rules governance CI template** — 新增可同步的 `examples/ci/rules-governance.yml` GitHub Actions 示例，运行 `rules lint` / `rules dry-run` / `rules report` 并上传 `artifacts/rules-report.json`，方便公开仓库启用规则治理 artifact。
- **Codex native hook PreToolUse 防护发布** — `clawsentry init codex --setup` 现在将 `PreToolUse(Bash)` 安装为同步 `clawsentry harness --framework codex` preflight，其他 Codex native events 保持 `--async` 观察；harness 使用 Codex-native normalization，经 Gateway block/defer 后返回已验证的 `permissionDecision: "deny"` 响应，fallback policy 默认 fail-open 并输出诊断。安装/卸载仍保留用户 / OMX hooks，`doctor` 会校验 managed hooks 的 sync/async 形态，并已补充真实 Codex CLI native hook smoke 记录。

## [0.5.0] — 2026-04-20

### 新增

- **AHP v2.3 compatibility support** — ClawSentry 现在可以识别并保留 `post_response`、`idle`、`heartbeat`、`success`、`rate_limit` 等上游 AHP v2.3 observation surfaces，同时保持 `pre_action/post_action/pre_prompt/post_response/error/session` 这 6 类 stable core 不扩枚举。
- **Confirmation bridge** — `confirmation` 事件现在复用现有 operator approval lifecycle：pending / resolve / timeout / no-route / queue-full 均有统一 `approval_*` telemetry，并兼容 `/ahp/resolve` 与既有 DEFER bridge。
- **Context 与 memory analysis-consumption** — `context_perception` 与 `memory_recall` 现在会生成 compact evidence summary，进入 replay、session risk、session list 与 `DecisionContext` / `semantic_analyzer` 的解释性分析路径。
- **Cognition research-to-runtime signals** — `planning`、`reasoning`、`intent_detection` 现在作为 compact runtime evidence 进入 replay、session 视图与语义分析，但不成为新的 blocking surface，也不暴露完整 chain-of-thought。

### 改进

- **能力分层口径完善** — 设计文档现已统一区分 stable core、compatibility support、bridge semantics 与 analysis-consumption，避免把兼容识别误读为 canonical enforcement。
- **Operator-facing evidence 更完整** — replay、session risk 与 session list 现在能展示 approval、context/memory 与 cognition summaries，帮助 operator 理解运行时上下文而不污染 canonical decision 字段。
- **发布目标升级为 0.5.0** — 本版本聚合 AHP v2.3 协议跟进、兼容层、审批桥接与分析消费链路，作为 0.5 系列基线。

### 测试与验证

- Python 回归：完整测试 `2962 passed, 3 skipped`
- AHP v2.3 compatibility / bridge / analysis 聚焦回归：`590 passed`

## [0.4.8] — 2026-04-17

### 修复

- **重新构建并发布实际 shipped 的 Web UI dist** — `src/clawsentry/ui/src` 里的浅色 premium operator console 已重新打包进 `src/clawsentry/ui/dist`，安装后的 `/ui` 不再继续落回旧暗色界面。
- **补齐 Web UI 构建契约测试** — 新增 dist 级别的浅色主题基线校验，防止源码已更新但发布资产仍停在旧 CSS/JS 哈希。
- **补齐公开发布面核对护栏** — release checklist 与 public-doc contract 现在显式核对 PyPI、在线配置页、在线 changelog 与实际安装后的 `/ui`，避免再次出现“文案已更新、安装产物未更新”的漂移。

### 测试与验证

- Python 回归：完整测试 `2891 passed, 3 skipped`
- UI build contract 聚焦回归：`4 passed`
- `npm run build` (`src/clawsentry/ui`)：PASS
- `mkdocs build --strict`：PASS
- `python -m build`：PASS

## [0.4.7] — 2026-04-17

### 改进

- **L3 trigger controls 正式发布** — DetectionConfig 与项目级配置现在公开支持 `l3_routing_mode`、`l3_trigger_profile`、`l3_budget_tuning_enabled` 三个高层控制面，用于在不改变默认行为的前提下，让本地 L3 更容易触发或直接替换 organic L2-entry 路径。
- **`replace_l2` 语义完善为真实路由替换** — 文档与运行态口径现已统一说明：`replace_l2` 不是模糊的 “force L3 follow-up”，而是命中 organic L2 入口后直接跳过 L2、改走本地 L3。
- **无本地 L3 能力时的公开遥测更诚实** — `l3_runtime` 现在补齐稳定 reason code `local_l3_unavailable`，并把 unsupported-local-L3 情况统一完善为 `l3_available=false`、`l3_state=skipped`、`l3_reason_code=local_l3_unavailable`。

### 文档

- **公开文档同步到 L3 trigger design 基线** — GitHub README、包内 README、在线文档的 concepts / detection config / env vars / L3 agent 页面，现已统一解释新的 L3 高层配置面与 unsupported-local-L3 运行态语义。
- **开发入口与内部状态页同步到 `v0.4.7`** — 根 README、PROJECT_STATUS 与 DEVELOPMENT_DYNAMIC_LOG 已更新到当前正式发布口径与完整回归基线。

### 测试与验证

- Python 回归：完整测试 `2888 passed, 3 skipped`
- L3 trigger config 聚焦回归：`5 passed`
- detection / project / trigger / risk 聚焦回归：`609 passed`
- agent / gateway 聚焦回归：`173 passed`
- `mkdocs build --strict`：PASS
- `python -m build`：PASS

## [0.4.6] — 2026-04-17

### 改进

- **Web UI 升级为 light-first premium operator console** — Dashboard、Sessions、Session Detail、Alerts 与 DEFER Panel 现在共享同一套浅色优先、长时间可读、以 operator scanning 为中心的视觉系统；旧版黑白混杂与深色 SOC 残留被整体完善。
- **Dashboard 首页补齐 operator brief** — `Security Console` hero 不再留出大片无信息空白，而是补上 coverage / posture / runtime pulse / budget pulse 四块低噪声摘要，让首页第一屏既完整又不喧宾夺主。
- **空状态、loading 与图表表面完成产品化完善** — `EmptyState`、`SkeletonCard`、图表卡片与 Session Detail tooltip 统一进入新的品牌化系统，去掉默认组件感并保持克制的高级感。

### 文档

- **在线 Web UI 文档同步到新视觉基线** — `site-docs/dashboard/index.md` 与 `site-docs/index.md` 已更新到 light-first operator console 口径，明确 Dashboard 顶部现在包含 operator brief，整体视觉不再描述为暗色 SOC。
- **开发入口与公开 release 文案同步到 `v0.4.6`** — 根 README、公开 README、PROJECT_STATUS 与 DEVELOPMENT_DYNAMIC_LOG 已同步说明这次 Web UI redesign + polish 已进入正式发布基线。

### 测试与验证

- Python 回归：完整测试 `2883 passed, 3 skipped`
- Web UI 回归：`29 passed`
- Web UI 生产构建：PASS
- `mkdocs build --strict`：未在该条目中记录最终结果

## [0.4.5] — 2026-04-15

### 改进

- **Enterprise OS 兼容 reporting facade** — 新增独立的 `enterprise/*` 查询接口层，在不侵入原有判决链和现有 WebUI 的前提下，对外提供企业安全中台可直接消费的健康状态、总体摘要、实时风险概览、会话列表、单会话风险时间线、回放、告警与 SSE 实时流。
- **TrinityGuard 风险映射与实时聚合** — 企业接口返回的 payload 现在附带 TrinityGuard 三层风险分类（tier / subtype），并补充实时风险总量、按风险等级分布、按 TrinityGuard 大类/小类分布等聚合信息，便于企业侧快速搭建定制看板。
- **统一 LLM 配置与 enterprise fallback** — L2、L3 与 enterprise 语义 fallback 现在共用同一套 `CS_LLM_*` 配置解析逻辑，并兼容旧 provider key；当规则映射无法覆盖企业分类时，enterprise 兼容层会按统一配置走 LLM 语义判断并安全降级到 `unmapped`。

### 文档

- **公开文档补齐 enterprise reporting 与统一 LLM 配置说明** — 在线文档、README 与 changelog 已同步说明企业报表接口、TrinityGuard 风险映射，以及统一 `CS_LLM_*` 配置在 L2、L3 和 enterprise fallback 中的复用方式。
- **公开版本口径同步到 `v0.4.5`** — GitHub README、包内 README、在线安装页、首页和 changelog 已统一更新到当前发布版本与测试基线。

### 测试与验证

- Python 回归：完整测试 `2883 passed, 3 skipped`
- enterprise / LLM 配置聚焦回归：`40 passed`
- Reporting 回归子集：`18 passed, 123 deselected`
- `mkdocs build --strict`：PASS

## [0.4.4] — 2026-04-15

### 改进

- **规则治理工具首版** — 新增 `clawsentry rules lint` 与 `clawsentry rules dry-run`，对现有 attack patterns / review skills 做上线前 `schema / duplicate / conflict` 校验，并支持用 sample canonical events 预演当前规则面的命中 pattern 与 skill 选择结果；`rules dry-run` 现在兼容 JSON object / JSON array / JSONL 输入，并把缺失或非法输入收成更清晰的命令级错误码；该能力刻意保持为窄范围治理层，不引入横跨 L1/L2/L3 的运行时 DSL。
- **L3 可观测字段与展示路径对齐** — `l3_state`、`l3_reason_code`、`trigger_detail`、compact `evidence_summary`、`budget_exhaustion_event` 与 `decision_path_io` 的公开说明现已同步到在线文档、包内 README 和 GitHub README，避免公开文档继续停留在早期内部术语。

### 文档

- **在线文档补齐规则治理与 L3 最新公开语义** — 新增规则治理页，CLI 参考现在覆盖 `clawsentry rules`，并补齐 custom skills / attack patterns 的上线前治理流程；L3 审查 Agent、Dashboard、Reporting API 与首页同步更新到当前公开能力口径。

### 测试与验证

- Python 回归：完整测试 `2812 passed, 3 skipped`
- rules / docs / L3 聚焦回归：`100 passed`
- 扩展安全回归：`440 passed`
- `mkdocs build --strict`：PASS

## [0.4.3] — 2026-04-14

### 改进

- **L3 operator telemetry 与 retained-evidence 继续完善** — `l3_state`、`l3_reason_code` 与 compact `evidence_summary` 现在不只停留在单点 trace，而是进一步对齐到 `watch`、Dashboard Runtime Feed、session summary、session risk 以及其他现有 gateway/reporting 路径，便于 operator 在不打开原始轨迹的情况下快速理解 L3 运行态与保留证据。
- **Gateway reporting 与 budget governance 对齐** — `budget` / `budget_exhaustion_event` 现在已扩展到 session/report/replay surfaces；`decision_path_io` 也继续从 `health` / `report_summary` 扩展到 session/report endpoints，使当前同步决策路径的运营读数更完整。
- **共享信号与 bounded evidence collection 继续硬化** — L3/runtime 相关实现继续沿“共享低级信号 + bounded evidence budget + 明确 degraded reason taxonomy”方向完善，在保持同步架构稳定的前提下扩大可解释性与运维可见性。

### 文档

- **公开文档同步到新发布基线** — GitHub README、PyPI README、在线文档安装页、首页与 changelog 已统一刷新到 `v0.4.3`，并更新当前完整测试基线与最新能力摘要。

### 测试与验证

- Python 回归：完整测试 `2795 passed, 3 skipped`
- UI 渲染测试：`5 passed`
- `mkdocs build --strict`：PASS
- UI 生产构建：PASS

## [0.4.2] — 2026-04-11

### 改进

- **L3 Python launcher hardening 完善** — `secret_harvest_archive` 对 bounded `python -c` 命令构造继续收紧并补全，当前已覆盖 `format_map(...)`、named / expanded-keyword `str.format(...)`、`string.Template(...).substitute(...)`、`string.Template(...).safe_substitute(...)` 与 literal `dict(...)` mapping constructor，同时继续保持纯 `print('...')`、本地 restore/inspection 与普通开发打包流负例不触发。
- **从执行 helper 扩展到命令构造 helper** — L3 现在能更稳定识别“先读 secret，再通过 Python 字符串 helper 拼出 zip/tar/export 命令”的路径，而不依赖原始 shell 文本里直接出现完整命令串。

### 文档

- **公开文档统一解释本次能力边界** — GitHub README、PyPI README、在线首页、安装页与 CHANGELOG 已同步到 `v0.4.2`，并把本次变化统一解释为 L3 bounded Python launcher hardening。

### 测试与验证

- Python 回归：完整测试 `2691 passed, 3 skipped`
- `mkdocs build --strict`：PASS
- L3 聚焦回归：`416 passed`
- L3 trigger 单测：`340 passed`

---

## [0.4.1] — 2026-04-11

### 改进

- **L3 基础能力正式完善** — `CS_L3_ENABLED=true` 时的默认 `multi_turn` 语义、显式 `trigger_reason`、基于聚合 L2 结果的 L3 装配、session transcript / risk 证据读取、`suspicious_pattern` 与 `trigger_detail` 观察链路现在已全部进入正式版本。
- **archive/export 边界继续收紧** — `secret_harvest_archive` 现在明确排除普通本地打包、`base64 -d`、extract/restore、archive inspection、zip/gzip validation、以及只是在 shell 文本中提到 archive 命令的负例，同时继续保留真实 shell wrapper 与 bounded `python -c` launcher 下的 archive/export 识别能力。
- **Python launcher helper 覆盖补全** — bounded `python -c` 匹配路径现已覆盖 `subprocess.run/call/Popen/check_call/check_output/getoutput/getstatusoutput`、`os.system/popen`、`os.execl/execlp/execv/execve/execvp/execvpe`、`os.spawnl/spawnlp/spawnv/spawnve/spawnvp/spawnvpe` 等常见执行 helper，同时保持纯 `print('...')` 文本负例不触发。

### 文档

- **公开发布口径同步** — 包内 README、在线安装页、首页与 CHANGELOG 已统一更新到 `v0.4.1` 和当前完整回归基线。

### 测试与验证

- Python 回归：完整测试 `2464 passed, 3 skipped`
- `mkdocs build --strict`：PASS
- L3 聚焦回归：`249 passed`
- L3 trigger 单测：`113 passed`

---

## [0.4.0] — 2026-04-10

### 改进

- **审计整改主线完善** — 统一 `Alerts` severity taxonomy，`watch --interactive` 真正接入 DEFER resolve 流程，L3 提升为可观测的一等决策层，RuntimeFeed 新增过滤 / 高优先级视图 / 暂停与 backlog 提示，跨框架兼容矩阵与浏览器级验证夹具一并落地。
- **多框架自检与启动体验增强** — `clawsentry integrations status` 新增 `framework_readiness`，按框架输出 `status / summary / checks / warnings / next_step`；`clawsentry start` 与 `start --with-latch` 复用同一份 readiness 诊断，在 banner 中直接提示 `a3s-code` 显式 SDK wiring、`codex` watcher/session dir、`claude-code` hooks、`openclaw` 宿主配置缺口。
- **Latch 集成产品化完善** — 修复 `start --with-latch --no-watch` 生命周期、将 `latch install` tar 解压改为兼容 Python 3.11 的安全实现，并让 `--with-latch` 的 `Web UI` / `--open-browser` 统一跳转到 Hub UI。

### 文档

- **公开文档与 README 对齐新语义** — Quickstart、CLI 参考、OpenClaw 集成页、GitHub README 与包内 README 全部更新到 readiness 诊断、多框架 start banner 和当前测试基线；包内 README 顶部 Python 版本口径同步为 `3.11+`。
- **新增正式审计与验证记录** — 仓库内补齐实现审计、整改方案、兼容矩阵、浏览器验证、Latch focused validation 与 rollout readiness 文档，形成本次 0.4.0 完善证据链。

### 测试与验证

- Python 回归：完整测试 `2331 passed, 3 skipped`
- `mkdocs build --strict`：PASS
- start/integrations 聚焦回归：`65 passed`

## [0.3.9] — 2026-04-09

### 修复

- **`clawsentry test-llm` 兼容当前 L2/L3 结果结构** — `_format_analysis_detail()` 统一兼容 `target_level` / `reasons` / `reason` 字段，L2/L3 探针不再依赖旧结果形状，输出细节与当前分析器实现一致。
- **L3 手动升级在无 trajectory store 时仍可执行** — `ReadOnlyToolkit.read_trajectory()` 在未注入 trajectory store 时返回空列表；手动触发的 L3 探针现在会真正执行，而不是因工具集缺少轨迹存储提前降级。

### 测试

- **补充回归覆盖** — 新增 `test_l3_manual_trigger_works_without_toolkit_trajectory_store`，以及 `test-llm` 的 L2/L3 probe 结果格式与触发失败回归测试。
- **公开文档测试数字对齐** — README、包内 README、安装页与首页测试数字更新到当前完整套件结果。

### 验证

- Python 回归：完整测试 `2298 passed, 3 skipped`
- `mkdocs build --strict`：PASS
- Web UI 生产构建：PASS

---

## [0.3.8] — 2026-04-09

### 改进

- **Web UI 升级为 Security Console** — Dashboard / Sessions / Session Detail 重新围绕 `framework -> workspace -> session` 三层信息组织，支持在单一监控视图中区分同一框架下的多个工作空间与多个 session，也能同时查看多框架并行运行时的风险态势。
- **会话报表补充工作空间上下文** — `/report/sessions` 与 `/report/session/{id}/risk` 现在暴露 `workspace_root`、`transcript_path`、`agent_id`、`source_framework`、`caller_adapter` 等字段，Web UI 与 API 使用者都可以直接定位“哪个框架、哪个工作空间、哪个 session”。
- **会话详情可读性增强** — 会话详情页明确展示 workspace、transcript、风险构成、时间线与 replay，减少仅凭 session_id 理解上下文的成本。

### 文档

- **在线文档重写 Web UI 说明** — `site-docs/dashboard/index.md` 现在先解释 Web UI 的使用模型，再解释页面职责，明确 Dashboard / Sessions / Session Detail / Alerts / DEFER Panel 各自回答什么问题。
- **快速开始补充 Web UI 导读** — `site-docs/getting-started/quickstart.md` 新增“第一次打开 Web UI 先看什么”的说明，帮助用户用正确的视角理解监控台。
- **报表 API 文档对齐新字段** — `site-docs/api/reporting.md` 更新会话列表与会话风险详情的响应示例，补充 `workspace_root` / `transcript_path` 等字段说明。
- **进度文档同步完善** — 内部进度记录已更新为包含本次 Web UI 重构、浏览器验收与后续发布建议。

### 验证

- Python 回归：完整测试 `2295 passed, 3 skipped`；Web UI 相关回归 `126 passed`
- Web UI 生产构建：PASS
- `mkdocs build --strict`：PASS
- 实际浏览器验收：PASS（本地 `/ui?token=...`，覆盖 Dashboard / Sessions / Session Detail / 实时 feed / mobile viewport）

---

## [0.3.7] — 2026-04-08

### 改进

- **OpenClaw setup 改为显式 opt-in** — `clawsentry init openclaw` 和 `clawsentry start --framework openclaw` 默认只写项目 `.env.clawsentry`，不再修改 `~/.openclaw/`；需要修改 OpenClaw 侧配置时可显式使用 `clawsentry init openclaw --setup`，或在一键启动路径中传入 `clawsentry start --setup-openclaw`。
- **多框架启动入口** — 新增 `clawsentry start --frameworks a3s-code,codex,openclaw`，按列表增量初始化 `.env.clawsentry` 并在启动 banner 中展示启用框架。
- **集成状态检查** — 新增 `clawsentry integrations status [--json]`，用于查看当前项目启用框架、Codex watcher、OpenClaw env、OpenClaw `.bak` 恢复可用性、Claude hooks 来源文件、Codex session dir 可达性和 a3s transport env 状态。

### 测试

- 新增 OpenClaw setup 默认无副作用、多框架 start、integrations status 回归覆盖。
- 代码审查后补充 integrations status 误报、无效 `CS_ENABLED_FRAMEWORKS`、Latch 多框架 banner 回归覆盖。
- 测试套件：2263 passed, 3 skipped (~34s)

---

## [0.3.6] — 2026-04-08

### 改进

- **CLI 启动提示收敛** — `clawsentry start` 现在只在真正自动检测框架时显示 `(auto-detected)`，显式 `--framework` 不再误导用户。
- **Codex 启动路径补齐** — `detect_framework()` 支持从 Codex session 目录识别 `codex`，`clawsentry init codex` 写入 `CS_CODEX_WATCH_ENABLED=true`，确保未显式设置 `CS_CODEX_SESSION_DIR` 时 Gateway 仍可按配置自动探测。
- **后台 Gateway 管理提示** — `clawsentry start --no-watch` 返回后提示使用 `clawsentry stop` 停止后台进程，避免继续提示已不可用的 Ctrl+C 停止方式。

### 文档

- **在线文档审阅修正** — 快速开始、Codex 集成、Claude Code 集成、CLI 参考和首页与当前实现对齐：Codex 标注为 session 日志监控而非自动拦截，a3s-code 标注为显式 SDK Transport，健康检查示例改为 `status=healthy`，速率限制变量统一为 `CS_RATE_LIMIT_PER_MINUTE`。
- **CLI 参考修正** — 更新 `start` 输出示例、Gateway 日志路径、harness 默认 deadline、fallback 行为和 `.clawsentry.toml` `[project]` 表名。

### 测试

- 新增 CLI/Codex 初始化回归覆盖。
- 测试套件：2234 passed, 3 skipped (~33s)

---

## [0.3.5] — 2026-04-08

### 修复

- **a3s-code 接入边界修正** — `clawsentry init a3s-code` 不再生成或复用 `.a3s-code/settings.json`，仅生成 `.env.clawsentry`，并引导用户使用显式 SDK Transport（`SessionOptions().ahp_transport`）。
- **a3s/source_framework 兼容性** — 扩展 `source_framework` 适配器别名（含 `.v1` 变体），并为 `/ahp/a3s` 增加 10MB 请求体大小保护（超限返回 413）。
- **框架自动检测收敛** — `detect_framework` 优先使用显式 `CS_FRAMEWORK`；`.a3s-code/settings.json` 仅作为旧版项目兼容标记，不再作为受支持的 AHP 配置入口。

### 文档与发布流程

- **双仓库发布边界修正** — `sync-to-public` 明确不再同步 `.github/workflows`，由公开仓库独立维护。
- **a3s 集成文档对齐实现** — 更新 token 传递、fallback 语义、deadline 默认值、限流变量与 health 示例响应。

### 测试

- 新增/增强 a3s 相关回归测试（init 不创建 settings、source_framework 别名、`/ahp/a3s` 认证与 payload 限制）
- 测试套件：2224 passed, 2 skipped (~34s)

---

## [0.3.4] — 2026-04-08

### 变更（Breaking）

- **Codex watcher 改为 opt-in** — `_detect_codex_session_dir()` 不再默认自动探测 Codex 会话目录；必须显式设置 `CS_CODEX_WATCH_ENABLED=true`（或 `1`/`yes`）才会启用自动探测。直接设置 `CS_CODEX_SESSION_DIR` 仍然生效。
- **a3s-code 集成方式更新** — `clawsentry init a3s-code` 输出的 next_steps 不再建议 "settings.json auto-loaded"，改为显示 SDK Transport 显式接入代码（`HttpTransport` + `SessionOptions`），与 a3s-code 最新 API 对齐。

### 修复

- **[CS-024]** `clawsentry watch` 加入已有会话时显示 "Framework: unknown" — 连接时预取 `/report/sessions` 已有会话信息
- **[CS-022/CS-026]** Web UI Sessions 页面 15s 轮询延迟过高 — 改用 SSE 实时推送（`createManagedSSE`），500ms 防抖，30s fallback 轮询兜底
- **`test-llm` L2/L3 调用签名修复** — `analyzer.analyze()` 和 `agent.analyze()` 新增缺失的第二参数（`None`），修复 `TypeError`
- **`watch` 时间戳本地化** — `_timestamp_hms()` 从 UTC 改为本地时区显示

### 改进

- **`clawsentry start` 静默初始化** — `ensure_init()` 使用 `quiet=True`，自动初始化时只输出一行确认而非完整 banner

### 文档

- 集成指南新增 `test-llm` CLI 使用说明
- a3s-code 集成文档新增 SDK Transport 接入方式（`HttpTransport` + `SessionOptions`）

### 测试

- 新增 `test_disabled_by_default` — 验证 Codex watcher 默认关闭行为
- 测试套件：2201 passed, 2 skipped (~33s)

---

## [0.3.3] — 2026-04-07

### 新增

- **`clawsentry test-llm` 命令**：LLM API 连通性和功能测试，支持 API 可达性、单次延迟、L2 语义分析、L3 Agent 审查四项测试，支持 `--json` 输出
- **`clawsentry service` 命令**：一键安装/卸载系统自启服务，Linux 支持 systemd user service，macOS 支持 launchd user agent
- **Web UI SSE 连接增强**：新增 `createManagedSSE()` 管理式连接，支持自动重连（指数退避）、连接状态指示器（connected/reconnecting/error）

### 修复

- **Web UI 事件不显示**：SSE 连接失败时静默失败，现在显示连接状态和错误信息，帮助用户排查问题

### 测试

- 新增 30 个测试（test-llm 19 + service 11）
- 测试套件：2200 passed, 2 skipped (~33s)

---

## [0.3.2] — 2026-04-01

### 新增

- **Windows 平台支持**：UDS 服务器和客户端适配器在 Windows 上自动降级到 HTTP-only 模式，避免 `asyncio.start_unix_server` 不可用错误
- 新增 2 个 Windows 兼容性测试（`test_windows_compatibility.py`）

### 修复

- **Windows 编码支持**：所有文件 I/O 操作显式指定 UTF-8 编码，修复 Windows 系统 GBK 默认编码导致的 `attack_patterns.yaml` 加载失败问题
- Gateway 在 Windows 上启动时日志显示 `uds=disabled(Windows)` 而非崩溃
- 适配器在 Windows 上自动使用本地 fallback 决策，保证基本安全监督功能

### 文档

- 新增 `docs/deployment/WINDOWS_DEPLOYMENT.md` — Windows 部署指南，包含路径配置、编码问题、环境变量设置等

### 测试

- 测试套件：2171 passed, 1 skipped (~33s)

---

## [0.3.1] — 2026-03-31

### 修复

#### P0+P1 审查修复（9 commits, +25 tests）

- **Hub Bridge 异步化 (P0-1)**：`LatchHubBridge._hub_request` 从同步 `urllib.request` 改为 `run_in_executor`，不再阻塞 Gateway 事件循环
- **server.py 拆分 (P0-2)**：提取 `TrajectoryStore` / `SessionRegistry` / `EventBus` / `AlertRegistry` 为独立模块，server.py 从 2580→1734 行
- **文档修正 (P0-3)**：修复 `site-docs/` 中 6 项文档-代码不一致 — `AHP_LLM_*` → `CS_LLM_*`、`settings.local.json` → `settings.json`、`watch --port` → `--gateway-url`、`gateway --setup` → `init openclaw --setup`、`.env` → `.env.clawsentry`、FAQ 保留期 7→30 天
- **L2→L3 递进分析 (P1-1)**：`CompositeAnalyzer` 改为顺序执行 — L2 先行，仅当 L2 信心 < 0.8 或风险 < HIGH 时触发 L3，节省不必要的 LLM 调用
- **Post-action 异步 (P1-2)**：后置分析改为 `asyncio.create_task` fire-and-forget，不阻塞请求返回
- **L2 线程池共享 (P1-3)**：`L1PolicyEngine` 共享 `ThreadPoolExecutor(max_workers=2)`，不再每次 L2 分析创建新线程池
- **Regex 转义重写 (P1-4)**：`_sanitize_for_regex` 改用 marker-based 方法，先替换为占位符→ re.escape 全文→恢复 regex 片段，修复原逻辑 regex 损坏问题
- **DEFER 队列上限 (P1-5)**：`DeferManager` 新增 `max_pending` 参数（默认 100），队列满时拒绝新 DEFER 并回退为 BLOCK，防止无限堆积
- **Hub Bridge 初始化修复 (P1-6)**：`LatchHubBridge.__init__` 正确初始化 `_sub_id` / `_source_queue`，移除未使用的 `_queue` 属性

### 测试覆盖

- 测试总量：2144 → 2169（+25 tests, 0 regressions）

---

## [0.3.0] — 2026-03-31

### 新增

#### Prometheus 可观测性

- **`/metrics` 端点**：Prometheus 格式的指标暴露端点，包含 8 个核心指标：决策计数 (`clawsentry_decisions_total`)、决策延迟 (`clawsentry_decision_latency_seconds`)、风险评分分布 (`clawsentry_risk_score`)、活跃会话 (`clawsentry_active_sessions`)、LLM 调用计数 (`clawsentry_llm_calls_total`)、LLM Token 用量 (`clawsentry_llm_tokens_total`)、LLM 成本估算 (`clawsentry_llm_cost_usd_total`)、DEFER 待处理数 (`clawsentry_defers_pending`)
- **No-op 降级**：`prometheus_client` 为可选依赖 (`pip install clawsentry[metrics]`)，未安装时所有指标操作静默退化为 no-op，零强制依赖
- **`CS_METRICS_AUTH`**：可选启用 `/metrics` 端点的 Bearer token 认证（默认无认证，与 `/health` 同级）

#### LLM 成本追踪

- **`InstrumentedProvider` 包装器**：透明包装 `AnthropicProvider` / `OpenAIProvider`，自动提取每次调用的 token 用量并上报 Prometheus 指标，LLMProvider Protocol 签名完全不变
- **`LLMUsage` dataclass**：`input_tokens` / `output_tokens` / `provider` / `model` 四字段，每次 SDK 调用后存入 provider 的 `_last_usage` 属性
- **成本估算**：基于硬编码参考价格（Anthropic $3/$15, OpenAI $2.5/$10 per M tokens）自动估算并累加到 `clawsentry_llm_cost_usd_total`

#### LLM 每日预算控制

- **`CS_LLM_DAILY_BUDGET_USD`**：设置每日 LLM 花费上限（默认 0 = 不限），超出后自动将 L2/L3 请求降级为 L1-only，decision reason 附加 `[LLM budget exhausted, L1-only]`
- **`LLMBudgetTracker`**：线程安全（`threading.Lock`）的日预算追踪器，UTC 日期自动翻转，首次超预算时广播 SSE 事件

#### 生产部署

- **systemd 服务模板**：`systemd/clawsentry-gateway.service`，含安全加固（NoNewPrivileges / ProtectSystem=strict / ProtectHome / PrivateTmp）
- **Docker Compose 可观测性栈**：Gateway + Prometheus + Grafana 三服务编排，Grafana 数据源自动配置，PromQL 查询参考文档
- **Docker 镜像默认含 Prometheus**：Dockerfile 改为安装 `".[metrics]"`

#### 安装途径

- **Homebrew tap 更新**（实验性）：formula 骨架更新至 v0.3.0，添加 `head` 选项
- **uv tool install**：验证并文档化 `uv tool install clawsentry` 安装路径

### 改进

- Docker Compose 格式升级至 Compose V2（移除已废弃的 `version` 键）
- `[metrics]` 可选依赖组加入 `pyproject.toml`，`[all]` 组包含 metrics
- 安装文档新增 Prometheus 可观测性标签页 + 依赖组表更新
- Homebrew 状态从「建设中」改为「实验性」

### 配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_METRICS_AUTH` | `false` | 启用 `/metrics` 端点认证 |
| `CS_LLM_DAILY_BUDGET_USD` | `0` | 每日 LLM 预算（0=不限） |
| `CS_PROMETHEUS_PORT` | `9090` | Docker Compose Prometheus 端口 |
| `CS_GRAFANA_PORT` | `3000` | Docker Compose Grafana 端口 |
| `CS_GRAFANA_PASSWORD` | `clawsentry` | Grafana admin 密码 |

### 测试覆盖

- 测试总量：2042 → 2144（+102 tests, 0 regressions）
- 新增：test_metrics.py (23) / test_instrumented_provider.py (26) / test_budget_tracker.py (21) + P2 Mobile UI 32 tests (previously unreleased)

---

## [0.2.9] — 2026-03-30

### 新增

#### DEFER → Operator 审批桥接（P1）

- **DEFER Bridge**：Gateway 的 DEFER 决策现在支持等待操作员实时审批，而非立即返回。当 `defer_bridge_enabled=true`（默认）且事件类型为 `PRE_ACTION` 时，Gateway 会注册一个 `cs-defer-*` 审批 ID、广播 `defer_pending` SSE 事件，并阻塞等待操作员通过 `/ahp/resolve` 端点做出 allow/deny 决定
- **`DecisionSource.OPERATOR`**：新增决策来源枚举值，标记由操作员审批产生的决策（区分于 `POLICY`/`MANUAL`/`SYSTEM`）
- **`/ahp/resolve` DeferManager 支持**：resolve 端点现在优先检查 DeferManager 中的待处理请求（`cs-defer-*` ID），若匹配则直接解决；否则 fallback 到 OpenClaw approval_client，保持向后兼容
- **`defer_pending` / `defer_resolved` SSE 事件**：新增两种 SSE 事件类型，EventBus 默认订阅，Watch CLI 和 Hub 均可接收

#### Latch Hub 事件转发

- **`LatchHubBridge`**：新模块 (`latch/hub_bridge.py`)，订阅 Gateway EventBus 并将事件转发到 Latch Hub CLI session API（`POST /cli/sessions` + `POST /cli/sessions/:id/messages`），支持自动创建 Hub session、HTTP 重试、人类可读消息格式化
- **自动启动**：当 `CS_LATCH_HUB_URL` 或 `CS_LATCH_HUB_PORT` 配置时，`run_stack()` 自动启动 Hub bridge 后台任务

#### Watch CLI 增强

- **DEFER 事件格式化**：`clawsentry watch` 现在显示黄色 `DEFER PENDING`（含工具名、命令、超时、审批 ID）和绿色/红色 `DEFER RESOLVED: ALLOW/BLOCK` 事件

#### Doctor 扩展

- **19 项检查**（从 17 项增加）：新增 `DEFER_BRIDGE`（验证 DEFER 桥接配置）和 `HUB_BRIDGE`（验证 Hub 可达性）两项健康检查

### 配置

- **`CS_DEFER_BRIDGE_ENABLED`**（bool, 默认 `true`）：DEFER 桥接开关，`low` 预设默认关闭
- **`CS_LATCH_HUB_URL`**（string, 默认空）：Hub 基础 URL，设置后启用事件转发
- **`CS_HUB_BRIDGE_ENABLED`**（`auto`/`true`/`false`, 默认 `auto`）：Hub 事件桥接模式
- **`CS_LATCH_HUB_PORT`**（int, 默认 `3006`）：Hub 端口（URL 未设时 fallback）

### 测试覆盖

- 测试总量：1970 → 2042（+72 tests, 0 regressions）

---

## [0.2.8] — 2026-03-30

### 新增

#### 项目级安全配置（E-10）

- **`.clawsentry.toml` 项目配置**：在项目根目录放置 `.clawsentry.toml` 即可自定义安全审核强度，harness 自动读取（60s TTL 缓存），支持 `enabled` 开关和 `preset` 预设等级
- **4 个安全预设等级**：`low`（个人项目/学习）、`medium`（默认/日常开发）、`high`（团队/敏感项目）、`strict`（CI/安全审计），每个预设映射到不同的 `DetectionConfig` 阈值组合
- **`clawsentry config` CLI 命令组**：`config init [--preset]` / `config show` / `config set <preset>` / `config disable` / `config enable`，快速管理项目级配置
- **Gateway per-request 预设应用**：harness 通过 `_clawsentry_meta` 将项目预设信息传递到 Gateway，Gateway 的 `L1PolicyEngine.evaluate()` 支持 `config` 覆盖参数，实现每请求独立的检测配置
- **`clawsentry stop` / `clawsentry status`**：PID 文件管理，一键停止/查询 Gateway 状态
- **`clawsentry start --open-browser`**：启动后自动打开 Web UI

#### Codex 会话监视器

- **Codex 会话监视器**：零侵入实时监控 Codex session JSONL 日志，自动发现 `$CODEX_HOME/sessions/` 下活跃 session 文件，tail 新行 → CodexAdapter 归一化 → Gateway 评估 → SSE 广播
- **`CS_CODEX_WATCH_POLL_INTERVAL` / `CS_CODEX_WATCH_ENABLED`**：可调 watcher 行为的环境变量

### 修复

- **`detect_framework` 检测失败**：修复只检查 `settings.local.json` 的 bug，现在同时检查 `settings.json` 和 `settings.local.json`
- **Claude Code hooks 目标文件**：`clawsentry init claude-code` 改为写入 `~/.claude/settings.json`（而非 `settings.local.json`），避免被项目级配置覆盖
- **Gateway 不可达时阻断所有工具**：当 Gateway UDS 不可达时，harness 的 fallback 决策现在 fail-open（允许），而非 fail-closed 阻断所有 Claude Code 工具调用
- **`--uninstall` 清理遗留**：uninstall 现在同时清理 `settings.json` 和 `settings.local.json` 中的 hooks

### 改进

- **`clawsentry init codex` 更新**：自动检测 Codex session 目录并配置 `CS_CODEX_SESSION_DIR`
- **quickstart.md 重构**：四框架集成路径 + 框架能力对比表 + 项目级配置文档 + uv/Homebrew 安装方式
- **installation.md 更新**：新增 `uv tool install` 和 Homebrew tap 安装标签页，更新 CLI 命令一览表
- **Homebrew formula 骨架**：`homebrew/clawsentry.rb` 模板（待创建 tap 仓库后激活）
- **Harness 诊断日志**：`CS_HARNESS_DIAG_LOG` 环境变量支持

### 测试覆盖

- 测试总量：1760 → 1893（+133 tests, 0 regressions）

---

## [0.2.7] — 2026-03-29

### 修复

#### 安全修复（4 P0）

- **ReDoS 正则退化**：`post_action_analyzer` 中 var-expansion 检测正则含嵌套量词，拆分为两个非嵌套简单模式
- **`--async` 模式 event loop 泄漏**：harness 每条消息创建新 event loop，改为持久 loop + finally 清理
- **异常静默吞没**：`server.py` 策略引擎强制执行路径 bare `except` 未记录异常，补充 `logger.exception()`
- **私有属性直接访问**：`PatternEvolutionManager._enabled` 未暴露公共接口，新增 `@property enabled`

#### 重要修复（11 P1）

- **curl 白名单绕过**：不可见 Unicode 字符可绕过 curl-pipe-shell 安全白名单，改为 raw + normalized 双重检查
- **combining diacritics 绕过**：NFD 组合变音符可避开英文注入模式匹配，新增 Mn 类别字符剥离（保留 U+FE0F emoji VS-16）
- **Codex 端点 fail-open**：Codex HTTP 端点异常时 fallback 为 "continue"（放行），改为 fail-closed "block"
- **Claude Code hooks 覆盖**：`_merge_settings` 直接覆盖已有 hooks，改为追加模式 + 防御性 JSON 解析
- **内存无限增长**：`risk_snapshot` 使用 `list.pop(0)` O(n) 操作且无上限，改为 `deque.popleft()` + 驱逐机制 + `_MAX_CLIENTS`
- **OpenClaw 缺少 content_origin**：OpenClaw normalizer 未注入 `_clawsentry_meta.content_origin`，补充 `infer_content_origin` 调用
- **秘密检测误报**：`pwd` 命令匹配 password 模式、`sk-` / `Bearer` token 模式重复计数，清理去重
- **doctor 弱 token 检测**：新增 `check_auth_weak_value`（14 项检查），检测 "changeme" 等已知弱 token
- **正则+import 修复**：`_BASH_EXTERNAL_RE` 错误匹配、`audit_command` 使用 `__import__`、`--stats --format json` 不支持
- **start 命令硬编码**：框架选项列表硬编码，改为动态读取 `FRAMEWORK_INITIALIZERS.keys()`
- **listen_address 判断风格**：多个 `or` 比较改为 `set` 成员检查

### 改进

- **event_id 生成统一**：提取 `adapters/event_id.py` 共享模块，消除 a3s_adapter / codex_adapter / openclaw_normalizer 三处重复
- **测试基础设施**：新增 `conftest.py` 共享 fixtures（`StubTrajectoryStore` / `skills_dir`），`review_toolkit` 测试 3→31 全方法覆盖
- **test_gateway.py**：消除 `__import__('collections')` 反模式

### 测试覆盖
- 测试总量：1760 → 1792（+32 tests, 0 regressions）

---

## [0.2.6] — 2026-03-29

### 新增

#### 高价值功能（E-8，5 Features）

- **`clawsentry doctor` CLI 命令**：离线配置安全审计，12 项检查（AUTH token 强度/Shannon 熵/UDS 权限/阈值排序/权重边界/LLM 配置/OpenClaw secret/监听地址/白名单正则/L2 预算/数据库路径），输出 PASS/WARN/FAIL 报告，支持 `--json` / `--no-color`，exit code 语义化（0=全 PASS, 1=有 FAIL, 2=仅 WARN）
- **`clawsentry audit` CLI 命令**：离线审计日志查询，只读打开 SQLite trajectory 数据库，支持多维过滤（`--session` / `--since` / `--risk` / `--decision` / `--tool`），三种输出格式（`--format table|json|csv`），`--stats` 聚合统计模式（按风险等级/判决/框架/Top Sessions），参数化 SQL 防注入
- **外部内容安全标记**：自动推断工具调用的内容来源（`external` / `user` / `unknown`），外部内容触发 D6 评分加成（默认 +0.3，`CS_EXTERNAL_CONTENT_D6_BOOST`）和 Post-action 乘数（默认 ×1.3，`CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER`），完全向后兼容
- **D4 工具频率异常检测**：三层滑动窗口速率追踪——突发检测（同工具 ≥10 次/5s → D4=2）、重复滥用（同工具 ≥20 次/60s → D4=1）、整体速率（全工具 ≥60 次/min → D4=1），合并逻辑 `d4 = min(max(accum, freq), 2)`，6 个新 `CS_D4_FREQ_*` 环境变量
- **Docker 生产部署**：多阶段 Dockerfile（python:3.12-slim，非 root 用户 `clawsentry`，healthcheck），docker-compose.yml（SQLite volume + env_file + healthcheck），`.env.example` 模板

#### 新增环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_EXTERNAL_CONTENT_D6_BOOST` | `0.3` | 外部内容 D6 加成 |
| `CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER` | `1.3` | 外部内容 Post-action 乘数 |
| `CS_D4_FREQ_ENABLED` | `true` | 启用频率异常检测 |
| `CS_D4_FREQ_BURST_COUNT` | `10` | 突发检测阈值 |
| `CS_D4_FREQ_BURST_WINDOW_S` | `5.0` | 突发检测窗口（秒） |
| `CS_D4_FREQ_REPETITIVE_COUNT` | `20` | 重复滥用阈值 |
| `CS_D4_FREQ_REPETITIVE_WINDOW_S` | `60.0` | 重复滥用窗口（秒） |
| `CS_D4_FREQ_RATE_LIMIT_PER_MIN` | `60` | 整体速率限制 |

#### Claude Code 独立接入（E-9 Phase 1）

- **`clawsentry init claude-code`**：一键生成 `.env.clawsentry` + 智能合并 `~/.claude/settings.local.json` hooks（PreToolUse 阻塞 + PostToolUse/SessionStart/SessionEnd 异步）
- **Harness 双格式自动检测**：JSON-RPC 2.0（a3s-code）+ 原生 hook JSON（Claude Code）自动识别分流
- **`--async` 模式**：非阻塞 hook（PostToolUse/SessionStart 等）后台 dispatch，不阻塞 Agent 主流程
- **Adapter `source_framework` 可配置**：`A3SCodeAdapter(source_framework="claude-code")` 在审计日志中区分不同框架
- **DEFER 超时配置**：`CS_DEFER_TIMEOUT_ACTION`（block/allow）+ `CS_DEFER_TIMEOUT_S`（默认 300s）
- **`--uninstall`**：精确移除 ClawSentry hooks，保留用户其他自定义 hooks

#### Codex 独立接入（E-9 Phase 2）

- **`POST /ahp/codex` HTTP 端点**：简化 JSON 请求格式（hook_type + payload），自动归一化为 CanonicalEvent
- **`CodexAdapter`**：支持 4 种事件类型（function_call → pre_action / function_call_output → post_action / session_meta → session / session_end → session）
- **`clawsentry init codex`**：生成 `.env.clawsentry`（含 `CS_HTTP_PORT`、`CS_AUTH_TOKEN`、`CS_FRAMEWORK=codex`）
- **`clawsentry doctor` Codex 检查**：自动检测 Codex 配置完整性（endpoint URL + auth token）
- **Fail-closed 安全默认**：Codex 端点异常时 fallback 为 block（非 continue）

#### 新增环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_DEFER_TIMEOUT_ACTION` | `block` | DEFER 超时行为（block / allow） |
| `CS_DEFER_TIMEOUT_S` | `300` | DEFER 超时秒数 |

### 测试覆盖
- 测试总量：1483 → 1760（+277 tests, 0 regressions）
- E-8 新增：test_doctor_command.py (61) / test_audit_command.py (40) / test_content_origin.py (43) / test_d4_frequency.py (25) / test_docker.py (11)
- E-9 新增：test_claude_code_e2e.py (5) / test_claude_code_initializer.py (12) / test_codex_adapter.py (13) / test_codex_http.py (7) / test_codex_e2e.py (8) / test_codex_initializer.py (8) / test_codex_doctor.py (5) / test_defer_manager.py (5) / test_harness_async.py (17) / test_harness_claude_code_format.py (17)

---

## [0.2.5] — 2026-03-29

### 新增

#### 安全检测能力增强（E-7 Hardening）

- **Unicode 归一化层** (`text_utils.py` 新模块)：393 个不可见 Unicode 码点检测 + NFKC 归一化 + 不可见字符计数，排除 U+FE0F 避免 emoji 误报
- **中文注入检测**：D6 `injection_detector.py` 新增 22 条中文注入模式（6 类：忽略/覆盖/新指令/时间锚定/安全绕过/角色扮演/系统标记/混合中英）
- **混淆检测扩充**：`post_action_analyzer.py` 4→13 模式（base64-pipe/hex-pipe/printf-pipe/eval-decode/curl-pipe/process-sub/heredoc/octal/hex-escape/script-exec/var-expansion/reverse-slice/hex-char）+ curl-pipe-shell 安全域名白名单
- **秘密泄露检测扩充**：新增 OpenAI/GitHub/AWS/Slack/Feishu/Bearer/ETH 7 种 secret 模式（含上下文约束避免误报）
- **危险工具扩充**：`risk_snapshot.py` DANGEROUS_TOOLS 9→56（跨平台：shells/execution/privilege/file-ops/process/macOS/Windows/network/persistence），D3 模式 10→25
- **ReDoS 安全正则编译** (`safe_regex.py` 新模块)：嵌套量词检测（含交替分支）+ `compile_safe_regex()` 门控
- **NFKC 穿透**：`injection_detector` + `post_action_analyzer` 全部检测函数先归一化再匹配

### 修复

#### 审查修复（3-agent Sonnet review → 4 P0 + 17 P1）
- **[P0]** `pattern_matcher.py`：移除 `_detection_match` 中 unsafe `re.search` fallback + `_eval_single_trigger` 中 `elif` 原始正则分支
- **[P0]** `injection_detector.py`：`must/should.*now` 换行绕过修复（`.*` → `[^\n]*`）
- **[P0]** `safe_regex.py`：`[]]` 字符类解析修复（首字符 `]` 不再提前终止解析）
- **[P1]** `injection_detector.py`：`[系统...]` 强模式收紧（需 `提示/指令/命令/消息` 关键词），`data:base64` 限界 `{0,2048}`，新增 `无视` 弱模式，混合模式扩展 `忘记/抛弃`
- **[P1]** `post_action_analyzer.py`：`detect_exfiltration` NFKC 归一化，`_is_safe_curl_pipe` 使用归一化文本，`sk-` 模式添加上下文约束，`var-expansion` 收紧需执行指示符，移除 `ghp_` 重复模式
- **[P1]** `risk_snapshot.py`：`DANGEROUS_TOOLS` 同步到 `_score_d1`（扩展工具 D1=3），`dd` 需设备目标（`of=/dev/`），删除过宽 `rm -f /var/log/` 模式，`iptables` 移除 `-Z`（计数器重置非危险）
- **[P1]** `text_utils` 测试精确化：393 精确计数断言 + 空字符串边界测试
- **[P1]** `pattern_matcher.py`：trigger 编译添加 `DOTALL` 与 detection 一致

### 测试覆盖
- 测试总量：1304 → 1483（+179 tests, 0 regressions）
- 14 commits（8 E-7 hardening + 6 review fixes）

---

## [0.2.4] — 2026-03-26

### 修复

#### Issue Batch 2026-03-26-3（013~018, 6 Issues + L3 增强）
- **[Issue 013]** `clawsentry watch` 无 decision 事件 — SSE 广播移到 deadline 检查之前
- **[Issue 014]** `/ahp/resolve` WS 不可用返回 502 而非 503 — 修正 `stack.py` status_code
- **[Issue 015]** L3 trace 未持久化 — 三层修复：CompositeAnalyzer 保留降级 trace / AgentAnalyzer 接入 trajectory_store 累积触发 / inner budget margin 防止外层 timeout 取消 trace
- **[Issue 016]** `/report/stream` 无事件 — 同 Issue 013 根因，同一修复
- **[Issue 017]** 轨迹告警缺失 — EventBus 新增 50 条 replay buffer
- **[Issue 018]** `pattern_evolved` 无事件 — 同 Issue 017 根因，同一修复

### 新增

#### L3 AgentAnalyzer 健壮性增强
- **健壮 LLM 响应解析**：自动剥离 markdown 代码块包裹 / 递归搜索嵌套 JSON 结构 (`risk_assessment.level`) / 映射非标风险等级别名 (`none`→LOW, `severe`→HIGH 等)
- **格式修正重试**：首次解析失败且剩余 budget ≥ 3s 时，自动发送格式修正 prompt 重试
- **`asyncio.CancelledError` 安全网**：Python 3.9+ 中 CancelledError 为 BaseException，确保任何超时场景下 L3 trace 都能保存
- **`deadline_ms` 上限提升至 120s**：适配 L3 多轮 LLM 调用 + 慢速 provider 场景
- **AgentAnalyzer budget 修正**：`effective_budget` 正确纳入 caller 传入的 `budget_ms`，使 inner margin 机制真正生效

#### 测试新增
- 15 个新测试：EventBus replay / SSE 广播 / L3 trace 持久化 / 累积触发 / markdown 解析 / 嵌套结构 / 别名映射 / 格式重试 / budget 耗尽无重试
- 5 个 budget 测试更新适配 inner margin
- 测试总量：1289 → 1304（+15 tests）

#### 真实环境验证
- 25/25 checks PASS（100%）：L3 非降级 trace 首次通过（Kimi K2.5 via SiliconFlow, confidence=0.95）

---

## [0.2.3] — 2026-03-26

### 修复

#### Issue Batch 2026-03-26-2（2 Critical + 1 High + 1 feat, 12 tests）
- **[Issue 012]** `_handle_sync_decision()` deadline exceeded 时 early return 跳过 `trajectory_store.record()` 和 `session_registry.record()`，导致 fallback 决策不落库 — 将 recording 移到 deadline 检查之前
- **[Issue 011]** `_send_request()` 收到 OpenClaw 错误响应时返回 `False` 而非抛异常，导致 `resolve()` reason 降级重试永不触发 — 新增 `ResolveError` 异常 + 匹配 "unexpected property" 错误格式
- **[CS-009]** L2 budget cap 无 overhead margin，LLM 调用耗尽 budget 后刚好超过 deadline — 预留 200ms margin

### 新增
- **`CS_L3_BUDGET_MS`** 环境变量：独立配置 L3 最大预算（默认跟随 L2），解决 L3 场景下 deadline 不足问题
- 穿透链：`DetectionConfig` → `policy_engine` → `llm_factory` → `AgentAnalyzerConfig`

#### 测试新增
- 12 个新测试覆盖：deadline 下 recording / ResolveError + retry E2E / overhead margin / L3 budget 配置
- 测试总量：1277 → 1289（+12 tests）

---

## [0.2.2] — 2026-03-26

### 修复

#### Issue Batch 2026-03-26（3 High defects + 6 tests）
- **[CS-008]** `CompositeAnalyzer.analyze()` 返回 `L2Result` 时遗漏 `trace=best.trace`，导致 L3 trace 始终为 NULL 无法落库
- **[CS-009]** `policy_engine.evaluate()` L2 budget 不受请求 `deadline_ms` 约束，高延迟场景触发 `DEADLINE_EXCEEDED` — 新增 `deadline_budget_ms` 参数，以 `min(config, remaining)` 为上限
- **[Issue 010]** `_build_openclaw_runtime()` 遗漏 `enforcement_enabled`/`openclaw_ws_url`/`openclaw_operator_token` 三字段，导致 WS 可用时 `/ahp/resolve` 仍返回 502
- **[CS-007]** LLM 超时日志改善：区分 `TimeoutError` 与其他 provider error，便于调参调试（WONTFIX，设计如此）

#### 测试新增
- 6 个新测试覆盖：trace 传递 / deadline budget 限制 / enforcement 参数穿透
- 测试总量：1271 → 1277（+6 tests）

---

## [0.2.1] — 2026-03-25

### 修复

#### OpenClaw 兼容性审查（12 defects + 31 tests，2026-03-25）
- **[C-1/C-2]** `run_gateway()` 未接入 `DetectionConfig` 和 LLM analyzer — 独立启动时 L1/L2 均回退默认值
- **[H-1]** OpenClaw POST_ACTION 事件缺少 `output` 字段映射（`toolOutput`/`command_output` 等别名未转换）
- **[H-2]** CompositeAnalyzer 热重载遍历失败 — `reload_patterns` 未递归查找内层 `_pattern_matcher`
- **[H-4]** Webhook 会话 ID 提取仅识别 `sessionKey`，缺少 `sessionId` 回退
- **[H-5/L-3]** WS future 注册顺序错误（先 send 后 register 导致竞态）+ `get_event_loop()` 弃用
- **[M-1]** D6 注入检测遗漏 OpenClaw `message`/`transcript`/`userMessage`/`user_message` 字段
- **[M-2/M-4]** `extract_candidate()` 未持久化 + `store_path` 空路径未校验
- **[M-6]** `CS_EVOLVING_ENABLED` 非法值静默忽略，现增加 warning 日志
- **[L-1]** `post_action_finding` SSE 事件缺少 `source_framework` 字段

#### 测试新增
- 31 个 OpenClaw 集成测试：D6 注入检测 / post-action 围栏 / 轨迹序列 / 攻击模式匹配 / Gateway 配置接入
- 测试总量：1239 → 1271（+32 tests）

---

## [0.2.0] — 2026-03-24

### 新增

#### 核心安全增强（E-4 Phase 1-3，2026-03-24）
- **D6 注入检测维度**：`injection_detector.py`，Layer 1（10 弱+8 强 regex, <0.3ms）+ Layer 2（Canary Token 泄露检测）
- **Post-action 安全围栏**：`post_action_analyzer.py`，异步检测间接注入/数据泄露/凭据暴露/混淆，分级响应（LOG/MONITOR/ESCALATE/EMERGENCY）
- **攻击模式库**：`attack_patterns.yaml` v1.1，25 条模式覆盖 OWASP ASI01-04（含供应链/容器逃逸/反弹 shell）
- **EmbeddingBackend Protocol**：可插拔 L3 向量相似度接口（纯 Protocol，无模型依赖）
- **TrajectoryAnalyzer**：5 个多步攻击序列检测（凭据窃取/后门安装/侦察渗透/密钥收割/分阶段渗出）
- **DetectionConfig**：统一 frozen dataclass（20 可调字段）+ `build_detection_config_from_env()` + 19 CS_ 环境变量（含 bool 型 CS_EVOLVING_ENABLED）
- L1 评分重构：加权公式 `0.4*max(D1,D2,D3)+0.25*D4+0.15*D5` + D6 乘数，新阈值 LOW<0.8/MED<1.5/HIGH<2.2/CRIT≥2.2
- SSE 新事件类型：`post_action_finding`、`trajectory_alert`

#### 自进化模式库（E-5，2026-03-24）
- **PatternEvolutionManager**：从高危事件自动提取候选模式，SHA-256 命令去重，模式 ID `EV-{hash8}`
- **EvolvedPattern 生命周期**：CANDIDATE → EXPERIMENTAL → STABLE → DEPRECATED（FP 率 >30% 自动废弃）
- **EvolvedPatternStore**：YAML 原子持久化（tempfile + os.replace），max_patterns=500，LRU 驱逐
- **compute_confidence()**：5 因子信心评分（确认率 30% / 频率 20% / 跨框架 20% / 准确率 20% / 时效 10%）
- **双源加载**：`load_patterns(evolved_path=...)` 合并内置 core + evolved，过滤 inactive 模式
- **REST API**：`GET /ahp/patterns` + `POST /ahp/patterns/confirm`；SSE `pattern_evolved` 事件
- **配置门控**：`CS_EVOLVING_ENABLED`（默认 false）+ `CS_EVOLVED_PATTERNS_PATH`

#### 测试缺口修复（E-6，2026-03-24）
- 4 并行 Sonnet subagent 审查 E-4/E-5 全部测试，发现 6C+14H+10M+3L 缺口
- 10 个测试文件新增 59 个测试：64KB 截断边界、VectorLayer 除零保护、EvolvedPatternStore 驱逐优先级、STABLE 幂等性、compute_confidence 边界、API 400/404 路径、轨迹负面测试、D6/PostAction Gateway 集成等

#### 用户体验改进（E-1~E-3，2026-03-23）
- **`clawsentry start`**：一键启动命令（框架自动检测 → 初始化 → Gateway → watch），Ctrl+C 优雅关闭
- **Web UI 自动登录**：启动时输出带 token 的 URL，点击即可免密登录
- **watch 输出优化**：混合格式（ALLOW 单行/BLOCK-DEFER 树形展开）+ SessionTracker Unicode 分组框 + Emoji 视觉锚点
- **watch 新 CLI 参数**：`--verbose` / `--no-emoji` / `--compact`
- **Web UI 重构**：Linear/Vercel 设计语言，Inter 字体，紫色 accent（#a78bfa），新组件：EmptyState/SkeletonCard/ScoreBar/VerdictBar/AreaChart 渐变/HintTag/LatencyBadge/TierBadge/SVG 环形倒计时

#### 测试覆盖
- 测试总量：775 → 1239（+464 tests，覆盖 D6/Post-action/模式库/DetectionConfig/TrajectoryAnalyzer/E-5 进化模式/E-6 缺口修复）
- 1 skipped = E2E SDK 测试（需 `A3S_SDK_E2E=1` + LLM API key，预期行为）
- E2E 全量测试（含 LLM 调用）：1243 passed（safe/dangerous/alert/eventbus 四项）

### 修复

#### 第二轮代码审查（3 Critical + 16 Important + 16 Minor + 9 Nitpick）
- **[C-1]** PatternMatcher `_detection_match` 全扫描修复（不再 early-return 丢失最高 weight）
- **[C-2]** `copy.copy(pattern)` 防止共享 AttackPattern 对象 mutation
- **[C-3]** TrajectoryAnalyzer `_emitted` set 上限 + LRU 驱逐防止内存泄漏
- SSE `/report/stream` 白名单补充 `post_action_finding` / `trajectory_alert`（I-1）
- `build_detection_config_from_env()` try/except 降级 + `d6_injection_multiplier` 验证（I-2/I-3）
- `score_layer1` + `PostActionAnalyzer` 64KB 输入上限（I-4/I-6）
- ThreadPoolExecutor `asyncio.wait_for` 包装防线程泄漏（I-7）
- `detect_instructional_content` 收窄标记 + 阈值 >0.5（I-8）
- 触发器 command/path_patterns 递归预编译（I-11）
- max_weight ≥ 8 → HIGH 风险升级（I-12）
- RiskSnapshot `frozen=True` 不可变保证（I-10）
- 正则优化 / 防御性拷贝 / bidi 字符检测 / 文档完善（Minor/Nitpick）

#### 第一轮代码审查
- PatternMatcher 正则预编译 + 100KB 输入限制（H9/H10）
- Post-action 复合评分聚合：max + 0.15 per extra signal（H8）
- LLM prompt payload 脱敏（4KB 截断 + REDACTED 标注，H3/H4）
- CDN 白名单扩展 + Shannon 熵阈值 7.0→5.5（M12/M13）
- `event_text()` 64KB 上限防止 regex 性能退化（M5）
- `mount` 加入 DANGEROUS_TOOLS（M3）

---

## [0.1.0] — 2026-03-23

首个公开版本。ClawSentry 是 Agent Harness Protocol (AHP) 的 Python 参考实现——一个面向 AI Agent 运行时的统一安全监督网关，支持 a3s-code 和 OpenClaw 双框架接入。

### 新增

#### 核心架构
- 实现 AHP (Agent Harness Protocol) 统一协议规范，归一化多框架运行时事件
- Sidecar 架构 + UDS（主传输）+ HTTP（备传输）双通道入口
- 同步阻塞 `pre_action` + 异步审计 `post_action` 双通道处理
- 基于 Pydantic v2 的 CanonicalEvent / CanonicalDecision 协议模型
- JSON-RPC 2.0 同步决策接口 (`sync_decision.1.0`)

#### 三层决策模型
- **L1 规则引擎** (<1ms)：D1-D5 五维风险评分（命令危险度/参数敏感度/上下文合理性/历史行为/作用域权限）
- **L2 语义分析** (<3s)：SemanticAnalyzer Protocol + RuleBased / LLM / Composite 三种实现
- **L3 审查 Agent** (<30s)：AgentAnalyzer + ReadOnlyToolkit + SkillRegistry + 多轮工具调用推理
- L3 推理轨迹持久化到 TrajectoryStore (`l3_trace_json` 列)

#### 框架适配器
- **a3s-code Adapter**：stdio harness + HTTP Transport (`POST /ahp/a3s`) 双模式
- **OpenClaw Adapter**：WebSocket 实时事件监听 + Webhook 接收器 + 审批执行器
- LLM 工厂：环境变量驱动的 Anthropic/OpenAI/自定义 provider 构建

#### 安全加固
- Bearer Token HTTP 认证 (`CS_AUTH_TOKEN`)
- Webhook HMAC-SHA256 签名验证 + IP 白名单 + Token TTL
- UDS socket `chmod 0o600` 权限保护
- SSL/TLS 支持 (`AHP_SSL_CERTFILE` / `AHP_SSL_KEYFILE`)
- 速率限制 (`CS_RATE_LIMIT_PER_MINUTE`，默认 300/分钟)
- 幂等性缓存防重复决策
- 按风险等级分层的重试预算（CRITICAL/HIGH=1, MEDIUM=2, LOW=3）

#### 会话管理
- SessionRegistry：会话生命周期追踪 + 风险累积
- 会话级强制策略 (SessionEnforcementPolicy)：累积 N 次高危后自动 DEFER/BLOCK/L3
- 冷却期自动释放 + 手动释放 REST API

#### 实时监控
- EventBus：进程内事件广播
- SSE 实时推送：decision / session_start / session_risk_change / alert / session_enforcement_change
- AlertRegistry：告警聚合 + 过滤 + 确认
- `clawsentry watch` CLI：终端实时展示（彩色输出/JSON 模式/事件过滤）
- `clawsentry watch --interactive`：DEFER 运维确认 (Allow/Deny/Skip + 超时安全余量)

#### Web 安全仪表板
- React 18 + TypeScript + Vite SPA，暗色 SOC 主题
- Dashboard：实时决策 feed + 指标卡 + 饼图/柱状图
- Sessions：会话列表 + D1-D5 雷达图 + 风险曲线 + 决策时间线
- Alerts：告警表格 + 过滤 + 确认 + SSE 自动推送
- DEFER Panel：倒计时 + Allow/Deny 按钮 + 503 降级提示
- Gateway 在 `/ui` 路径提供静态文件 + SPA fallback

#### CLI 工具
- `clawsentry init <framework>`：零配置初始化（支持 `--auto-detect` / `--setup` / `--dry-run`）
- `clawsentry gateway`：智能启动（自动检测 OpenClaw 配置，按需启用 Webhook/WS）
- `clawsentry harness`：a3s-code stdio harness
- `clawsentry watch`：SSE 实时监控
- `.env` 文件自动加载（dotenv_loader）

#### REST API 接口
- `POST /ahp` — OpenClaw Webhook 决策端点
- `POST /ahp/a3s` — a3s-code HTTP Transport
- `POST /ahp/resolve` — DEFER 决策代理 (allow-once/deny)
- `GET /health` — 健康检查
- `GET /report/summary` — 跨框架聚合统计
- `GET /report/stream` — SSE 实时推送（支持 `?token=` query param 认证）
- `GET /report/sessions` — 活跃会话列表 + 风险排序
- `GET /report/session/{id}` — 会话轨迹回放
- `GET /report/session/{id}/risk` — 会话风险详情 + 时间线
- `GET /report/session/{id}/enforcement` — 会话执法状态查询
- `POST /report/session/{id}/enforcement` — 会话执法手动释放
- `GET /report/alerts` — 告警列表 + 过滤
- `POST /report/alerts/{id}/acknowledge` — 确认告警

#### L3 技能
- 6 个内置审查技能：shell-audit / credential-audit / code-review / file-system-audit / network-audit / general-review
- 自定义 Skills 支持 (`AHP_SKILLS_DIR` 环境变量)
- Skills Schema：enabled / priority 字段 + 双语 system_prompt + 扩展 triggers

#### 测试
- 775 个测试用例，覆盖单元测试 + 集成测试 + E2E 测试
- 测试通过时间 ~6.5s

[0.6.2]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.2
[0.6.1]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.1
[0.6.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.0
[0.5.14]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.14
[0.5.13]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.13
[0.5.12]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.12
[0.5.11]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.11
[0.5.10]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.10
[0.5.9]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.9
[0.5.8]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.8
[0.5.7]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.7
[0.5.6]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.6
[0.5.5]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.5
[0.5.4]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.4
[0.5.3]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.3
[0.5.2]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.2
[0.5.1]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.1
[0.5.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.5.0
[0.4.8]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.4.8
[0.4.6]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.4.6
[0.4.7]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.4.7
[0.4.5]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.4.5
[0.4.4]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.4.4
[0.4.3]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.4.3
[0.4.1]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.4.1
[0.4.2]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.4.2
[0.4.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.4.0
[0.3.6]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.6
[0.3.9]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.9
[0.3.8]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.8
[0.3.5]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.5
[0.3.4]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.4
[0.3.3]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.3
[0.3.2]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.2
[0.3.1]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.1
[0.3.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.3.0
[0.2.9]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.9
[0.2.8]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.8
[0.2.7]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.7
[0.2.6]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.6
[0.2.5]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.5
[0.2.4]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.4
[0.2.3]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.3
[0.2.2]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.2
[0.2.1]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.1
[0.2.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.0
[0.1.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.1.0

[0.6.4]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.4
[0.6.3]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.3
[0.6.5]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.5
[0.6.6]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.6
[0.6.7]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.7
[0.6.8]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.8
