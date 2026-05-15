# Changelog

This public changelog lists user-facing release highlights. Internal validation
notes and development-only experiment records are kept in the development
repository.

## v0.6.9 — 2026-05-15

- Release tag: <https://github.com/Elroyper/ClawSentry/releases/tag/v0.6.9>
- Package metadata source: `pyproject.toml`.
- Added Persistence-write / SC-4 policy for writes that create future automatic
  execution or re-entry entrypoints.
- Added configurable SC-4 actions through `CS_PERSISTENCE_WRITE_ACTION`,
  `CS_PERSISTENCE_WRITE_FALLBACK_ACTION`, and
  `CS_PERSISTENCE_WRITE_L3_ALLOW_CONFIDENCE`.
- Routed `force_l3` SC-4 decisions through the synchronous pre-action L3
  verdict path with redacted evidence summaries.
- Improved pre-action write payload normalization for nested write/edit fields.

## v0.6.8 — 2026-05-11

- Added anti-bypass LLM-assisted recognition using sanitized semantic capsules.
- Added compact `anti_bypass_probe` metadata for provider, timeout, budget, and
  confidence diagnostics.
- Added `CS_LLM_API_KEY_ENV` support for shared LLM key indirection.
- Refined anti-bypass matching precedence and candidate gating.

## v0.6.7 and Earlier

Earlier releases introduced the multi-framework startup flow, Codex managed
hooks, scope restrictions, L3 advisory review, token budgets, Gemini/Kimi/OpenClaw
integration support, dashboard reporting, and the core L1/L2/L3 supervision
pipeline.
