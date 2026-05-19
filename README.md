[![PyPI](https://img.shields.io/pypi/v/clawsentry)](https://pypi.org/project/clawsentry/) [![Python](https://img.shields.io/pypi/pyversions/clawsentry)](https://pypi.org/project/clawsentry/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Docs](https://img.shields.io/badge/docs-online-blue)](https://elroyper.github.io/ClawSentry/)

# ClawSentry

AHP (Agent Harness Protocol) reference implementation — a unified security supervision gateway for AI agent runtimes.

<p align="center">
  <img src="site-docs/assets/architecture-overview.png" alt="ClawSentry Architecture Overview" width="820">
</p>

## Features

- **Three-tier progressive decision**: L1 rule engine (<1 ms) → L2 semantic analysis (<3 s) → L3 review agent (<30 s)
- **Six-dimensional risk scoring (D1–D6)**: command danger / path sensitivity / command patterns / session history / trust level / **injection detection**
- **D6 injection detection**: 3-layer analysis — heuristic regex + Canary Token leak + pluggable EmbeddingBackend (vector similarity)
- **Post-action security fence**: non-blocking post-tool analysis — indirect injection, data exfiltration, secret exposure, obfuscation (4 response tiers)
- **25 built-in attack patterns (v1.1)**: OWASP ASI01–ASI05, covering supply chain, container escape, reverse shell, staged exfiltration
- **Multi-step attack trajectory detection**: 5 built-in sequences with sliding-window analysis, SSE `trajectory_alert` broadcast
- **Self-evolving pattern library (E-5)**: auto-extract candidates from high-risk events, CANDIDATE→EXPERIMENTAL→STABLE lifecycle, confidence scoring, REST API feedback loop
- **Tunable detection pipeline**: `DetectionConfig` frozen dataclass with explicit `CS_` / project-level overrides, including high-level L3 routing and trigger controls
- **Skill Trust and policy traceability**: registry/preflight controls for local skill packages, first-use actions, compound/taint evidence, capability narrowing, and policy drift reports
- **Six-framework support with explicit boundaries**: a3s-code (explicit SDK transport) + OpenClaw (WS approval + webhook) + Claude Code (host hooks) + Codex CLI (session-log watcher + default managed `PreToolUse(Bash)` preflight / `PermissionRequest(Bash|apply_patch|Edit|Write|mcp__.*)` approval gate / async compact observation via `clawsentry start --framework codex`) + Gemini CLI (native hooks; real provider `BeforeTool` deny smoke proven for `run_shell_command`) + Kimi CLI (native hooks; real E2E proven for prompt deny, safe Shell observation, and dangerous Shell `PreToolUse` deny; no native modify/defer parity)
- **Real-time monitoring**: SSE streaming, `clawsentry watch` CLI, React/TypeScript web dashboard
- **Production security**: Bearer token auth, HMAC webhook signatures, UDS chmod 0o600, SSL/TLS, rate limiting
- **Session enforcement**: auto-escalate after N high-risk events with configurable cooldown
- **3645 public Python regression tests + 56 Web UI tests**, with release-time CI/build evidence

## Installation

```bash
pip install clawsentry           # core
pip install clawsentry[llm]      # + Anthropic/OpenAI for L2/L3
pip install clawsentry[all]      # everything
```

Requires Python >= 3.11.

## What's New in v0.8.0

- **Skill Trust runtime binding control plane**: Gateway binds observed skill paths, native skill names, allowed mirrors, runner contracts, and Gateway-owned metadata into explicit runtime trust statuses.
- **Ledger and provenance validation**: replay-safe skill-use ledger records observed allow/block/defer skill use; post-action provenance validation compares artifact claims with the ledger without rewriting completed decisions.
- **FSPR and lifecycle controls**: first-use package review emits evidence and transition recommendations; allowlist/greylist/blacklist/revoke/disable/restore/override mutations go through auditable lifecycle API/CLI.

## What's New in v0.7.5

- **Cross-CLI Skill Trust runtime binding**: Kimi CLI, Claude Code, Gemini CLI, Codex, and a3s-code attach Skill Trust runtime metadata from real skill paths and project context into Gateway evaluation.
- **Prompt-hook parity and replay hardening**: Claude Code `UserPromptSubmit` uses prompt-block response semantics, and session replay keeps Skill Trust metadata hash/label-only.
- **Benchmark matrix cleanup**: SkillsSafety/SKILL-INJECT docs separate raw baselines from protected pairings and document current four-framework live coverage.

## What's New in v0.7.4

- **L3 multi-turn by default**: L3 AgentAnalyzer now uses multi-turn review unless `CS_L3_MULTI_TURN=false`, `0`, `no`, or `off` explicitly requests legacy single-turn mode.
- **Benchmark Docker alignment**: protected SkillsSafetyBench sweeps set `CS_L3_MULTI_TURN=true`, matching the public runtime default for unattended Docker benchmark runs.
- **Docs and config refresh**: env-var docs, L3 docs, and benchmark notes now describe multi-turn as the default path.

## What's New in v0.7.3

- **L2/L3 shared evidence path**: L2 semantic analysis now emits a redacted evidence capsule that L3 review prompts and audit metadata can reuse.
- **Triggered L3 review prompt**: L3 reviews are organized around trigger reason, policy intent, skill context, review skill manifest, evidence, and operator next steps.
- **Expanded review skills**: prompt-injection transcript, data-staging exfil chain, dependency supply-chain, persistence, and skill-trust audit skills are available as manifest entries.

## What's New in v0.7.2

- **Anti-bypass L1 capability-equivalence enforcement**: denied and pending risky effects are normalized into redacted action summaries, so equivalent follow-up attempts cannot bypass policy by changing tool, shell syntax, or execution wrapper.
- **Approval effect binding**: defer approvals are bound to the approved effect and fail closed if the resolved action drifts.
- **Replay evidence**: the anti-bypass L1 replay fixture covers 14 cases with decision match, evidence, fallback, rule, and schema-sync coverage at `1.0`.

## What's New in v0.7.1

- **Public release metadata correction**: the public release surface now reports the public repository validation count consistently and keeps the online documentation focused on install, integration, operations, and Benchmark mode usage.

## What's New in v0.7.0

- **Runtime safety controls**: Skill Trust registry/preflight, AHP policy replay, deterministic compound/taint evidence, capability narrowing, redacted agent feedback, and policy drift traceability are now on the mainline path.
- **Skill Trust first-use control**: local skill packages can be scanned and registered with `clawsentry skill-trust`, then routed through audit, L2/L3 review, defer, or block actions by runtime profile.
- **Generalized persistence evidence**: startup/bootstrap/autoload/reentry and related persistence-write patterns are represented through `rule_hits` and `taint_flow_summary`, instead of a case-specific runtime switch.
- **Benchmark mode**: non-interactive safety-test runs can use deterministic defer handling and temporary Codex homes through the `clawsentry benchmark` commands.

## Quick Start

### One-Command Launch (Recommended)

```bash
clawsentry start                   # auto-detect framework + init + gateway + watch
# or specify framework:
clawsentry start --framework codex       # installs/refreshes Codex managed hooks by default
clawsentry start --framework openclaw
clawsentry start --framework a3s-code --interactive  # enable DEFER interaction
```

The `start` command will:
1. Auto-detect your framework (a3s-code, Claude Code, Codex, Gemini CLI, Kimi CLI, or OpenClaw)
2. Initialize configuration if needed
3. Start the gateway in the background
4. Display live monitoring in the foreground
5. Show Web UI URL with auto-login token

### Web UI auth quick note

`clawsentry start` prints a Web UI URL such as
`http://127.0.0.1:8080/ui?token=...`. The browser stores that token in
`sessionStorage` and removes `?token=` from the address bar before loading data.
Manual login uses the same `CS_AUTH_TOKEN` from the startup environment, explicit `--env-file`, or the ephemeral token printed by `start`.

- `invalid token` / `401` means the pasted value does not match
  `CS_AUTH_TOKEN`.
- `Gateway unavailable` means the local Gateway cannot be reached; this is not
  an invalid-token error.
- If your shell exports proxy variables, use
  `NO_PROXY=localhost,127.0.0.1,::1` for local Gateway calls.

Press Ctrl+C to gracefully shutdown.

`clawsentry init <framework>` updates `CS_FRAMEWORK / CS_ENABLED_FRAMEWORKS` by
default and does not write secrets. Framework enablement is stored in project
config; local tokens and provider keys belong in process/deployment env or an
explicit `--env-file` such as `.clawsentry.env.local`.

Start multiple integrations together:

```bash
clawsentry start --frameworks a3s-code,codex,openclaw --no-watch
clawsentry integrations status
```

Codex `start` installs only ClawSentry-managed hooks and trust state, preserving user hooks. The startup banner prints the removal command:

```bash
clawsentry init codex --uninstall
```

If you want `start` to also patch OpenClaw-side approval config, opt in explicitly:

```bash
clawsentry start --frameworks codex,openclaw --setup-openclaw --no-watch
clawsentry integrations status --json
```

`integrations status` now reports more than enabled frameworks: it also shows
OpenClaw backup restore availability, Claude hook source files, Codex
session directory reachability, Gemini settings/hook readiness, a per-framework
readiness verdict with next steps, and a machine-readable framework capability matrix. The multi-framework
`start` banner now prints the same readiness summary before it returns or
begins streaming events.

Disable one framework without disturbing the others:

```bash
clawsentry init codex --uninstall
clawsentry init gemini-cli --uninstall  # removes project-local managed Gemini hooks
clawsentry init claude-code --uninstall  # also removes Claude Code hooks
clawsentry init openclaw --uninstall     # env only; use --restore for OpenClaw-side backups
```

### Manual Step-by-Step

#### a3s-code

```bash
clawsentry init a3s-code           # update CS_FRAMEWORK / CS_ENABLED_FRAMEWORKS
clawsentry gateway                 # start gateway (default :8080)
clawsentry watch                   # tail live decisions in your terminal
```

Wire a3s-code through explicit SDK transport in your agent script, for example
`SessionOptions().ahp_transport = StdioTransport(program="clawsentry-harness", args=[])`.
Do not rely on `.a3s-code/settings.json` for AHP; the current upstream runtime
does not auto-load it.

#### OpenClaw

```bash
clawsentry init openclaw           # update CS_FRAMEWORK / CS_ENABLED_FRAMEWORKS only
clawsentry init openclaw --setup   # opt-in: patch OpenClaw settings
clawsentry gateway                 # start gateway (default :8080)
open http://localhost:8080/ui      # open web dashboard
```

OpenClaw setup is explicit opt-in. Plain `init openclaw` and `start --frameworks`
do not modify `~/.openclaw/`. Setup writes `.bak` backups before changing
OpenClaw-side config. To preview or restore those backups:

```bash
clawsentry init openclaw --restore --dry-run
clawsentry init openclaw --restore
```

## Framework Compatibility

| Framework | Integration mode | Pre-action interception | Post-action observation | Main dependency |
|---|---|---|---|---|
| `a3s-code` | Explicit SDK transport + `clawsentry-harness` | Yes | Yes | Agent code must wire `SessionOptions.ahp_transport` |
| `openclaw` | WebSocket approvals + webhook receiver | Yes | Yes | `~/.openclaw/` must be configured for gateway exec + callbacks |
| `codex` | Session JSONL watcher + managed native hooks | Managed `PreToolUse(Bash)` preflight response path + `PermissionRequest(Bash|apply_patch|Edit|Write|mcp__.*)` approval gate when started through `clawsentry start --framework codex` | Yes, including async `PreCompact` / `PostCompact` observation | Session logs and `$CODEX_HOME/hooks.json` managed entries must be reachable |
| `gemini-cli` | Gemini CLI native command hooks | Yes; real `BeforeTool` deny smoke proven for `run_shell_command` | Yes, with post-action side-effect caveat | Project `.gemini/settings.json` managed hooks; global home only with explicit `--gemini-home` |
| `kimi-cli` | Kimi CLI native `[[hooks]]` | Yes; `PreToolUse` and prompt deny via Kimi permission decision | Yes, observation-only for post/session/subagent/compact/notification | `$KIMI_SHARE_DIR/config.toml` or `~/.kimi/config.toml` marker-managed hooks |
| `claude-code` | Host hooks + `clawsentry-harness` | Yes | Yes | `~/.claude/settings.json` hooks must remain installed |

`codex` should be understood as observation plus narrow managed native hooks by default when launched through `clawsentry start --framework codex`: `PreToolUse(Bash)` can deny and `PermissionRequest(Bash|apply_patch|Edit|Write|mcp__.*)` can gate approvals, while non-Bash `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SessionStart(startup|resume|clear)`, `PreCompact`, and `PostCompact` remain advisory/observational by default. `a3s-code`
should be understood as explicit transport wiring, not `.a3s-code/settings.json`
auto-loading. `claude-code` and `openclaw` remain more host-config-dependent than
`a3s-code`.

`gemini-cli` should be understood as native-hook support: `clawsentry init gemini-cli --setup` installs project-local managed hooks in `.gemini/settings.json`, and shell-tool events are canonicalized to policy-facing `bash` before evaluation. Kimi/OpenAI-compatible endpoints are not directly supported by Gemini CLI. Managed Gemini hook commands redirect diagnostics away from stderr and exit fail-open on harness process failure so Gemini does not treat plain stderr text as hook output.

`kimi-cli` is native-hook support, not AHP transport parity: `clawsentry init kimi-cli --setup` adds marker-managed `[[hooks]]` entries to `$KIMI_SHARE_DIR/config.toml` (or `~/.kimi/config.toml`) and preserves non-ClawSentry user hooks. Kimi `PreToolUse` can block dangerous tool calls, `UserPromptSubmit` can block prompts, and lifecycle hooks provide observation. Native tool-input rewrite and true `defer` are reported as unsupported/degraded rather than presented as equal to `a3s-code`.

For a machine-readable local view of the same boundaries, run
`clawsentry integrations status --json`.

## Architecture

**Decision tiers:**

- **L1 PolicyEngine** — deterministic rule scoring across six risk dimensions (D1–D6), sub-millisecond latency
  - Composite score: `base = 0.4×max(D1,D2,D3) + 0.25×D4 + 0.15×D5; score = base × (1.0 + 0.5×D6/3.0)`
  - Risk thresholds: LOW < 0.8 / MEDIUM 0.8–1.5 / HIGH 1.5–2.2 / CRITICAL ≥ 2.2
- **L2 SemanticAnalyzer** — LLM-backed semantic analysis with configurable provider (Anthropic / OpenAI / rule-based fallback); 25-pattern attack library + trajectory analysis
- **L3 AgentAnalyzer** — multi-turn review agent with read-only toolkit and per-session skill dispatch
- **PostActionAnalyzer** — non-blocking post-execution fence; 4 detectors × 4 response tiers

## Documentation

Full documentation is available at **https://elroyper.github.io/ClawSentry/**

- [Getting Started](https://elroyper.github.io/ClawSentry/getting-started/installation/)
- [Core Concepts](https://elroyper.github.io/ClawSentry/getting-started/concepts/)
- [a3s-code Integration](https://elroyper.github.io/ClawSentry/integration/a3s-code/)
- [OpenClaw Integration](https://elroyper.github.io/ClawSentry/integration/openclaw/)
- [L1 Rules Engine](https://elroyper.github.io/ClawSentry/decision-layers/l1-rules/)
- [L2 Semantic Analysis](https://elroyper.github.io/ClawSentry/decision-layers/l2-semantic/)
- [Configuration Reference](https://elroyper.github.io/ClawSentry/configuration/env-vars/)
- [REST & SSE API](https://elroyper.github.io/ClawSentry/api/decisions/)

## Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CS_AUTH_TOKEN` | *(required)* | Bearer token for all REST / SSE endpoints |
| `CS_LLM_PROVIDER` | *(empty = rules only)* | LLM backend for L2/L3: `anthropic`, `openai`, or empty for rules-only mode |
| `CS_L3_ENABLED` | `false` | Enable L3 multi-turn review agent |
| `AHP_SESSION_ENFORCEMENT_ENABLED` | `false` | Legacy session-enforcement flag; prefer canonical `CS_*` settings where available |
| `OPENCLAW_WS_URL` | — | WebSocket URL of a running OpenClaw gateway |
| `CS_EVOLVING_ENABLED` | `false` | Enable self-evolving pattern library (E-5) |
| `CS_EVOLVED_PATTERNS_PATH` | — | Path to store evolved patterns YAML |
| `CS_ATTACK_PATTERNS_PATH` | *(built-in)* | Path to custom attack patterns YAML (hot-reload) |
| `CS_THRESHOLD_CRITICAL` | `2.2` | Risk score threshold for CRITICAL level |
| `CS_THRESHOLD_HIGH` | `1.5` | Risk score threshold for HIGH level |
| `CS_THRESHOLD_MEDIUM` | `0.8` | Risk score threshold for MEDIUM level |
| `CS_POST_ACTION_WHITELIST` | — | Comma-separated regex list for post-action path whitelist |

See the [full configuration reference](https://elroyper.github.io/ClawSentry/configuration/env-vars/) for all 20+ tunable parameters.

## License

MIT — see [LICENSE](LICENSE)
