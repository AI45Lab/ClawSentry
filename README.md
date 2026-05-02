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
- **Six-framework support with explicit boundaries**: a3s-code (explicit SDK transport) + OpenClaw (WS approval + webhook) + Claude Code (host hooks) + Codex CLI (session-log watcher + optional tested `PreToolUse(Bash)` preflight / `PermissionRequest(Bash)` approval gate) + Gemini CLI (native hooks; real provider `BeforeTool` deny smoke proven for `run_shell_command`) + Kimi CLI (native hooks; real `kimi-k2.5` E2E proven for prompt deny, safe Shell observation, and dangerous Shell `PreToolUse` deny; no native modify/defer parity)
- **Real-time monitoring**: SSE streaming, `clawsentry watch` CLI, React/TypeScript web dashboard
- **Production security**: Bearer token auth, HMAC webhook signatures, UDS chmod 0o600, SSL/TLS, rate limiting
- **Session enforcement**: auto-escalate after N high-risk events with configurable cooldown
- **3152+ regression tests**, with release-time CI/build evidence

## Installation

```bash
pip install clawsentry           # core
pip install clawsentry[llm]      # + Anthropic/OpenAI for L2/L3
pip install clawsentry[all]      # everything
```

Requires Python >= 3.11.

## What's New in v0.6.5

- **Scope preview before enforcement**: `clawsentry scope validate/preview` and `POST /ahp/scope/preview` show dry-run/enforced boundaries and readable reason codes before operators opt in.
- **Capability-honest sanitizer reporting**: watch/report output uses `would_sanitize`, redacted previews, and degraded/unsupported states instead of overclaiming output rewriting.
- **Reversible OpenClaw hardening**: hardened profile setup remains opt-in, dry-run-first, marker-managed, and restore-tested.
- **Docs and release status refreshed**: progress docs, online docs, changelog, and API metadata are aligned for v0.6.5.

## Quick Start

### One-Command Launch (Recommended)

```bash
clawsentry start                   # auto-detect framework + init + gateway + watch
# or specify framework:
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
| `codex` | Session JSONL watcher + optional native hooks | No by default; optional tested `PreToolUse(Bash)` preflight + `PermissionRequest(Bash)` approval gate | Yes | Session logs / optional `.codex/hooks.json` must be reachable |
| `gemini-cli` | Gemini CLI native command hooks | Yes; real `BeforeTool` deny smoke proven for `run_shell_command` | Yes, with post-action side-effect caveat | Project `.gemini/settings.json` managed hooks; global home only with explicit `--gemini-home` |
| `kimi-cli` | Kimi CLI native `[[hooks]]` | Yes; `PreToolUse` and prompt deny via Kimi permission decision | Yes, observation-only for post/session/subagent/compact/notification | `$KIMI_SHARE_DIR/config.toml` or `~/.kimi/config.toml` marker-managed hooks |
| `claude-code` | Host hooks + `clawsentry-harness` | Yes | Yes | `~/.claude/settings.json` hooks must remain installed |

`codex` should be understood as observation-first by default; optional managed native hooks now provide narrow `PreToolUse(Bash)` deny and `PermissionRequest(Bash)` approval-gate paths, while `PostToolUse`, `UserPromptSubmit`, `Stop`, and `SessionStart` remain advisory/observational by default. `a3s-code`
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
