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
- **Tunable detection pipeline**: `DetectionConfig` frozen dataclass with 20 parameters, all overridable via `CS_` environment variables
- **Dual framework support**: a3s-code (stdio / HTTP) + OpenClaw (WebSocket / Webhook)
- **Real-time monitoring**: SSE streaming, `clawsentry watch` CLI, React/TypeScript web dashboard
- **Production security**: Bearer token auth, HMAC webhook signatures, UDS chmod 0o600, SSL/TLS, rate limiting
- **Session enforcement**: auto-escalate after N high-risk events with configurable cooldown
- **1239+ tests**, ~24 s full suite

## Installation

```bash
pip install clawsentry           # core
pip install clawsentry[llm]      # + Anthropic/OpenAI for L2/L3
pip install clawsentry[all]      # everything
```

Requires Python >= 3.11.

## Quick Start

### One-Command Launch (Recommended)

```bash
clawsentry start                   # auto-detect framework + init + gateway + watch
# or specify framework:
clawsentry start --framework openclaw
clawsentry start --framework a3s-code --interactive  # enable DEFER interaction
```

The `start` command will:
1. Auto-detect your framework (OpenClaw or a3s-code)
2. Initialize configuration if needed
3. Start the gateway in the background
4. Display live monitoring in the foreground
5. Show Web UI URL with auto-login token

Press Ctrl+C to gracefully shutdown.

### Manual Step-by-Step

#### a3s-code

```bash
clawsentry init a3s-code --setup   # generate config + patch a3s-code settings
clawsentry gateway                 # start gateway (default :8080)
clawsentry watch                   # tail live decisions in your terminal
```

#### OpenClaw

```bash
clawsentry init openclaw --setup   # generate config + patch OpenClaw settings
clawsentry gateway                 # start gateway (default :8080)
open http://localhost:8080/ui      # open web dashboard
```

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
| `AHP_LLM_PROVIDER` | `rule_based` | LLM backend for L2/L3: `anthropic`, `openai`, or `rule_based` |
| `AHP_L3_ENABLED` | `false` | Enable L3 multi-turn review agent |
| `AHP_SESSION_ENFORCEMENT_ENABLED` | `false` | Auto-escalate sessions after N high-risk events |
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
