[![PyPI](https://img.shields.io/pypi/v/clawsentry)](https://pypi.org/project/clawsentry/) [![Python](https://img.shields.io/pypi/pyversions/clawsentry)](https://pypi.org/project/clawsentry/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![Docs](https://img.shields.io/badge/docs-online-blue)](https://elroyper.github.io/ClawSentry/)

# ClawSentry

[AHP (Agent Harness Protocol)](https://github.com/A3S-Lab/AgentHarnessProtocol) reference implementation — a unified security supervision gateway for AI agent runtimes.

## Features

- **Three-tier progressive decision**: L1 rule engine (<1 ms) → L2 semantic analysis (<3 s) → L3 review agent (<30 s)
- **Dual framework support**: a3s-code (stdio / HTTP) + OpenClaw (WebSocket / Webhook)
- **Real-time monitoring**: SSE streaming, `clawsentry watch` CLI, React/TypeScript web dashboard
- **Production security**: Bearer token auth, HMAC webhook signatures, UDS chmod 0o600, SSL/TLS, rate limiting
- **Session enforcement**: auto-escalate after N high-risk events with configurable cooldown
- **775+ tests**, ~6.5 s full suite

## Installation

```bash
pip install clawsentry           # core
pip install clawsentry[llm]      # + Anthropic/OpenAI for L2/L3
pip install clawsentry[all]      # everything
```

Requires Python >= 3.11.

## Quick Start

### a3s-code

```bash
clawsentry init a3s-code --setup   # generate config + patch a3s-code settings
clawsentry gateway                 # start gateway (default :8765)
clawsentry watch                   # tail live decisions in your terminal
```

### OpenClaw

```bash
clawsentry init openclaw --setup   # generate config + patch OpenClaw settings
clawsentry gateway                 # start gateway (default :8765)
open http://localhost:8765/ui      # open web dashboard
```

## Architecture

```
a3s-code ──→ A3S Adapter ──┐
                            ├──→ AHP CanonicalEvent ──→ PolicyEngine ──→ L1/L2/L3
OpenClaw ──→ OC Adapter ───┘                                                │
                                                            SessionRegistry ←┘
                                                            EventBus ──→ SSE / CLI / Web UI
```

**Decision tiers:**

- **L1 PolicyEngine** — deterministic rule scoring across five risk dimensions (D1–D5), sub-millisecond latency
- **L2 SemanticAnalyzer** — LLM-backed semantic analysis with configurable provider (Anthropic / OpenAI / rule-based fallback)
- **L3 AgentAnalyzer** — multi-turn review agent with read-only toolkit and per-session skill dispatch

## Documentation

Full documentation is available at **https://elroyper.github.io/ClawSentry/**

- [Getting Started](https://elroyper.github.io/ClawSentry/getting-started/)
- [Architecture Overview](https://elroyper.github.io/ClawSentry/architecture/)
- [a3s-code Integration Guide](https://elroyper.github.io/ClawSentry/guides/a3s-code/)
- [OpenClaw Integration Guide](https://elroyper.github.io/ClawSentry/guides/openclaw/)
- [Configuration Reference](https://elroyper.github.io/ClawSentry/reference/configuration/)
- [REST & SSE API](https://elroyper.github.io/ClawSentry/reference/api/)

## Key Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CS_AUTH_TOKEN` | *(required)* | Bearer token for all REST / SSE endpoints |
| `AHP_LLM_PROVIDER` | `rule_based` | LLM backend for L2/L3: `anthropic`, `openai`, or `rule_based` |
| `AHP_L3_ENABLED` | `false` | Enable L3 multi-turn review agent |
| `AHP_SESSION_ENFORCEMENT_ENABLED` | `false` | Auto-escalate sessions after N high-risk events |
| `OPENCLAW_WS_URL` | — | WebSocket URL of a running OpenClaw gateway |

See the [full configuration reference](https://elroyper.github.io/ClawSentry/reference/configuration/) for all variables.

## License

MIT — see [LICENSE](LICENSE)
