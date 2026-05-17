# ClawSentry — AHP Supervision Gateway

> **Python 3.11+** | **3456 public Python regression tests + 56 Web UI tests** | Protocol `ahp.1.0`

**ClawSentry** is the Python reference implementation of AHP (Agent Harness Protocol) — a unified security supervision gateway for multi-agent frameworks. Deployed as a sidecar, it normalizes runtime events from different frameworks (a3s-code, Claude Code, Codex, Gemini CLI, Kimi CLI, OpenClaw) into a unified protocol, passes them through a three-layer progressive risk evaluation pipeline, and produces real-time decisions (allow / block / modify / defer) with complete audit trails.

**Core goal**: Eliminate cross-framework policy duplication and observability fragmentation through a "protocol-first, decision-centralized" approach to agent security governance.

**Current release highlight (v0.7.5)**: Cross-CLI Skill Trust runtime metadata is now bound to real skill paths and runtime context across Kimi CLI, Claude Code, Gemini CLI, Codex, and a3s-code, while replay output remains hash/label-only.

---

## Table of Contents

- [Three-Layer Decision Model](#three-layer-decision-model)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
- [API Endpoints](#api-endpoints)
- [Web Dashboard](#web-dashboard)
- [Project Structure](#project-structure)
- [Configuration](#configuration)
- [Running Tests](#running-tests)

---

## Three-Layer Decision Model

```
                    Event Flow 100%
                        |
                 +------v------+
                 |  L1 Rules   |  < 0.3ms, D1-D6 composite scoring
                 +------+------+
                        |
            +-----------+-----------+
            v           v           v
     LOW (allow)   MEDIUM (?)   CRITICAL (block)
      ~60%          ~30%          ~10%
         |              |           |
         |       +------v------+   |
         |       |  L2 Semantic |   |  Pluggable LLM, < 3s
         |       +------+------+   |
         |              |          |
         |       +------v------+   |
         |       |  L3 Agent   |   |  Multi-turn tool use, < 30s
         |       +------+------+   |
         |              |          |
         v              v          v
       allow      allow/block    block
```

| Layer | Implementation | Latency | Activation |
|-------|---------------|---------|------------|
| **L1** Rules | D1-D6 six-dimensional scoring + short-circuit rules | < 0.3ms | Always on |
| **L2** Semantic | RuleBased / LLM / Composite + 25 attack patterns | < 3s | `CS_LLM_PROVIDER` |
| **L3** Agent | AgentAnalyzer + ReadOnlyToolkit + SkillRegistry | < 30s | `CS_L3_ENABLED=true` |

When L3 is enabled, the env-driven factory now assembles a nested chain:
`CompositeAnalyzer([CompositeAnalyzer([RuleBasedAnalyzer, LLMAnalyzer]), AgentAnalyzer])`.
That keeps the three-layer contract honest: L3 is only considered after the
combined L2 result is known.

Current deterministic L3 trigger reasons are:
`manual_l3_escalate`, `suspicious_pattern`, `cumulative_risk`, and
`high_risk_complex_payload`. The new `suspicious_pattern` path currently
covers five bounded sequence families:
- secret-access-plus-network sequences
- progressive `read -> write -> exec -> sudo` escalation chains
- temporary-file staging followed by outbound exfiltration
- reconnaissance commands followed by `sudo`-backed privileged execution
- repeated secret harvest followed by archive/packaging preparation

For runtime observability, the top-level `trigger_reason` remains stable,
while suspicious-pattern traces now also expose a finer `trigger_detail`
family such as `secret_plus_network` or `secret_harvest_archive`.
That detail is now visible in `clawsentry watch`, the dashboard runtime feed,
and the session replay timeline without changing the alert taxonomy.

The archive/packaging branch is intentionally narrow: ordinary local
`tar`/`zip` packaging of build artifacts does not trigger by itself, even if
the session previously read secrets. The packaging step must visibly involve
sensitive material before it upgrades into `suspicious_pattern`. Decode-style
restore flows such as `base64 -d` are also excluded from the archive signal;
the heuristic is intentionally biased toward export/packaging behavior.
Extract-style local restore flows such as `tar -x*` / `tar x*`, `unzip`,
`gunzip`, and `gzip -dc` are also excluded, so unpacking a local archive does
not get conflated with secret export.
Archive inspection flows such as `tar tf` and `tar --list` are excluded as
well, so listing local archive contents does not get conflated with export.
Local `gzip`/`zip` inspection and validation flows such as `gzip -l`, `zip -T`,
and `zip -sf` are also excluded, so checking an archive does not get conflated
with packaging or export.
Their long-option equivalents such as `gzip --list`, `zip --test`, and
`zip --show-files` are excluded as well.
The inspection matcher is now command-token-aware rather than raw-substring
based, so `zip -t` no longer accidentally aliases `gzip -tv`. `gzip -t*`
validation flows such as `gzip -tv` and `gzip --test` are excluded explicitly.
Archive-family detection now also keys off actual shell command heads, so
printed examples such as `echo "zip ..."` or heredoc bodies that merely
contain archive commands do not get conflated with real export behavior.
Wrapped shell execution such as `bash -lc "zip ..."` and `sh -c 'tar ...'`
is now unwrapped before matching, so real nested archive/export commands are
still detected while quoted `echo` text remains excluded.
Bounded `python -c` launchers such as `os.system("zip ...")` and
`subprocess.run(['tar', ...])` are also unwrapped now, while pure debug
printing such as `python -c "print('zip ...')"` remains excluded.
That bounded launcher path now treats `subprocess.Popen(...)` consistently as
well, even after command normalization lowercases the outer `python -c`
payload.
That same bounded launcher path now also recognizes
`subprocess.check_call(...)` and `subprocess.check_output(...)` when their
first argument is a constant command string or argv list, while quoted debug
text remains excluded.
It now also recognizes `subprocess.getoutput(...)` and
`subprocess.getstatusoutput(...)` for bounded constant-string command flows,
while quoted debug text remains excluded.
The same bounded launcher path now also recognizes `os.popen(...)` for
constant-string command flows, while quoted debug text remains excluded.
It now also recognizes bounded `os.execlp(...)` argv flows, while quoted debug
text remains excluded.
It now also recognizes bounded `os.spawnlp(...)` argv flows after skipping the
leading mode argument, while quoted debug text remains excluded.
It now also recognizes bounded `os.execvp(...)` argv-list flows, while quoted
debug text remains excluded.
It now also recognizes bounded `os.spawnvp(...)` argv-list flows after skipping
the leading mode argument, while quoted debug text remains excluded.
It now also recognizes bounded `os.execv(...)` argv-list flows while ignoring
the leading executable path argument, and quoted debug text remains excluded.
It now also recognizes bounded `os.spawnv(...)` argv-list flows while skipping
the leading mode and executable path arguments, and quoted debug text remains
excluded.
It now also recognizes bounded `os.execve(...)` argv-list flows while ignoring
the leading executable path argument and trailing env mapping, and quoted debug
text remains excluded.
It now also recognizes bounded `os.spawnve(...)` argv-list flows while
skipping the leading mode and executable path arguments plus the trailing env
mapping, and quoted debug text remains excluded.
It now also recognizes bounded `os.execvpe(...)` argv-list flows while
ignoring the leading executable name argument and trailing env mapping, and
quoted debug text remains excluded.
It now also recognizes bounded `os.spawnvpe(...)` argv-list flows while
skipping the leading mode and executable name arguments plus the trailing env
mapping, and quoted debug text remains excluded.
It now also recognizes bounded vararg `os.execl(...)` and `os.spawnl(...)`
flows, plus bounded `os.execle(...)` and `os.spawnle(...)` flows that carry a
trailing env mapping, while quoted debug text remains excluded.
The same bounded launcher path now also reconstructs literal argv-list
concatenation such as `['tar'] + ['-czf', ...]`, so constant split-sequence
helpers still map back to archive/export behavior without evaluating dynamic
expressions.
It also reconstructs literal command-string concatenation such as
`'zip /tmp/secrets.zip ' + '/app/.env ...'`, so bounded `os.system(...)` and
`subprocess.*(..., shell=True)` constant helpers still map back to
archive/export behavior without evaluating dynamic expressions.
It also reconstructs literal separator joins such as
`' '.join(['zip', ...])`, plus direct `shlex.join(['zip', ...])`, so bounded
command-string helpers still map back to archive/export behavior when the
entire sequence is statically literal.
It also reconstructs bounded f-strings and positional `str.format(...)`
helpers when every fragment still reduces to a supported constant command
string, so helper-composed archive/export commands remain visible without
falling through to variable evaluation.
It also reconstructs bounded `%` formatting and direct
`subprocess.list2cmdline(...)` helpers when their inputs remain fully literal,
so more shell-oriented command builders still map back to archive/export
behavior without widening into dynamic expression evaluation.
It also reconstructs bounded `string.Template(...).substitute(...)` and
`literal_template.format_map(literal_dict)` helpers when every template input
remains fully literal, so named-template command builders remain visible
without falling through into general expression evaluation.
It now also reconstructs bounded named `str.format(...)` helpers when every
keyword value remains fully literal, so named-placeholder command builders
remain visible without widening into dynamic expression evaluation.
It now also reconstructs bounded expanded-keyword `str.format(**{...})`
helpers when every mapping entry remains fully literal, so literal expanded
placeholder mappings remain visible without widening into variable evaluation.
It now also reconstructs bounded `string.Template(...).substitute(literal_dict)`
helpers when every mapping entry remains fully literal, so positional template
mapping helpers remain visible without widening into variable evaluation.
It now also reconstructs bounded `string.Template(...).safe_substitute(...)`
helpers, including literal positional mappings, when every mapping entry
remains fully literal, so safe-substitution command builders remain visible
without widening into variable evaluation.
It now also reconstructs bounded literal `dict(...)` mapping constructors when
every keyword value remains fully literal, so constructor-based mapping helpers
remain visible without widening into dynamic mapping evaluation.

### D1-D6 Risk Dimensions

| Dim | Target | Score | Notes |
|-----|--------|-------|-------|
| **D1** | Tool type risk (bash=3, read_file=0) | 0-3 | |
| **D2** | Target path sensitivity (/etc/passwd=3, /tmp=0) | 0-3 | |
| **D3** | Command pattern (rm -rf=3, ls=0) | 0-3 | |
| **D4** | Session accumulation (high-risk event count) | 0-2 | |
| **D5** | Agent trust level | 0-2 | |
| **D6** | Injection detection (prompt injection heuristics) | 0-3 | E-4, multiplier formula |

**Composite scoring**: `base = max(D1,D2,D3)*w1 + D4*w2 + D5*w3`, then `score = base * (1.0 + 0.5 * D6/3.0)`

**Short-circuit rules**: D1=3 & D2>=2 -> CRITICAL | D3=3 -> CRITICAL | D1=D2=D3=0 -> LOW

### Post-Action Security Fence

For `POST_ACTION` events, an async post-action analyzer inspects command outputs for:
- Indirect prompt injection patterns
- Data exfiltration (10 types: curl, wget, base64, DNS, etc.)
- Obfuscation (Shannon entropy, encoding)

Tiered response: `LOG_ONLY` / `MONITOR` / `ESCALATE` / `EMERGENCY`

### Trajectory Analyzer

Multi-step attack sequence detection across session events:
- `exfil-credential`: credential file read -> outbound transfer
- `backdoor-install`: download -> permission change -> persistence
- `recon-then-exploit`: enumeration -> targeted attack
- `secret-harvest`: multiple secret file accesses
- `staged-exfil`: staging to temp -> bulk exfiltration

### Self-Evolving Pattern Repository (E-5)

High-risk events automatically extract candidate attack patterns. Patterns progress through `CANDIDATE -> EXPERIMENTAL -> STABLE -> DEPRECATED` lifecycle with confidence scoring. Controlled by `CS_EVOLVING_ENABLED`.

---

## Architecture

```
 +------------------------------------------------------------------+
 |              Framework Runtime Layer                               |
 |  +------------------+          +-------------------------+        |
 |  | a3s-code (Rust)   |          |  OpenClaw (TypeScript)   |        |
 |  |   stdio Hook      |          |  WS exec.approval        |        |
 |  +--------+---------+          +----------+--------------+        |
 +-----------|-------------------------------|---------------------+
             |                               |
 +-----------v-------------------------------v---------------------+
 |                    Adapter Layer                                  |
 |  +------------------+     +------------------------------+      |
 |  |  A3SCodeAdapter   |     |  OpenClawAdapter + WS Client |      |
 |  |  + Harness bridge |     |  + Webhook Receiver          |      |
 |  +--------+---------+     +----------+-------------------+      |
 +-----------|--------------------------|------------------------+
             |   UDS / HTTP (JSON-RPC)  |
 +-----------v--------------------------v------------------------+
 |              ClawSentry  -  AHP Supervision Gateway             |
 |                                                                  |
 |  +----------+  +----------+  +----------+  +---------------+   |
 |  | L1 Rules |->| L2 LLM   |->| L3 Agent |->| Decision      |   |
 |  | D1-D6    |  | Semantic |  | Toolkit  |  | Router        |   |
 |  | <0.3ms   |  | <3s      |  | <30s     |  | allow/block/  |   |
 |  +----------+  +----------+  +----------+  | modify/defer  |   |
 |                                              +-------+-------+   |
 |  +---------------+  +--------------+  +----------v--------+    |
 |  | D6 Injection  |  | Post-Action  |  | TrajectoryStore   |    |
 |  | Detector      |  | Analyzer     |  | SQLite audit      |    |
 |  +---------------+  +--------------+  +-------------------+    |
 |                                                                  |
 |  +---------------+  +--------------+  +-------------------+    |
 |  | SessionRegistry|  | AlertRegistry|  | PatternEvolution  |    |
 |  | + EventBus/SSE|  | + AttackPats |  | Self-evolving     |    |
 |  +---------------+  +--------------+  +-------------------+    |
 |                                                                  |
 |  +-------------------+                +-------------------+     |
 |  | DetectionConfig   |                | Web Dashboard     |     |
 |  | 17 CS_* env vars  |                | React SPA at /ui  |     |
 |  +-------------------+                +-------------------+     |
 +------------------------------------------------------------------+
```

**Design principles**:

| Principle | Description |
|-----------|-------------|
| Protocol-first | Solve cross-framework interop before stacking policies |
| Centralized decisions | All final decisions from Gateway; adapters don't decide |
| Dual-channel | pre-action sync blocking, post-action async audit |
| Escalate only | L2/L3 can only raise risk level, never lower it |
| Adapter-specific fallback | Direct AHP endpoints can fail closed; native CLI hooks may fail open when required to preserve host usability |

---

## Quick Start

### Install

```bash
pip install clawsentry            # Base
pip install "clawsentry[llm]"     # + LLM semantic analysis
pip install "clawsentry[all]"     # Everything

# Development
git clone <repo-url> && cd ClawSentry
pip install -e ".[dev]"
```

### OpenClaw Users

```bash
clawsentry init openclaw --auto-detect   # Auto-detect ~/.openclaw config
clawsentry init openclaw --setup         # Configure OpenClaw settings
clawsentry start --framework openclaw    # Project env only (no ~/.openclaw edits)
clawsentry start --framework openclaw --setup-openclaw
clawsentry gateway                        # Start (auto-detects OpenClaw)
clawsentry watch                          # Real-time monitoring
# Browser: http://127.0.0.1:8080/ui      # Web dashboard
```

### a3s-code Users

```bash
clawsentry init a3s-code
clawsentry gateway
clawsentry watch
```

---

## Framework Compatibility

| Framework | Integration mode | Pre-action interception | Post-action observation | Main dependency | Maturity |
|---------|-------------------|-------------------------|-------------------------|-----------------|----------|
| `a3s-code` | Explicit SDK transport + `clawsentry-harness` | Yes | Yes | Agent code must wire `SessionOptions.ahp_transport` | High |
| `openclaw` | WebSocket approvals + webhook receiver | Yes | Yes | `~/.openclaw/` must be configured for gateway exec + callbacks | Medium-high |
| `codex` | Session JSONL watcher + managed native hooks | Managed `PreToolUse(Bash)` preflight response path + `PermissionRequest(Bash|apply_patch|Edit|Write|mcp__.*)` approval gate when started through `clawsentry start --framework codex` | Yes, including async compact observation | Session logs / `$CODEX_HOME/hooks.json` managed entries must be reachable | Medium-high |
| `gemini-cli` | Gemini CLI native command hooks | Yes; `BeforeTool` can deny shell commands | Yes, with post-tool caveat | Project `.gemini/settings.json` managed hooks; global home only with explicit `--gemini-home` | Medium-high (`real_beforetool_block_supported`) |
| `kimi-cli` | Kimi CLI native `[[hooks]]` | Yes; `PreToolUse` / prompt deny via Kimi permission decision | Yes, observation-only for post/session/subagent/compact/notification | `$KIMI_SHARE_DIR/config.toml` or `~/.kimi/config.toml` marker-managed hooks | Medium-high (`native_hook_allow_block_supported`) |
| `claude-code` | Host hooks + `clawsentry-harness` | Yes | Yes | `~/.claude/settings.json` hooks must remain installed | Medium |

Operational boundary notes:

- `codex` now gets managed native hooks by default through `clawsentry start --framework codex`, without replacing user or third-party hooks. The startup banner prints `clawsentry init codex --uninstall` for removal. The synchronous response surface is intentionally narrow: `PreToolUse(Bash)` sends a deny response when Gateway returns block/defer, and `PermissionRequest(Bash|apply_patch|Edit|Write|mcp__.*)` can allow/deny approval requests; non-Bash `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`, `SessionStart(startup|resume|clear)`, `PreCompact`, and `PostCompact` stay async advisory/observational.
- `gemini-cli` uses Gemini native command hooks via `clawsentry init gemini-cli --setup`, defaulting to project-local `.gemini/settings.json`. Shell-tool events are canonicalized before policy evaluation. Do not treat Kimi/OpenAI-compatible endpoints as directly supported by Gemini CLI.
- Gemini managed hook commands redirect diagnostics away from stderr and fail open if the harness process itself cannot start, because Gemini can interpret plain stderr text as hook output.
- `kimi-cli` uses Kimi native `[[hooks]]` through `clawsentry init kimi-cli --setup`. It can block dangerous tool calls through `PreToolUse`, block prompts through `UserPromptSubmit`, and record safe Shell plus lifecycle observation events. Native tool-input rewrite and true `defer` parity with `a3s-code` are not supported; those effects are reported as degraded/unsupported in adapter reporting.
- `a3s-code` should be documented as explicit SDK transport wiring, not `.a3s-code/settings.json` auto-loading.
- `openclaw` and `claude-code` provide strong coverage only when host-side setup remains intact.

For a machine-readable local view of the same boundaries, run
`clawsentry integrations status --json`.
The command now also emits per-framework readiness diagnostics with concrete
next steps, and `clawsentry start` reuses the same summary in its startup
banner.

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `clawsentry gateway` | Start Gateway (auto-detects framework, starts WS/Webhook as needed) |
| `clawsentry start` | Auto-init + Gateway + watch; supports `--frameworks`, explicit `--setup-openclaw`, and startup readiness summaries |
| `clawsentry integrations status` | Inspect enabled frameworks, host-side diagnostics, framework capability summaries, and per-framework readiness |
| `clawsentry watch` | SSE real-time display (`--filter`/`--json`/`--no-color`/`--interactive`) |
| `clawsentry init <framework>` | Initialize config (`a3s-code`/`claude-code`/`codex`/`gemini-cli`/`kimi-cli`/`openclaw`) |
| `clawsentry harness` | a3s-code stdio bridge subprocess |
| `clawsentry rules lint` | Authoring-time validation for attack patterns + review skills (`--json`) |
| `clawsentry rules dry-run` | Replay sample canonical events against current rule surfaces (`--events`, `--json`; accepts JSON object / array / JSONL) |
| `clawsentry rules report` | Write combined lint/dry-run JSON and optional markdown dashboard artifacts for CI or release evidence (`--output`, optional `--events`, optional `--summary-markdown`) |

### Rule Governance

`clawsentry rules` is the rule-governance entrypoint. It is intentionally
narrow: it validates and dry-runs the existing YAML rule assets instead of
introducing a runtime DSL for L1/L2/L3 control flow.

```bash
clawsentry rules lint --json
clawsentry rules dry-run --events examples/sample-events.jsonl --json
clawsentry rules report \
  --output artifacts/rules-report.json \
  --events examples/sample-events.jsonl \
  --summary-markdown artifacts/rules-dashboard.md
```

`rules lint` reports schema / duplicate / conflict findings for attack
patterns and review skills. `rules dry-run` replays sample canonical events
from a JSON object, JSON array, or JSONL file through the current
attack-pattern matcher and review-skill selector so authors can preview
policy effects before rollout. `rules report` combines those checks into a
stable JSON artifact with `status`, `exit_code`, per-check summaries, the
deterministic fingerprint, and optional dry-run results for CI/release records.
When `--summary-markdown` is provided, it also writes a human-readable rollout
dashboard summarizing status, findings, and dry-run event coverage.

---

## API Endpoints

All endpoints require `Authorization: Bearer <token>` (except `/health` and `/ui`).

| Method | Path | Description |
|--------|------|-------------|
| POST | `/ahp` | JSON-RPC sync decision |
| POST | `/ahp/resolve` | DEFER resolution proxy |
| GET | `/ahp/patterns` | List attack patterns (core + evolved) |
| POST | `/ahp/patterns/confirm` | Confirm/reject evolved pattern |
| GET | `/health` | Health check (no auth) |
| GET | `/report/summary` | Cross-framework aggregate stats |
| GET | `/report/sessions` | Active sessions + risk ranking |
| GET | `/report/session/{id}` | Session trajectory replay |
| GET | `/report/session/{id}/risk` | Session risk detail + D1-D6 timeline |
| GET | `/report/stream` | SSE real-time events |
| GET | `/report/alerts` | Alert list (filter: severity/acknowledged) |
| POST | `/report/alerts/{id}/acknowledge` | Acknowledge alert |
| GET | `/ui` | Web dashboard SPA (no auth) |

---

## Web Dashboard

Built-in React SPA operator console at `/ui`. Light-first premium dashboard with real-time SSE data and a summary-first landing view.

`clawsentry start` prints a Web UI URL such as
`http://127.0.0.1:8080/ui?token=...`. The page saves that token to
`sessionStorage`, strips `?token=` from the address bar, and then calls the
Gateway. Manual login uses the same `CS_AUTH_TOKEN`. An `invalid token` / `401`
message means the value does not match `CS_AUTH_TOKEN`; `Gateway unavailable`
means the local Gateway cannot be reached and is not a credential failure. In
proxy-heavy shells, set `NO_PROXY=localhost,127.0.0.1,::1` for loopback Gateway
calls.

| Page | Features |
|------|----------|
| **Dashboard** | Operator brief + live decision feed + metric cards + risk overview |
| **Sessions** | Active sessions + D1-D6 radar + risk curve + decision timeline |
| **Alerts** | Alert table + severity filter + acknowledge + SSE auto-push |
| **DEFER Panel** | Pending decisions + countdown + Allow/Deny buttons |

Tech stack: React 18 + TypeScript + Vite + recharts + lucide-react

---

## Project Structure

```
src/clawsentry/
|-- gateway/                           # Core supervision engine
|   |-- models.py                      # Unified data models (CanonicalEvent/Decision/RiskSnapshot)
|   |-- server.py                      # FastAPI HTTP + UDS + Auth + SSE + static files
|   |-- stack.py                       # One-click start: Gateway + OpenClaw runtime + DEFER
|   |-- policy_engine.py               # L1 rules + L2 Analyzer integration
|   |-- risk_snapshot.py               # D1-D6 six-dimensional risk assessment
|   |-- injection_detector.py          # D6 injection detection (weak/strong patterns + canary)
|   |-- post_action_analyzer.py        # Post-action security fence (exfil/injection/obfuscation)
|   |-- trajectory_analyzer.py         # Multi-step attack sequence detection (5 sequences)
|   |-- pattern_matcher.py             # Attack pattern matching engine (25 OWASP ASI patterns)
|   |-- pattern_evolution.py           # Self-evolving pattern repository (E-5)
|   |-- detection_config.py            # DetectionConfig (17 tunable CS_* env vars)
|   |-- semantic_analyzer.py           # L2 pluggable semantic (Protocol + 3 implementations)
|   |-- llm_provider.py                # LLM Provider base (Anthropic/OpenAI)
|   |-- llm_factory.py                 # Environment-driven analyzer builder
|   |-- agent_analyzer.py              # L3 review Agent (multi-turn default + legacy single-turn fallback)
|   |-- review_toolkit.py              # L3 ReadOnlyToolkit (7 read-only tools incl. transcript/session risk)
|   |-- review_skills.py               # L3 SkillRegistry (YAML load/select)
|   |-- l3_trigger.py                  # L3 trigger policy (explicit trigger reasons)
|   |-- idempotency.py                 # Request idempotency cache
|   +-- skills/                        # 6 built-in review domain skills (YAML)
|-- adapters/                          # Framework adapters
|   |-- a3s_adapter.py                 # a3s-code Hook -> CanonicalEvent normalization
|   |-- a3s_gateway_harness.py         # a3s-code stdio bridge (JSON-RPC 2.0)
|   |-- openclaw_adapter.py            # OpenClaw main adapter (approval state machine)
|   |-- openclaw_normalizer.py         # OpenClaw event normalization
|   |-- openclaw_ws_client.py          # OpenClaw WS client (listen + resolve)
|   |-- openclaw_webhook_receiver.py   # OpenClaw Webhook secure receiver
|   |-- openclaw_gateway_client.py     # OpenClaw -> Gateway RPC client
|   |-- openclaw_approval.py           # Approval lifecycle state machine
|   |-- openclaw_bootstrap.py          # OpenClaw unified config factory
|   +-- webhook_security.py            # Token + HMAC verification
|-- cli/                               # Unified CLI
|   |-- main.py                        # clawsentry entry (init/gateway/watch/harness)
|   |-- init_command.py                # init + --setup + --auto-detect
|   |-- start_command.py               # Framework detection + start routing
|   |-- watch_command.py               # watch SSE terminal + --interactive DEFER
|   |-- dotenv_loader.py               # explicit env-file parser
|   +-- initializers/                  # Framework initializers (openclaw/a3s_code)
|-- ui/                                # Web security dashboard (React SPA)
|   |-- src/                           # TypeScript source
|   +-- dist/                          # Pre-built artifacts (shipped with pip)
+-- tests/                             # Public Python regression suite (3456 passed / 16 skipped)
```

---

## Configuration

### Core

| Variable | Default | Description |
|----------|---------|-------------|
| `CS_AUTH_TOKEN` | (disabled) | HTTP Bearer token (>= 32 chars recommended) |
| `CS_HTTP_HOST` | `127.0.0.1` | HTTP bind address |
| `CS_HTTP_PORT` | `8080` | HTTP port |
| `CS_UDS_PATH` | `/tmp/clawsentry.sock` | UDS listen path |
| `CS_TRAJECTORY_DB_PATH` | `/tmp/clawsentry-trajectory.db` | SQLite trajectory file |

### Detection Tuning (CS_*)

| Variable | Default | Description |
|----------|---------|-------------|
| `CS_COMPOSITE_WEIGHT_MAX_D123` | `0.6` | Weight for max(D1,D2,D3) |
| `CS_COMPOSITE_WEIGHT_D4` | `0.25` | Weight for D4 session risk |
| `CS_COMPOSITE_WEIGHT_D5` | `0.15` | Weight for D5 trust |
| `CS_D6_INJECTION_MULTIPLIER` | `0.5` | D6 multiplier coefficient |
| `CS_THRESHOLD_CRITICAL` | `2.2` | Score threshold for CRITICAL |
| `CS_THRESHOLD_HIGH` | `1.5` | Score threshold for HIGH |
| `CS_THRESHOLD_MEDIUM` | `0.8` | Score threshold for MEDIUM |
| `CS_L2_BUDGET_MS` | `3000` | L2 analysis time budget (ms) |
| `CS_ATTACK_PATTERNS_PATH` | (built-in) | Custom attack patterns YAML |
| `CS_EVOLVING_ENABLED` | `false` | Enable self-evolving pattern repository |
| `CS_EVOLVED_PATTERNS_PATH` | (none) | Path for evolved patterns YAML |
| `CS_POST_ACTION_EMERGENCY` | `0.9` | Post-action EMERGENCY tier threshold |
| `CS_POST_ACTION_ESCALATE` | `0.6` | Post-action ESCALATE tier threshold |
| `CS_POST_ACTION_MONITOR` | `0.3` | Post-action MONITOR tier threshold |

### LLM

| Variable | Description |
|----------|-------------|
| `CS_LLM_PROVIDER` | `anthropic` / `openai` |
| `CS_LLM_BASE_URL` | Custom API endpoint |
| `CS_LLM_MODEL` | Model name |
| `CS_L3_ENABLED` | Enable L3 review Agent |
| `CS_L3_MULTI_TURN` | L3 runtime mode guard; defaults to multi-turn, only `false`/`0`/`no`/`off` forces legacy single-turn |
| `CS_L3_ADVISORY_ASYNC_ENABLED` | Auto-create frozen advisory snapshots after high/critical decisions or high+ trajectory alerts (default off; automatic snapshots do not run a real review scheduler) |
| `CS_L3_HEARTBEAT_REVIEW_ENABLED` | Reserved heartbeat/idle advisory snapshot review trigger (default off; no timer-only review is started by the current implementation) |
| `CS_LLM_TEMPERATURE` | Shared LLM provider temperature for L2/L3/advisory provider calls |
| `CS_LLM_PROVIDER_TIMEOUT_MS` | Shared LLM provider timeout for L2/L3/advisory provider calls |
| `CS_L3_ADVISORY_RUN_REAL_SMOKE` | Pytest real-provider smoke gate; defaults to skip |
| `CS_L3_ADVISORY_SMOKE_STRIP_PROXY_ENV` | Manual smoke proxy hygiene; defaults to `true` |

When `CS_L3_ENABLED=true`, the env-driven factory now defaults L3 to `multi_turn`.
Set `CS_L3_MULTI_TURN=false` only when you intentionally need the older single-turn behavior. The
`clawsentry test-llm` probe surfaces the active L3 mode and trigger reason in
its detail output so operators can verify the runtime path.

### L3 Advisory Review and Full Review

L3 advisory review adds a separate bounded evidence workflow without
changing canonical decisions. Operators can create a frozen
`l3_evidence_snapshot` over a bounded trajectory record range, then attach an
`l3_advisory_review` result marked `advisory_only=true`. When
`CS_L3_ADVISORY_ASYNC_ENABLED=true`, high/critical decisions and high+
trajectory alerts automatically create frozen advisory snapshots. These records
are surfaced through report/session/replay payloads and SSE events
(`l3_advisory_snapshot`, `l3_advisory_review`) but never retroactively mutate
the original `allow` / `block` decision or run a real background L3 review by
default.

The default `llm_provider` worker runner reuses the shared `CS_LLM_*`
configuration (`CS_LLM_PROVIDER`, provider API key, `CS_LLM_MODEL`,
`CS_LLM_BASE_URL`, `CS_LLM_TEMPERATURE`, and `CS_LLM_PROVIDER_TIMEOUT_MS`).
When that configuration is missing or invalid, full-review completes with a
`degraded` advisory review and an explicit provider/config reason instead of
silently falling back to local deterministic review.

For operator-controlled readiness checks, use the packaged manual smoke helper:

```bash
CS_LLM_PROVIDER=openai \
CS_LLM_MODEL=gpt-advisory-smoke \
OPENAI_API_KEY=sk-... \
python -m clawsentry.devtools.l3_advisory_provider_smoke \
  --output-report l3-advisory-provider-smoke-readiness.md
```

The provider smoke creates a frozen snapshot, queues one `llm_provider` job, and
runs it once. Without valid `CS_LLM_*` configuration it records a degraded review;
use `--require-completed` for real-provider validation. Pytest real-network smoke
additionally requires `CS_L3_ADVISORY_RUN_REAL_SMOKE=true`; otherwise it is
skipped by default.

Operators can also trigger a bounded full advisory review explicitly:

```http
POST /report/session/{session_id}/l3-advisory/full-review
```

This endpoint creates an `operator_full_review` frozen snapshot, queues one
advisory job, and can either leave it queued (`run=false`) or execute exactly one
runner. Omitting `runner` uses `llm_provider`; pass `runner=deterministic_local`
only for the explicit local support path. The response is always advisory-only
and includes `canonical_decision_mutated=false`.

CLI equivalent:

```bash
clawsentry l3 full-review \
  --session <session-id> \
  --runner deterministic_local \
  --queue-only
```

### OpenClaw

| Variable | Description |
|----------|-------------|
| `OPENCLAW_WS_URL` | OpenClaw Gateway WS URL |
| `OPENCLAW_OPERATOR_TOKEN` | Operator token |
| `OPENCLAW_ENFORCEMENT_ENABLED` | Enable enforcement mode |
| `OPENCLAW_WEBHOOK_TOKEN` | Webhook auth token |
| `OPENCLAW_WEBHOOK_SECRET` | Webhook HMAC secret |

### Session Enforcement

| Variable | Default | Description |
|----------|---------|-------------|
| `AHP_SESSION_ENFORCEMENT_ENABLED` | `false` | Enable session-level cumulative enforcement |
| `AHP_SESSION_ENFORCEMENT_THRESHOLD` | `3` | High-risk event accumulation threshold |
| `AHP_SESSION_ENFORCEMENT_ACTION` | `defer` | Action on trigger (`defer`/`block`/`l3_require`) |

---

## Running Tests

```bash
pip install -e ".[dev]"

# Full suite
python -m pytest src/clawsentry/tests/ -v --tb=short
# Expected: current public release validation 3456 passed, 16 skipped

# E2E (requires LLM API key)
A3S_SDK_E2E=1 python -m pytest src/clawsentry/tests/ -v --tb=short
# Runs additional a3s-code SDK E2E coverage when a3s_code, agent.hcl, and credentials are available

# By module
python -m pytest src/clawsentry/tests/test_risk_and_policy.py -v
python -m pytest src/clawsentry/tests/test_injection_detector.py -v
python -m pytest src/clawsentry/tests/test_post_action_analyzer.py -v
python -m pytest src/clawsentry/tests/test_trajectory_analyzer.py -v
python -m pytest src/clawsentry/tests/test_pattern_evolution.py -v
python -m pytest src/clawsentry/tests/test_ws_gateway_integration.py -v
python -m pytest src/clawsentry/tests/test_openclaw_e2e.py -v
python -m pytest src/clawsentry/tests/test_detection_config.py -v
```

### Decision Effects, Session Quarantine, and Rewrite

ClawSentry can attach request-only `decision_effects` metadata to canonical decisions without changing the stable `allow/block/modify/defer` verdict set.

- `block + action_scope=session` marks a session as quarantined; v1 blocks subsequent same-session `pre_action` events but does not terminate the host process.
- `modify + modified_payload + rewrite_effect` supports audited command/tool-input rewrite. The host response may include the replacement payload; persisted replay/reporting surfaces keep hashes and redacted previews by default.
- Adapter outcomes are recorded separately via `adapter_effect_result` records and `/ahp/adapter-effect-result`, so unsupported hosts are reported as degraded/unsupported instead of falsely enforced.
