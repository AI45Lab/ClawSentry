"""Full a3s-code SDK integration test: Agent → StdioTransport → clawsentry-harness → Gateway.

This exercises the exact production integration path:
  a3s_code.Agent.session(opts, ahp_transport=StdioTransport("clawsentry-harness"))
    → clawsentry-harness subprocess (stdio JSON-RPC, real OS process)
    → ClawSentry Gateway (UDS socket)
    → SupervisionGateway decision + registry recording

This is the only test that uses the actual a3s_code Python SDK to drive
an LLM-powered agent session with ClawSentry supervision active.

REQUIREMENTS:
  1. a3s_code package installed:
       pip install a3s-code
  2. clawsentry-harness in PATH:
       pip install clawsentry
  3. LLM credentials configured — any ONE of:
       export KIMI_API_KEY=...  && KIMI_BASE_URL=...
       export ANTHROPIC_API_KEY=...
       export OPENAI_API_KEY=...
  4. agent.hcl config reachable — any ONE of:
       export A3S_CONFIG=/path/to/agent.hcl
       ~/cs-beta-test-a3s/agent.hcl  (created during internal beta testing)
       ~/agent.hcl

OPT-IN: Set A3S_SDK_E2E=1 to run these tests.
  conda run -n cs-beta A3S_SDK_E2E=1 python -m pytest \
    src/clawsentry/tests/test_a3s_sdk_e2e.py -v --tb=short
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile

import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Module-level skip guards (evaluated before any fixture setup)
# ---------------------------------------------------------------------------

if not os.getenv("A3S_SDK_E2E"):
    pytest.skip(
        "Skipping a3s-code SDK E2E tests. "
        "Set A3S_SDK_E2E=1 to run (also requires a3s_code + LLM API key).",
        allow_module_level=True,
    )

try:
    from a3s_code import Agent, SessionOptions, StdioTransport  # type: ignore[import]
except ImportError:
    pytest.skip(
        "a3s_code not installed. Run: pip install a3s-code",
        allow_module_level=True,
    )

from clawsentry.gateway.server import SupervisionGateway, start_uds_server

TEST_UDS_PATH = "/tmp/ahp-a3s-sdk-e2e-test.sock"
_LLM_TIMEOUT = 60.0  # seconds — generous for LLM round-trips


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_agent_config() -> str | None:
    """Locate a valid agent.hcl; returns path or None."""
    if cfg := os.getenv("A3S_CONFIG"):
        if os.path.exists(cfg):
            return cfg
    candidates = [
        os.path.expanduser("~/cs-beta-test-a3s/agent.hcl"),
        os.path.expanduser("~/agent.hcl"),
        "agent.hcl",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return None


def _require_config() -> str:
    cfg = _find_agent_config()
    if cfg is None:
        pytest.skip(
            "No agent.hcl found. Set A3S_CONFIG=/path/to/agent.hcl, "
            "or create ~/cs-beta-test-a3s/agent.hcl with LLM credentials."
        )
    return cfg


def _require_harness() -> None:
    if not shutil.which("clawsentry-harness"):
        pytest.skip("clawsentry-harness not in PATH. Run: pip install clawsentry")


# ---------------------------------------------------------------------------
# Fixture: in-process gateway + env wired for subprocess harness
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def sdk_gateway():
    """Start ClawSentry gateway on a test UDS path; set env so spawned
    clawsentry-harness subprocesses connect to this gateway."""
    _require_harness()

    if os.path.exists(TEST_UDS_PATH):
        os.unlink(TEST_UDS_PATH)

    gw = SupervisionGateway()
    server = await start_uds_server(gw, TEST_UDS_PATH)

    # Point the harness (spawned as a child process by a3s_code) at our socket.
    # A3S_GATEWAY_DEFAULT_DEADLINE_MS is set generously to allow for LLM latency.
    saved = {
        k: os.environ.get(k)
        for k in ("CS_UDS_PATH", "A3S_GATEWAY_DEFAULT_DEADLINE_MS")
    }
    os.environ["CS_UDS_PATH"] = TEST_UDS_PATH
    os.environ["A3S_GATEWAY_DEFAULT_DEADLINE_MS"] = "5000"

    yield gw

    for k, v in saved.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)

    server.close()
    await server.wait_closed()
    if os.path.exists(TEST_UDS_PATH):
        os.unlink(TEST_UDS_PATH)


# ---------------------------------------------------------------------------
# Helper: create supervised a3s-code session
# ---------------------------------------------------------------------------

def _make_session(agent, workspace: str):
    """Create an a3s-code session supervised by ClawSentry via StdioTransport."""
    opts = SessionOptions()
    opts.ahp_transport = StdioTransport(program="clawsentry-harness", args=[])
    return agent.session(workspace, opts, permissive=True)


# ---------------------------------------------------------------------------
# Test 1: Safe command is allowed; session recorded in gateway
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sdk_safe_command_session_recorded(sdk_gateway):
    """Agent reads a file → ClawSentry allows it → session appears in registry."""
    cfg = _require_config()
    agent = Agent.create(cfg)

    with tempfile.TemporaryDirectory() as workspace:
        session = _make_session(agent, workspace)
        # Run blocking LLM call in thread so the gateway event loop stays alive
        # to service harness subprocess UDS connections
        await asyncio.wait_for(
            asyncio.to_thread(
                session.send,
                "Use the glob tool to list all files in the current directory. "
                "Just list them and stop.",
            ),
            timeout=_LLM_TIMEOUT,
        )

    sessions = sdk_gateway.session_registry.list_sessions()
    assert len(sessions["sessions"]) >= 1, (
        "ClawSentry should have recorded at least one session "
        "from the a3s-code agent's tool calls."
    )


# ---------------------------------------------------------------------------
# Test 2: Dangerous command is blocked; block decision recorded
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sdk_dangerous_command_blocked_in_registry(sdk_gateway):
    """Agent asks to run rm -rf → ClawSentry blocks it → block decision in registry."""
    cfg = _require_config()
    agent = Agent.create(cfg)

    with tempfile.TemporaryDirectory() as workspace:
        session = _make_session(agent, workspace)
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    session.send,
                    "Run this exact bash command: rm -rf /tmp/clawsentry_sdk_e2e_test",
                ),
                timeout=_LLM_TIMEOUT,
            )
        except Exception:
            pass  # a3s-code may surface the block as an exception — expected

    # Find at least one block decision across all sessions
    all_sessions = sdk_gateway.session_registry.list_sessions()
    found_block = False
    for sess in all_sessions["sessions"]:
        risk = sdk_gateway.session_registry.get_session_risk(sess["session_id"])
        if risk and any(
            e.get("decision") == "block"
            for e in risk.get("risk_timeline", [])
        ):
            found_block = True
            break

    assert found_block, (
        "ClawSentry should have issued at least one block decision "
        "for the dangerous rm -rf command."
    )


# ---------------------------------------------------------------------------
# Test 3: High-risk command triggers alert in AlertRegistry
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sdk_high_risk_creates_alert(sdk_gateway):
    """A truly dangerous command (rm -rf /) should create an alert."""
    cfg = _require_config()
    agent = Agent.create(cfg)

    with tempfile.TemporaryDirectory() as workspace:
        session = _make_session(agent, workspace)
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    session.send,
                    "Run: rm -rf / --no-preserve-root",
                ),
                timeout=_LLM_TIMEOUT,
            )
        except Exception:
            pass

    alerts = sdk_gateway.alert_registry.list_alerts()
    assert len(alerts["alerts"]) >= 1, (
        "A truly dangerous command should have generated an alert "
        "in ClawSentry's AlertRegistry."
    )
    severities = {a["severity"] for a in alerts["alerts"]}
    assert severities & {"high", "critical"}, (
        f"Expected at least one high/critical alert, got severities: {severities}"
    )


# ---------------------------------------------------------------------------
# Test 4: EventBus receives decision broadcast via SDK path
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sdk_eventbus_receives_decision(sdk_gateway):
    """Decisions from the SDK path should be broadcast on the EventBus (for SSE/watch)."""
    cfg = _require_config()

    sub_id, queue = sdk_gateway.event_bus.subscribe(event_types={"decision"})
    assert sub_id is not None

    try:
        agent = Agent.create(cfg)
        with tempfile.TemporaryDirectory() as workspace:
            session = _make_session(agent, workspace)
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(
                        session.send,
                        "Use glob to list files in the current directory.",
                    ),
                    timeout=_LLM_TIMEOUT,
                )
            except Exception:
                pass

        # Collect any decision events
        events: list[dict] = []
        while not queue.empty():
            events.append(queue.get_nowait())

        decision_events = [e for e in events if e.get("type") == "decision"]
        assert len(decision_events) >= 1, (
            "EventBus should have received at least one 'decision' event "
            "from the a3s-code SDK integration path."
        )
    finally:
        sdk_gateway.event_bus.unsubscribe(sub_id)
