"""Subprocess integration tests: clawsentry-harness as a real OS process.

Unlike test_a3s_gateway_harness.py (in-process dispatch_async calls),
these tests spawn the real `clawsentry-harness` binary and communicate
over stdio JSON-RPC — the exact process boundary that a3s-code's
StdioTransport uses in production.

This fills the gap between:
  - In-process harness tests (existing)
  - Full a3s-code SDK tests (test_a3s_sdk_e2e.py, requires LLM)

Run condition: clawsentry-harness must be installed and in PATH.
  pip install clawsentry  (or pip install -e .[dev] in dev environment)
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil

import pytest
import pytest_asyncio

from clawsentry.gateway.server import SupervisionGateway, start_uds_server

TEST_UDS_PATH = "/tmp/ahp-harness-subprocess-test.sock"
_HARNESS_DEADLINE_MS = 500
_SUBPROCESS_TIMEOUT = 15.0


# ---------------------------------------------------------------------------
# Skip guard
# ---------------------------------------------------------------------------

def _require_harness() -> None:
    if not shutil.which("clawsentry-harness"):
        pytest.skip(
            "clawsentry-harness not found in PATH. "
            "Install the package first: pip install clawsentry"
        )


# ---------------------------------------------------------------------------
# Fixture: in-process gateway on test UDS path
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def sub_gateway():
    """Start a ClawSentry gateway on the test UDS path."""
    if os.path.exists(TEST_UDS_PATH):
        os.unlink(TEST_UDS_PATH)

    gw = SupervisionGateway()
    server = await start_uds_server(gw, TEST_UDS_PATH)
    yield gw
    server.close()
    await server.wait_closed()
    if os.path.exists(TEST_UDS_PATH):
        os.unlink(TEST_UDS_PATH)


# ---------------------------------------------------------------------------
# Helper: spawn harness subprocess, send messages, collect responses
# ---------------------------------------------------------------------------

async def _run_harness(messages: list[dict]) -> list[dict]:
    """Spawn clawsentry-harness, pipe JSON-RPC messages, return parsed responses."""
    _require_harness()

    env = os.environ.copy()
    env["CS_UDS_PATH"] = TEST_UDS_PATH
    env["A3S_GATEWAY_DEFAULT_DEADLINE_MS"] = str(_HARNESS_DEADLINE_MS)

    proc = await asyncio.create_subprocess_exec(
        "clawsentry-harness",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    assert proc.stdin is not None
    assert proc.stdout is not None

    stdin_bytes = ("\n".join(json.dumps(m) for m in messages) + "\n").encode()
    stdout_bytes, _ = await asyncio.wait_for(
        proc.communicate(stdin_bytes),
        timeout=_SUBPROCESS_TIMEOUT,
    )

    responses: list[dict] = []
    for line in stdout_bytes.decode().splitlines():
        line = line.strip()
        if line:
            responses.append(json.loads(line))
    return responses


def _pre_event(req_id: int, tool: str, command: str = "", path: str = "",
               session_id: str = "sub-test-sess") -> dict:
    arguments: dict = {}
    if command:
        arguments["command"] = command
    if path:
        arguments["path"] = path
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "method": "ahp/event",
        "params": {
            "event_type": "pre_action",
            "session_id": session_id,
            "agent_id": "sub-test-agent",
            "payload": {"tool": tool, "arguments": arguments},
        },
    }


# ---------------------------------------------------------------------------
# Test 1: Handshake over real subprocess stdio
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_handshake(sub_gateway):
    responses = await _run_harness([
        {"jsonrpc": "2.0", "id": 1, "method": "ahp/handshake", "params": {}},
    ])
    assert len(responses) == 1
    r = responses[0]
    assert r["id"] == 1
    assert r["result"]["protocol_version"] == "2.0"
    assert "pre_action" in r["result"]["harness_info"]["capabilities"]


# ---------------------------------------------------------------------------
# Test 2: Safe read_file → allow
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_allows_safe_read(sub_gateway):
    responses = await _run_harness([
        {"jsonrpc": "2.0", "id": 1, "method": "ahp/handshake", "params": {}},
        _pre_event(2, "read_file", path="/tmp/safe.txt", session_id="sub-allow-1"),
    ])
    assert len(responses) == 2
    result = responses[1]["result"]
    assert result["decision"] == "allow"
    assert result["action"] == "continue"


# ---------------------------------------------------------------------------
# Test 3: Dangerous rm -rf → block
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_blocks_dangerous_rm(sub_gateway):
    responses = await _run_harness([
        {"jsonrpc": "2.0", "id": 1, "method": "ahp/handshake", "params": {}},
        _pre_event(2, "bash", command="rm -rf /important-data", session_id="sub-block-1"),
    ])
    assert len(responses) == 2
    result = responses[1]["result"]
    assert result["decision"] == "block"
    assert result["action"] == "block"
    assert result["reason"]  # non-empty reason string


# ---------------------------------------------------------------------------
# Test 4: post_action passes through (audit-only, no blocking)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_post_action_passthrough(sub_gateway):
    responses = await _run_harness([
        {"jsonrpc": "2.0", "id": 1, "method": "ahp/handshake", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ahp/event",
            "params": {
                "event_type": "post_action",
                "session_id": "sub-post-1",
                "agent_id": "sub-test-agent",
                "payload": {
                    "tool": "read_file",
                    "arguments": {"path": "/tmp/out.txt"},
                    "output": "file contents here",
                },
            },
        },
    ])
    assert len(responses) == 2
    result = responses[1]["result"]
    assert result["action"] in ("continue", "allow")


# ---------------------------------------------------------------------------
# Test 5: Multiple events in a single harness invocation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_multiple_events_sequentially(sub_gateway):
    responses = await _run_harness([
        {"jsonrpc": "2.0", "id": 1, "method": "ahp/handshake", "params": {}},
        _pre_event(2, "read_file", path="/tmp/a.txt", session_id="sub-multi"),
        _pre_event(3, "read_file", path="/tmp/b.txt", session_id="sub-multi"),
        _pre_event(4, "bash", command="rm -rf /tmp/secret_dir", session_id="sub-multi"),
    ])
    assert len(responses) == 4
    assert responses[1]["result"]["decision"] == "allow"   # read_file: safe
    assert responses[2]["result"]["decision"] == "allow"   # read_file: safe
    assert responses[3]["result"]["decision"] == "block"   # rm -rf: dangerous


# ---------------------------------------------------------------------------
# Test 6: Harness response contains metadata from gateway
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_response_contains_metadata(sub_gateway):
    responses = await _run_harness([
        {"jsonrpc": "2.0", "id": 1, "method": "ahp/handshake", "params": {}},
        _pre_event(2, "bash", command="cat /etc/shadow", session_id="sub-meta-1"),
    ])
    assert len(responses) == 2
    result = responses[1]["result"]
    assert "metadata" in result
    meta = result["metadata"]
    assert meta["source"] == "clawsentry-gateway-harness"
    assert "risk_level" in meta
    assert "decision_source" in meta


# ---------------------------------------------------------------------------
# Test 7: Gateway SessionRegistry records events sent via subprocess harness
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_decision_reaches_gateway_registry(sub_gateway):
    """Decision sent via subprocess harness must be recorded in the gateway."""
    session_id = "sub-registry-verify"

    await _run_harness([
        {"jsonrpc": "2.0", "id": 1, "method": "ahp/handshake", "params": {}},
        _pre_event(2, "bash", command="echo hello", session_id=session_id),
    ])

    # Verify session was registered in the gateway
    risk = sub_gateway.session_registry.get_current_risk(session_id)
    assert risk is not None, \
        "Gateway SessionRegistry should record the event after harness subprocess call"

    sessions = sub_gateway.session_registry.list_sessions()
    session_ids = [s["session_id"] for s in sessions["sessions"]]
    assert session_id in session_ids


# ---------------------------------------------------------------------------
# Test 8: High-risk command triggers alert in gateway
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_subprocess_high_risk_triggers_alert(sub_gateway):
    """A truly dangerous command sent via subprocess harness should create an alert."""
    session_id = "sub-alert-verify"

    await _run_harness([
        {"jsonrpc": "2.0", "id": 1, "method": "ahp/handshake", "params": {}},
        _pre_event(2, "bash", command="rm -rf /", session_id=session_id),
    ])

    alerts = sub_gateway.alert_registry.list_alerts()
    session_alerts = [
        a for a in alerts["alerts"] if a["session_id"] == session_id
    ]
    assert len(session_alerts) >= 1, \
        "High-risk command should generate an alert in the gateway AlertRegistry"
    assert session_alerts[0]["severity"] in ("high", "critical")
