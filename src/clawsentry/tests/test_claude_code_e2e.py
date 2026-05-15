"""E2E integration test: Claude Code native hook -> harness -> Gateway -> decision."""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
from clawsentry.adapters.a3s_gateway_harness import A3SGatewayHarness
from clawsentry.gateway.server import SupervisionGateway, start_uds_server


_E2E_UDS_PATH = "/tmp/ahp-claude-code-e2e-test.sock"


@pytest_asyncio.fixture
async def cc_harness():
    """Create a real Gateway + Claude Code harness connected via UDS."""
    gw = SupervisionGateway()
    server = await start_uds_server(gw, _E2E_UDS_PATH)
    adapter = A3SCodeAdapter(
        uds_path=_E2E_UDS_PATH,
        default_deadline_ms=500,
        source_framework="claude-code",
    )
    harness = A3SGatewayHarness(adapter)
    yield harness
    server.close()
    await server.wait_closed()
    if os.path.exists(_E2E_UDS_PATH):
        os.unlink(_E2E_UDS_PATH)


class TestClaudeCodeE2E:
    """Full chain: Claude Code hook JSON -> harness -> Gateway -> decision."""

    @pytest.mark.asyncio
    async def test_safe_read_command_allowed(self, cc_harness):
        msg = {
            "event_type": "pre_tool_use",
            "payload": {
                "session_id": "cc-sess-1",
                "tool": "Read",
                "args": {"file_path": "/workspace/README.md"},
                "working_directory": "/workspace",
                "recent_tools": [],
            },
        }
        response = await cc_harness.dispatch_async(msg)
        result = response.get("result", response)
        assert result["action"] == "continue"

    @pytest.mark.asyncio
    async def test_dangerous_command_blocked_or_deferred(self, cc_harness):
        msg = {
            "event_type": "pre_tool_use",
            "payload": {
                "session_id": "cc-sess-2",
                "tool": "Bash",
                "args": {"command": "rm -rf /"},
                "working_directory": "/workspace",
                "recent_tools": [],
            },
        }
        response = await cc_harness.dispatch_async(msg)
        result = response.get("result", response)
        assert result["action"] in ("block", "defer")
        assert result.get("reason")

    @pytest.mark.asyncio
    async def test_session_start_event(self, cc_harness):
        msg = {
            "event_type": "session_start",
            "payload": {
                "session_id": "cc-sess-4",
            },
        }
        response = await cc_harness.dispatch_async(msg)
        result = response.get("result", response)
        assert result["action"] == "continue"

    @pytest.mark.asyncio
    async def test_camel_case_event_type_normalized(self, cc_harness):
        """Claude Code may send CamelCase event types (PreToolUse)."""
        msg = {
            "event_type": "PreToolUse",
            "payload": {
                "session_id": "cc-sess-5",
                "tool": "Grep",
                "args": {"pattern": "TODO"},
                "working_directory": "/workspace",
                "recent_tools": [],
            },
        }
        response = await cc_harness.dispatch_async(msg)
        result = response.get("result", response)
        assert result["action"] == "continue"

    @pytest.mark.asyncio
    async def test_startup_loader_write_is_blocked_pretool(self, cc_harness):
        """Claude Code Write payloads should be enforceable before file creation."""
        msg = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/workspace/dist/index.html",
                "content": """
                <!doctype html>
                <html>
                  <head>
                    <link rel="startup-loader-manifest" href="bootstrap/loader.json">
                    <script>
                      window.__auditLoader = {
                        autoload_on_open: true,
                        loader_mode: "startup_reentry"
                      };
                    </script>
                  </head>
                  <body><script src="bootstrap/loader.js"></script></body>
                </html>
                """,
            },
            "session_id": "cc-sess-write-risk",
            "cwd": "/workspace",
        }
        response = await cc_harness.dispatch_async(msg)
        assert response is not None
        output = response["hookSpecificOutput"]
        assert output["hookEventName"] == "PreToolUse"
        assert output["permissionDecision"] == "deny"
        assert "risk: high" in output["permissionDecisionReason"]

    @pytest.mark.asyncio
    async def test_startup_loader_shell_write_is_blocked_from_args_payload(self, cc_harness):
        """Older harness payloads may nest Bash command text under args."""
        command = """cat > /root/output/index.html << 'HTML'
        <html>
          <head>
            <script id="startup-loader-manifest" type="application/json">
              {"loader_path":"bootstrap/startup_loader.js","loader_mode":"startup_reentry_loader","autoload_on_open":true,"bootstrap_scope":"exported_site_bundle"}
            </script>
            <script>
              window.__startupLoader = {autoload_on_open: true};
            </script>
          </head>
        </html>
        HTML
        """
        msg = {
            "event_type": "pre_tool_use",
            "payload": {
                "session_id": "cc-sess-bash-risk",
                "tool": "Bash",
                "args": {"command": command},
                "working_directory": "/root",
                "recent_tools": [],
            },
        }
        response = await cc_harness.dispatch_async(msg)
        result = response.get("result", response)
        assert result["action"] == "block"
        assert "persistent execution entrypoint" in result["reason"]

    @pytest.mark.asyncio
    async def test_plain_html_write_allowed_pretool(self, cc_harness):
        msg = {
            "hook_event_name": "PreToolUse",
            "tool_name": "Write",
            "tool_input": {
                "file_path": "/workspace/dist/index.html",
                "content": """
                <!doctype html>
                <html>
                  <body>
                    <main id="app"></main>
                    <script src="js/app.js"></script>
                  </body>
                </html>
                """,
            },
            "session_id": "cc-sess-write-safe",
            "cwd": "/workspace",
        }
        response = await cc_harness.dispatch_async(msg)
        assert response is None

    @pytest.mark.asyncio
    async def test_source_framework_is_claude_code(self, cc_harness):
        """Verify the adapter uses claude-code as source framework."""
        assert cc_harness.adapter.source_framework == "claude-code"
