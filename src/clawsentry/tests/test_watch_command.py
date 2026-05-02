"""Tests for clawsentry watch CLI command."""

from __future__ import annotations

import json
import time
import urllib.request
from unittest.mock import AsyncMock

import pytest

import clawsentry.cli.watch_command as watch_command
from clawsentry.cli.watch_command import (
    SessionTracker,
    _format_defer_pending,
    _format_defer_resolved,
    format_alert,
    format_decision,
    format_event,
    handle_defer_interactive,
    parse_sse_line,
)


class _JsonResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def read(self):
        return json.dumps(self._payload).encode()


# ---------------------------------------------------------------------------
# TestParseSSELine
# ---------------------------------------------------------------------------


class TestParseSSELine:
    def test_data_line_returns_parsed_json(self):
        line = 'data: {"type": "decision", "risk_level": "high"}'
        result = parse_sse_line(line)
        assert result == {"type": "decision", "risk_level": "high"}

    def test_comment_line_returns_none(self):
        assert parse_sse_line(": keepalive") is None

    def test_empty_line_returns_none(self):
        assert parse_sse_line("") is None


class TestBuildStreamUrl:
    def test_without_filters_returns_plain_stream_endpoint(self):
        url = watch_command._build_stream_url("http://localhost:8080")
        assert url == "http://localhost:8080/report/stream"

    def test_priority_only_adds_operator_priority_types(self):
        url = watch_command._build_stream_url(
            "http://localhost:8080",
            priority_only=True,
        )
        assert "types=" in url
        assert "decision" in url
        assert "defer_pending" in url
        assert "l3_advisory_job" in url
        assert "l3_advisory_action" in url

    def test_priority_only_merges_with_explicit_filter_without_duplicates(self):
        url = watch_command._build_stream_url(
            "http://localhost:8080",
            filter_types="decision,alert,custom_event,decision",
            priority_only=True,
        )
        parsed = url.split("types=", 1)[1]
        decoded = parsed.replace("%2C", ",")
        assert "custom_event" in decoded
        assert decoded.count("decision") == 1


class TestLoopbackProxyBypass:
    def _patch_loopback_opener(self, monkeypatch: pytest.MonkeyPatch, response) -> list[dict[str, str]]:
        proxy_maps: list[dict[str, str]] = []

        class FakeOpener:
            def open(self, request, timeout=None):
                return response(request, timeout) if callable(response) else response

        def fake_build_opener(*handlers):
            assert len(handlers) == 1
            assert isinstance(handlers[0], urllib.request.ProxyHandler)
            proxy_maps.append(dict(handlers[0].proxies))
            return FakeOpener()

        monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
        monkeypatch.setenv("ALL_PROXY", "http://proxy.invalid:3128")
        monkeypatch.setattr(watch_command.urllib.request, "build_opener", fake_build_opener)
        monkeypatch.setattr(
            watch_command.urllib.request,
            "urlopen",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("loopback gateway calls must not use default urlopen")
            ),
        )
        return proxy_maps

    @pytest.mark.asyncio
    async def test_interactive_defer_resolve_bypasses_proxy_for_loopback(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        opened: list[tuple[str, float | None]] = []

        def response(request, timeout=None):
            opened.append((request.full_url, timeout))
            return _JsonResponse({"status": "ok"})

        proxy_maps = self._patch_loopback_opener(monkeypatch, response)

        assert await watch_command._resolve_defer_approval(
            "http://127.0.0.1:8080",
            "approval-1",
            "allow-once",
            token="token-123",
        ) is True

        assert proxy_maps == [{}]
        assert opened == [("http://127.0.0.1:8080/ahp/resolve", 10)]

    def test_session_prefetch_bypasses_proxy_for_localhost(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        opened: list[tuple[str, float | None]] = []

        def response(request, timeout=None):
            opened.append((request.full_url, timeout))
            return _JsonResponse(
                {
                    "sessions": [
                        {
                            "session_id": "sess-1",
                            "agent_id": "agent-1",
                            "source_framework": "codex",
                            "first_event_at": "2026-04-10T12:00:00Z",
                        }
                    ]
                }
            )

        proxy_maps = self._patch_loopback_opener(monkeypatch, response)
        tracker = SessionTracker()

        watch_command._prefetch_sessions(tracker, "http://localhost:8080", {})

        assert proxy_maps == [{}]
        assert opened == [("http://localhost:8080/report/sessions", 3)]
        assert tracker.session_info["sess-1"]["framework"] == "codex"

    def test_watch_sse_stream_bypasses_proxy_for_ipv6_loopback(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        responses = iter([
            _FakeSSEStream([b'data: {"type": "decision", "decision": "allow"}\n']),
            KeyboardInterrupt(),
        ])
        opened: list[str] = []

        def response(request, timeout=None):
            opened.append(request.full_url)
            item = next(responses)
            if isinstance(item, BaseException):
                raise item
            return item

        proxy_maps = self._patch_loopback_opener(monkeypatch, response)
        monkeypatch.setattr(watch_command, "_prefetch_sessions", lambda *_args, **_kwargs: None)

        watch_command.run_watch("http://[::1]:8080", color=False)

        assert proxy_maps == [{}, {}]
        assert opened == [
            "http://[::1]:8080/report/stream",
            "http://[::1]:8080/report/stream",
        ]

    def test_non_loopback_watch_requests_keep_default_proxy_behavior(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        opened: list[str] = []

        def fake_urlopen(request, timeout=None):
            opened.append(request.full_url)
            return _JsonResponse({"sessions": []})

        monkeypatch.setattr(
            watch_command.urllib.request,
            "build_opener",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("non-loopback gateway calls must keep urllib default opener")
            ),
        )
        monkeypatch.setattr(watch_command.urllib.request, "urlopen", fake_urlopen)

        watch_command._prefetch_sessions(SessionTracker(), "http://gateway.example:8080", {})

        assert opened == ["http://gateway.example:8080/report/sessions"]


# ---------------------------------------------------------------------------
# TestFormatDecision  (existing tests updated for new mixed format)
# ---------------------------------------------------------------------------


class TestFormatDecision:
    def _make_decision(self, **overrides) -> dict:
        base = {
            "type": "decision",
            "session_id": "sess-001",
            "event_id": "evt-001",
            "risk_level": "high",
            "decision": "block",
            "command": "rm -rf /data",
            "reason": "D1: destructive pattern",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        base.update(overrides)
        return base

    def test_block_decision_red_color(self):
        event = self._make_decision(decision="block", risk_level="high")
        result = format_decision(event, color=True)
        # BLOCK uses red ANSI colour
        assert "\033[91m" in result
        assert "BLOCK" in result
        assert "rm -rf /data" in result
        # New format: tree-style "Risk: 🔴 high" instead of "risk=high"
        assert "Risk:" in result
        assert "high" in result
        assert "D1: destructive pattern" in result

    def test_allow_decision_green_color(self):
        event = self._make_decision(
            decision="allow", risk_level="low", command="echo hello"
        )
        result = format_decision(event, color=True)
        assert "\033[92m" in result
        assert "ALLOW" in result
        assert "echo hello" in result
        # Compact ALLOW format does NOT show risk level
        assert "Risk:" not in result

    def test_defer_decision_no_color(self):
        event = self._make_decision(
            decision="defer", risk_level="medium", command="pip install requests"
        )
        result = format_decision(event, color=False)
        # No ANSI codes when color=False
        assert "\033[" not in result
        assert "DEFER" in result
        assert "pip install requests" in result
        # New format: "Risk: medium" not "risk=medium"
        assert "Risk:" in result
        assert "medium" in result

    def test_command_truncated_to_50_chars(self):
        long_command = "a" * 60
        event = self._make_decision(command=long_command)
        result = format_decision(event, color=False)
        # Full 60-char command should not appear; truncation should occur
        assert long_command not in result
        assert "aaa..." in result


# ---------------------------------------------------------------------------
# TestDecisionFormatterMixedFormat  (new)
# ---------------------------------------------------------------------------


class TestDecisionFormatterMixedFormat:
    """Tests for the mixed display format: compact ALLOW, detailed BLOCK/DEFER."""

    def _make(self, **overrides) -> dict:
        base = {
            "type": "decision",
            "session_id": "sess-001",
            "decision": "block",
            "command": "rm -rf /data",
            "risk_level": "high",
            "reason": "D1: destructive pattern",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        base.update(overrides)
        return base

    # --- ALLOW compact ---

    def test_allow_is_single_line(self):
        event = self._make(decision="allow", risk_level="low", command="cat README.md")
        result = format_decision(event, color=False)
        nonempty = [ln for ln in result.split("\n") if ln.strip()]
        assert len(nonempty) == 1

    def test_allow_contains_decision_and_command(self):
        event = self._make(decision="allow", command="cat README.md")
        result = format_decision(event, color=False)
        assert "ALLOW" in result
        assert "cat README.md" in result

    def test_allow_does_not_show_risk(self):
        event = self._make(decision="allow", risk_level="low")
        result = format_decision(event, color=False)
        assert "Risk:" not in result

    def test_allow_does_not_show_reason(self):
        event = self._make(decision="allow", reason="read-only operation")
        result = format_decision(event, color=False)
        assert "Reason:" not in result

    # --- BLOCK detailed ---

    def test_block_is_multiline(self):
        event = self._make(decision="block", risk_level="high", reason="D1")
        result = format_decision(event, color=False)
        nonempty = [ln for ln in result.split("\n") if ln.strip()]
        assert len(nonempty) >= 2

    def test_block_has_tree_structure(self):
        event = self._make(decision="block", risk_level="high", reason="D1")
        result = format_decision(event, color=False)
        assert "├─" in result or "└─" in result

    def test_block_shows_risk_and_reason(self):
        event = self._make(decision="block", risk_level="high", reason="D1: pattern")
        result = format_decision(event, color=False)
        assert "Risk:" in result
        assert "high" in result
        assert "Reason:" in result
        assert "D1: pattern" in result
        assert "Action:" in result
        assert "inspect session evidence" in result

    # --- DEFER with expiry ---

    def test_defer_shows_expires_countdown(self):
        event = self._make(
            decision="defer",
            risk_level="high",
            reason="needs approval",
            expires_at=int((time.time() + 60) * 1000),
        )
        result = format_decision(event, color=False)
        assert "Expires in:" in result
        assert "operator approval pending" in result

    def test_defer_without_expires_no_countdown(self):
        event = self._make(decision="defer", risk_level="high", reason="needs approval")
        result = format_decision(event, color=False)
        assert "Expires" not in result

    def test_defer_past_expiry_no_countdown(self):
        event = self._make(
            decision="defer",
            risk_level="high",
            expires_at=int((time.time() - 30) * 1000),
        )
        result = format_decision(event, color=False)
        assert "Expires in:" not in result

    # --- Verbose mode ---

    def test_verbose_allow_shows_risk_and_reason(self):
        event = self._make(decision="allow", risk_level="low", reason="read-only")
        result = format_decision(event, color=False, verbose=True)
        nonempty = [ln for ln in result.split("\n") if ln.strip()]
        assert len(nonempty) >= 2
        assert "Risk:" in result
        assert "Reason:" in result

    def test_verbose_allow_shows_tier(self):
        event = self._make(decision="allow", risk_level="low", actual_tier="L1")
        result = format_decision(event, color=False, verbose=True)
        assert "Tier:" in result
        assert "L1" in result

    def test_verbose_decision_shows_trigger_detail(self):
        event = self._make(
            decision="block",
            risk_level="high",
            actual_tier="L3",
            trigger_detail="secret_plus_network",
        )
        result = format_decision(event, color=False, verbose=True)
        assert "Trigger:" in result
        assert "secret_plus_network" in result

    def test_verbose_decision_shows_l3_reason_code(self):
        event = self._make(
            decision="block",
            risk_level="high",
            actual_tier="L3",
            l3_reason_code="hard_cap_exceeded",
        )
        result = format_decision(event, color=False, verbose=True)
        assert "L3 reason code:" in result
        assert "hard_cap_exceeded" in result

    def test_verbose_decision_shows_l3_state_and_reason(self):
        event = self._make(
            decision="block",
            risk_level="high",
            actual_tier="L3",
            l3_state="degraded",
            l3_reason="L3 hard cap exceeded",
        )
        result = format_decision(event, color=False, verbose=True)
        assert "L3 state:" in result
        assert "degraded" in result
        assert "L3 reason:" in result
        assert "L3 hard cap exceeded" in result

    def test_verbose_decision_shows_compact_evidence_summary(self):
        event = self._make(
            decision="block",
            risk_level="high",
            actual_tier="L3",
            evidence_summary={
                "retained_sources": ["trajectory", "file"],
                "tool_calls_count": 2,
                "toolkit_budget_mode": "multi_turn",
                "toolkit_budget_cap": 5,
                "toolkit_calls_remaining": 0,
                "toolkit_budget_exhausted": True,
            },
        )
        result = format_decision(event, color=False, verbose=True)
        assert "Evidence:" in result
        assert "trajectory, file" in result
        assert "2 tool call(s)" in result
        assert "toolkit 0/5 (exhausted)" in result
        assert "tool_calls" not in result

    # --- no_emoji mode ---

    def test_no_emoji_removes_decision_emoji(self):
        event = self._make(decision="block", risk_level="high")
        result = format_decision(event, color=False, no_emoji=True)
        assert "🚫" not in result
        assert "BLOCK" in result

    def test_no_emoji_removes_risk_emoji(self):
        event = self._make(decision="block", risk_level="high")
        result = format_decision(event, color=False, no_emoji=True)
        assert "🔴" not in result
        assert "high" in result

    def test_with_emoji_includes_decision_emoji(self):
        event = self._make(decision="block", risk_level="high")
        result = format_decision(event, color=False, no_emoji=False)
        assert "🚫" in result

    # --- Observation-only events (no command) ---

    def test_empty_command_returns_empty_string(self):
        event = self._make(command="")
        result = format_decision(event, color=False)
        assert result == ""

    def test_none_command_returns_empty_string(self):
        event = self._make(command=None)
        result = format_decision(event, color=False)
        assert result == ""

    # --- Color semantics ---

    def test_block_uses_red_color(self):
        event = self._make(decision="block", risk_level="high")
        result = format_decision(event, color=True)
        assert "\033[91m" in result  # red

    def test_allow_uses_green_color(self):
        event = self._make(decision="allow", command="ls")
        result = format_decision(event, color=True)
        assert "\033[92m" in result  # green

    def test_defer_uses_yellow_color(self):
        event = self._make(decision="defer", risk_level="high")
        result = format_decision(event, color=True)
        assert "\033[93m" in result  # yellow


# ---------------------------------------------------------------------------
# TestFormatAlert  (updated for new tree format)
# ---------------------------------------------------------------------------


class TestFormatAlert:
    def test_alert_formatting(self):
        event = {
            "type": "alert",
            "alert_id": "alert-abc123",
            "severity": "high",
            "session_id": "sess-001",
            "message": "Risk escalation detected",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_alert(event, color=False)
        assert "ALERT" in result
        # New format: "Session: sess-001" in tree instead of "sess=sess-001"
        assert "sess-001" in result
        # New format: "Severity: high" in tree instead of "severity=high"
        assert "high" in result
        assert "Risk escalation detected" in result

    def test_alert_with_color(self):
        event = {
            "type": "alert",
            "alert_id": "alert-abc123",
            "severity": "critical",
            "session_id": "sess-002",
            "message": "Critical risk",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_alert(event, color=True)
        # Alert label uses magenta
        assert "\033[95m" in result
        assert "ALERT" in result

    def test_alert_has_tree_structure(self):
        event = {
            "type": "alert",
            "severity": "high",
            "session_id": "sess-001",
            "message": "Risk up",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_alert(event, color=False)
        assert "├─" in result or "└─" in result

    def test_alert_no_emoji(self):
        event = {
            "type": "alert",
            "severity": "high",
            "session_id": "sess-001",
            "message": "test",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_alert(event, color=False, no_emoji=True)
        assert "⚠️" not in result
        assert "ALERT" in result


# ---------------------------------------------------------------------------
# TestFormatEvent
# ---------------------------------------------------------------------------


class TestFormatEvent:
    def test_decision_dispatch(self):
        event = {
            "type": "decision",
            "decision": "block",
            "risk_level": "high",
            "command": "rm -rf /",
            "reason": "destructive",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "BLOCK" in result
        assert "rm -rf /" in result

    def test_alert_dispatch(self):
        event = {
            "type": "alert",
            "severity": "high",
            "session_id": "sess-001",
            "message": "Risk up",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "ALERT" in result

    def test_session_start_returns_empty(self):
        """session_start handled by SessionTracker header; format_event returns empty."""
        event = {
            "type": "session_start",
            "session_id": "sess-abc",
            "agent_id": "agent-1",
            "source_framework": "openclaw",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert result == ""

    def test_session_risk_change_dispatch(self):
        event = {
            "type": "session_risk_change",
            "session_id": "sess-001",
            "previous_risk": "low",
            "current_risk": "high",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "RISK" in result
        assert "sess-001" in result

    def test_json_mode_returns_json(self):
        event = {
            "type": "decision",
            "decision": "allow",
            "risk_level": "low",
            "command": "ls",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, json_mode=True)
        parsed = json.loads(result)
        assert parsed["type"] == "decision"
        assert parsed["decision"] == "allow"


    def test_decision_human_output_shows_compact_posture_and_trend_hints(self):
        event = {
            "type": "decision",
            "decision": "block",
            "risk_level": "high",
            "command": "deploy prod",
            "reason": "operator policy",
            "risk_posture_hint": {"summary": "High-risk posture"},
            "operator_hints": {"risk_trend_hint": "high-risk trend rising"},
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "Posture: High-risk posture" in result
        assert "Trend: high-risk trend rising" in result

    def test_allow_default_does_not_spam_posture_or_trend_hints(self):
        event = {
            "type": "decision",
            "decision": "allow",
            "risk_level": "low",
            "command": "cat README.md",
            "risk_posture_hint": "Healthy",
            "risk_trend_hint": "flat",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "ALLOW" in result
        assert "Posture:" not in result
        assert "Trend:" not in result

    def test_session_risk_change_human_output_shows_posture_and_trend_hints(self):
        event = {
            "type": "session_risk_change",
            "session_id": "sess-001",
            "previous_risk": "medium",
            "current_risk": "high",
            "posture_hint": "Session entering high-risk posture",
            "trend_hint": {"direction": "up"},
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "Posture: Session entering high-risk posture" in result
        assert "Trend: up" in result

    def test_json_mode_preserves_full_posture_and_trend_hint_fields(self):
        event = {
            "type": "decision",
            "decision": "block",
            "risk_level": "high",
            "command": "deploy prod",
            "risk_posture_hint": {
                "summary": "High-risk posture",
                "windows": {"5m": {"count": 3, "ratio": 0.5}},
            },
            "risk_trend_hint": {
                "direction_5m": "up",
                "series_5m": [{"high_or_critical_count": 3}],
            },
            "timestamp": "2026-03-22T10:30:45Z",
        }
        parsed = json.loads(format_event(event, json_mode=True))
        assert parsed["risk_posture_hint"]["windows"]["5m"]["count"] == 3
        assert parsed["risk_trend_hint"]["series_5m"][0]["high_or_critical_count"] == 3

    def test_verbose_param_forwarded_to_decision(self):
        event = {
            "type": "decision",
            "decision": "allow",
            "risk_level": "low",
            "reason": "read-only",
            "command": "cat file.txt",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False, verbose=True)
        # verbose=True: ALLOW shows details
        assert "Risk:" in result

    def test_no_emoji_param_forwarded_to_decision(self):
        event = {
            "type": "decision",
            "decision": "block",
            "risk_level": "high",
            "command": "rm -rf /",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False, no_emoji=True)
        assert "🚫" not in result

    def test_trajectory_alert_dispatch(self):
        event = {
            "type": "trajectory_alert",
            "session_id": "sess-001",
            "sequence_id": "seq-exfil",
            "risk_level": "critical",
            "matched_event_ids": ["evt-1", "evt-2"],
            "reason": "read secret then exfiltrate",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "TRAJECTORY" in result
        assert "seq-exfil" in result
        assert "critical" in result
        assert "read secret then exfiltrate" in result
        assert not result.startswith("{")

    def test_post_action_finding_dispatch(self):
        event = {
            "type": "post_action_finding",
            "session_id": "sess-001",
            "tier": "emergency",
            "score": 0.94,
            "patterns_matched": ["secret_leak", "external_content"],
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "POST-ACTION" in result
        assert "emergency" in result
        assert "0.94" in result
        assert "secret_leak" in result
        assert not result.startswith("{")

    def test_pattern_evolved_dispatch(self):
        event = {
            "type": "pattern_evolved",
            "pattern_id": "EV-ABC123",
            "result": "promoted_to_experimental",
            "confirmed": True,
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "PATTERN" in result
        assert "EV-ABC123" in result
        assert "promoted_to_experimental" in result
        assert not result.startswith("{")

    def test_pattern_candidate_dispatch(self):
        event = {
            "type": "pattern_candidate",
            "pattern_id": "EV-CANDIDATE",
            "session_id": "sess-001",
            "status": "candidate",
            "source_framework": "test",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "PATTERN CANDIDATE" in result
        assert "EV-CANDIDATE" in result
        assert "sess-001" in result
        assert "candidate" in result
        assert not result.startswith("{")

    def test_pattern_evolved_dispatch_uses_explicit_label(self):
        event = {
            "type": "pattern_evolved",
            "pattern_id": "EV-ABC123",
            "result": "promoted_to_experimental",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False)
        assert "PATTERN EVOLVED" in result

    def test_trajectory_alert_compact_mode_is_single_line(self):
        event = {
            "type": "trajectory_alert",
            "session_id": "sess-001",
            "sequence_id": "seq-exfil",
            "risk_level": "critical",
            "handling": "block",
            "reason": "read secret then exfiltrate",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False, compact=True)
        assert "\n" not in result
        assert "TRAJECTORY" in result
        assert "seq-exfil" in result

    def test_pattern_candidate_compact_mode_is_single_line(self):
        event = {
            "type": "pattern_candidate",
            "pattern_id": "EV-CANDIDATE",
            "session_id": "sess-001",
            "status": "candidate",
            "source_framework": "test",
            "timestamp": "2026-03-22T10:30:45Z",
        }
        result = format_event(event, color=False, compact=True)
        assert "\n" not in result
        assert "EV-CANDIDATE" in result

    def test_budget_exhausted_dispatch(self):
        event = {
            "type": "budget_exhausted",
            "timestamp": "2026-03-22T10:30:45Z",
            "provider": "openai",
            "tier": "L2",
            "status": "ok",
            "cost_usd": 1.25,
            "budget": {
                "daily_budget_usd": 10.0,
                "daily_spend_usd": 10.0,
                "remaining_usd": 0.0,
                "exhausted": True,
            },
        }
        result = format_event(event, color=False)
        assert not result.startswith("{")
        assert "\n" not in result
        assert "BUDGET EXHAUSTED" in result
        assert "provider=openai" in result
        assert "tier=L2" in result
        assert "cost=$1.25" in result
        assert "budget=$10.00/$10.00" in result
        assert "remaining=$0.00" in result

    def test_l3_advisory_snapshot_dispatch(self):
        event = {
            "type": "l3_advisory_snapshot",
            "session_id": "sess-l3adv",
            "snapshot_id": "l3snap-abc123",
            "trigger_reason": "trajectory_alert",
            "event_range": {"from_record_id": 1, "to_record_id": 3},
            "timestamp": "2026-04-21T00:00:00Z",
        }
        result = format_event(event, color=False)
        assert "L3 ADVISORY SNAPSHOT" in result
        assert "l3snap-abc123" in result
        assert "1->3" in result

    def test_l3_advisory_review_dispatch(self):
        event = {
            "type": "l3_advisory_review",
            "session_id": "sess-l3adv",
            "snapshot_id": "l3snap-abc123",
            "review_id": "l3adv-def456",
            "risk_level": "high",
            "l3_state": "running",
            "recommended_operator_action": "inspect",
            "timestamp": "2026-04-21T00:00:00Z",
        }
        result = format_event(event, color=False)
        assert "L3 ADVISORY REVIEW" in result
        assert "l3adv-def456" in result
        assert "running" in result
        assert "inspect" in result

    def test_l3_advisory_review_shows_advisory_boundary(self):
        event = {
            "type": "l3_advisory_review",
            "session_id": "sess-l3adv",
            "snapshot_id": "l3snap-abc123",
            "review_id": "l3adv-def456",
            "risk_level": "high",
            "l3_state": "completed",
            "recommended_operator_action": "inspect",
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": "2026-04-21T00:00:00Z",
        }
        result = format_event(event, color=False)
        assert "Boundary:" in result
        assert "advisory only" in result
        assert "canonical unchanged" in result

    def test_l3_advisory_job_dispatch(self):
        event = {
            "type": "l3_advisory_job",
            "session_id": "sess-l3adv",
            "snapshot_id": "l3snap-abc123",
            "job_id": "l3job-ghi789",
            "job_state": "queued",
            "runner": "deterministic_local",
            "timestamp": "2026-04-21T00:00:00Z",
        }
        result = format_event(event, color=False)
        assert "L3 ADVISORY JOB" in result
        assert "l3job-ghi789" in result
        assert "queued" in result
        assert "deterministic_local" in result

    def test_l3_advisory_job_shows_transition_hint(self):
        event = {
            "type": "l3_advisory_job",
            "session_id": "sess-l3adv",
            "snapshot_id": "l3snap-abc123",
            "job_id": "l3job-ghi789",
            "job_state": "queued",
            "runner": "deterministic_local",
            "timestamp": "2026-04-21T00:00:00Z",
        }
        result = format_event(event, color=False)
        assert "Next:" in result
        assert "waiting for explicit operator run" in result

    def test_l3_advisory_job_shows_operator_labels_and_frozen_boundary(self):
        event = {
            "type": "l3_advisory_job",
            "session_id": "sess-l3adv",
            "snapshot_id": "l3snap-abc123",
            "job_id": "l3job-ghi789",
            "job_state": "queued",
            "runner": "deterministic_local",
            "timestamp": "2026-04-21T00:00:00Z",
        }
        result = format_event(event, color=False)
        assert "State:" in result
        assert "Queued" in result
        assert "Runner:" in result
        assert "Deterministic local" in result
        assert "Boundary:" in result
        assert "frozen snapshot; explicit run only" in result

    def test_l3_advisory_job_shows_review_and_error_when_present(self):
        event = {
            "type": "l3_advisory_job",
            "session_id": "sess-l3adv",
            "snapshot_id": "l3snap-abc123",
            "job_id": "l3job-ghi789",
            "review_id": "l3adv-def456",
            "job_state": "failed",
            "runner": "llm_provider",
            "error": "provider timeout",
            "timestamp": "2026-04-21T00:00:00Z",
        }
        result = format_event(event, color=False)
        assert "Review:" in result
        assert "l3adv-def456" in result
        assert "Error:" in result
        assert "provider timeout" in result

    def test_l3_advisory_action_dispatch_shows_advisory_boundary(self):
        event = {
            "type": "l3_advisory_action",
            "session_id": "sess-l3adv",
            "snapshot_id": "l3snap-abc123",
            "job_id": "l3job-ghi789",
            "review_id": "l3adv-def456",
            "risk_level": "critical",
            "recommended_operator_action": "escalate",
            "l3_state": "completed",
            "source_record_range": {"from_record_id": 2, "to_record_id": 8},
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "timestamp": "2026-04-21T00:00:00Z",
        }
        result = format_event(event, color=False)
        assert "L3 ADVISORY ACTION" in result
        assert "l3adv-def456" in result
        assert "escalate" in result
        assert "2->8" in result
        assert "advisory only" in result
        assert "canonical unchanged" in result


# ---------------------------------------------------------------------------
# TestFormatDeferEvents
# ---------------------------------------------------------------------------


class TestFormatDeferEvents:
    """Tests for _format_defer_pending and _format_defer_resolved formatters."""

    def _make_defer_pending(self, **overrides) -> dict:
        base = {
            "type": "defer_pending",
            "approval_id": "appr-abc-123",
            "tool_name": "bash",
            "command": "rm -rf /tmp/data",
            "reason": "D1: destructive pattern",
            "timeout_s": 300,
            "timestamp": "2026-03-22T10:30:45Z",
        }
        base.update(overrides)
        return base

    def _make_defer_resolved(self, **overrides) -> dict:
        base = {
            "type": "defer_resolved",
            "approval_id": "appr-abc-123",
            "resolved_decision": "allow-once",
            "resolved_reason": "operator approved",
            "timestamp": "2026-03-22T10:31:10Z",
        }
        base.update(overrides)
        return base

    def test_format_defer_pending_basic(self):
        """Output contains DEFER PENDING, tool name, and approval_id."""
        event = self._make_defer_pending()
        result = _format_defer_pending(event, color=False)
        assert "DEFER PENDING" in result
        assert "bash" in result
        assert "rm -rf /tmp/data" in result
        assert "appr-abc-123" in result
        assert "300s" in result
        assert "D1: destructive pattern" in result

    def test_format_defer_pending_no_color(self):
        """No ANSI escape codes when color=False."""
        event = self._make_defer_pending()
        result = _format_defer_pending(event, color=False)
        assert "\033[" not in result
        assert "DEFER PENDING" in result

    def test_format_defer_resolved_allow(self):
        """DEFER RESOLVED: ALLOW with allow emoji."""
        event = self._make_defer_resolved(resolved_decision="allow-once")
        result = _format_defer_resolved(event, color=False, no_emoji=False)
        assert "DEFER RESOLVED: ALLOW" in result
        assert "✅" in result
        assert "appr-abc-123" in result
        assert "operator approved" in result

    def test_format_defer_resolved_block(self):
        """DEFER RESOLVED: BLOCK with block emoji."""
        event = self._make_defer_resolved(
            resolved_decision="deny",
            resolved_reason="operator denied via watch CLI",
        )
        result = _format_defer_resolved(event, color=False, no_emoji=False)
        assert "DEFER RESOLVED: BLOCK" in result
        assert "🚫" in result
        assert "appr-abc-123" in result
        assert "operator denied" in result

    def test_format_event_dispatches_defer(self):
        """format_event routes defer_pending and defer_resolved correctly."""
        pending = self._make_defer_pending()
        result_pending = format_event(pending, color=False)
        assert "DEFER PENDING" in result_pending

        resolved = self._make_defer_resolved()
        result_resolved = format_event(resolved, color=False)
        assert "DEFER RESOLVED: ALLOW" in result_resolved


# ---------------------------------------------------------------------------
# TestSessionTracker  (new)
# ---------------------------------------------------------------------------


class TestSessionTracker:
    def _make_event(self, session_id: str | None, event_type: str = "decision") -> dict:
        return {
            "type": event_type,
            "session_id": session_id,
            "agent_id": "agent-1",
            "source_framework": "openclaw",
            "timestamp": "2026-03-22T10:30:45Z",
        }

    def test_new_session_returns_header(self):
        tracker = SessionTracker()
        event = self._make_event("sess-001")
        before, after = tracker.update(event, color=False)
        assert before is not None
        assert "sess-001" in before
        assert after is None

    def test_same_session_no_output(self):
        tracker = SessionTracker()
        event = self._make_event("sess-001")
        tracker.update(event, color=False)
        before, after = tracker.update(event, color=False)
        assert before is None
        assert after is None

    def test_session_switch_returns_footer_and_header(self):
        tracker = SessionTracker()
        event1 = self._make_event("sess-001")
        event2 = self._make_event("sess-002")
        tracker.update(event1, color=False)
        before, after = tracker.update(event2, color=False)
        # before contains footer of sess-001 + header of sess-002
        assert before is not None
        assert "sess-002" in before
        assert after is None

    def test_session_switch_before_contains_footer_chars(self):
        tracker = SessionTracker()
        tracker.update(self._make_event("sess-001"), color=False)
        before, _ = tracker.update(self._make_event("sess-002"), color=False)
        # Footer contains closing box character
        assert "╰" in before or "===" in before

    def test_no_session_id_no_output(self):
        tracker = SessionTracker()
        event = self._make_event(None)
        before, after = tracker.update(event, color=False)
        assert before is None
        assert after is None

    def test_empty_session_id_no_output(self):
        tracker = SessionTracker()
        event = self._make_event("")
        before, after = tracker.update(event, color=False)
        assert before is None
        assert after is None

    def test_in_session_true_after_new_session(self):
        tracker = SessionTracker()
        assert tracker.in_session is False
        tracker.update(self._make_event("sess-001"), color=False)
        assert tracker.in_session is True

    def test_in_session_false_for_no_session_id(self):
        tracker = SessionTracker()
        tracker.update(self._make_event(None), color=False)
        assert tracker.in_session is False

    def test_session_end_returns_footer_after(self):
        tracker = SessionTracker()
        tracker.update(self._make_event("sess-001"), color=False)
        end_event = self._make_event("sess-001", event_type="session_end")
        before, after = tracker.update(end_event, color=False)
        assert before is None
        assert after is not None

    def test_session_end_closes_in_session(self):
        tracker = SessionTracker()
        tracker.update(self._make_event("sess-001"), color=False)
        assert tracker.in_session is True
        end_event = self._make_event("sess-001", event_type="session_end")
        tracker.update(end_event, color=False)
        assert tracker.in_session is False

    def test_compact_header_no_unicode_box(self):
        tracker = SessionTracker()
        event = self._make_event("sess-001")
        before, _ = tracker.update(event, color=False, compact=True)
        assert "╭" not in before
        assert "sess-001" in before
        assert "===" in before

    def test_compact_footer_no_unicode_box(self):
        tracker = SessionTracker()
        tracker.update(self._make_event("sess-001"), color=False)
        before, _ = tracker.update(self._make_event("sess-002"), color=False, compact=True)
        assert "╰" not in before
        assert "===" in before

    def test_header_contains_agent_and_framework(self):
        tracker = SessionTracker()
        event = {
            "type": "decision",
            "session_id": "sess-001",
            "agent_id": "my-agent",
            "source_framework": "a3s-code",
            "timestamp": "2026-03-22T10:30:00Z",
        }
        before, _ = tracker.update(event, color=False)
        assert "my-agent" in before
        assert "a3s-code" in before

    def test_no_emoji_header_no_session_emoji(self):
        tracker = SessionTracker()
        event = self._make_event("sess-001")
        before, _ = tracker.update(event, color=False, no_emoji=True)
        assert "📍" not in before
        assert "sess-001" in before


# ---------------------------------------------------------------------------
# TestWatchCLIParser
# ---------------------------------------------------------------------------


class TestWatchCLIParser:
    def test_watch_subcommand_exists(self):
        from clawsentry.cli.main import _build_parser

        parser = _build_parser()
        args, _ = parser.parse_known_args(["watch"])
        assert args.command == "watch"

    def test_watch_flags_parsed(self):
        from clawsentry.cli.main import _build_parser

        parser = _build_parser()
        args, _ = parser.parse_known_args([
            "watch",
            "--gateway-url", "http://localhost:9100",
            "--token", "secret123",
            "--filter", "decision,alert",
            "--json",
            "--no-color",
        ])
        assert args.command == "watch"
        assert args.gateway_url == "http://localhost:9100"
        assert args.token == "secret123"
        assert args.filter == "decision,alert"
        assert args.json is True
        assert args.no_color is True

    def test_interactive_flag_parsed(self):
        from clawsentry.cli.main import _build_parser

        parser = _build_parser()
        args, _ = parser.parse_known_args(["watch", "--interactive"])
        assert args.interactive is True

    def test_interactive_short_flag_parsed(self):
        from clawsentry.cli.main import _build_parser

        parser = _build_parser()
        args, _ = parser.parse_known_args(["watch", "-i"])
        assert args.interactive is True


# ---------------------------------------------------------------------------
# TestNewCLIFlags  (new)
# ---------------------------------------------------------------------------


class TestNewCLIFlags:
    """Tests for watch subcommand ergonomic output flags."""

    def _parse(self, extra_args: list[str]):
        from clawsentry.cli.main import _build_parser

        parser = _build_parser()
        args, _ = parser.parse_known_args(["watch"] + extra_args)
        return args

    def test_verbose_flag_long(self):
        args = self._parse(["--verbose"])
        assert args.verbose is True

    def test_verbose_flag_short(self):
        args = self._parse(["-v"])
        assert args.verbose is True

    def test_verbose_default_false(self):
        args = self._parse([])
        assert args.verbose is False

    def test_no_emoji_flag(self):
        args = self._parse(["--no-emoji"])
        assert args.no_emoji is True

    def test_no_emoji_default_false(self):
        args = self._parse([])
        assert args.no_emoji is False

    def test_compact_flag(self):
        args = self._parse(["--compact"])
        assert args.compact is True

    def test_compact_default_false(self):
        args = self._parse([])
        assert args.compact is False

    def test_priority_only_flag(self):
        args = self._parse(["--priority-only"])
        assert args.priority_only is True

    def test_priority_only_default_false(self):
        args = self._parse([])
        assert args.priority_only is False

    def test_all_new_flags_together(self):
        args = self._parse(["--verbose", "--no-emoji", "--compact", "--priority-only"])
        assert args.verbose is True
        assert args.no_emoji is True
        assert args.compact is True
        assert args.priority_only is True


# ---------------------------------------------------------------------------
# TestInteractivePrompt
# ---------------------------------------------------------------------------


class TestInteractivePrompt:
    """Tests for handle_defer_interactive()."""

    def _make_defer_event(self, **overrides) -> dict:
        """Build a DEFER decision event with sensible defaults."""
        # expires_at is in milliseconds (30 seconds from now)
        base = {
            "type": "decision",
            "decision": "defer",
            "risk_level": "medium",
            "command": "pip install requests",
            "reason": "D3: network access",
            "approval_id": "appr-abc-123",
            "expires_at": int((time.time() + 30) * 1000),
            "timestamp": "2026-03-22T10:30:45Z",
        }
        base.update(overrides)
        return base

    @pytest.mark.asyncio
    async def test_handle_defer_allow(self):
        """User inputs 'a' -> resolve called with allow-once, returns 'allow'."""
        resolve_fn = AsyncMock(return_value=True)
        event = self._make_defer_event()

        result = await handle_defer_interactive(
            event,
            resolve_fn=resolve_fn,
            _input_fn=lambda _prompt: "a",
        )

        assert result == "allow"
        resolve_fn.assert_called_once_with(
            event["approval_id"], "allow-once",
        )

    @pytest.mark.asyncio
    async def test_handle_defer_deny(self):
        """User inputs 'd' -> resolve called with deny + reason, returns 'deny'."""
        resolve_fn = AsyncMock(return_value=True)
        event = self._make_defer_event()

        result = await handle_defer_interactive(
            event,
            resolve_fn=resolve_fn,
            _input_fn=lambda _prompt: "d",
        )

        assert result == "deny"
        resolve_fn.assert_called_once()
        call_args = resolve_fn.call_args
        assert call_args[0][0] == event["approval_id"]
        assert call_args[0][1] == "deny"
        assert "operator denied" in call_args[1]["reason"]

    @pytest.mark.asyncio
    async def test_handle_defer_skip(self):
        """User inputs 's' -> resolve NOT called, returns 'skip'."""
        resolve_fn = AsyncMock(return_value=True)
        event = self._make_defer_event()

        result = await handle_defer_interactive(
            event,
            resolve_fn=resolve_fn,
            _input_fn=lambda _prompt: "s",
        )

        assert result == "skip"
        resolve_fn.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_defer_expired_skips(self):
        """expires_at in the past -> returns 'expired' without prompting."""
        resolve_fn = AsyncMock(return_value=True)
        # Set expires_at to 1 second ago (well within SAFETY_MARGIN_S)
        event = self._make_defer_event(
            expires_at=int((time.time() - 1) * 1000),
        )
        called = False

        def _should_not_be_called(_prompt):
            nonlocal called
            called = True
            return "a"

        result = await handle_defer_interactive(
            event,
            resolve_fn=resolve_fn,
            _input_fn=_should_not_be_called,
        )

        assert result == "expired"
        assert not called, "_input_fn should not have been called"
        resolve_fn.assert_not_called()

    @pytest.mark.asyncio
    async def test_handle_defer_no_approval_id_skips(self):
        """No approval_id -> returns 'skip' without prompting."""
        resolve_fn = AsyncMock(return_value=True)
        event = self._make_defer_event(approval_id=None)
        called = False

        def _should_not_be_called(_prompt):
            nonlocal called
            called = True
            return "a"

        result = await handle_defer_interactive(
            event,
            resolve_fn=resolve_fn,
            _input_fn=_should_not_be_called,
        )

        assert result == "skip"
        assert not called, "_input_fn should not have been called"
        resolve_fn.assert_not_called()


class _FakeSSEStream:
    def __init__(self, lines: list[bytes]) -> None:
        self._lines = lines

    def __iter__(self):
        return iter(self._lines)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestRunWatchInteractive:
    def _make_defer_pending_event(self) -> dict:
        return {
            "type": "defer_pending",
            "session_id": "sess-watch-001",
            "approval_id": "appr-watch-001",
            "tool_name": "bash",
            "command": "rm -rf /tmp/data",
            "reason": "D1: destructive pattern",
            "timeout_s": 300,
            "timestamp": "2026-04-10T12:00:00Z",
        }

    def _stub_single_stream(self, monkeypatch: pytest.MonkeyPatch, event: dict) -> None:
        responses = iter([
            _FakeSSEStream([f"data: {json.dumps(event)}\n".encode("utf-8")]),
            KeyboardInterrupt(),
        ])

        def fake_urlopen(*_args, **_kwargs):
            response = next(responses)
            if isinstance(response, BaseException):
                raise response
            return response

        monkeypatch.setattr(watch_command, "_prefetch_sessions", lambda *_args, **_kwargs: None)
        monkeypatch.setattr(watch_command.urllib.request, "urlopen", fake_urlopen)

    def test_run_watch_interactive_handles_defer_pending_events(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_single_stream(monkeypatch, self._make_defer_pending_event())
        handled: list[dict] = []

        async def fake_handle(event: dict, *, resolve_fn, _input_fn=None):
            handled.append(event)
            return "allow"

        monkeypatch.setattr(watch_command, "handle_defer_interactive", fake_handle)

        watch_command.run_watch("http://gateway.test", interactive=True, color=False)

        assert len(handled) == 1
        assert handled[0]["type"] == "defer_pending"
        assert handled[0]["approval_id"] == "appr-watch-001"
        assert "expires_at" in handled[0]

    def test_run_watch_non_interactive_does_not_prompt_for_defer_pending(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._stub_single_stream(monkeypatch, self._make_defer_pending_event())
        handled = False

        async def fake_handle(event: dict, *, resolve_fn, _input_fn=None):
            nonlocal handled
            handled = True
            return "allow"

        monkeypatch.setattr(watch_command, "handle_defer_interactive", fake_handle)

        watch_command.run_watch("http://gateway.test", interactive=False, color=False)

        assert handled is False


class TestScopeCompletionWatchUX:
    def test_decision_format_shows_scope_evaluation_boundary(self):
        event = {
            "type": "decision",
            "timestamp": "2026-05-02T00:00:00+00:00",
            "decision": "defer",
            "command": "read_file ~/.ssh/id_rsa",
            "risk_level": "medium",
            "reason": "Session scope requires operator review",
            "scope_evaluation": {
                "profile_id": "docs-only",
                "source": "operator",
                "confirmed": False,
                "dry_run": True,
                "enforced": False,
                "verdict": "deny",
                "reason_codes": ["scope_deny:path ~/.ssh"],
            },
        }

        result = format_decision(event, color=False)

        assert "Scope: dry-run only" in result
        assert "docs-only" in result
        assert "scope_deny:path ~/.ssh" in result

    def test_decision_format_shows_sanitize_would_not_enforced(self):
        event = {
            "type": "decision",
            "timestamp": "2026-05-02T00:00:00+00:00",
            "decision": "block",
            "command": "tool output",
            "risk_level": "high",
            "reason": "secret-like output detected",
            "effect_summary": {
                "sanitize_effect": {
                    "target": "tool_output",
                    "advisory_only": True,
                    "outcome": "tool_output_would_sanitize",
                    "redaction_types": ["api_key"],
                    "redaction_counts": {"api_key": 1},
                    "original_preview_redacted": "sk-***",
                    "sanitized_preview_redacted": "[REDACTED:api_key]",
                }
            },
        }

        result = format_decision(event, color=False)

        assert "Sanitizer: would_sanitize tool_output" in result
        assert "api_key=1" in result
        assert "ENFORCED" not in result
        assert "sk-live-secret" not in result

    def test_post_action_finding_formats_sanitize_advisory_without_raw_secret(self):
        event = {
            "type": "post_action_finding",
            "timestamp": "2026-05-02T00:00:00+00:00",
            "session_id": "sess-1",
            "tier": "emergency",
            "score": 0.95,
            "handling": "broadcast",
            "patterns_matched": ["secret_output"],
            "sanitize_advisory": {
                "would_sanitize": True,
                "target": "tool_output",
                "redaction_types": ["api_key"],
                "redaction_counts": {"api_key": 1},
                "redacted_preview": "[REDACTED:api_key]",
            },
        }

        result = format_event(event, color=False)

        assert "Sanitizer: would_sanitize tool_output" in result
        assert "api_key=1" in result
        assert "[REDACTED:api_key]" in result
        assert "sk-live-secret" not in result
