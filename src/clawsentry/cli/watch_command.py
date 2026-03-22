"""``clawsentry watch`` — real-time SSE event monitor for the terminal."""

from __future__ import annotations

import asyncio
import json
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Any, Callable

# ── ANSI colour helpers ──────────────────────────────────────────────────────

_COLORS: dict[str, str] = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "bold": "\033[1m",
    "reset": "\033[0m",
}

_DECISION_COLORS: dict[str, str] = {
    "block": "red",
    "allow": "green",
    "defer": "yellow",
    "modify": "cyan",
}

_CMD_MAX_LEN = 40


def _c(name: str, text: str, *, color: bool = True) -> str:
    """Wrap *text* in ANSI colour codes if *color* is enabled."""
    if not color:
        return text
    return f"{_COLORS.get(name, '')}{text}{_COLORS['reset']}"


def _timestamp_hms(ts: str | None) -> str:
    """Extract ``HH:MM:SS`` from an ISO-8601 timestamp string.

    Falls back to the current UTC time if the string cannot be parsed.
    """
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            return dt.strftime("%H:%M:%S")
        except (ValueError, AttributeError):
            pass
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _truncate(text: str, max_len: int = _CMD_MAX_LEN) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


# ── SSE line parser ─────────────────────────────────────────────────────────


def parse_sse_line(line: str) -> dict | None:
    """Parse a single SSE line.

    Returns the parsed JSON dict for ``data:`` lines,
    or ``None`` for comments and blank lines.
    """
    if not line or line.startswith(":"):
        return None
    if line.startswith("data: "):
        payload = line[6:]
        try:
            return json.loads(payload)
        except json.JSONDecodeError:
            return None
    return None


# ── Event formatters ────────────────────────────────────────────────────────


def format_decision(event: dict, *, color: bool = True) -> str:
    """Format a *decision* event for terminal output.

    Example (colour stripped)::

        [10:30:45]  BLOCK   rm -rf /data           risk=high    D1: destructive pattern

    Returns an empty string for observation-only events (pre-prompt / post-response)
    that are always fail-open and carry no tool name — callers should skip these.
    """
    hms = _timestamp_hms(event.get("timestamp"))
    decision = str(event.get("decision") or "unknown").upper()
    command = _truncate(str(event.get("command") or event.get("tool_name") or ""))
    risk = str(event.get("risk_level") or "unknown")
    reason = str(event.get("reason") or "")

    # Skip observation-only events that carry no tool name (pre-prompt, post-response, etc.).
    # These are always fail-open / non-blocking and never actionable for an operator.
    if command.strip() in ("", "None"):
        return ""

    colour_name = _DECISION_COLORS.get(decision.lower(), "cyan")
    decision_str = _c(colour_name, f"{decision:8s}", color=color)

    actual_tier = str(event.get("actual_tier") or "")
    tier_suffix = f" [{actual_tier}]" if actual_tier and actual_tier != "L1" else ""

    parts = [
        f"[{hms}]",
        decision_str,
        f"{command:40s}",
        f"risk={risk}",
    ]
    if reason:
        parts.append(f"   {reason}{tier_suffix}")
    elif tier_suffix:
        parts.append(tier_suffix)

    return "  ".join(parts)


def format_alert(event: dict, *, color: bool = True) -> str:
    """Format an *alert* event for terminal output.

    Example (colour stripped)::

        [10:30:45]  ALERT   sess=sess-001  severity=high  Risk escalation detected
    """
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    severity = str(event.get("severity") or "unknown")
    message = str(event.get("message") or "")

    alert_label = _c("magenta", "ALERT   ", color=color)

    parts = [
        f"[{hms}]",
        alert_label,
        f"sess={session_id}",
        f"severity={severity}",
        message,
    ]
    return "  ".join(parts)


def _format_session_start(event: dict, *, color: bool = True) -> str:
    """Format a *session_start* event for terminal output."""
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    agent_id = str(event.get("agent_id") or "unknown")
    framework = str(event.get("source_framework") or "unknown")

    label = _c("cyan", "SESSION ", color=color)
    parts = [
        f"[{hms}]",
        label,
        f"started  sess={session_id}",
        f"agent={agent_id}",
        f"framework={framework}",
    ]
    return "  ".join(parts)


def _format_risk_change(event: dict, *, color: bool = True) -> str:
    """Format a *session_risk_change* event for terminal output."""
    hms = _timestamp_hms(event.get("timestamp"))
    session_id = str(event.get("session_id") or "unknown")
    prev = str(event.get("previous_risk") or "?")
    curr = str(event.get("current_risk") or "?")

    label = _c("yellow", "RISK    ", color=color)
    parts = [
        f"[{hms}]",
        label,
        f"sess={session_id}",
        f"{prev} -> {curr}",
    ]
    return "  ".join(parts)


def format_event(
    event: dict,
    *,
    color: bool = True,
    json_mode: bool = False,
) -> str:
    """Unified dispatcher: routes to the appropriate formatter.

    If *json_mode* is ``True``, returns ``json.dumps(event)`` regardless of
    event type.
    """
    if json_mode:
        return json.dumps(event)

    event_type = str(event.get("type") or "unknown")

    if event_type == "decision":
        return format_decision(event, color=color)
    if event_type == "alert":
        return format_alert(event, color=color)
    if event_type == "session_start":
        return _format_session_start(event, color=color)
    if event_type == "session_risk_change":
        return _format_risk_change(event, color=color)

    # Fallback: compact JSON
    return json.dumps(event)


# ── Interactive DEFER handler ────────────────────────────────────────────────

SAFETY_MARGIN_S = 5  # seconds before OpenClaw timeout to stop accepting input


async def handle_defer_interactive(
    event: dict,
    *,
    resolve_fn: Callable[..., Any],
    _input_fn: Callable[[str], str] | None = None,
) -> str:
    """Handle a DEFER decision interactively.

    Returns one of: ``"allow"``, ``"deny"``, ``"skip"``, or ``"expired"``.

    Parameters
    ----------
    event:
        The SSE decision event dict (must contain ``approval_id`` and
        optionally ``expires_at`` in epoch-milliseconds).
    resolve_fn:
        ``async fn(approval_id, decision, *, reason=None) -> bool``
        called to resolve the approval in the upstream gateway.
    _input_fn:
        Injectable synchronous callable for testing. Receives the prompt
        string and returns the user answer.  When ``None`` (production),
        uses ``asyncio`` + blocking ``input()`` with a timeout.
    """
    approval_id = event.get("approval_id")
    if not approval_id:
        return "skip"

    # ── compute remaining time budget ────────────────────────────────────
    expires_at_ms = event.get("expires_at")
    remaining: float | None = None
    if expires_at_ms is not None:
        remaining = (expires_at_ms / 1000) - time.time() - SAFETY_MARGIN_S
        if remaining <= 0:
            return "expired"

    # ── build prompt ─────────────────────────────────────────────────────
    reason = event.get("reason") or ""
    command = event.get("command") or ""
    timeout_hint = f" (timeout in {int(remaining)}s)" if remaining else ""
    prompt = (
        f"\n  Command: {command}\n"
        f"  Reason:  {reason}\n"
        f"  [A]llow  [D]eny  [S]kip{timeout_hint} > "
    )

    # ── get user input ───────────────────────────────────────────────────
    try:
        if _input_fn is not None:
            answer = _input_fn(prompt)
        else:
            loop = asyncio.get_running_loop()
            if remaining is not None:
                answer = await asyncio.wait_for(
                    loop.run_in_executor(None, input, prompt),
                    timeout=remaining,
                )
            else:
                answer = await loop.run_in_executor(None, input, prompt)
    except (asyncio.TimeoutError, EOFError):
        return "skip"

    choice = answer.strip().lower()

    if choice == "a":
        await resolve_fn(approval_id, "allow-once")
        return "allow"
    elif choice == "d":
        await resolve_fn(
            approval_id, "deny", reason="operator denied via watch CLI",
        )
        return "deny"
    # 's', empty, or anything else → skip
    return "skip"


# ── CLI runner ───────────────────────────────────────────────────────────────

_RECONNECT_DELAY = 3.0


def run_watch(
    gateway_url: str,
    token: str | None = None,
    filter_types: str | None = None,
    json_mode: bool = False,
    color: bool = True,
    interactive: bool = False,
) -> None:
    """Connect to the Gateway SSE stream and print events.

    This is a **blocking** call that runs until interrupted with ``Ctrl-C``.

    Parameters
    ----------
    gateway_url:
        Base URL of the Supervision Gateway (e.g. ``http://localhost:9100``).
    token:
        Optional Bearer token for authentication.
    filter_types:
        Comma-separated event types to subscribe to
        (e.g. ``"decision,alert"``).
    json_mode:
        If ``True``, output raw JSON instead of formatted text.
    color:
        If ``False``, strip ANSI colour codes from output.
    interactive:
        If ``True``, prompt operator to Allow/Deny/Skip on DEFER decisions.
    """
    url = f"{gateway_url.rstrip('/')}/report/stream"
    if filter_types:
        url += f"?types={filter_types}"

    headers: dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    while True:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req) as resp:
                if not json_mode:
                    print(
                        _c("bold", f"Connected to {gateway_url}", color=color),
                        flush=True,
                    )
                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").rstrip("\n\r")
                    parsed = parse_sse_line(line)
                    if parsed is None:
                        continue
                    output = format_event(parsed, color=color, json_mode=json_mode)
                    if not output:
                        continue
                    print(output, flush=True)

        except KeyboardInterrupt:
            if not json_mode:
                print(
                    _c("bold", "\nDisconnected.", color=color),
                    file=sys.stderr,
                    flush=True,
                )
            break

        except (urllib.error.URLError, OSError) as exc:
            if not json_mode:
                print(
                    _c(
                        "yellow",
                        f"Connection failed: {exc} — retrying in {_RECONNECT_DELAY}s ...",
                        color=color,
                    ),
                    file=sys.stderr,
                    flush=True,
                )
            time.sleep(_RECONNECT_DELAY)
