"""Standard a3s-code AHP stdio harness bridged to ClawSentry Gateway."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime
from typing import Any, Optional

try:
    from .a3s_adapter import A3SCodeAdapter
    from ..gateway.models import CanonicalDecision, DecisionVerdict
except ImportError:
    # Support direct script execution:
    # python src/clawsentry/adapters/a3s_gateway_harness.py
    from pathlib import Path

    _SRC_ROOT = str(Path(__file__).resolve().parent.parent.parent)
    if _SRC_ROOT not in sys.path:
        sys.path.insert(0, _SRC_ROOT)
    from clawsentry.adapters.a3s_adapter import A3SCodeAdapter  # type: ignore[no-redef]
    from clawsentry.gateway.models import CanonicalDecision, DecisionVerdict  # type: ignore[no-redef]

logger = logging.getLogger("a3s-gateway-harness")

_EVENT_TO_HOOK: dict[str, str] = {
    "pre_action": "PreToolUse",
    "pre_tool_use": "PreToolUse",
    "post_action": "PostToolUse",
    "post_tool_use": "PostToolUse",
    "pre_prompt": "PrePrompt",
    "generate_start": "GenerateStart",
    "session_start": "SessionStart",
    "session_end": "SessionEnd",
    "error": "OnError",
}


def _log_stderr(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] [a3s-gateway-harness] {msg}", file=sys.stderr, flush=True)


def _resolve_payload(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        payload = dict(raw)
    else:
        payload = {}

    if "arguments" not in payload and isinstance(payload.get("args"), dict):
        payload["arguments"] = payload["args"]

    if "tool" not in payload and isinstance(payload.get("tool_name"), str):
        payload["tool"] = payload["tool_name"]

    args = payload.get("arguments")
    if isinstance(args, dict):
        for key in ("command", "path", "target", "file_path"):
            if key in args and key not in payload:
                payload[key] = args[key]

    return payload


def _resolve_string(*values: Any) -> Optional[str]:
    for v in values:
        if isinstance(v, str) and v.strip():
            return v
    return None


def _decision_to_ahp_result(decision: CanonicalDecision) -> dict[str, Any]:
    action = "continue"
    if decision.decision == DecisionVerdict.BLOCK:
        action = "block"
    elif decision.decision == DecisionVerdict.MODIFY:
        action = "modify"
    elif decision.decision == DecisionVerdict.DEFER:
        action = "defer"

    result: dict[str, Any] = {
        "action": action,
        "decision": decision.decision.value,
        "reason": decision.reason,
        "metadata": {
            "source": "clawsentry-gateway-harness",
            "policy_id": decision.policy_id,
            "risk_level": decision.risk_level.value,
            "decision_source": decision.decision_source.value,
            "final": decision.final,
        },
    }
    if decision.modified_payload is not None:
        result["modified_payload"] = decision.modified_payload
    if decision.retry_after_ms is not None:
        result["retry_after_ms"] = decision.retry_after_ms

    return result


class A3SGatewayHarness:
    """Bridge AHP stdio requests to ClawSentry Gateway decisions."""

    def __init__(
        self,
        adapter: A3SCodeAdapter,
        *,
        protocol_version: str = "2.0",
        harness_name: str = "a3s-gateway-harness",
        harness_version: str = "1.0.0",
        default_session_id: str = "ahp-session",
        default_agent_id: str = "ahp-agent",
    ) -> None:
        self.adapter = adapter
        self.protocol_version = protocol_version
        self.harness_name = harness_name
        self.harness_version = harness_version
        self.default_session_id = default_session_id
        self.default_agent_id = default_agent_id

    def _handshake_result(self) -> dict[str, Any]:
        return {
            "protocol_version": self.protocol_version,
            "harness_info": {
                "name": self.harness_name,
                "version": self.harness_version,
                "capabilities": [
                    "pre_action",
                    "post_action",
                    "pre_prompt",
                    "session",
                    "error",
                ],
            },
        }

    async def _handle_event(self, params: dict[str, Any]) -> dict[str, Any]:
        event_type_raw = str(params.get("event_type", "")).strip().lower()
        payload = _resolve_payload(params.get("payload"))

        hook_type = _EVENT_TO_HOOK.get(event_type_raw)
        if hook_type is None:
            return {
                "action": "continue",
                "decision": "allow",
                "reason": f"Unmapped event_type: {event_type_raw or 'unknown'}",
                "metadata": {"source": "clawsentry-gateway-harness"},
            }

        session_id = _resolve_string(
            params.get("session_id"),
            params.get("sessionKey"),
            payload.get("session_id"),
            payload.get("sessionKey"),
            self.default_session_id,
        )
        agent_id = _resolve_string(
            params.get("agent_id"),
            params.get("agentId"),
            payload.get("agent_id"),
            payload.get("agentId"),
            self.default_agent_id,
        )

        evt = self.adapter.normalize_hook_event(
            hook_type,
            payload,
            session_id=session_id,
            agent_id=agent_id,
        )
        if evt is None:
            return {
                "action": "continue",
                "decision": "allow",
                "reason": f"Event filtered: hook_type={hook_type}",
                "metadata": {"source": "clawsentry-gateway-harness"},
            }

        decision = await self.adapter.request_decision(evt)
        return _decision_to_ahp_result(decision)

    async def dispatch_async(self, msg: dict[str, Any]) -> Optional[dict[str, Any]]:
        req_id = msg.get("id")
        method = msg.get("method")
        params_raw = msg.get("params")
        params = params_raw if isinstance(params_raw, dict) else {}

        if method == "ahp/handshake":
            if req_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": self._handshake_result(),
            }

        try:
            result = await self._handle_event(params)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed handling AHP event")
            if req_id is None:
                return None
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32000,
                    "message": "AHP harness internal error",
                    "data": {"detail": "Internal harness error. Check server logs for details."},
                },
            }

        if req_id is None:
            return None

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }

    def run_stdio(self) -> None:
        _log_stderr("harness started")
        for raw_line in sys.stdin:
            line = raw_line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError as exc:
                _log_stderr(f"invalid json: {exc}")
                continue

            response = asyncio.run(self.dispatch_async(msg))
            if response is not None:
                print(json.dumps(response, ensure_ascii=False), flush=True)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a3s-code AHP stdio harness bridged to ClawSentry Gateway."
    )
    parser.add_argument(
        "--uds-path",
        default=os.getenv("CS_UDS_PATH", "/tmp/clawsentry.sock"),
    )
    parser.add_argument(
        "--default-deadline-ms",
        type=int,
        default=int(os.getenv("A3S_GATEWAY_DEFAULT_DEADLINE_MS", "4500")),
    )
    parser.add_argument(
        "--max-rpc-retries",
        type=int,
        default=int(os.getenv("A3S_GATEWAY_MAX_RPC_RETRIES", "1")),
    )
    parser.add_argument(
        "--retry-backoff-ms",
        type=int,
        default=int(os.getenv("A3S_GATEWAY_RETRY_BACKOFF_MS", "50")),
    )
    parser.add_argument(
        "--default-session-id",
        default=os.getenv("A3S_GATEWAY_DEFAULT_SESSION_ID", "ahp-session"),
    )
    parser.add_argument(
        "--default-agent-id",
        default=os.getenv("A3S_GATEWAY_DEFAULT_AGENT_ID", "ahp-agent"),
    )
    return parser


def main() -> None:
    parser = _build_arg_parser()
    args = parser.parse_args()

    adapter = A3SCodeAdapter(
        uds_path=args.uds_path,
        default_deadline_ms=args.default_deadline_ms,
        max_rpc_retries=args.max_rpc_retries,
        retry_backoff_ms=args.retry_backoff_ms,
    )
    harness = A3SGatewayHarness(
        adapter,
        default_session_id=args.default_session_id,
        default_agent_id=args.default_agent_id,
    )
    harness.run_stdio()


if __name__ == "__main__":
    main()
