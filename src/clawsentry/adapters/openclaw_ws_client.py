"""
OpenClaw Approval Client — WebSocket client for exec.approval.resolve + event listening.

Maintains a persistent WS connection to OpenClaw Gateway as an operator client.
Handles both outbound RPC (resolve) and inbound events (exec.approval.requested).

Design basis:
  - 11-long-term-evolution-vision.md section 8 (Phase 5.5)
  - OpenClaw Gateway protocol: WebSocket JSON frames
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Coroutine, Optional

from ..gateway.models import DecisionVerdict

logger = logging.getLogger("openclaw-approval-client")

_VALID_DECISIONS = frozenset({"allow-once", "allow-always", "deny"})


class ResolveError(Exception):
    """Raised when OpenClaw responds with an error to a resolve request.

    Carries the error message so callers (e.g. resolve()) can inspect it
    for retry-eligible patterns like "additional properties".
    """

_VERDICT_TO_OPENCLAW: dict[DecisionVerdict, Optional[str]] = {
    DecisionVerdict.ALLOW: "allow-once",
    DecisionVerdict.BLOCK: "deny",
    DecisionVerdict.DEFER: None,
}

# Type alias for event callbacks
ApprovalCallback = Callable[[dict[str, Any]], Coroutine[Any, Any, None]]


def map_verdict_to_openclaw(verdict: DecisionVerdict) -> Optional[str]:
    """Map a Monitor DecisionVerdict to an OpenClaw approval decision string.

    Returns None for DEFER (let OpenClaw timeout naturally).
    """
    return _VERDICT_TO_OPENCLAW.get(verdict)


@dataclass(frozen=True)
class OpenClawApprovalClientConfig:
    """Configuration for the WebSocket approval client."""

    ws_url: str = "ws://127.0.0.1:18789"
    operator_token: str = ""
    enabled: bool = False
    connect_timeout_s: float = 10.0
    resolve_timeout_s: float = 5.0
    max_reconnect_attempts: int = 5
    reconnect_base_delay_s: float = 0.1

    @classmethod
    def from_env(cls, **overrides: Any) -> "OpenClawApprovalClientConfig":
        raw_enabled = os.getenv("OPENCLAW_ENFORCEMENT_ENABLED", "")
        enabled = raw_enabled.strip().lower() in {"1", "true", "yes", "on"}
        base = cls(
            ws_url=os.getenv("OPENCLAW_WS_URL", "ws://127.0.0.1:18789"),
            operator_token=os.getenv("OPENCLAW_OPERATOR_TOKEN", ""),
            enabled=enabled,
        )
        if not overrides:
            return base
        data = {f.name: getattr(base, f.name) for f in base.__dataclass_fields__.values()}
        for key, value in overrides.items():
            if value is None:
                continue
            if key not in data:
                raise TypeError(f"Unknown config field: {key}")
            data[key] = value
        return cls(**data)


class OpenClawApprovalClient:
    """WebSocket client for OpenClaw Gateway operator channel.

    Supports two modes of operation:
    1. Outbound RPC: resolve() calls exec.approval.resolve
    2. Inbound events: start_listening() receives exec.approval.requested

    When the listener is active, all incoming WS frames are routed through
    the listener loop. RPC responses are matched by request ID via Futures.
    """

    def __init__(self, config: OpenClawApprovalClientConfig) -> None:
        self._config = config
        self._ws: Any = None
        self._connected = False
        # Pending RPC requests: request_id → Future[dict]
        self._pending_requests: dict[str, asyncio.Future[dict[str, Any]]] = {}
        # Listener task and callback
        self._listener_task: Optional[asyncio.Task[None]] = None
        self._on_approval_requested: Optional[ApprovalCallback] = None
        self._listening = False

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def listening(self) -> bool:
        return self._listening

    async def connect(self) -> None:
        """Establish WebSocket connection and authenticate with OpenClaw Gateway."""
        if not self._config.enabled:
            return
        try:
            import websockets
        except ImportError:
            logger.error(
                "websockets package not installed. "
                "Install with: pip install clawsentry[enforcement]"
            )
            return

        try:
            self._ws = await websockets.connect(
                self._config.ws_url,
                open_timeout=self._config.connect_timeout_s,
                additional_headers={
                    "Authorization": f"Bearer {self._config.operator_token}",
                    "Origin": self._config.ws_url.replace("ws://", "http://").replace("wss://", "https://"),
                },
            )
            # Wait for connect.challenge
            challenge_raw = await asyncio.wait_for(
                self._ws.recv(),
                timeout=self._config.connect_timeout_s,
            )
            challenge = json.loads(challenge_raw)
            if challenge.get("event") != "connect.challenge":
                logger.warning(
                    "Expected connect.challenge, got: %s", challenge.get("event")
                )

            # Send connect request (token-based auth)
            connect_req = {
                "type": "req",
                "id": uuid.uuid4().hex,
                "method": "connect",
                "params": {
                    "minProtocol": 3,
                    "maxProtocol": 3,
                    "client": {
                        "id": "openclaw-control-ui",
                        "version": "1.0.0",
                        "platform": "linux",
                        "mode": "backend",
                    },
                    "role": "operator",
                    "scopes": [
                        "operator.read",
                        "operator.write",
                        "operator.approvals",
                    ],
                    "caps": [],
                    "commands": [],
                    "permissions": {},
                    "auth": {"token": self._config.operator_token},
                    "locale": "en-US",
                    "userAgent": "clawsentry-enforcement/1.0.0",
                },
            }
            await self._ws.send(json.dumps(connect_req))

            # Wait for hello-ok
            hello_raw = await asyncio.wait_for(
                self._ws.recv(),
                timeout=self._config.connect_timeout_s,
            )
            hello = json.loads(hello_raw)
            if hello.get("ok"):
                self._connected = True
                logger.info(
                    "Connected to OpenClaw Gateway at %s", self._config.ws_url
                )
            else:
                error = hello.get("error", {})
                logger.error(
                    "OpenClaw Gateway auth failed: %s",
                    error.get("message", "unknown"),
                )
        except Exception:
            logger.exception("Failed to connect to OpenClaw Gateway")
            self._connected = False

    async def start_listening(self, on_approval_requested: ApprovalCallback) -> None:
        """Start background event listener loop.

        When exec.approval.requested events arrive, on_approval_requested(payload)
        is called. RPC responses are matched to pending Futures.
        """
        if not self._connected or self._ws is None:
            logger.warning("Cannot start listening: not connected")
            return
        self._on_approval_requested = on_approval_requested
        self._listening = True
        self._listener_task = asyncio.create_task(self._listener_loop())
        logger.info("WS event listener started")

    async def _listener_loop(self) -> None:
        """Background task: read all inbound WS frames, dispatch by type."""
        try:
            async for raw_msg in self._ws:
                try:
                    msg = json.loads(raw_msg)
                except json.JSONDecodeError:
                    logger.warning("Received non-JSON WS frame, ignoring")
                    continue

                msg_type = msg.get("type", "")

                if msg_type == "res":
                    # RPC response — match to pending Future
                    msg_id = msg.get("id")
                    future = self._pending_requests.pop(msg_id, None)
                    if future and not future.done():
                        future.set_result(msg)
                    elif msg_id:
                        logger.debug("Unmatched response id=%s", msg_id)

                elif msg_type == "event":
                    event_name = msg.get("event", "")
                    payload = msg.get("payload", {})
                    if event_name == "exec.approval.requested" and self._on_approval_requested:
                        # Fire-and-forget: callback may call resolve() which
                        # needs the listener loop to read the RPC response.
                        # Running it as a task prevents deadlock.
                        asyncio.create_task(self._run_event_callback(payload))
                    else:
                        logger.debug("Unhandled event: %s", event_name)
                else:
                    logger.debug("Unknown WS frame type: %s", msg_type)

        except Exception as e:
            import websockets
            if isinstance(e, websockets.exceptions.ConnectionClosed):
                logger.warning("WS connection closed: %s", e)
            else:
                logger.exception("Listener loop error")
        finally:
            self._listening = False
            # Fail all pending requests
            for fut in self._pending_requests.values():
                if not fut.done():
                    fut.set_result({"ok": False, "error": {"message": "connection lost"}})
            self._pending_requests.clear()
            logger.info("WS event listener stopped")

    async def _run_event_callback(self, payload: dict[str, Any]) -> None:
        """Run the approval event callback with error handling."""
        try:
            await self._on_approval_requested(payload)  # type: ignore[misc]
        except Exception:
            logger.exception(
                "Error in approval event callback for %s",
                payload.get("id", "?"),
            )

    async def resolve(
        self, approval_id: str, decision: str, *, reason: str | None = None
    ) -> bool:
        """Call exec.approval.resolve on OpenClaw Gateway.

        Args:
            approval_id: The approval request ID to resolve.
            decision: One of "allow-once", "allow-always", "deny".
            reason: Optional human-readable reason for the decision.
                    When provided (including empty string), included in RPC params.
                    When None (default), omitted for backwards compatibility.

        Returns True if the resolve was accepted, False otherwise.
        """
        if not self._config.enabled:
            return False

        if decision not in _VALID_DECISIONS:
            raise ValueError(
                f"Invalid decision: {decision!r}. "
                f"Must be one of: {', '.join(sorted(_VALID_DECISIONS))}"
            )

        params: dict[str, Any] = {"id": approval_id, "decision": decision}
        if reason is not None:
            params["reason"] = reason

        try:
            return await self._send_request(
                "exec.approval.resolve",
                params,
            )
        except Exception as e:
            err_lower = str(e).lower()
            if reason is not None and (
                "additional properties" in err_lower
                or "unexpected property" in err_lower
            ):
                logger.info(
                    "OpenClaw rejected reason field, retrying without it "
                    "(approval=%s)",
                    approval_id,
                )
                try:
                    return await self._send_request(
                        "exec.approval.resolve",
                        {"id": approval_id, "decision": decision},
                    )
                except Exception:
                    logger.exception(
                        "Retry without reason also failed for approval %s",
                        approval_id,
                    )
                    return False
            logger.exception(
                "Failed to resolve approval %s with decision %s",
                approval_id,
                decision,
            )
            return False

    async def _send_request(self, method: str, params: dict[str, Any]) -> bool:
        """Send a JSON-RPC-style request over WebSocket and await response.

        When the listener loop is active, uses Future-based matching.
        Otherwise falls back to simple send-recv.
        """
        if self._ws is None or not self._connected:
            logger.warning("WebSocket not connected, cannot send %s", method)
            return False

        request_id = uuid.uuid4().hex
        frame = {
            "type": "req",
            "id": request_id,
            "method": method,
            "params": params,
        }
        if self._listening and self._listener_task and not self._listener_task.done():
            # Register future BEFORE sending to avoid race condition (H-5)
            future: asyncio.Future[dict[str, Any]] = asyncio.get_running_loop().create_future()
            self._pending_requests[request_id] = future
            await self._ws.send(json.dumps(frame))
            try:
                response = await asyncio.wait_for(
                    future,
                    timeout=self._config.resolve_timeout_s,
                )
            except asyncio.TimeoutError:
                self._pending_requests.pop(request_id, None)
                logger.warning("Request %s timed out", method)
                return False
        else:
            # No listener: simple send-recv (backward-compatible)
            await self._ws.send(json.dumps(frame))
            response_raw = await asyncio.wait_for(
                self._ws.recv(),
                timeout=self._config.resolve_timeout_s,
            )
            response = json.loads(response_raw)

        if response.get("id") != request_id:
            logger.warning(
                "Response ID mismatch: expected %s, got %s",
                request_id,
                response.get("id"),
            )
            return False

        if response.get("ok"):
            logger.info(
                "Approval %s resolved: %s",
                params.get("id"),
                params.get("decision"),
            )
            return True

        error = response.get("error", {})
        error_msg = error.get("message", "unknown error")
        logger.error("Approval resolve failed: %s", error_msg)
        raise ResolveError(error_msg)

    async def stop_listening(self) -> None:
        """Stop the background listener loop."""
        if self._listener_task and not self._listener_task.done():
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
        self._listening = False
        self._listener_task = None

    async def close(self) -> None:
        """Close the WebSocket connection and stop listener."""
        await self.stop_listening()
        self._connected = False
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
