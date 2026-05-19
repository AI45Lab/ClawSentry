"""
OpenClaw Gateway Client — HTTP + UDS client to Supervision Gateway.

Design basis:
  - 03-openclaw-adapter-design.md section 3.4.2 (communication protocol)
  - 04-policy-decision-and-fallback.md section 11.1-11.3 (retry/fallback)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
import sys
import time
from typing import Any, Optional, Literal

from ..gateway.models import (
    CanonicalDecision,
    CanonicalEvent,
    DecisionContext,
    DecisionTier,
    SyncDecisionRequest,
)
from ..gateway.policy_engine import make_fallback_decision

logger = logging.getLogger("openclaw-gateway-client")

_VALID_TRANSPORT_PREFERENCES = {"uds_first", "http_first"}


class OpenClawGatewayClient:
    """
    Client for communicating with the Supervision Gateway.

    Primary: UDS. Fallback: HTTP. Local fallback if both fail.
    """

    SOURCE_FRAMEWORK = "openclaw"
    CALLER_ADAPTER_ID = "openclaw-adapter.v1"

    def __init__(
        self,
        http_url: str = "http://127.0.0.1:8080/ahp",
        uds_path: str = "/tmp/clawsentry.sock",
        default_deadline_ms: int = 100,
        max_rpc_retries: int = 1,
        retry_backoff_ms: int = 50,
        auth_token: str = "",
        transport_preference: Literal["uds_first", "http_first"] = "uds_first",
    ) -> None:
        if transport_preference not in _VALID_TRANSPORT_PREFERENCES:
            raise ValueError(
                "transport_preference must be one of {'uds_first', 'http_first'}"
            )
        self.http_url = http_url
        self.uds_path = uds_path
        self.default_deadline_ms = default_deadline_ms
        self.max_rpc_retries = max_rpc_retries
        self.retry_backoff_ms = retry_backoff_ms
        self.auth_token = auth_token or os.getenv("CS_AUTH_TOKEN", "")
        self.transport_preference = transport_preference
        self.last_decision_response_metadata: dict[str, Any] = {}

    def _transport_chain(self) -> tuple[Any, Any]:
        if self.transport_preference == "http_first":
            return (self._send_http_request, self._send_uds_request)
        return (self._send_uds_request, self._send_http_request)

    async def request_decision(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext] = None,
        deadline_ms: Optional[int] = None,
        decision_tier: DecisionTier = DecisionTier.L1,
    ) -> CanonicalDecision:
        """Send SyncDecision request with retry and fallback."""
        self.last_decision_response_metadata = {}
        effective_deadline = deadline_ms or self.default_deadline_ms
        request_id = f"oc-{event.event_id}-{int(time.monotonic() * 1000)}"
        deadline_start = time.monotonic()
        effective_context = context
        if effective_context is None:
            effective_context = DecisionContext(
                caller_adapter=self.CALLER_ADAPTER_ID
            )
        elif not effective_context.caller_adapter:
            effective_context = effective_context.model_copy(
                update={"caller_adapter": self.CALLER_ADAPTER_ID}
            )

        req = SyncDecisionRequest(
            request_id=request_id,
            deadline_ms=effective_deadline,
            decision_tier=decision_tier,
            event=event,
            context=effective_context,
        )

        last_error: Optional[Exception] = None
        for attempt in range(1 + self.max_rpc_retries):
            elapsed_ms = (time.monotonic() - deadline_start) * 1000
            remaining_ms = effective_deadline - elapsed_ms
            should_retry = False

            if attempt > 0:
                min_required = self.retry_backoff_ms + 20
                if remaining_ms < min_required:
                    break
                await asyncio.sleep(self.retry_backoff_ms / 1000.0)

            for transport_fn in self._transport_chain():
                try:
                    response = await transport_fn(req)
                    if "result" in response:
                        result = response["result"]
                        if result.get("rpc_status") == "ok":
                            self.last_decision_response_metadata = {
                                key: result[key]
                                for key in (
                                    "agent_safety_feedback",
                                    "agent_advisory_feedback",
                                )
                                if result.get(key) is not None
                            }
                            return CanonicalDecision(**result["decision"])
                    if "error" in response:
                        error_data = response["error"].get("data", {})
                        if error_data.get("retry_eligible") and attempt < self.max_rpc_retries:
                            should_retry = True
                            break
                        if "fallback_decision" in error_data and error_data["fallback_decision"]:
                            return CanonicalDecision(**error_data["fallback_decision"])
                    break
                except Exception as e:
                    last_error = e
                    logger.debug(f"Transport failed: {e}")
                    continue
            else:
                # Both transports failed
                continue
            if should_retry:
                continue
            break

        # All retries exhausted: local fallback
        logger.warning(f"Falling back to local decision for event {event.event_id}")
        has_high_danger = bool(
            set(event.risk_hints) & {"destructive_pattern", "shell_execution"}
        )
        return make_fallback_decision(event, risk_hints_contain_high_danger=has_high_danger)

    async def _send_uds_request(self, req: SyncDecisionRequest) -> dict[str, Any]:
        """Send JSON-RPC 2.0 request over UDS."""
        if sys.platform == "win32":
            raise OSError("UDS not supported on Windows")

        jsonrpc_body = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ahp/sync_decision",
            "params": req.model_dump(mode="json"),
        }).encode("utf-8")

        reader, writer = await asyncio.open_unix_connection(self.uds_path)
        try:
            writer.write(struct.pack("!I", len(jsonrpc_body)))
            writer.write(jsonrpc_body)
            await writer.drain()

            length_bytes = await asyncio.wait_for(
                reader.readexactly(4), timeout=req.deadline_ms / 1000.0
            )
            resp_length = struct.unpack("!I", length_bytes)[0]
            if resp_length > 10 * 1024 * 1024:  # 10MB limit
                raise ValueError(f"Response too large: {resp_length} bytes")
            resp_data = await asyncio.wait_for(
                reader.readexactly(resp_length), timeout=req.deadline_ms / 1000.0
            )
            return json.loads(resp_data)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _send_http_request(self, req: SyncDecisionRequest) -> dict[str, Any]:
        """Send JSON-RPC 2.0 request over HTTP using asyncio (no external deps)."""
        from urllib.parse import urlparse

        parsed = urlparse(self.http_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 8080
        path = parsed.path or "/ahp"

        jsonrpc_body = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ahp/sync_decision",
            "params": req.model_dump(mode="json"),
        }).encode("utf-8")

        timeout_s = req.deadline_ms / 1000.0
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout_s,
        )
        try:
            auth_line = ""
            if self.auth_token:
                auth_line = f"Authorization: Bearer {self.auth_token}\r\n"

            request_line = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                f"Content-Type: application/json\r\n"
                f"Content-Length: {len(jsonrpc_body)}\r\n"
                f"{auth_line}"
                f"Connection: close\r\n"
                f"\r\n"
            )
            writer.write(request_line.encode() + jsonrpc_body)
            await writer.drain()

            # Read headers
            header_data = b""
            while b"\r\n\r\n" not in header_data:
                chunk = await asyncio.wait_for(
                    reader.read(4096), timeout=timeout_s
                )
                if not chunk:
                    raise ValueError("Connection closed before headers complete")
                header_data += chunk

            header_end = header_data.index(b"\r\n\r\n")
            headers_raw = header_data[:header_end].decode("utf-8", errors="replace")
            body = header_data[header_end + 4:]

            # Parse Content-Length
            content_length = None
            for line in headers_raw.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    content_length = int(line.split(":", 1)[1].strip())
                    break

            max_body = 10 * 1024 * 1024  # 10MB
            if content_length is not None:
                if content_length > max_body:
                    raise ValueError(f"HTTP response too large: {content_length} bytes")
                remaining = content_length - len(body)
                if remaining > 0:
                    rest = await asyncio.wait_for(
                        reader.readexactly(remaining), timeout=timeout_s
                    )
                    body += rest
            else:
                # No Content-Length: read until connection close (up to 10MB)
                while len(body) < max_body:
                    chunk = await asyncio.wait_for(
                        reader.read(65536), timeout=timeout_s
                    )
                    if not chunk:
                        break
                    body += chunk

            return json.loads(body)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
