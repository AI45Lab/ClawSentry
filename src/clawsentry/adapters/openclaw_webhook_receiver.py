"""
OpenClaw Webhook Receiver — FastAPI server for Webhook events.

Design basis:
  - 03-openclaw-adapter-design.md section 3.2, 3.4
  - 08-openclaw-webhook-security-hardening.md section 4.1
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any

from fastapi import FastAPI, Request, Response

from .openclaw_normalizer import OpenClawNormalizer
from .webhook_security import (
    WebhookSecurityConfig,
    verify_webhook_request,
)

logger = logging.getLogger("openclaw-webhook-receiver")


def create_webhook_app(
    config: WebhookSecurityConfig,
    normalizer: OpenClawNormalizer,
    gateway_client: Any,  # OpenClawGatewayClient (duck-typed for testability)
    idem_max_size: int = 10_000,
    idem_ttl_seconds: int = 300,
) -> FastAPI:
    """Create FastAPI app for the OpenClaw Webhook Receiver."""
    app = FastAPI(title="OpenClaw Webhook Receiver", version="1.0")

    # Bounded in-memory idempotency cache with TTL for Webhook dedup
    _idem_cache: dict[str, tuple[str, dict, float]] = {}  # key -> (request_hash, result, expire_at)

    @app.get("/health")
    async def health():
        return {"status": "healthy", "component": "openclaw-webhook-receiver"}

    @app.post("/webhook/openclaw")
    async def webhook_endpoint(request: Request) -> Response:
        body = await request.body()

        # Extract headers
        auth_header = request.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer") else auth_header
        signature = request.headers.get("X-AHP-Signature")
        timestamp = request.headers.get("X-AHP-Timestamp")
        content_type = request.headers.get("Content-Type", "")
        source_url = str(request.url)

        # Security verification
        source_ip = request.client.host if request.client else ""
        check = verify_webhook_request(
            config=config,
            token=token,
            signature=signature,
            timestamp=timestamp,
            content_type=content_type,
            body=body,
            source_url=source_url,
            source_ip=source_ip,
        )

        if not check.ok:
            return Response(
                content=json.dumps({
                    "error": check.message,
                    "failure_class": check.failure_class.value,
                }),
                status_code=check.http_status,
                media_type="application/json",
            )

        parsed = check.parsed_body
        request_hash = hashlib.sha256(
            json.dumps(parsed, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

        # Idempotency dedup (with TTL and bounded size)
        idem_key = parsed.get("idempotencyKey")
        now = time.monotonic()
        if idem_key and idem_key in _idem_cache:
            cached_hash, cached_result, expire_at = _idem_cache[idem_key]
            if now <= expire_at:
                if cached_hash != request_hash:
                    return Response(
                        content=json.dumps({
                            "error": "Idempotency key reuse with different request payload",
                            "failure_class": "invalid_request",
                        }),
                        status_code=409,
                        media_type="application/json",
                    )
                return Response(
                    content=json.dumps(cached_result),
                    media_type="application/json",
                )
            else:
                del _idem_cache[idem_key]

        # Normalize to CanonicalEvent
        event_type = parsed["type"]
        session_id = parsed.get("sessionKey")
        agent_id = parsed.get("agentId")
        payload = parsed.get("payload", parsed)
        run_id = (
            parsed.get("run_id")
            or parsed.get("runId")
            or (payload.get("run_id") if isinstance(payload, dict) else None)
            or (payload.get("runId") if isinstance(payload, dict) else None)
        )
        source_seq_raw = parsed.get("source_seq", parsed.get("sourceSeq"))
        if source_seq_raw is None and isinstance(payload, dict):
            source_seq_raw = payload.get("source_seq", payload.get("sourceSeq"))
        try:
            source_seq = int(source_seq_raw) if source_seq_raw is not None else None
        except (TypeError, ValueError):
            source_seq = None

        canonical_event = normalizer.normalize(
            event_type=event_type,
            payload=payload,
            session_id=session_id,
            agent_id=agent_id,
            run_id=run_id,
            source_seq=source_seq,
        )

        if canonical_event is None:
            return Response(
                content=json.dumps({"error": f"Unmapped event type: {event_type}"}),
                status_code=422,
                media_type="application/json",
            )

        # Request decision from Gateway
        decision = await gateway_client.request_decision(canonical_event)

        result = {
            "decision": decision.decision.value,
            "reason": decision.reason,
            "risk_level": decision.risk_level.value,
            "failure_class": decision.failure_class.value,
            "final": decision.final,
        }

        # Cache result if idempotency key present (bounded + TTL)
        if idem_key:
            # Evict expired entries if at capacity
            if len(_idem_cache) >= idem_max_size:
                expired_keys = [
                    k for k, (_, _, exp) in _idem_cache.items() if now > exp
                ]
                for k in expired_keys:
                    del _idem_cache[k]
                # If still at capacity, evict oldest
                while len(_idem_cache) >= idem_max_size:
                    oldest_key = next(iter(_idem_cache))
                    del _idem_cache[oldest_key]
            _idem_cache[idem_key] = (request_hash, result, now + idem_ttl_seconds)

        return Response(
            content=json.dumps(result),
            media_type="application/json",
        )

    return app
