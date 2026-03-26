"""
AHP Supervision Gateway — UDS + HTTP dual-transport server.

Design basis:
  - 01-scope-and-architecture.md section 6 (Sidecar + UDS + HTTP)
  - 04-policy-decision-and-fallback.md section 8-11 (SyncDecision v1 / JSON-RPC 2.0)

Transports:
  - Primary: Unix Domain Socket at /tmp/clawsentry.sock
  - Backup: HTTP at localhost:8080
"""

from __future__ import annotations

import asyncio
from collections import defaultdict, deque
from datetime import datetime, timezone
import hmac
import json
import argparse
import logging
import os
import sqlite3
import struct
import time
from typing import Any, Callable, Optional

from pathlib import Path
import uuid
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse
from starlette.responses import FileResponse, HTMLResponse
from pydantic import ValidationError

from .idempotency import IdempotencyCache, periodic_cleanup
from .models import (
    CanonicalDecision,
    CanonicalEvent,
    DecisionContext,
    DecisionSource,
    DecisionTier,
    DecisionVerdict,
    EventType,
    FailureClass,
    RiskLevel,
    RPCErrorCode,
    RPC_VERSION,
    SyncDecisionErrorResponse,
    SyncDecisionRequest,
    SyncDecisionResponse,
    utc_now_iso,
)
from .detection_config import DetectionConfig, build_detection_config_from_env
from .llm_factory import build_analyzer_from_env
from .pattern_evolution import PatternEvolutionManager
from .policy_engine import L1PolicyEngine
from .post_action_analyzer import PostActionAnalyzer
from .trajectory_analyzer import TrajectoryAnalyzer
from .session_enforcement import (
    EnforcementAction,
    SessionEnforcementPolicy,
)

logger = logging.getLogger("clawsentry")

_DEFAULT_UI_DIR = Path(__file__).parent.parent / "ui" / "dist"

# ---------------------------------------------------------------------------
# Shared risk-level helpers
# ---------------------------------------------------------------------------

_RISK_LEVEL_RANK: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

def _risk_rank(risk_level: Optional[str]) -> int:
    return _RISK_LEVEL_RANK.get(str(risk_level or "low").lower(), 0)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_UDS_PATH = "/tmp/clawsentry.sock"
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8080
DEFAULT_TRAJECTORY_DB_PATH = "/tmp/clawsentry-trajectory.db"
DEFAULT_TRAJECTORY_RETENTION_SECONDS = 30 * 24 * 3600
HIGH_RISK_LEVELS = {"high", "critical"}

INVALID_EVENT_COUNT_THRESHOLD_1M = 20
INVALID_EVENT_RATE_CRITICAL_5M = 0.01
INVALID_EVENT_RATE_WARNING_15M_MIN = 0.001
INVALID_EVENT_RATE_WARNING_15M_MAX = 0.01

JSONRPC_METHOD = "ahp/sync_decision"
JSONRPC_VERSION = "2.0"
MAX_WINDOW_SECONDS = 604800  # 1 week = 7 * 24 * 3600

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def _read_auth_token() -> str:
    """Read auth token from environment. Empty string means auth disabled."""
    return os.getenv("CS_AUTH_TOKEN", "")


def _make_auth_dependency(auth_token: str):
    """Create a FastAPI dependency that enforces Bearer token auth.

    When auth_token is empty, returns a no-op dependency (auth disabled).
    """
    if not auth_token:
        async def _no_auth(request: Request):  # noqa: ARG001
            pass
        return _no_auth

    async def _require_bearer(request: Request):
        # 1. Try Authorization: Bearer header first
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # len("Bearer ") == 7
            if hmac.compare_digest(token, auth_token):
                return None  # Authorized via header

        # 2. Fallback: try ?token= query param (for browser EventSource)
        query_token = request.query_params.get("token", "")
        if query_token and hmac.compare_digest(query_token, auth_token):
            return None  # Authorized via query param

        # 3. Both methods failed — reject
        return Response(
            content=json.dumps({"error": "Unauthorized"}),
            status_code=401,
            media_type="application/json",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return _require_bearer


# ---------------------------------------------------------------------------
# Trajectory Store (SQLite persistence, Phase 3 minimal)
# ---------------------------------------------------------------------------

class TrajectoryStore:
    """SQLite-backed trajectory store with retention + query window support."""

    def __init__(
        self,
        db_path: str = ":memory:",
        retention_seconds: int = DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    ) -> None:
        self.db_path = db_path
        self.retention_seconds = retention_seconds
        if db_path != ":memory:":
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()
        self._prune_expired()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS trajectory_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recorded_at_ts REAL NOT NULL,
                recorded_at TEXT NOT NULL,
                session_id TEXT,
                source_framework TEXT,
                event_type TEXT,
                decision TEXT,
                risk_level TEXT,
                event_json TEXT NOT NULL,
                decision_json TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                meta_json TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_traj_recorded_at ON trajectory_records(recorded_at_ts)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_traj_session_id ON trajectory_records(session_id)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_traj_source_framework ON trajectory_records(source_framework)"
        )
        # Migrate: add l3_trace_json column if missing
        try:
            cur.execute("ALTER TABLE trajectory_records ADD COLUMN l3_trace_json TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        self._conn.commit()

    @staticmethod
    def _iso_from_ts(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    def _prune_expired(self, now_ts: Optional[float] = None) -> None:
        if self.retention_seconds <= 0:
            return
        cutoff = (now_ts or time.time()) - self.retention_seconds
        cur = self._conn.cursor()
        cur.execute("DELETE FROM trajectory_records WHERE recorded_at_ts < ?", (cutoff,))
        self._conn.commit()

    def record(
        self,
        event: dict,
        decision: dict,
        snapshot: dict,
        meta: dict,
        recorded_at_ts: Optional[float] = None,
        l3_trace: Optional[dict] = None,
    ) -> None:
        ts = recorded_at_ts if recorded_at_ts is not None else time.time()
        recorded_at = self._iso_from_ts(ts)
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO trajectory_records (
                recorded_at_ts,
                recorded_at,
                session_id,
                source_framework,
                event_type,
                decision,
                risk_level,
                event_json,
                decision_json,
                snapshot_json,
                meta_json,
                l3_trace_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ts,
                recorded_at,
                event.get("session_id"),
                event.get("source_framework"),
                event.get("event_type"),
                decision.get("decision"),
                decision.get("risk_level"),
                json.dumps(event),
                json.dumps(decision),
                json.dumps(snapshot),
                json.dumps(meta),
                json.dumps(l3_trace) if l3_trace else None,
            ),
        )
        self._conn.commit()
        self._prune_expired(now_ts=ts)

    def _query_records(
        self,
        *,
        session_id: Optional[str] = None,
        since_seconds: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        self._prune_expired()
        clauses: list[str] = []
        params: list[Any] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if since_seconds is not None and since_seconds > 0:
            clauses.append("recorded_at_ts >= ?")
            params.append(time.time() - since_seconds)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        if limit is not None and limit > 0:
            sql = (
                "SELECT recorded_at_ts, recorded_at, event_json, decision_json, snapshot_json, meta_json, l3_trace_json "
                "FROM trajectory_records "
                f"{where_sql} "
                "ORDER BY id DESC LIMIT ?"
            )
            rows = self._conn.execute(sql, (*params, limit)).fetchall()
            rows = list(reversed(rows))
        else:
            sql = (
                "SELECT recorded_at_ts, recorded_at, event_json, decision_json, snapshot_json, meta_json, l3_trace_json "
                "FROM trajectory_records "
                f"{where_sql} "
                "ORDER BY id ASC"
            )
            rows = self._conn.execute(sql, params).fetchall()

        records: list[dict[str, Any]] = []
        for row in rows:
            l3_raw = row["l3_trace_json"]
            records.append(
                {
                    "event": json.loads(row["event_json"]),
                    "decision": json.loads(row["decision_json"]),
                    "risk_snapshot": json.loads(row["snapshot_json"]),
                    "meta": json.loads(row["meta_json"]),
                    "recorded_at": row["recorded_at"],
                    "recorded_at_ts": float(row["recorded_at_ts"]),
                    "l3_trace": json.loads(l3_raw) if l3_raw else None,
                }
            )
        return records

    @property
    def records(self) -> list[dict[str, Any]]:
        return self._query_records()

    def count(self, since_seconds: Optional[int] = None) -> int:
        self._prune_expired()
        clauses: list[str] = []
        params: list[Any] = []
        if since_seconds is not None and since_seconds > 0:
            clauses.append("recorded_at_ts >= ?")
            params.append(time.time() - since_seconds)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT COUNT(*) AS c FROM trajectory_records {where_sql}"
        row = self._conn.execute(sql, params).fetchone()
        return int(row["c"]) if row else 0

    def summary(self, since_seconds: Optional[int] = None) -> dict[str, Any]:
        records = self._query_records(since_seconds=since_seconds)
        by_source_framework: dict[str, int] = defaultdict(int)
        by_event_type: dict[str, int] = defaultdict(int)
        by_decision: dict[str, int] = defaultdict(int)
        by_risk_level: dict[str, int] = defaultdict(int)
        by_actual_tier: dict[str, int] = defaultdict(int)
        by_caller_adapter: dict[str, int] = defaultdict(int)
        now_ts = time.time()

        for rec in records:
            event = rec.get("event", {})
            decision = rec.get("decision", {})
            meta = rec.get("meta", {})
            source_framework = str(event.get("source_framework", "unknown"))
            event_type = str(event.get("event_type", "unknown"))
            decision_verdict = str(decision.get("decision", "unknown"))
            risk_level = str(decision.get("risk_level", "unknown"))
            actual_tier = str(meta.get("actual_tier", "L1"))
            caller_adapter = str(meta.get("caller_adapter", "unknown"))

            by_source_framework[source_framework] += 1
            by_event_type[event_type] += 1
            by_decision[decision_verdict] += 1
            by_risk_level[risk_level] += 1
            by_actual_tier[actual_tier] += 1
            by_caller_adapter[caller_adapter] += 1

        return {
            "total_records": len(records),
            "by_source_framework": dict(by_source_framework),
            "by_event_type": dict(by_event_type),
            "by_decision": dict(by_decision),
            "by_risk_level": dict(by_risk_level),
            "by_actual_tier": dict(by_actual_tier),
            "by_caller_adapter": dict(by_caller_adapter),
            "invalid_event": self._build_invalid_event_metrics(records, now_ts),
            "high_risk_trend": self._build_high_risk_trend(records, now_ts),
        }

    @staticmethod
    def _is_invalid_event_record(record: dict[str, Any]) -> bool:
        event = record.get("event", {})
        decision = record.get("decision", {})
        event_type = str(event.get("event_type", "")).lower()
        event_subtype = str(event.get("event_subtype", "")).lower()
        failure_class = str(decision.get("failure_class", "")).lower()
        return (
            event_type == "invalid_event"
            or event_subtype == "invalid_event"
            or failure_class == "input_invalid"
        )

    @staticmethod
    def _is_high_risk_record(record: dict[str, Any]) -> bool:
        decision = record.get("decision", {})
        risk_level = str(decision.get("risk_level", "")).lower()
        return risk_level in HIGH_RISK_LEVELS

    @staticmethod
    def _count_in_window(
        records: list[dict[str, Any]],
        *,
        now_ts: float,
        window_seconds: int,
        predicate: Optional[Callable[[dict[str, Any]], bool]] = None,
    ) -> int:
        cutoff = now_ts - window_seconds
        count = 0
        for rec in records:
            recorded_at_ts = float(rec.get("recorded_at_ts", 0.0))
            if recorded_at_ts < cutoff:
                continue
            if predicate is not None and not predicate(rec):
                continue
            count += 1
        return count

    @staticmethod
    def _count_in_range(
        records: list[dict[str, Any]],
        *,
        start_ts: float,
        end_ts: float,
        predicate: Optional[Callable[[dict[str, Any]], bool]] = None,
    ) -> int:
        count = 0
        for rec in records:
            recorded_at_ts = float(rec.get("recorded_at_ts", 0.0))
            if recorded_at_ts < start_ts or recorded_at_ts >= end_ts:
                continue
            if predicate is not None and not predicate(rec):
                continue
            count += 1
        return count

    def _build_invalid_event_metrics(
        self,
        records: list[dict[str, Any]],
        now_ts: float,
    ) -> dict[str, Any]:
        total_5m = self._count_in_window(records, now_ts=now_ts, window_seconds=300)
        total_15m = self._count_in_window(records, now_ts=now_ts, window_seconds=900)
        invalid_1m = self._count_in_window(
            records,
            now_ts=now_ts,
            window_seconds=60,
            predicate=self._is_invalid_event_record,
        )
        invalid_5m = self._count_in_window(
            records,
            now_ts=now_ts,
            window_seconds=300,
            predicate=self._is_invalid_event_record,
        )
        invalid_15m = self._count_in_window(
            records,
            now_ts=now_ts,
            window_seconds=900,
            predicate=self._is_invalid_event_record,
        )

        rate_5m = (invalid_5m / total_5m) if total_5m > 0 else 0.0
        rate_15m = (invalid_15m / total_15m) if total_15m > 0 else 0.0

        alerts: list[dict[str, Any]] = []
        if invalid_1m > INVALID_EVENT_COUNT_THRESHOLD_1M:
            alerts.append(
                {
                    "metric": "invalid_event_count_1m",
                    "severity": "critical",
                    "value": invalid_1m,
                    "threshold": ">20/min",
                }
            )
        if rate_5m > INVALID_EVENT_RATE_CRITICAL_5M:
            alerts.append(
                {
                    "metric": "invalid_event_rate_5m",
                    "severity": "critical",
                    "value": rate_5m,
                    "threshold": ">1%/5m",
                }
            )
        if (
            total_15m > 0
            and INVALID_EVENT_RATE_WARNING_15M_MIN <= rate_15m <= INVALID_EVENT_RATE_WARNING_15M_MAX
        ):
            alerts.append(
                {
                    "metric": "invalid_event_rate_15m",
                    "severity": "warning",
                    "value": rate_15m,
                    "threshold": "0.1%-1%/15m",
                }
            )

        return {
            "count_1m": invalid_1m,
            "count_5m": invalid_5m,
            "count_15m": invalid_15m,
            "rate_5m": rate_5m,
            "rate_15m": rate_15m,
            "alerts": alerts,
        }

    def _build_high_risk_trend(
        self,
        records: list[dict[str, Any]],
        now_ts: float,
    ) -> dict[str, Any]:
        def ratio(high_count: int, total_count: int) -> float:
            return (high_count / total_count) if total_count > 0 else 0.0

        total_5m = self._count_in_window(records, now_ts=now_ts, window_seconds=300)
        total_15m = self._count_in_window(records, now_ts=now_ts, window_seconds=900)
        total_60m = self._count_in_window(records, now_ts=now_ts, window_seconds=3600)

        high_5m = self._count_in_window(
            records,
            now_ts=now_ts,
            window_seconds=300,
            predicate=self._is_high_risk_record,
        )
        high_15m = self._count_in_window(
            records,
            now_ts=now_ts,
            window_seconds=900,
            predicate=self._is_high_risk_record,
        )
        high_60m = self._count_in_window(
            records,
            now_ts=now_ts,
            window_seconds=3600,
            predicate=self._is_high_risk_record,
        )

        prev_5m_high = self._count_in_range(
            records,
            start_ts=now_ts - 600,
            end_ts=now_ts - 300,
            predicate=self._is_high_risk_record,
        )
        if high_5m > prev_5m_high:
            direction_5m = "up"
        elif high_5m < prev_5m_high:
            direction_5m = "down"
        else:
            direction_5m = "flat"

        series_5m: list[dict[str, Any]] = []
        for idx in range(12):
            bucket_start_ts = now_ts - (12 - idx) * 300
            bucket_end_ts = bucket_start_ts + 300
            total_bucket = self._count_in_range(
                records,
                start_ts=bucket_start_ts,
                end_ts=bucket_end_ts,
            )
            high_bucket = self._count_in_range(
                records,
                start_ts=bucket_start_ts,
                end_ts=bucket_end_ts,
                predicate=self._is_high_risk_record,
            )
            series_5m.append(
                {
                    "bucket_start": self._iso_from_ts(bucket_start_ts),
                    "bucket_end": self._iso_from_ts(bucket_end_ts),
                    "total_count": total_bucket,
                    "high_or_critical_count": high_bucket,
                    "ratio": ratio(high_bucket, total_bucket),
                }
            )

        return {
            "windows": {
                "5m": {"count": high_5m, "total": total_5m, "ratio": ratio(high_5m, total_5m)},
                "15m": {"count": high_15m, "total": total_15m, "ratio": ratio(high_15m, total_15m)},
                "60m": {"count": high_60m, "total": total_60m, "ratio": ratio(high_60m, total_60m)},
            },
            "direction_5m": direction_5m,
            "series_5m": series_5m,
        }

    def replay_session(
        self,
        session_id: str,
        limit: int = 100,
        since_seconds: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        return self._query_records(
            session_id=session_id,
            limit=limit,
            since_seconds=since_seconds,
        )

    def clear(self) -> None:
        self._conn.execute("DELETE FROM trajectory_records")
        self._conn.commit()


def _parse_iso_timestamp(value: Optional[str]) -> float:
    """Parse an ISO-8601 timestamp string to a Unix timestamp float.

    Returns 0.0 for missing or malformed values.
    """
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return 0.0


class SessionRegistry:
    """In-memory live session view for current-process metrics endpoints."""

    DEFAULT_MAX_SESSIONS = 10_000
    DEFAULT_MAX_TIMELINE_PER_SESSION = 1000

    def __init__(
        self,
        max_sessions: int = DEFAULT_MAX_SESSIONS,
        max_timeline_per_session: int = DEFAULT_MAX_TIMELINE_PER_SESSION,
    ) -> None:
        self.max_sessions = max(max_sessions, 1)
        self.max_timeline_per_session = max(max_timeline_per_session, 1)
        self._sessions: dict[str, dict[str, Any]] = {}

    def _evict_if_needed(self) -> None:
        while len(self._sessions) > self.max_sessions:
            oldest_session_id = next(iter(self._sessions))
            del self._sessions[oldest_session_id]

    def get_current_risk(self, session_id: str) -> Optional[str]:
        """Return current risk level for session_id, or None if not tracked yet."""
        session = self._sessions.get(session_id)
        return str(session["current_risk_level"]) if session is not None else None

    def get_session_stats(self, session_id: str) -> dict[str, Any]:
        """Return a copy of session stats for alert generation."""
        return dict(self._sessions.get(session_id, {}))

    def record(
        self,
        *,
        event: dict[str, Any],
        decision: dict[str, Any],
        snapshot: dict[str, Any],
        meta: dict[str, Any],
    ) -> None:
        session_id = str(event.get("session_id") or "")
        if not session_id:
            return

        occurred_at = str(event.get("occurred_at") or utc_now_iso())
        occurred_at_ts = _parse_iso_timestamp(occurred_at)
        risk_level = str(snapshot.get("risk_level") or decision.get("risk_level") or "low")
        dimensions = snapshot.get("dimensions") or {}
        tool_name = event.get("tool_name")
        decision_verdict = str(decision.get("decision") or "unknown")
        actual_tier = str(meta.get("actual_tier") or "unknown")

        session = self._sessions.pop(session_id, None)
        if session is None:
            session = {
                "session_id": session_id,
                "agent_id": str(event.get("agent_id") or "unknown"),
                "source_framework": str(event.get("source_framework") or "unknown"),
                "caller_adapter": str(meta.get("caller_adapter") or "unknown"),
                "current_risk_level": "low",
                "cumulative_score": 0,
                "event_count": 0,
                "high_risk_event_count": 0,
                "decision_distribution": defaultdict(int),
                "actual_tier_distribution": defaultdict(int),
                "first_event_at": occurred_at,
                "last_event_at": occurred_at,
                "last_event_ts": occurred_at_ts,
                "d4_accumulation": 0,
                "dimensions_latest": {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
                "risk_hints_seen": set(),
                "tools_used": set(),
                "risk_timeline": deque(maxlen=self.max_timeline_per_session),
            }

        session["agent_id"] = str(event.get("agent_id") or session["agent_id"])
        session["source_framework"] = str(event.get("source_framework") or session["source_framework"])
        session["caller_adapter"] = str(meta.get("caller_adapter") or session["caller_adapter"])
        session["event_count"] += 1
        session["decision_distribution"][decision_verdict] += 1
        session["actual_tier_distribution"][actual_tier] += 1
        session["current_risk_level"] = risk_level
        session["cumulative_score"] = int(snapshot.get("composite_score") or 0)
        session["dimensions_latest"] = {
            "d1": int(dimensions.get("d1") or 0),
            "d2": int(dimensions.get("d2") or 0),
            "d3": int(dimensions.get("d3") or 0),
            "d4": int(dimensions.get("d4") or 0),
            "d5": int(dimensions.get("d5") or 0),
        }
        session["d4_accumulation"] = session["d4_accumulation"] + int(dimensions.get("d4") or 0)
        if _risk_rank(risk_level) >= _risk_rank("high"):
            session["high_risk_event_count"] += 1
        if occurred_at_ts and occurred_at_ts < _parse_iso_timestamp(session["first_event_at"]):
            session["first_event_at"] = occurred_at
        if occurred_at_ts >= float(session.get("last_event_ts", 0.0)):
            session["last_event_at"] = occurred_at
            session["last_event_ts"] = occurred_at_ts
        if tool_name:
            session["tools_used"].add(str(tool_name))
        for hint in event.get("risk_hints", []) or []:
            session["risk_hints_seen"].add(str(hint))

        timeline = session["risk_timeline"]
        timeline.append(
            {
                "event_id": str(event.get("event_id") or "unknown"),
                "occurred_at": occurred_at,
                "occurred_at_ts": occurred_at_ts,
                "risk_level": risk_level,
                "composite_score": int(snapshot.get("composite_score") or 0),
                "tool_name": tool_name,
                "decision": decision_verdict,
            }
        )
        self._sessions[session_id] = session
        self._evict_if_needed()

    def list_sessions(
        self,
        *,
        status: str = "active",
        sort: str = "risk_level",
        min_risk: Optional[str] = None,
        limit: int = 50,
        since_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        # NOTE: session lifecycle tracking is not yet implemented;
        # both status="active" and status="all" return all in-memory sessions.
        _ = status
        sessions = list(self._sessions.values())
        if since_seconds is not None and since_seconds > 0:
            cutoff = time.time() - since_seconds
            sessions = [s for s in sessions if float(s.get("last_event_ts", 0.0)) >= cutoff]
        if min_risk:
            min_rank = _risk_rank(min_risk)
            sessions = [
                s for s in sessions
                if _risk_rank(s.get("current_risk_level")) >= min_rank
            ]

        if sort == "last_event":
            sessions.sort(
                key=lambda s: (
                    float(s.get("last_event_ts", 0.0)),
                    _risk_rank(s.get("current_risk_level")),
                ),
                reverse=True,
            )
        else:
            sessions.sort(
                key=lambda s: (
                    _risk_rank(s.get("current_risk_level")),
                    float(s.get("last_event_ts", 0.0)),
                ),
                reverse=True,
            )

        effective_limit = min(max(limit, 1), 200)
        serialized_sessions: list[dict[str, Any]] = []
        for session in sessions[:effective_limit]:
            serialized_sessions.append(
                {
                    "session_id": session["session_id"],
                    "agent_id": session["agent_id"],
                    "source_framework": session["source_framework"],
                    "caller_adapter": session["caller_adapter"],
                    "current_risk_level": session["current_risk_level"],
                    "cumulative_score": session["cumulative_score"],
                    "event_count": session["event_count"],
                    "high_risk_event_count": session["high_risk_event_count"],
                    "decision_distribution": dict(session["decision_distribution"]),
                    "first_event_at": session["first_event_at"],
                    "last_event_at": session["last_event_at"],
                    "d4_accumulation": session["d4_accumulation"],
                }
            )

        return {
            "sessions": serialized_sessions,
            "total_active": len(sessions),
        }

    def get_session_risk(
        self,
        session_id: str,
        *,
        limit: int = 100,
        since_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if session is None:
            return {
                "session_id": session_id,
                "current_risk_level": "low",
                "cumulative_score": 0,
                "dimensions_latest": {"d1": 0, "d2": 0, "d3": 0, "d4": 0, "d5": 0},
                "risk_timeline": [],
                "risk_hints_seen": [],
                "tools_used": [],
                "actual_tier_distribution": {},
            }

        timeline = list(session["risk_timeline"])
        if since_seconds is not None and since_seconds > 0:
            cutoff = time.time() - since_seconds
            timeline = [item for item in timeline if float(item.get("occurred_at_ts", 0.0)) >= cutoff]
        effective_limit = min(max(limit, 1), 1000)
        timeline = timeline[-effective_limit:]

        return {
            "session_id": session_id,
            "current_risk_level": session["current_risk_level"],
            "cumulative_score": session["cumulative_score"],
            "dimensions_latest": dict(session["dimensions_latest"]),
            "risk_timeline": [
                {
                    "event_id": item["event_id"],
                    "occurred_at": item["occurred_at"],
                    "risk_level": item["risk_level"],
                    "composite_score": item["composite_score"],
                    "tool_name": item["tool_name"],
                    "decision": item["decision"],
                }
                for item in timeline
            ],
            "risk_hints_seen": sorted(session["risk_hints_seen"]),
            "tools_used": sorted(session["tools_used"]),
            "actual_tier_distribution": dict(session["actual_tier_distribution"]),
        }


class EventBus:
    """In-process event bus for SSE stream subscribers."""

    MAX_SUBSCRIBERS = 100
    MAX_QUEUE_SIZE = 500

    def __init__(self) -> None:
        self._subscribers: dict[str, dict[str, Any]] = {}

    def subscribe(
        self,
        *,
        session_id: Optional[str] = None,
        min_risk: Optional[str] = None,
        event_types: Optional[set[str]] = None,
    ) -> tuple[Optional[str], Optional[asyncio.Queue]]:
        if len(self._subscribers) >= self.MAX_SUBSCRIBERS:
            return None, None

        subscriber_id = f"sub-{uuid.uuid4().hex}"
        queue: asyncio.Queue = asyncio.Queue(maxsize=self.MAX_QUEUE_SIZE)
        self._subscribers[subscriber_id] = {
            "queue": queue,
            "session_id": session_id,
            "min_risk": min_risk,
            "event_types": event_types or {"decision", "session_risk_change", "session_start", "session_enforcement_change", "post_action_finding", "trajectory_alert", "pattern_evolved"},
        }
        return subscriber_id, queue

    def unsubscribe(self, subscriber_id: str) -> None:
        self._subscribers.pop(subscriber_id, None)

    def _matches(self, subscriber: dict[str, Any], event: dict[str, Any]) -> bool:
        event_type = str(event.get("type") or "")
        if event_type not in subscriber["event_types"]:
            return False
        if subscriber.get("session_id") and event.get("session_id") != subscriber["session_id"]:
            return False
        if subscriber.get("min_risk"):
            event_risk = str(event.get("risk_level") or event.get("current_risk") or "low")
            if _risk_rank(event_risk) < _risk_rank(subscriber["min_risk"]):
                return False
        return True

    def broadcast(self, event: dict[str, Any]) -> None:
        for sub_id, subscriber in list(self._subscribers.items()):
            if not self._matches(subscriber, event):
                continue
            queue = subscriber["queue"]
            if queue.full():
                try:
                    queue.get_nowait()
                    subscriber["dropped_count"] = subscriber.get("dropped_count", 0) + 1
                    logger.warning(
                        "EventBus: dropped oldest event for subscriber %s (total dropped: %d)",
                        sub_id,
                        subscriber["dropped_count"],
                    )
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass


# ---------------------------------------------------------------------------
# Alert Registry
# ---------------------------------------------------------------------------

class AlertRegistry:
    """In-memory store for triggered alerts with acknowledgement support."""

    MAX_ALERTS = 5_000
    VALID_SEVERITIES = {"low", "medium", "high", "critical"}

    def __init__(self) -> None:
        self._alerts: dict[str, dict[str, Any]] = {}  # alert_id -> alert record

    def add(self, alert: dict[str, Any]) -> None:
        """Insert a new alert, evicting the oldest entry when the cap is reached."""
        if len(self._alerts) >= self.MAX_ALERTS:
            oldest = next(iter(self._alerts))
            del self._alerts[oldest]
        alert_id = str(alert.get("alert_id") or "")
        if alert_id:
            self._alerts[alert_id] = alert

    def list_alerts(
        self,
        *,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        since_seconds: Optional[int] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        alerts = list(self._alerts.values())
        if since_seconds is not None and since_seconds > 0:
            cutoff = time.time() - since_seconds
            alerts = [a for a in alerts if float(a.get("triggered_at_ts", 0.0)) >= cutoff]
        if severity is not None:
            alerts = [a for a in alerts if a.get("severity") == severity]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.get("acknowledged", False) == acknowledged]
        alerts.sort(key=lambda a: float(a.get("triggered_at_ts", 0.0)), reverse=True)
        effective_limit = min(max(limit, 1), 1000)
        serialized = [
            {
                "alert_id": a["alert_id"],
                "severity": a["severity"],
                "metric": a["metric"],
                "session_id": a.get("session_id"),
                "message": a["message"],
                "details": a.get("details", {}),
                "triggered_at": a["triggered_at"],
                "acknowledged": a.get("acknowledged", False),
                "acknowledged_by": a.get("acknowledged_by"),
                "acknowledged_at": a.get("acknowledged_at"),
            }
            for a in alerts[:effective_limit]
        ]
        total_unacknowledged = sum(
            1 for a in self._alerts.values() if not a.get("acknowledged", False)
        )
        return {
            "alerts": serialized,
            "total_unacknowledged": total_unacknowledged,
        }

    def acknowledge(self, alert_id: str, acknowledged_by: str) -> Optional[dict[str, Any]]:
        """Mark an alert as acknowledged. Returns updated alert or None if not found."""
        alert = self._alerts.get(alert_id)
        if alert is None:
            return None
        alert["acknowledged"] = True
        alert["acknowledged_by"] = acknowledged_by
        alert["acknowledged_at"] = utc_now_iso()
        return {
            "alert_id": alert["alert_id"],
            "acknowledged": True,
            "acknowledged_by": alert["acknowledged_by"],
            "acknowledged_at": alert["acknowledged_at"],
        }


# ---------------------------------------------------------------------------
# Gateway Core
# ---------------------------------------------------------------------------

class SupervisionGateway:
    """
    Core gateway logic shared between UDS and HTTP transports.

    Handles JSON-RPC 2.0 dispatch, SyncDecision v1 processing,
    idempotency, and trajectory recording.
    """

    def __init__(
        self,
        trajectory_db_path: Optional[str] = None,
        trajectory_retention_seconds: int = DEFAULT_TRAJECTORY_RETENTION_SECONDS,
        analyzer=None,
        session_enforcement: Optional[SessionEnforcementPolicy] = None,
        detection_config: Optional[DetectionConfig] = None,
    ) -> None:
        self._detection_config = detection_config if detection_config is not None else DetectionConfig()
        self.policy_engine = L1PolicyEngine(analyzer=analyzer, config=self._detection_config)
        self.idempotency_cache = IdempotencyCache()
        effective_db_path = trajectory_db_path
        if effective_db_path is None:
            effective_db_path = os.getenv("CS_TRAJECTORY_DB_PATH", ":memory:")
        self.trajectory_store = TrajectoryStore(
            db_path=effective_db_path,
            retention_seconds=trajectory_retention_seconds,
        )
        self.session_registry = SessionRegistry()
        self.event_bus = EventBus()
        self.alert_registry = AlertRegistry()
        self.session_enforcement = session_enforcement or SessionEnforcementPolicy()
        self.post_action_analyzer = PostActionAnalyzer(
            whitelist_patterns=self._detection_config.post_action_whitelist,
            tier_emergency=self._detection_config.post_action_emergency,
            tier_escalate=self._detection_config.post_action_escalate,
            tier_monitor=self._detection_config.post_action_monitor,
        )
        self.trajectory_analyzer = TrajectoryAnalyzer(
            max_events_per_session=self._detection_config.trajectory_max_events,
            max_sessions=self._detection_config.trajectory_max_sessions,
        )
        # E-5: Self-evolving pattern repository
        self.evolution_manager = PatternEvolutionManager(
            store_path=self._detection_config.evolved_patterns_path or "",
            enabled=self._detection_config.evolving_enabled,
        )
        self._start_time = time.monotonic()
        self._ready = True

    async def handle_jsonrpc(self, raw_body: bytes) -> dict[str, Any]:
        """
        Process a JSON-RPC 2.0 request and return a JSON-RPC response dict.
        """
        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return self._jsonrpc_error(None, -32700, f"Parse error: {e}")

        # Validate JSON-RPC envelope
        if not isinstance(body, dict):
            return self._jsonrpc_error(None, -32600, "Invalid request: not an object")

        jsonrpc_version = body.get("jsonrpc")
        if jsonrpc_version != JSONRPC_VERSION:
            return self._jsonrpc_error(
                body.get("id"), -32600,
                f"Invalid jsonrpc version: expected '{JSONRPC_VERSION}', got '{jsonrpc_version}'",
            )

        method = body.get("method")
        rpc_id = body.get("id")
        params = body.get("params", {})

        if method != JSONRPC_METHOD:
            return self._jsonrpc_error(
                rpc_id, -32601,
                f"Method not found: '{method}'. Expected '{JSONRPC_METHOD}'",
            )

        return await self._handle_sync_decision(rpc_id, params)

    async def _handle_sync_decision(
        self, rpc_id: Any, params: dict[str, Any]
    ) -> dict[str, Any]:
        """Process a SyncDecision v1 request."""
        request_id = params.get("request_id", "")

        # ENGINE_UNAVAILABLE when gateway is not ready
        if not self._ready:
            error_resp = SyncDecisionErrorResponse(
                request_id=request_id or "unknown",
                rpc_error_code=RPCErrorCode.ENGINE_UNAVAILABLE,
                rpc_error_message="Gateway is starting up",
                retry_eligible=True,
                retry_after_ms=500,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32603, error_resp)

        # Check idempotency cache
        cached = self.idempotency_cache.get(request_id)
        if cached is not None:
            return self._jsonrpc_success(rpc_id, cached)

        # Validate request
        try:
            req = SyncDecisionRequest(**params)
        except ValidationError as e:
            error_resp = SyncDecisionErrorResponse(
                request_id=request_id or "unknown",
                rpc_error_code=RPCErrorCode.INVALID_REQUEST,
                rpc_error_message=f"Request validation failed: {e.error_count()} error(s)",
                retry_eligible=False,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32602, error_resp)

        # Check rpc_version
        if req.rpc_version != RPC_VERSION:
            error_resp = SyncDecisionErrorResponse(
                request_id=req.request_id,
                rpc_error_code=RPCErrorCode.VERSION_NOT_SUPPORTED,
                rpc_error_message=f"Unsupported rpc_version: '{req.rpc_version}'",
                retry_eligible=False,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32602, error_resp)

        # Check deadline
        start = time.monotonic()
        deadline_at = start + req.deadline_ms / 1000.0

        # --- A-7: Session enforcement check (before policy_engine) ---
        enforcement = self.session_enforcement.check(
            str(req.event.session_id or "")
        )
        enforcement_applied = False
        if (
            enforcement is not None
            and req.event.event_type == EventType.PRE_ACTION
        ):
            decision = self._make_enforcement_decision(enforcement, req.event)
            # Still need a snapshot for recording — run L1 but override decision
            try:
                remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                _, snapshot, _ = self.policy_engine.evaluate(
                    req.event, req.context, req.decision_tier,
                    deadline_budget_ms=remaining_ms,
                )
            except Exception:
                from .policy_engine import RiskSnapshot
                snapshot = RiskSnapshot()
            actual_tier = DecisionTier.L1
            enforcement_applied = True
        else:
            # Evaluate normally
            try:
                remaining_ms = max(0, (deadline_at - time.monotonic()) * 1000)
                decision, snapshot, actual_tier = self.policy_engine.evaluate(
                    req.event, req.context, req.decision_tier,
                    deadline_budget_ms=remaining_ms,
                )
            except Exception:
                logger.exception("Policy engine error")
                error_resp = SyncDecisionErrorResponse(
                    request_id=req.request_id,
                    rpc_error_code=RPCErrorCode.ENGINE_INTERNAL_ERROR,
                    rpc_error_message="Internal engine error. Check server logs for details.",
                    retry_eligible=True,
                    retry_after_ms=50,
                )
                return self._jsonrpc_error_with_data(rpc_id, -32603, error_resp)

        # --- CS-012: Record decision BEFORE deadline check ---
        # Recording must happen unconditionally so that even deadline-exceeded
        # decisions are persisted to trajectory_store and session_registry.
        event_dict = req.event.model_dump(mode="json")
        decision_dict = decision.model_dump(mode="json")
        snapshot_dict = snapshot.model_dump(mode="json")
        meta_dict = {
            "request_id": req.request_id,
            "actual_tier": actual_tier.value,
            "deadline_ms": req.deadline_ms,
            "caller_adapter": (
                req.context.caller_adapter
                if req.context and req.context.caller_adapter
                else "unknown"
            ),
        }
        _sid = str(event_dict.get("session_id") or "")
        previous_risk_level = self.session_registry.get_current_risk(_sid)
        l3_trace = snapshot.l3_trace
        self.trajectory_store.record(
            event=event_dict,
            decision=decision_dict,
            snapshot=snapshot_dict,
            meta=meta_dict,
            l3_trace=l3_trace,
        )
        self.session_registry.record(
            event=event_dict,
            decision=decision_dict,
            snapshot=snapshot_dict,
            meta=meta_dict,
        )

        # --- E-4 Phase 2: Trajectory analysis ---
        try:
            traj_event = {
                "session_id": _sid,
                "event_id": req.event.event_id,
                "tool_name": req.event.tool_name or "",
                "occurred_at_ts": _parse_iso_timestamp(
                    str(event_dict.get("occurred_at") or "")
                ),
                "payload": req.event.payload or {},
            }
            traj_matches = self.trajectory_analyzer.record(traj_event)
            for tm in traj_matches:
                self.event_bus.broadcast({
                    "type": "trajectory_alert",
                    "session_id": _sid,
                    "sequence_id": tm.sequence_id,
                    "risk_level": tm.risk_level,
                    "matched_event_ids": tm.matched_event_ids,
                    "reason": tm.reason,
                    "timestamp": str(event_dict.get("occurred_at") or utc_now_iso()),
                })
        except Exception:
            logger.exception("trajectory analysis failed for event %s", req.event.event_id)

        # --- A-7: Check if threshold is newly breached ---
        session_id = str(event_dict.get("session_id") or "")
        if session_id and self.session_enforcement.enabled:
            stats = self.session_registry.get_session_stats(session_id)
            new_enf = self.session_enforcement.evaluate_threshold(
                session_id, stats.get("high_risk_event_count", 0)
            )
            if new_enf:
                self.event_bus.broadcast(
                    {
                        "type": "session_enforcement_change",
                        "session_id": session_id,
                        "state": "enforced",
                        "action": new_enf.action.value,
                        "high_risk_count": new_enf.high_risk_count,
                        "timestamp": str(event_dict.get("occurred_at") or utc_now_iso()),
                    }
                )

        # Check if we exceeded deadline (after recording, so audit trail is intact)
        if time.monotonic() > deadline_at:
            error_resp = SyncDecisionErrorResponse(
                request_id=req.request_id,
                rpc_error_code=RPCErrorCode.DEADLINE_EXCEEDED,
                rpc_error_message=f"Decision took longer than deadline_ms={req.deadline_ms}",
                retry_eligible=True,
                retry_after_ms=50,
                fallback_decision=decision,
            )
            return self._jsonrpc_error_with_data(rpc_id, -32604, error_resp)

        # Build success response
        resp = SyncDecisionResponse(
            request_id=req.request_id,
            decision=decision,
            actual_tier=actual_tier,
            served_at=utc_now_iso(),
        )
        resp_dict = resp.model_dump(mode="json")

        # Cache response
        self.idempotency_cache.put(req.request_id, resp_dict, req.deadline_ms)

        current_risk_level = str(snapshot_dict.get("risk_level") or decision_dict.get("risk_level") or "low")
        occurred_at = str(event_dict.get("occurred_at") or utc_now_iso())

        if previous_risk_level is None and session_id:
            self.event_bus.broadcast(
                {
                    "type": "session_start",
                    "session_id": session_id,
                    "agent_id": str(event_dict.get("agent_id") or "unknown"),
                    "source_framework": str(event_dict.get("source_framework") or "unknown"),
                    "timestamp": occurred_at,
                }
            )

        self.event_bus.broadcast(
            {
                "type": "decision",
                "session_id": session_id,
                "event_id": str(event_dict.get("event_id") or "unknown"),
                "risk_level": current_risk_level,
                "decision": str(decision_dict.get("decision") or "unknown"),
                "tool_name": event_dict.get("tool_name"),
                "actual_tier": actual_tier.value,
                "timestamp": occurred_at,
                "reason": str(decision_dict.get("reason") or ""),
                "command": str(
                    event_dict.get("payload", {}).get("command", "")
                    or event_dict.get("tool_name", "")
                ),
                "approval_id": event_dict.get("approval_id"),
                "expires_at": event_dict.get("payload", {}).get("expiresAtMs"),
            }
        )

        if (
            previous_risk_level is not None
            and _risk_rank(current_risk_level) > _risk_rank(previous_risk_level)
        ):
            self.event_bus.broadcast(
                {
                    "type": "session_risk_change",
                    "session_id": session_id,
                    "previous_risk": previous_risk_level,
                    "current_risk": current_risk_level,
                    "trigger_event": str(event_dict.get("event_id") or "unknown"),
                    "timestamp": occurred_at,
                }
            )

        if session_id and _risk_rank(current_risk_level) >= _risk_rank("high"):
            import uuid as _uuid
            alert_id = f"alert-{_uuid.uuid4().hex[:12]}"
            triggered_at_ts = time.time()
            severity = current_risk_level  # "high" or "critical"
            session_data = self.session_registry.get_session_stats(session_id)
            high_risk_count = session_data.get("high_risk_event_count", 1)
            message = (
                f"Session risk escalated to {current_risk_level.upper()}: "
                f"{high_risk_count} high-risk event(s) detected"
            )
            alert = {
                "alert_id": alert_id,
                "severity": severity,
                "metric": "session_risk_escalation",
                "session_id": session_id,
                "message": message,
                "details": {
                    "previous_risk": previous_risk_level,
                    "current_risk": current_risk_level,
                    "high_risk_count": high_risk_count,
                    "cumulative_score": session_data.get("cumulative_score", 0),
                    "trigger_event_id": str(event_dict.get("event_id") or "unknown"),
                    "tool_name": event_dict.get("tool_name"),
                },
                "triggered_at": occurred_at,
                "triggered_at_ts": triggered_at_ts,
                "acknowledged": False,
                "acknowledged_by": None,
                "acknowledged_at": None,
            }
            self.alert_registry.add(alert)
            self.event_bus.broadcast(
                {
                    "type": "alert",
                    "alert_id": alert_id,
                    "severity": severity,
                    "metric": "session_risk_escalation",
                    "session_id": session_id,
                    "current_risk": current_risk_level,
                    "message": message,
                    "timestamp": occurred_at,
                }
            )

        # --- E-4: Post-action security analysis ---
        if req.event.event_type == EventType.POST_ACTION:
            try:
                output_text = str(
                    req.event.payload.get("output", "")
                    or req.event.payload.get("result", "")
                    or ""
                )
                if output_text:
                    finding = self.post_action_analyzer.analyze(
                        tool_output=output_text,
                        tool_name=req.event.tool_name or "unknown",
                        event_id=req.event.event_id,
                    )
                    if finding.tier.value != "log_only":
                        self.event_bus.broadcast({
                            "type": "post_action_finding",
                            "event_id": req.event.event_id,
                            "session_id": session_id,
                            "source_framework": req.event.source_framework,
                            "tier": finding.tier.value,
                            "patterns_matched": finding.patterns_matched,
                            "score": finding.score,
                            "timestamp": occurred_at,
                        })
            except Exception:
                logger.exception("post-action analysis failed for event %s", req.event.event_id)

        # --- E-5: Extract candidate pattern from confirmed high-risk events ---
        if (
            self.evolution_manager._enabled
            and req.event.event_type == EventType.PRE_ACTION
            and decision.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        ):
            try:
                self.evolution_manager.extract_candidate(
                    event_id=req.event.event_id,
                    session_id=str(req.event.session_id or ""),
                    tool_name=req.event.tool_name or "",
                    command=str(req.event.payload.get("command", "")) if req.event.payload else "",
                    risk_level=decision.risk_level,
                    source_framework=req.event.source_framework or "",
                    reasons=decision.reason.split("; ") if decision.reason else [],
                )
            except Exception:
                logger.warning("evolved pattern extraction failed", exc_info=True)

        return self._jsonrpc_success(rpc_id, resp_dict)

    def _make_enforcement_decision(
        self, enforcement, event: CanonicalEvent,
    ) -> CanonicalDecision:
        """Build a decision that overrides normal evaluation due to A-7 enforcement."""
        if enforcement.action == EnforcementAction.BLOCK:
            verdict = DecisionVerdict.BLOCK
            policy_id = "session-enforcement-A7"
            reason = (
                f"Session enforcement: BLOCK after {enforcement.high_risk_count} "
                f"high-risk events (threshold reached)"
            )
        elif enforcement.action == EnforcementAction.L3_REQUIRE:
            verdict = DecisionVerdict.DEFER
            policy_id = "session-enforcement-A7-L3"
            reason = (
                f"Session enforcement: L3 review required after "
                f"{enforcement.high_risk_count} high-risk events"
            )
        else:
            # DEFER (default)
            verdict = DecisionVerdict.DEFER
            policy_id = "session-enforcement-A7"
            reason = (
                f"Session enforcement: DEFER after {enforcement.high_risk_count} "
                f"high-risk events (threshold reached)"
            )
        return CanonicalDecision(
            decision=verdict,
            reason=reason,
            policy_id=policy_id,
            risk_level=RiskLevel.HIGH,
            decision_source=DecisionSource.POLICY,
            policy_version="A7",
            failure_class=FailureClass.NONE,
            final=True,
        )

    def health(self) -> dict[str, Any]:
        """Return gateway health status."""
        uptime = time.monotonic() - self._start_time
        return {
            "status": "healthy",
            "uptime_seconds": round(uptime, 1),
            "cache_size": self.idempotency_cache.size(),
            "trajectory_count": self.trajectory_store.count(),
            "trajectory_backend": "sqlite",
            "policy_engine": "L1+L2",
            "rpc_version": RPC_VERSION,
            "auth_enabled": bool(os.getenv("CS_AUTH_TOKEN")),
        }

    def report_summary(self, window_seconds: Optional[int] = None) -> dict[str, Any]:
        """Return cross-framework summary metrics from trajectory records."""
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        summary = self.trajectory_store.summary(since_seconds=since_seconds)
        summary["generated_at"] = utc_now_iso()
        summary["window_seconds"] = since_seconds
        return summary

    def replay_session(
        self,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        """Return timeline records for a session (most recent first by append order)."""
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        records = self.trajectory_store.replay_session(
            session_id=session_id,
            limit=limit,
            since_seconds=since_seconds,
        )
        return {
            "session_id": session_id,
            "record_count": len(records),
            "records": records,
            "generated_at": utc_now_iso(),
            "window_seconds": since_seconds,
        }

    def report_sessions(
        self,
        *,
        status: str = "active",
        sort: str = "risk_level",
        limit: int = 50,
        min_risk: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), 200)
        result = self.session_registry.list_sessions(
            status=status,
            sort=sort,
            min_risk=min_risk,
            limit=effective_limit,
            since_seconds=since_seconds,
        )
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        return result

    def report_session_risk(
        self,
        session_id: str,
        *,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), 1000)
        result = self.session_registry.get_session_risk(
            session_id,
            limit=effective_limit,
            since_seconds=since_seconds,
        )
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        return result

    def report_alerts(
        self,
        *,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        window_seconds: Optional[int] = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        since_seconds = window_seconds if window_seconds and window_seconds > 0 else None
        effective_limit = min(max(limit, 1), 1000)
        result = self.alert_registry.list_alerts(
            severity=severity,
            acknowledged=acknowledged,
            since_seconds=since_seconds,
            limit=effective_limit,
        )
        result["generated_at"] = utc_now_iso()
        result["window_seconds"] = since_seconds
        return result

    def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str,
    ) -> Optional[dict[str, Any]]:
        return self.alert_registry.acknowledge(alert_id, acknowledged_by)

    # --- JSON-RPC helpers ---

    @staticmethod
    def _jsonrpc_success(rpc_id: Any, result: Any) -> dict[str, Any]:
        return {"jsonrpc": JSONRPC_VERSION, "id": rpc_id, "result": result}

    @staticmethod
    def _jsonrpc_error(
        rpc_id: Any, code: int, message: str, data: Any = None,
    ) -> dict[str, Any]:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        return {"jsonrpc": JSONRPC_VERSION, "id": rpc_id, "error": error}

    @staticmethod
    def _jsonrpc_error_with_data(
        rpc_id: Any, code: int, error_resp: SyncDecisionErrorResponse,
    ) -> dict[str, Any]:
        return SupervisionGateway._jsonrpc_error(
            rpc_id, code,
            error_resp.rpc_error_message,
            error_resp.model_dump(mode="json"),
        )


# ---------------------------------------------------------------------------
# HTTP Transport (FastAPI)
# ---------------------------------------------------------------------------

class _RateLimiter:
    """Simple sliding-window rate limiter per client identifier."""

    def __init__(self, max_requests: int, window_seconds: float):
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, list[float]] = {}

    def check(self, client_id: str) -> bool:
        """Return True if allowed, False if rate limited."""
        now = time.monotonic()
        bucket = self._buckets.setdefault(client_id, [])
        bucket[:] = [t for t in bucket if now - t < self._window]
        if len(bucket) >= self._max:
            return False
        bucket.append(now)
        return True


def _find_and_reload_pattern_matcher(analyzer) -> bool:
    """Traverse analyzer hierarchy to find and reload PatternMatcher.

    Works with both RuleBasedAnalyzer (direct _pattern_matcher) and
    CompositeAnalyzer (nested _analyzers list).
    """
    if hasattr(analyzer, '_pattern_matcher'):
        analyzer._pattern_matcher.reload()
        return True
    if hasattr(analyzer, '_analyzers'):
        for a in analyzer._analyzers:
            if hasattr(a, '_pattern_matcher'):
                a._pattern_matcher.reload()
                return True
    return False


def create_http_app(
    gateway: SupervisionGateway,
    *,
    ui_dir: Path | None = None,
) -> FastAPI:
    """Create FastAPI application for the HTTP transport."""
    app = FastAPI(title="AHP Supervision Gateway", version="1.0")

    auth_token = _read_auth_token()
    if not auth_token:
        logger.warning(
            "CS_AUTH_TOKEN not set — HTTP endpoints are UNAUTHENTICATED. "
            "Set CS_AUTH_TOKEN for production deployments."
        )
    elif len(auth_token) < 32:
        logger.warning(
            "CS_AUTH_TOKEN is shorter than 32 chars — "
            "consider using a stronger token for production."
        )

    verify_auth = _make_auth_dependency(auth_token)

    # Rate limiter (0 = disabled)
    rate_limit_per_min = int(os.getenv("CS_RATE_LIMIT_PER_MINUTE", "300"))
    rate_limiter: _RateLimiter | None = None
    if rate_limit_per_min > 0:
        rate_limiter = _RateLimiter(max_requests=rate_limit_per_min, window_seconds=60.0)

    def _check_rate_limit(request: Request) -> Response | None:
        if rate_limiter is None:
            return None
        client_ip = request.client.host if request.client else "unknown"
        if not rate_limiter.check(client_ip):
            error_resp = SyncDecisionErrorResponse(
                request_id="rate-limited",
                rpc_error_code=RPCErrorCode.RATE_LIMITED,
                rpc_error_message="Rate limit exceeded",
                retry_eligible=True,
                retry_after_ms=1000,
            )
            return Response(
                content=json.dumps(error_resp.model_dump()),
                status_code=429,
                media_type="application/json",
            )
        return None

    @app.post("/ahp")
    async def ahp_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        body = await request.body()
        if len(body) > 10 * 1024 * 1024:
            return Response(
                content=json.dumps({"error": "Payload too large"}),
                status_code=413,
                media_type="application/json",
            )
        result = await gateway.handle_jsonrpc(body)
        return Response(
            content=json.dumps(result),
            media_type="application/json",
        )

    # --- a3s-code HTTP transport (B-1) ---
    from ..adapters.a3s_adapter import InProcessA3SAdapter
    from ..adapters.a3s_gateway_harness import A3SGatewayHarness

    _a3s_adapter = InProcessA3SAdapter(gateway)
    _a3s_harness = A3SGatewayHarness(_a3s_adapter)

    @app.post("/ahp/a3s")
    async def ahp_a3s_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        rl_result = _check_rate_limit(request)
        if rl_result is not None:
            return rl_result
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON body"}),
                status_code=400,
                media_type="application/json",
            )
        response = await _a3s_harness.dispatch_async(body)
        if response is None:
            return Response(status_code=204)
        return response

    @app.get("/health")
    async def health_endpoint():
        return gateway.health()

    @app.get("/report/summary")
    async def report_summary_endpoint(request: Request, window_seconds: Optional[int] = None):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        return gateway.report_summary(window_seconds=window_seconds)

    @app.get("/report/stream")
    async def report_stream_endpoint(
        request: Request,
        session_id: Optional[str] = None,
        min_risk: Optional[str] = None,
        types: Optional[str] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if min_risk is not None and min_risk not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "min_risk must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )

        event_types = {"decision", "session_risk_change", "session_start", "alert", "session_enforcement_change", "post_action_finding", "trajectory_alert", "pattern_evolved"}
        if types:
            requested_types = {item.strip() for item in types.split(",") if item.strip()}
            if not requested_types or not requested_types.issubset(event_types):
                return Response(
                    content=json.dumps({"error": "types must be a comma-separated subset of: decision, session_risk_change, session_start, alert, session_enforcement_change, post_action_finding, trajectory_alert, pattern_evolved"}),
                    status_code=400,
                    media_type="application/json",
                )
            event_types = requested_types

        subscriber_id, queue = gateway.event_bus.subscribe(
            session_id=session_id,
            min_risk=min_risk,
            event_types=event_types,
        )
        if subscriber_id is None or queue is None:
            return Response(
                content=json.dumps({"error": "Too many SSE subscribers"}),
                status_code=503,
                media_type="application/json",
            )

        async def event_generator():
            yield ": connected\n\n"  # Immediately flush headers to client
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15.0)
                        event_type = str(event.get("type") or "message")
                        # Keep "type" in data payload so clients that only parse data: lines
                        # (e.g. urllib-based watch CLI) can still dispatch on event type.
                        payload = {**event, "type": event_type}
                        yield f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"
            finally:
                gateway.event_bus.unsubscribe(subscriber_id)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.get("/report/sessions")
    async def report_sessions_endpoint(
        request: Request,
        status: str = "active",
        sort: str = "risk_level",
        limit: int = 50,
        min_risk: Optional[str] = None,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        if status not in {"active", "all"}:
            return Response(
                content=json.dumps({"error": "status must be one of: active, all"}),
                status_code=400,
                media_type="application/json",
            )
        if sort not in {"risk_level", "last_event"}:
            return Response(
                content=json.dumps({"error": "sort must be one of: risk_level, last_event"}),
                status_code=400,
                media_type="application/json",
            )
        if min_risk is not None and min_risk not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "min_risk must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 200)
        return gateway.report_sessions(
            status=status,
            sort=sort,
            limit=effective_limit,
            min_risk=min_risk,
            window_seconds=window_seconds,
        )

    @app.get("/report/session/{session_id}/risk")
    async def report_session_risk_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.report_session_risk(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    @app.get("/report/session/{session_id}")
    async def report_session_endpoint(
        request: Request,
        session_id: str,
        limit: int = 100,
        window_seconds: Optional[int] = None,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        effective_limit = min(max(limit, 1), 1000)
        return gateway.replay_session(
            session_id=session_id,
            limit=effective_limit,
            window_seconds=window_seconds,
        )

    @app.get("/report/alerts")
    async def report_alerts_endpoint(
        request: Request,
        severity: Optional[str] = None,
        acknowledged: Optional[str] = None,
        window_seconds: Optional[int] = None,
        limit: int = 100,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if severity is not None and severity not in {"low", "medium", "high", "critical"}:
            return Response(
                content=json.dumps({"error": "severity must be one of: low, medium, high, critical"}),
                status_code=400,
                media_type="application/json",
            )
        if acknowledged is not None and acknowledged not in {"true", "false"}:
            return Response(
                content=json.dumps({"error": "acknowledged must be 'true' or 'false'"}),
                status_code=400,
                media_type="application/json",
            )
        if window_seconds is not None and (window_seconds < 1 or window_seconds > MAX_WINDOW_SECONDS):
            return Response(
                content=json.dumps({"error": f"window_seconds must be between 1 and {MAX_WINDOW_SECONDS}"}),
                status_code=400,
                media_type="application/json",
            )
        ack_filter: Optional[bool] = None
        if acknowledged is not None:
            ack_filter = acknowledged == "true"
        effective_limit = min(max(limit, 1), 1000)
        return gateway.report_alerts(
            severity=severity,
            acknowledged=ack_filter,
            window_seconds=window_seconds,
            limit=effective_limit,
        )

    @app.post("/report/alerts/{alert_id}/acknowledge")
    async def acknowledge_alert_endpoint(
        request: Request,
        alert_id: str,
    ):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            body = await request.json()
        except Exception:
            body = {}
        acknowledged_by = str(body.get("acknowledged_by") or "unknown")
        result = gateway.acknowledge_alert(alert_id, acknowledged_by)
        if result is None:
            return Response(
                content=json.dumps({"error": f"Alert '{alert_id}' not found"}),
                status_code=404,
                media_type="application/json",
            )
        return result

    # --- Session enforcement management (A-7) ---

    @app.get("/report/session/{session_id}/enforcement")
    async def get_enforcement_endpoint(request: Request, session_id: str):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return gateway.session_enforcement.get_status(session_id)

    @app.post("/report/session/{session_id}/enforcement")
    async def post_enforcement_endpoint(request: Request, session_id: str):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON body"}),
                status_code=400,
                media_type="application/json",
            )
        action = str(body.get("action", "")).lower()
        if action != "release":
            return Response(
                content=json.dumps({"error": "action must be 'release'"}),
                status_code=400,
                media_type="application/json",
            )
        released = gateway.session_enforcement.release(session_id)
        if released:
            gateway.event_bus.broadcast(
                {
                    "type": "session_enforcement_change",
                    "session_id": session_id,
                    "state": "released",
                    "action": None,
                    "high_risk_count": None,
                    "timestamp": utc_now_iso(),
                }
            )
        return {
            "session_id": session_id,
            "released": released,
        }

    # --- E-5: Self-evolving pattern endpoints ---

    @app.get("/ahp/patterns")
    async def list_patterns_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        return Response(
            content=json.dumps({"patterns": gateway.evolution_manager.list_patterns()}),
            media_type="application/json",
        )

    @app.post("/ahp/patterns/confirm")
    async def confirm_pattern_endpoint(request: Request):
        auth_result = await verify_auth(request)
        if isinstance(auth_result, Response):
            return auth_result
        if not gateway.evolution_manager._enabled:
            return Response(
                content=json.dumps({"error": "pattern evolution is disabled (CS_EVOLVING_ENABLED=0)"}),
                status_code=403,
                media_type="application/json",
            )
        try:
            body = await request.json()
        except Exception:
            return Response(
                content=json.dumps({"error": "invalid JSON"}),
                status_code=400,
                media_type="application/json",
            )
        pattern_id = body.get("pattern_id")
        confirmed = body.get("confirmed")
        if not pattern_id or confirmed is None:
            return Response(
                content=json.dumps({"error": "pattern_id and confirmed (bool) are required"}),
                status_code=400,
                media_type="application/json",
            )
        result = gateway.evolution_manager.confirm(pattern_id, confirmed=bool(confirmed))
        if result == "not_found":
            return Response(
                content=json.dumps({"error": "pattern not found"}),
                status_code=404,
                media_type="application/json",
            )
        # Broadcast SSE event
        gateway.event_bus.broadcast({
            "type": "pattern_evolved",
            "pattern_id": pattern_id,
            "action": result,
        })
        # Trigger hot-reload so new experimental/stable patterns take effect
        if result in ("promoted_to_experimental", "promoted_to_stable"):
            if not _find_and_reload_pattern_matcher(gateway.policy_engine._analyzer):
                logger.warning("could not hot-reload PatternMatcher: no RuleBasedAnalyzer found")
        return Response(
            content=json.dumps({"result": result, "pattern_id": pattern_id}),
            media_type="application/json",
        )

    # --- Web Dashboard UI (static SPA) ---
    _ui_dir = ui_dir if ui_dir is not None else _DEFAULT_UI_DIR
    if _ui_dir.exists() and (_ui_dir / "index.html").exists():
        _index_html = (_ui_dir / "index.html").read_text()

        @app.get("/ui/{path:path}")
        async def ui_spa_fallback(path: str):
            """SPA fallback: serve index.html for unmatched /ui/* paths."""
            # Check if requested path is a real file
            file_path = _ui_dir / path
            if file_path.is_file() and file_path.resolve().is_relative_to(
                _ui_dir.resolve()
            ):
                return FileResponse(str(file_path))
            return HTMLResponse(_index_html)

        @app.get("/ui")
        async def ui_root():
            return HTMLResponse(_index_html)

    return app


# ---------------------------------------------------------------------------
# UDS Transport (asyncio)
# ---------------------------------------------------------------------------

async def _uds_client_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    gateway: SupervisionGateway,
) -> None:
    """Handle a single UDS client connection using length-prefixed framing."""
    try:
        while True:
            # Read 4-byte length prefix (big-endian uint32)
            length_bytes = await reader.readexactly(4)
            msg_length = struct.unpack("!I", length_bytes)[0]

            if msg_length == 0 or msg_length > 10 * 1024 * 1024:  # 10MB limit
                logger.warning("UDS: rejected frame with length %d", msg_length)
                break

            data = await reader.readexactly(msg_length)
            result = await gateway.handle_jsonrpc(data)
            response_bytes = json.dumps(result).encode("utf-8")

            # Write length-prefixed response
            writer.write(struct.pack("!I", len(response_bytes)))
            writer.write(response_bytes)
            await writer.drain()

    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    except Exception:
        logger.exception("UDS client handler error")
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def start_uds_server(
    gateway: SupervisionGateway,
    path: str = DEFAULT_UDS_PATH,
) -> asyncio.AbstractServer:
    """Start the Unix Domain Socket server."""
    # Remove stale socket file
    if os.path.exists(path):
        os.unlink(path)

    async def handler(reader, writer):
        await _uds_client_handler(reader, writer, gateway)

    server = await asyncio.start_unix_server(handler, path=path)
    os.chmod(path, 0o600)  # Only owner can access
    logger.info(f"UDS server listening on {path} (mode=0600)")
    return server


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def run_gateway(
    uds_path: str = DEFAULT_UDS_PATH,
    http_host: str = DEFAULT_HTTP_HOST,
    http_port: int = DEFAULT_HTTP_PORT,
    trajectory_db_path: str = DEFAULT_TRAJECTORY_DB_PATH,
    trajectory_retention_seconds: int = DEFAULT_TRAJECTORY_RETENTION_SECONDS,
    ssl_certfile: str | None = None,
    ssl_keyfile: str | None = None,
) -> None:
    """Run the Supervision Gateway with both UDS and HTTP transports."""
    # Build detection config from CS_ environment variables
    detection_config = build_detection_config_from_env()
    logger.info("DetectionConfig: %s", detection_config)

    gateway = SupervisionGateway(
        trajectory_db_path=trajectory_db_path,
        trajectory_retention_seconds=trajectory_retention_seconds,
        detection_config=detection_config,
    )

    # Wire LLM analyzer (same pattern as stack.py)
    analyzer = build_analyzer_from_env(
        trajectory_store=gateway.trajectory_store,
        patterns_path=detection_config.attack_patterns_path,
        evolved_patterns_path=detection_config.evolved_patterns_path if detection_config.evolving_enabled else None,
        l3_budget_ms=detection_config.l3_budget_ms,
    )
    if analyzer is not None:
        gateway.policy_engine = L1PolicyEngine(analyzer=analyzer, config=detection_config)

    app = create_http_app(gateway)

    # Start UDS server
    uds_server = await start_uds_server(gateway, uds_path)

    # Start periodic cleanup
    cleanup_task = asyncio.create_task(
        periodic_cleanup(gateway.idempotency_cache, interval_seconds=10.0)
    )

    # Start HTTP server
    uvicorn_kwargs: dict[str, Any] = {
        "app": app,
        "host": http_host,
        "port": http_port,
        "log_level": "info",
        "access_log": False,
    }
    if ssl_certfile and ssl_keyfile:
        uvicorn_kwargs["ssl_certfile"] = ssl_certfile
        uvicorn_kwargs["ssl_keyfile"] = ssl_keyfile
        logger.info("HTTPS enabled (cert=%s, key=%s)", ssl_certfile, ssl_keyfile)
    config = uvicorn.Config(**uvicorn_kwargs)
    server = uvicorn.Server(config)

    logger.info(
        "Gateway starting: UDS=%s, HTTP=%s:%s, TrajectoryDB=%s",
        uds_path,
        http_host,
        http_port,
        trajectory_db_path,
    )

    try:
        await server.serve()
    finally:
        cleanup_task.cancel()
        uds_server.close()
        await uds_server.wait_closed()
        if os.path.exists(uds_path):
            os.unlink(uds_path)


def _gateway_args_from_env() -> dict:
    """Read gateway configuration from environment variables."""
    args: dict[str, Any] = {
        "uds_path": os.environ.get("CS_UDS_PATH", DEFAULT_UDS_PATH),
        "http_host": os.environ.get("CS_HTTP_HOST", DEFAULT_HTTP_HOST),
        "http_port": int(os.environ.get("CS_HTTP_PORT", str(DEFAULT_HTTP_PORT))),
        "trajectory_db_path": os.environ.get(
            "CS_TRAJECTORY_DB_PATH", DEFAULT_TRAJECTORY_DB_PATH
        ),
        "trajectory_retention_seconds": int(os.environ.get(
            "AHP_TRAJECTORY_RETENTION_SECONDS",
            str(DEFAULT_TRAJECTORY_RETENTION_SECONDS),
        )),
    }
    ssl_cert = os.environ.get("AHP_SSL_CERTFILE", "").strip() or None
    ssl_key = os.environ.get("AHP_SSL_KEYFILE", "").strip() or None
    if ssl_cert and ssl_key:
        args["ssl_certfile"] = ssl_cert
        args["ssl_keyfile"] = ssl_key
    return args


def _build_gateway_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clawsentry-gateway",
        description=(
            "Run the ClawSentry Supervision Gateway.\n\n"
            "All options can also be set via environment variables (shown in brackets).\n"
            "CLI flags take precedence over environment variables."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--uds-path",
        default=None,
        metavar="PATH",
        help=f"Unix domain socket path [CS_UDS_PATH] (default: {DEFAULT_UDS_PATH})",
    )
    parser.add_argument(
        "--host",
        default=None,
        metavar="HOST",
        help=f"HTTP bind host [CS_HTTP_HOST] (default: {DEFAULT_HTTP_HOST})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        metavar="PORT",
        help=f"HTTP bind port [CS_HTTP_PORT] (default: {DEFAULT_HTTP_PORT})",
    )
    parser.add_argument(
        "--trajectory-db-path",
        default=None,
        metavar="PATH",
        help=f"SQLite trajectory DB path [CS_TRAJECTORY_DB_PATH] (default: {DEFAULT_TRAJECTORY_DB_PATH})",
    )
    parser.add_argument(
        "--trajectory-retention-seconds",
        type=int,
        default=None,
        metavar="SECONDS",
        help=f"Trajectory retention window [AHP_TRAJECTORY_RETENTION_SECONDS] (default: {DEFAULT_TRAJECTORY_RETENTION_SECONDS})",
    )
    parser.add_argument(
        "--ssl-certfile",
        default=None,
        metavar="PATH",
        help="TLS certificate file [AHP_SSL_CERTFILE] (enables HTTPS when combined with --ssl-keyfile)",
    )
    parser.add_argument(
        "--ssl-keyfile",
        default=None,
        metavar="PATH",
        help="TLS private key file [AHP_SSL_KEYFILE]",
    )
    return parser


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(message)s")
    from ..cli.dotenv_loader import load_dotenv
    load_dotenv()

    parser = _build_gateway_parser()
    args = parser.parse_args()

    # Build kwargs: env-derived defaults, then override with explicit CLI flags
    kwargs = _gateway_args_from_env()
    if args.uds_path is not None:
        kwargs["uds_path"] = args.uds_path
    if args.host is not None:
        kwargs["http_host"] = args.host
    if args.port is not None:
        kwargs["http_port"] = args.port
    if args.trajectory_db_path is not None:
        kwargs["trajectory_db_path"] = args.trajectory_db_path
    if args.trajectory_retention_seconds is not None:
        kwargs["trajectory_retention_seconds"] = args.trajectory_retention_seconds
    if args.ssl_certfile is not None:
        kwargs["ssl_certfile"] = args.ssl_certfile
    if args.ssl_keyfile is not None:
        kwargs["ssl_keyfile"] = args.ssl_keyfile

    try:
        asyncio.run(run_gateway(**kwargs))
    except KeyboardInterrupt:
        logger.info("Gateway stopped by user.")


if __name__ == "__main__":
    main()
