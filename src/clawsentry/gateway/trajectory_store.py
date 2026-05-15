"""SQLite-backed trajectory store with retention + query window support."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import hashlib
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Callable, Optional

logger = logging.getLogger("clawsentry")

DEFAULT_TRAJECTORY_DB_PATH = "/tmp/clawsentry-trajectory.db"
DEFAULT_TRAJECTORY_RETENTION_SECONDS = 30 * 24 * 3600
HIGH_RISK_LEVELS = {"high", "critical"}
L3_ADVISORY_REVIEW_STATES = {"pending", "running", "completed", "failed", "degraded"}
L3_ADVISORY_TERMINAL_STATES = {"completed", "failed", "degraded"}
L3_ADVISORY_JOB_STATES = {"queued", "running", "completed", "failed"}
L3_ADVISORY_JOB_TERMINAL_STATES = {"completed", "failed"}
L3_ADVISORY_RUNNERS = {"deterministic_local", "fake_llm", "llm_provider"}
_RISK_LEVEL_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

INVALID_EVENT_COUNT_THRESHOLD_1M = 20
INVALID_EVENT_RATE_CRITICAL_5M = 0.01
INVALID_EVENT_RATE_WARNING_15M_MIN = 0.001
INVALID_EVENT_RATE_WARNING_15M_MAX = 0.01

MAX_WINDOW_SECONDS = 604800  # 1 week
UNIVERSAL_METRIC_CELL_TRACEABILITY_FIELDS = (
    "request_ids",
    "fallback_paths",
)
CONDITIONAL_METRIC_CELL_TRACEABILITY_FIELDS = (
    "rule_evidence",
    "registry_states",
    "adapter_effect_result_ids",
)


def _empty_policy_drift_bucket() -> dict[str, Any]:
    return {
        "record_count": 0,
        "decision_distribution": defaultdict(int),
        "risk_distribution": defaultdict(int),
        "rule_hits": defaultdict(int),
    }


def _empty_policy_drift_traceability() -> dict[str, set[str]]:
    return {
        "request_ids": set(),
        "record_ids": set(),
        "event_ids": set(),
        "registry_states": set(),
        "rule_evidence": set(),
        "fallback_paths": set(),
        "adapter_effect_result_ids": set(),
    }


def _empty_policy_drift_traceability_applicability(rule_family: str) -> dict[str, bool]:
    return {
        "rule_evidence": rule_family != "general",
        "registry_states": rule_family == "skill_trust",
        "adapter_effect_result_ids": False,
    }


def _workspace_root_for_event(event: dict[str, Any]) -> str:
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    for key in ("workspace_root", "workspace", "cwd", "working_directory"):
        value = event.get(key)
        if value is None:
            value = payload.get(key)
        text = str(value or "").strip()
        if text:
            return text
    return "unbound"


def _rule_families_for_snapshot(snapshot: dict[str, Any]) -> list[str]:
    raw_hits = snapshot.get("rule_hits")
    rule_hits = [str(item) for item in raw_hits] if isinstance(raw_hits, list) else []
    raw_findings = snapshot.get("skill_trust_findings")
    if isinstance(raw_findings, list) and raw_findings:
        return ["skill_trust"]
    families: set[str] = set()
    for hit in rule_hits:
        lowered = hit.lower()
        if "skill" in lowered or "registry" in lowered or "alias" in lowered:
            families.add("skill_trust")
        elif "taint" in lowered or "flow" in lowered or "secret" in lowered or "exfil" in lowered:
            families.add("taint_flow")
        elif "scope" in lowered or "mcp" in lowered or "session" in lowered:
            families.add("session_scope")
        elif "trajectory" in lowered:
            families.add("trajectory")
        else:
            families.add("general")
    return sorted(families or {"general"})


def _add_record_to_policy_drift_bucket(bucket: dict[str, Any], record: dict[str, Any]) -> None:
    decision = record.get("decision") if isinstance(record.get("decision"), dict) else {}
    snapshot = (
        record.get("risk_snapshot")
        if isinstance(record.get("risk_snapshot"), dict)
        else {}
    )
    verdict = str(decision.get("decision") or "unknown")
    risk = str(decision.get("risk_level") or snapshot.get("risk_level") or "unknown")
    bucket["record_count"] = int(bucket["record_count"]) + 1
    bucket["decision_distribution"][verdict] += 1
    bucket["risk_distribution"][risk] += 1
    raw_hits = snapshot.get("rule_hits")
    if isinstance(raw_hits, list):
        for hit in raw_hits:
            bucket["rule_hits"][str(hit)] += 1


def _finalize_policy_drift_bucket(bucket: dict[str, Any]) -> dict[str, Any]:
    count = int(bucket["record_count"])
    decisions = dict(bucket["decision_distribution"])
    risks = dict(bucket["risk_distribution"])
    high_or_critical = int(risks.get("high", 0)) + int(risks.get("critical", 0))
    return {
        "record_count": count,
        "decision_distribution": decisions,
        "risk_distribution": risks,
        "rule_hits": dict(bucket["rule_hits"]),
        "block_rate": round(float(decisions.get("block", 0)) / count, 6) if count else 0.0,
        "high_or_critical_rate": round(float(high_or_critical) / count, 6) if count else 0.0,
    }


def _skill_registry_states(record: dict[str, Any]) -> set[str]:
    states: set[str] = set()
    snapshot = (
        record.get("risk_snapshot")
        if isinstance(record.get("risk_snapshot"), dict)
        else {}
    )
    findings = snapshot.get("skill_trust_findings")
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for key in (
                "registry_status",
                "registry_state",
                "status",
                "trust_level",
                "list_state",
                "trust_list_state",
            ):
                value = str(finding.get(key) or "").strip()
                if value:
                    states.add(value)
    return states


def _add_policy_drift_traceability(
    traceability: dict[str, set[str]],
    record: dict[str, Any],
    effects: list[dict[str, Any]],
) -> None:
    event = record.get("event") if isinstance(record.get("event"), dict) else {}
    meta = record.get("meta") if isinstance(record.get("meta"), dict) else {}
    snapshot = (
        record.get("risk_snapshot")
        if isinstance(record.get("risk_snapshot"), dict)
        else {}
    )
    for key, value in (
        ("request_ids", meta.get("request_id")),
        ("record_ids", record.get("record_id")),
        ("event_ids", event.get("event_id")),
        ("fallback_paths", meta.get("fallback_path") or meta.get("fallback_mode")),
    ):
        text = str(value or "").strip()
        if text:
            traceability[key].add(text)
    raw_hits = snapshot.get("rule_hits")
    if isinstance(raw_hits, list):
        for hit in raw_hits:
            traceability["rule_evidence"].add(str(hit))
    for state in _skill_registry_states(record):
        traceability["registry_states"].add(state)
    for effect in effects:
        if not isinstance(effect, dict):
            continue
        value = str(effect.get("effect_id") or effect.get("id") or "").strip()
        if value:
            traceability["adapter_effect_result_ids"].add(value)


def _finalize_policy_drift_traceability(
    traceability: dict[str, set[str]],
) -> dict[str, list[str]]:
    return {
        key: sorted(values)
        for key, values in traceability.items()
    }


def _truthy_traceability_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _adapter_effect_results_applicable(
    record: dict[str, Any],
    effects: list[dict[str, Any]],
) -> bool:
    if effects:
        return True
    meta = record.get("meta") if isinstance(record.get("meta"), dict) else {}
    event = record.get("event") if isinstance(record.get("event"), dict) else {}
    for container in (meta, event):
        for key in ("adapter_effects_applicable", "adapter_effect_result_ids_applicable"):
            if key in container and _truthy_traceability_flag(container.get(key)):
                return True
    return False


def _required_metric_cell_traceability_fields(cell: dict[str, Any]) -> list[str]:
    fields = list(UNIVERSAL_METRIC_CELL_TRACEABILITY_FIELDS)
    rule_family = str(cell.get("rule_family") or "general")
    applicability = (
        cell.get("traceability_applicability")
        if isinstance(cell.get("traceability_applicability"), dict)
        else {}
    )
    if rule_family != "general" or applicability.get("rule_evidence"):
        fields.append("rule_evidence")
    if rule_family == "skill_trust" or applicability.get("registry_states"):
        fields.append("registry_states")
    if (
        applicability.get("adapter_effect_result_ids")
        or applicability.get("adapter_effects_applicable")
    ):
        fields.append("adapter_effect_result_ids")
    return fields


def _metric_cell_traceability(policy_drift: dict[str, Any]) -> dict[str, Any]:
    cells = policy_drift.get("cells") if isinstance(policy_drift, dict) else []
    complete_count = 0
    incomplete_cells: list[dict[str, Any]] = []
    for cell in cells or []:
        if not isinstance(cell, dict):
            continue
        trace = cell.get("traceability") if isinstance(cell.get("traceability"), dict) else {}
        missing = [
            field
            for field in _required_metric_cell_traceability_fields(cell)
            if not trace.get(field)
        ]
        if missing:
            incomplete_cells.append({
                "workspace_root": cell.get("workspace_root"),
                "source_framework": cell.get("source_framework"),
                "session_id": cell.get("session_id"),
                "rule_family": cell.get("rule_family"),
                "missing_fields": missing,
            })
        else:
            complete_count += 1
    total = len([cell for cell in cells or [] if isinstance(cell, dict)])
    coverage = 1.0 if total <= 0 else round(float(complete_count) / total, 6)
    return {
        "required_fields": list(UNIVERSAL_METRIC_CELL_TRACEABILITY_FIELDS),
        "conditional_fields": list(CONDITIONAL_METRIC_CELL_TRACEABILITY_FIELDS),
        "total_cells": total,
        "cell_count": total,
        "complete_cell_count": complete_count,
        "coverage": coverage,
        "passed": total > 0 and not incomplete_cells,
        "incomplete_cells": incomplete_cells,
    }


def _new_io_metric_bucket() -> dict[str, float | int]:
    return {
        "calls": 0,
        "total_seconds": 0.0,
        "last_seconds": 0.0,
        "max_seconds": 0.0,
    }


def _observe_io_metric(bucket: dict[str, float | int], elapsed_seconds: float) -> None:
    elapsed = max(0.0, float(elapsed_seconds))
    bucket["calls"] = int(bucket["calls"]) + 1
    bucket["total_seconds"] = float(bucket["total_seconds"]) + elapsed
    bucket["last_seconds"] = elapsed
    bucket["max_seconds"] = max(float(bucket["max_seconds"]), elapsed)


def _snapshot_io_metric(bucket: dict[str, float | int]) -> dict[str, float | int]:
    return {
        "calls": int(bucket["calls"]),
        "total_seconds": round(float(bucket["total_seconds"]), 6),
        "last_seconds": round(float(bucket["last_seconds"]), 6),
        "max_seconds": round(float(bucket["max_seconds"]), 6),
    }


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
        self._io_metrics = {
            "count": _new_io_metric_bucket(),
            "summary": _new_io_metric_bucket(),
            "policy_drift": _new_io_metric_bucket(),
            "replay_session": _new_io_metric_bucket(),
            "replay_session_page": _new_io_metric_bucket(),
        }
        self._init_schema()
        self._prune_expired()

    def io_metrics_snapshot(self) -> dict[str, dict[str, float | int]]:
        return {
            name: _snapshot_io_metric(bucket)
            for name, bucket in self._io_metrics.items()
        }

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
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS adapter_effect_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                idempotency_key TEXT NOT NULL UNIQUE,
                effect_id TEXT NOT NULL,
                session_id TEXT,
                event_id TEXT,
                tool_use_id TEXT,
                adapter TEXT NOT NULL,
                framework TEXT NOT NULL,
                result_kind TEXT NOT NULL,
                recorded_at_ts REAL NOT NULL,
                recorded_at TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_adapter_effect_session ON adapter_effect_results(session_id, recorded_at_ts)"
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_adapter_effect_event ON adapter_effect_results(event_id)"
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS l3_evidence_snapshots (
                snapshot_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                trigger_event_id TEXT NOT NULL,
                trigger_reason TEXT NOT NULL,
                trigger_detail TEXT,
                from_record_id INTEGER NOT NULL,
                to_record_id INTEGER NOT NULL,
                record_count INTEGER NOT NULL,
                trajectory_fingerprint TEXT NOT NULL,
                risk_summary_json TEXT NOT NULL,
                evidence_budget_json TEXT NOT NULL,
                created_at_ts REAL NOT NULL,
                created_at TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_l3_snapshots_session ON l3_evidence_snapshots(session_id, created_at_ts)"
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS l3_advisory_reviews (
                review_id TEXT PRIMARY KEY,
                snapshot_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                advisory_only INTEGER NOT NULL,
                recommended_operator_action TEXT NOT NULL,
                l3_state TEXT NOT NULL,
                l3_reason_code TEXT,
                created_at_ts REAL NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                review_json TEXT NOT NULL,
                FOREIGN KEY(snapshot_id) REFERENCES l3_evidence_snapshots(snapshot_id)
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_l3_reviews_session ON l3_advisory_reviews(session_id, created_at_ts)"
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS l3_advisory_jobs (
                job_id TEXT PRIMARY KEY,
                snapshot_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                review_id TEXT,
                job_state TEXT NOT NULL,
                runner TEXT NOT NULL,
                created_at_ts REAL NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                completed_at TEXT,
                job_json TEXT NOT NULL,
                FOREIGN KEY(snapshot_id) REFERENCES l3_evidence_snapshots(snapshot_id)
            )
            """
        )
        cur.execute(
            "CREATE INDEX IF NOT EXISTS idx_l3_jobs_session ON l3_advisory_jobs(session_id, created_at_ts)"
        )
        # Migrate: add l3_trace_json column if missing
        try:
            cur.execute("ALTER TABLE trajectory_records ADD COLUMN l3_trace_json TEXT")
        except sqlite3.OperationalError:
            pass  # Column already exists
        self._conn.commit()

    def record_adapter_effect_result(
        self,
        result: dict[str, Any],
        *,
        recorded_at_ts: Optional[float] = None,
    ) -> dict[str, Any]:
        """Append an observed adapter effect result with idempotent writeback."""

        ts = recorded_at_ts if recorded_at_ts is not None else time.time()
        recorded_at = self._iso_from_ts(ts)
        result_json = dict(result)
        idempotency_key = str(
            result_json.get("idempotency_key")
            or ":".join(
                [
                    str(result_json.get("effect_id") or "unknown"),
                    str(result_json.get("adapter") or "unknown"),
                    str(
                        result_json.get("tool_use_id")
                        or result_json.get("event_id")
                        or result_json.get("session_id")
                        or "unknown"
                    ),
                    str(result_json.get("result_kind") or "observed"),
                ]
            )
        )
        result_json["idempotency_key"] = idempotency_key
        try:
            cur = self._conn.cursor()
            cur.execute(
                """
                INSERT INTO adapter_effect_results (
                    idempotency_key,
                    effect_id,
                    session_id,
                    event_id,
                    tool_use_id,
                    adapter,
                    framework,
                    result_kind,
                    recorded_at_ts,
                    recorded_at,
                    result_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    idempotency_key,
                    str(result_json.get("effect_id") or ""),
                    result_json.get("session_id"),
                    result_json.get("event_id"),
                    result_json.get("tool_use_id"),
                    str(result_json.get("adapter") or "unknown"),
                    str(result_json.get("framework") or "unknown"),
                    str(result_json.get("result_kind") or "observed"),
                    ts,
                    recorded_at,
                    json.dumps(result_json),
                ),
            )
            record_id = int(cur.lastrowid)
            self._conn.commit()
            return {
                "created": True,
                "record_id": record_id,
                "idempotency_key": idempotency_key,
                "result": result_json,
            }
        except sqlite3.IntegrityError:
            row = self._conn.execute(
                "SELECT id, result_json FROM adapter_effect_results WHERE idempotency_key = ?",
                (idempotency_key,),
            ).fetchone()
            return {
                "created": False,
                "record_id": int(row["id"]) if row else None,
                "idempotency_key": idempotency_key,
                "result": json.loads(row["result_json"]) if row else result_json,
            }

    def _adapter_results_for_records(
        self, records: list[dict[str, Any]]
    ) -> dict[tuple[str | None, str | None], list[dict[str, Any]]]:
        event_ids = [
            str(rec.get("event", {}).get("event_id"))
            for rec in records
            if rec.get("event", {}).get("event_id") is not None
        ]
        session_ids = [
            str(rec.get("event", {}).get("session_id"))
            for rec in records
            if rec.get("event", {}).get("session_id") is not None
        ]
        if not event_ids and not session_ids:
            return {}

        clauses: list[str] = []
        params: list[Any] = []
        if event_ids:
            clauses.append(f"event_id IN ({','.join(['?'] * len(event_ids))})")
            params.extend(event_ids)
        if session_ids:
            clauses.append(f"session_id IN ({','.join(['?'] * len(session_ids))})")
            params.extend(session_ids)
        rows = self._conn.execute(
            """
            SELECT event_id, session_id, result_json
            FROM adapter_effect_results
            WHERE """ + " OR ".join(clauses) + """
            ORDER BY id ASC
            """,
            params,
        ).fetchall()
        grouped: dict[tuple[str | None, str | None], list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            result = json.loads(row["result_json"])
            grouped[(row["event_id"], row["session_id"])].append(result)
        return grouped

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
    ) -> int:
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
        record_id = int(cur.lastrowid)
        self._conn.commit()
        self._prune_expired(now_ts=ts)
        return record_id

    def record_resolution(
        self,
        *,
        event: dict,
        decision: dict,
        snapshot: dict,
        meta: dict,
        recorded_at_ts: Optional[float] = None,
        l3_trace: Optional[dict] = None,
    ) -> int:
        resolution_meta = dict(meta)
        resolution_meta["record_type"] = "decision_resolution"
        return self.record(
            event=event,
            decision=decision,
            snapshot=snapshot,
            meta=resolution_meta,
            recorded_at_ts=recorded_at_ts,
            l3_trace=l3_trace,
        )

    def _query_records(
        self,
        *,
        session_id: Optional[str] = None,
        since_seconds: Optional[int] = None,
        limit: Optional[int] = None,
        before_id: Optional[int] = None,
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
        if before_id is not None and before_id > 0:
            clauses.append("id < ?")
            params.append(before_id)

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        if limit is not None and limit > 0:
            sql = (
                "SELECT id, recorded_at_ts, recorded_at, event_json, decision_json, snapshot_json, meta_json, l3_trace_json "
                "FROM trajectory_records "
                f"{where_sql} "
                "ORDER BY id DESC LIMIT ?"
            )
            rows = self._conn.execute(sql, (*params, limit)).fetchall()
            rows = list(reversed(rows))
        else:
            sql = (
                "SELECT id, recorded_at_ts, recorded_at, event_json, decision_json, snapshot_json, meta_json, l3_trace_json "
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
                    "record_id": int(row["id"]),
                    "recorded_at": row["recorded_at"],
                    "recorded_at_ts": float(row["recorded_at_ts"]),
                    "l3_trace": json.loads(l3_raw) if l3_raw else None,
                }
            )
        return records

    def _query_records_by_id_range(
        self,
        *,
        session_id: str,
        from_record_id: int,
        to_record_id: int,
    ) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            """
            SELECT id, recorded_at_ts, recorded_at, event_json, decision_json, snapshot_json, meta_json, l3_trace_json
            FROM trajectory_records
            WHERE session_id = ? AND id >= ? AND id <= ?
            ORDER BY id ASC
            """,
            (session_id, from_record_id, to_record_id),
        ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            l3_raw = row["l3_trace_json"]
            records.append(
                {
                    "event": json.loads(row["event_json"]),
                    "decision": json.loads(row["decision_json"]),
                    "risk_snapshot": json.loads(row["snapshot_json"]),
                    "meta": json.loads(row["meta_json"]),
                    "record_id": int(row["id"]),
                    "recorded_at": row["recorded_at"],
                    "recorded_at_ts": float(row["recorded_at_ts"]),
                    "l3_trace": json.loads(l3_raw) if l3_raw else None,
                }
            )
        return records

    @staticmethod
    def _json_dumps(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _hash_text(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _select_l3_snapshot_records(
        self,
        *,
        session_id: str,
        to_record_id: int | None,
        from_record_id: int | None,
        max_records: int,
    ) -> list[dict[str, Any]]:
        clauses = ["session_id = ?"]
        params: list[Any] = [session_id]
        if to_record_id is not None:
            clauses.append("id <= ?")
            params.append(to_record_id)
        if from_record_id is not None:
            clauses.append("id >= ?")
            params.append(from_record_id)
        rows = self._conn.execute(
            f"""
            SELECT id
            FROM trajectory_records
            WHERE {' AND '.join(clauses)}
            ORDER BY id DESC
            LIMIT ?
            """,
            (*params, max(max_records, 1)),
        ).fetchall()
        record_ids = sorted(int(row["id"]) for row in rows)
        if not record_ids:
            return []
        return self._query_records_by_id_range(
            session_id=session_id,
            from_record_id=record_ids[0],
            to_record_id=record_ids[-1],
        )

    @staticmethod
    def _build_l3_snapshot_risk_summary(records: list[dict[str, Any]]) -> dict[str, Any]:
        decision_distribution: dict[str, int] = defaultdict(int)
        high_risk_count = 0
        current_risk_level = "low"
        for record in records:
            decision = record.get("decision") or {}
            risk_level = str(decision.get("risk_level") or record.get("risk_snapshot", {}).get("risk_level") or "low")
            current_risk_level = risk_level
            decision_distribution[str(decision.get("decision") or "unknown")] += 1
            if risk_level.lower() in HIGH_RISK_LEVELS:
                high_risk_count += 1
        return {
            "current_risk_level": current_risk_level,
            "high_risk_event_count": high_risk_count,
            "decision_distribution": dict(decision_distribution),
        }

    def create_l3_evidence_snapshot(
        self,
        *,
        session_id: str,
        trigger_event_id: str,
        trigger_reason: str,
        trigger_detail: str | None = None,
        to_record_id: int | None = None,
        from_record_id: int | None = None,
        max_records: int = 50,
        max_tool_calls: int = 4,
    ) -> dict[str, Any]:
        records = self._select_l3_snapshot_records(
            session_id=session_id,
            to_record_id=to_record_id,
            from_record_id=from_record_id,
            max_records=max_records,
        )
        if not records:
            raise ValueError(f"no trajectory records found for session {session_id!r}")

        from_id = int(records[0]["record_id"])
        to_id = int(records[-1]["record_id"])
        fingerprint_input = [
            {
                "record_id": record["record_id"],
                "event_id": record.get("event", {}).get("event_id"),
                "decision": record.get("decision", {}).get("decision"),
                "risk_level": record.get("decision", {}).get("risk_level"),
                "recorded_at": record.get("recorded_at"),
            }
            for record in records
        ]
        trajectory_fingerprint = self._hash_text(self._json_dumps(fingerprint_input))
        snapshot_hash = self._hash_text(
            self._json_dumps(
                {
                    "session_id": session_id,
                    "trigger_event_id": trigger_event_id,
                    "trigger_reason": trigger_reason,
                    "trigger_detail": trigger_detail,
                    "from_record_id": from_id,
                    "to_record_id": to_id,
                    "trajectory_fingerprint": trajectory_fingerprint,
                }
            )
        )
        snapshot_id = f"l3snap-{snapshot_hash[:16]}"
        existing = self.get_l3_evidence_snapshot(snapshot_id)
        if existing is not None:
            return existing

        ts = time.time()
        created_at = self._iso_from_ts(ts)
        risk_summary = self._build_l3_snapshot_risk_summary(records)
        evidence_budget = {
            "max_records": max_records,
            "max_tool_calls": max_tool_calls,
        }
        snapshot = {
            "snapshot_id": snapshot_id,
            "session_id": session_id,
            "created_at": created_at,
            "trigger_event_id": trigger_event_id,
            "trigger_reason": trigger_reason,
            "trigger_detail": trigger_detail,
            "event_range": {
                "from_record_id": from_id,
                "to_record_id": to_id,
            },
            "record_count": len(records),
            "trajectory_fingerprint": trajectory_fingerprint,
            "risk_summary": risk_summary,
            "evidence_budget": evidence_budget,
            "advisory_only": True,
        }
        self._conn.execute(
            """
            INSERT INTO l3_evidence_snapshots (
                snapshot_id, session_id, trigger_event_id, trigger_reason, trigger_detail,
                from_record_id, to_record_id, record_count, trajectory_fingerprint,
                risk_summary_json, evidence_budget_json, created_at_ts, created_at, snapshot_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                session_id,
                trigger_event_id,
                trigger_reason,
                trigger_detail,
                from_id,
                to_id,
                len(records),
                trajectory_fingerprint,
                self._json_dumps(risk_summary),
                self._json_dumps(evidence_budget),
                ts,
                created_at,
                self._json_dumps(snapshot),
            ),
        )
        self._conn.commit()
        return snapshot

    def get_l3_evidence_snapshot(self, snapshot_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT snapshot_json FROM l3_evidence_snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        return json.loads(row["snapshot_json"]) if row else None

    def list_l3_evidence_snapshots(self, *, session_id: str | None = None) -> list[dict[str, Any]]:
        if session_id is None:
            rows = self._conn.execute(
                "SELECT snapshot_json FROM l3_evidence_snapshots ORDER BY created_at_ts ASC"
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT snapshot_json FROM l3_evidence_snapshots WHERE session_id = ? ORDER BY created_at_ts ASC",
                (session_id,),
            ).fetchall()
        return [json.loads(row["snapshot_json"]) for row in rows]

    def replay_l3_evidence_snapshot(self, snapshot_id: str) -> list[dict[str, Any]]:
        snapshot = self.get_l3_evidence_snapshot(snapshot_id)
        if snapshot is None:
            return []
        event_range = snapshot.get("event_range") or {}
        return self._query_records_by_id_range(
            session_id=str(snapshot.get("session_id") or ""),
            from_record_id=int(event_range.get("from_record_id") or 0),
            to_record_id=int(event_range.get("to_record_id") or 0),
        )

    def record_l3_advisory_review(
        self,
        *,
        snapshot_id: str,
        risk_level: str,
        findings: list[str] | None = None,
        confidence: float | None = None,
        advisory_only: bool = True,
        recommended_operator_action: str = "inspect",
        l3_state: str = "completed",
        l3_reason_code: str | None = None,
        completed_at: str | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if advisory_only is not True:
            raise ValueError("l3 advisory reviews must keep advisory_only=true")
        if l3_state not in L3_ADVISORY_REVIEW_STATES:
            raise ValueError(f"l3_state must be one of: {', '.join(sorted(L3_ADVISORY_REVIEW_STATES))}")
        snapshot = self.get_l3_evidence_snapshot(snapshot_id)
        if snapshot is None:
            raise ValueError(f"snapshot {snapshot_id!r} was not found")
        normalized_findings = [str(item) for item in (findings or [])]
        review_hash = self._hash_text(
            self._json_dumps(
                {
                    "snapshot_id": snapshot_id,
                    "risk_level": risk_level,
                    "findings": normalized_findings,
                    "confidence": confidence,
                    "recommended_operator_action": recommended_operator_action,
                    "l3_state": l3_state,
                    "l3_reason_code": l3_reason_code,
                }
            )
        )
        review_id = f"l3adv-{review_hash[:16]}"
        existing = self.get_l3_advisory_review(review_id)
        if existing is not None:
            return existing

        ts = time.time()
        created_at = self._iso_from_ts(ts)
        if completed_at is None and l3_state in L3_ADVISORY_TERMINAL_STATES:
            completed_at = created_at
        review = {
            "review_id": review_id,
            "type": "l3_advisory_review",
            "snapshot_id": snapshot_id,
            "session_id": snapshot["session_id"],
            "risk_level": risk_level,
            "findings": normalized_findings,
            "confidence": confidence,
            "advisory_only": True,
            "recommended_operator_action": recommended_operator_action,
            "l3_state": l3_state,
            "l3_reason_code": l3_reason_code,
            "created_at": created_at,
            "completed_at": completed_at,
        }
        if extra_fields:
            review.update(extra_fields)
        self._conn.execute(
            """
            INSERT INTO l3_advisory_reviews (
                review_id, snapshot_id, session_id, risk_level, advisory_only,
                recommended_operator_action, l3_state, l3_reason_code,
                created_at_ts, created_at, completed_at, review_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review_id,
                snapshot_id,
                snapshot["session_id"],
                risk_level,
                1,
                recommended_operator_action,
                l3_state,
                l3_reason_code,
                ts,
                created_at,
                completed_at,
                self._json_dumps(review),
            ),
        )
        self._conn.commit()
        return review

    def update_l3_advisory_review(
        self,
        review_id: str,
        *,
        risk_level: str | None = None,
        findings: list[str] | None = None,
        confidence: float | None = None,
        recommended_operator_action: str | None = None,
        l3_state: str | None = None,
        l3_reason_code: str | None = None,
        completed_at: str | None = None,
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        current = self.get_l3_advisory_review(review_id)
        if current is None:
            raise ValueError(f"review {review_id!r} was not found")
        if l3_state is not None and l3_state not in L3_ADVISORY_REVIEW_STATES:
            raise ValueError(f"l3_state must be one of: {', '.join(sorted(L3_ADVISORY_REVIEW_STATES))}")

        next_review = dict(current)
        if risk_level is not None:
            next_review["risk_level"] = risk_level
        if findings is not None:
            next_review["findings"] = [str(item) for item in findings]
        if confidence is not None:
            next_review["confidence"] = confidence
        if recommended_operator_action is not None:
            next_review["recommended_operator_action"] = recommended_operator_action
        if l3_state is not None:
            next_review["l3_state"] = l3_state
        if l3_reason_code is not None:
            next_review["l3_reason_code"] = l3_reason_code
        if completed_at is not None:
            next_review["completed_at"] = completed_at
        elif (
            next_review.get("completed_at") is None
            and next_review.get("l3_state") in L3_ADVISORY_TERMINAL_STATES
        ):
            next_review["completed_at"] = self._iso_from_ts(time.time())
        if extra_fields:
            next_review.update(extra_fields)

        self._conn.execute(
            """
            UPDATE l3_advisory_reviews
            SET risk_level = ?,
                recommended_operator_action = ?,
                l3_state = ?,
                l3_reason_code = ?,
                completed_at = ?,
                review_json = ?
            WHERE review_id = ?
            """,
            (
                next_review["risk_level"],
                next_review["recommended_operator_action"],
                next_review["l3_state"],
                next_review.get("l3_reason_code"),
                next_review.get("completed_at"),
                self._json_dumps(next_review),
                review_id,
            ),
        )
        self._conn.commit()
        return next_review

    @staticmethod
    def _highest_risk_level(records: list[dict[str, Any]]) -> str:
        highest = "low"
        for record in records:
            risk_level = str(
                record.get("decision", {}).get("risk_level")
                or record.get("risk_snapshot", {}).get("risk_level")
                or "low"
            ).lower()
            if _RISK_LEVEL_RANK.get(risk_level, 0) > _RISK_LEVEL_RANK.get(highest, 0):
                highest = risk_level
        return highest

    @staticmethod
    def _recommended_action_for_risk(risk_level: str) -> str:
        if risk_level == "critical":
            return "escalate"
        if risk_level in {"high", "medium"}:
            return "inspect"
        return "none"

    @staticmethod
    def build_l3_advisory_action_summary(
        *,
        review: dict[str, Any] | None,
        job: dict[str, Any] | None = None,
        snapshot: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Derive a compact operator action from an advisory review.

        The summary intentionally carries identifiers and bounded record range
        only. It never includes provider prompts/responses or live transcript
        payloads, and it always preserves the advisory-only/canonical-unchanged
        boundary for downstream report/SSE/watch/UI surfaces.
        """

        if not review:
            return None
        l3_state = str(review.get("l3_state") or "").lower()
        risk_level = str(review.get("risk_level") or "low").lower()
        recommended = str(review.get("recommended_operator_action") or "none").lower()
        reason_code = str(review.get("l3_reason_code") or "").lower()
        is_degraded = l3_state == "degraded"
        if l3_state not in {"completed", "degraded"}:
            return None
        is_actionable = (
            risk_level in HIGH_RISK_LEVELS
            or recommended in {"pause", "escalate", "inspect"}
            or is_degraded
        )
        if not is_actionable or (risk_level == "low" and recommended == "none" and not is_degraded):
            return None

        if is_degraded:
            operator_action = (
                "inspect_provider_config"
                if reason_code in {"provider_disabled", "provider_response_invalid", "provider_error"}
                else "inspect"
            )
            summary = "L3 advisory degraded; inspect provider configuration before relying on provider output."
        else:
            operator_action = recommended if recommended != "none" else ("escalate" if risk_level == "critical" else "inspect")
            summary = f"L3 advisory {risk_level} risk recommends {operator_action}; advisory only, canonical unchanged."

        source_range = review.get("source_record_range")
        if not isinstance(source_range, dict) and snapshot is not None:
            source_range = snapshot.get("event_range")

        snapshot_id = str(review.get("snapshot_id") or (snapshot or {}).get("snapshot_id") or "")
        review_id = str(review.get("review_id") or "")
        job_id = str((job or {}).get("job_id") or "")
        action = {
            "type": "l3_advisory_action",
            "action_id": f"l3action-{review_id}",
            "session_id": str(review.get("session_id") or (snapshot or {}).get("session_id") or ""),
            "snapshot_id": snapshot_id,
            "job_id": job_id or None,
            "review_id": review_id,
            "risk_level": risk_level,
            "recommended_operator_action": operator_action,
            "l3_state": l3_state,
            "l3_reason_code": review.get("l3_reason_code"),
            "source_record_range": source_range if isinstance(source_range, dict) else None,
            "summary": summary,
            "advisory_only": True,
            "canonical_decision_mutated": False,
            "created_at": review.get("completed_at") or review.get("created_at"),
        }
        for key in ("analysis_summary", "analysis_points", "operator_next_steps"):
            if key in review:
                action[key] = review[key]
        return action

    def run_local_l3_advisory_review(self, snapshot_id: str) -> dict[str, Any]:
        """Run a deterministic local advisory review over a frozen snapshot.

        This is intentionally not an LLM worker. It proves that the review
        lifecycle consumes only snapshot-bounded records and can be updated
        without changing canonical decision records.
        """

        snapshot = self.get_l3_evidence_snapshot(snapshot_id)
        if snapshot is None:
            raise ValueError(f"snapshot {snapshot_id!r} was not found")
        records = self.replay_l3_evidence_snapshot(snapshot_id)
        if not records:
            raise ValueError(f"snapshot {snapshot_id!r} has no replayable records")

        event_ids = [str(record.get("event", {}).get("event_id") or "") for record in records]
        event_ids = [event_id for event_id in event_ids if event_id]
        risk_summary = self._build_l3_snapshot_risk_summary(records)
        risk_level = self._highest_risk_level(records)
        action = self._recommended_action_for_risk(risk_level)
        event_range = snapshot.get("event_range") or {}
        decision_distribution = risk_summary.get("decision_distribution") or {}
        decision_summary = ", ".join(
            f"{key}={value}" for key, value in sorted(decision_distribution.items())
        ) or "none"
        findings = [
            (
                f"Reviewed {len(records)} frozen record(s) from "
                f"{event_range.get('from_record_id')} to {event_range.get('to_record_id')}"
            ),
            f"Source events: {', '.join(event_ids) or '-'}",
            f"Decision distribution: {decision_summary}",
        ]
        analysis_summary = (
            f"Frozen L3 evidence shows {risk_level} risk across {len(records)} record(s) "
            f"from {event_range.get('from_record_id')} to {event_range.get('to_record_id')}; "
            f"decision distribution is {decision_summary}. This advisory does not change canonical decisions."
        )
        analysis_points = [
            f"Trigger reason: {snapshot.get('trigger_reason') or 'unknown'}.",
            f"Source events: {', '.join(event_ids) or '-'}.",
            f"Recommended operator action: {action}.",
        ]
        operator_next_steps = [
            "Inspect the frozen replay range before releasing or escalating the session.",
            "Confirm the advisory-only output did not mutate canonical decision state.",
        ]

        review = self.record_l3_advisory_review(
            snapshot_id=snapshot_id,
            risk_level=risk_level,
            findings=[],
            recommended_operator_action=action,
            l3_state="pending",
        )
        self.update_l3_advisory_review(
            review["review_id"],
            l3_state="running",
            findings=["Deterministic local advisory review started"],
        )
        return self.update_l3_advisory_review(
            review["review_id"],
            l3_state="completed",
            risk_level=risk_level,
            findings=findings,
            confidence=None,
            recommended_operator_action=action,
            extra_fields={
                "evidence_record_count": len(records),
                "evidence_event_ids": event_ids,
                "source_record_range": {
                    "from_record_id": int(event_range.get("from_record_id") or 0),
                    "to_record_id": int(event_range.get("to_record_id") or 0),
                },
                "review_runner": "deterministic_local",
                "analysis_summary": analysis_summary[:360],
                "analysis_points": [item[:180] for item in analysis_points[:5]],
                "operator_next_steps": [item[:180] for item in operator_next_steps[:3]],
            },
        )

    def enqueue_l3_advisory_job(
        self,
        snapshot_id: str,
        *,
        runner: str = "deterministic_local",
    ) -> dict[str, Any]:
        snapshot = self.get_l3_evidence_snapshot(snapshot_id)
        if snapshot is None:
            raise ValueError(f"snapshot {snapshot_id!r} was not found")
        job_id = f"l3job-{self._hash_text(self._json_dumps({'snapshot_id': snapshot_id, 'runner': runner}))[:16]}"
        existing = self.get_l3_advisory_job(job_id)
        if existing is not None:
            return existing
        ts = time.time()
        created_at = self._iso_from_ts(ts)
        job = {
            "job_id": job_id,
            "snapshot_id": snapshot_id,
            "session_id": snapshot["session_id"],
            "review_id": None,
            "job_state": "queued",
            "runner": runner,
            "created_at": created_at,
            "updated_at": created_at,
            "completed_at": None,
        }
        self._conn.execute(
            """
            INSERT INTO l3_advisory_jobs (
                job_id, snapshot_id, session_id, review_id, job_state, runner,
                created_at_ts, created_at, updated_at, completed_at, job_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                snapshot_id,
                snapshot["session_id"],
                None,
                "queued",
                runner,
                ts,
                created_at,
                created_at,
                None,
                self._json_dumps(job),
            ),
        )
        self._conn.commit()
        return job

    def get_l3_advisory_job(self, job_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT job_json FROM l3_advisory_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        return json.loads(row["job_json"]) if row else None

    def list_l3_advisory_jobs(
        self,
        *,
        session_id: str | None = None,
        snapshot_id: str | None = None,
        job_state: str | None = None,
        runner: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if snapshot_id is not None:
            clauses.append("snapshot_id = ?")
            params.append(snapshot_id)
        if job_state is not None:
            if job_state not in L3_ADVISORY_JOB_STATES:
                raise ValueError(f"job_state must be one of: {', '.join(sorted(L3_ADVISORY_JOB_STATES))}")
            clauses.append("job_state = ?")
            params.append(job_state)
        if runner is not None:
            clauses.append("runner = ?")
            params.append(runner)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT job_json FROM l3_advisory_jobs {where_sql} ORDER BY created_at_ts ASC",
            params,
        ).fetchall()
        return [json.loads(row["job_json"]) for row in rows]

    def claim_l3_advisory_job(
        self,
        job_id: str,
        *,
        expected_runner: str | None = None,
    ) -> dict[str, Any] | None:
        """Atomically transition one queued advisory job to running.

        Returns the running job when this call won the queued-only claim.
        Returns ``None`` when the job exists but is no longer queued. Missing
        jobs and runner mismatches remain hard errors so callers do not
        accidentally hide malformed operator requests.
        """

        current = self.get_l3_advisory_job(job_id)
        if current is None:
            raise ValueError(f"job {job_id!r} was not found")
        if expected_runner is not None and current.get("runner") != expected_runner:
            raise ValueError(
                f"job runner {current.get('runner')!r} does not match requested runner {expected_runner!r}"
            )
        if current.get("job_state") != "queued":
            return None

        next_job = dict(current)
        updated_at = self._iso_from_ts(time.time())
        next_job["job_state"] = "running"
        next_job["updated_at"] = updated_at
        cur = self._conn.execute(
            """
            UPDATE l3_advisory_jobs
            SET job_state = ?,
                updated_at = ?,
                job_json = ?
            WHERE job_id = ? AND job_state = 'queued'
            """,
            (
                "running",
                updated_at,
                self._json_dumps(next_job),
                job_id,
            ),
        )
        self._conn.commit()
        if cur.rowcount != 1:
            return None
        return next_job

    def claim_next_l3_advisory_job(
        self,
        *,
        runner: str,
        session_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Claim the oldest queued job for a runner using queued-only semantics."""

        clauses = ["job_state = ?", "runner = ?"]
        params: list[Any] = ["queued", runner]
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        row = self._conn.execute(
            f"""
            SELECT job_id
            FROM l3_advisory_jobs
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at_ts ASC
            LIMIT 1
            """,
            params,
        ).fetchone()
        if row is None:
            return None
        return self.claim_l3_advisory_job(str(row["job_id"]), expected_runner=runner)

    def latest_l3_advisory_job(self, *, session_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT job_json FROM l3_advisory_jobs
            WHERE session_id = ?
            ORDER BY created_at_ts DESC
            LIMIT 1
            """,
            (session_id,),
        ).fetchone()
        return json.loads(row["job_json"]) if row else None

    def update_l3_advisory_job(
        self,
        job_id: str,
        *,
        job_state: str | None = None,
        review_id: str | None = None,
        error: str | None = None,
    ) -> dict[str, Any]:
        current = self.get_l3_advisory_job(job_id)
        if current is None:
            raise ValueError(f"job {job_id!r} was not found")
        if job_state is not None and job_state not in L3_ADVISORY_JOB_STATES:
            raise ValueError(f"job_state must be one of: {', '.join(sorted(L3_ADVISORY_JOB_STATES))}")
        next_job = dict(current)
        if job_state is not None:
            next_job["job_state"] = job_state
        if review_id is not None:
            next_job["review_id"] = review_id
        if error is not None:
            next_job["error"] = error
        updated_at = self._iso_from_ts(time.time())
        next_job["updated_at"] = updated_at
        if next_job["job_state"] in L3_ADVISORY_JOB_TERMINAL_STATES and next_job.get("completed_at") is None:
            next_job["completed_at"] = updated_at
        self._conn.execute(
            """
            UPDATE l3_advisory_jobs
            SET review_id = ?,
                job_state = ?,
                updated_at = ?,
                completed_at = ?,
                job_json = ?
            WHERE job_id = ?
            """,
            (
                next_job.get("review_id"),
                next_job["job_state"],
                next_job["updated_at"],
                next_job.get("completed_at"),
                self._json_dumps(next_job),
                job_id,
            ),
        )
        self._conn.commit()
        return next_job

    def run_l3_advisory_job_local(self, job_id: str) -> dict[str, Any]:
        job = self.get_l3_advisory_job(job_id)
        if job is None:
            raise ValueError(f"job {job_id!r} was not found")
        if job["runner"] != "deterministic_local":
            raise ValueError(f"unsupported advisory job runner {job['runner']!r}")
        claimed = self.claim_l3_advisory_job(job_id, expected_runner="deterministic_local")
        if claimed is None:
            raise ValueError(f"job {job_id!r} is not queued and cannot be rerun")
        try:
            review = self.run_local_l3_advisory_review(job["snapshot_id"])
        except Exception as exc:
            failed = self.update_l3_advisory_job(
                job_id,
                job_state="failed",
                error=str(exc),
            )
            raise ValueError(str(exc)) from exc
        completed = self.update_l3_advisory_job(
            job_id,
            job_state="completed",
            review_id=review["review_id"],
        )
        return {"job": completed, "review": review}

    def get_l3_advisory_review(self, review_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT review_json FROM l3_advisory_reviews WHERE review_id = ?",
            (review_id,),
        ).fetchone()
        return json.loads(row["review_json"]) if row else None

    def list_l3_advisory_reviews(
        self,
        *,
        session_id: str | None = None,
        snapshot_id: str | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if snapshot_id is not None:
            clauses.append("snapshot_id = ?")
            params.append(snapshot_id)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        rows = self._conn.execute(
            f"SELECT review_json FROM l3_advisory_reviews {where_sql} ORDER BY created_at_ts ASC",
            params,
        ).fetchall()
        return [json.loads(row["review_json"]) for row in rows]

    def latest_l3_advisory_review(self, *, session_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT review_json FROM l3_advisory_reviews
            WHERE session_id = ?
            ORDER BY created_at_ts DESC
            LIMIT 1
            """,
            (session_id,),
        ).fetchone()
        return json.loads(row["review_json"]) if row else None

    @property
    def records(self) -> list[dict[str, Any]]:
        return self._query_records()

    def count(self, since_seconds: Optional[int] = None) -> int:
        start = time.perf_counter()
        try:
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
        finally:
            _observe_io_metric(self._io_metrics["count"], time.perf_counter() - start)

    def summary(self, since_seconds: Optional[int] = None) -> dict[str, Any]:
        start = time.perf_counter()
        try:
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

            invalid_event = self._build_invalid_event_metrics(records, now_ts)
            high_risk_trend = self._build_high_risk_trend(records, now_ts)
            return {
                "total_records": len(records),
                "by_source_framework": dict(by_source_framework),
                "by_event_type": dict(by_event_type),
                "by_decision": dict(by_decision),
                "by_risk_level": dict(by_risk_level),
                "by_actual_tier": dict(by_actual_tier),
                "by_caller_adapter": dict(by_caller_adapter),
                "invalid_event": invalid_event,
                "high_risk_trend": high_risk_trend,
                "system_security_posture": self._build_system_security_posture(
                    by_risk_level=dict(by_risk_level),
                    invalid_event=invalid_event,
                    high_risk_trend=high_risk_trend,
                    now_ts=now_ts,
                    window_seconds=since_seconds or 3600,
                ),
            }
        finally:
            _observe_io_metric(self._io_metrics["summary"], time.perf_counter() - start)

    def policy_drift_report(
        self,
        *,
        window_seconds: Optional[int] = None,
        max_cells: int = 200,
    ) -> dict[str, Any]:
        """Aggregate policy drift by workspace/framework/session/rule family."""

        start = time.perf_counter()
        try:
            effective_window = window_seconds if window_seconds and window_seconds > 0 else None
            query_window = effective_window * 2 if effective_window else None
            records = self._query_records(since_seconds=query_window)
            adapter_results = self._adapter_results_for_records(records)
            now_ts = time.time()
            current_cutoff = now_ts - effective_window if effective_window else None
            cells: dict[tuple[str, str, str, str], dict[str, Any]] = {}

            for record in records:
                event = record.get("event") if isinstance(record.get("event"), dict) else {}
                snapshot = (
                    record.get("risk_snapshot")
                    if isinstance(record.get("risk_snapshot"), dict)
                    else {}
                )
                families = _rule_families_for_snapshot(snapshot)
                workspace_root = _workspace_root_for_event(event)
                source_framework = str(event.get("source_framework") or "unknown")
                session_id = str(event.get("session_id") or "unknown")
                period = "current"
                if current_cutoff is not None and float(record.get("recorded_at_ts") or 0.0) < current_cutoff:
                    period = "previous"
                for family in families:
                    key = (workspace_root, source_framework, session_id, family)
                    cell = cells.setdefault(
                        key,
                        {
                            "workspace_root": workspace_root,
                            "source_framework": source_framework,
                            "session_id": session_id,
                            "rule_family": family,
                            "current": _empty_policy_drift_bucket(),
                            "previous": _empty_policy_drift_bucket(),
                            "traceability": _empty_policy_drift_traceability(),
                            "traceability_applicability": (
                                _empty_policy_drift_traceability_applicability(family)
                            ),
                        },
                    )
                    _add_record_to_policy_drift_bucket(cell[period], record)
                    if period == "current":
                        event_id = event.get("event_id")
                        session_key = (None, event.get("session_id"))
                        result_key = (event_id, event.get("session_id"))
                        effects = (
                            adapter_results.get(result_key, [])
                            + adapter_results.get(session_key, [])
                        )
                        _add_policy_drift_traceability(
                            cell["traceability"],
                            record,
                            effects,
                        )
                        if _adapter_effect_results_applicable(record, effects):
                            cell["traceability_applicability"][
                                "adapter_effect_result_ids"
                            ] = True

            finalized: list[dict[str, Any]] = []
            for cell in cells.values():
                current = _finalize_policy_drift_bucket(cell["current"])
                previous = _finalize_policy_drift_bucket(cell["previous"])
                finalized.append({
                    "cell_id": "|".join(
                        [
                            cell["workspace_root"],
                            cell["source_framework"],
                            cell["session_id"],
                            cell["rule_family"],
                        ]
                    ),
                    "workspace_root": cell["workspace_root"],
                    "source_framework": cell["source_framework"],
                    "session_id": cell["session_id"],
                    "rule_family": cell["rule_family"],
                    "current": current,
                    "previous": previous,
                    "delta": {
                        "record_count": current["record_count"] - previous["record_count"],
                        "block_rate": round(current["block_rate"] - previous["block_rate"], 6),
                        "high_or_critical_rate": round(
                            current["high_or_critical_rate"]
                            - previous["high_or_critical_rate"],
                            6,
                        ),
                    },
                    "traceability": _finalize_policy_drift_traceability(
                        cell["traceability"]
                    ),
                    "traceability_applicability": dict(
                        cell["traceability_applicability"]
                    ),
                })
            finalized.sort(
                key=lambda item: (
                    -abs(float(item["delta"]["block_rate"])),
                    -int(item["current"]["record_count"]),
                    item["cell_id"],
                )
            )
            effective_limit = min(max(max_cells, 1), 5000)
            policy_drift = {
                "cells": finalized,
            }
            return {
                "generated_at": self._iso_from_ts(now_ts),
                "window_seconds": effective_window,
                "comparison_window_seconds": effective_window,
                "grouping_dimensions": [
                    "workspace_root",
                    "source_framework",
                    "session_id",
                    "rule_family",
                ],
                "total_cells": len(finalized),
                "cells": finalized[:effective_limit],
                "metric_cell_traceability": _metric_cell_traceability(policy_drift),
            }
        finally:
            _observe_io_metric(self._io_metrics["policy_drift"], time.perf_counter() - start)

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
            records, now_ts=now_ts, window_seconds=60, predicate=self._is_invalid_event_record,
        )
        invalid_5m = self._count_in_window(
            records, now_ts=now_ts, window_seconds=300, predicate=self._is_invalid_event_record,
        )
        invalid_15m = self._count_in_window(
            records, now_ts=now_ts, window_seconds=900, predicate=self._is_invalid_event_record,
        )

        rate_5m = (invalid_5m / total_5m) if total_5m > 0 else 0.0
        rate_15m = (invalid_15m / total_15m) if total_15m > 0 else 0.0

        alerts: list[dict[str, Any]] = []
        if invalid_1m > INVALID_EVENT_COUNT_THRESHOLD_1M:
            alerts.append({
                "metric": "invalid_event_count_1m", "severity": "critical",
                "value": invalid_1m, "threshold": ">20/min",
            })
        if rate_5m > INVALID_EVENT_RATE_CRITICAL_5M:
            alerts.append({
                "metric": "invalid_event_rate_5m", "severity": "critical",
                "value": rate_5m, "threshold": ">1%/5m",
            })
        if total_15m > 0 and INVALID_EVENT_RATE_WARNING_15M_MIN <= rate_15m <= INVALID_EVENT_RATE_WARNING_15M_MAX:
            alerts.append({
                "metric": "invalid_event_rate_15m", "severity": "medium",
                "value": rate_15m, "threshold": "0.1%-1%/15m",
            })

        return {
            "count_1m": invalid_1m, "count_5m": invalid_5m, "count_15m": invalid_15m,
            "rate_5m": rate_5m, "rate_15m": rate_15m, "alerts": alerts,
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
        high_5m = self._count_in_window(records, now_ts=now_ts, window_seconds=300, predicate=self._is_high_risk_record)
        high_15m = self._count_in_window(records, now_ts=now_ts, window_seconds=900, predicate=self._is_high_risk_record)
        high_60m = self._count_in_window(records, now_ts=now_ts, window_seconds=3600, predicate=self._is_high_risk_record)

        prev_5m_high = self._count_in_range(
            records, start_ts=now_ts - 600, end_ts=now_ts - 300, predicate=self._is_high_risk_record,
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
            total_bucket = self._count_in_range(records, start_ts=bucket_start_ts, end_ts=bucket_end_ts)
            high_bucket = self._count_in_range(records, start_ts=bucket_start_ts, end_ts=bucket_end_ts, predicate=self._is_high_risk_record)
            series_5m.append({
                "bucket_start": self._iso_from_ts(bucket_start_ts),
                "bucket_end": self._iso_from_ts(bucket_end_ts),
                "total_count": total_bucket,
                "high_or_critical_count": high_bucket,
                "ratio": ratio(high_bucket, total_bucket),
            })

        return {
            "windows": {
                "5m": {"count": high_5m, "total": total_5m, "ratio": ratio(high_5m, total_5m)},
                "15m": {"count": high_15m, "total": total_15m, "ratio": ratio(high_15m, total_15m)},
                "60m": {"count": high_60m, "total": total_60m, "ratio": ratio(high_60m, total_60m)},
            },
            "direction_5m": direction_5m,
            "series_5m": series_5m,
        }

    @staticmethod
    def _system_posture_level(score_0_100: float) -> str:
        if score_0_100 >= 90:
            return "healthy"
        if score_0_100 >= 70:
            return "guarded"
        if score_0_100 >= 40:
            return "degraded"
        return "critical"

    def _build_system_security_posture(
        self,
        *,
        by_risk_level: dict[str, int],
        invalid_event: dict[str, Any],
        high_risk_trend: dict[str, Any],
        now_ts: float,
        window_seconds: int,
    ) -> dict[str, Any]:
        critical_records = int(by_risk_level.get("critical", 0))
        high_records = int(by_risk_level.get("high", 0))
        trend_15m = high_risk_trend.get("windows", {}).get("15m", {})
        high_risk_ratio_15m = float(trend_15m.get("ratio") or 0.0)
        invalid_event_rate_15m = float(invalid_event.get("rate_15m") or 0.0)

        risk_exposure = min(
            100.0,
            (20.0 * critical_records)
            + (10.0 * high_records)
            + (20.0 * high_risk_ratio_15m)
            + (30.0 * invalid_event_rate_15m),
        )
        score = round(max(0.0, 100.0 - risk_exposure), 2)

        drivers = [
            {
                "metric": "critical_records",
                "value": critical_records,
                "weight": 20.0,
                "contribution": round(20.0 * critical_records, 2),
            },
            {
                "metric": "high_records",
                "value": high_records,
                "weight": 10.0,
                "contribution": round(10.0 * high_records, 2),
            },
            {
                "metric": "high_risk_ratio_15m",
                "value": high_risk_ratio_15m,
                "weight": 20.0,
                "contribution": round(20.0 * high_risk_ratio_15m, 2),
            },
            {
                "metric": "invalid_event_rate_15m",
                "value": invalid_event_rate_15m,
                "weight": 30.0,
                "contribution": round(30.0 * invalid_event_rate_15m, 2),
            },
        ]
        drivers.sort(key=lambda item: item["contribution"], reverse=True)

        return {
            "score_0_100": score,
            "level": self._system_posture_level(score),
            "drivers": drivers,
            "window_seconds": int(window_seconds),
            "generated_at": self._iso_from_ts(now_ts),
        }

    def replay_session(
        self,
        session_id: str,
        limit: int = 100,
        since_seconds: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        start = time.perf_counter()
        try:
            records = self._query_records(session_id=session_id, limit=limit, since_seconds=since_seconds)
            adapter_results = self._adapter_results_for_records(records)
            for record in records:
                event = record.get("event", {})
                key = (event.get("event_id"), event.get("session_id"))
                session_key = (None, event.get("session_id"))
                record["adapter_effect_results"] = (
                    adapter_results.get(key, []) + adapter_results.get(session_key, [])
                )
            return records
        finally:
            _observe_io_metric(self._io_metrics["replay_session"], time.perf_counter() - start)

    def replay_session_page(
        self,
        session_id: str,
        *,
        limit: int = 100,
        cursor: Optional[int] = None,
        since_seconds: Optional[int] = None,
    ) -> dict[str, Any]:
        start = time.perf_counter()
        try:
            effective_limit = min(max(limit, 1), 500)
            records = self._query_records(
                session_id=session_id,
                limit=effective_limit + 1,
                since_seconds=since_seconds,
                before_id=cursor,
            )
            has_more = len(records) > effective_limit
            page_records = records[-effective_limit:] if has_more else records
            adapter_results = self._adapter_results_for_records(page_records)
            for record in page_records:
                event = record.get("event", {})
                key = (event.get("event_id"), event.get("session_id"))
                session_key = (None, event.get("session_id"))
                record["adapter_effect_results"] = (
                    adapter_results.get(key, []) + adapter_results.get(session_key, [])
                )
            next_cursor = page_records[0]["record_id"] if has_more and page_records else None
            return {
                "records": page_records,
                "next_cursor": next_cursor,
            }
        finally:
            _observe_io_metric(self._io_metrics["replay_session_page"], time.perf_counter() - start)

    def clear(self) -> None:
        self._conn.execute("DELETE FROM trajectory_records")
        self._conn.execute("DELETE FROM adapter_effect_results")
        self._conn.execute("DELETE FROM l3_evidence_snapshots")
        self._conn.execute("DELETE FROM l3_advisory_reviews")
        self._conn.execute("DELETE FROM l3_advisory_jobs")
        self._conn.commit()


def _parse_iso_timestamp(value: Optional[str]) -> float:
    """Parse an ISO-8601 timestamp string to a Unix timestamp float."""
    if not value:
        return 0.0
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return 0.0
