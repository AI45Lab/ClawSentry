"""Deterministic session-scope validation and preview commands."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ..gateway.models import CanonicalEvent, DecisionContext, SessionScopeProfile
from ..gateway.session_scope import evaluate_session_scope, scope_protection_statement
from ..gateway.tool_permissions import resolve_tool_permission


def run_scope_validate(*, profile_path: Path, json_mode: bool = False) -> int:
    """Validate a scope profile file and print a user-facing summary."""

    try:
        profile = _load_profile(profile_path)
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        print(f"scope profile validation failed: {exc}", file=sys.stderr)
        return 1

    payload = _profile_summary(profile)
    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"Scope profile {profile.profile_id}: valid")
    print(f"  source: {profile.source.value}")
    print(f"  dry_run: {profile.dry_run}")
    print(f"  confirmed: {profile.confirmed}")
    print(f"  enforced: {payload['enforced']}")
    print(f"  {payload['protection_statement']}")
    return 0


def run_scope_preview(
    *,
    profile_path: Path,
    event_path: Path,
    confirm: bool = False,
    json_mode: bool = False,
) -> int:
    """Preview how a profile evaluates one canonical event."""

    try:
        profile = _load_profile(profile_path)
        if confirm:
            profile = profile.model_copy(update={"confirmed": True, "dry_run": False})
        event = _load_event(event_path)
        evaluation = evaluate_session_scope(
            event,
            DecisionContext(session_scope_profile=profile),
        )
    except (OSError, json.JSONDecodeError, ValidationError, ValueError) as exc:
        print(f"scope preview failed: {exc}", file=sys.stderr)
        return 1

    summary = evaluation.summary().model_dump(mode="json") if evaluation else None
    enforced = bool(summary and summary.get("enforced"))
    payload = {
        "valid": True,
        "mode": "enforced" if enforced else "dry_run_only",
        "profile": _profile_summary(profile),
        "scope_evaluation": summary,
        "tool_permission": resolve_tool_permission(
            event.tool_name,
            session_state="critical" if profile.confirmed and not profile.dry_run else "baseline",
        ).to_dict(),
        "protection_statement": scope_protection_statement(enforced=enforced),
    }
    if json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"Scope preview for {profile.profile_id}: {payload['mode']}")
    if summary:
        print(f"  verdict: {summary['verdict']}")
        print(f"  enforced: {summary['enforced']}")
        for reason in summary.get("reason_codes") or []:
            print(f"  - {reason}")
    permission = payload["tool_permission"]
    print(f"  tool group: {permission['group']} ({permission['action']})")
    print(f"  {payload['protection_statement']}")
    return 0


def _load_profile(path: Path) -> SessionScopeProfile:
    return SessionScopeProfile.model_validate(_read_json(path))


def _load_event(path: Path) -> CanonicalEvent:
    return CanonicalEvent.model_validate(_read_json(path))


def _read_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _profile_summary(profile: SessionScopeProfile) -> dict[str, Any]:
    enforced = bool(profile.confirmed and not profile.dry_run)
    return {
        "valid": True,
        "profile_id": profile.profile_id,
        "source": profile.source.value,
        "confirmed": profile.confirmed,
        "dry_run": profile.dry_run,
        "enforced": enforced,
        "protection_statement": scope_protection_statement(enforced=enforced),
    }
