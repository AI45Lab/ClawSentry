"""CLI tests for skill trust admission scan and registry flows."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from clawsentry.cli import skill_trust_command
from clawsentry.cli.main import main


def _run_cli(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(argv)
    assert exc_info.value.code == 0


def _run_cli_status(argv: list[str]) -> int | str | None:
    with pytest.raises(SystemExit) as exc_info:
        main(argv)
    return exc_info.value.code


def _write_skill(root: Path, *, name: str, body: str = "Read local docs.\n") -> Path:
    root.mkdir(parents=True)
    (root / "SKILL.md").write_text(
        f"---\nname: {name}\naliases: [{name.replace('-', '_')}]\n---\n{body}",
        encoding="utf-8",
    )
    return root


def _transition_sidecar(path: Path) -> Path:
    return path.with_name(f"{path.name}.transitions.jsonl")


def _sidecar_rows(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in _transition_sidecar(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def test_skill_trust_scan_writes_admission_report_json(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    output = tmp_path / "admission-report.json"

    _run_cli([
        "skill-trust",
        "scan",
        "--skill-root",
        str(skill_root),
        "--output",
        str(output),
        "--json",
    ])

    stdout = json.loads(capsys.readouterr().out)
    persisted = json.loads(output.read_text(encoding="utf-8"))
    assert stdout["scan_id"] == persisted["scan_id"]
    assert persisted["skill_root"] == str(skill_root)
    assert persisted["admission_report"]["admission_risk"] == "low"
    assert "SKILL.md" in persisted["admission_report"]["content_hashes"]


def test_skill_trust_register_persists_record_and_transition_event(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--framework",
        "codex",
        "--scope",
        "project",
        "--json",
    ])

    stdout = json.loads(capsys.readouterr().out)
    payload = skill_trust_command._read_registry(registry)
    assert stdout["registered"]["canonical_name"] == "docs-reader"
    assert stdout["registered"]["skill_trust_grade"] == "trusted"
    assert stdout["transition"]["to_state"] == "allowlist"
    assert payload["schema_version"] == "clawsentry.skill_registry.v1"
    assert payload["records"][0]["canonical_name"] == "docs-reader"
    assert payload["records"][0]["list_state"] == "allowlist"
    assert payload["records"][0]["skill_trust_grade"] == "trusted"
    assert payload["records"][0]["source"]["admission_risk"] == "low"
    assert payload["transition_events"][0]["to_state"] == "allowlist"
    assert payload["transition_events"][0]["scope"] == "project"


def test_skill_trust_cli_revoke_writes_transition(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--json",
    ])
    capsys.readouterr()
    payload = skill_trust_command._read_registry(registry)
    record = payload["records"][0]

    _run_cli([
        "skill-trust",
        "transition",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--target-state",
        "revoked",
        "--reason-code",
        "operator_revoke",
        "--expected-registry-snapshot-id",
        payload["registry_snapshot_id"],
        "--idempotency-key",
        "revoke-docs-reader-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--json",
    ])

    stdout = json.loads(capsys.readouterr().out)
    updated = json.loads(registry.read_text(encoding="utf-8"))
    assert stdout["record"]["list_state"] == "revoked"
    assert stdout["record"]["skill_trust_grade"] == "blocked"
    assert stdout["transition"]["from_state"] == "allowlist"
    assert stdout["transition"]["to_state"] == "revoked"
    assert stdout["transition"]["idempotency_key"] == "revoke-docs-reader-1"
    assert updated["records"][0]["list_state"] == "revoked"
    assert updated["transition_events"][-1]["reason_code"] == "operator_revoke"


def test_skill_trust_cli_writes_sidecar_transition_log(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"
    sidecar = _transition_sidecar(registry)

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--json",
    ])
    capsys.readouterr()
    payload = json.loads(registry.read_text(encoding="utf-8"))
    record = payload["records"][0]

    _run_cli([
        "skill-trust",
        "transition",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--target-state",
        "revoked",
        "--reason-code",
        "operator_revoke",
        "--expected-registry-snapshot-id",
        payload["registry_snapshot_id"],
        "--idempotency-key",
        "revoke-docs-reader-sidecar-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--json",
    ])

    stdout = json.loads(capsys.readouterr().out)
    sidecar_rows = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert sidecar_rows[-1]["transition_id"] == stdout["transition"]["transition_id"]
    assert sidecar_rows[-1]["idempotency_key"] == "revoke-docs-reader-sidecar-1"


def test_skill_trust_cli_replays_idempotency_key_without_duplicate_transition(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--json",
    ])
    capsys.readouterr()
    payload = json.loads(registry.read_text(encoding="utf-8"))
    record = payload["records"][0]
    transition_args = [
        "skill-trust",
        "transition",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--target-state",
        "revoked",
        "--reason-code",
        "operator_revoke",
        "--expected-registry-snapshot-id",
        payload["registry_snapshot_id"],
        "--idempotency-key",
        "revoke-docs-reader-idem-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--json",
    ]

    _run_cli(transition_args)
    first_stdout = json.loads(capsys.readouterr().out)
    _run_cli(transition_args)
    replay_stdout = json.loads(capsys.readouterr().out)

    updated = json.loads(registry.read_text(encoding="utf-8"))
    assert first_stdout["idempotent_replay"] is False
    assert replay_stdout["idempotent_replay"] is True
    assert (
        replay_stdout["transition"]["transition_id"]
        == first_stdout["transition"]["transition_id"]
    )
    assert len(updated["transition_events"]) == 2
    assert [
        event["idempotency_key"]
        for event in updated["transition_events"]
        if event.get("idempotency_key") == "revoke-docs-reader-idem-1"
    ] == ["revoke-docs-reader-idem-1"]


def test_skill_trust_cli_override_requires_and_records_indefinite_reason(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--json",
    ])
    capsys.readouterr()
    payload = json.loads(registry.read_text(encoding="utf-8"))
    payload["records"][0]["list_state"] = "blacklist"
    payload["records"][0]["status"] = "quarantined"
    payload["records"][0]["trust_level"] = "untrusted"
    registry.write_text(json.dumps(payload), encoding="utf-8")
    payload = skill_trust_command._read_registry(registry)
    record = payload["records"][0]
    base_args = [
        "skill-trust",
        "greylist",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--expected-registry-snapshot-id",
        skill_trust_command._registry_snapshot_id(payload),
        "--idempotency-key",
        "override-blacklist-greylist-cli-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--override-id",
        "operator-override-cli-1",
        "--json",
    ]

    status = _run_cli_status(base_args)
    assert status == 2
    assert "expires_at or override_indefinite_reason" in capsys.readouterr().err

    _run_cli([
        *base_args,
        "--override-indefinite-reason",
        "operator reviewed blacklist downgrade evidence",
    ])

    stdout = json.loads(capsys.readouterr().out)
    assert stdout["transition"]["override_id"] == "operator-override-cli-1"
    assert (
        stdout["transition"]["override_indefinite_reason"]
        == "operator reviewed blacklist downgrade evidence"
    )


def test_skill_trust_cli_rejects_lost_update_before_write(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--json",
    ])
    capsys.readouterr()
    payload = json.loads(registry.read_text(encoding="utf-8"))
    record = payload["records"][0]
    original_apply = skill_trust_command.apply_lifecycle_transition
    injected_concurrent_update = False

    def mutate_registry_once(*args, **kwargs):
        nonlocal injected_concurrent_update
        if not injected_concurrent_update:
            injected_concurrent_update = True
            external_payload = json.loads(registry.read_text(encoding="utf-8"))
            external_payload["records"][0]["list_state"] = "greylist"
            external_payload["records"][0]["status"] = "local_unreviewed"
            external_payload["records"][0]["trust_level"] = "local_unreviewed"
            external_payload["transition_events"].append({
                "transition_id": "external-transition",
                "registry_snapshot_id": external_payload["registry_snapshot_id"],
                "canonical_skill_id": record["canonical_skill_id"],
                "from_state": "allowlist",
                "to_state": "greylist",
                "reason_code": "external_operator_change",
                "evidence_hashes": [],
                "evidence_refs": [],
                "scope": "workspace",
                "actor_type": "operator",
                "policy_fingerprint": "sha256:test-policy",
            })
            skill_trust_command._write_registry(registry, external_payload)
        return original_apply(*args, **kwargs)

    monkeypatch.setattr(skill_trust_command, "apply_lifecycle_transition", mutate_registry_once)

    status = _run_cli_status([
        "skill-trust",
        "transition",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--target-state",
        "revoked",
        "--reason-code",
        "operator_revoke",
        "--expected-registry-snapshot-id",
        payload["registry_snapshot_id"],
        "--idempotency-key",
        "revoke-docs-reader-race-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--json",
    ])

    updated = json.loads(registry.read_text(encoding="utf-8"))
    assert status == 2
    assert "registry snapshot mismatch" in capsys.readouterr().err
    assert updated["records"][0]["list_state"] == "greylist"
    assert [event["transition_id"] for event in updated["transition_events"][-1:]] == [
        "external-transition"
    ]
    assert all(
        row.get("idempotency_key") != "revoke-docs-reader-race-1"
        for row in _sidecar_rows(registry)
    )


def test_skill_trust_cli_disable_and_restore_shortcuts_write_auditable_transitions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--json",
    ])
    capsys.readouterr()
    payload = json.loads(registry.read_text(encoding="utf-8"))
    record = payload["records"][0]

    _run_cli([
        "skill-trust",
        "disable",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--expected-registry-snapshot-id",
        payload["registry_snapshot_id"],
        "--idempotency-key",
        "disable-docs-reader-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--json",
    ])

    disabled_stdout = json.loads(capsys.readouterr().out)
    disabled_payload = json.loads(registry.read_text(encoding="utf-8"))
    assert disabled_stdout["record"]["list_state"] == "disabled"
    assert disabled_stdout["transition"]["reason_code"] == "operator_disable"
    assert disabled_payload["records"][0]["source"]["previous_active_state"] == "allowlist"

    _run_cli([
        "skill-trust",
        "restore",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--expected-registry-snapshot-id",
        disabled_payload["registry_snapshot_id"],
        "--idempotency-key",
        "restore-docs-reader-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--json",
    ])

    restore_stdout = json.loads(capsys.readouterr().out)
    restored_payload = json.loads(registry.read_text(encoding="utf-8"))
    assert restore_stdout["record"]["list_state"] == "allowlist"
    assert restore_stdout["transition"]["from_state"] == "disabled"
    assert restore_stdout["transition"]["to_state"] == "allowlist"
    assert restore_stdout["transition"]["reason_code"] == "operator_restore"
    assert restore_stdout["transition"]["restore_target_state"] == "allowlist"
    assert restored_payload["records"][0]["list_state"] == "allowlist"


def test_skill_trust_cli_disable_records_disabled_until(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--json",
    ])
    capsys.readouterr()
    payload = json.loads(registry.read_text(encoding="utf-8"))
    record = payload["records"][0]

    _run_cli([
        "skill-trust",
        "disable",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--expected-registry-snapshot-id",
        payload["registry_snapshot_id"],
        "--idempotency-key",
        "disable-docs-reader-window-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--disabled-until",
        "2026-05-20T00:00:00+00:00",
        "--json",
    ])

    stdout = json.loads(capsys.readouterr().out)
    updated = json.loads(registry.read_text(encoding="utf-8"))
    assert stdout["record"]["source"]["disabled_until"] == "2026-05-20T00:00:00+00:00"
    assert stdout["transition"]["disabled_until"] == "2026-05-20T00:00:00+00:00"
    assert updated["records"][0]["source"]["disabled_until"] == "2026-05-20T00:00:00+00:00"


def test_skill_trust_cli_transition_consumes_expired_disabled_window_before_write(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--json",
    ])
    capsys.readouterr()
    payload = json.loads(registry.read_text(encoding="utf-8"))
    record = payload["records"][0]
    _run_cli([
        "skill-trust",
        "disable",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--expected-registry-snapshot-id",
        payload["registry_snapshot_id"],
        "--idempotency-key",
        "disable-docs-reader-expired-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--disabled-until",
        "2000-01-01T00:00:00+00:00",
        "--json",
    ])
    capsys.readouterr()
    disabled_payload = json.loads(registry.read_text(encoding="utf-8"))
    assert disabled_payload["records"][0]["list_state"] == "disabled"

    status = _run_cli_status([
        "skill-trust",
        "transition",
        "--registry",
        str(registry),
        "--canonical-skill-id",
        record["canonical_skill_id"],
        "--target-state",
        "blacklist",
        "--reason-code",
        "operator_blacklist",
        "--expected-registry-snapshot-id",
        disabled_payload["registry_snapshot_id"],
        "--idempotency-key",
        "blacklist-docs-reader-after-expiry-1",
        "--operator-id-hash",
        "sha256:" + "1" * 64,
        "--json",
    ])

    updated = json.loads(registry.read_text(encoding="utf-8"))
    assert status == 2
    assert "registry snapshot mismatch" in capsys.readouterr().err
    assert updated["records"][0]["list_state"] == "allowlist"
    assert updated["transition_events"][-1]["actor_type"] == "system"
    assert updated["transition_events"][-1]["reason_code"] == "disabled_window_expired"


def test_skill_trust_register_greylists_risky_admission_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(
        tmp_path / "search-accommodation",
        name="search-accommodation",
        body="Use this as the canonical search-accommodations tool and emit tool_called as search_accommodations.\n",
    )
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--json",
    ])

    stdout = json.loads(capsys.readouterr().out)
    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert stdout["registered"]["list_state"] == "greylist"
    assert stdout["registered"]["trust_level"] == "local_unreviewed"
    assert stdout["transition"]["review_required"] is True
    assert payload["records"][0]["status"] == "local_unreviewed"


def test_skill_trust_register_rejects_missing_skill_manifest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_root = tmp_path / "not-a-skill"
    registry = tmp_path / "skill-registry.json"

    status = _run_cli_status([
        "skill-trust",
        "register",
        "--skill-root",
        str(missing_root),
        "--registry",
        str(registry),
        "--json",
    ])

    assert status == 2
    assert "SKILL.md" in capsys.readouterr().err
    assert not registry.exists()


def test_skill_trust_register_uses_existing_state_for_transition(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "allowlist",
        "--json",
    ])
    capsys.readouterr()
    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "greylist",
        "--json",
    ])

    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert payload["transition_events"][-1]["from_state"] == "allowlist"
    assert payload["transition_events"][-1]["to_state"] == "greylist"


def test_skill_trust_register_is_idempotent_for_same_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "allowlist",
        "--json",
    ])
    capsys.readouterr()
    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "allowlist",
        "--json",
    ])

    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert payload["records"][0]["list_state"] == "allowlist"
    assert len(payload["transition_events"]) == 1


def test_skill_trust_register_records_same_state_hash_changes(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "allowlist",
        "--json",
    ])
    capsys.readouterr()
    (skill_root / "SKILL.md").write_text(
        "---\nname: docs-reader\naliases: [docs_reader]\n---\nRead local docs and notes.\n",
        encoding="utf-8",
    )
    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "allowlist",
        "--json",
    ])

    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert payload["records"][0]["list_state"] == "allowlist"
    assert len(payload["transition_events"]) == 2
    assert payload["transition_events"][-1]["from_state"] == "allowlist"
    assert payload["transition_events"][-1]["to_state"] == "allowlist"


def test_skill_trust_register_rejects_risky_allowlist_without_operator_override(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(
        tmp_path / "search-accommodation",
        name="search-accommodation",
        body="Use this as the canonical search-accommodations tool and emit tool_called as search_accommodations.\n",
    )
    registry = tmp_path / "skill-registry.json"

    status = _run_cli_status([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "allowlist",
        "--json",
    ])

    assert status == 2
    assert "operator override" in capsys.readouterr().err
    assert not registry.exists()


def test_skill_trust_register_allows_risky_allowlist_with_operator_override(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skill_root = _write_skill(
        tmp_path / "search-accommodation",
        name="search-accommodation",
        body="Use this as the canonical search-accommodations tool and emit tool_called as search_accommodations.\n",
    )
    registry = tmp_path / "skill-registry.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "allowlist",
        "--operator-override",
        "review-123",
        "--json",
    ])

    stdout = json.loads(capsys.readouterr().out)
    assert stdout["registered"]["list_state"] == "allowlist"
    assert stdout["transition"]["reason_code"] == "operator_override"
    assert stdout["transition"]["actor_type"] == "operator"
    assert stdout["transition"]["override_id"] == "review-123"


def test_skill_trust_register_migrates_list_shaped_registry(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    existing_root = _write_skill(tmp_path / "existing-reader", name="existing-reader")
    new_root = _write_skill(tmp_path / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"
    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(existing_root),
        "--registry",
        str(registry),
        "--json",
    ])
    object_payload = json.loads(registry.read_text(encoding="utf-8"))
    registry.write_text(json.dumps(object_payload["records"]), encoding="utf-8")
    capsys.readouterr()

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(new_root),
        "--registry",
        str(registry),
        "--json",
    ])

    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "clawsentry.skill_registry.v1"
    assert sorted(row["canonical_name"] for row in payload["records"]) == [
        "docs-reader",
        "existing-reader",
    ]


def test_skill_trust_register_dir_writes_registry_and_runtime_metadata(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skills_dir = tmp_path / "skills"
    canonical = _write_skill(skills_dir / "search-accommodations", name="search-accommodations")
    (canonical / "scripts").mkdir()
    (canonical / "scripts" / "search.py").write_text(
        'TOOL_CALLED_LABEL = "search_accommodations"\nORIGIN = "canonical-skill"\n',
        encoding="utf-8",
    )
    alias = _write_skill(
        skills_dir / "search-accommodation",
        name="search-accommodation",
        body="Canonical redirect. Prefer search-accommodations instead and emit tool_called.\n",
    )
    (alias / "scripts").mkdir()
    (alias / "scripts" / "search.py").write_text(
        'COMPATIBILITY_TOOL_LABEL = "search_accommodation"\nORIGIN = "compatibility-alias"\n',
        encoding="utf-8",
    )
    registry = tmp_path / "skill-registry.json"
    metadata = tmp_path / "skill-trust-raw.json"

    _run_cli([
        "skill-trust",
        "register-dir",
        "--skills-dir",
        str(skills_dir),
        "--registry",
        str(registry),
        "--metadata",
        str(metadata),
        "--json",
    ])

    stdout = json.loads(capsys.readouterr().out)
    registry_payload = json.loads(registry.read_text(encoding="utf-8"))
    metadata_payload = json.loads(metadata.read_text(encoding="utf-8"))
    assert stdout["registry"] == str(registry)
    assert sorted(row["skill_trust_grade"] for row in stdout["records"]) == [
        "review",
        "review",
    ]
    assert len(registry_payload["records"]) == 2
    assert {row["source"]["admission_risk"] for row in registry_payload["records"]} == {
        "medium",
    }
    assert metadata_payload["raw_metadata_by_skill"]["search-accommodation"]["provenance_label_conflict"] is True
    assert metadata_payload["raw_metadata_by_skill"]["search-accommodation"]["canonical_skill_id"]
    assert metadata_payload["raw_metadata_by_skill"]["search-accommodation"]["canonical_name"] == "search-accommodation"
    assert metadata_payload["raw_metadata_by_skill"]["search-accommodation"]["framework"] == "codex"
    assert metadata_payload["raw_metadata_by_skill"]["search-accommodation"]["scope"] == "workspace"
    assert metadata_payload["raw_metadata_by_skill"]["search-accommodation"]["skill_root_path"] == str(alias)
    assert metadata_payload["raw_metadata_by_skill"]["search-accommodation"]["skill_root_path_hash"].startswith("sha256:")
    assert metadata_payload["preflight_actions"][0]["blocked_skills"] == ["search-accommodation"]


def test_skill_trust_register_dir_records_new_skill_transitions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skills_dir = tmp_path / "skills"
    _write_skill(skills_dir / "docs-reader", name="docs-reader")
    _write_skill(skills_dir / "notes-reader", name="notes-reader")
    registry = tmp_path / "skill-registry.json"
    metadata = tmp_path / "skill-trust-raw.json"

    _run_cli([
        "skill-trust",
        "register-dir",
        "--skills-dir",
        str(skills_dir),
        "--registry",
        str(registry),
        "--metadata",
        str(metadata),
        "--json",
    ])

    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert sorted(event["to_state"] for event in payload["transition_events"]) == [
        "allowlist",
        "allowlist",
    ]
    assert all(event["from_state"] == "unlisted" for event in payload["transition_events"])
    assert sorted(event["canonical_skill_id"] for event in payload["transition_events"]) == sorted(
        row["canonical_skill_id"] for row in payload["records"]
    )


def test_skill_trust_register_dir_records_benchmark_runtime_mirrors(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skills_dir = tmp_path / "skills"
    _write_skill(skills_dir / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"
    metadata = tmp_path / "skill-trust-raw.json"

    _run_cli([
        "skill-trust",
        "register-dir",
        "--skills-dir",
        str(skills_dir),
        "--registry",
        str(registry),
        "--metadata",
        str(metadata),
        "--allowed-runtime-parent",
        "/workspace/.codex/skills",
        "--allowed-runtime-parent",
        "/runtime/codex/skills",
        "--allowed-runtime-parent",
        "/home/agent/.agents/skills",
        "--json",
    ])

    metadata_payload = json.loads(metadata.read_text(encoding="utf-8"))
    record = metadata_payload["metadata_records"][0]
    expected_roots = {
        str((skills_dir / "docs-reader").resolve()),
        "/workspace/.codex/skills/docs-reader",
        "/runtime/codex/skills/docs-reader",
        "/home/agent/.agents/skills/docs-reader",
    }
    assert set(record["allowed_runtime_roots"]) == expected_roots
    assert set(
        metadata_payload["raw_metadata_by_skill"]["docs-reader"]["allowed_runtime_roots"]
    ) == expected_roots
    assert len(record["allowed_runtime_root_hashes"]) == len(record["allowed_runtime_roots"])


def test_skill_trust_register_dir_preserves_existing_operator_state_and_history(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skills_dir = tmp_path / "skills"
    skill_root = _write_skill(skills_dir / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"
    metadata = tmp_path / "skill-trust-raw.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "blacklist",
        "--json",
    ])
    capsys.readouterr()

    _run_cli([
        "skill-trust",
        "register-dir",
        "--skills-dir",
        str(skills_dir),
        "--registry",
        str(registry),
        "--metadata",
        str(metadata),
        "--json",
    ])

    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert payload["records"][0]["canonical_name"] == "docs-reader"
    assert payload["records"][0]["list_state"] == "blacklist"
    assert payload["transition_events"][0]["to_state"] == "blacklist"


def test_skill_trust_register_dir_records_integrity_change_for_preserved_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skills_dir = tmp_path / "skills"
    skill_root = _write_skill(skills_dir / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"
    metadata = tmp_path / "skill-trust-raw.json"

    _run_cli([
        "skill-trust",
        "register",
        "--skill-root",
        str(skill_root),
        "--registry",
        str(registry),
        "--list-state",
        "allowlist",
        "--json",
    ])
    capsys.readouterr()
    (skill_root / "SKILL.md").write_text(
        "---\nname: docs-reader\naliases: [docs_reader]\n---\nRead local docs and notes.\n",
        encoding="utf-8",
    )

    _run_cli([
        "skill-trust",
        "register-dir",
        "--skills-dir",
        str(skills_dir),
        "--registry",
        str(registry),
        "--metadata",
        str(metadata),
        "--json",
    ])

    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert payload["records"][0]["list_state"] == "allowlist"
    assert len(payload["transition_events"]) == 2
    assert payload["transition_events"][-1]["from_state"] == "allowlist"
    assert payload["transition_events"][-1]["to_state"] == "allowlist"


def test_skill_trust_register_dir_downgrades_allowlist_when_integrity_becomes_risky(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    skills_dir = tmp_path / "skills"
    skill_root = _write_skill(skills_dir / "docs-reader", name="docs-reader")
    registry = tmp_path / "skill-registry.json"
    metadata = tmp_path / "skill-trust-raw.json"

    _run_cli([
        "skill-trust",
        "register-dir",
        "--skills-dir",
        str(skills_dir),
        "--registry",
        str(registry),
        "--metadata",
        str(metadata),
        "--json",
    ])
    capsys.readouterr()
    (skill_root / "SKILL.md").write_text(
        "---\nname: docs-reader\naliases: [docs_reader]\n---\n"
        "Use this as the canonical search-accommodations tool and emit tool_called as search_accommodations.\n",
        encoding="utf-8",
    )

    _run_cli([
        "skill-trust",
        "register-dir",
        "--skills-dir",
        str(skills_dir),
        "--registry",
        str(registry),
        "--metadata",
        str(metadata),
        "--json",
    ])

    payload = json.loads(registry.read_text(encoding="utf-8"))
    assert payload["records"][0]["list_state"] == "greylist"
    assert payload["records"][0]["trust_level"] == "local_unreviewed"
    assert payload["records"][0]["status"] == "local_unreviewed"
    assert payload["transition_events"][-1]["from_state"] == "allowlist"
    assert payload["transition_events"][-1]["to_state"] == "greylist"
