"""HTTP API tests for Skill Trust lifecycle operations."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from clawsentry.gateway import server as gateway_server
from clawsentry.gateway.detection_config import DetectionConfig
from clawsentry.gateway.server import SupervisionGateway, create_http_app


def test_api_docs_include_skill_trust_transition_endpoints() -> None:
    repo_root = Path(__file__).resolve().parents[3]
    openapi = json.loads((repo_root / "site-docs" / "api" / "openapi.json").read_text(
        encoding="utf-8"
    ))
    reporting = (repo_root / "site-docs" / "api" / "reporting.md").read_text(
        encoding="utf-8"
    )

    assert "/skill-trust/registry" in openapi["paths"]
    assert "/skill-trust/transition" in openapi["paths"]
    assert "/skill-trust/transition/recommendations" in openapi["paths"]
    assert "GET /skill-trust/registry" in reporting
    assert "POST /skill-trust/transition" in reporting
    assert "GET /skill-trust/transition/recommendations" in reporting
    assert "expected_registry_snapshot_id" in reporting
    assert "idempotency_key" in reporting


def _write_registry(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "clawsentry.skill_registry.v1",
                "records": [
                    {
                        "canonical_skill_id": "skill:docs-reader",
                        "canonical_name": "docs-reader",
                        "source": {"path_hash": "sha256:" + "0" * 64},
                        "trust_level": "trusted",
                        "list_state": "allowlist",
                        "status": "trusted",
                        "policy_fingerprint": "sha256:test-policy",
                    }
                ],
                "transition_events": [],
            }
        ),
        encoding="utf-8",
    )


def _write_registry_with_recommendations(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "clawsentry.skill_registry.v1",
                "records": [
                    {
                        "canonical_skill_id": "skill:docs-reader",
                        "canonical_name": "docs-reader",
                        "source": {
                            "path_hash": "sha256:" + "0" * 64,
                            "metadata_record_id": "meta-docs-reader",
                        },
                        "trust_level": "trusted",
                        "list_state": "greylist",
                        "status": "trusted",
                        "policy_fingerprint": "sha256:test-policy",
                    }
                ],
                "transition_events": [],
                "transition_recommendations": [
                    {
                        "recommendation_id": "fspr-rec-1",
                        "source": "fspr",
                        "canonical_skill_id": "skill:docs-reader",
                        "metadata_record_id": "meta-docs-reader",
                        "session_id": "sess-fspr",
                        "severity": "high",
                        "recommended_state": "blacklist",
                        "evidence_refs": ["fspr://sess-fspr/skill/docs-reader"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_registry_with_expired_disabled_window(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "clawsentry.skill_registry.v1",
                "records": [
                    {
                        "canonical_skill_id": "skill:docs-reader",
                        "canonical_name": "docs-reader",
                        "source": {
                            "path_hash": "sha256:" + "0" * 64,
                            "previous_active_state": "greylist",
                            "disabled_until": "2026-05-18T00:00:00+00:00",
                        },
                        "trust_level": "local_unreviewed",
                        "list_state": "disabled",
                        "status": "local_unreviewed",
                        "policy_fingerprint": "sha256:test-policy",
                    }
                ],
                "transition_events": [],
            }
        ),
        encoding="utf-8",
    )


def _transition_sidecar(path: Path) -> Path:
    return path.with_name(f"{path.name}.transitions.jsonl")


def _sidecar_rows(path: Path) -> list[dict[str, object]]:
    return [
        json.loads(line)
        for line in _transition_sidecar(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.mark.asyncio
async def test_skill_trust_transition_api_requires_snapshot_and_idempotency(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "skill-registry.json"
    _write_registry(registry)
    gateway = SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(skill_trust_registry_path=str(registry)),
    )
    app = create_http_app(gateway)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        missing = await client.post(
            "/skill-trust/transition",
            json={
                "canonical_skill_id": "skill:docs-reader",
                "target_state": "revoked",
                "reason_code": "operator_revoke",
            },
        )
        assert missing.status_code == 400
        assert "expected_registry_snapshot_id" in missing.text
        assert "idempotency_key" in missing.text

        listed = await client.get("/skill-trust/registry")
        assert listed.status_code == 200
        listed_body = listed.json()
        snapshot_id = listed_body["registry_snapshot_id"]
        assert listed_body["records"][0]["skill_trust_grade"] == "trusted"

        changed = await client.post(
            "/skill-trust/transition",
            json={
                "canonical_skill_id": "skill:docs-reader",
                "target_state": "revoked",
                "reason_code": "operator_revoke",
                "expected_registry_snapshot_id": snapshot_id,
                "idempotency_key": "api-revoke-1",
                "operator_id_hash": "sha256:" + "2" * 64,
            },
        )
        assert changed.status_code == 200
        body = changed.json()
        assert body["record"]["list_state"] == "revoked"
        assert body["record"]["skill_trust_grade"] == "blocked"
        assert body["transition_event"]["idempotency_key"] == "api-revoke-1"


@pytest.mark.asyncio
async def test_skill_trust_transition_api_writes_sidecar_transition_log(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "skill-registry.json"
    _write_registry(registry)
    sidecar = _transition_sidecar(registry)
    gateway = SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(skill_trust_registry_path=str(registry)),
    )
    app = create_http_app(gateway)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        listed = await client.get("/skill-trust/registry")
        snapshot_id = listed.json()["registry_snapshot_id"]

        changed = await client.post(
            "/skill-trust/transition",
            json={
                "canonical_skill_id": "skill:docs-reader",
                "target_state": "revoked",
                "reason_code": "operator_revoke",
                "expected_registry_snapshot_id": snapshot_id,
                "idempotency_key": "api-sidecar-revoke-1",
                "operator_id_hash": "sha256:" + "2" * 64,
            },
        )

        assert changed.status_code == 200
        event = changed.json()["transition_event"]
        sidecar_rows = [
            json.loads(line)
            for line in sidecar.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert [row["transition_id"] for row in sidecar_rows] == [event["transition_id"]]
        assert sidecar_rows[0]["idempotency_key"] == "api-sidecar-revoke-1"

        hydrated = await client.get("/skill-trust/registry")
        assert hydrated.status_code == 200
        assert [
            row["transition_id"]
            for row in hydrated.json()["transition_events"]
        ] == [event["transition_id"]]


@pytest.mark.asyncio
async def test_skill_trust_registry_api_consumes_expired_disabled_window(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "skill-registry.json"
    _write_registry_with_expired_disabled_window(registry)
    gateway = SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(skill_trust_registry_path=str(registry)),
    )
    app = create_http_app(gateway)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        listed = await client.get("/skill-trust/registry")

        assert listed.status_code == 200
        body = listed.json()
        assert body["records"][0]["list_state"] == "greylist"
        assert body["transition_events"][-1]["actor_type"] == "system"
        assert body["transition_events"][-1]["reason_code"] == "disabled_window_expired"
        sidecar_rows = _sidecar_rows(registry)
        assert len(sidecar_rows) == 1
        assert sidecar_rows[0]["actor_type"] == "system"
        assert sidecar_rows[0]["reason_code"] == "disabled_window_expired"

        listed_again = await client.get("/skill-trust/registry")
        assert listed_again.status_code == 200
        assert len(_sidecar_rows(registry)) == 1

    persisted = json.loads(registry.read_text(encoding="utf-8"))
    assert persisted["records"][0]["list_state"] == "greylist"
    assert persisted["transition_events"][-1]["to_state"] == "greylist"


@pytest.mark.asyncio
async def test_skill_trust_transition_api_replays_idempotency_key(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "skill-registry.json"
    _write_registry(registry)
    gateway = SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(skill_trust_registry_path=str(registry)),
    )
    app = create_http_app(gateway)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        listed = await client.get("/skill-trust/registry")
        assert listed.status_code == 200
        original_snapshot_id = listed.json()["registry_snapshot_id"]
        request_body = {
            "canonical_skill_id": "skill:docs-reader",
            "target_state": "revoked",
            "reason_code": "operator_revoke",
            "expected_registry_snapshot_id": original_snapshot_id,
            "idempotency_key": "api-revoke-1",
            "operator_id_hash": "sha256:" + "2" * 64,
            "evidence_refs": ["registry://skill/docs-reader"],
        }

        changed = await client.post("/skill-trust/transition", json=request_body)
        assert changed.status_code == 200
        first_body = changed.json()
        assert first_body["idempotent_replay"] is False
        assert len(_sidecar_rows(registry)) == 1

        replay = await client.post("/skill-trust/transition", json=request_body)
        assert replay.status_code == 200
        replay_body = replay.json()
        assert replay_body["idempotent_replay"] is True
        assert (
            replay_body["transition_event"]["transition_id"]
            == first_body["transition_event"]["transition_id"]
        )
        assert replay_body["record"]["list_state"] == "revoked"
        assert len(_sidecar_rows(registry)) == 1

        conflict_body = dict(request_body)
        conflict_body["target_state"] = "blacklist"
        conflict = await client.post("/skill-trust/transition", json=conflict_body)
        assert conflict.status_code == 409
        assert "idempotency key conflict" in conflict.text
        assert len(_sidecar_rows(registry)) == 1

        listed_after = await client.get("/skill-trust/registry")
        assert listed_after.status_code == 200
        assert len(listed_after.json()["transition_events"]) == 1


@pytest.mark.asyncio
async def test_skill_trust_transition_api_override_records_indefinite_reason(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "skill-registry.json"
    _write_registry(registry)
    payload = json.loads(registry.read_text(encoding="utf-8"))
    payload["records"][0]["list_state"] = "blacklist"
    payload["records"][0]["status"] = "quarantined"
    payload["records"][0]["trust_level"] = "untrusted"
    registry.write_text(json.dumps(payload), encoding="utf-8")
    gateway = SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(skill_trust_registry_path=str(registry)),
    )
    app = create_http_app(gateway)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        listed = await client.get("/skill-trust/registry")
        original_snapshot_id = listed.json()["registry_snapshot_id"]
        request_body = {
            "canonical_skill_id": "skill:docs-reader",
            "target_state": "greylist",
            "reason_code": "operator_greylist",
            "expected_registry_snapshot_id": original_snapshot_id,
            "idempotency_key": "api-override-blacklist-greylist-1",
            "operator_id_hash": "sha256:" + "2" * 64,
            "override_id": "operator-override-api-1",
            "override_indefinite_reason": "operator reviewed blacklist downgrade evidence",
        }

        changed = await client.post("/skill-trust/transition", json=request_body)

    assert changed.status_code == 200
    event = changed.json()["transition_event"]
    assert event["override_id"] == "operator-override-api-1"
    assert event["override_indefinite_reason"] == "operator reviewed blacklist downgrade evidence"


@pytest.mark.asyncio
async def test_skill_trust_transition_api_rejects_lost_update_before_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry = tmp_path / "skill-registry.json"
    _write_registry(registry)
    gateway = SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(skill_trust_registry_path=str(registry)),
    )
    app = create_http_app(gateway)
    original_apply = gateway_server.apply_lifecycle_transition
    injected_concurrent_update = False

    def mutate_registry_once(*args, **kwargs):
        nonlocal injected_concurrent_update
        if not injected_concurrent_update:
            injected_concurrent_update = True
            payload = gateway_server._read_skill_trust_registry_payload(registry)
            payload["records"][0]["list_state"] = "greylist"
            payload["transition_events"].append(
                {
                    "transition_id": "external-transition",
                    "registry_snapshot_id": payload["registry_snapshot_id"],
                    "canonical_skill_id": "skill:docs-reader",
                    "from_state": "allowlist",
                    "to_state": "greylist",
                    "reason_code": "external_operator_change",
                    "evidence_hashes": [],
                    "evidence_refs": [],
                    "scope": "workspace",
                    "actor_type": "operator",
                    "policy_fingerprint": "sha256:test-policy",
                }
            )
            gateway_server._write_skill_trust_registry_payload(registry, payload)
        return original_apply(*args, **kwargs)

    monkeypatch.setattr(gateway_server, "apply_lifecycle_transition", mutate_registry_once)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        listed = await client.get("/skill-trust/registry")
        assert listed.status_code == 200
        original_snapshot_id = listed.json()["registry_snapshot_id"]

        changed = await client.post(
            "/skill-trust/transition",
            json={
                "canonical_skill_id": "skill:docs-reader",
                "target_state": "revoked",
                "reason_code": "operator_revoke",
                "expected_registry_snapshot_id": original_snapshot_id,
                "idempotency_key": "api-revoke-race",
                "operator_id_hash": "sha256:" + "2" * 64,
            },
        )

        assert changed.status_code == 409
        assert "registry snapshot conflict" in changed.text
        payload = json.loads(registry.read_text(encoding="utf-8"))
        assert payload["records"][0]["list_state"] == "greylist"
        assert [event["transition_id"] for event in payload["transition_events"]] == [
            "external-transition"
        ]


@pytest.mark.asyncio
async def test_skill_trust_transition_recommendations_api_is_read_only(
    tmp_path: Path,
) -> None:
    registry = tmp_path / "skill-registry.json"
    _write_registry_with_recommendations(registry)
    before = registry.read_text(encoding="utf-8")
    gateway = SupervisionGateway(
        trajectory_db_path=":memory:",
        detection_config=DetectionConfig(skill_trust_registry_path=str(registry)),
    )
    app = create_http_app(gateway)

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        listed = await client.get(
            "/skill-trust/transition/recommendations",
            params={
                "canonical_skill_id": "skill:docs-reader",
                "metadata_record_id": "meta-docs-reader",
                "session_id": "sess-fspr",
                "severity": "high",
                "limit": "1",
            },
        )

        assert listed.status_code == 200
        body = listed.json()
        assert body["recommendations"][0]["recommendation_id"] == "fspr-rec-1"
        assert body["recommendations"][0]["source"] == "fspr"
        assert body["next_cursor"] is None
        assert registry.read_text(encoding="utf-8") == before
