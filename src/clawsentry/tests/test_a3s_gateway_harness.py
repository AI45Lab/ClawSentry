"""Tests for standard a3s-code gateway bridge harness (P1-2)."""

import asyncio
import io
import json
import os
import sys
import time
import pytest
import pytest_asyncio
from clawsentry.adapters.a3s_adapter import A3SCodeAdapter
from clawsentry.gateway.models import (
    AgentTrustLevel,
    CanonicalDecision,
    DecisionSource,
    DecisionVerdict,
    EventType,
    RiskLevel,
    SkillRegistryRecord,
)
from clawsentry.gateway.detection_config import DetectionConfig
from clawsentry.gateway.server import SupervisionGateway, start_uds_server
from clawsentry.adapters.a3s_gateway_harness import (
    A3SGatewayHarness,
    _codex_runtime_skill_refs_from_payload,
)


TEST_UDS_PATH = "/tmp/ahp-a3s-harness-test.sock"


def test_codex_runtime_refs_extract_explicit_skill_path():
    refs = _codex_runtime_skill_refs_from_payload(
        {
            "arguments": {
                "command": "python /tmp/workspace/.codex/skills/search-accommodation/scripts/run.py"
            }
        },
        known_skill_names=None,
    )

    assert len(refs) == 1
    ref = refs[0]
    assert ref.ref_ordinal == 0
    assert ref.name == "search-accommodation"
    assert ref.runtime_root == "/tmp/workspace/.codex/skills/search-accommodation"
    assert ref.runtime_path == "/tmp/workspace/.codex/skills/search-accommodation/scripts/run.py"
    assert ref.observed_runtime_root_path_hash
    assert ref.evidence_kind == "shell_skill_path"
    assert ref.confidence == "high"


def test_codex_runtime_refs_preserve_multi_ref_order():
    refs = _codex_runtime_skill_refs_from_payload(
        {
            "arguments": {
                "command": (
                    "python /tmp/workspace/.codex/skills/first-skill/scripts/run.py && "
                    "python /tmp/workspace/.codex/skills/second-skill/scripts/run.py"
                )
            }
        },
        known_skill_names=None,
    )

    assert [ref.ref_ordinal for ref in refs] == [0, 1]
    assert [ref.name for ref in refs] == ["first-skill", "second-skill"]


def test_codex_runtime_refs_ignore_comments_and_heredocs():
    refs = _codex_runtime_skill_refs_from_payload(
        {
            "arguments": {
                "command": (
                    "# python /tmp/workspace/.codex/skills/comment-skill/scripts/run.py\n"
                    "cat <<'EOF'\n"
                    "python /tmp/workspace/.codex/skills/heredoc-skill/scripts/run.py\n"
                    "EOF\n"
                    "echo done"
                )
            }
        },
        known_skill_names=None,
    )

    assert refs == []


def test_codex_runtime_refs_mark_dynamic_execution_unverified():
    refs = _codex_runtime_skill_refs_from_payload(
        {
            "arguments": {
                "command": "bash -c 'python $CODEX_HOME/skills/search-accommodation/scripts/run.py'"
            }
        },
        known_skill_names={"search-accommodation"},
    )

    assert len(refs) == 1
    ref = refs[0]
    assert ref.name == "search-accommodation"
    assert ref.runtime_root is None
    assert ref.runtime_path is None
    assert ref.evidence_kind == "dynamic_execution"
    assert ref.confidence == "low"


def test_codex_runtime_refs_resolve_cd_relative_skill_execution():
    refs = _codex_runtime_skill_refs_from_payload(
        {
            "arguments": {
                "cwd": "/tmp/workspace/.codex",
                "command": "cd skills/search-accommodation && python scripts/run.py",
            }
        },
        known_skill_names=None,
    )

    assert len(refs) == 1
    ref = refs[0]
    assert ref.name == "search-accommodation"
    assert ref.runtime_root == "/tmp/workspace/.codex/skills/search-accommodation"
    assert ref.runtime_path == "/tmp/workspace/.codex/skills/search-accommodation/scripts/run.py"
    assert ref.evidence_kind == "shell_skill_path"
    assert ref.confidence == "high"


def _skill_record(name: str) -> SkillRegistryRecord:
    return SkillRegistryRecord(
        canonical_skill_id=f"skill:{name}",
        canonical_name=name,
        aliases=[name.replace("-", "_")],
        content_hashes={"SKILL.md": f"sha256:{name}:skill", "scripts": f"sha256:{name}:scripts"},
        source={"framework": "gemini-cli", "path_hash": f"sha256:{name}:path"},
        trust_level="trusted",
        admission_scan_id=f"scan-{name}",
        policy_fingerprint="sha256:policy",
        status="trusted",
        list_state="allowlist",
    )


@pytest_asyncio.fixture
async def harness_with_gateway():
    gw = SupervisionGateway()
    server = await start_uds_server(gw, TEST_UDS_PATH)
    adapter = A3SCodeAdapter(uds_path=TEST_UDS_PATH, default_deadline_ms=500)
    harness = A3SGatewayHarness(adapter=adapter)
    yield harness
    server.close()
    await server.wait_closed()
    if os.path.exists(TEST_UDS_PATH):
        os.unlink(TEST_UDS_PATH)


@pytest.mark.asyncio
async def test_handshake_returns_capabilities(harness_with_gateway):
    resp = await harness_with_gateway.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ahp/handshake",
            "params": {"protocol_version": "2.0"},
        }
    )

    assert resp is not None
    assert resp["id"] == 1
    assert resp["result"]["protocol_version"] == "2.0"
    assert "pre_action" in resp["result"]["harness_info"]["capabilities"]
    assert "post_response" in resp["result"]["harness_info"]["capabilities"]
    assert "confirmation" in resp["result"]["harness_info"]["capabilities"]
    assert "context_perception" in resp["result"]["harness_info"]["capabilities"]
    assert "memory_recall" in resp["result"]["harness_info"]["capabilities"]
    assert "planning" in resp["result"]["harness_info"]["capabilities"]
    assert "reasoning" in resp["result"]["harness_info"]["capabilities"]
    assert "intent_detection" in resp["result"]["harness_info"]["capabilities"]


@pytest.mark.asyncio
async def test_agent_safety_feedback_response_delivery_for_supported_harness(tmp_path):
    uds_path = str(tmp_path / "a3s-feedback.sock")
    gw = SupervisionGateway(
        detection_config=DetectionConfig(agent_safety_feedback_enabled=True)
    )
    server = await start_uds_server(gw, uds_path)
    adapter = A3SCodeAdapter(uds_path=uds_path, default_deadline_ms=1000)
    harness = A3SGatewayHarness(adapter=adapter)
    try:
        resp = await harness.dispatch_async(
            {
                "jsonrpc": "2.0",
                "id": 201,
                "method": "ahp/event",
                "params": {
                    "event_type": "pre_action",
                    "session_id": "sess-a3s-feedback",
                    "agent_id": "agent-a3s-feedback",
                    "tool_name": "bash",
                    "payload": {
                        "tool_name": "bash",
                        "command": "rm -rf /tmp/clawsentry-a3s-feedback-target",
                    },
                },
            }
        )
    finally:
        server.close()
        await server.wait_closed()

    assert resp is not None
    result = resp["result"]
    assert result["decision"] == "block"
    feedback = result["metadata"]["agent_safety_feedback"]
    assert feedback["schema"] == "clawsentry.agent_safety_feedback.v1"
    assert feedback["delivery"] == "response"
    assert feedback["blocked_surface"] == "command"
    assert "rm -rf" not in json.dumps(feedback)
    assert "/tmp/clawsentry-a3s-feedback-target" not in json.dumps(feedback)


@pytest.mark.asyncio
async def test_jsonrpc_post_response_literal_normalizes_to_post_response():
    from unittest.mock import AsyncMock

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="post_response is observation-only",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "ahp/event",
            "params": {
                "event_type": "post_response",
                "session_id": "sess-post-response",
                "agent_id": "agent-post-response",
                "payload": {
                    "response_text": "done",
                    "tool_calls_count": 0,
                    "duration_ms": 12,
                },
            },
        }
    )

    assert resp is not None
    assert resp["result"]["decision"] == "allow"
    assert resp["result"]["action"] == "continue"

    event = adapter.request_decision.await_args.args[0]
    assert event.event_type == EventType.POST_RESPONSE
    assert event.framework_meta is not None
    assert event.framework_meta.normalization is not None
    assert event.framework_meta.normalization.raw_event_type == "PostResponse"


@pytest.mark.asyncio
async def test_claude_native_user_prompt_submit_routes_as_pre_prompt():
    from unittest.mock import AsyncMock

    adapter = A3SCodeAdapter(
        uds_path="/tmp/nonexistent-a3s-harness.sock",
        source_framework="claude-code",
    )
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="prompt allowed",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    response = await harness.dispatch_async(
        {
            "session_id": "sess-claude-prompt",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "Review this prompt before model submission.",
            "cwd": "/workspace/project",
        }
    )

    assert response is None
    event = adapter.request_decision.await_args.args[0]
    assert event.event_type == EventType.PRE_PROMPT
    assert event.event_subtype == "PrePrompt"
    assert event.payload["prompt"] == "Review this prompt before model submission."


@pytest.mark.asyncio
async def test_claude_native_user_prompt_submit_block_returns_prompt_block_shape():
    from unittest.mock import AsyncMock

    adapter = A3SCodeAdapter(
        uds_path="/tmp/nonexistent-a3s-harness.sock",
        source_framework="claude-code",
    )
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.BLOCK,
            reason="prompt contains a secret",
            policy_id="test-policy",
            risk_level=RiskLevel.CRITICAL,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    response = await harness.dispatch_async(
        {
            "session_id": "sess-claude-prompt-block",
            "hook_event_name": "UserPromptSubmit",
            "prompt": "my key is sk-test",
            "cwd": "/workspace/project",
        }
    )

    assert response == {
        "decision": "block",
        "reason": "[ClawSentry] prompt contains a secret (risk: critical)",
    }


@pytest.mark.asyncio
async def test_kimi_native_hook_enriches_skill_trust_from_cwd_runtime_metadata(tmp_path, monkeypatch):
    from unittest.mock import AsyncMock

    skill_root = tmp_path / "skills" / "local-shadow-skill"
    scripts = skill_root / "scripts"
    scripts.mkdir(parents=True)
    (skill_root / "SKILL.md").write_text(
        "---\nname: local-shadow-skill\n---\nRead local notes.\n",
        encoding="utf-8",
    )
    runtime_dir = tmp_path / ".clawsentry"
    runtime_dir.mkdir()
    (runtime_dir / "skill-trust-runtime.json").write_text(
        json.dumps(
            {
                "schema_version": "clawsentry.skill_trust_bundle.v1",
                "framework": "kimi-cli",
                "raw_metadata_by_skill": {
                    "local-shadow-skill": {
                        "presented_name": "local-shadow-skill",
                        "admission_scan_id": "scan-kimi-1",
                        "admission_risk": "low",
                        "policy_fingerprint": "sha256:policy-kimi",
                        "skill_root_path": str(skill_root),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("CS_SKILL_TRUST_METADATA_PATH", raising=False)

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    adapter.source_framework = "kimi-cli"
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="kimi skill trust bound",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    await harness.dispatch_async(
        {
            "session_id": "sess-kimi-skill",
            "hook_event_name": "PreToolUse",
            "tool_name": "Shell",
            "tool_input": {
                "command": f"python {scripts / 'run.py'}",
            },
            "cwd": str(tmp_path),
        }
    )

    event = adapter.request_decision.await_args.args[0]
    meta = event.payload["_clawsentry_meta"]
    assert meta["skill_trust_raw"]["presented_name"] == "local-shadow-skill"
    assert meta["skill_trust_raw"]["admission_scan_id"] == "scan-kimi-1"
    assert meta["skill_lineage_raw"]["presented_name"] == "local-shadow-skill"
    assert meta["skill_lineage_raw"]["metadata_source"] == "cwd_runtime_metadata"


@pytest.mark.asyncio
async def test_kimi_native_hook_falls_back_to_cwd_runtime_metadata_when_env_path_missing(
    tmp_path, monkeypatch
):
    from unittest.mock import AsyncMock

    skill_root = tmp_path / "skills" / "local-shadow-skill"
    scripts = skill_root / "scripts"
    scripts.mkdir(parents=True)
    (skill_root / "SKILL.md").write_text(
        "---\nname: local-shadow-skill\n---\nRead local notes.\n",
        encoding="utf-8",
    )
    runtime_dir = tmp_path / ".clawsentry"
    runtime_dir.mkdir()
    (runtime_dir / "skill-trust-runtime.json").write_text(
        json.dumps(
            {
                "schema_version": "clawsentry.skill_trust_bundle.v1",
                "framework": "kimi-cli",
                "raw_metadata_by_skill": {
                    "local-shadow-skill": {
                        "presented_name": "local-shadow-skill",
                        "admission_scan_id": "scan-kimi-cwd-fallback",
                        "admission_risk": "low",
                        "skill_root_path": str(skill_root),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv(
        "CS_SKILL_TRUST_METADATA_PATH",
        str(tmp_path / "missing" / "skill-trust-raw.json"),
    )

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    adapter.source_framework = "kimi-cli"
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="kimi skill trust bound",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    await harness.dispatch_async(
        {
            "session_id": "sess-kimi-skill-cwd-fallback",
            "hook_event_name": "PreToolUse",
            "tool_name": "Shell",
            "tool_input": {"command": f"python {scripts / 'run.py'}"},
            "cwd": str(tmp_path),
        }
    )

    event = adapter.request_decision.await_args.args[0]
    meta = event.payload["_clawsentry_meta"]
    assert meta["skill_trust_raw"]["admission_scan_id"] == "scan-kimi-cwd-fallback"
    assert meta["skill_lineage_raw"]["metadata_source"] == "cwd_runtime_metadata"


@pytest.mark.asyncio
async def test_jsonrpc_event_enriches_skill_trust_from_cwd_runtime_metadata(tmp_path, monkeypatch):
    from unittest.mock import AsyncMock

    skill_root = tmp_path / "skills" / "a3s-shadow-skill"
    scripts = skill_root / "scripts"
    scripts.mkdir(parents=True)
    (skill_root / "SKILL.md").write_text(
        "---\nname: a3s-shadow-skill\n---\nRead local notes.\n",
        encoding="utf-8",
    )
    runtime_dir = tmp_path / ".clawsentry"
    runtime_dir.mkdir()
    (runtime_dir / "skill-trust-runtime.json").write_text(
        json.dumps(
            {
                "schema_version": "clawsentry.skill_trust_bundle.v1",
                "framework": "a3s-code",
                "raw_metadata_by_skill": {
                    "a3s-shadow-skill": {
                        "presented_name": "a3s-shadow-skill",
                        "canonical_skill_id": "skill:a3s-shadow-skill",
                        "canonical_name": "a3s-shadow-skill",
                        "framework": "a3s-code",
                        "scope": "workspace",
                        "admission_scan_id": "scan-a3s-1",
                        "admission_risk": "low",
                        "policy_fingerprint": "sha256:policy-a3s",
                        "skill_root_path": str(skill_root),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.delenv("CS_SKILL_TRUST_METADATA_PATH", raising=False)

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="a3s skill trust bound",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 111,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_action",
                "session_id": "sess-a3s-skill",
                "agent_id": "agent-a3s-skill",
                "payload": {
                    "tool": "bash",
                    "command": f"python {scripts / 'run.py'}",
                    "cwd": str(tmp_path),
                },
            },
        }
    )

    assert resp is not None
    event = adapter.request_decision.await_args.args[0]
    meta = event.payload["_clawsentry_meta"]
    assert meta["skill_trust_raw"]["presented_name"] == "a3s-shadow-skill"
    assert meta["skill_trust_raw"]["canonical_skill_id"] == "skill:a3s-shadow-skill"
    assert meta["skill_trust_raw"]["framework"] == "a3s-code"
    assert meta["skill_lineage_raw"]["metadata_source"] == "cwd_runtime_metadata"


@pytest.mark.asyncio
async def test_jsonrpc_top_level_context_and_metadata_are_carried():
    from unittest.mock import AsyncMock

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="compat metadata carried",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 102,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_action",
                "event_id": "evt-rich-001",
                "trace_id": "trace-rich-001",
                "session_id": "sess-rich-001",
                "agent_id": "agent-rich-001",
                "context": {
                    "session": {"mode": "supervised"},
                    "agent": {"role": "implementer"},
                },
                "metadata": {
                    "event_family": "ahp.v2.3",
                    "labels": ["compat", "rich"],
                },
                "payload": {
                    "tool": "read_file",
                    "arguments": {"path": "/tmp/x"},
                },
            },
        }
    )

    assert resp is not None
    assert resp["result"]["decision"] == "allow"

    event = adapter.request_decision.await_args.args[0]
    assert event.trace_id == "trace-rich-001"
    compat = event.payload["_clawsentry_meta"]["ahp_compat"]
    assert compat["preservation_mode"] == "compatibility-carrying"
    assert compat["raw_event_type"] == "pre_action"
    assert compat["context_present"] is True
    assert compat["metadata_present"] is True
    assert compat["context"]["session"]["mode"] == "supervised"
    assert compat["metadata"]["event_family"] == "ahp.v2.3"
    assert compat["identity"]["event_id"] == "evt-rich-001"
    assert compat["identity"]["session_id"] == "sess-rich-001"
    assert compat["identity"]["agent_id"] == "agent-rich-001"


@pytest.mark.asyncio
@pytest.mark.parametrize("event_type", ["idle", "heartbeat", "success", "rate_limit"])
async def test_jsonrpc_compat_literals_normalize_to_observation_only_session_events(event_type):
    from unittest.mock import AsyncMock

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason=f"{event_type} observed",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 103,
            "method": "ahp/event",
            "params": {
                "event_type": event_type,
                "session_id": f"sess-{event_type}",
                "agent_id": f"agent-{event_type}",
                "payload": {
                    "message": f"{event_type} compat event",
                },
            },
        }
    )

    assert resp is not None
    assert resp["result"]["decision"] == "allow"
    assert resp["result"]["action"] == "continue"

    event = adapter.request_decision.await_args.args[0]
    assert event.event_type == EventType.SESSION
    assert event.event_subtype == f"compat:{event_type}"
    assert event.payload["_clawsentry_meta"]["ahp_compat"]["raw_event_type"] == event_type


@pytest.mark.asyncio
@pytest.mark.parametrize("event_type", ["context_perception", "memory_recall"])
async def test_jsonrpc_context_memory_literals_preserve_compat_identity_and_fields(event_type):
    from unittest.mock import AsyncMock

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason=f"{event_type} observed",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 1031,
            "method": "ahp/event",
            "params": {
                "event_type": event_type,
                "event_id": f"evt-{event_type}",
                "trace_id": f"trace-{event_type}",
                "session_id": f"sess-{event_type}",
                "agent_id": f"agent-{event_type}",
                "context": {
                    "window": "recent_messages",
                    "confidence": "high",
                },
                "query": {
                    "text": "What happened before this step?",
                    "kind": event_type,
                },
                "target": {
                    "scope": "active_task",
                    "id": "target-001",
                },
                "summary": {
                    "text": "condensed state snapshot",
                    "tokens": 24,
                },
                "payload": {
                    "message": f"{event_type} compat event",
                },
            },
        }
    )

    assert resp is not None
    assert resp["result"]["decision"] == "allow"
    assert resp["result"]["action"] == "continue"

    event = adapter.request_decision.await_args.args[0]
    assert event.event_type == EventType.SESSION
    assert event.event_subtype == f"compat:{event_type}"

    compat = event.payload["_clawsentry_meta"]["ahp_compat"]
    assert compat["preservation_mode"] == "compatibility-carrying"
    assert compat["raw_event_type"] == event_type
    assert compat["identity"]["event_id"] == f"evt-{event_type}"
    assert compat["identity"]["trace_id"] == f"trace-{event_type}"
    assert compat["identity"]["session_id"] == f"sess-{event_type}"
    assert compat["identity"]["agent_id"] == f"agent-{event_type}"
    assert compat["context"]["window"] == "recent_messages"
    assert compat["query"]["kind"] == event_type
    assert compat["target"]["id"] == "target-001"
    assert compat["summary"]["text"] == "condensed state snapshot"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("event_type", "compat_fields"),
    [
        (
            "planning",
            {
                "task": "route cognition-signal compat events through ingress",
                "strategy": {
                    "mode": "compatibility-carrying",
                    "preserve_raw_type": True,
                },
                "constraints": [
                    "no new canonical EventType",
                    "observation-safe bucket only",
                ],
            },
        ),
        (
            "reasoning",
            {
                "reasoning_type": "deliberate",
                "problem_statement": "Preserve reasoning payload safely",
                "hints": [
                    "keep canonical surface unchanged",
                    "retain ingress identity",
                ],
            },
        ),
        (
            "intent_detection",
            {
                "prompt": "识别当前请求属于哪种认知信号",
                "language_hint": "zh-CN",
                "detected_intent": "compatibility_carrying",
                "target_hints": {
                    "surface": "a3s-ingress",
                    "bucket": "observation-safe",
                },
            },
        ),
    ],
)
async def test_jsonrpc_cognition_signal_literals_preserve_raw_type_identity_and_fields(
    event_type,
    compat_fields,
):
    from unittest.mock import AsyncMock

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason=f"{event_type} observed",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 1032,
            "method": "ahp/event",
            "params": {
                "event_type": event_type,
                "event_id": f"evt-{event_type}",
                "trace_id": f"trace-{event_type}",
                "session_id": f"sess-{event_type}",
                "agent_id": f"agent-{event_type}",
                **compat_fields,
                "payload": {
                    "message": f"{event_type} compat event",
                },
            },
        }
    )

    assert resp is not None
    assert resp["result"]["decision"] == "allow"
    assert resp["result"]["action"] == "continue"

    event = adapter.request_decision.await_args.args[0]
    assert event.event_type == EventType.SESSION
    assert event.event_subtype == f"compat:{event_type}"

    compat = event.payload["_clawsentry_meta"]["ahp_compat"]
    assert compat["preservation_mode"] == "compatibility-carrying"
    assert compat["raw_event_type"] == event_type
    assert compat["identity"]["event_id"] == f"evt-{event_type}"
    assert compat["identity"]["trace_id"] == f"trace-{event_type}"
    assert compat["identity"]["session_id"] == f"sess-{event_type}"
    assert compat["identity"]["agent_id"] == f"agent-{event_type}"

    for key, value in compat_fields.items():
        assert compat[key] == value


@pytest.mark.asyncio
async def test_jsonrpc_camelcase_intent_detection_preserves_compat_fields_without_identity():
    from unittest.mock import AsyncMock

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="intent detection observed",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 1033,
            "method": "ahp/event",
            "params": {
                "event_type": "IntentDetection",
                "session_id": "sess-camel-intent",
                "agent_id": "agent-camel-intent",
                "detected_intent": "inspect_runtime_context",
                "language_hint": "en-US",
                "target_hints": {"surface": "gateway"},
                "payload": {"message": "camelcase intent detection compat event"},
            },
        }
    )

    assert resp is not None
    event = adapter.request_decision.await_args.args[0]
    assert event.event_type == EventType.SESSION
    assert event.event_subtype == "compat:intent_detection"

    compat = event.payload["_clawsentry_meta"]["ahp_compat"]
    assert compat["raw_event_type"] == "IntentDetection"
    assert compat["identity"]["event_type"] == "IntentDetection"
    assert compat["identity"]["normalized_event_type"] == "intent_detection"
    assert compat["identity"]["session_id"] == "sess-camel-intent"
    assert compat["identity"]["agent_id"] == "agent-camel-intent"
    assert compat["detected_intent"] == "inspect_runtime_context"
    assert compat["language_hint"] == "en-US"
    assert compat["target_hints"] == {"surface": "gateway"}


@pytest.mark.asyncio
async def test_jsonrpc_confirmation_literal_preserves_raw_type_and_approval_id():
    from unittest.mock import AsyncMock

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="confirmation resolved",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 104,
            "method": "ahp/event",
            "params": {
                "event_type": "confirmation",
                "approval_id": "approval-confirm-123",
                "session_id": "sess-confirmation",
                "agent_id": "agent-confirmation",
                "payload": {
                    "tool": "bash",
                    "arguments": {"command": "sudo rm -rf /tmp/test"},
                },
            },
        }
    )

    assert resp is not None
    assert resp["result"]["decision"] == "allow"
    assert resp["result"]["action"] == "continue"

    event = adapter.request_decision.await_args.args[0]
    assert event.event_type == EventType.SESSION
    assert event.event_subtype == "compat:confirmation"
    assert event.approval_id == "approval-confirm-123"
    assert event.payload["_clawsentry_meta"]["ahp_compat"]["raw_event_type"] == "confirmation"


@pytest.mark.asyncio
@pytest.mark.parametrize("event_type", ["idle", "heartbeat"])
async def test_compat_high_frequency_events_are_interval_limited(event_type):
    from unittest.mock import AsyncMock

    now = 1000.0

    def fake_clock() -> float:
        return now

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(
        adapter=adapter,
        compat_observation_window_seconds=2.0,
        clock=fake_clock,
    )
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason=f"{event_type} observed",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    first = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 201,
            "method": "ahp/event",
            "params": {
                "event_type": event_type,
                "session_id": "sess-sampled",
                "agent_id": "agent-sampled",
                "payload": {"message": "first"},
            },
        }
    )
    assert first is not None
    assert first["result"]["decision"] == "allow"
    assert adapter.request_decision.await_count == 1

    second = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 202,
            "method": "ahp/event",
            "params": {
                "event_type": event_type,
                "session_id": "sess-sampled",
                "agent_id": "agent-sampled",
                "payload": {"message": "second"},
            },
        }
    )
    assert second is not None
    assert second["result"]["decision"] == "allow"
    assert "sampled" in second["result"]["reason"]
    assert adapter.request_decision.await_count == 1

    now += 2.1
    third = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 203,
            "method": "ahp/event",
            "params": {
                "event_type": event_type,
                "session_id": "sess-sampled",
                "agent_id": "agent-sampled",
                "payload": {"message": "third"},
            },
        }
    )
    assert third is not None
    assert third["result"]["decision"] == "allow"
    assert adapter.request_decision.await_count == 2

    event = adapter.request_decision.await_args.args[0]
    compat_meta = event.payload["_clawsentry_meta"]
    assert compat_meta["ahp_compat"]["raw_event_type"] == event_type
    assert compat_meta["compat_observation"]["strategy"] == "interval_limit"
    assert compat_meta["compat_observation"]["window_seconds"] == 2.0
    assert compat_meta["compat_observation"]["suppressed_since_last_emit"] == 1


@pytest.mark.asyncio
async def test_session_end_clears_matching_compat_observation_state():
    from unittest.mock import AsyncMock

    now = 1000.0

    def fake_clock() -> float:
        return now

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(
        adapter=adapter,
        compat_observation_window_seconds=10.0,
        clock=fake_clock,
    )
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="session observed",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    async def emit(event_type: str, session_id: str, agent_id: str) -> None:
        response = await harness.dispatch_async(
            {
                "jsonrpc": "2.0",
                "id": f"{event_type}-{session_id}-{agent_id}",
                "method": "ahp/event",
                "params": {
                    "event_type": event_type,
                    "session_id": session_id,
                    "agent_id": agent_id,
                    "payload": {"message": f"{event_type} event"},
                },
            }
        )
        assert response is not None
        assert response["result"]["decision"] == "allow"

    await emit("idle", "sess-ended", "agent-ended")
    await emit("heartbeat", "sess-ended", "agent-ended")
    await emit("idle", "sess-active", "agent-active")

    assert set(harness._compat_observation_state) == {
        ("idle", "sess-ended", "agent-ended"),
        ("heartbeat", "sess-ended", "agent-ended"),
        ("idle", "sess-active", "agent-active"),
    }

    session_end = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 204,
            "method": "ahp/event",
            "params": {
                "event_type": "session_end",
                "session_id": "sess-ended",
                "agent_id": "agent-ended",
                "payload": {"message": "session done"},
            },
        }
    )

    assert session_end is not None
    assert session_end["result"]["decision"] == "allow"
    assert ("idle", "sess-ended", "agent-ended") not in harness._compat_observation_state
    assert ("heartbeat", "sess-ended", "agent-ended") not in harness._compat_observation_state
    assert ("idle", "sess-active", "agent-active") in harness._compat_observation_state


@pytest.mark.asyncio
async def test_compat_observation_state_prunes_stale_sessions_during_sampling():
    from unittest.mock import AsyncMock

    now = 1000.0

    def fake_clock() -> float:
        return now

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(
        adapter=adapter,
        compat_observation_window_seconds=2.0,
        clock=fake_clock,
    )
    adapter.request_decision = AsyncMock(
        return_value=CanonicalDecision(
            decision=DecisionVerdict.ALLOW,
            reason="compat event observed",
            policy_id="test-policy",
            risk_level=RiskLevel.LOW,
            decision_source=DecisionSource.POLICY,
            final=True,
        )
    )

    for index in range(5):
        session_id = f"sess-{index}"
        response = await harness.dispatch_async(
            {
                "jsonrpc": "2.0",
                "id": 300 + index,
                "method": "ahp/event",
                "params": {
                    "event_type": "idle",
                    "session_id": session_id,
                    "agent_id": "agent-pruned",
                    "payload": {"message": f"idle {index}"},
                },
            }
        )

        assert response is not None
        assert response["result"]["decision"] == "allow"
        assert set(harness._compat_observation_state) == {
            ("idle", session_id, "agent-pruned"),
        }

        now += 3.0

@pytest.mark.asyncio
async def test_pre_action_safe_command_allowed(harness_with_gateway):
    resp = await harness_with_gateway.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_action",
                "session_id": "sess-allow",
                "agent_id": "agent-allow",
                "payload": {
                    "tool": "read_file",
                    "arguments": {"path": "/tmp/x"},
                },
            },
        }
    )

    assert resp is not None
    result = resp["result"]
    assert result["decision"] == "allow"
    assert result["action"] == "continue"


@pytest.mark.asyncio
async def test_pre_action_dangerous_command_blocked(harness_with_gateway):
    resp = await harness_with_gateway.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_action",
                "session_id": "sess-block",
                "agent_id": "agent-block",
                "payload": {
                    "tool": "bash",
                    "arguments": {"command": "rm -rf /"},
                },
            },
        }
    )

    assert resp is not None
    result = resp["result"]
    assert result["decision"] == "block"
    assert result["action"] == "block"


@pytest.mark.asyncio
async def test_notification_post_action_returns_none(harness_with_gateway):
    resp = await harness_with_gateway.dispatch_async(
        {
            "jsonrpc": "2.0",
            "method": "ahp/event",
            "params": {
                "event_type": "post_action",
                "payload": {"tool": "bash", "result": {"success": True}},
            },
        }
    )
    assert resp is None


@pytest.mark.asyncio
async def test_unknown_event_type_returns_allow_result(harness_with_gateway):
    resp = await harness_with_gateway.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "ahp/event",
            "params": {
                "event_type": "completely_unknown_event",
                "payload": {},
            },
        }
    )

    assert resp is not None
    result = resp["result"]
    assert result["decision"] == "allow"
    assert result["action"] == "continue"


@pytest.mark.asyncio
async def test_jsonrpc_camelcase_event_type_is_normalized(harness_with_gateway):
    resp = await harness_with_gateway.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 41,
            "method": "ahp/event",
            "params": {
                "event_type": "PreToolUse",
                "session_id": "sess-camelcase",
                "agent_id": "agent-camelcase",
                "payload": {
                    "tool": "bash",
                    "arguments": {"command": "rm -rf /"},
                },
            },
        }
    )

    assert resp is not None
    result = resp["result"]
    assert result["decision"] == "block"
    assert result["action"] == "block"


@pytest.mark.asyncio
async def test_gateway_down_fallback_blocks_dangerous_pre_action():
    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_action",
                "payload": {
                    "tool": "bash",
                    "arguments": {"command": "rm -rf /"},
                },
            },
        }
    )

    assert resp is not None
    result = resp["result"]
    assert result["decision"] == "block"
    assert result["action"] == "block"


@pytest.mark.asyncio
async def test_gateway_down_fallback_defers_safe_pre_action():
    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)

    resp = await harness.dispatch_async(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_action",
                "payload": {
                    "tool": "read_file",
                    "arguments": {"path": "/tmp/x"},
                },
            },
        }
    )

    assert resp is not None
    result = resp["result"]
    assert result["decision"] == "defer"
    assert result["action"] == "defer"


# ---------------------------------------------------------------------------
# W-2: Error response must not leak exception details
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_dispatch_error_does_not_leak_exception_detail():
    """W-2: Error responses must not expose raw exception messages."""
    from unittest.mock import AsyncMock, patch

    adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent-a3s-harness.sock")
    harness = A3SGatewayHarness(adapter=adapter)

    secret_message = "super secret internal traceback info 12345"

    with patch.object(
        harness,
        "_handle_event",
        new_callable=AsyncMock,
        side_effect=RuntimeError(secret_message),
    ):
        resp = await harness.dispatch_async(
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "ahp/event",
                "params": {
                    "event_type": "pre_action",
                    "payload": {"tool": "bash", "arguments": {"command": "ls"}},
                },
            }
        )

    assert resp is not None
    error = resp["error"]
    assert error["code"] == -32000
    assert secret_message not in error["message"]
    assert secret_message not in error["data"]["detail"]
    assert error["data"]["detail"] == "Internal harness error. Check server logs for details."


# ---------------------------------------------------------------------------
# E-9 Task 2: Dual-format auto-detection (JSON-RPC + native hook)
# ---------------------------------------------------------------------------


class TestNativeHookFormat:
    """Harness should accept raw hook JSON (no JSON-RPC wrapper)."""

    @pytest.fixture
    def harness(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock")
        return A3SGatewayHarness(adapter)

    @pytest.mark.asyncio
    async def test_native_pre_tool_use_detected(self, harness):
        """Native hook format without 'method' field should be auto-detected."""
        msg = {
            "event_type": "pre_tool_use",
            "payload": {
                "session_id": "sess-123",
                "tool": "Bash",
                "args": {"command": "echo hello"},
                "working_directory": "/workspace",
                "recent_tools": [],
            },
        }
        response = await harness.dispatch_async(msg)
        assert response is not None
        result = response.get("result", response)
        assert result["action"] in ("continue", "block", "defer", "modify")

    @pytest.mark.asyncio
    async def test_native_format_returns_simple_response(self, harness):
        """Native hook response should NOT have jsonrpc/id fields."""
        msg = {
            "event_type": "session_start",
            "payload": {"session_id": "sess-456"},
        }
        response = await harness.dispatch_async(msg)
        assert response is not None
        assert "jsonrpc" not in response

    @pytest.mark.asyncio
    async def test_claude_native_write_payload_lifts_nested_edit_text(self):
        """Claude native write/edit hooks should expose edit body text to policy."""
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(
            uds_path="/tmp/nonexistent.sock",
            source_framework="claude-code",
        )
        adapter.request_decision = AsyncMock(
            return_value=CanonicalDecision(
                decision=DecisionVerdict.ALLOW,
                reason="captured",
                policy_id="test-policy",
                risk_level=RiskLevel.LOW,
                decision_source=DecisionSource.POLICY,
                final=True,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-claude-edit",
                "hook_event_name": "PreToolUse",
                "tool_name": "MultiEdit",
                "tool_input": {
                    "file_path": "/workspace/app/bootstrap.js",
                    "edits": [
                        {
                            "old_string": "window.appReady = true;",
                            "new_string": "window.__clawsentryLoader = eval(location.hash);",
                        }
                    ],
                },
            }
        )

        assert response is None
        event = adapter.request_decision.await_args.args[0]
        assert event.payload["file_path"] == "/workspace/app/bootstrap.js"
        assert "window.__clawsentryLoader" in event.payload["content"]

    @pytest.mark.asyncio
    async def test_claude_native_hook_enriches_skill_trust_from_cwd_runtime_metadata(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        skill_root = tmp_path / "skills" / "claude-shadow-skill"
        scripts = skill_root / "scripts"
        scripts.mkdir(parents=True)
        (skill_root / "SKILL.md").write_text(
            "---\nname: claude-shadow-skill\n---\nRead local notes.\n",
            encoding="utf-8",
        )
        runtime_dir = tmp_path / ".clawsentry"
        runtime_dir.mkdir()
        (runtime_dir / "skill-trust-runtime.json").write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "framework": "claude-code",
                    "raw_metadata_by_skill": {
                        "claude-shadow-skill": {
                            "presented_name": "claude-shadow-skill",
                            "canonical_skill_id": "skill:claude-shadow-skill",
                            "canonical_name": "claude-shadow-skill",
                            "framework": "claude-code",
                            "scope": "workspace",
                            "admission_scan_id": "scan-claude-1",
                            "admission_risk": "low",
                            "policy_fingerprint": "sha256:policy-claude",
                            "skill_root_path": str(skill_root),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.delenv("CS_SKILL_TRUST_METADATA_PATH", raising=False)

        adapter = A3SCodeAdapter(
            uds_path="/tmp/nonexistent.sock",
            source_framework="claude-code",
        )
        adapter.request_decision = AsyncMock(
            return_value=CanonicalDecision(
                decision=DecisionVerdict.ALLOW,
                reason="captured",
                policy_id="test-policy",
                risk_level=RiskLevel.LOW,
                decision_source=DecisionSource.POLICY,
                final=True,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-claude-skill",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": f"python {scripts / 'run.py'}"},
                "cwd": str(tmp_path),
            }
        )

        assert response is None
        event = adapter.request_decision.await_args.args[0]
        meta = event.payload["_clawsentry_meta"]
        assert meta["skill_trust_raw"]["presented_name"] == "claude-shadow-skill"
        assert meta["skill_trust_raw"]["canonical_skill_id"] == "skill:claude-shadow-skill"
        assert meta["skill_trust_raw"]["framework"] == "claude-code"
        assert meta["skill_lineage_raw"]["metadata_source"] == "cwd_runtime_metadata"

    @pytest.mark.asyncio
    async def test_claude_native_skill_tool_enriches_skill_trust_from_skill_argument(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        skill_root = tmp_path / "skills" / "search-accommodation"
        skill_root.mkdir(parents=True)
        (skill_root / "SKILL.md").write_text(
            "---\nname: search-accommodation\n---\nUse the singular alias.\n",
            encoding="utf-8",
        )
        runtime_dir = tmp_path / ".clawsentry"
        runtime_dir.mkdir()
        (runtime_dir / "skill-trust-runtime.json").write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "framework": "claude-code",
                    "raw_metadata_by_skill": {
                        "search-cities": {
                            "presented_name": "search-cities",
                            "canonical_skill_id": "skill:search-cities",
                            "canonical_name": "search-cities",
                            "framework": "claude-code",
                            "provenance_label_conflict": False,
                            "skill_root_path": str(tmp_path / "skills" / "search-cities"),
                        },
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "canonical_skill_id": "skill:search-accommodation",
                            "canonical_name": "search-accommodation",
                            "framework": "claude-code",
                            "provenance_label_conflict": True,
                            "skill_root_path": str(skill_root),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.delenv("CS_SKILL_TRUST_METADATA_PATH", raising=False)

        adapter = A3SCodeAdapter(
            uds_path="/tmp/nonexistent.sock",
            source_framework="claude-code",
        )
        adapter.request_decision = AsyncMock(
            return_value=CanonicalDecision(
                decision=DecisionVerdict.ALLOW,
                reason="captured",
                policy_id="test-policy",
                risk_level=RiskLevel.LOW,
                decision_source=DecisionSource.POLICY,
                final=True,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-claude-native-skill",
                "hook_event_name": "PreToolUse",
                "tool_name": "Skill",
                "tool_input": {"skill": "search-accommodation"},
                "cwd": str(tmp_path),
            }
        )

        assert response is None
        event = adapter.request_decision.await_args.args[0]
        raw = event.payload["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["presented_name"] == "search-accommodation"
        assert raw["provenance_claim"] == "search-accommodations"
        assert raw["provenance_label_conflict"] is True

    @pytest.mark.asyncio
    async def test_gemini_invoke_agent_prompt_enriches_skill_trust_from_skill_path(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        skill_root = tmp_path / "skills" / "search-accommodation"
        (skill_root / "scripts").mkdir(parents=True)
        (skill_root / "SKILL.md").write_text(
            "---\nname: search-accommodation\n---\nUse the singular alias.\n",
            encoding="utf-8",
        )
        runtime_dir = tmp_path / ".clawsentry"
        runtime_dir.mkdir()
        (runtime_dir / "skill-trust-runtime.json").write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "framework": "gemini-cli",
                    "raw_metadata_by_skill": {
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "canonical_skill_id": "skill:search-accommodation",
                            "canonical_name": "search-accommodation",
                            "framework": "gemini-cli",
                            "provenance_label_conflict": True,
                            "skill_root_path": str(skill_root),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.delenv("CS_SKILL_TRUST_METADATA_PATH", raising=False)

        adapter = A3SCodeAdapter(
            uds_path="/tmp/nonexistent.sock",
            source_framework="gemini-cli",
        )
        adapter.request_decision = AsyncMock(
            return_value=CanonicalDecision(
                decision=DecisionVerdict.ALLOW,
                reason="captured",
                policy_id="test-policy",
                risk_level=RiskLevel.LOW,
                decision_source=DecisionSource.POLICY,
                final=True,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-gemini-delegate",
                "hook_event_name": "BeforeTool",
                "tool_name": "invoke_agent",
                "tool_input": {
                    "prompt": (
                        "Use `/root/.agents/skills/search-accommodation/scripts/"
                        "search_accommodations.py` for accommodations."
                    )
                },
                "cwd": str(tmp_path),
            }
        )

        assert response is None
        event = adapter.request_decision.await_args.args[0]
        raw = event.payload["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["presented_name"] == "search-accommodation"
        assert raw["provenance_claim"] == "search-accommodations"
        assert raw["provenance_label_conflict"] is True

    @pytest.mark.asyncio
    async def test_gemini_invoke_agent_prompt_with_poisoned_skill_is_denied_by_gateway(
        self,
        tmp_path,
        monkeypatch,
    ):
        skill_root = tmp_path / "skills" / "search-accommodation"
        (skill_root / "scripts").mkdir(parents=True)
        (skill_root / "SKILL.md").write_text(
            "---\nname: search-accommodation\n---\nUse the singular alias.\n",
            encoding="utf-8",
        )
        runtime_dir = tmp_path / ".clawsentry"
        runtime_dir.mkdir()
        metadata_path = runtime_dir / "skill-trust-runtime.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "framework": "gemini-cli",
                    "raw_metadata_by_skill": {
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "canonical_skill_id": "skill:search-accommodation",
                            "canonical_name": "search-accommodation",
                            "framework": "gemini-cli",
                            "provenance_label_conflict": True,
                            "control_language_findings": [
                                "canonical_name_claim",
                                "routing_claim",
                            ],
                            "skill_root_path": str(skill_root),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata_path))
        monkeypatch.setenv("CS_MODE", "benchmark")

        uds_path = str(tmp_path / "gateway.sock")
        gateway = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(mode="benchmark"),
            skill_registry_records=[
                _skill_record("search-cities"),
                _skill_record("search-accommodation"),
                _skill_record("search-accommodations"),
            ],
        )
        server = await start_uds_server(gateway, uds_path)
        try:
            adapter = A3SCodeAdapter(
                uds_path=uds_path,
                default_deadline_ms=500,
                source_framework="gemini-cli",
            )
            harness = A3SGatewayHarness(adapter)

            response = await harness.dispatch_async(
                {
                    "session_id": "sess-gemini-delegate-deny",
                    "hook_event_name": "BeforeTool",
                    "tool_name": "invoke_agent",
                    "tool_input": {
                        "prompt": (
                            "Use `/root/.agents/skills/search-accommodation/scripts/"
                            "search_accommodations.py` for accommodations."
                        )
                    },
                    "cwd": str(tmp_path),
                }
            )
        finally:
            server.close()
            await server.wait_closed()

        assert response is not None
        assert response["decision"] == "deny"
        assert "(risk: high)" in response["reason"]
        assert "runtime_path_disallowed" in response["reason"]

    @pytest.mark.asyncio
    async def test_gemini_generated_script_with_poisoned_skill_path_is_denied_by_gateway(
        self,
        tmp_path,
        monkeypatch,
    ):
        skill_root = tmp_path / "skills" / "search-accommodation"
        (skill_root / "scripts").mkdir(parents=True)
        (skill_root / "SKILL.md").write_text(
            "---\nname: search-accommodation\n---\nUse the singular alias.\n",
            encoding="utf-8",
        )
        runtime_dir = tmp_path / ".clawsentry"
        runtime_dir.mkdir()
        metadata_path = runtime_dir / "skill-trust-runtime.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "framework": "gemini-cli",
                    "raw_metadata_by_skill": {
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "canonical_skill_id": "skill:search-accommodation",
                            "canonical_name": "search-accommodation",
                            "framework": "gemini-cli",
                            "provenance_label_conflict": True,
                            "control_language_findings": ["canonical_name_claim"],
                            "skill_root_path": str(skill_root),
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata_path))

        uds_path = str(tmp_path / "gateway.sock")
        gateway = SupervisionGateway(
            trajectory_db_path=":memory:",
            detection_config=DetectionConfig(mode="benchmark"),
            skill_registry_records=[
                _skill_record("search-accommodation"),
                _skill_record("search-accommodations"),
            ],
        )
        server = await start_uds_server(gateway, uds_path)
        try:
            adapter = A3SCodeAdapter(
                uds_path=uds_path,
                default_deadline_ms=500,
                source_framework="gemini-cli",
            )
            harness = A3SGatewayHarness(adapter)

            response = await harness.dispatch_async(
                {
                    "session_id": "sess-gemini-generated-script-deny",
                    "hook_event_name": "BeforeTool",
                    "tool_name": "run_shell_command",
                    "tool_input": {
                        "command": (
                            "cat <<'EOF' > gather_data.py\n"
                            "import sys\n"
                            'sys.path.append("/root/.agents/skills/search-accommodation/scripts")\n'
                            "from search_accommodations import Accommodations\n"
                            "EOF\n"
                            "python3 gather_data.py\n"
                        )
                    },
                    "cwd": str(tmp_path),
                }
            )
        finally:
            server.close()
            await server.wait_closed()

        assert response is not None
        assert response["decision"] == "deny"
        assert "runtime_path_disallowed" in response["reason"]

    @pytest.mark.asyncio
    async def test_jsonrpc_format_still_works(self, harness):
        """Existing JSON-RPC format should still work unchanged."""
        msg = {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "ahp/event",
            "params": {
                "event_type": "pre_tool_use",
                "payload": {"tool": "Bash", "command": "ls"},
            },
        }
        response = await harness.dispatch_async(msg)
        assert response is not None
        assert response.get("jsonrpc") == "2.0"
        assert response.get("id") == 42


class TestFrameworkArgument:
    """Harness --framework flag should set adapter source_framework."""

    def test_default_framework_is_a3s_code(self):
        adapter = A3SCodeAdapter()
        harness = A3SGatewayHarness(adapter)
        assert harness.adapter.source_framework == "a3s-code"

    def test_claude_code_framework(self):
        adapter = A3SCodeAdapter(source_framework="claude-code")
        harness = A3SGatewayHarness(adapter)
        assert harness.adapter.source_framework == "claude-code"


class TestCodexNativeHookDispatch:
    """Codex native hooks use Codex normalization and Codex response semantics."""

    @staticmethod
    def _decision(
        decision: DecisionVerdict,
        *,
        policy_id: str = "test-policy",
        reason: str = "test decision",
        risk_level: RiskLevel = RiskLevel.HIGH,
    ) -> CanonicalDecision:
        return CanonicalDecision(
            decision=decision,
            reason=reason,
            policy_id=policy_id,
            risk_level=risk_level,
            decision_source=DecisionSource.POLICY,
            final=True,
        )

    @pytest.mark.asyncio
    async def test_codex_pretooluse_uses_codex_adapter_then_gateway_transport(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-native-codex",
                "turn_id": "turn-native-codex",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo ok"},
                "tool_use_id": "tool-native-codex",
                "cwd": "/workspace/project",
            }
        )

        assert response is None
        event = adapter.request_decision.await_args.args[0]
        assert event.source_framework == "codex"
        assert event.event_type == EventType.PRE_ACTION
        assert event.event_subtype == "PreToolUse"
        assert event.tool_name == "bash"
        assert event.trace_id == "tool-native-codex"
        assert event.payload["turn_id"] == "turn-native-codex"
        assert event.payload["arguments"]["command"] == "echo ok"

    @pytest.mark.asyncio
    async def test_codex_pretooluse_enriches_skill_trust_metadata_from_runtime_bundle(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        codex_home = tmp_path / "codex"
        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "provenance_label_conflict": True,
                            "control_language_findings": ["canonical_name_claim"],
                            "content_hashes": {"SKILL.md": "sha256:skill"},
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CODEX_HOME", str(codex_home))
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        await harness.dispatch_async(
            {
                "session_id": "sess-native-codex-skill",
                "turn_id": "turn-native-codex-skill",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {
                    "command": f"python {codex_home}/skills/search-accommodation/scripts/search.py",
                },
                "tool_use_id": "tool-native-codex-skill",
                "cwd": "/workspace/project",
            }
        )

        event = adapter.request_decision.await_args.args[0]
        raw = event.payload["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["presented_name"] == "search-accommodation"
        assert raw["provenance_claim"] == "search-accommodations"
        assert raw["provenance_label_conflict"] is True
        lineage = event.payload["_clawsentry_meta"]["skill_lineage_raw"]
        assert lineage["presented_name"] == "search-accommodation"
        assert "raw_skill_path" not in raw

    @pytest.mark.asyncio
    async def test_codex_pretooluse_enriches_skill_trust_metadata_from_split_skill_path(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "provenance_label_conflict": True,
                            "control_language_findings": ["canonical_name_claim"],
                        },
                        "search-accommodations": {
                            "presented_name": "search-accommodations",
                            "provenance_claim": "search_accommodations",
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        await harness.dispatch_async(
            {
                "session_id": "sess-native-codex-split-skill",
                "turn_id": "turn-native-codex-split-skill",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "base = Path('/root/.agents/skills')\n"
                        "load(base/'search-accommodation/scripts/search_accommodations.py')"
                    ),
                },
                "tool_use_id": "tool-native-codex-split-skill",
                "cwd": "/workspace/project",
            }
        )

        event = adapter.request_decision.await_args.args[0]
        raw = event.payload["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["presented_name"] == "search-accommodation"
        assert raw["provenance_label_conflict"] is True

    @pytest.mark.asyncio
    async def test_codex_pretooluse_split_skill_path_preserves_runtime_order(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "short": {
                            "presented_name": "short",
                            "provenance_label_conflict": False,
                        },
                        "a-much-longer-skill": {
                            "presented_name": "a-much-longer-skill",
                            "provenance_label_conflict": True,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        await harness.dispatch_async(
            {
                "session_id": "sess-native-codex-split-order",
                "turn_id": "turn-native-codex-split-order",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "base = Path('/root/.agents/skills')\n"
                        "load(base/'short/scripts/run.py')\n"
                        "load(base/'a-much-longer-skill/scripts/run.py')"
                    ),
                },
                "tool_use_id": "tool-native-codex-split-order",
                "cwd": "/workspace/project",
            }
        )

        event = adapter.request_decision.await_args.args[0]
        raw = event.payload["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["presented_name"] == "short"
        assert raw["provenance_label_conflict"] is False

    @pytest.mark.asyncio
    async def test_codex_pretooluse_preserves_runtime_skill_order_when_command_mentions_many_skills(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "search-cities": {
                            "presented_name": "search-cities",
                            "provenance_label_conflict": False,
                        },
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "provenance_label_conflict": True,
                            "control_language_findings": ["canonical_name_claim", "routing_claim"],
                        },
                        "search-driving-distance": {
                            "presented_name": "search-driving-distance",
                            "provenance_label_conflict": False,
                            "control_language_findings": ["routing_claim"],
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        await harness.dispatch_async(
            {
                "session_id": "sess-native-codex-many-skills",
                "turn_id": "turn-native-codex-many-skills",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "sys.path.extend(['/root/.agents/skills/search-cities/scripts',"
                        "'/root/.agents/skills/search-accommodation/scripts',"
                        "'/root/.agents/skills/search-driving-distance/scripts'])"
                    ),
                },
                "tool_use_id": "tool-native-codex-many-skills",
                "cwd": "/workspace/project",
            }
        )

        event = adapter.request_decision.await_args.args[0]
        raw = event.payload["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["presented_name"] == "search-cities"
        assert raw["provenance_label_conflict"] is False

    @pytest.mark.asyncio
    async def test_codex_message_text_does_not_override_executed_skill_path(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "provenance_label_conflict": True,
                        },
                        "search-accommodations": {
                            "presented_name": "search-accommodations",
                            "provenance_label_conflict": False,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        await harness.dispatch_async(
            {
                "session_id": "sess-native-codex-message-order",
                "turn_id": "turn-native-codex-message-order",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "python /root/.agents/skills/search-accommodations/"
                        "scripts/search_accommodations.py"
                    ),
                    "message": "search-accommodation",
                },
                "tool_use_id": "tool-native-codex-message-order",
                "cwd": "/workspace/project",
            }
        )

        event = adapter.request_decision.await_args.args[0]
        raw = event.payload["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["presented_name"] == "search-accommodations"
        assert raw["provenance_label_conflict"] is False

    @pytest.mark.asyncio
    async def test_codex_pretooluse_does_not_enrich_from_incidental_skill_name_text(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "provenance_label_conflict": True,
                            "control_language_findings": ["canonical_name_claim"],
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        await harness.dispatch_async(
            {
                "session_id": "sess-native-codex-incidental-skill-text",
                "turn_id": "turn-native-codex-incidental-skill-text",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "cat <<'EOF' > notes.txt\n"
                        "Do not select /root/.agents/skills/search-accommodation/scripts/search.py\n"
                        "EOF\n"
                        "# validate /root/.agents/skills/search-accommodation/scripts/search.py was not selected\n"
                        "python /workspace/validate.py"
                    ),
                },
                "tool_use_id": "tool-native-codex-incidental-skill-text",
                "cwd": "/workspace/project",
            }
        )

        event = adapter.request_decision.await_args.args[0]
        assert "_clawsentry_meta" not in event.payload or "skill_trust_raw" not in event.payload["_clawsentry_meta"]

    @pytest.mark.asyncio
    async def test_codex_pretooluse_ignores_incidental_alias_path_when_canonical_path_executes(
        self,
        tmp_path,
        monkeypatch,
    ):
        from unittest.mock import AsyncMock

        metadata = tmp_path / "skill-trust-raw.json"
        metadata.write_text(
            json.dumps(
                {
                    "schema_version": "clawsentry.skill_trust_bundle.v1",
                    "raw_metadata_by_skill": {
                        "search-accommodation": {
                            "presented_name": "search-accommodation",
                            "provenance_claim": "search-accommodations",
                            "provenance_label_conflict": True,
                            "control_language_findings": ["canonical_name_claim"],
                        },
                        "search-accommodations": {
                            "presented_name": "search-accommodations",
                            "provenance_claim": "search_accommodations",
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        monkeypatch.setenv("CS_SKILL_TRUST_METADATA_PATH", str(metadata))
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        await harness.dispatch_async(
            {
                "session_id": "sess-native-codex-canonical-with-incidental-alias",
                "turn_id": "turn-native-codex-canonical-with-incidental-alias",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {
                    "command": (
                        "python /root/.agents/skills/search-accommodations/scripts/search_accommodations.py "
                        "--city Cleveland\n"
                        "# old alias path: /root/.agents/skills/search-accommodation/scripts/search.py\n"
                        "cat <<'EOF' >/tmp/audit.txt\n"
                        "/root/.agents/skills/search-accommodation/scripts/search.py\n"
                        "EOF"
                    ),
                },
                "tool_use_id": "tool-native-codex-canonical-with-incidental-alias",
                "cwd": "/workspace/project",
            }
        )

        event = adapter.request_decision.await_args.args[0]
        raw = event.payload["_clawsentry_meta"]["skill_trust_raw"]
        assert raw["presented_name"] == "search-accommodations"
        assert raw.get("provenance_label_conflict") is not True

    @pytest.mark.asyncio
    async def test_codex_pretooluse_sends_standard_agent_trust_context(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="allowed",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        await harness.dispatch_async(
            {
                "session_id": "sess-native-codex-context",
                "turn_id": "turn-native-codex-context",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "python - <<'PY'\nprint('ok')\nPY"},
                "tool_use_id": "tool-native-codex-context",
                "cwd": "/workspace/project",
            }
        )

        context = adapter.request_decision.await_args.args[1]
        assert context.agent_trust_level == AgentTrustLevel.STANDARD

    @pytest.mark.asyncio
    async def test_codex_pretooluse_block_returns_verified_deny_shape(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                reason="dangerous command",
                risk_level=RiskLevel.CRITICAL,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-block-codex",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /"},
                "tool_use_id": "tool-block-codex",
            }
        )

        assert response == {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    "[ClawSentry] dangerous command (risk: critical)"
                ),
            }
        }

    @pytest.mark.asyncio
    async def test_codex_sessionstart_never_returns_host_block(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                reason="observation-only event",
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-start-codex",
                "hook_event_name": "SessionStart",
                "source": "startup",
            }
        )

        assert response is None

    @pytest.mark.asyncio
    async def test_codex_fallback_policy_fails_open_with_diagnostic(self, capsys):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                policy_id="fallback-fail-closed",
                reason="gateway unreachable fallback",
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-fallback-codex",
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/x"},
            }
        )

        assert response is None
        assert "Gateway unreachable" in capsys.readouterr().err

    @pytest.mark.asyncio
    async def test_codex_permission_request_block_returns_deny_behavior(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                reason="approval request violates policy",
                risk_level=RiskLevel.HIGH,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-permission-deny",
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {
                    "command": "grep -R api_key .",
                    "description": "needs file scan approval",
                },
            }
        )

        assert response == {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {
                    "behavior": "deny",
                    "message": "[ClawSentry] approval request violates policy (risk: high)",
                },
            }
        }

    @pytest.mark.asyncio
    async def test_codex_permission_request_allow_returns_allow_behavior(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="low risk approval",
                risk_level=RiskLevel.LOW,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-permission-allow",
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {"command": "ls"},
            }
        )

        assert response == {
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": {"behavior": "allow"},
            }
        }

    @pytest.mark.asyncio
    async def test_codex_permission_request_medium_allow_declines_to_decide(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.ALLOW,
                reason="medium risk should keep normal approval",
                risk_level=RiskLevel.MEDIUM,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-permission-medium",
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {"command": "grep -R TODO ."},
            }
        )

        assert response is None

    @pytest.mark.asyncio
    async def test_codex_user_prompt_submit_block_returns_prompt_block_shape(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                reason="prompt contains a secret",
                risk_level=RiskLevel.CRITICAL,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-prompt-block",
                "hook_event_name": "UserPromptSubmit",
                "prompt": "my key is sk-test",
            }
        )

        assert response == {
            "decision": "block",
            "reason": "[ClawSentry] prompt contains a secret (risk: critical)",
        }

    @pytest.mark.asyncio
    async def test_codex_posttooluse_block_returns_containment_feedback(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                reason="tool output needs review",
                risk_level=RiskLevel.HIGH,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-post-contain",
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "cat secret.txt"},
                "tool_response": "SECRET=abc",
            }
        )

        assert response == {
            "continue": False,
            "stopReason": "[ClawSentry] tool output needs review (risk: high)",
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "additionalContext": (
                    "[ClawSentry] tool output needs review (risk: high)"
                ),
            },
        }

    @pytest.mark.asyncio
    async def test_codex_stop_block_requests_one_continuation_when_not_already_active(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                reason="run one more verification pass",
                risk_level=RiskLevel.HIGH,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-stop-continue",
                "hook_event_name": "Stop",
                "stop_hook_active": False,
                "last_assistant_message": "done",
            }
        )

        assert response == {
            "decision": "block",
            "reason": "[ClawSentry] run one more verification pass (risk: high)",
        }

    @pytest.mark.asyncio
    async def test_codex_stop_block_fails_open_when_stop_hook_already_active(self):
        from unittest.mock import AsyncMock

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        adapter.request_decision = AsyncMock(
            return_value=self._decision(
                DecisionVerdict.BLOCK,
                reason="would continue forever",
                risk_level=RiskLevel.HIGH,
            )
        )
        harness = A3SGatewayHarness(adapter)

        response = await harness.dispatch_async(
            {
                "session_id": "sess-stop-active",
                "hook_event_name": "Stop",
                "stop_hook_active": True,
            }
        )

        assert response is None


class TestCamelToSnake:
    """Test the _camel_to_snake helper."""

    def test_pre_tool_use(self):
        from clawsentry.adapters.a3s_gateway_harness import _camel_to_snake
        assert _camel_to_snake("PreToolUse") == "pre_tool_use"

    def test_post_tool_use(self):
        from clawsentry.adapters.a3s_gateway_harness import _camel_to_snake
        assert _camel_to_snake("PostToolUse") == "post_tool_use"

    def test_session_start(self):
        from clawsentry.adapters.a3s_gateway_harness import _camel_to_snake
        assert _camel_to_snake("SessionStart") == "session_start"

    def test_already_snake_case(self):
        from clawsentry.adapters.a3s_gateway_harness import _camel_to_snake
        assert _camel_to_snake("pre_tool_use") == "pre_tool_use"

    def test_generate_start(self):
        from clawsentry.adapters.a3s_gateway_harness import _camel_to_snake
        assert _camel_to_snake("GenerateStart") == "generate_start"


# ---------------------------------------------------------------------------
# E-9 Task 5: --async mode
# ---------------------------------------------------------------------------


class TestAsyncMode:
    """Harness --async flag should return immediately for non-blocking hooks."""

    @pytest.fixture
    def async_harness(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock")
        return A3SGatewayHarness(adapter, async_mode=True)

    @pytest.mark.asyncio
    async def test_async_mode_returns_continue_immediately(self, async_harness):
        msg = {
            "event_type": "post_tool_use",
            "payload": {"session_id": "s1", "tool": "Bash", "args": {}},
        }
        response = await async_harness.dispatch_async(msg)
        result = response.get("result", response)
        assert result["action"] == "continue"
        assert "async" in result.get("reason", "").lower()

    @pytest.mark.asyncio
    async def test_async_mode_flag_default_false(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock")
        harness = A3SGatewayHarness(adapter)
        assert harness.async_mode is False

    @pytest.mark.asyncio
    async def test_async_jsonrpc_still_processed(self):
        """JSON-RPC messages should still be processed normally in async mode."""
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock")
        harness = A3SGatewayHarness(adapter, async_mode=True)
        msg = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ahp/handshake",
            "params": {},
        }
        response = await harness.dispatch_async(msg)
        assert response is not None
        assert response.get("jsonrpc") == "2.0"


class TestAsyncBackgroundDispatch:
    """Async mode should dispatch to gateway in background, not drop."""

    @pytest.mark.asyncio
    async def test_async_mode_dispatches_in_background(self):
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock")
        harness = A3SGatewayHarness(adapter, async_mode=True)

        msg = {
            "event_type": "post_tool_use",
            "payload": {"session_id": "s1", "tool": "Read", "args": {}},
        }

        from unittest.mock import AsyncMock, patch

        with patch.object(harness, "_handle_event", new_callable=AsyncMock) as mock_handle:
            result = await harness.dispatch_async(msg)
            # Should return immediately with continue
            assert result["result"]["action"] == "continue"
            # Background task should have been scheduled — let it run
            await asyncio.sleep(0.05)
            mock_handle.assert_called_once()

    @pytest.mark.asyncio
    async def test_async_mode_does_not_block_on_gateway_error(self):
        """Background dispatch errors should not propagate."""
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock")
        harness = A3SGatewayHarness(adapter, async_mode=True)

        msg = {
            "event_type": "session_end",
            "payload": {"session_id": "s2"},
        }

        from unittest.mock import AsyncMock, patch

        with patch.object(
            harness, "_handle_event", new_callable=AsyncMock,
            side_effect=Exception("gateway down"),
        ):
            result = await harness.dispatch_async(msg)
            assert result["result"]["action"] == "continue"
            # Let the background task run (and fail silently)
            await asyncio.sleep(0.05)

    @pytest.mark.asyncio
    async def test_async_reason_says_dispatched_not_queued(self):
        """Reason should say 'dispatched' not 'queued' (old behavior)."""
        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock")
        harness = A3SGatewayHarness(adapter, async_mode=True)

        from unittest.mock import AsyncMock, patch

        msg = {
            "event_type": "post_tool_use",
            "payload": {"session_id": "s3", "tool": "Bash", "args": {}},
        }
        with patch.object(harness, "_handle_event", new_callable=AsyncMock):
            result = await harness.dispatch_async(msg)

        assert "dispatched" in result["result"]["reason"]

    def test_async_run_stdio_uses_bounded_shutdown_grace_for_codex_hooks(
        self,
        monkeypatch,
    ):
        """Short-lived Codex --async hook command should not wait for gateway timeout."""
        from unittest.mock import patch

        async def slow_dispatch(*_args, **_kwargs):
            await asyncio.sleep(10)

        adapter = A3SCodeAdapter(uds_path="/tmp/nonexistent.sock", source_framework="codex")
        harness = A3SGatewayHarness(
            adapter,
            async_mode=True,
            async_shutdown_grace_seconds=0.01,
        )
        msg = {
            "session_id": "sess-async-stdio",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "echo observed"},
        }
        monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(msg) + "\n"))
        monkeypatch.setattr(sys, "stderr", io.StringIO())

        start = time.monotonic()
        with patch.object(
            harness,
            "_async_dispatch_codex_native",
            side_effect=slow_dispatch,
        ) as dispatch:
            harness.run_stdio()

        assert dispatch.called
        assert time.monotonic() - start < 0.5
