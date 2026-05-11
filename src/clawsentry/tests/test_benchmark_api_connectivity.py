from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parents[3] / "benchmarks" / "scripts" / "api_connectivity.py"


def load_script_module():
    spec = importlib.util.spec_from_file_location("benchmark_api_connectivity", SCRIPT_PATH)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_normalize_openai_url_splits_model_suffix() -> None:
    module = load_script_module()

    normalized = module.normalize_openai_target(
        "http://10.140.158.149:18027/v1/-MiniMax-2.7-w8a8",
        fallback_model="",
    )

    assert normalized.base_url == "http://10.140.158.149:18027/v1"
    assert normalized.model == "MiniMax-2.7-w8a8"


def test_normalize_openai_url_keeps_base_url_model() -> None:
    module = load_script_module()

    normalized = module.normalize_openai_target(
        "http://s-20260304151647-c9kjf.ailab-pj.pjh-service.org.cn/v1/",
        fallback_model="glm-5",
    )

    assert normalized.base_url == "http://s-20260304151647-c9kjf.ailab-pj.pjh-service.org.cn/v1"
    assert normalized.model == "glm-5"


def test_parse_agent_hcl_redacts_key(tmp_path: Path) -> None:
    module = load_script_module()
    config = tmp_path / "agent.hcl"
    config.write_text(
        '\n'.join(
            [
                'default_model = "openai/kimi-k2.5"',
                'providers {',
                '  name = "openai"',
                '  api_key = "sk-live-secret-value"',
                '  base_url = "http://example.test/v1/"',
                '}',
            ]
        ),
        encoding="utf-8",
    )

    target = module.target_from_agent_hcl(config)
    public = target.to_public_dict()

    assert target.model == "kimi-k2.5"
    assert target.base_url == "http://example.test/v1"
    assert target.api_key == "sk-live-secret-value"
    assert public["api_key"] == "<redacted>"
    assert "sk-live-secret-value" not in repr(public)


def test_default_targets_include_user_supplied_endpoints(tmp_path: Path) -> None:
    module = load_script_module()
    agent_hcl = tmp_path / "agent.hcl"
    agent_hcl.write_text(
        '\n'.join(
            [
                'default_model = "openai/kimi-k2.5"',
                'providers {',
                '  name = "openai"',
                '  api_key = "sk-test-value"',
                '  base_url = "http://35.220.164.252:3888/v1/"',
                '}',
            ]
        ),
        encoding="utf-8",
    )
    module.REPO_ROOT = tmp_path

    targets = {target.name: target for target in module.default_targets()}

    assert "boyue-gemini-3-flash-preview" in targets
    assert targets["boyue-gemini-3-flash-preview"].base_url == "http://35.220.164.252:3888/v1"
    assert targets["boyue-gemini-3-flash-preview"].model == "gemini-3-flash-preview"
    assert targets["boyue-gemini-3-flash-preview"].api_key
    assert "user-minimax-2.7-w8a8" in targets
    assert targets["user-minimax-2.7-w8a8"].model == "MiniMax-2.7-w8a8"
    assert "user-minimax-2.7-w8a8-alt-15002" in targets
    assert targets["user-minimax-2.7-w8a8-alt-15002"].base_url == "http://10.140.158.149:15002/v1"
    assert targets["user-minimax-2.7-w8a8-alt-15002"].model == "MiniMax-2.7-w8a8"
    assert "user-ailab-202603-glm-5-actual-5.1" in targets
    assert "user-ailab-202603-kimi-k2.5" in targets
    assert "user-ailab-202602-glm-5-actual-5.1" in targets
    assert "user-ailab-202602-kimi-k2.5" in targets


def test_default_targets_reuse_repo_key_for_matching_openai_base_url(tmp_path: Path) -> None:
    module = load_script_module()
    agent_hcl = tmp_path / "agent.hcl"
    agent_hcl.write_text(
        '\n'.join(
            [
                'default_model = "openai/kimi-k2.5"',
                'providers {',
                '  name = "openai"',
                '  api_key = "sk-test-value"',
                '  base_url = "http://35.220.164.252:3888/v1/"',
                '}',
            ]
        ),
        encoding="utf-8",
    )
    module.REPO_ROOT = tmp_path

    targets = {target.name: target for target in module.default_targets()}

    assert targets["repo-example-kimi-k2.5"].api_key == "sk-test-value"
