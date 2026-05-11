"""``clawsentry benchmark`` — deterministic benchmark-mode helpers."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence

from .initializers.codex import (
    _enable_codex_hooks_feature,
    _remove_codex_hook_state_sections,
    _clawsentry_codex_hook_trust_states,
    _trust_clawsentry_codex_hooks,
)

BENCHMARK_ENV_FILE_NAME = ".env.clawsentry.benchmark"

_BENCHMARK_HOOK_COMMAND_SYNC = "clawsentry harness --framework codex"
_BENCHMARK_HOOK_COMMAND_ASYNC = "clawsentry harness --framework codex --async"
_BENCHMARK_NON_BASH_TOOL_MATCHER = "apply_patch|Edit|Write|mcp__.*"


def _render_hook_command(event_name: str, matcher: str | None) -> str:
    if (event_name == "PreToolUse" and matcher == "Bash") or event_name == "PermissionRequest":
        return _BENCHMARK_HOOK_COMMAND_SYNC
    return _BENCHMARK_HOOK_COMMAND_ASYNC


def _is_active_user_codex_home(path: Path) -> bool:
    return path.expanduser().resolve() == (Path.home() / ".codex").resolve()


def _require_safe_codex_home(
    codex_home: Path | None,
    *,
    force_user_home: bool = False,
) -> Path:
    if codex_home is None:
        raise ValueError("--codex-home is required unless run with temporary benchmark mode")
    resolved = codex_home.expanduser()
    if _is_active_user_codex_home(resolved) and not force_user_home:
        raise ValueError(
            "Refusing to modify active ~/.codex during benchmark setup; pass --force-user-home"
        )
    return resolved


def render_benchmark_env(
    *,
    framework: str = "codex",
    mode: str = "guarded",
) -> str:
    """Return a minimal benchmark environment file payload as text."""
    if framework != "codex":
        raise ValueError("benchmark env currently supports framework=codex")
    return "\n".join(
        [
            "# ClawSentry benchmark environment",
            "CS_MODE=benchmark",
            f"CS_BENCHMARK_PROFILE={mode}",
            "CS_BENCHMARK_AUTO_RESOLVE_DEFER=true",
            "CS_DEFER_BRIDGE_ENABLED=false",
            "CS_DEFER_TIMEOUT_ACTION=block",
            "CS_DEFER_TIMEOUT_S=1",
            "CS_FRAMEWORK=codex",
            "",
        ]
    )


def _parse_env_text(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _benchmark_hooks_payload() -> dict[str, object]:
    hooks: dict[str, list[dict[str, object]]] = {}
    for event_name, matcher, message in (
        ("SessionStart", "startup|resume|clear", "ClawSentry Codex session monitor"),
        ("UserPromptSubmit", None, "ClawSentry prompt review"),
        ("PreToolUse", "Bash", "ClawSentry Bash preflight"),
        ("PreToolUse", _BENCHMARK_NON_BASH_TOOL_MATCHER, "ClawSentry tool preflight observer"),
        ("PermissionRequest", "Bash", "ClawSentry approval gate"),
        ("PermissionRequest", _BENCHMARK_NON_BASH_TOOL_MATCHER, "ClawSentry approval gate"),
        ("PostToolUse", "Bash", "ClawSentry tool review"),
        ("PostToolUse", _BENCHMARK_NON_BASH_TOOL_MATCHER, "ClawSentry tool review"),
        ("PreCompact", None, "ClawSentry compaction preflight observer"),
        ("PostCompact", None, "ClawSentry compaction observer"),
        ("Stop", None, "ClawSentry session finalization"),
    ):
        entry: dict[str, object] = {
            "hooks": [
                {
                    "type": "command",
                    "command": _render_hook_command(event_name, matcher),
                    "statusMessage": message,
                }
            ],
        }
        if matcher is not None:
            entry["matcher"] = matcher
        hooks.setdefault(event_name, []).append(entry)
    return {"hooks": hooks}


def _is_benchmark_hook(entry: object) -> bool:
    return isinstance(entry, dict) and "clawsentry harness --framework codex" in str(entry)


def _load_codex_hooks(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"hooks": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"hooks": {}}
    if not isinstance(payload, dict):
        return {"hooks": {}}
    return payload


def _save_codex_hooks(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _enable_codex_feature_flag(config_path: Path) -> None:
    config_text = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    config_path.write_text(_enable_codex_hooks_feature(config_text), encoding="utf-8")


def _merge_benchmark_hooks(existing: dict[str, object]) -> dict[str, object]:
    hooks = existing.get("hooks")
    if not isinstance(hooks, dict):
        hooks = {}
        existing["hooks"] = hooks

    payload = _benchmark_hooks_payload()
    for event_name, entries in payload.get("hooks", {}).items():
        current = hooks.get(event_name)
        current_entries = list(current) if isinstance(current, list) else []
        current_entries = [entry for entry in current_entries if not _is_benchmark_hook(entry)]
        current_entries.extend(entries)
        hooks[event_name] = current_entries

    existing["hooks"] = hooks
    return existing


def run_benchmark_env(
    *,
    framework: str = "codex",
    mode: str = "guarded",
    output_path: Path | None = None,
) -> int:
    content = render_benchmark_env(framework=framework, mode=mode)
    if output_path is None:
        print(content, end="")
    else:
        output_path.write_text(content, encoding="utf-8")
        print(f"Wrote {output_path}")
    return 0


def run_benchmark_enable(
    *,
    target_dir: Path,
    framework: str = "codex",
    mode: str = "guarded",
    codex_home: Path | None = None,
    force_user_home: bool = False,
) -> int:
    if framework != "codex":
        raise ValueError("benchmark enable currently supports framework=codex")
    home = _require_safe_codex_home(codex_home, force_user_home=force_user_home)

    home.mkdir(parents=True, exist_ok=True)
    config_path = home / "config.toml"
    hooks_path = home / "hooks.json"
    config_backup_path = home / "config.toml.clawsentry-benchmark.bak"
    backup_path = home / "hooks.json.clawsentry-benchmark.bak"

    if config_path.exists() and not config_backup_path.exists():
        shutil.copy2(config_path, config_backup_path)
    _enable_codex_feature_flag(config_path)

    payload = _load_codex_hooks(hooks_path)
    desired = _benchmark_hooks_payload()
    if hooks_path.exists() and payload != desired and not backup_path.exists():
        shutil.copy2(hooks_path, backup_path)

    merged_hooks = _merge_benchmark_hooks(dict(payload))
    config_text = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    config_path.write_text(
        _trust_clawsentry_codex_hooks(
            config_text,
            hooks_path=hooks_path,
            hooks_payload=merged_hooks,
        ),
        encoding="utf-8",
    )
    _save_codex_hooks(hooks_path, merged_hooks)

    env_path = target_dir / BENCHMARK_ENV_FILE_NAME
    if not env_path.exists():
        run_benchmark_env(
            framework=framework,
            mode=mode,
            output_path=env_path,
        )

    print(f"Benchmark mode enabled for {framework}; CODEX_HOME={home}")
    return 0


def run_benchmark_disable(
    *,
    target_dir: Path,
    framework: str = "codex",
    codex_home: Path | None = None,
    force_user_home: bool = False,
) -> int:
    if framework != "codex":
        raise ValueError("benchmark disable currently supports framework=codex")
    home = _require_safe_codex_home(codex_home, force_user_home=force_user_home)

    hooks_path = home / "hooks.json"
    config_path = home / "config.toml"
    payload = _load_codex_hooks(hooks_path)
    trust_keys = [
        key
        for key, _hash in _clawsentry_codex_hook_trust_states(
            hooks_path=hooks_path,
            hooks_payload=payload,
        )
    ]
    hooks = payload.get("hooks")
    if isinstance(hooks, dict):
        for event_name, entries in list(hooks.items()):
            if not isinstance(entries, list):
                continue
            filtered = [entry for entry in entries if not _is_benchmark_hook(entry)]
            if filtered:
                hooks[event_name] = filtered
            else:
                hooks.pop(event_name, None)
        payload["hooks"] = hooks

    backup_path = home / "hooks.json.clawsentry-benchmark.bak"
    if backup_path.exists():
        shutil.move(str(backup_path), str(hooks_path))
    elif hooks_path.exists():
        if isinstance(payload.get("hooks"), dict) and payload["hooks"]:
            _save_codex_hooks(hooks_path, payload)
        else:
            hooks_path.unlink()

    config_backup_path = home / "config.toml.clawsentry-benchmark.bak"
    if config_backup_path.exists():
        shutil.move(str(config_backup_path), str(config_path))
    elif config_path.exists() and trust_keys:
        config_path.write_text(
            _remove_codex_hook_state_sections(
                config_path.read_text(encoding="utf-8"),
                trust_keys,
            ),
            encoding="utf-8",
        )

    # Remove benchmark env artifact that this helper writes.
    (target_dir / BENCHMARK_ENV_FILE_NAME).unlink(missing_ok=True)

    print(f"Benchmark mode disabled for {framework}; CODEX_HOME={home}")
    return 0


def run_benchmark_run(
    *,
    target_dir: Path,
    framework: str = "codex",
    mode: str = "guarded",
    codex_home: Path | None = None,
    command: Sequence[str] = (),
    keep_artifacts: bool = False,
    force_user_home: bool = False,
) -> int:
    if framework != "codex":
        raise ValueError("benchmark run currently supports framework=codex")

    env_path = target_dir / BENCHMARK_ENV_FILE_NAME
    existing_env_text = env_path.read_text(encoding="utf-8") if env_path.exists() else None

    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    home: Path
    if codex_home is None:
        temp_dir = tempfile.TemporaryDirectory(prefix="clawsentry-benchmark-", dir=str(target_dir))
        home = Path(temp_dir.name)
    else:
        home = _require_safe_codex_home(codex_home, force_user_home=force_user_home)

    command_list = list(command)
    if command_list and command_list[0] == "--":
        command_list = command_list[1:]

    env = dict(os.environ)
    env.update(_parse_env_text(render_benchmark_env(framework=framework, mode=mode)))
    env["CODEX_HOME"] = str(home)

    try:
        run_benchmark_enable(
            target_dir=target_dir,
            framework=framework,
            mode=mode,
            codex_home=home,
            force_user_home=force_user_home,
        )

        if not command_list:
            print("Benchmark environment prepared; no command supplied.")
            return 0

        return subprocess.run(command_list, cwd=target_dir, env=env, check=False).returncode
    finally:
        if keep_artifacts:
            if existing_env_text is not None:
                env_path.write_text(existing_env_text, encoding="utf-8")
        else:
            run_benchmark_disable(
                target_dir=target_dir,
                framework=framework,
                codex_home=home,
                force_user_home=force_user_home,
            )
        if not keep_artifacts and existing_env_text is not None:
            env_path.write_text(existing_env_text, encoding="utf-8")

        if temp_dir is not None:
            temp_dir.cleanup()
