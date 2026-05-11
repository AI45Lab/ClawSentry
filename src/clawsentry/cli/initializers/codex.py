"""Codex framework initializer."""

from __future__ import annotations

import hashlib
import json
import os
import tomllib
from pathlib import Path
from typing import Any

from .base import LOCAL_ENV_FILE_EXAMPLE, InitResult, SetupResult, merge_project_framework_config


_CODEX_HOOK_MARKER = "clawsentry harness --framework codex"
_CODEX_HOOK_COMMAND_SYNC = "clawsentry harness --framework codex"
_CODEX_HOOK_COMMAND_ASYNC = "clawsentry harness --framework codex --async"
_CODEX_NON_BASH_TOOL_MATCHER = "apply_patch|Edit|Write|mcp__.*"
_CODEX_HOOK_EVENTS: tuple[tuple[str, str | None, str], ...] = (
    ("SessionStart", "startup|resume|clear", "ClawSentry Codex session monitor"),
    ("UserPromptSubmit", None, "ClawSentry prompt review"),
    ("PreToolUse", "Bash", "ClawSentry Bash preflight"),
    ("PreToolUse", _CODEX_NON_BASH_TOOL_MATCHER, "ClawSentry tool preflight observer"),
    ("PermissionRequest", "Bash", "ClawSentry approval gate"),
    ("PermissionRequest", _CODEX_NON_BASH_TOOL_MATCHER, "ClawSentry approval gate"),
    ("PostToolUse", "Bash", "ClawSentry tool review"),
    ("PostToolUse", _CODEX_NON_BASH_TOOL_MATCHER, "ClawSentry tool review"),
    ("PreCompact", None, "ClawSentry compaction preflight observer"),
    ("PostCompact", None, "ClawSentry compaction observer"),
    ("Stop", None, "ClawSentry session finalization"),
)


class CodexInitializer:
    """Generate configuration for Codex integration."""

    framework_name: str = "codex"

    def generate_config(
        self,
        target_dir: Path,
        *,
        force: bool = False,
        **_kwargs: object,
    ) -> InitResult:
        warnings: list[str] = []
        files_created: list[Path] = []

        _, env_vars = merge_project_framework_config(
            target_dir,
            framework=self.framework_name,
            force=force,
        )

        next_steps = [
            f"Optional local secrets: clawsentry start --env-file {LOCAL_ENV_FILE_EXAMPLE}",
            "Optional native hooks: clawsentry init codex --setup",
            "clawsentry doctor     # verify Codex env and optional hook shape",
            "clawsentry gateway    # start Gateway (auto-monitors Codex sessions)",
            "codex                  # use Codex normally",
            "clawsentry watch      # real-time risk evaluation (another terminal)",
        ]

        return InitResult(
            files_created=files_created,
            env_vars=env_vars,
            next_steps=next_steps,
            warnings=warnings,
        )

    def setup_codex_hooks(
        self,
        *,
        codex_home: Path | None = None,
        dry_run: bool = False,
    ) -> SetupResult:
        """Install non-destructive Codex native hook registration.

        The installer owns only entries whose command contains the
        ClawSentry Codex marker.  Existing user/OMX hook entries are
        preserved and ClawSentry entries are idempotently refreshed.
        """
        effective_codex_home = codex_home or Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
        config_path = effective_codex_home / "config.toml"
        hooks_path = effective_codex_home / "hooks.json"

        warnings: list[str] = []
        files_modified = [config_path, hooks_path]
        changes = [
            f"Enable Codex native hooks in {config_path}",
            f"Install ClawSentry managed hook entries in {hooks_path}",
            f"Trust ClawSentry managed hook commands in {config_path}",
        ]

        if dry_run:
            return SetupResult(
                changes_applied=changes,
                files_modified=files_modified,
                files_backed_up=[],
                warnings=warnings,
                dry_run=True,
            )

        effective_codex_home.mkdir(parents=True, exist_ok=True)
        config_text = _enable_codex_hooks_feature(
            config_path.read_text(encoding="utf-8") if config_path.exists() else ""
        )
        hooks_payload = _load_codex_hooks(hooks_path, warnings)
        merged_hooks = _merge_codex_hooks(hooks_payload)
        config_path.write_text(
            _trust_clawsentry_codex_hooks(
                config_text,
                hooks_path=hooks_path,
                hooks_payload=merged_hooks,
            ),
            encoding="utf-8",
        )
        hooks_path.write_text(
            json.dumps(merged_hooks, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        return SetupResult(
            changes_applied=changes,
            files_modified=files_modified,
            files_backed_up=[],
            warnings=warnings,
            dry_run=False,
        )

    def uninstall(self, *, codex_home: Path | None = None) -> InitResult:
        """Remove only ClawSentry-managed Codex native hook entries."""
        effective_codex_home = codex_home or Path(os.environ.get("CODEX_HOME", "~/.codex")).expanduser()
        config_path = effective_codex_home / "config.toml"
        hooks_path = effective_codex_home / "hooks.json"
        warnings: list[str] = []

        if not hooks_path.exists():
            warnings.append(f"{hooks_path} does not exist; no Codex hooks were removed.")
            return InitResult(
                files_created=[],
                env_vars={},
                next_steps=["No ClawSentry Codex hooks were found."],
                warnings=warnings,
            )

        hooks_payload = _load_codex_hooks(hooks_path, warnings)
        trust_keys = [
            key
            for key, _hash in _clawsentry_codex_hook_trust_states(
                hooks_path=hooks_path,
                hooks_payload=hooks_payload,
            )
        ]
        cleaned_payload, removed = _remove_clawsentry_codex_hooks(hooks_payload)
        if removed:
            hooks_path.write_text(
                json.dumps(cleaned_payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            if config_path.exists() and trust_keys:
                config_text = _remove_codex_hook_state_sections(
                    config_path.read_text(encoding="utf-8"),
                    trust_keys,
                )
                config_text = _remove_stale_codex_hook_state_sections(
                    config_text,
                    hooks_path=hooks_path,
                    keep_keys=_codex_hook_state_keys_for_payload(
                        hooks_path=hooks_path,
                        hooks_payload=cleaned_payload,
                    ),
                )
                config_path.write_text(config_text, encoding="utf-8")
            next_steps = ["ClawSentry Codex hooks removed. Restart Codex for changes to take effect."]
        else:
            warnings.append("No ClawSentry Codex hooks found in hooks.json")
            next_steps = ["No ClawSentry Codex hooks were found."]

        return InitResult(
            files_created=[],
            env_vars={},
            next_steps=next_steps,
            warnings=warnings,
        )


def _enable_codex_hooks_feature(config_text: str) -> str:
    """Return TOML text with the current Codex hook feature flag enabled."""
    lines = config_text.splitlines()
    output: list[str] = []
    in_features = False
    saw_features = False
    saw_hooks = False

    def append_missing_feature_flags() -> None:
        nonlocal saw_hooks
        if not saw_hooks:
            output.append("hooks = true")
            saw_hooks = True

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_features:
                append_missing_feature_flags()
            in_features = stripped == "[features]"
            saw_features = saw_features or in_features
            output.append(line)
            continue
        if in_features:
            key = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
            if key == "hooks":
                output.append("hooks = true")
                saw_hooks = True
                continue
            if key == "codex_hooks":
                continue
        output.append(line)

    if in_features:
        append_missing_feature_flags()
    if not saw_features:
        if output and output[-1].strip():
            output.append("")
        output.append("[features]")
        append_missing_feature_flags()

    return "\n".join(output).rstrip() + "\n"


_CODEX_EVENT_KEY_LABELS = {
    "PreToolUse": "pre_tool_use",
    "PermissionRequest": "permission_request",
    "PostToolUse": "post_tool_use",
    "PreCompact": "pre_compact",
    "PostCompact": "post_compact",
    "SessionStart": "session_start",
    "UserPromptSubmit": "user_prompt_submit",
    "Stop": "stop",
}


def _codex_hook_event_key_label(event_name: str) -> str:
    return _CODEX_EVENT_KEY_LABELS[event_name]


def _codex_hooks_source_key(hooks_path: Path) -> str:
    return str(hooks_path.expanduser().resolve(strict=False))


def _codex_hook_state_key(
    *,
    hooks_path: Path,
    event_name: str,
    group_index: int,
    handler_index: int,
) -> str:
    return (
        f"{_codex_hooks_source_key(hooks_path)}:"
        f"{_codex_hook_event_key_label(event_name)}:{group_index}:{handler_index}"
    )


def _codex_hook_state_keys_for_payload(
    *,
    hooks_path: Path,
    hooks_payload: dict[str, Any],
) -> set[str]:
    hooks = hooks_payload.get("hooks")
    if not isinstance(hooks, dict):
        return set()

    keys: set[str] = set()
    for event_name in _CODEX_EVENT_KEY_LABELS:
        entries = hooks.get(event_name)
        if not isinstance(entries, list):
            continue
        for group_index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            hook_specs = entry.get("hooks")
            if not isinstance(hook_specs, list):
                continue
            for handler_index, hook_spec in enumerate(hook_specs):
                if isinstance(hook_spec, dict) and hook_spec.get("type") == "command":
                    keys.add(
                        _codex_hook_state_key(
                            hooks_path=hooks_path,
                            event_name=event_name,
                            group_index=group_index,
                            handler_index=handler_index,
                        )
                    )
    return keys


def _codex_command_hook_hash(
    *,
    event_name: str,
    matcher: str | None,
    command: str,
    timeout_sec: int = 600,
    async_: bool = False,
    status_message: str | None = None,
) -> str:
    """Return Codex's currentHash for a normalized command hook identity."""

    handler: dict[str, Any] = {
        "type": "command",
        "command": command,
        "timeout": max(timeout_sec, 1),
        "async": async_,
    }
    if status_message is not None:
        handler["statusMessage"] = status_message

    identity: dict[str, Any] = {
        "event_name": _codex_hook_event_key_label(event_name),
        "hooks": [handler],
    }
    # Codex ignores matchers for prompt/stop hooks when hashing.
    if matcher is not None and event_name not in {"UserPromptSubmit", "Stop"}:
        identity["matcher"] = matcher

    serialized = json.dumps(
        identity,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(serialized).hexdigest()}"


def _clawsentry_codex_hook_trust_states(
    *,
    hooks_path: Path,
    hooks_payload: dict[str, Any],
) -> list[tuple[str, str]]:
    """Return ``(hook_state_key, current_hash)`` for ClawSentry-owned hooks."""

    hooks = hooks_payload.get("hooks")
    if not isinstance(hooks, dict):
        return []

    states: list[tuple[str, str]] = []
    for event_name in _CODEX_EVENT_KEY_LABELS:
        entries = hooks.get(event_name)
        if not isinstance(entries, list):
            continue
        for group_index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                continue
            matcher = entry.get("matcher")
            matcher_value = matcher if isinstance(matcher, str) else None
            hook_specs = entry.get("hooks")
            if not isinstance(hook_specs, list):
                continue
            for handler_index, hook_spec in enumerate(hook_specs):
                if not isinstance(hook_spec, dict):
                    continue
                command = hook_spec.get("command")
                if not isinstance(command, str) or _CODEX_HOOK_MARKER not in command:
                    continue
                timeout_raw = hook_spec.get("timeout", 600)
                timeout_sec = timeout_raw if isinstance(timeout_raw, int) else 600
                status_raw = hook_spec.get("statusMessage")
                status_message = status_raw if isinstance(status_raw, str) else None
                states.append(
                    (
                        _codex_hook_state_key(
                            hooks_path=hooks_path,
                            event_name=event_name,
                            group_index=group_index,
                            handler_index=handler_index,
                        ),
                        _codex_command_hook_hash(
                            event_name=event_name,
                            matcher=matcher_value,
                            command=command,
                            timeout_sec=timeout_sec,
                            async_=bool(hook_spec.get("async", False)),
                            status_message=status_message,
                        ),
                    )
                )
    return states


def _trust_clawsentry_codex_hooks(
    config_text: str,
    *,
    hooks_path: Path,
    hooks_payload: dict[str, Any],
) -> str:
    trust_states = _clawsentry_codex_hook_trust_states(
        hooks_path=hooks_path,
        hooks_payload=hooks_payload,
    )
    if not trust_states:
        return config_text

    keys = [key for key, _hash in trust_states]
    output = _remove_codex_hook_state_sections(config_text, keys).rstrip()
    if output:
        output += "\n\n"
    for key, trusted_hash in trust_states:
        output += f"[hooks.state.{_toml_basic_string(key)}]\n"
        output += f"trusted_hash = {_toml_basic_string(trusted_hash)}\n\n"
    return output.rstrip() + "\n"


def _codex_hook_state_trust_issues(
    config_text: str,
    *,
    hooks_path: Path,
    hooks_payload: dict[str, Any],
) -> list[str]:
    expected = _clawsentry_codex_hook_trust_states(
        hooks_path=hooks_path,
        hooks_payload=hooks_payload,
    )
    if not expected:
        return []
    try:
        parsed = tomllib.loads(config_text)
    except tomllib.TOMLDecodeError as exc:
        return [f"config.toml cannot be parsed for hook trust state: {exc}"]
    hook_state = parsed.get("hooks", {}).get("state", {})
    if not isinstance(hook_state, dict):
        hook_state = {}
    issues: list[str] = []
    for key, trusted_hash in expected:
        state = hook_state.get(key)
        found_hash = state.get("trusted_hash") if isinstance(state, dict) else None
        if found_hash != trusted_hash:
            issues.append(f"untrusted or modified Codex hook state: {key}")
    return issues


def _remove_codex_hook_state_sections(config_text: str, keys: list[str]) -> str:
    if not config_text or not keys:
        return config_text
    headers = {_codex_hook_state_header(key) for key in keys}
    output: list[str] = []
    dropping = False
    for line in config_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            dropping = stripped in headers
            if dropping:
                continue
        if not dropping:
            output.append(line)
    return "\n".join(output).rstrip() + ("\n" if output else "")


def _remove_stale_codex_hook_state_sections(
    config_text: str,
    *,
    hooks_path: Path,
    keep_keys: set[str],
) -> str:
    source_prefix = f"{_codex_hooks_source_key(hooks_path)}:"
    stale_keys = [
        key
        for key in _codex_hook_state_section_keys(config_text)
        if key.startswith(source_prefix) and key not in keep_keys
    ]
    return _remove_codex_hook_state_sections(config_text, stale_keys)


def _codex_hook_state_section_keys(config_text: str) -> list[str]:
    keys: list[str] = []
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("[hooks.state.") or not stripped.endswith("]"):
            continue
        raw_key = stripped.removeprefix("[hooks.state.").removesuffix("]")
        try:
            key = json.loads(raw_key)
        except json.JSONDecodeError:
            continue
        if isinstance(key, str):
            keys.append(key)
    return keys


def _codex_hook_state_header(key: str) -> str:
    return f"[hooks.state.{_toml_basic_string(key)}]"


def _toml_basic_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _load_codex_hooks(path: Path, warnings: list[str]) -> dict[str, Any]:
    if not path.exists():
        return {"hooks": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        warnings.append(f"Could not parse {path}, creating fresh hooks.json: {exc}")
        return {"hooks": {}}
    if not isinstance(payload, dict):
        warnings.append(f"{path} must contain a JSON object; creating fresh hooks.json")
        return {"hooks": {}}
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        payload = dict(payload)
        payload["hooks"] = {}
    return payload


def _merge_codex_hooks(existing: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    hooks = dict(merged.get("hooks") or {})
    desired_by_event: dict[str, list[dict[str, Any]]] = {}
    for event_name, matcher, status_message in _CODEX_HOOK_EVENTS:
        desired_by_event.setdefault(event_name, []).append(
            _build_codex_hook_entry(
                event_name=event_name,
                matcher=matcher,
                status_message=status_message,
            )
        )
    for event_name, desired_entries in desired_by_event.items():
        current = hooks.get(event_name)
        entries = list(current) if isinstance(current, list) else []
        entries = [entry for entry in entries if not _is_clawsentry_codex_hook_entry(entry)]
        entries.extend(desired_entries)
        hooks[event_name] = entries
    merged["hooks"] = hooks
    return merged


def _remove_clawsentry_codex_hooks(existing: dict[str, Any]) -> tuple[dict[str, Any], int]:
    cleaned = dict(existing)
    hooks = dict(cleaned.get("hooks") or {})
    removed = 0
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = []
        for entry in entries:
            if _is_clawsentry_codex_hook_entry(entry):
                removed += 1
            else:
                filtered.append(entry)
        if filtered:
            hooks[event_name] = filtered
        else:
            del hooks[event_name]
    cleaned["hooks"] = hooks
    return cleaned, removed


def _is_clawsentry_codex_hook_entry(entry: Any) -> bool:
    return isinstance(entry, dict) and _CODEX_HOOK_MARKER in str(entry)


def _build_codex_hook_entry(
    *,
    event_name: str,
    matcher: str | None,
    status_message: str,
) -> dict[str, Any]:
    command = (
        _CODEX_HOOK_COMMAND_SYNC
        if (
            (event_name == "PreToolUse" and matcher == "Bash")
            or event_name == "PermissionRequest"
        )
        else _CODEX_HOOK_COMMAND_ASYNC
    )
    entry: dict[str, Any] = {
        "hooks": [
            {
                "type": "command",
                "command": command,
                "statusMessage": status_message,
            }
        ]
    }
    if matcher is not None:
        entry["matcher"] = matcher
    return entry
