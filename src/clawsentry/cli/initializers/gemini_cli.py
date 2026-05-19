"""Gemini CLI framework initializer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import LOCAL_ENV_FILE_EXAMPLE, InitResult, SetupResult, merge_project_framework_config


_GEMINI_HOOK_MARKER = "clawsentry harness --framework gemini-cli"
_GEMINI_HOOK_COMMAND_SYNC = (
    "sh -c 'PATH=\"${HOME}/.local/bin:${PATH}\"; clawsentry harness --framework gemini-cli "
    "2>>\"${CS_HARNESS_DIAG_LOG:-/dev/null}\" || true'"
)
_GEMINI_HOOK_COMMAND_ASYNC = (
    "sh -c 'PATH=\"${HOME}/.local/bin:${PATH}\"; clawsentry harness --framework gemini-cli --async "
    "2>>\"${CS_HARNESS_DIAG_LOG:-/dev/null}\" || true'"
)
_GEMINI_SYNC_EVENTS = {
    "BeforeAgent",
    "AfterAgent",
    "BeforeModel",
    "AfterModel",
    "BeforeTool",
    "AfterTool",
}
_GEMINI_HOOK_EVENTS: tuple[tuple[str, str | None, str], ...] = (
    ("SessionStart", None, "ClawSentry Gemini session monitor"),
    ("SessionEnd", None, "ClawSentry Gemini session finalization"),
    ("BeforeAgent", None, "ClawSentry Gemini prompt gate"),
    ("AfterAgent", None, "ClawSentry Gemini response review"),
    ("BeforeModel", None, "ClawSentry Gemini model-request gate"),
    ("AfterModel", None, "ClawSentry Gemini model-response review"),
    ("BeforeToolSelection", None, "ClawSentry Gemini tool-selection advisory"),
    ("BeforeTool", None, "ClawSentry Gemini tool preflight"),
    ("AfterTool", None, "ClawSentry Gemini tool-result review"),
    ("PreCompress", None, "ClawSentry Gemini compression advisory"),
    ("Notification", None, "ClawSentry Gemini notification monitor"),
)


class GeminiCLIInitializer:
    """Generate project-local configuration for Gemini CLI integration."""

    framework_name: str = "gemini-cli"

    def generate_config(
        self,
        target_dir: Path,
        *,
        force: bool = False,
        gemini_home: Path | None = None,
        **_kwargs: object,
    ) -> InitResult:
        settings_path = _gemini_settings_path(target_dir, gemini_home=gemini_home)
        warnings: list[str] = []

        _, env_vars = merge_project_framework_config(
            target_dir,
            framework=self.framework_name,
            force=force,
        )
        env_vars["CS_GEMINI_SETTINGS_PATH"] = str(settings_path)

        next_steps = [
            f"Optional local secrets: clawsentry start --env-file {LOCAL_ENV_FILE_EXAMPLE}",
            "clawsentry gateway    # start Gateway for Gemini hook decisions",
            "clawsentry init gemini-cli --setup --dry-run    # preview project-local .gemini/settings.json hook changes",
            "clawsentry init gemini-cli --setup              # install project-local Gemini hooks",
            "gemini --prompt 'say hello'                    # use Gemini CLI in this project",
        ]
        return InitResult(
            files_created=[],
            env_vars=env_vars,
            next_steps=next_steps,
            warnings=warnings,
        )

    def setup_gemini_hooks(
        self,
        *,
        target_dir: Path,
        gemini_home: Path | None = None,
        dry_run: bool = False,
    ) -> SetupResult:
        """Install non-destructive Gemini CLI managed hook entries.

        By default this writes only ``<target_dir>/.gemini/settings.json``.
        Passing ``gemini_home`` explicitly targets ``<gemini_home>/settings.json``.
        Existing non-ClawSentry settings and hook entries are preserved.
        """
        settings_path = _gemini_settings_path(target_dir, gemini_home=gemini_home)
        changes = [
            f"Enable Gemini CLI hooks in {settings_path}",
            f"Install ClawSentry managed hook entries in {settings_path}",
        ]
        files_modified = [settings_path]
        warnings: list[str] = []

        if dry_run:
            return SetupResult(
                changes_applied=changes,
                files_modified=files_modified,
                files_backed_up=[],
                warnings=warnings,
                dry_run=True,
            )

        settings_path.parent.mkdir(parents=True, exist_ok=True)
        payload = _load_gemini_settings(settings_path, warnings)
        merged = _merge_gemini_hooks(payload)
        settings_path.write_text(
            json.dumps(merged, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return SetupResult(
            changes_applied=changes,
            files_modified=files_modified,
            files_backed_up=[],
            warnings=warnings,
            dry_run=False,
        )

    def uninstall(
        self,
        *,
        target_dir: Path,
        gemini_home: Path | None = None,
    ) -> InitResult:
        """Remove only ClawSentry-managed Gemini CLI hook entries."""
        settings_path = _gemini_settings_path(target_dir, gemini_home=gemini_home)
        warnings: list[str] = []
        if not settings_path.exists():
            warnings.append(f"{settings_path} does not exist; no Gemini hooks were removed.")
            return InitResult(
                files_created=[],
                env_vars={},
                next_steps=["No ClawSentry Gemini CLI hooks were found."],
                warnings=warnings,
            )

        payload = _load_gemini_settings(settings_path, warnings)
        cleaned, removed = _remove_clawsentry_gemini_hooks(payload)
        if removed:
            settings_path.write_text(
                json.dumps(cleaned, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            next_steps = ["ClawSentry Gemini CLI hooks removed. Restart Gemini CLI for changes to take effect."]
        else:
            warnings.append("No ClawSentry Gemini CLI hooks found in settings.json")
            next_steps = ["No ClawSentry Gemini CLI hooks were found."]
        return InitResult(
            files_created=[],
            env_vars={},
            next_steps=next_steps,
            warnings=warnings,
        )


def _gemini_settings_path(target_dir: Path, *, gemini_home: Path | None = None) -> Path:
    if gemini_home is not None:
        return gemini_home.expanduser() / "settings.json"
    return target_dir / ".gemini" / "settings.json"


def _load_gemini_settings(path: Path, warnings: list[str]) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        warnings.append(f"Could not parse {path}, creating fresh settings.json: {exc}")
        return {}
    if not isinstance(payload, dict):
        warnings.append(f"{path} must contain a JSON object; creating fresh settings.json")
        return {}
    return payload


def _merge_gemini_hooks(existing: dict[str, Any]) -> dict[str, Any]:
    merged = dict(existing)
    hooks_config = dict(merged.get("hooksConfig") or {})
    hooks_config["enabled"] = True
    merged["hooksConfig"] = hooks_config

    hooks = dict(merged.get("hooks") or {})
    hooks.pop("enabled", None)
    for event_name, matcher, description in _GEMINI_HOOK_EVENTS:
        current = hooks.get(event_name)
        entries = list(current) if isinstance(current, list) else []
        entries = [entry for entry in entries if not _is_clawsentry_gemini_hook_entry(entry)]
        entries.append(_build_gemini_hook_entry(event_name, matcher, description))
        hooks[event_name] = entries
    merged["hooks"] = hooks
    return merged


def _remove_clawsentry_gemini_hooks(existing: dict[str, Any]) -> tuple[dict[str, Any], int]:
    cleaned = dict(existing)
    hooks = dict(cleaned.get("hooks") or {})
    removed = 0
    for event_name in list(hooks.keys()):
        entries = hooks[event_name]
        if not isinstance(entries, list):
            continue
        filtered = []
        for entry in entries:
            if _is_clawsentry_gemini_hook_entry(entry):
                removed += 1
            else:
                filtered.append(entry)
        if filtered:
            hooks[event_name] = filtered
        else:
            del hooks[event_name]
    cleaned["hooks"] = hooks
    return cleaned, removed


def _is_clawsentry_gemini_hook_entry(entry: Any) -> bool:
    return isinstance(entry, dict) and _GEMINI_HOOK_MARKER in str(entry)


def _build_gemini_hook_entry(
    event_name: str,
    matcher: str | None,
    description: str,
) -> dict[str, Any]:
    command = _GEMINI_HOOK_COMMAND_SYNC if event_name in _GEMINI_SYNC_EVENTS else _GEMINI_HOOK_COMMAND_ASYNC
    entry: dict[str, Any] = {
        "hooks": [
            {
                "type": "command",
                "name": f"clawsentry-{event_name}",
                "command": command,
                "description": description,
            }
        ]
    }
    if matcher is not None:
        entry["matcher"] = matcher
    return entry
