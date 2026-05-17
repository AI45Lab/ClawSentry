"""Claude Code framework initializer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .base import LOCAL_ENV_FILE_EXAMPLE, InitResult, merge_project_framework_config


_CLAWSENTRY_HOOK_MARKER = "clawsentry-harness"

# Hook types ClawSentry monitors
_HOOK_TYPES: dict[str, bool] = {
    "PreToolUse": True,     # blocking
    "UserPromptSubmit": True,  # blocking
    "PostToolUse": False,   # async
    "SessionStart": False,
    "SessionEnd": False,
}


def _build_hook_entry(hook_type: str, blocking: bool) -> dict[str, Any]:
    """Build a single Claude Code hook configuration entry."""
    cmd = "clawsentry-harness --framework claude-code"
    if not blocking:
        cmd += " --async"
    return {
        "matcher": "",
        "hooks": [{"type": "command", "command": cmd}],
    }


def _merge_settings(existing: dict[str, Any], new_hooks: dict[str, Any]) -> dict[str, Any]:
    """Merge new hooks into existing settings, preserving all other keys."""
    merged = dict(existing)
    existing_hooks = merged.get("hooks", {})
    if not isinstance(existing_hooks, dict):
        existing_hooks = {}

    for hook_type, entries in new_hooks.items():
        current = existing_hooks.get(hook_type)
        if isinstance(current, list):
            if any(_CLAWSENTRY_HOOK_MARKER in str(h) for h in current):
                continue  # Already installed, skip
            # Append to existing hooks instead of replacing them
            existing_hooks[hook_type] = current + entries
        else:
            existing_hooks[hook_type] = entries

    merged["hooks"] = existing_hooks
    return merged


class ClaudeCodeInitializer:
    """Generate configuration for Claude Code integration."""

    framework_name: str = "claude-code"

    def generate_config(
        self,
        target_dir: Path,
        *,
        force: bool = False,
        claude_home: Path | None = None,
        **_kwargs: object,
    ) -> InitResult:
        warnings: list[str] = []
        files_created: list[Path] = []

        _, env_vars = merge_project_framework_config(
            target_dir,
            framework=self.framework_name,
            force=force,
        )

        # --- ~/.claude/settings.json (hooks) ---
        # Write hooks to settings.json (not settings.local.json) to ensure
        # they survive project-level settings.local.json overrides.
        # Claude Code merges settings from multiple files, but project-level
        # settings.local.json may shadow the global one for some keys.
        effective_claude_home = claude_home or Path.home() / ".claude"
        settings_path = effective_claude_home / "settings.json"

        new_hooks: dict[str, Any] = {}
        for hook_type, blocking in _HOOK_TYPES.items():
            new_hooks[hook_type] = [_build_hook_entry(hook_type, blocking)]

        existing_settings: dict[str, Any] = {}
        if settings_path.exists():
            try:
                existing_settings = json.loads(settings_path.read_text())
            except (json.JSONDecodeError, OSError):
                warnings.append(f"Could not parse {settings_path}, will create fresh")
                existing_settings = {}

        merged = _merge_settings(existing_settings, new_hooks)

        effective_claude_home.mkdir(parents=True, exist_ok=True)
        settings_path.write_text(json.dumps(merged, indent=2) + "\n")
        files_created.append(settings_path)

        next_steps = [
            f"Optional local secrets: clawsentry start --env-file {LOCAL_ENV_FILE_EXAMPLE}",
            "clawsentry gateway    # start Gateway on UDS + HTTP :8080",
            "claude                 # hooks auto-loaded from ~/.claude/settings.json",
            "clawsentry watch --token <startup-token>    # real-time monitoring",
        ]

        return InitResult(
            files_created=files_created,
            env_vars=env_vars,
            next_steps=next_steps,
            warnings=warnings,
        )

    def uninstall(self, *, claude_home: Path | None = None) -> InitResult:
        """Remove ClawSentry hooks from Claude Code settings.

        Cleans hooks from both ``settings.json`` and ``settings.local.json``
        to handle installations from older versions that wrote to
        ``settings.local.json``.
        """
        effective_claude_home = claude_home or Path.home() / ".claude"
        warnings: list[str] = []
        cleaned_any = False

        # Clean hooks from both settings files (current=settings.json, legacy=settings.local.json)
        for filename in ("settings.json", "settings.local.json"):
            settings_path = effective_claude_home / filename
            if not settings_path.exists():
                continue

            try:
                settings = json.loads(settings_path.read_text())
            except (json.JSONDecodeError, OSError) as exc:
                warnings.append(f"Could not parse {settings_path}: {exc}")
                continue

            hooks = settings.get("hooks", {})
            if not isinstance(hooks, dict):
                continue

            changed = False
            for hook_type in list(hooks.keys()):
                entries = hooks[hook_type]
                if isinstance(entries, list):
                    filtered = [e for e in entries if _CLAWSENTRY_HOOK_MARKER not in str(e)]
                    if len(filtered) != len(entries):
                        changed = True
                    if filtered:
                        hooks[hook_type] = filtered
                    else:
                        del hooks[hook_type]

            if changed:
                if not hooks and "hooks" in settings:
                    del settings["hooks"]
                settings_path.write_text(json.dumps(settings, indent=2) + "\n")
                cleaned_any = True

        if not cleaned_any:
            warnings.append("No ClawSentry hooks found in settings files")

        return InitResult(
            files_created=[],
            env_vars={},
            next_steps=["ClawSentry hooks removed. Restart Claude Code for changes to take effect."],
            warnings=warnings,
        )
