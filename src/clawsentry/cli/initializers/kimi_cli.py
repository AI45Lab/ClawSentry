"""Kimi CLI framework initializer."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from .base import LOCAL_ENV_FILE_EXAMPLE, InitResult, SetupResult, merge_project_framework_config

_KIMI_HOOK_MARKER = "clawsentry harness --framework kimi-cli"
_KIMI_HOOK_COMMAND_SYNC = 'clawsentry harness --framework kimi-cli 2>>"${CS_HARNESS_DIAG_LOG:-/dev/null}"'
_KIMI_HOOK_COMMAND_ASYNC = 'clawsentry harness --framework kimi-cli --async 2>>"${CS_HARNESS_DIAG_LOG:-/dev/null}"'
_KIMI_SYNC_EVENTS = {"PreToolUse", "UserPromptSubmit", "Stop"}
_KIMI_HOOK_EVENTS: tuple[tuple[str, str, str], ...] = (
    ("PreToolUse", "", "ClawSentry Kimi tool preflight"),
    ("PostToolUse", "", "ClawSentry Kimi tool-result observation"),
    ("PostToolUseFailure", "", "ClawSentry Kimi tool-failure observation"),
    ("UserPromptSubmit", "", "ClawSentry Kimi prompt gate"),
    ("Stop", "", "ClawSentry Kimi stop/session gate"),
    ("StopFailure", "", "ClawSentry Kimi stop-failure observation"),
    ("SessionStart", "", "ClawSentry Kimi session-start observation"),
    ("SessionEnd", "", "ClawSentry Kimi session-end observation"),
    ("SubagentStart", "", "ClawSentry Kimi subagent-start observation"),
    ("SubagentStop", "", "ClawSentry Kimi subagent-stop observation"),
    ("PreCompact", "", "ClawSentry Kimi pre-compact observation"),
    ("PostCompact", "", "ClawSentry Kimi post-compact observation"),
    ("Notification", "", "ClawSentry Kimi notification observation"),
)


class KimiCLIInitializer:
    """Generate safe Kimi CLI integration configuration."""

    framework_name: str = "kimi-cli"

    def generate_config(
        self,
        target_dir: Path,
        *,
        force: bool = False,
        kimi_home: Path | None = None,
        **_kwargs: object,
    ) -> InitResult:
        _, env_vars = merge_project_framework_config(
            target_dir,
            framework=self.framework_name,
            force=force,
        )
        kimi_config_path = _kimi_config_path(kimi_home=kimi_home)
        runtime_context = _kimi_runtime_context(kimi_config_path)
        env_vars["CS_KIMI_CONFIG_PATH"] = str(kimi_config_path)
        env_vars["CS_KIMI_HOOKS_ENABLED"] = "true"
        env_vars["CS_KIMI_SKILLS_DIR"] = runtime_context["CS_KIMI_SKILLS_DIR"]
        env_vars["CS_SKILL_TRUST_REGISTRY_PATH"] = runtime_context["CS_SKILL_TRUST_REGISTRY_PATH"]
        env_vars["CS_SKILL_TRUST_METADATA_PATH"] = runtime_context["CS_SKILL_TRUST_METADATA_PATH"]
        if os.environ.get("KIMI_SHARE_DIR"):
            env_vars["KIMI_SHARE_DIR"] = str(kimi_config_path.parent)

        next_steps = [
            f"Optional local secrets: clawsentry start --env-file {LOCAL_ENV_FILE_EXAMPLE}",
            (
                'Optional skill trust: clawsentry skill-trust register-dir --skills-dir "$CS_KIMI_SKILLS_DIR" '
                '--registry "$CS_SKILL_TRUST_REGISTRY_PATH" --metadata "$CS_SKILL_TRUST_METADATA_PATH" '
                "--framework kimi-cli --scope workspace"
            ),
            "clawsentry gateway    # start Gateway for Kimi hook decisions",
            "clawsentry init kimi-cli --setup --dry-run    # preview Kimi config.toml hook changes",
            "clawsentry init kimi-cli --setup              # install ClawSentry-managed Kimi hooks",
            "kimi --help                                  # use Kimi CLI with native hooks enabled",
        ]
        return InitResult(
            files_created=[],
            env_vars=env_vars,
            next_steps=next_steps,
            warnings=[],
        )

    def setup_kimi_hooks(
        self,
        *,
        target_dir: Path,
        kimi_home: Path | None = None,
        dry_run: bool = False,
    ) -> SetupResult:
        """Install marker-managed Kimi ``[[hooks]]`` entries.

        Kimi reads ``KIMI_SHARE_DIR/config.toml`` when ``KIMI_SHARE_DIR`` is set,
        otherwise ``~/.kimi/config.toml``. Existing non-ClawSentry TOML content
        and user hooks are preserved; only hook blocks containing the ClawSentry
        marker command are replaced.
        """
        config_path = _kimi_config_path(kimi_home=kimi_home)
        runtime_context = _kimi_runtime_context(config_path)
        changes = [
            f"Install ClawSentry managed Kimi hook entries in {config_path}",
            f"Bind Kimi skill-trust runtime context to {runtime_context['CS_KIMI_SKILLS_DIR']}",
            "Preserve non-ClawSentry Kimi hooks and TOML content",
        ]
        files_modified = [config_path]
        warnings: list[str] = []

        if dry_run:
            return SetupResult(
                changes_applied=changes,
                files_modified=files_modified,
                files_backed_up=[],
                warnings=warnings,
                dry_run=True,
            )

        config_path.parent.mkdir(parents=True, exist_ok=True)
        existing = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
        merged = _merge_kimi_hooks(existing, runtime_context=runtime_context)
        config_path.write_text(merged, encoding="utf-8")
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
        kimi_home: Path | None = None,
    ) -> InitResult:
        """Remove only ClawSentry-managed Kimi hook blocks."""
        config_path = _kimi_config_path(kimi_home=kimi_home)
        warnings: list[str] = []
        if not config_path.exists():
            warnings.append(f"{config_path} does not exist; no Kimi hooks were removed.")
            return InitResult(
                files_created=[],
                env_vars={},
                next_steps=["No ClawSentry Kimi CLI hooks were found."],
                warnings=warnings,
            )

        existing = config_path.read_text(encoding="utf-8")
        cleaned, removed = _remove_clawsentry_kimi_hook_blocks(existing)
        if removed:
            config_path.write_text(cleaned, encoding="utf-8")
            next_steps = ["ClawSentry Kimi CLI hooks removed. Restart Kimi CLI for changes to take effect."]
        else:
            warnings.append("No ClawSentry Kimi CLI hooks found in config.toml")
            next_steps = ["No ClawSentry Kimi CLI hooks were found."]
        return InitResult(
            files_created=[],
            env_vars={},
            next_steps=next_steps,
            warnings=warnings,
        )


def _kimi_config_path(*, kimi_home: Path | None = None) -> Path:
    if kimi_home is not None:
        return kimi_home.expanduser() / "config.toml"
    if share_dir := os.environ.get("KIMI_SHARE_DIR"):
        return Path(share_dir).expanduser() / "config.toml"
    return Path.home() / ".kimi" / "config.toml"


def _kimi_runtime_context(kimi_config_path: Path) -> dict[str, str]:
    runtime_dir = kimi_config_path.parent / "clawsentry"
    return {
        "CS_KIMI_CONFIG_PATH": str(kimi_config_path),
        "KIMI_SHARE_DIR": str(kimi_config_path.parent),
        "CS_KIMI_SKILLS_DIR": os.environ.get(
            "CS_KIMI_SKILLS_DIR",
            str(Path.home() / ".claude" / "skills"),
        ),
        "CS_SKILL_TRUST_REGISTRY_PATH": os.environ.get(
            "CS_SKILL_TRUST_REGISTRY_PATH",
            str(runtime_dir / "skill-registry.json"),
        ),
        "CS_SKILL_TRUST_METADATA_PATH": os.environ.get(
            "CS_SKILL_TRUST_METADATA_PATH",
            str(runtime_dir / "skill-trust-raw.json"),
        ),
    }


def _merge_kimi_hooks(existing: str, *, runtime_context: dict[str, str] | None = None) -> str:
    cleaned, _removed = _remove_clawsentry_kimi_hook_blocks(existing)
    cleaned = cleaned.rstrip()
    blocks = "\n\n".join(
        _build_kimi_hook_block(
            event,
            matcher,
            description,
            runtime_context=runtime_context or {},
        )
        for event, matcher, description in _KIMI_HOOK_EVENTS
    )
    if cleaned:
        return f"{cleaned}\n\n{blocks}\n"
    return f"{blocks}\n"


def _remove_clawsentry_kimi_hook_blocks(text: str) -> tuple[str, int]:
    """Remove ``[[hooks]]`` blocks containing the ClawSentry command marker."""
    lines = text.splitlines(keepends=True)
    blocks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip() == "[[hooks]]" and current:
            blocks.append(current)
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append(current)

    kept: list[str] = []
    removed = 0
    for block in blocks:
        block_text = "".join(block)
        is_hook_block = any(line.strip() == "[[hooks]]" for line in block)
        if is_hook_block and _KIMI_HOOK_MARKER in block_text:
            removed += 1
            continue
        kept.append(block_text)
    output = "".join(kept).rstrip() + ("\n" if kept else "")
    return output, removed


def _build_kimi_hook_block(
    event: str,
    matcher: str,
    description: str,
    *,
    runtime_context: dict[str, str],
) -> str:
    command = _kimi_hook_command(event, runtime_context=runtime_context)
    fields = [
        "[[hooks]]",
        f'event = "{_toml_escape(event)}"',
        f'matcher = "{_toml_escape(matcher)}"',
        f'command = "{_toml_escape(command)}"',
        "timeout = 30",
        f'# {description}',
    ]
    return "\n".join(fields)


def _kimi_hook_command(event: str, *, runtime_context: dict[str, str]) -> str:
    command = _KIMI_HOOK_COMMAND_SYNC if event in _KIMI_SYNC_EVENTS else _KIMI_HOOK_COMMAND_ASYNC
    assignments = [
        _shell_default_env_assignment(name, runtime_context[name])
        for name in (
            "CS_KIMI_CONFIG_PATH",
            "KIMI_SHARE_DIR",
            "CS_KIMI_SKILLS_DIR",
            "CS_SKILL_TRUST_REGISTRY_PATH",
            "CS_SKILL_TRUST_METADATA_PATH",
        )
        if runtime_context.get(name)
    ]
    if not assignments:
        return command
    return f"{' '.join(assignments)} {command}"


def _shell_default_env_assignment(name: str, value: str) -> str:
    escaped = (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
    )
    return f'{name}="${{{name}:-{escaped}}}"'


def _toml_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')
