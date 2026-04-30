"""``clawsentry config`` — inspect and generate env-first configuration."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from .dotenv_loader import (
    EnvFileError,
    discover_local_env_files,
    format_env_file_hint,
    resolve_explicit_env_file,
)
from .initializers import FRAMEWORK_INITIALIZERS
from clawsentry.gateway.detection_config import PRESETS
from clawsentry.gateway.env_config import (
    CONFIG_FIELDS,
    canonical_env_source_for,
    export_instruction,
    resolve_effective_config,
    set_env_file_value,
    write_env_template,
)

ENV_TEMPLATE_NAME = ".clawsentry.env.example"
LOCAL_ENV_TEMPLATE_NAME = ".clawsentry.env.local"
_VALID_MODES = {"normal", "strict", "permissive", "benchmark"}
_VALID_PROVIDERS = {"", "none", "openai", "anthropic"}


def run_config_init(
    *,
    target_dir: Path,
    preset: str = "medium",
    force: bool = False,
    output: Path | None = None,
) -> None:
    """Write a safe env example template; never writes project TOML."""
    if preset not in PRESETS:
        raise ValueError(f"Unknown preset: {preset!r}. Available: {sorted(PRESETS.keys())}")
    path = output or (target_dir / ENV_TEMPLATE_NAME)
    write_env_template(path, preset=preset, force=force)
    print(f"Created env-first template {path} (preset: {preset})")
    print(f"Copy to {LOCAL_ENV_TEMPLATE_NAME} for local secrets, then pass --env-file explicitly.")


def run_config_show(
    *,
    target_dir: Path,
    effective: bool = False,
    env_file: Path | None = None,
) -> None:
    _ = target_dir
    try:
        parsed = resolve_explicit_env_file(cli_env_file=env_file, environ=os.environ)
    except EnvFileError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc
    eff = resolve_effective_config(environ=os.environ, env_file=parsed)
    title = "Effective ClawSentry env-first configuration:" if effective else "ClawSentry env-first defaults/effective environment:"
    print(title)
    for key, value, source in eff.rows():
        field_env = canonical_env_source_for(key)
        detail = eff.source_detail_for(key)
        source_label = source
        if source == "process-env":
            source_label = f"process-env:{detail or field_env or ''}".rstrip(":")
        elif source == "env-file":
            source_label = f"env-file:{detail}" if detail else "env-file"
        elif source == "cli":
            source_label = f"cli:{detail}" if detail else "cli"
        elif source == "deprecated-env-alias":
            source_label = f"deprecated-env-alias:{detail}" if detail else source
        env_suffix = f" env={field_env}" if field_env else ""
        print(f"  {key}: {value} (source={source_label}{env_suffix})")
    for warning in parsed.warnings:
        eff.warnings.append(warning)
    if eff.warnings:
        print("Warnings:")
        for warning in eff.warnings:
            print(f"  - {warning}")
    if parsed.path is None and not os.environ.get("CLAWSENTRY_ENV_FILE"):
        hint_lines = format_env_file_hint(
            discover_local_env_files(target_dir),
            command="clawsentry config show --effective",
        )
        if hint_lines:
            print("Hints:")
            for line in hint_lines:
                print(f"  - {line}")
    print("No project TOML is read. Env-file loading is explicit only.")


def _config_key_to_env(key_or_preset: str, value: str | None) -> tuple[str, str]:
    if value is None and key_or_preset in PRESETS:
        return "CS_PRESET", key_or_preset
    if value is None:
        raise ValueError("value is required unless setting a preset")
    if key_or_preset.startswith("CS_") or key_or_preset in {"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}:
        return key_or_preset, value
    mapping = {field.key: field.env_var for field in CONFIG_FIELDS if field.env_var}
    env_key = mapping.get(key_or_preset)
    if not env_key:
        raise ValueError(f"Unknown config key: {key_or_preset}")
    return env_key, value


def run_config_set(
    *,
    target_dir: Path,
    preset: str | None = None,
    key: str | None = None,
    value: str | None = None,
    env_file: Path | None = None,
    output: Path | None = None,
) -> None:
    """Print an export instruction by default, or update an explicit env file."""
    _ = target_dir
    if key is None:
        if preset not in PRESETS:
            raise ValueError(f"Unknown preset: {preset!r}. Available: {sorted(PRESETS.keys())}")
        env_key, env_value = "CS_PRESET", str(preset)
    else:
        env_key, env_value = _config_key_to_env(key, value)
    target = env_file or output
    if target is None:
        print("No env file target supplied; no files were changed.")
        print(export_instruction(env_key, env_value))
        print("To persist intentionally, rerun with --env-file PATH or --output PATH.")
        return
    set_env_file_value(target, env_key, env_value)
    print(f"Updated {env_key} in explicit env file {target}")


def _print_wizard_header(target_dir: Path) -> None:
    print("+--------------------------------------------+")
    print("| ClawSentry Env-First Setup                 |")
    print("| Interactive env/template configuration     |")
    print("+--------------------------------------------+")
    print(f"Target template: {target_dir / ENV_TEMPLATE_NAME}")
    print()


def _print_wizard_boundary_notes() -> None:
    print("Configuration boundary:")
    print("  - Writes only env template values; project TOML is not read or written.")
    print("  - API key values are env-only; keep secrets in process env or explicit --env-file.")
    print("  - Runtime precedence: CLI > process env > explicit env-file > defaults.")
    print("  - features.l3 requests L3; actual runtime use still requires provider support.")
    print("  - L3 routing/eager profiles, advisory automation, anti-bypass, DEFER, and timeouts")
    print("    stay in env/docs or advanced templates unless a dedicated wizard exposes them.")
    print("  - Verify final sources with `clawsentry config show --effective --env-file PATH`.")
    print()


def _prompt_choice(*, step: str, label: str, choices: list[str], default: str) -> str:
    choice_text = ", ".join(f"{index}) {choice}" for index, choice in enumerate(choices, start=1))
    while True:
        raw = input(f"{step} {label} [{choice_text}] (default: {default}): ").strip()
        if raw.isdigit():
            index = int(raw)
            value = choices[index - 1] if 1 <= index <= len(choices) else raw
        else:
            value = raw or default
        if value in choices:
            return value
        print(f"  Choose one of: {choice_text}")


def _prompt_text(*, step: str, label: str, default: str = "") -> str:
    suffix = f" (default: {default})" if default else ""
    raw = input(f"{step} {label}{suffix}: ").strip()
    return raw or default


def _prompt_bool(*, step: str, label: str, default: bool = False) -> bool:
    default_text = "y" if default else "n"
    while True:
        raw = input(f"{step} {label} [y/n] (default: {default_text}): ").strip().lower()
        if not raw:
            return default
        if raw in {"y", "yes", "1", "true", "on"}:
            return True
        if raw in {"n", "no", "0", "false", "off"}:
            return False
        print("  Enter y or n.")


def _prompt_int(*, step: str, label: str, default: int = 0) -> int:
    while True:
        raw = input(f"{step} {label} (default: {default}): ").strip()
        if not raw:
            return default
        try:
            value = int(raw)
        except ValueError:
            print("  Enter a whole number.")
            continue
        if value < 0:
            print("  Enter 0 or a positive number.")
            continue
        return value


def _interactive_wizard_values(
    *,
    target_dir: Path,
    framework: str,
    mode: str,
    llm_provider: str,
    llm_model: str,
    llm_base_url: str,
    l2: bool | None,
    l3: bool,
    token_budget: int,
) -> dict[str, Any]:
    _print_wizard_header(target_dir)
    _print_wizard_boundary_notes()
    framework_choices = sorted(FRAMEWORK_INITIALIZERS.keys())
    provider_choices = ["none", "openai", "anthropic"]
    provider_default = "none" if llm_provider in {"", "none"} else llm_provider
    print("Step 1/5 - Select the agent framework.")
    selected_framework = _prompt_choice(step="Step 1/5", label="Agent framework", choices=framework_choices, default=framework if framework in framework_choices else "codex")
    print("Step 2/5 - Choose the security mode.")
    selected_mode = _prompt_choice(step="Step 2/5", label="Security mode", choices=sorted(_VALID_MODES), default=mode)
    print("Step 3/5 - Configure optional LLM analysis.")
    selected_provider = _prompt_choice(step="Step 3/5", label="LLM provider for L2/L3", choices=provider_choices, default=provider_default)
    if selected_provider == "none":
        selected_provider = ""
        selected_model = ""
        selected_base_url = ""
        selected_l2 = False
        selected_l3 = False
        print("Step 4/5 - Choose deeper review features.")
        print("  No LLM provider selected; L2 and L3 review are disabled.")
    else:
        selected_model = _prompt_text(step="Step 3/5", label="LLM model", default=llm_model)
        selected_base_url = _prompt_text(step="Step 3/5", label="OpenAI-compatible base URL", default=llm_base_url)
        print("Step 4/5 - Choose deeper review features.")
        print("  L2/L3 can improve semantic detection, but they add model cost and latency.")
        selected_l2 = _prompt_bool(step="Step 4/5", label="Enable L2 semantic analysis", default=True if l2 is None else bool(l2))
        selected_l3 = _prompt_bool(step="Step 4/5", label="Enable L3 advisory review", default=bool(l3))
    print("Step 5/5 - Set budget guardrails.")
    selected_token_budget = _prompt_int(step="Step 5/5", label="Daily LLM token budget, 0 disables budget enforcement", default=int(token_budget))
    print()
    return {
        "framework": selected_framework,
        "mode": selected_mode,
        "llm_provider": selected_provider,
        "llm_model": selected_model,
        "llm_base_url": selected_base_url,
        "l2": selected_l2,
        "l3": selected_l3,
        "token_budget": selected_token_budget,
    }


def run_config_wizard(
    *,
    target_dir: Path,
    non_interactive: bool = False,
    interactive: bool | None = None,
    framework: str = "codex",
    mode: str = "normal",
    llm_provider: str = "",
    llm_model: str = "",
    llm_base_url: str = "",
    l2: bool | None = None,
    l3: bool = False,
    token_budget: int = 0,
    force: bool = False,
    output: Path | None = None,
) -> None:
    stdin_is_tty = bool(getattr(sys.stdin, "isatty", lambda: False)())
    use_interactive = False
    if not non_interactive:
        use_interactive = bool(interactive) or (interactive is None and stdin_is_tty)
    if use_interactive and not stdin_is_tty:
        raise RuntimeError(
            "Interactive wizard requires a TTY. Re-run in a terminal, or use "
            "`clawsentry config wizard --non-interactive` with explicit flags."
        )
    elif not non_interactive and not use_interactive:
        if os.environ.get("CI") or os.environ.get("NO_COLOR"):
            print("Non-interactive/CI-safe wizard path: using supplied/default values.")
        else:
            print("Interactive wizard is not available in this terminal; using supplied/default values.")

    if mode not in _VALID_MODES:
        raise ValueError("mode must be normal, strict, permissive, or benchmark")
    if llm_provider not in _VALID_PROVIDERS:
        raise ValueError("llm_provider must be openai, anthropic, none, or empty")
    if llm_provider == "none":
        llm_provider = ""
    if framework not in FRAMEWORK_INITIALIZERS:
        framework = "codex"

    if use_interactive:
        values = _interactive_wizard_values(
            target_dir=target_dir,
            framework=framework,
            mode=mode,
            llm_provider=llm_provider,
            llm_model=llm_model,
            llm_base_url=llm_base_url,
            l2=l2,
            l3=l3,
            token_budget=token_budget,
        )
        framework = values["framework"]
        mode = values["mode"]
        llm_provider = values["llm_provider"]
        llm_model = values["llm_model"]
        llm_base_url = values["llm_base_url"]
        l2 = values["l2"]
        l3 = values["l3"]
        token_budget = values["token_budget"]

    if not llm_provider:
        l2 = False
        l3 = False
    l2_enabled = bool(llm_provider) if l2 is None else bool(l2)
    path = output or (target_dir / ENV_TEMPLATE_NAME)
    write_env_template(
        path,
        framework=framework,
        mode=mode,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_base_url=llm_base_url,
        l2=l2_enabled,
        l3=bool(l3),
        token_budget=token_budget,
        force=force,
    )
    print(f"Wrote ClawSentry env template {path} ({mode} mode).")
    if llm_provider:
        print("LLM API key is read from CS_LLM_API_KEY; secrets were not written to the template.")
    print("Framework integration is represented by CS_FRAMEWORK/CS_ENABLED_FRAMEWORKS; this wizard does not install hooks.")
    print("Next: pass the template explicitly with `clawsentry start --env-file PATH` if needed.")
    print("Next: run `clawsentry config show --effective --env-file PATH` to verify resolved values.")


def run_config_disable(*, target_dir: Path) -> None:
    _ = target_dir
    print("No files were changed. To disable for one process, set:")
    print("export CS_PROJECT_ENABLED=false")


def run_config_enable(*, target_dir: Path) -> None:
    _ = target_dir
    print("No files were changed. To enable for one process, set:")
    print("export CS_PROJECT_ENABLED=true")
