"""Handler for `clawsentry init <framework>`."""

from __future__ import annotations

import sys
from pathlib import Path

from .initializers import get_initializer


_FRAMEWORK_ENV_KEYS: dict[str, set[str]] = {
    "a3s-code": set(),
    "claude-code": set(),
    "codex": {"CS_CODEX_SESSION_DIR", "CS_CODEX_WATCH_ENABLED"},
    "gemini-cli": {"CS_GEMINI_HOOKS_ENABLED", "CS_GEMINI_SETTINGS_PATH"},
    "kimi-cli": {"CS_KIMI_HOOKS_ENABLED", "CS_KIMI_CONFIG_PATH"},
    "openclaw": {
        "OPENCLAW_ENFORCEMENT_ENABLED",
        "OPENCLAW_OPERATOR_TOKEN",
        "OPENCLAW_WEBHOOK_PORT",
        "OPENCLAW_WEBHOOK_TOKEN",
        "OPENCLAW_WS_URL",
    },
}


def run_init(
    *,
    framework: str,
    target_dir: Path,
    force: bool,
    auto_detect: bool = False,
    setup: bool = False,
    dry_run: bool = False,
    hardened_profile: bool = False,
    openclaw_home: Path | None = None,
    codex_home: Path | None = None,
    gemini_home: Path | None = None,
    kimi_home: Path | None = None,
    quiet: bool = False,
) -> int:
    """Run init and print results. Returns exit code (0=ok, 1=error).

    When *quiet* is ``True`` (e.g. called from ``clawsentry start``),
    only a one-line confirmation is printed instead of the full banner.
    """
    # --setup implies --auto-detect
    if setup:
        auto_detect = True

    try:
        initializer = get_initializer(framework)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    target_dir.mkdir(parents=True, exist_ok=True)

    try:
        kwargs: dict[str, object] = {"force": force}
        if auto_detect:
            kwargs["auto_detect"] = True
        if openclaw_home is not None:
            kwargs["openclaw_home"] = openclaw_home
        if codex_home is not None:
            kwargs["codex_home"] = codex_home
        if gemini_home is not None:
            kwargs["gemini_home"] = gemini_home
        if kimi_home is not None:
            kwargs["kimi_home"] = kimi_home
        result = initializer.generate_config(target_dir, **kwargs)
    except FileExistsError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if quiet:
        print(f"[clawsentry] {framework} integration auto-initialized.")
        return 0

    print(f"[clawsentry] {framework} integration initialized\n")

    if result.warnings:
        for w in result.warnings:
            print(f"  WARNING: {w}")
        print()

    if result.files_created:
        print("  Files created:")
        for f in result.files_created:
            print(f"    {f}")
        print()

    print("  Environment variables:")
    for key, val in result.env_vars.items():
        print(f"    {key}={val}")
    print()

    print("  Next steps:")
    for i, step in enumerate(result.next_steps, 1):
        print(f"    {i}. {step}")
    print()

    # --- OpenClaw --setup ---
    if setup and hasattr(initializer, "setup_openclaw_config"):
        setup_kwargs: dict[str, object] = {"dry_run": dry_run}
        if openclaw_home is not None:
            setup_kwargs["openclaw_home"] = openclaw_home
        if hardened_profile:
            setup_kwargs["hardened_profile"] = True
        setup_result = initializer.setup_openclaw_config(**setup_kwargs)

        if setup_result.dry_run:
            print("  [DRY RUN] The following changes would be applied:")
        else:
            print("  OpenClaw configuration updated:")
        for change in setup_result.changes_applied:
            print(f"    - {change}")
        if setup_result.files_backed_up:
            print(
                f"  Backups: {', '.join(str(f) for f in setup_result.files_backed_up)}"
            )
        if setup_result.warnings:
            for w in setup_result.warnings:
                print(f"  WARNING: {w}")
        print()

    # --- Codex --setup ---
    if setup and hasattr(initializer, "setup_codex_hooks"):
        setup_kwargs = {"dry_run": dry_run}
        if codex_home is not None:
            setup_kwargs["codex_home"] = codex_home
        setup_result = initializer.setup_codex_hooks(**setup_kwargs)

        if setup_result.dry_run:
            print("  [DRY RUN] The following Codex hook changes would be applied:")
        else:
            print("  Codex native hooks updated:")
        for change in setup_result.changes_applied:
            print(f"    - {change}")
        if setup_result.warnings:
            for w in setup_result.warnings:
                print(f"  WARNING: {w}")
        print()

    # --- Kimi CLI --setup ---
    if setup and hasattr(initializer, "setup_kimi_hooks"):
        setup_kwargs = {"target_dir": target_dir, "dry_run": dry_run}
        if kimi_home is not None:
            setup_kwargs["kimi_home"] = kimi_home
        setup_result = initializer.setup_kimi_hooks(**setup_kwargs)

        if setup_result.dry_run:
            print("  [DRY RUN] The following Kimi CLI hook changes would be applied:")
        else:
            print("  Kimi CLI native hooks updated:")
        for change in setup_result.changes_applied:
            print(f"    - {change}")
        if setup_result.warnings:
            for w in setup_result.warnings:
                print(f"  WARNING: {w}")
        print()

    # --- Gemini CLI --setup ---
    if setup and hasattr(initializer, "setup_gemini_hooks"):
        setup_kwargs = {"target_dir": target_dir, "dry_run": dry_run}
        if gemini_home is not None:
            setup_kwargs["gemini_home"] = gemini_home
        setup_result = initializer.setup_gemini_hooks(**setup_kwargs)

        if setup_result.dry_run:
            print("  [DRY RUN] The following Gemini CLI hook changes would be applied:")
        else:
            print("  Gemini CLI native hooks updated:")
        for change in setup_result.changes_applied:
            print(f"    - {change}")
        if setup_result.warnings:
            for w in setup_result.warnings:
                print(f"  WARNING: {w}")
        print()

    return 0


def run_uninstall(
    *,
    framework: str,
    target_dir: Path,
    claude_home: Path | None = None,
    codex_home: Path | None = None,
    gemini_home: Path | None = None,
    kimi_home: Path | None = None,
    quiet: bool = False,
) -> int:
    """Disable one framework integration without disturbing other frameworks."""
    try:
        initializer = get_initializer(framework)
    except KeyError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    warnings: list[str] = []
    next_steps: list[str] = []

    if framework == "claude-code" and hasattr(initializer, "uninstall"):
        uninstall_kwargs: dict[str, object] = {}
        if claude_home is not None:
            uninstall_kwargs["claude_home"] = claude_home
        result = initializer.uninstall(**uninstall_kwargs)
        warnings.extend(result.warnings)
        next_steps.extend(result.next_steps)
    elif framework == "codex" and hasattr(initializer, "uninstall"):
        uninstall_kwargs = {}
        if codex_home is not None:
            uninstall_kwargs["codex_home"] = codex_home
        result = initializer.uninstall(**uninstall_kwargs)
        warnings.extend(result.warnings)
        next_steps.extend(result.next_steps)
    elif framework == "gemini-cli" and hasattr(initializer, "uninstall"):
        uninstall_kwargs = {"target_dir": target_dir}
        if gemini_home is not None:
            uninstall_kwargs["gemini_home"] = gemini_home
        result = initializer.uninstall(**uninstall_kwargs)
        warnings.extend(result.warnings)
        next_steps.extend(result.next_steps)
    elif framework == "kimi-cli" and hasattr(initializer, "uninstall"):
        uninstall_kwargs = {"target_dir": target_dir}
        if kimi_home is not None:
            uninstall_kwargs["kimi_home"] = kimi_home
        result = initializer.uninstall(**uninstall_kwargs)
        warnings.extend(result.warnings)
        next_steps.extend(result.next_steps)

    next_steps.append(
        f"Remove {framework} from CS_ENABLED_FRAMEWORKS/CS_FRAMEWORK in your process env or explicit env file."
    )

    if quiet:
        print(f"[clawsentry] {framework} integration uninstalled.")
        return 0

    print(f"[clawsentry] {framework} integration uninstalled\n")

    if warnings:
        for warning in warnings:
            print(f"  WARNING: {warning}")
        print()

    print("  Next steps:")
    for i, step in enumerate(next_steps, 1):
        print(f"    {i}. {step}")
    print()

    return 0
