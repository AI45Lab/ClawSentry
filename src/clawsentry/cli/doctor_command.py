"""``clawsentry doctor`` — offline configuration security audit.

Runs offline checks and can include explicit env-file values when requested.
"""

from __future__ import annotations

import json
import math
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

from .initializers.codex import _codex_hook_state_trust_issues
from .initializers.gemini_cli import (
    _GEMINI_HOOK_COMMAND_ASYNC,
    _GEMINI_HOOK_COMMAND_SYNC,
)


@dataclass
class DoctorCheck:
    check_id: str
    status: Literal["PASS", "WARN", "FAIL"]
    message: str
    detail: str = ""


def _shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values() if c > 0
    )


def _env(key: str) -> str:
    """Read an environment variable, returning '' if unset."""
    return os.environ.get(key, "")


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def check_auth_presence() -> DoctorCheck:
    token = _env("CS_AUTH_TOKEN")
    if token:
        return DoctorCheck("AUTH_PRESENCE", "PASS", "CS_AUTH_TOKEN is set.")
    return DoctorCheck("AUTH_PRESENCE", "FAIL", "CS_AUTH_TOKEN is not set.",
                       detail="Set CS_AUTH_TOKEN to a strong random value.")


def check_auth_length() -> DoctorCheck:
    token = _env("CS_AUTH_TOKEN")
    if not token:
        return DoctorCheck("AUTH_LENGTH", "FAIL", "CS_AUTH_TOKEN is not set.")
    n = len(token)
    if n >= 32:
        return DoctorCheck("AUTH_LENGTH", "PASS", f"Token length {n} >= 32.")
    if n >= 16:
        return DoctorCheck("AUTH_LENGTH", "WARN",
                           f"Token length {n} is short (16-31).",
                           detail="Recommended: >= 32 characters.")
    return DoctorCheck("AUTH_LENGTH", "FAIL", f"Token length {n} < 16.",
                       detail="Minimum recommended: 16 characters.")


def check_auth_entropy() -> DoctorCheck:
    token = _env("CS_AUTH_TOKEN")
    if not token:
        return DoctorCheck("AUTH_ENTROPY", "WARN",
                           "CS_AUTH_TOKEN not set, cannot measure entropy.")
    ent = _shannon_entropy(token)
    if ent >= 3.5:
        return DoctorCheck("AUTH_ENTROPY", "PASS",
                           f"Token entropy {ent:.2f} bits/char >= 3.5.")
    return DoctorCheck("AUTH_ENTROPY", "WARN",
                       f"Token entropy {ent:.2f} bits/char < 3.5.",
                       detail="Use a mix of uppercase, lowercase, digits, and symbols.")


_KNOWN_WEAK_TOKENS = frozenset({
    "changeme", "secret", "password", "admin", "test", "token",
    "changeme-replace-with-a-strong-random-token",
})


def check_auth_weak_value() -> DoctorCheck:
    token = _env("CS_AUTH_TOKEN")
    if not token:
        return DoctorCheck("AUTH_WEAK_VALUE", "PASS", "No token to check.")
    if token.lower() in _KNOWN_WEAK_TOKENS or token.lower().startswith("changeme"):
        return DoctorCheck(
            "AUTH_WEAK_VALUE", "FAIL",
            "CS_AUTH_TOKEN appears to be a placeholder or weak value.",
            detail="Replace with a cryptographically random value: openssl rand -hex 32",
        )
    return DoctorCheck("AUTH_WEAK_VALUE", "PASS", "Token does not match known weak values.")


def check_uds_permissions() -> DoctorCheck:
    sock_path = _env("CS_UDS_PATH") or "/tmp/clawsentry.sock"
    if not os.path.exists(sock_path):
        return DoctorCheck("UDS_PERMISSIONS", "PASS",
                           f"Socket {sock_path} does not exist (OK).")
    try:
        mode = os.stat(sock_path).st_mode & 0o777
    except OSError as e:
        return DoctorCheck("UDS_PERMISSIONS", "WARN",
                           f"Cannot stat {sock_path}: {e}")
    if mode == 0o600:
        return DoctorCheck("UDS_PERMISSIONS", "PASS",
                           f"Socket permissions {oct(mode)} (owner-only).")
    return DoctorCheck("UDS_PERMISSIONS", "WARN",
                       f"Socket permissions {oct(mode)}, expected 0o600.",
                       detail="Run: chmod 600 " + sock_path)


def check_threshold_ordering() -> DoctorCheck:
    try:
        med = float(_env("CS_THRESHOLD_MEDIUM") or "0.8")
        high = float(_env("CS_THRESHOLD_HIGH") or "1.5")
        crit = float(_env("CS_THRESHOLD_CRITICAL") or "2.2")
    except ValueError as e:
        return DoctorCheck("THRESHOLD_ORDERING", "FAIL",
                           f"Non-numeric threshold value: {e}")
    if med <= high <= crit:
        return DoctorCheck("THRESHOLD_ORDERING", "PASS",
                           f"Thresholds ordered: {med} <= {high} <= {crit}.")
    return DoctorCheck("THRESHOLD_ORDERING", "FAIL",
                       f"Thresholds out of order: med={med}, high={high}, crit={crit}.",
                       detail="Ensure CS_THRESHOLD_MEDIUM <= CS_THRESHOLD_HIGH <= CS_THRESHOLD_CRITICAL.")


def check_weight_bounds() -> DoctorCheck:
    weight_keys = [
        "CS_COMPOSITE_WEIGHT_MAX_D123",
        "CS_COMPOSITE_WEIGHT_D4",
        "CS_COMPOSITE_WEIGHT_D5",
        "CS_D6_INJECTION_MULTIPLIER",
    ]
    negatives: list[str] = []
    for key in weight_keys:
        raw = _env(key)
        if raw:
            try:
                val = float(raw)
                if val < 0:
                    negatives.append(f"{key}={val}")
            except ValueError:
                negatives.append(f"{key}='{raw}' (invalid)")
    if negatives:
        return DoctorCheck("WEIGHT_BOUNDS", "FAIL",
                           f"Negative/invalid weights: {', '.join(negatives)}.")
    return DoctorCheck("WEIGHT_BOUNDS", "PASS", "All weights >= 0.")


def check_llm_config() -> DoctorCheck:
    provider = _env("CS_LLM_PROVIDER")
    api_key = (_env("CS_LLM_API_KEY") or _env("ANTHROPIC_API_KEY")
               or _env("OPENAI_API_KEY"))
    if not provider and not api_key:
        return DoctorCheck("LLM_CONFIG", "PASS",
                           "No LLM provider configured (L2/L3 disabled).")
    if provider and not api_key:
        return DoctorCheck("LLM_CONFIG", "WARN",
                           f"LLM provider '{provider}' set but no API key found.",
                           detail="Set CS_LLM_API_KEY or provider-specific key.")
    return DoctorCheck("LLM_CONFIG", "PASS",
                       "LLM provider and API key configured.")


def check_openclaw_secret() -> DoctorCheck:
    token = _env("CS_OPENCLAW_TOKEN")
    secret = _env("CS_OPENCLAW_WEBHOOK_SECRET")
    if not token:
        return DoctorCheck("OPENCLAW_SECRET", "PASS",
                           "OpenClaw integration not configured.")
    if secret:
        return DoctorCheck("OPENCLAW_SECRET", "PASS",
                           "OpenClaw webhook secret is set.")
    return DoctorCheck("OPENCLAW_SECRET", "WARN",
                       "CS_OPENCLAW_TOKEN set but CS_OPENCLAW_WEBHOOK_SECRET is empty.",
                       detail="Set CS_OPENCLAW_WEBHOOK_SECRET for webhook verification.")


def check_listen_address() -> DoctorCheck:
    host = _env("CS_HTTP_HOST") or "127.0.0.1"
    if host in {"127.0.0.1", "localhost", "::1"}:
        return DoctorCheck("LISTEN_ADDRESS", "PASS",
                           f"Listening on {host} (localhost only).")
    return DoctorCheck("LISTEN_ADDRESS", "WARN",
                       f"Listening on {host} (publicly accessible).",
                       detail="Use 127.0.0.1 for local-only access, "
                              "or ensure firewall rules are in place.")


def check_whitelist_regex() -> DoctorCheck:
    raw = _env("CS_POST_ACTION_WHITELIST")
    if not raw:
        return DoctorCheck("WHITELIST_REGEX", "PASS",
                           "No post-action whitelist configured.")
    patterns = [p.strip() for p in raw.split(",") if p.strip()]
    invalid: list[str] = []
    for p in patterns:
        try:
            re.compile(p)
        except re.error as e:
            invalid.append(f"'{p}': {e}")
    if invalid:
        return DoctorCheck("WHITELIST_REGEX", "FAIL",
                           f"Invalid whitelist regex: {'; '.join(invalid)}.")
    return DoctorCheck("WHITELIST_REGEX", "PASS",
                       f"All {len(patterns)} whitelist patterns compile OK.")


def check_l2_budget() -> DoctorCheck:
    raw = _env("CS_L2_TIMEOUT_MS") or _env("CS_L2_BUDGET_MS")
    env_name = "CS_L2_TIMEOUT_MS" if _env("CS_L2_TIMEOUT_MS") else "CS_L2_BUDGET_MS"
    if not raw:
        return DoctorCheck("L2_TIMEOUT", "PASS",
                           "L2 timeout using default (60000ms).")
    try:
        val = float(raw)
    except ValueError:
        return DoctorCheck("L2_TIMEOUT", "FAIL",
                           f"{env_name}='{raw}' is not a number.")
    if val > 0:
        return DoctorCheck("L2_TIMEOUT", "PASS", f"L2 timeout: {val}ms.")
    return DoctorCheck("L2_TIMEOUT", "FAIL",
                       f"{env_name}={val} <= 0.",
                       detail="L2 timeout must be positive.")


def check_trajectory_db() -> DoctorCheck:
    db_path = _env("CS_TRAJECTORY_DB_PATH") or "/tmp/clawsentry-trajectory.db"
    parent = os.path.dirname(db_path) or "."
    if os.path.isdir(parent) and os.access(parent, os.W_OK):
        return DoctorCheck("TRAJECTORY_DB", "PASS",
                           f"Database directory '{parent}' is writable.")
    if not os.path.isdir(parent):
        return DoctorCheck("TRAJECTORY_DB", "WARN",
                           f"Database directory '{parent}' does not exist.",
                           detail="It will be created on first run if possible.")
    return DoctorCheck("TRAJECTORY_DB", "WARN",
                       f"Database directory '{parent}' is not writable.")


def check_codex_config() -> DoctorCheck:
    if not _framework_enabled("codex"):
        return DoctorCheck("CODEX_CONFIG", "PASS",
                           "Codex is not enabled (Codex check skipped).")
    token = _env("CS_AUTH_TOKEN")
    port = _env("CS_HTTP_PORT") or "8080"
    if not token:
        return DoctorCheck("CODEX_CONFIG", "WARN",
                           "CS_FRAMEWORK=codex but CS_AUTH_TOKEN is not set.",
                           detail="Codex endpoint /ahp/codex requires authentication.")
    return DoctorCheck("CODEX_CONFIG", "PASS",
                       f"Codex configured: /ahp/codex on port {port}.")


def _framework_enabled(name: str) -> bool:
    framework = _env("CS_FRAMEWORK")
    enabled = {
        item.strip()
        for item in _env("CS_ENABLED_FRAMEWORKS").split(",")
        if item.strip()
    }
    return framework == name or name in enabled


def check_gemini_config() -> DoctorCheck:
    if not _framework_enabled("gemini-cli"):
        return DoctorCheck("GEMINI_CONFIG", "PASS",
                           "Gemini CLI is not enabled (Gemini check skipped).")
    token = _env("CS_AUTH_TOKEN")
    port = _env("CS_HTTP_PORT") or "8080"
    hooks_enabled = _env("CS_GEMINI_HOOKS_ENABLED").lower() in {
        "1", "true", "yes", "on",
    }
    if not token:
        return DoctorCheck("GEMINI_CONFIG", "WARN",
                           "Gemini CLI is enabled but CS_AUTH_TOKEN is not set.",
                           detail="Gemini hook decisions require an authenticated local Gateway.")
    if not hooks_enabled:
        return DoctorCheck("GEMINI_CONFIG", "WARN",
                           "Gemini CLI is enabled but CS_GEMINI_HOOKS_ENABLED is not true.",
                           detail="Run clawsentry init gemini-cli to merge Gemini env keys.")
    return DoctorCheck("GEMINI_CONFIG", "PASS",
                       f"Gemini CLI configured for local Gateway on port {port}.")


_CODEX_HOOK_MARKER = "clawsentry harness --framework codex"
_CODEX_HOOK_SYNC_COMMAND = "clawsentry harness --framework codex"
_CODEX_HOOK_ASYNC_COMMAND = "clawsentry harness --framework codex --async"
_CODEX_NON_BASH_TOOL_MATCHER = "apply_patch|Edit|Write|mcp__.*"
_CODEX_REQUIRED_HOOK_SHAPES: tuple[tuple[str, str | None, str, str], ...] = (
    ("PreToolUse", "Bash", _CODEX_HOOK_SYNC_COMMAND, "synchronous"),
    ("PreToolUse", _CODEX_NON_BASH_TOOL_MATCHER, _CODEX_HOOK_ASYNC_COMMAND, "--async"),
    ("PermissionRequest", "Bash", _CODEX_HOOK_SYNC_COMMAND, "synchronous"),
    ("PermissionRequest", _CODEX_NON_BASH_TOOL_MATCHER, _CODEX_HOOK_SYNC_COMMAND, "synchronous"),
    ("PostToolUse", "Bash", _CODEX_HOOK_ASYNC_COMMAND, "--async"),
    ("PostToolUse", _CODEX_NON_BASH_TOOL_MATCHER, _CODEX_HOOK_ASYNC_COMMAND, "--async"),
    ("UserPromptSubmit", None, _CODEX_HOOK_ASYNC_COMMAND, "--async"),
    ("Stop", None, _CODEX_HOOK_ASYNC_COMMAND, "--async"),
    ("SessionStart", "startup|resume|clear", _CODEX_HOOK_ASYNC_COMMAND, "--async"),
    ("PreCompact", None, _CODEX_HOOK_ASYNC_COMMAND, "--async"),
    ("PostCompact", None, _CODEX_HOOK_ASYNC_COMMAND, "--async"),
)

_GEMINI_HOOK_MARKER = "clawsentry harness --framework gemini-cli"
_GEMINI_HOOK_SYNC_COMMAND = _GEMINI_HOOK_COMMAND_SYNC
_GEMINI_HOOK_ASYNC_COMMAND = _GEMINI_HOOK_COMMAND_ASYNC
_GEMINI_REQUIRED_HOOK_SHAPES: tuple[tuple[str, str, str], ...] = (
    ("BeforeAgent", _GEMINI_HOOK_SYNC_COMMAND, "synchronous"),
    ("AfterAgent", _GEMINI_HOOK_SYNC_COMMAND, "synchronous"),
    ("BeforeModel", _GEMINI_HOOK_SYNC_COMMAND, "synchronous"),
    ("AfterModel", _GEMINI_HOOK_SYNC_COMMAND, "synchronous"),
    ("BeforeTool", _GEMINI_HOOK_SYNC_COMMAND, "synchronous"),
    ("AfterTool", _GEMINI_HOOK_SYNC_COMMAND, "synchronous"),
    ("SessionStart", _GEMINI_HOOK_ASYNC_COMMAND, "--async"),
    ("SessionEnd", _GEMINI_HOOK_ASYNC_COMMAND, "--async"),
    ("BeforeToolSelection", _GEMINI_HOOK_ASYNC_COMMAND, "--async"),
    ("PreCompress", _GEMINI_HOOK_ASYNC_COMMAND, "--async"),
    ("Notification", _GEMINI_HOOK_ASYNC_COMMAND, "--async"),
)


def _codex_hook_label(event_name: str, matcher: str | None) -> str:
    return f"{event_name}({matcher})" if matcher else event_name


def _codex_hook_display_mode(expected_command: str) -> str:
    return "sync" if expected_command == _CODEX_HOOK_SYNC_COMMAND else "async"


def _codex_managed_hook_commands(
    hooks_payload: dict[str, Any],
    *,
    event_name: str,
    matcher: str | None,
) -> list[str]:
    hooks = hooks_payload.get("hooks")
    if not isinstance(hooks, dict):
        return []
    entries = hooks.get(event_name)
    if not isinstance(entries, list):
        return []

    commands: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if matcher is None:
            if "matcher" in entry:
                continue
        elif entry.get("matcher") != matcher:
            continue
        hook_specs = entry.get("hooks")
        if not isinstance(hook_specs, list):
            continue
        for hook_spec in hook_specs:
            if not isinstance(hook_spec, dict):
                continue
            command = hook_spec.get("command")
            if isinstance(command, str) and _CODEX_HOOK_MARKER in command:
                commands.append(command)
    return commands


def _codex_native_hook_shape_issues(
    hooks_payload: dict[str, Any],
) -> list[str]:
    issues: list[str] = []
    for event_name, matcher, expected_command, expected_mode in _CODEX_REQUIRED_HOOK_SHAPES:
        commands = _codex_managed_hook_commands(
            hooks_payload,
            event_name=event_name,
            matcher=matcher,
        )
        label = _codex_hook_label(event_name, matcher)
        if not commands:
            issues.append(f"{label}: missing ClawSentry managed entry")
            continue
        if expected_command not in commands:
            issues.append(
                f"{label}: expected {expected_mode} command "
                f"'{expected_command}', found {commands!r}"
            )
    return issues


def _codex_native_hook_shape_detail(hooks_payload: dict[str, Any]) -> str:
    """Return operator-readable per-hook sync/async status lines."""

    lines: list[str] = []
    for event_name, matcher, expected_command, _expected_mode in _CODEX_REQUIRED_HOOK_SHAPES:
        label = _codex_hook_label(event_name, matcher)
        expected_display = _codex_hook_display_mode(expected_command)
        commands = _codex_managed_hook_commands(
            hooks_payload,
            event_name=event_name,
            matcher=matcher,
        )
        if expected_command in commands:
            lines.append(f"{label}: {expected_display}")
        elif not commands:
            lines.append(f"{label}: missing")
        else:
            found = ", ".join(commands)
            lines.append(f"{label}: expected {expected_display}, found {found}")
    return "\n".join(lines)


def _codex_feature_flag_enabled(config_text: str, name: str) -> bool:
    in_features = False
    for line in config_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            in_features = stripped == "[features]"
            continue
        if not in_features or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key.strip() == name and value.strip().lower() == "true":
            return True
    return False


def check_codex_native_hooks() -> DoctorCheck:
    if not _framework_enabled("codex"):
        return DoctorCheck("CODEX_NATIVE_HOOKS", "PASS",
                           "Codex is not enabled (native hooks check skipped).")

    codex_home = Path(_env("CODEX_HOME") or "~/.codex").expanduser()
    config_path = codex_home / "config.toml"
    hooks_path = codex_home / "hooks.json"
    if not config_path.exists() or not hooks_path.exists():
        return DoctorCheck(
            "CODEX_NATIVE_HOOKS",
            "WARN",
            "Codex native hooks are not installed.",
            detail="Optional: run clawsentry init codex --setup",
        )

    try:
        config_text = config_path.read_text(encoding="utf-8")
        hooks_payload = json.loads(hooks_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return DoctorCheck(
            "CODEX_NATIVE_HOOKS",
            "WARN",
            f"Could not inspect Codex native hooks: {exc}",
            detail="Run clawsentry init codex --setup to repair managed hook entries.",
        )

    has_feature = _codex_feature_flag_enabled(config_text, "hooks")
    shape_issues = _codex_native_hook_shape_issues(hooks_payload)
    trust_issues = _codex_hook_state_trust_issues(
        config_text,
        hooks_path=hooks_path,
        hooks_payload=hooks_payload,
    )
    shape_detail = _codex_native_hook_shape_detail(hooks_payload)
    if has_feature and not shape_issues and not trust_issues:
        return DoctorCheck(
            "CODEX_NATIVE_HOOKS",
            "PASS",
            (
                f"Codex native hooks installed: {hooks_path}; "
                "managed entries are trusted; PreToolUse(Bash) and PermissionRequest(Bash) sync + advisory hooks async."
            ),
            detail=shape_detail,
        )

    missing: list[str] = []
    if not has_feature:
        missing.append("[features].hooks = true")
    missing.extend(shape_issues)
    missing.extend(trust_issues)
    detail = (
        f"{shape_detail}\n"
        f"Missing: {', '.join(missing)}. Run clawsentry init codex --setup."
    )
    return DoctorCheck(
        "CODEX_NATIVE_HOOKS",
        "WARN",
        "Codex native hooks are incomplete.",
        detail=detail,
    )


def _gemini_settings_path() -> Path:
    explicit = _env("CS_GEMINI_SETTINGS_PATH").strip()
    if explicit:
        return Path(explicit).expanduser()
    return Path.cwd() / ".gemini" / "settings.json"


def _gemini_managed_hook_commands(
    settings_payload: dict[str, Any],
    *,
    event_name: str,
) -> list[str]:
    hooks = settings_payload.get("hooks")
    if not isinstance(hooks, dict):
        return []
    entries = hooks.get(event_name)
    if not isinstance(entries, list):
        return []
    commands: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        hook_specs = entry.get("hooks")
        if not isinstance(hook_specs, list):
            continue
        for hook_spec in hook_specs:
            if not isinstance(hook_spec, dict):
                continue
            command = hook_spec.get("command")
            if isinstance(command, str) and _GEMINI_HOOK_MARKER in command:
                commands.append(command)
    return commands


def _gemini_native_hook_shape_issues(
    settings_payload: dict[str, Any],
) -> list[str]:
    issues: list[str] = []
    hooks_config = settings_payload.get("hooksConfig")
    hooks = settings_payload.get("hooks")
    hooks_enabled = (
        isinstance(hooks_config, dict) and hooks_config.get("enabled") is True
    ) or (
        isinstance(hooks, dict) and hooks.get("enabled") is True
    )
    if not hooks_enabled:
        issues.append("hooksConfig.enabled=true (or hooks.enabled=true)")
    for event_name, expected_command, expected_mode in _GEMINI_REQUIRED_HOOK_SHAPES:
        commands = _gemini_managed_hook_commands(settings_payload, event_name=event_name)
        if not commands:
            issues.append(f"{event_name}: missing ClawSentry managed entry")
            continue
        if expected_command not in commands:
            issues.append(
                f"{event_name}: expected {expected_mode} command "
                f"'{expected_command}', found {commands!r}"
            )
    return issues


def _gemini_native_hook_shape_detail(settings_payload: dict[str, Any]) -> str:
    lines: list[str] = []
    for event_name, expected_command, _expected_mode in _GEMINI_REQUIRED_HOOK_SHAPES:
        expected_display = (
            "sync" if expected_command == _GEMINI_HOOK_SYNC_COMMAND else "async"
        )
        commands = _gemini_managed_hook_commands(settings_payload, event_name=event_name)
        if expected_command in commands:
            lines.append(f"{event_name}: {expected_display}")
        elif not commands:
            lines.append(f"{event_name}: missing")
        else:
            lines.append(f"{event_name}: expected {expected_display}, found {', '.join(commands)}")
    return "\n".join(lines)


def check_gemini_native_hooks() -> DoctorCheck:
    if not _framework_enabled("gemini-cli"):
        return DoctorCheck("GEMINI_NATIVE_HOOKS", "PASS",
                           "Gemini CLI is not enabled (native hooks check skipped).")

    settings_path = _gemini_settings_path()
    if not settings_path.exists():
        return DoctorCheck(
            "GEMINI_NATIVE_HOOKS",
            "WARN",
            "Gemini CLI native hooks are not installed.",
            detail="Run clawsentry init gemini-cli --setup (use --dry-run first).",
        )
    try:
        settings_payload = json.loads(settings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return DoctorCheck(
            "GEMINI_NATIVE_HOOKS",
            "WARN",
            f"Could not inspect Gemini CLI native hooks: {exc}",
            detail="Run clawsentry init gemini-cli --setup to repair managed hook entries.",
        )
    if not isinstance(settings_payload, dict):
        return DoctorCheck(
            "GEMINI_NATIVE_HOOKS",
            "WARN",
            "Gemini CLI settings are not a JSON object.",
            detail="Run clawsentry init gemini-cli --setup to repair managed hook entries.",
        )

    shape_issues = _gemini_native_hook_shape_issues(settings_payload)
    shape_detail = _gemini_native_hook_shape_detail(settings_payload)
    if not shape_issues:
        return DoctorCheck(
            "GEMINI_NATIVE_HOOKS",
            "PASS",
            (
                f"Gemini CLI native hooks installed: {settings_path}; "
                "prompt/model/tool hooks sync + lifecycle/advisory hooks async."
            ),
            detail=(
                f"{shape_detail}\n"
                "Maturity: real CLI smoke proved SessionStart/BeforeAgent/BeforeModel and "
                "real BeforeTool deny for run_shell_command."
            ),
        )

    return DoctorCheck(
        "GEMINI_NATIVE_HOOKS",
        "WARN",
        "Gemini CLI native hooks are incomplete.",
        detail=(
            f"{shape_detail}\n"
            f"Missing: {', '.join(shape_issues)}. "
            "Run clawsentry init gemini-cli --setup."
        ),
    )


# ---------------------------------------------------------------------------
# Latch checks
# ---------------------------------------------------------------------------


def check_latch_binary() -> DoctorCheck:
    """Check whether the Latch binary is installed and executable."""
    try:
        from clawsentry.latch.binary_manager import BinaryManager
    except ImportError:
        return DoctorCheck("LATCH_BINARY", "PASS",
                           "Latch package not installed (optional).")

    mgr = BinaryManager()
    if not mgr.is_installed:
        return DoctorCheck("LATCH_BINARY", "WARN",
                           "Latch binary not installed.",
                           detail="Run: clawsentry latch install")
    if not os.access(mgr.binary_path, os.X_OK):
        return DoctorCheck("LATCH_BINARY", "WARN",
                           f"Latch binary at {mgr.binary_path} is not executable.",
                           detail=f"Run: chmod +x {mgr.binary_path}")
    return DoctorCheck("LATCH_BINARY", "PASS",
                       f"Latch binary installed at {mgr.binary_path}.")


def check_latch_hub_health() -> DoctorCheck:
    """Check whether Latch Hub is responding on its health endpoint."""
    import urllib.request

    hub_port = _env("CS_LATCH_HUB_PORT") or "3006"
    url = f"http://127.0.0.1:{hub_port}/health"
    try:
        with urllib.request.urlopen(url, timeout=2) as resp:
            if resp.status == 200:
                return DoctorCheck("LATCH_HUB_HEALTH", "PASS",
                                   f"Latch Hub responding on port {hub_port}.")
    except (OSError, urllib.error.URLError):
        pass
    return DoctorCheck("LATCH_HUB_HEALTH", "WARN",
                       f"Latch Hub not responding on port {hub_port}.",
                       detail="Start with: clawsentry latch start")


def check_latch_token_sync() -> DoctorCheck:
    """Check CS_AUTH_TOKEN and CLI_API_TOKEN are consistent."""
    cs_token = _env("CS_AUTH_TOKEN")
    cli_token = _env("CLI_API_TOKEN")
    if not cs_token and not cli_token:
        return DoctorCheck("LATCH_TOKEN_SYNC", "PASS",
                           "No Latch tokens configured (optional).")
    if not cli_token:
        return DoctorCheck("LATCH_TOKEN_SYNC", "PASS",
                           "CLI_API_TOKEN not set (Latch Hub not configured).")
    if cs_token == cli_token:
        return DoctorCheck("LATCH_TOKEN_SYNC", "PASS",
                           "CS_AUTH_TOKEN and CLI_API_TOKEN match.")
    return DoctorCheck("LATCH_TOKEN_SYNC", "WARN",
                       "CS_AUTH_TOKEN and CLI_API_TOKEN differ.",
                       detail="Ensure both tokens match for Latch ↔ Gateway auth.")


# ---------------------------------------------------------------------------
# Bridge checks
# ---------------------------------------------------------------------------


def check_defer_bridge() -> DoctorCheck:
    """Check DEFER bridge configuration."""
    enabled_raw = (_env("CS_DEFER_BRIDGE_ENABLED") or "true").lower()
    if enabled_raw in ("false", "0", "no"):
        return DoctorCheck("DEFER_BRIDGE", "PASS",
                           "DEFER bridge disabled (immediate DEFER return).")
    timeout_action = _env("CS_DEFER_TIMEOUT_ACTION") or "block"
    timeout_s = _env("CS_DEFER_TIMEOUT_S") or "300"
    try:
        timeout_val = float(timeout_s)
    except ValueError:
        return DoctorCheck("DEFER_BRIDGE", "WARN",
                           f"CS_DEFER_TIMEOUT_S='{timeout_s}' is not a number.",
                           detail="Using default timeout (300s).")
    if timeout_action not in ("block", "allow"):
        return DoctorCheck("DEFER_BRIDGE", "WARN",
                           f"CS_DEFER_TIMEOUT_ACTION='{timeout_action}' invalid.",
                           detail="Must be 'block' or 'allow'.")
    return DoctorCheck("DEFER_BRIDGE", "PASS",
                       f"DEFER bridge enabled (timeout: {int(timeout_val)}s, action: {timeout_action}).")


def check_hub_bridge() -> DoctorCheck:
    """Check Latch Hub bridge configuration and reachability."""
    import urllib.request
    import urllib.error

    hub_enabled = (_env("CS_HUB_BRIDGE_ENABLED") or "auto").lower()
    if hub_enabled == "false":
        return DoctorCheck("HUB_BRIDGE", "PASS",
                           "Hub bridge explicitly disabled.")

    hub_url = _env("CS_LATCH_HUB_URL")
    hub_port = _env("CS_LATCH_HUB_PORT") or "3006"
    if not hub_url:
        hub_url = f"http://127.0.0.1:{hub_port}"

    health_url = f"{hub_url.rstrip('/')}/health"
    try:
        with urllib.request.urlopen(health_url, timeout=2) as resp:
            if resp.status == 200:
                return DoctorCheck("HUB_BRIDGE", "PASS",
                                   f"Hub bridge reachable at {hub_url}.")
    except (OSError, urllib.error.URLError):
        pass

    if hub_enabled == "true":
        return DoctorCheck("HUB_BRIDGE", "WARN",
                           f"Hub bridge enabled but not reachable at {hub_url}.",
                           detail="Start Hub: clawsentry latch start")
    return DoctorCheck("HUB_BRIDGE", "PASS",
                       f"Hub bridge auto-mode, Hub not running at {hub_url} (OK).")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_auth_presence,
    check_auth_length,
    check_auth_entropy,
    check_auth_weak_value,
    check_uds_permissions,
    check_threshold_ordering,
    check_weight_bounds,
    check_llm_config,
    check_openclaw_secret,
    check_listen_address,
    check_whitelist_regex,
    check_l2_budget,
    check_trajectory_db,
    check_codex_config,
    check_codex_native_hooks,
    check_gemini_config,
    check_gemini_native_hooks,
    check_latch_binary,
    check_latch_hub_health,
    check_latch_token_sync,
    check_defer_bridge,
    check_hub_bridge,
]


def run_all_checks() -> list[DoctorCheck]:
    """Run all doctor checks and return results."""
    return [fn() for fn in ALL_CHECKS]


def _colorize(status: str, color: bool) -> str:
    if not color:
        return status
    codes = {"PASS": "\033[32m", "WARN": "\033[33m", "FAIL": "\033[31m"}
    reset = "\033[0m"
    return f"{codes.get(status, '')}{status}{reset}"


def format_table(results: list[DoctorCheck], color: bool = True) -> str:
    """Format results as a human-readable table."""
    lines: list[str] = []
    lines.append("ClawSentry Doctor Report")
    lines.append("=" * 60)
    for r in results:
        status = _colorize(r.status, color)
        lines.append(f"  [{status}] {r.check_id}: {r.message}")
        if r.detail:
            lines.append(f"         {r.detail}")
    lines.append("=" * 60)
    counts = Counter(r.status for r in results)
    summary_parts = []
    for s in ("PASS", "WARN", "FAIL"):
        if counts.get(s, 0) > 0:
            label = _colorize(s, color)
            summary_parts.append(f"{label}: {counts[s]}")
    lines.append("  " + "  ".join(summary_parts))
    return "\n".join(lines)


def format_json(results: list[DoctorCheck]) -> str:
    """Format results as JSON."""
    return json.dumps([asdict(r) for r in results], indent=2)


def compute_exit_code(results: list[DoctorCheck]) -> int:
    """0 = all PASS, 1 = any FAIL, 2 = WARN only (no FAIL)."""
    statuses = {r.status for r in results}
    if "FAIL" in statuses:
        return 1
    if "WARN" in statuses:
        return 2
    return 0


def run_doctor(
    json_mode: bool = False,
    color: bool = True,
    env_file: Path | None = None,
) -> int:
    """Run doctor command and print output. Returns exit code."""
    from .dotenv_loader import EnvFileError, overlay_env_file, resolve_explicit_env_file

    old_env: dict[str, str] | None = None
    if env_file is not None or os.environ.get("CLAWSENTRY_ENV_FILE"):
        try:
            parsed = resolve_explicit_env_file(cli_env_file=env_file, environ=os.environ)
        except EnvFileError as exc:
            print(str(exc))
            return 2
        # Doctor checks are still env-backed; isolate by restoring os.environ.
        old_env = dict(os.environ)
        os.environ.clear()
        os.environ.update(overlay_env_file(old_env, parsed))
    try:
        results = run_all_checks()
    finally:
        if old_env is not None:
            os.environ.clear()
            os.environ.update(old_env)
    if json_mode:
        print(format_json(results))
    else:
        print(format_table(results, color=color))
    return compute_exit_code(results)
