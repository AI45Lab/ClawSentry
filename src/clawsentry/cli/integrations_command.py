"""``clawsentry integrations`` — inspect configured framework integrations."""

from __future__ import annotations

import json
import os
from pathlib import Path

from .dotenv_loader import EnvFileError, overlay_env_file, resolve_explicit_env_file
from clawsentry.gateway.env_config import parse_enabled_frameworks


FRAMEWORK_CAPABILITIES: dict[str, dict[str, str]] = {
    "a3s-code": {
        "integration_mode": "explicit_sdk_transport",
        "integration_mode_label": "explicit SDK transport + harness",
        "pre_action_interception": "supported",
        "pre_action_label": "yes",
        "post_action_observation": "supported",
        "post_action_label": "yes",
        "host_config_dependency": "agent code must set SessionOptions.ahp_transport explicitly",
        "failure_mode": "agent runs without ClawSentry supervision if transport is not wired",
        "maturity": "strong_reference_integration",
        "maturity_label": "high",
    },
    "openclaw": {
        "integration_mode": "websocket_webhook",
        "integration_mode_label": "websocket approvals + webhook receiver",
        "pre_action_interception": "host_config_required",
        "pre_action_label": "yes",
        "post_action_observation": "supported",
        "post_action_label": "yes",
        "host_config_dependency": "~/.openclaw must be configured for gateway exec + webhook/WS callbacks",
        "failure_mode": "falls back to partial coverage or no enforcement when host-side OpenClaw config is missing",
        "maturity": "strong_with_host_setup",
        "maturity_label": "medium-high",
    },
    "codex": {
        "integration_mode": "session_jsonl_watcher_native_hooks",
        "integration_mode_label": "session JSONL watcher + managed native hooks",
        "pre_action_interception": "managed_native_hooks",
        "pre_action_label": "managed Bash preflight + approval gate",
        "post_action_observation": "session_log_watcher_native_hooks",
        "post_action_label": "yes",
        "host_config_dependency": "Codex session logs and $CODEX_HOME/hooks.json managed entries must be reachable",
        "failure_mode": "watcher misses sessions when logs are unavailable; native hooks fail open when Gateway is unreachable",
        "maturity": "bounded_native_defense",
        "maturity_label": "medium-high",
    },
    "gemini-cli": {
        "integration_mode": "native_command_hooks",
        "integration_mode_label": "Gemini CLI native command hooks",
        "pre_action_interception": "supported",
        "pre_action_label": "yes, real BeforeTool deny smoke proven for run_shell_command",
        "post_action_observation": "native_hooks_partial_containment",
        "post_action_label": "yes, but post-tool cannot undo side effects",
        "host_config_dependency": "project .gemini/settings.json hooksConfig.enabled plus ClawSentry managed hook entries",
        "failure_mode": "Gemini CLI runs without ClawSentry supervision if hooks are disabled, untrusted, or Gateway is unreachable; fallback policy fails open",
        "maturity": "real_beforetool_block_supported",
        "maturity_label": "medium-high (real BeforeTool deny smoke proven)",
    },

    "kimi-cli": {
        "integration_mode": "native_command_hooks",
        "integration_mode_label": "Kimi CLI native command hooks",
        "pre_action_interception": "supported",
        "pre_action_label": "yes, via Kimi PreToolUse deny",
        "post_action_observation": "native_hooks_observation",
        "post_action_label": "yes, observation only; post-tool cannot undo side effects",
        "host_config_dependency": "$KIMI_SHARE_DIR/config.toml or ~/.kimi/config.toml must contain ClawSentry managed [[hooks]] entries",
        "failure_mode": "Kimi CLI runs without ClawSentry supervision if hooks are absent, disabled by config selection, or Gateway is unreachable; fallback policy fails open",
        "maturity": "native_hook_allow_block_supported",
        "maturity_label": "medium-high (native-hook based; no modify/defer parity)",
    },
    "claude-code": {
        "integration_mode": "host_hooks",
        "integration_mode_label": "host hooks + clawsentry-harness",
        "pre_action_interception": "supported",
        "pre_action_label": "yes",
        "post_action_observation": "supported",
        "post_action_label": "yes",
        "host_config_dependency": "~/.claude/settings.json hooks must stay installed",
        "failure_mode": "Claude Code runs without ClawSentry interception if hooks are missing or bypassed",
        "maturity": "hook_dependent",
        "maturity_label": "medium",
    },
}


def _enabled_frameworks(values: dict[str, str]) -> list[str]:
    enabled: list[str] = []
    for item in values.get("CS_ENABLED_FRAMEWORKS", "").split(","):
        item = item.strip()
        if item and item not in enabled:
            enabled.append(item)
    legacy = values.get("CS_FRAMEWORK", "").strip()
    if legacy and legacy not in enabled:
        enabled.append(legacy)
    return enabled


def _claude_code_hooks_present(claude_home: Path | None = None) -> bool:
    """Return whether Claude Code settings contain ClawSentry hooks."""
    return bool(_claude_code_hook_files(claude_home))


def _claude_code_hook_files(claude_home: Path | None = None) -> list[str]:
    """Return Claude settings files that currently contain ClawSentry hooks."""
    home = claude_home or Path.home() / ".claude"
    found: list[str] = []
    for filename in ("settings.json", "settings.local.json"):
        settings_path = home / filename
        if not settings_path.is_file():
            continue
        try:
            data = json.loads(settings_path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        hooks = data.get("hooks", {})
        if any("clawsentry" in str(value) for value in hooks.values()):
            found.append(str(settings_path))
    return found


def _openclaw_restore_files(openclaw_home: Path | None = None) -> list[str]:
    """Return OpenClaw backup files created by `init openclaw --setup`."""
    home = openclaw_home or Path.home() / ".openclaw"
    backups = [
        home / "openclaw.json.bak",
        home / "exec-approvals.json.bak",
    ]
    return [str(path) for path in backups if path.is_file()]


def _codex_session_dir(values: dict[str, str]) -> Path | None:
    """Resolve the Codex session directory for status reporting."""
    explicit = values.get("CS_CODEX_SESSION_DIR", "").strip()
    if explicit:
        return Path(explicit).expanduser()

    codex_home = Path(
        values.get("CODEX_HOME") or os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))
    ).expanduser()
    return codex_home / "sessions"


def _kimi_config_path(values: dict[str, str]) -> Path:
    explicit = values.get("CS_KIMI_CONFIG_PATH", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    share_dir = values.get("KIMI_SHARE_DIR") or os.environ.get("KIMI_SHARE_DIR")
    if share_dir:
        return Path(share_dir).expanduser() / "config.toml"
    return Path.home() / ".kimi" / "config.toml"


def _read_text_file(path: Path) -> tuple[str | None, str | None]:
    if not path.is_file():
        return None, f"missing file: {path}"
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError as exc:
        return None, f"failed to read {path}: {exc}"


def _gemini_settings_path(target_dir: Path, values: dict[str, str]) -> Path:
    explicit = values.get("CS_GEMINI_SETTINGS_PATH", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    return target_dir / ".gemini" / "settings.json"


def _read_json_object(path: Path) -> tuple[dict[str, object] | None, str | None]:
    """Read a JSON object from disk for host-side readiness checks."""
    if not path.is_file():
        return None, f"missing file: {path}"
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"failed to parse {path}: {exc}"
    if not isinstance(data, dict):
        return None, f"expected JSON object in {path}"
    return data, None


def _status_label(status: str) -> str:
    return status.replace("_", " ")


def _build_framework_readiness(
    *,
    values: dict[str, str],
    enabled: list[str],
    claude_hook_files: list[str],
    openclaw_restore_files: list[str],
    codex_session_dir: Path | None,
    gemini_settings_path: Path | None,
    gemini_settings_payload: dict[str, object] | None,
    gemini_settings_error: str | None,
    kimi_config_path: Path | None,
    kimi_config_text: str | None,
    kimi_config_error: str | None,
    openclaw_home: Path | None = None,
) -> dict[str, dict[str, object]]:
    readiness: dict[str, dict[str, object]] = {}

    if "a3s-code" in enabled:
        gateway_endpoint_configured = bool(
            values.get("CS_UDS_PATH") or values.get("CS_HTTP_PORT")
        )
        warnings: list[str] = []
        if not gateway_endpoint_configured:
            warnings.append("Gateway transport env is not configured in process env or explicit env file.")
        else:
            warnings.append(
                "ClawSentry cannot prove runtime coverage for a3s-code from env alone."
            )
        readiness["a3s-code"] = {
            "status": (
                "manual_verification_required"
                if gateway_endpoint_configured
                else "needs_attention"
            ),
            "summary": (
                "project env is ready, but agent code must wire SessionOptions.ahp_transport"
                if gateway_endpoint_configured
                else "project env is incomplete; configure the Gateway endpoint first"
            ),
            "checks": {
                "gateway_endpoint_configured": gateway_endpoint_configured,
            },
            "warnings": warnings,
            "next_step": (
                "Verify agent code sets SessionOptions.ahp_transport before starting the session."
                if gateway_endpoint_configured
                else "Run clawsentry init a3s-code and ensure CS_UDS_PATH or CS_HTTP_PORT is present."
            ),
        }

    if "codex" in enabled:
        watcher_enabled = (
            values.get("CS_CODEX_WATCH_ENABLED", "").lower()
            in {"1", "true", "yes", "on"}
        )
        session_dir_reachable = bool(codex_session_dir and codex_session_dir.is_dir())
        warnings = []
        if not watcher_enabled:
            warnings.append("Codex watcher is disabled; no session logs will be monitored.")
        if not session_dir_reachable:
            warnings.append("Codex session directory is not reachable.")
        readiness["codex"] = {
            "status": "ready" if watcher_enabled and session_dir_reachable else "needs_attention",
            "summary": (
                "watcher enabled and session directory is reachable"
                if watcher_enabled and session_dir_reachable
                else "observer path is not fully wired; ClawSentry may miss Codex sessions"
            ),
            "checks": {
                "watcher_enabled": watcher_enabled,
                "session_dir_resolved": codex_session_dir is not None,
                "session_dir_reachable": session_dir_reachable,
            },
            "warnings": warnings,
            "next_step": (
                "No action required."
                if watcher_enabled and session_dir_reachable
                else "Set CS_CODEX_SESSION_DIR or ensure $CODEX_HOME/sessions exists, then keep CS_CODEX_WATCH_ENABLED=true."
            ),
        }

    if "claude-code" in enabled:
        hooks_present = bool(claude_hook_files)
        warnings = []
        if not hooks_present:
            warnings.append("ClawSentry hooks were not found in ~/.claude settings files.")
        readiness["claude-code"] = {
            "status": "ready" if hooks_present else "needs_attention",
            "summary": (
                "hooks are installed and Claude Code should emit monitored events"
                if hooks_present
                else "host hooks are missing, so Claude Code can bypass ClawSentry"
            ),
            "checks": {
                "hooks_present": hooks_present,
                "hook_files_found": bool(claude_hook_files),
            },
            "warnings": warnings,
            "next_step": (
                "No action required."
                if hooks_present
                else "Run clawsentry init claude-code to reinstall the required Claude hooks."
            ),
        }

    if "gemini-cli" in enabled:
        hooks_enabled = False
        managed_entries = False
        settings_present = gemini_settings_payload is not None
        if isinstance(gemini_settings_payload, dict):
            hooks_config = gemini_settings_payload.get("hooksConfig")
            hooks = gemini_settings_payload.get("hooks")
            hooks_enabled = (
                isinstance(hooks_config, dict)
                and hooks_config.get("enabled") is True
            ) or (
                isinstance(hooks, dict)
                and hooks.get("enabled") is True
            )
            managed_entries = "clawsentry harness --framework gemini-cli" in str(
                gemini_settings_payload
            )
        warnings = []
        if gemini_settings_error:
            warnings.append(gemini_settings_error)
        if not hooks_enabled:
            warnings.append("Gemini CLI hooks are not enabled in settings.")
        if not managed_entries:
            warnings.append("ClawSentry managed Gemini CLI hooks were not found.")
        ready = settings_present and hooks_enabled and managed_entries
        readiness["gemini-cli"] = {
            "status": "ready" if ready else "needs_attention",
            "summary": (
                "Gemini CLI settings contain enabled ClawSentry managed hooks"
                if ready
                else "Gemini CLI hook settings are not fully wired"
            ),
            "checks": {
                "settings_path": str(gemini_settings_path) if gemini_settings_path else None,
                "settings_present": settings_present,
                "hooks_enabled": hooks_enabled,
                "managed_entries_present": managed_entries,
                "real_beforetool_smoke": True,
            },
            "warnings": warnings,
            "next_step": (
                "No action required for hook installation; real BeforeTool deny smoke is documented in docs/validation."
                if ready
                else "Run clawsentry init gemini-cli --setup (use --dry-run first to preview)."
            ),
        }

    if "kimi-cli" in enabled:
        config_present = kimi_config_text is not None
        managed_entries = bool(kimi_config_text and "clawsentry harness --framework kimi-cli" in kimi_config_text)
        warnings = []
        if kimi_config_error:
            warnings.append(kimi_config_error)
        if not managed_entries:
            warnings.append("ClawSentry managed Kimi CLI hooks were not found.")
        ready = config_present and managed_entries
        readiness["kimi-cli"] = {
            "status": "ready" if ready else "needs_attention",
            "summary": (
                "Kimi config.toml contains ClawSentry managed native hooks"
                if ready
                else "Kimi native hook config is not fully wired"
            ),
            "checks": {
                "config_path": str(kimi_config_path) if kimi_config_path else None,
                "config_present": config_present,
                "managed_entries_present": managed_entries,
                "native_modify_supported": False,
                "native_defer_supported": False,
            },
            "warnings": warnings,
            "next_step": (
                "No action required for hook installation; run the isolated Kimi smoke before claiming production coverage."
                if ready
                else "Run clawsentry init kimi-cli --setup --dry-run, then apply setup after reviewing config.toml changes."
            ),
        }

    if "openclaw" in enabled:
        home = openclaw_home or Path.home() / ".openclaw"
        openclaw_json, openclaw_json_error = _read_json_object(home / "openclaw.json")
        approvals_json, approvals_json_error = _read_json_object(
            home / "exec-approvals.json"
        )
        openclaw_exec_host_gateway = (
            isinstance(openclaw_json, dict)
            and openclaw_json.get("tools", {}).get("exec", {}).get("host") == "gateway"
        )
        exec_approvals_configured = (
            isinstance(approvals_json, dict)
            and approvals_json.get("security") == "allowlist"
            and approvals_json.get("ask") == "always"
        )
        project_env_configured = any(key.startswith("OPENCLAW_") for key in values)
        warnings = []
        if openclaw_json_error:
            warnings.append(openclaw_json_error)
        if approvals_json_error:
            warnings.append(approvals_json_error)
        if project_env_configured and not openclaw_exec_host_gateway:
            warnings.append('openclaw.json is not configured with tools.exec.host = "gateway".')
        if project_env_configured and not exec_approvals_configured:
            warnings.append(
                'exec-approvals.json is not configured with security="allowlist" and ask="always".'
            )
        ready = (
            project_env_configured
            and openclaw_exec_host_gateway
            and exec_approvals_configured
        )
        readiness["openclaw"] = {
            "status": "ready" if ready else "needs_attention",
            "summary": (
                "project env and host approval files are aligned"
                if ready
                else "project env is present, but host-side OpenClaw setup is still incomplete"
            ),
            "checks": {
                "project_env_configured": project_env_configured,
                "openclaw_config_present": openclaw_json is not None,
                "openclaw_exec_host_gateway": openclaw_exec_host_gateway,
                "exec_approvals_present": approvals_json is not None,
                "exec_approvals_configured": exec_approvals_configured,
                "restore_backup_available": bool(openclaw_restore_files),
            },
            "warnings": warnings,
            "next_step": (
                "No action required."
                if ready
                else "Run clawsentry init openclaw --setup --dry-run, then apply setup (or rerun start with --setup-openclaw)."
            ),
        }

    return readiness


def collect_integration_status(
    target_dir: Path,
    *,
    claude_home: Path | None = None,
    openclaw_home: Path | None = None,
    env_values: dict[str, str] | None = None,
    env_file_present: bool = False,
) -> dict[str, object]:
    values = dict(env_values or {})
    enabled, legacy_default = parse_enabled_frameworks(values)
    enabled_framework_details = {
        framework: dict(FRAMEWORK_CAPABILITIES[framework])
        for framework in enabled
        if framework in FRAMEWORK_CAPABILITIES
    }
    claude_hook_files = (
        _claude_code_hook_files(claude_home) if "claude-code" in enabled else []
    )
    openclaw_restore_files = (
        _openclaw_restore_files(openclaw_home) if "openclaw" in enabled else []
    )
    codex_session_dir = (
        _codex_session_dir(values) if "codex" in enabled else None
    )
    gemini_settings_path = (
        _gemini_settings_path(target_dir, values) if "gemini-cli" in enabled else None
    )
    kimi_config_path = (
        _kimi_config_path(values) if "kimi-cli" in enabled else None
    )
    gemini_settings_payload: dict[str, object] | None = None
    gemini_settings_error: str | None = None
    if gemini_settings_path is not None:
        gemini_settings_payload, gemini_settings_error = _read_json_object(
            gemini_settings_path
        )
    kimi_config_text: str | None = None
    kimi_config_error: str | None = None
    if kimi_config_path is not None:
        kimi_config_text, kimi_config_error = _read_text_file(kimi_config_path)
    payload = {
        "env_file": "(explicit only)",
        "env_exists": env_file_present,
        "default_framework": legacy_default,
        "legacy_default": legacy_default,
        "enabled_frameworks": enabled,
        "framework_capabilities": FRAMEWORK_CAPABILITIES,
        "enabled_framework_details": enabled_framework_details,
        "codex_watcher_enabled": (
            values.get("CS_CODEX_WATCH_ENABLED", "").lower()
            in {"1", "true", "yes", "on"}
        ),
        "openclaw_env_configured": any(key.startswith("OPENCLAW_") for key in values),
        "openclaw_restore_available": bool(openclaw_restore_files),
        "openclaw_restore_files": openclaw_restore_files,
        "claude_code_hooks": (
            "claude-code" in enabled and bool(claude_hook_files)
        ),
        "claude_code_hook_files": claude_hook_files,
        "a3s_transport_env": (
            "a3s-code" in enabled
            and bool(values.get("CS_UDS_PATH") or values.get("CS_HTTP_PORT"))
        ),
        "codex_session_dir": str(codex_session_dir) if codex_session_dir else None,
        "codex_session_dir_reachable": bool(
            codex_session_dir and codex_session_dir.is_dir()
        ),
        "gemini_cli_hooks": (
            "gemini-cli" in enabled
            and gemini_settings_payload is not None
            and "clawsentry harness --framework gemini-cli" in str(gemini_settings_payload)
        ),
        "gemini_cli_settings_path": (
            str(gemini_settings_path) if gemini_settings_path else None
        ),
        "gemini_cli_settings_present": bool(
            gemini_settings_path and gemini_settings_path.is_file()
        ),
        "kimi_cli_hooks": (
            "kimi-cli" in enabled
            and kimi_config_text is not None
            and "clawsentry harness --framework kimi-cli" in kimi_config_text
        ),
        "kimi_cli_config_path": (
            str(kimi_config_path) if kimi_config_path else None
        ),
        "kimi_cli_config_present": bool(
            kimi_config_path and kimi_config_path.is_file()
        ),
    }
    payload["framework_readiness"] = _build_framework_readiness(
        values=values,
        enabled=enabled,
        claude_hook_files=claude_hook_files,
        openclaw_restore_files=openclaw_restore_files,
        codex_session_dir=codex_session_dir,
        gemini_settings_path=gemini_settings_path,
        gemini_settings_payload=gemini_settings_payload,
        gemini_settings_error=gemini_settings_error,
        kimi_config_path=kimi_config_path,
        kimi_config_text=kimi_config_text,
        kimi_config_error=kimi_config_error,
        openclaw_home=openclaw_home,
    )
    return payload


def run_integrations_status(
    *,
    target_dir: Path = Path("."),
    json_mode: bool = False,
    env_file: Path | None = None,
) -> int:
    """Print configured framework integration status."""
    try:
        parsed = resolve_explicit_env_file(cli_env_file=env_file, environ=os.environ)
    except EnvFileError as exc:
        print(str(exc))
        return 2
    effective_env = overlay_env_file(os.environ, parsed)
    payload = collect_integration_status(
        target_dir,
        env_values=effective_env,
        env_file_present=parsed.path is not None,
    )
    if parsed.path:
        payload["env_file"] = str(parsed.path)
        payload["env_exists"] = True
    if json_mode:
        print(json.dumps(payload, indent=2))
        return 0

    enabled = payload["enabled_frameworks"]
    enabled_text = ", ".join(enabled) if enabled else "(none)"
    print("ClawSentry Integrations")
    print("=" * 60)
    print(f"Env file: {payload['env_file']}")
    print(f"Env exists: {'yes' if payload['env_exists'] else 'no'}")
    print(f"Enabled frameworks: {enabled_text}")
    print(f"Default framework: {payload['default_framework'] or '(none)'}")
    print(
        "Codex watcher: "
        f"{'enabled' if payload['codex_watcher_enabled'] else 'disabled'}"
    )
    print(
        "OpenClaw env: "
        f"{'configured' if payload['openclaw_env_configured'] else 'not configured'}"
    )
    print(
        "OpenClaw restore: "
        f"{'available' if payload['openclaw_restore_available'] else 'not available'}"
    )
    restore_files = payload["openclaw_restore_files"]
    print(
        "OpenClaw restore files: "
        f"{', '.join(restore_files) if restore_files else '(none)'}"
    )
    print(
        "a3s transport env: "
        f"{'configured' if payload['a3s_transport_env'] else 'not configured'}"
    )
    print(
        "Claude hooks: "
        f"{'present' if payload['claude_code_hooks'] else 'not present'}"
    )
    hook_files = payload["claude_code_hook_files"]
    print(
        "Claude hooks files: "
        f"{', '.join(hook_files) if hook_files else '(none)'}"
    )
    codex_session_dir = payload["codex_session_dir"]
    if codex_session_dir:
        codex_status = (
            "reachable" if payload["codex_session_dir_reachable"] else "missing"
        )
        print(f"Codex session dir: {codex_session_dir} ({codex_status})")
    else:
        print("Codex session dir: (not configured)")
    gemini_settings_path = payload["gemini_cli_settings_path"]
    if gemini_settings_path:
        print(
            "Gemini settings: "
            f"{gemini_settings_path} "
            f"({'present' if payload['gemini_cli_settings_present'] else 'missing'})"
        )
        print(
            "Gemini hooks: "
            f"{'present' if payload['gemini_cli_hooks'] else 'not present'}"
        )
    else:
        print("Gemini settings: (not configured)")
    kimi_config_path = payload["kimi_cli_config_path"]
    if kimi_config_path:
        print(
            "Kimi config: "
            f"{kimi_config_path} "
            f"({'present' if payload['kimi_cli_config_present'] else 'missing'})"
        )
        print(
            "Kimi hooks: "
            f"{'present' if payload['kimi_cli_hooks'] else 'not present'}"
        )
    else:
        print("Kimi config: (not configured)")
    all_capabilities = payload["framework_capabilities"]
    framework_details = payload["enabled_framework_details"]
    print("Framework capabilities:")
    if all_capabilities:
        for framework, details in all_capabilities.items():
            print(
                f"{framework}: mode={details['integration_mode']} "
                f"pre={details['pre_action_interception']} "
                f"post={details['post_action_observation']} "
                f"maturity={details['maturity']}"
            )
    else:
        print("(none)")
    print("Enabled framework details:")
    if framework_details:
        for framework in enabled:
            details = framework_details.get(framework)
            if not details:
                continue
            print(
                f"{framework}: {details['integration_mode_label']} | "
                f"pre-action: {details['pre_action_label']} | "
                f"post-action: {details['post_action_label']} | "
                f"maturity: {details['maturity_label']}"
            )
            print(f"  dependency: {details['host_config_dependency']}")
            print(f"  failure mode: {details['failure_mode']}")
    else:
        print("(none)")
    readiness = payload["framework_readiness"]
    print("Readiness:")
    if readiness:
        for framework in enabled:
            details = readiness.get(framework)
            if not details:
                continue
            print(
                f"{framework}: {_status_label(str(details['status']))} | "
                f"{details['summary']}"
            )
            for warning in details["warnings"]:
                print(f"  warning: {warning}")
            next_step = details.get("next_step")
            if next_step:
                print(f"  next step: {next_step}")
    else:
        print("(none)")
    print("=" * 60)
    return 0
