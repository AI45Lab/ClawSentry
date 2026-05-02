"""Env-first ClawSentry configuration registry and resolver.

Normal configuration sources are explicit and layered as:
CLI overrides > process environment > selected explicit env-file > built-in defaults.
This module never discovers, reads, or writes project-local TOML configuration.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, MutableMapping

from clawsentry.cli.dotenv_loader import ParsedEnvFile

_VALID_MODES = {"normal", "strict", "permissive", "benchmark"}
_VALID_PRESETS = {"low", "medium", "high", "strict"}
_SUPPORTED_FRAMEWORKS = frozenset({
    "openclaw",
    "a3s-code",
    "codex",
    "claude-code",
    "gemini-cli",
    "kimi-cli",
})


@dataclass(frozen=True)
class ConfigField:
    key: str
    env_var: str | None
    default: Any
    typ: type = str
    category: str = "general"
    description: str = ""
    secret: bool = False
    deprecated_aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class EffectiveConfig:
    """Resolved operator-facing config values and source metadata."""

    values: dict[str, Any]
    sources: dict[str, str]
    source_details: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def rows(self) -> list[tuple[str, Any, str]]:
        return [(key, self.values[key], self.sources.get(key, "default")) for key in sorted(self.values)]

    def source_detail_for(self, key: str) -> str | None:
        return self.source_details.get(key)


def _as_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    raw = str(value).strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


def _redact_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "***"
    if value.startswith("sk-"):
        return f"{value[:4]}... (redacted)"
    return f"{value[:4]}...{value[-4:]}"


CONFIG_FIELDS: tuple[ConfigField, ...] = (
    ConfigField("project.enabled", "CS_PROJECT_ENABLED", True, bool, "project", "Enable ClawSentry for this process", deprecated_aliases=("CS_ENABLED",)),
    ConfigField("project.mode", "CS_MODE", "normal", str, "project", "Runtime mode"),
    ConfigField("project.preset", "CS_PRESET", "medium", str, "project", "Detection preset"),
    ConfigField("llm.provider", "CS_LLM_PROVIDER", "", str, "llm", "LLM provider"),
    ConfigField("llm.api_key_env", "CS_LLM_API_KEY_ENV", "CS_LLM_API_KEY", str, "llm", "API key env var name"),
    ConfigField("llm.api_key", None, "", str, "llm", "Resolved LLM API key", secret=True),
    ConfigField("llm.model", "CS_LLM_MODEL", "", str, "llm", "LLM model"),
    ConfigField("llm.base_url", "CS_LLM_BASE_URL", "", str, "llm", "OpenAI-compatible base URL"),
    ConfigField("features.l2", "CS_L2_ENABLED", False, bool, "features", "L2 request flag"),
    ConfigField("features.l3", "CS_L3_ENABLED", False, bool, "features", "L3 request flag"),
    ConfigField("features.enterprise", "CS_ENTERPRISE_ENABLED", False, bool, "features", "Enterprise analysis flag"),
    ConfigField("scope.profile_file", "CS_SESSION_SCOPE_PROFILE_FILE", "", str, "scope", "Default session scope profile file"),
    ConfigField("budgets.llm_token_budget_enabled", "CS_LLM_TOKEN_BUDGET_ENABLED", False, bool, "budgets", "Enable LLM token budget"),
    ConfigField("budgets.llm_daily_token_budget", "CS_LLM_DAILY_TOKEN_BUDGET", 0, int, "budgets", "Daily LLM token budget"),
    ConfigField("budgets.llm_token_budget_scope", "CS_LLM_TOKEN_BUDGET_SCOPE", "total", str, "budgets", "Budget scope"),
    ConfigField("budgets.l2_timeout_ms", "CS_L2_TIMEOUT_MS", 60_000.0, float, "budgets", "L2 timeout"),
    ConfigField("budgets.l3_timeout_ms", "CS_L3_TIMEOUT_MS", 300_000.0, float, "budgets", "L3 timeout", deprecated_aliases=("CS_L3_BUDGET_MS",)),
    ConfigField("budgets.hard_timeout_ms", "CS_HARD_TIMEOUT_MS", 600_000.0, float, "budgets", "Hard timeout"),
    ConfigField("defer.bridge_enabled", "CS_DEFER_BRIDGE_ENABLED", True, bool, "defer", "Enable DEFER bridge"),
    ConfigField("defer.timeout_s", "CS_DEFER_TIMEOUT_S", 86_400.0, float, "defer", "DEFER timeout seconds"),
    ConfigField("defer.timeout_action", "CS_DEFER_TIMEOUT_ACTION", "block", str, "defer", "DEFER timeout action"),
    ConfigField("defer.max_pending", "CS_DEFER_MAX_PENDING", 0, int, "defer", "DEFER max pending"),
    ConfigField("benchmark.auto_resolve_defer", "CS_BENCHMARK_AUTO_RESOLVE_DEFER", True, bool, "benchmark", "Benchmark auto-resolve DEFER"),
    ConfigField("benchmark.defer_action", "CS_BENCHMARK_DEFER_ACTION", "block", str, "benchmark", "Benchmark DEFER action"),
    ConfigField("benchmark.persist_scope", "CS_BENCHMARK_PERSIST_SCOPE", "project", str, "benchmark", "Benchmark persistence scope"),
    ConfigField("frameworks.enabled", "CS_ENABLED_FRAMEWORKS", [], list, "frameworks", "Enabled frameworks"),
    ConfigField("frameworks.default", "CS_FRAMEWORK", "", str, "frameworks", "Default framework"),
)

_FIELDS_BY_KEY = {field.key: field for field in CONFIG_FIELDS}
_ENV_TO_KEY = {field.env_var: field.key for field in CONFIG_FIELDS if field.env_var}
_KEY_TO_ENV = {field.key: field.env_var for field in CONFIG_FIELDS if field.env_var}
_ALIAS_TO_FIELD: dict[str, tuple[ConfigField, str]] = {
    alias: (field, field.env_var or field.key)
    for field in CONFIG_FIELDS
    for alias in field.deprecated_aliases
}


def canonical_env_source_for(key: str) -> str | None:
    return _KEY_TO_ENV.get(key)


def default_values() -> dict[str, Any]:
    return {field.key: (list(field.default) if isinstance(field.default, list) else field.default) for field in CONFIG_FIELDS}


def _coerce(field: ConfigField, raw: Any) -> Any:
    if field.typ is bool:
        return _as_bool(raw, bool(field.default))
    if field.typ is int:
        return int(raw)
    if field.typ is float:
        return float(raw)
    if field.typ is list:
        if isinstance(raw, list):
            return [str(item).strip() for item in raw if str(item).strip()]
        return [item.strip() for item in str(raw).split(",") if item.strip()]
    return str(raw)


def _detail(parsed: ParsedEnvFile | None, env_key: str) -> str:
    if parsed is None:
        return env_key
    return parsed.source_detail_for(env_key) or env_key


def _set_value(
    *,
    key: str,
    value: Any,
    source: str,
    detail: str | None,
    values: dict[str, Any],
    sources: dict[str, str],
    source_details: dict[str, str],
) -> None:
    values[key] = value
    sources[key] = source
    if detail:
        source_details[key] = detail
    else:
        source_details.pop(key, None)


def parse_enabled_frameworks(values: Mapping[str, str]) -> tuple[list[str], str]:
    """Return enabled frameworks and default framework from env-like values."""
    enabled: list[str] = []
    for item in str(values.get("CS_ENABLED_FRAMEWORKS", "") or "").split(","):
        item = item.strip()
        if item and item in _SUPPORTED_FRAMEWORKS and item not in enabled:
            enabled.append(item)
    default = str(values.get("CS_FRAMEWORK", "") or "").strip()
    if default and default not in _SUPPORTED_FRAMEWORKS:
        default = ""
    if default and default not in enabled:
        enabled.append(default)
    return enabled, default


def resolve_effective_config(
    *,
    environ: Mapping[str, str] | None = None,
    env_file: ParsedEnvFile | None = None,
    env_file_values: Mapping[str, str] | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
) -> EffectiveConfig:
    env = os.environ if environ is None else environ
    file_values = env_file.values if env_file is not None else dict(env_file_values or {})
    cli = dict(cli_overrides or {})
    values = default_values()
    sources = {key: "default" for key in values}
    source_details: dict[str, str] = {}
    warnings: list[str] = []

    def apply_env_map(raw_values: Mapping[str, str], source: str, parsed: ParsedEnvFile | None = None) -> None:
        for env_key, key in _ENV_TO_KEY.items():
            raw = raw_values.get(env_key)
            if raw is None or str(raw).strip() == "":
                continue
            field = _FIELDS_BY_KEY[key]
            try:
                _set_value(
                    key=key,
                    value=_coerce(field, raw),
                    source=source,
                    detail=_detail(parsed, env_key) if source == "env-file" else env_key,
                    values=values,
                    sources=sources,
                    source_details=source_details,
                )
            except (TypeError, ValueError):
                warnings.append(f"Ignoring invalid {source} {env_key}={raw!r}")

    apply_env_map(file_values, "env-file", env_file)
    apply_env_map(env, "process-env", None)

    for alias, (field, canonical) in _ALIAS_TO_FIELD.items():
        raw = env.get(alias)
        if raw is None or str(raw).strip() == "":
            continue
        if canonical in env or sources.get(field.key) in {"process-env", "env-file", "cli"}:
            warnings.append(f"Ignoring deprecated {alias}; canonical {canonical} wins")
            continue
        try:
            _set_value(
                key=field.key,
                value=_coerce(field, raw),
                source="deprecated-env-alias",
                detail=alias,
                values=values,
                sources=sources,
                source_details=source_details,
            )
            warnings.append(f"Deprecated {alias}; use {canonical}")
        except (TypeError, ValueError):
            warnings.append(f"Ignoring invalid {alias}={raw!r}")

    for key, raw in cli.items():
        if raw is None or str(raw).strip() == "" or key not in _FIELDS_BY_KEY:
            continue
        field = _FIELDS_BY_KEY[key]
        try:
            _set_value(
                key=key,
                value=_coerce(field, raw),
                source="cli",
                detail=key,
                values=values,
                sources=sources,
                source_details=source_details,
            )
        except (TypeError, ValueError):
            warnings.append(f"Ignoring invalid CLI override {key}={raw!r}")

    # Normalize framework values from the final env-like map/source precedence.
    effective_raw_framework_env: dict[str, str] = {}
    for key in ("CS_ENABLED_FRAMEWORKS", "CS_FRAMEWORK"):
        if key in file_values:
            effective_raw_framework_env[key] = str(file_values[key])
        if key in env:
            effective_raw_framework_env[key] = str(env[key])
    if "frameworks.enabled" in cli:
        raw = cli["frameworks.enabled"]
        effective_raw_framework_env["CS_ENABLED_FRAMEWORKS"] = ",".join(raw) if isinstance(raw, list) else str(raw)
    if "frameworks.default" in cli:
        effective_raw_framework_env["CS_FRAMEWORK"] = str(cli["frameworks.default"])
    enabled, default = parse_enabled_frameworks(effective_raw_framework_env)
    if enabled or sources.get("frameworks.enabled") != "default":
        values["frameworks.enabled"] = enabled
    if default or sources.get("frameworks.default") != "default":
        values["frameworks.default"] = default

    if values.get("project.mode") not in _VALID_MODES:
        warnings.append(f"Invalid project.mode={values.get('project.mode')!r}; using normal")
        values["project.mode"] = "normal"
    if values.get("project.preset") not in _VALID_PRESETS:
        warnings.append(f"Invalid project.preset={values.get('project.preset')!r}; using medium")
        values["project.preset"] = "medium"

    api_key_env = str(values.get("llm.api_key_env") or "CS_LLM_API_KEY")
    api_key = ""
    api_source = "default"
    api_detail: str | None = None
    if api_key_env in file_values and str(file_values[api_key_env]).strip():
        api_key = str(file_values[api_key_env])
        api_source = "env-file"
        api_detail = _detail(env_file, api_key_env)
    if api_key_env in env and str(env[api_key_env]).strip():
        api_key = str(env[api_key_env])
        api_source = "process-env"
        api_detail = api_key_env
    provider = str(values.get("llm.provider") or "").lower()
    provider_key = "OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY" if provider == "anthropic" else ""
    if not api_key and provider_key:
        if provider_key in file_values and str(file_values[provider_key]).strip():
            api_key = str(file_values[provider_key])
            api_source = "env-file"
            api_detail = _detail(env_file, provider_key)
        if provider_key in env and str(env[provider_key]).strip():
            api_key = str(env[provider_key])
            api_source = "process-env"
            api_detail = provider_key
    _set_value(
        key="llm.api_key",
        value=_redact_secret(api_key),
        source=api_source if api_key else "default",
        detail=api_detail,
        values=values,
        sources=sources,
        source_details=source_details,
    )

    if _as_bool(values.get("budgets.llm_token_budget_enabled")) and int(values.get("budgets.llm_daily_token_budget") or 0) <= 0:
        warnings.append("Token budget enabled with non-positive limit; runtime disables enforcement")

    return EffectiveConfig(values=values, sources=sources, source_details=source_details, warnings=warnings)


def config_to_child_env(
    *,
    environ: Mapping[str, str] | None = None,
    env_file: ParsedEnvFile | None = None,
    cli_overrides: Mapping[str, Any] | None = None,
) -> dict[str, str]:
    """Build a child process env using env-file, process env, then CLI overrides."""
    env = os.environ if environ is None else environ
    child: dict[str, str] = dict(env_file.values if env_file is not None else {})
    child.update({str(k): str(v) for k, v in env.items()})
    effective = resolve_effective_config(environ=env, env_file=env_file, cli_overrides=cli_overrides)
    for key, source in effective.sources.items():
        if source != "cli":
            continue
        env_key = canonical_env_source_for(key)
        if env_key:
            value = effective.values[key]
            if isinstance(value, list):
                child[env_key] = ",".join(str(item) for item in value)
            elif isinstance(value, bool):
                child[env_key] = "true" if value else "false"
            else:
                child[env_key] = str(value)
    return child


def write_env_template(
    path: Path,
    *,
    framework: str = "codex",
    mode: str = "normal",
    preset: str = "medium",
    llm_provider: str = "",
    llm_model: str = "",
    llm_base_url: str = "",
    l2: bool = False,
    l3: bool = False,
    token_budget: int = 0,
    force: bool = False,
) -> None:
    if path.exists() and not force:
        raise FileExistsError(f"{path} already exists. Use --force to overwrite.")
    lines = [
        "# ClawSentry env-first configuration example",
        "# Copy to .clawsentry.env.local for local-only secrets, or export these variables.",
        "# Source precedence: CLI > process env > explicit --env-file/CLAWSENTRY_ENV_FILE > defaults.",
        "# This file is not auto-discovered; pass it with --env-file when needed.",
        "",
        f"CS_FRAMEWORK={framework}",
        f"CS_ENABLED_FRAMEWORKS={framework}",
        f"CS_MODE={mode}",
        f"CS_PRESET={preset}",
        f"CS_LLM_PROVIDER={llm_provider}",
        f"CS_LLM_MODEL={llm_model}",
        f"CS_LLM_BASE_URL={llm_base_url}",
        "# Set CS_LLM_API_KEY in local env/secrets manager; do not commit real secrets.",
        f"CS_L2_ENABLED={'true' if l2 else 'false'}",
        f"CS_L3_ENABLED={'true' if l3 else 'false'}",
        "CS_ENTERPRISE_ENABLED=false",
        "# Optional: default task-boundary profile applied to every pre_action.",
        "# CS_SESSION_SCOPE_PROFILE_FILE=scope.json",
        f"CS_LLM_TOKEN_BUDGET_ENABLED={'true' if token_budget > 0 else 'false'}",
        f"CS_LLM_DAILY_TOKEN_BUDGET={int(token_budget)}",
        "CS_LLM_TOKEN_BUDGET_SCOPE=total",
        "CS_L2_TIMEOUT_MS=60000",
        "CS_L3_TIMEOUT_MS=300000",
        "CS_HARD_TIMEOUT_MS=600000",
        "CS_DEFER_BRIDGE_ENABLED=true",
        "CS_DEFER_TIMEOUT_S=86400",
        "CS_DEFER_TIMEOUT_ACTION=block",
        "CS_DEFER_MAX_PENDING=0",
        "CS_BENCHMARK_AUTO_RESOLVE_DEFER=true",
        "CS_BENCHMARK_DEFER_ACTION=block",
        "CS_BENCHMARK_PERSIST_SCOPE=project",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def set_env_file_value(path: Path, key: str, value: str, *, force_secret: bool = False) -> None:
    if key not in set(_ENV_TO_KEY) | {"CS_AUTH_TOKEN", "CS_LLM_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"}:
        raise ValueError(f"Unknown or unsupported env key: {key}")
    if any(secret in key for secret in ("TOKEN", "API_KEY", "SECRET")) and not force_secret:
        # The caller still requested an explicit file target, so allow placeholder writes
        # but avoid accidentally encouraging real secret persistence.
        value = value
    existing: list[str] = []
    if path.exists():
        existing = path.read_text(encoding="utf-8").splitlines()
    seen = False
    output: list[str] = []
    for line in existing:
        if line.strip().startswith(f"{key}=") or line.strip().startswith(f"export {key}="):
            output.append(f"{key}={value}")
            seen = True
        else:
            output.append(line)
    if not seen:
        if output and output[-1].strip():
            output.append("")
        output.append(f"{key}={value}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(output).rstrip() + "\n", encoding="utf-8")
    path.chmod(0o600)


def export_instruction(key: str, value: str) -> str:
    return f"export {key}={value}"
