"""Shared low-level risk signal predicates for L3-related analyzers."""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Iterable


READ_TOOLS = frozenset({"read_file", "read", "cat", "head", "tail"})
WRITE_TOOLS = frozenset({
    "write_file", "edit_file", "create_file", "write", "edit", "chmod", "chown",
})
EXEC_TOOLS = frozenset({"bash", "shell", "exec", "sudo"})
NETWORK_TOOLS = frozenset({"http_request", "fetch", "web_fetch", "curl", "wget"})

CREDENTIAL_HINTS = frozenset({
    "credential_access",
    "credential_exfiltration",
    "credential_exfiltration_confirmed",
    "secret_access",
    "key_access",
    "env_access",
    "config_access",
})
NETWORK_HINTS = frozenset({
    "data_exfiltration",
    "network_exfiltration",
    "suspicious_network",
})
ARCHIVE_TOKENS = (
    "tar ",
    "zip ",
    "gzip ",
    "base64 ",
)
BASE64_DECODE_TOKENS = (
    "base64 -d",
    "base64 --decode",
    "base64 -d ",
    "base64 --decode ",
)
ARCHIVE_RESTORE_TOKENS = (
    "tar -x",
    "tar x",
    "tar --extract",
    "unzip ",
    "gunzip ",
    "gzip -d",
    "gzip --decompress",
)
ARCHIVE_INSPECTION_TOKENS = (
    "tar -t",
    "tar t",
    "tar --list",
    "gzip -l",
    "gzip -t",
    "gzip --list",
    "gzip --test",
    "zip -t",
    "zip --test",
    "zip -sf",
    "zip --show-files",
)

_CREDENTIAL_PATH_RE = re.compile(
    r"\.(env|pem|key|p12|pfx|jks|keystore)(?:$|[^a-z0-9])|"
    r"id_rsa|id_ed25519|credentials|\.secret|\.token|\.password|"
    r"\.aws/|\.ssh/",
    re.IGNORECASE,
)
_NETWORK_COMMAND_RE = re.compile(r"\b(curl|wget|scp|rsync|nc|ncat|socat)\b|https?://", re.IGNORECASE)
_REMOTE_PIPE_EXEC_RE = re.compile(
    r"(?:curl|wget)\b.*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
    re.IGNORECASE,
)
_DECODE_PIPE_EXEC_PATTERNS = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"base64\s+(?:-d|--decode)\b.*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
        r"xxd\s+-r\b.*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
        r"printf\s+.*\\x[0-9a-f]{2}.*\|\s*(?:sh|bash|zsh|dash|ksh)\b",
    )
)
_EVAL_DECODE_RE = re.compile(r"eval[\s(].*(?:base64|xxd|printf|decode)", re.IGNORECASE)
_SCRIPT_ENCODED_EXEC_RE = re.compile(
    r"(?:python[23]?|perl|ruby)\s+-[ec]\s+.*(?:base64|b64decode|decode|exec|eval)",
    re.IGNORECASE,
)
_PROCESS_SUB_REMOTE_RE = re.compile(
    r"(?:bash|sh|zsh)\s+<\(\s*(?:curl|wget)\b",
    re.IGNORECASE,
)
_HEREDOC_EXEC_RE = re.compile(
    r"(?:sh|bash|zsh)\s+<<-?\s*['\"]?[a-zA-Z_]",
    re.IGNORECASE,
)
_VARIABLE_EXPANSION_RE = re.compile(
    r"(?:[a-zA-Z_]\w{0,2}=[^;\s]+;){2,}[^;$]{0,40}\$[a-zA-Z_{]",
)
_VARIABLE_EXEC_TRIGGER_RE = re.compile(
    r"\$[a-zA-Z_{][^\n]{0,60}(?:\||>|`|/tmp/|/dev/|https?://)",
)
_RECON_RE = re.compile(
    r"\b(uname|id|whoami|hostname|cat\s+/etc/(os-release|issue|passwd)|lsb_release|arch)\b",
    re.IGNORECASE,
)
_PRIVESC_RE = re.compile(
    r"\bsudo\b.*\b(chmod|chown|rm|mv|cp|useradd|usermod|visudo|passwd|install)\b",
    re.IGNORECASE,
)
_TMP_PATH_RE = re.compile(r"/tmp/|/var/tmp/|c:\\temp\\", re.IGNORECASE)

_NETWORK_INDICATOR_TOKENS = (
    "curl",
    "wget",
    "http://",
    "https://",
    "scp",
    "rsync",
    "nc ",
    "ncat",
    "socat",
    "dig ",
    "nslookup",
)
_STAGING_INDICATOR_TOKENS = (
    "cp ",
    "mv ",
    "tee ",
    ">",
)
_RECON_INDICATOR_TOKENS = (
    "whoami",
    "id",
    "uname",
    "hostname",
    "printenv",
    "env",
    "/etc/os-release",
    "ps -",
    "ss -",
    "ifconfig",
    "ip addr",
)
_FILE_WRITE_CONTENT_TOOLS = WRITE_TOOLS | frozenset({"multi_edit", "multiedit", "apply_patch"})
_SHELL_WRITE_TOOLS = frozenset({
    "bash",
    "sh",
    "shell",
    "terminal",
    "command",
    "exec",
    "exec_command",
    "run_shell_command",
})
_DELEGATED_WRITE_TOOLS = frozenset({"agent", "task", "delegate", "subagent"})
_SHELL_FILE_WRITE_RE = re.compile(
    r"(?:^|[;&|]\s*)(?:"
    r"tee\s+(?:-a\s+)?(?:['\"]?)(?:~|/|[A-Za-z]:\\|[A-Za-z0-9_.-]+/)|"
    r"dd\b[\s\S]{0,160}\bof\s*=\s*(?:['\"]?)(?:~|/|[A-Za-z]:\\|[A-Za-z0-9_.-]+/)|"
    r"(?:cat|echo|printf|python[23]?|node)\b[\s\S]{0,400}"
    r"(?:>>?|tee\s+(?:-a\s+)?)\s*(?:['\"]?)(?:~|/|[A-Za-z]:\\|[A-Za-z0-9_.-]+/)"
    r")",
    re.IGNORECASE,
)
_SHELL_PROGRAMMATIC_FILE_WRITE_RE = re.compile(
    r"\b(?:python[23]?|node)\b[\s\S]{0,2000}"
    r"(?:\bopen\s*\(\s*['\"][^'\"]+['\"]\s*,\s*['\"][wax][^'\"]*['\"]|"
    r"\bwrite_text\s*\(|\bwrite_bytes\s*\(|\bwriteFile(?:Sync)?\s*\()",
    re.IGNORECASE,
)
_DELEGATED_WRITE_INTENT_RE = re.compile(
    r"\b(?:write|create|edit|modify|generate|save|persist)\b[\s\S]{0,240}"
    r"(?:~|/|[A-Za-z]:\\|[A-Za-z0-9_.-]+/)",
    re.IGNORECASE,
)
_ENCODED_OR_OBFUSCATED_WRITE_RE = re.compile(
    r"\b(?:base64(?:\.b64decode|\s+(?:-d|--decode))|b64decode|atob\s*\(|"
    r"fromCharCode|bytes\.fromhex|xxd\s+-r|decodeURIComponent\s*\()",
    re.IGNORECASE,
)
_PATH_LITERAL_RE = re.compile(
    r"['\"](?P<path>(?:~|/|[A-Za-z]:\\|[A-Za-z0-9_.-]+/)[^'\"\s<>]+)['\"]"
)
_AUTOSTART_PATH_RE = re.compile(
    r"(^|/)(?:"
    r"\.bashrc|\.bash_profile|\.profile|\.zshrc|\.config/autostart/|"
    r"\.git/hooks/|crontab|cron\.d/|systemd/(?:system|user)/|"
    r"launchagents/|launchdaemons/|schtasks|startup|service-worker\.js|"
    r"package\.json|dockerfile|docker-compose\.ya?ml|\.github/workflows/"
    r")(?:$|/)",
    re.IGNORECASE,
)
_ENTRYPOINT_PATH_RE = re.compile(
    r"(^|/)(?:index|main|app)\.(?:html|js|mjs|cjs|ts|tsx|jsx)$|"
    r"(^|/)(?:package|manifest|importmap)\.json$",
    re.IGNORECASE,
)
_BOOTSTRAP_LOADER_PATH_RE = re.compile(
    r"(^|/)(?:bootstrap|startup|reentry|loader)/[^/\s'\"<>]+\."
    r"(?:js|mjs|cjs|ts|tsx|jsx)$",
    re.IGNORECASE,
)
_LOADER_REFERENCE_RE = re.compile(
    r"<(?:script|link)\b[^>]*(?:src|href|rel)\s*=\s*['\"][^'\"]*"
    r"(?:loader|bootstrap|startup|manifest)[^'\"]*['\"]",
    re.IGNORECASE,
)
_INLINE_LOADER_CONTRACT_RE = re.compile(
    r"(?is)<script\b[^>]*(?:type\s*=\s*['\"]application/json['\"]|"
    r"(?:id|class|name)\s*=\s*['\"][^'\"]*(?:loader|bootstrap|startup|reentry|manifest)[^'\"]*['\"])[^>]*>"
    r"[\s\S]*?\b(?:loader_path|loader_mode|bootstrap_scope)\b[\s\S]*?</script>|"
    r"\b(?:loader_path|loader_mode|bootstrap_scope)\b"
)
_AUTOLOAD_INTENT_RE = re.compile(
    r"\b(?:autoload(?:[_-]?on[_-]?open)?|auto[-_ ]?load|startup|start[-_ ]?up|re[-_ ]?entry|"
    r"reenter|restore[-_ ]?session|resume[-_ ]?session|persist(?:ence|ent)?|"
    r"on\s+(?:load|startup|open)|at\s+(?:startup|login|boot))\b",
    re.IGNORECASE,
)
_EXECUTION_ENTRYPOINT_RE = re.compile(
    r"\b(?:eval|Function|setTimeout|setInterval|import\s*\(|require\s*\(|"
    r"child_process|subprocess|os\.system|exec\s*\(|register\(|"
    r"serviceWorker\.register|NODE_OPTIONS|LD_PRELOAD|PYTHONPATH)\b",
    re.IGNORECASE,
)
_DYNAMIC_OR_REMOTE_CODE_RE = re.compile(
    r"(?:https?://|fetch\s*\(|XMLHttpRequest|atob\s*\(|base64|fromCharCode|"
    r"unescape\s*\(|decodeURIComponent\s*\()",
    re.IGNORECASE,
)
_WINDOW_LOADER_STATE_RE = re.compile(
    r"\b(?:window|globalThis|global)\.__[A-Za-z0-9_$]*"
    r"(?:loader|bootstrap|startup|reentry)[A-Za-z0-9_$]*\b",
    re.IGNORECASE,
)


def normalize_hints(risk_hints: Iterable[str] | None) -> set[str]:
    return {str(h).lower() for h in (risk_hints or [])}


def is_credential_path(value: str) -> bool:
    return bool(_CREDENTIAL_PATH_RE.search(str(value or "")))


def is_temp_path(value: str) -> bool:
    return bool(_TMP_PATH_RE.search(str(value or "")))


def has_network_command(value: str) -> bool:
    return bool(_NETWORK_COMMAND_RE.search(str(value or "")))


def has_remote_pipe_exec_command(value: str) -> bool:
    return bool(_REMOTE_PIPE_EXEC_RE.search(str(value or "")))


def has_decode_pipe_exec_command(value: str) -> bool:
    text = str(value or "")
    return any(pattern.search(text) for pattern in _DECODE_PIPE_EXEC_PATTERNS)


def has_eval_decode_command(value: str) -> bool:
    return bool(_EVAL_DECODE_RE.search(str(value or "")))


def has_script_encoded_exec_command(value: str) -> bool:
    return bool(_SCRIPT_ENCODED_EXEC_RE.search(str(value or "")))


def has_process_sub_remote_command(value: str) -> bool:
    return bool(_PROCESS_SUB_REMOTE_RE.search(str(value or "")))


def has_heredoc_exec_command(value: str) -> bool:
    return bool(_HEREDOC_EXEC_RE.search(str(value or "")))


def has_variable_expansion_command(value: str) -> bool:
    return bool(_VARIABLE_EXPANSION_RE.search(str(value or "")))


def has_variable_exec_trigger_command(value: str) -> bool:
    return bool(_VARIABLE_EXEC_TRIGGER_RE.search(str(value or "")))


def has_recon_command(value: str) -> bool:
    return bool(_RECON_RE.search(str(value or "")))


def has_privilege_escalation_command(value: str) -> bool:
    return bool(_PRIVESC_RE.search(str(value or "")))

def has_network_indicator(value: str) -> bool:
    text = str(value or "").lower()
    return any(token in text for token in _NETWORK_INDICATOR_TOKENS)


def has_staging_indicator(value: str) -> bool:
    text = str(value or "").lower()
    if any(token in text for token in _STAGING_INDICATOR_TOKENS):
        return True
    return any(token in text for token in ARCHIVE_TOKENS)


def has_recon_indicator(value: str) -> bool:
    text = str(value or "").lower()
    return any(token in text for token in _RECON_INDICATOR_TOKENS)


def _default_command_token_matcher(command_text: str, token: str) -> bool:
    pattern = re.compile(rf"(?<![a-z0-9_-]){re.escape(token)}")
    return pattern.search(str(command_text or "")) is not None


def build_archive_command_signals(
    *,
    tool_name: str,
    payload_text: str = "",
    command_text: str = "",
    token_matcher: Callable[[str, str], bool] | None = None,
) -> dict[str, bool]:
    tool = str(tool_name or "").lower()
    payload_value = str(payload_text or "")
    command_value = str(command_text or payload_value)
    matcher = token_matcher or _default_command_token_matcher

    archive_restore_action = any(
        matcher(command_value, token) for token in BASE64_DECODE_TOKENS
    ) or any(
        matcher(command_value, token) for token in ARCHIVE_RESTORE_TOKENS
    )
    archive_inspection_action = any(
        matcher(command_value, token) for token in ARCHIVE_INSPECTION_TOKENS
    )
    archive_action = (
        tool in EXEC_TOOLS
        and any(matcher(command_value, token) for token in ARCHIVE_TOKENS)
        and not archive_restore_action
        and not archive_inspection_action
    )
    archive_sensitive_material = archive_action and is_credential_path(
        f"{payload_value} {command_value}"
    )

    return {
        "archive_action": archive_action,
        "archive_sensitive_material": archive_sensitive_material,
        "archive_restore_action": archive_restore_action,
        "archive_inspection_action": archive_inspection_action,
    }


def build_base_event_signals(
    *,
    tool_name: str,
    path_text: str = "",
    payload_text: str = "",
    command_text: str = "",
    risk_hints: Iterable[str] | None = None,
) -> dict[str, bool]:
    tool = str(tool_name or "").lower()
    hints = normalize_hints(risk_hints)
    path_value = str(path_text or "")
    payload_value = str(payload_text or "")
    command_value = str(command_text or payload_value)
    combined = f"{path_value} {payload_value} {command_value}"

    credential_access = (
        bool(hints.intersection(CREDENTIAL_HINTS))
        or (tool in READ_TOOLS and is_credential_path(combined))
    )
    network_activity = (
        tool in NETWORK_TOOLS
        or bool(hints.intersection(NETWORK_HINTS))
        or has_network_command(combined)
    )
    tmp_path_touched = is_temp_path(combined)
    read_action = tool in READ_TOOLS
    write_action = tool in WRITE_TOOLS
    exec_action = tool in EXEC_TOOLS or "chmod" in combined.lower() or "install " in combined.lower()
    sudo_action = tool == "sudo" or "sudo " in combined.lower()
    recon_action = (read_action or exec_action or tool == "bash") and has_recon_command(combined)

    return {
        "credential_access": credential_access,
        "network_activity": network_activity,
        "read_action": read_action,
        "write_action": write_action,
        "exec_action": exec_action,
        "sudo_action": sudo_action,
        "tmp_path_touched": tmp_path_touched,
        "recon_action": recon_action,
    }


def build_file_write_persistence_signals(
    *,
    tool_name: str,
    path_text: str = "",
    content_text: str = "",
    risk_hints: Iterable[str] | None = None,
) -> dict[str, bool]:
    """Detect pre-write attempts to install long-lived execution entrypoints.

    The predicates are intentionally semantic and tool/path generic: they look
    for future automatic execution or re-entry behavior, not benchmark case
    names or fixture-specific identifiers.
    """
    tool = str(tool_name or "").lower()
    path_value = str(path_text or "")
    content_value = str(content_text or "")
    combined = f"{path_value}\n{content_value}"
    hints = normalize_hints(risk_hints)
    path_tokens = [
        token.strip("'\"`;,)(")
        for token in re.split(r"\s+", path_value)
        if token.strip("'\"`;,)(")
    ]
    path_tokens.extend(match.group("path") for match in _PATH_LITERAL_RE.finditer(combined))

    shell_file_write_action = tool in _SHELL_WRITE_TOOLS and bool(
        _SHELL_FILE_WRITE_RE.search(content_value)
        or _SHELL_PROGRAMMATIC_FILE_WRITE_RE.search(content_value)
    )
    delegated_write_action = tool in _DELEGATED_WRITE_TOOLS and bool(
        _DELEGATED_WRITE_INTENT_RE.search(content_value)
    )
    write_action = (
        tool in _FILE_WRITE_CONTENT_TOOLS
        or shell_file_write_action
        or delegated_write_action
    )
    autostart_path = any(_AUTOSTART_PATH_RE.search(token) for token in path_tokens)
    entrypoint_path = any(_ENTRYPOINT_PATH_RE.search(token) for token in path_tokens)
    html_entrypoint_path = any(
        re.search(r"(^|/)(?:index|main|app)\.html?$", token, re.IGNORECASE)
        for token in path_tokens
    )
    bootstrap_loader_path = any(
        _BOOTSTRAP_LOADER_PATH_RE.search(token) for token in path_tokens
    )
    startup_or_autoload_intent = (
        bool(_AUTOLOAD_INTENT_RE.search(combined))
        or "persistence_mechanism" in hints
        or "persistence_or_reentry_foothold" in hints
    )
    loader_reference = bool(_LOADER_REFERENCE_RE.search(content_value))
    inline_loader_contract = bool(_INLINE_LOADER_CONTRACT_RE.search(content_value))
    execution_entrypoint = bool(_EXECUTION_ENTRYPOINT_RE.search(content_value))
    dynamic_or_remote_code = bool(_DYNAMIC_OR_REMOTE_CODE_RE.search(content_value))
    encoded_or_obfuscated_write = bool(_ENCODED_OR_OBFUSCATED_WRITE_RE.search(content_value))
    window_loader_state = bool(_WINDOW_LOADER_STATE_RE.search(content_value))
    package_lifecycle_script = (
        path_value.lower().endswith("/package.json")
        or path_value.lower() == "package.json"
    ) and bool(re.search(r'"(?:preinstall|postinstall|prepare|start)"\s*:', content_value))
    entrypoint_autoloads_loader = (
        entrypoint_path
        and startup_or_autoload_intent
        and loader_reference
        and (window_loader_state or dynamic_or_remote_code or execution_entrypoint)
    )
    entrypoint_inline_loader_contract = (
        html_entrypoint_path
        and startup_or_autoload_intent
        and inline_loader_contract
        and window_loader_state
    )
    bootstrap_loader_state = (
        bootstrap_loader_path
        and startup_or_autoload_intent
        and window_loader_state
    )
    bootstrap_loader_opaque_write = (
        bootstrap_loader_path
        and encoded_or_obfuscated_write
    )
    persistence_write = write_action and (
        autostart_path
        or package_lifecycle_script
        or entrypoint_autoloads_loader
        or entrypoint_inline_loader_contract
        or bootstrap_loader_state
        or bootstrap_loader_opaque_write
        or (
            startup_or_autoload_intent
            and execution_entrypoint
            and (dynamic_or_remote_code or window_loader_state)
        )
    )

    return {
        "write_action": write_action,
        "shell_file_write_action": shell_file_write_action,
        "delegated_write_action": delegated_write_action,
        "autostart_path": autostart_path,
        "entrypoint_path": entrypoint_path,
        "html_entrypoint_path": html_entrypoint_path,
        "bootstrap_loader_path": bootstrap_loader_path,
        "startup_or_autoload_intent": startup_or_autoload_intent,
        "loader_reference": loader_reference,
        "inline_loader_contract": inline_loader_contract,
        "execution_entrypoint": execution_entrypoint,
        "dynamic_or_remote_code": dynamic_or_remote_code,
        "encoded_or_obfuscated_write": encoded_or_obfuscated_write,
        "window_loader_state": window_loader_state,
        "package_lifecycle_script": package_lifecycle_script,
        "entrypoint_autoloads_loader": entrypoint_autoloads_loader,
        "entrypoint_inline_loader_contract": entrypoint_inline_loader_contract,
        "bootstrap_loader_state": bootstrap_loader_state,
        "bootstrap_loader_opaque_write": bootstrap_loader_opaque_write,
        "persistence_write": persistence_write,
    }
