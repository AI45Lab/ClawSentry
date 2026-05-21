"""Deterministic action-effect normalization for Gateway L1 evidence.

The normalizer intentionally stores only hashes, labels, and compact rule ids.
Raw commands, prompts, payloads, paths, and environment values stay out of the
returned envelope and downstream ledgers.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
from pathlib import Path
from typing import Any

from .models import (
    ActionEffectEnvelope,
    ActionEffectTarget,
    CanonicalEvent,
    DecisionContext,
)


_NATIVE_WRITE_TOOLS = {
    "write",
    "write_file",
    "edit",
    "edit_file",
    "create_file",
    "apply_patch",
}
_DELEGATION_TOOLS = {"agent", "task"}
_EXECUTABLE_SUFFIXES = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ps1", ".bat", ".cmd")
_MAX_SCRIPT_BINDING_BYTES = 1_048_576
_PERSISTENCE_MARKERS = (
    ".bashrc",
    ".zshrc",
    ".profile",
    "crontab",
    "/cron.",
    "/systemd/",
    ".service",
    "launchagents",
    "launchdaemons",
)
_CREDENTIAL_MARKERS = (
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    ".env",
    "credentials",
    "credential",
    "secret",
    "token",
)
_PATH_RE = re.compile(r"(?:[A-Za-z]:)?(?:[./~]?[\w.-]+/)*[\w.-]+\.[A-Za-z0-9_+-]+")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
_SHELL_SEGMENT_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;)\s*")
_ARCHIVE_DELETE_RE = re.compile(
    r"(?:^|[;&]\s*)(?:rm|shred|srm)\s+-?[^;&|]*\b|find\b[^;&|]*\s-delete\b",
    re.IGNORECASE,
)


def normalize_action_effect(
    event: CanonicalEvent,
    context: DecisionContext | None = None,
) -> ActionEffectEnvelope:
    """Return a redacted effect envelope for a canonical action event."""

    tool = str(event.tool_name or "")
    tool_l = tool.lower()
    payload = event.payload or {}
    raw_text = _payload_text(payload)
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    interpreters: list[str] = []
    wrappers: list[str] = []
    rules: list[str] = []
    analysis_state = "complete"
    confidence = "low"

    if tool_l in _NATIVE_WRITE_TOOLS:
        _add_effect(effects, "filesystem.write")
        target = _first_payload_path(payload) or _first_path(raw_text)
        if target:
            targets.append(_target_for_path(target))
        _add_rule(rules, "native_write_effect")
        confidence = "high"

    if tool_l in {"bash", "shell", "terminal", "command", "exec", "sh", "zsh"}:
        interpreters.append("bash")
        shell_result = _analyze_shell(raw_text)
        _merge(effects, shell_result["effects"])
        targets.extend(shell_result["targets"])
        _merge(rules, shell_result["rules"])
        wrappers.extend(shell_result["wrappers"])
        if shell_result["analysis_state"] != "complete":
            analysis_state = shell_result["analysis_state"]
        confidence = _max_confidence(confidence, shell_result["confidence"])
        if raw_text and analysis_state == "complete":
            confidence = _max_confidence(confidence, "medium")

    if tool_l in {"python", "python3"} or _looks_like_python(raw_text):
        _add_unique(interpreters, "python")
        py_result = _analyze_python(raw_text)
        _merge(effects, py_result["effects"])
        targets.extend(py_result["targets"])
        _merge(rules, py_result["rules"])
        confidence = _max_confidence(confidence, py_result["confidence"])

    if tool_l in {"node", "nodejs", "javascript"} or _looks_like_node(raw_text):
        _add_unique(interpreters, "node")
        node_result = _analyze_node(raw_text)
        _merge(effects, node_result["effects"])
        targets.extend(node_result["targets"])
        _merge(rules, node_result["rules"])
        confidence = _max_confidence(confidence, node_result["confidence"])

    if tool_l in {"powershell", "pwsh"} or _looks_like_powershell(raw_text):
        _add_unique(interpreters, "powershell")
        ps_result = _analyze_powershell(raw_text)
        _merge(effects, ps_result["effects"])
        targets.extend(ps_result["targets"])
        _merge(rules, ps_result["rules"])
        confidence = _max_confidence(confidence, ps_result["confidence"])

    if tool_l in _DELEGATION_TOOLS:
        delegated = _analyze_delegation(raw_text)
        _merge(effects, delegated["effects"])
        targets.extend(delegated["targets"])
        _merge(rules, delegated["rules"])
        confidence = _max_confidence(confidence, delegated["confidence"])

    content_result = _analyze_content_evidence(context)
    _merge(effects, content_result["effects"])
    targets.extend(content_result["targets"])
    _merge(rules, content_result["rules"])
    confidence = _max_confidence(confidence, content_result["confidence"])
    if content_result["analysis_state"] != "complete":
        analysis_state = content_result["analysis_state"]

    if _URL_RE.search(raw_text) and re.search(r"\b(curl|wget|scp|rsync)\b", raw_text, re.IGNORECASE):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "network_equivalent_fetch")
        confidence = _max_confidence(confidence, "high")

    if re.search(r"\b(?:pip|pip3|npm|yarn|pnpm)\s+(?:install|add)\b", raw_text, re.IGNORECASE):
        _add_effect(effects, "package.install")
        _add_rule(rules, "package_install")
        confidence = _max_confidence(confidence, "high")

    if any(target.path_role in {"future_execution.artifact", "bootstrap_loader"} for target in targets):
        _add_effect(effects, "future_execution.artifact")
        _add_rule(rules, "generated_script_future_exec")
    if any(target.path_role == "persistence_entrypoint" for target in targets):
        _add_effect(effects, "future_execution.entrypoint")
        _add_rule(rules, "persistence_entrypoint_write")

    if "<(" in raw_text or re.search(r"\b(?:bash|sh|zsh)\s+<\(", raw_text):
        analysis_state = "unsupported"
        _add_rule(rules, "wrapper_chain_unresolved")
        _add_unique(wrappers, "process_substitution")

    disabled = _disabled_capabilities(context)
    matched_disabled = sorted(set(effects).intersection(disabled))
    if matched_disabled:
        _add_rule(rules, "disabled_capability_equivalent")

    envelope = ActionEffectEnvelope(
        effects=effects,
        tool_name=tool or None,
        canonical_argv_hash=_hash(raw_text) if raw_text else None,
        raw_payload_hash=_hash_json(payload),
        targets=_dedupe_targets(targets),
        interpreters=interpreters,
        wrapper_chain=wrappers,
        confidence=confidence,
        evidence_rules=rules,
        analysis_state=analysis_state,
        disabled_capabilities=matched_disabled,
    )
    return envelope


def effect_hash(envelope: ActionEffectEnvelope) -> str:
    projection = {
        "effects": envelope.effects,
        "targets": [
            {
                "kind": target.kind,
                "path_hash": target.path_hash,
                "path_role": target.path_role,
            }
            for target in envelope.targets
        ],
    }
    return _hash_json(projection)


def target_hashes(envelope: ActionEffectEnvelope) -> list[str]:
    return sorted({str(target.path_hash) for target in envelope.targets if target.path_hash})


def artifact_families(envelope: ActionEffectEnvelope) -> list[str]:
    return sorted({str(target.path_role) for target in envelope.targets if target.path_role})


_INPUT_TARGET_ROLES = frozenset({"document_input", "source", "input"})
_OUTPUT_TARGET_ROLES = frozenset({
    "future_execution.artifact",
    "generated_artifact",
    "verifier_artifact",
    "workspace_file",
    "persistence_entrypoint",
    "bootstrap_loader",
})


def contextual_binding_parts(
    event: CanonicalEvent,
    context: DecisionContext | None = None,
) -> dict[str, Any]:
    envelope = normalize_action_effect(event, context)
    payload = event.payload or {}
    cwd = str(payload.get("cwd") or payload.get("working_directory") or "").strip()
    input_hashes = sorted(
        target.path_hash for target in envelope.targets
        if target.path_hash and target.path_role in _INPUT_TARGET_ROLES
    )
    output_hashes = sorted(
        target.path_hash for target in envelope.targets
        if target.path_hash and target.path_role in _OUTPUT_TARGET_ROLES
    )
    return {
        "event_id": event.event_id,
        "session_id": event.session_id,
        "effect_hash": effect_hash(envelope),
        "canonical_argv_hash": envelope.canonical_argv_hash,
        "raw_payload_hash": envelope.raw_payload_hash,
        "cwd_hash": _hash(cwd) if cwd else None,
        "interpreter": envelope.interpreters[0] if envelope.interpreters else None,
        "script_or_content_hash": _script_or_content_hash(event, envelope, context),
        "input_path_hashes": input_hashes,
        "output_path_hashes": output_hashes,
        "analysis_state": envelope.analysis_state,
        "confidence": envelope.confidence,
        "effects": list(envelope.effects),
        "evidence_rules": list(envelope.evidence_rules),
        "wrapper_chain": list(envelope.wrapper_chain),
        "target_roles": sorted({target.path_role for target in envelope.targets if target.path_role}),
    }


def _script_or_content_hash(
    event: CanonicalEvent,
    envelope: ActionEffectEnvelope,
    context: DecisionContext | None,
) -> str | None:
    payload = event.payload or {}
    command = str(payload.get("command") or payload.get("cmd") or "").strip()
    cwd = str(payload.get("cwd") or payload.get("working_directory") or "").strip()
    script_path = _script_path_from_command(command)
    if script_path and cwd:
        relative = Path(script_path)
        if relative.is_absolute() or ".." in relative.parts:
            return envelope.raw_payload_hash
        cwd_root = _trusted_cwd_root(cwd, context)
        if cwd_root is None:
            return envelope.raw_payload_hash
        try:
            candidate = (cwd_root / relative).resolve(strict=True)
            candidate.relative_to(cwd_root)
            if candidate.is_file() and candidate.stat().st_size <= _MAX_SCRIPT_BINDING_BYTES:
                digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
                return "sha256:" + digest
        except (OSError, RuntimeError, ValueError):
            pass
    return envelope.raw_payload_hash


def _trusted_cwd_root(cwd: str, context: DecisionContext | None) -> Path | None:
    scope = context.session_scope_profile if context is not None else None
    prefixes = (
        list(scope.task_rules.allowed_path_prefixes or [])
        if scope is not None and scope.task_rules is not None
        else []
    )
    if not prefixes:
        return None
    try:
        cwd_root = Path(cwd).resolve(strict=True)
    except OSError:
        return None
    for prefix in prefixes:
        try:
            allowed_root = Path(str(prefix)).resolve(strict=True)
            cwd_root.relative_to(allowed_root)
            return cwd_root
        except (OSError, RuntimeError, ValueError):
            continue
    return None


def _script_path_from_command(command: str) -> str | None:
    if not command:
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for index, token in enumerate(tokens[:-1]):
        name = Path(token).name.lower()
        if name in {"python", "python3", "node", "nodejs", "bash", "sh", "zsh"}:
            for candidate in tokens[index + 1:]:
                if candidate.startswith("-"):
                    continue
                if candidate.endswith(_EXECUTABLE_SUFFIXES):
                    return candidate
                return None
    return None


def _analyze_shell(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    wrappers: list[str] = []
    confidence = "low"
    analysis_state = "complete"

    if re.search(r"\b(?:bash|sh|zsh)\s+-[^;|&]*c\b", text):
        wrappers.append("shell -c")

    heredoc_write = "<<" in text and re.search(r"(?:^|\s)(?:cat|tee)\b[^;&|]*(?:>|tee)\s*", text)
    redirection_paths = _redirection_paths(text)
    if redirection_paths:
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in redirection_paths)
        _add_rule(rules, "shell_heredoc_write" if heredoc_write else "shell_redirection_write")
        confidence = "high"

    tee_paths = _tee_paths(text)
    if tee_paths:
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in tee_paths)
        _add_rule(rules, "shell_tee_write")
        confidence = "high"

    dd_paths = re.findall(r"(?:^|\s)of=([^\s'\";|&]+)", text)
    if dd_paths and re.search(r"\bdd\b", text):
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in dd_paths)
        _add_rule(rules, "dd_output_write")
        confidence = "high"

    if re.search(r"\b(?:base64|xxd)\b[^;&|]*(?:-d|-r|--decode)", text) and redirection_paths:
        _add_effect(effects, "encoded_payload.materialization")
        _add_rule(rules, "decode_to_file_write")
        confidence = "high"

    copy_targets = _copy_like_targets(text)
    if copy_targets:
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in copy_targets)
        _add_rule(rules, "shell_copy_write")
        confidence = _max_confidence(confidence, "medium")

    archive_result = _analyze_encrypted_archive_creation(text)
    if archive_result["rules"]:
        _add_effect(effects, "filesystem.write")
        targets.extend(_target_for_path(path) for path in archive_result["targets"])
        _merge(rules, archive_result["rules"])
        confidence = _max_confidence(confidence, archive_result["confidence"])

    if re.search(r"\b(?:curl|wget|scp|rsync)\b", text):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "network_equivalent_fetch")
        confidence = _max_confidence(confidence, "high")
        download_targets = _network_download_targets(text)
        if download_targets:
            _add_effect(effects, "filesystem.write")
            targets.extend(_target_for_path(path) for path in download_targets)
            _add_rule(rules, "network_download_write")
            confidence = _max_confidence(confidence, "high")

    if re.search(r"\brm\s+-[^\s;|&]*r[^\s;|&]*f|\brm\s+-[^\s;|&]*f[^\s;|&]*r", text):
        _add_rule(rules, "destructive_delete")
        confidence = _max_confidence(confidence, "high")

    return {
        "effects": effects,
        "targets": targets,
        "rules": rules,
        "wrappers": wrappers,
        "confidence": confidence,
        "analysis_state": analysis_state,
    }


def _shell_segments(text: str) -> list[list[str]]:
    segments: list[list[str]] = []
    for part in _SHELL_SEGMENT_SPLIT_RE.split(text):
        stripped = part.strip()
        if not stripped:
            continue
        try:
            tokens = shlex.split(stripped)
        except ValueError:
            tokens = stripped.split()
        if tokens:
            segments.append(tokens)
    return segments


def _zip_password_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() != "zip":
        return False
    read_modes = {"--test", "-T", "--show-files", "-sf", "-h", "--help", "-v", "--version"}
    if any(token in read_modes for token in tokens[1:]):
        return False
    for index, token in enumerate(tokens[1:], start=1):
        if token in {"-P", "--password"} and index + 1 < len(tokens):
            return True
        if token.startswith("-P") and len(token) > 2:
            return True
        if token in {"-e", "--encrypt"} or (
            "e" in token[1:] and token.startswith("-") and not token.startswith("--")
        ):
            return True
    return False


def _seven_zip_password_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() not in {"7z", "7za", "7zr"}:
        return False
    if len(tokens) < 2 or tokens[1].lower() not in {"a", "u"}:
        return False
    return any(token == "-p" or token.startswith("-p") for token in tokens[2:])


def _gpg_symmetric_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() not in {"gpg", "gpg2"}:
        return False
    if any(token in {"--decrypt", "-d", "--verify", "--list-packets", "--list-keys"} for token in tokens[1:]):
        return False
    return any(token in {"-c", "--symmetric"} for token in tokens[1:])


def _openssl_enc_creation(tokens: list[str]) -> bool:
    if not tokens or Path(tokens[0]).name.lower() != "openssl":
        return False
    if "enc" not in tokens[1:]:
        return False
    if "-d" in tokens or "-decrypt" in tokens:
        return False
    return "-out" in tokens or any(token.startswith("-out=") for token in tokens)


def _archive_encrypt_pipeline(text: str) -> bool:
    if "|" not in text:
        return False
    left, right = text.split("|", 1)
    try:
        left_tokens = shlex.split(left.strip())
        right_tokens = shlex.split(right.strip())
    except ValueError:
        left_tokens = left.strip().split()
        right_tokens = right.strip().split()
    if not left_tokens or Path(left_tokens[0]).name.lower() != "tar":
        return False
    return _gpg_symmetric_creation(right_tokens) or _openssl_enc_creation(right_tokens)


def _archive_targets(tokens: list[str]) -> list[str]:
    return [
        token
        for token in tokens[1:]
        if not token.startswith("-") and _PATH_RE.search(token)
    ][:3]


def _analyze_encrypted_archive_creation(text: str) -> dict[str, Any]:
    rules: list[str] = []
    targets: list[str] = []
    segments = _shell_segments(text)

    for tokens in segments:
        if _zip_password_creation(tokens) or _seven_zip_password_creation(tokens):
            _add_rule(rules, "password_protected_archive_creation")
            targets.extend(_archive_targets(tokens))
        elif _gpg_symmetric_creation(tokens) or _openssl_enc_creation(tokens):
            _add_rule(rules, "encrypted_artifact_creation")
            targets.extend(_archive_targets(tokens))

    if _archive_encrypt_pipeline(text):
        _add_rule(rules, "archive_encrypt_pipeline")
        targets.extend(_first_path(part) for part in text.split("|") if _first_path(part))

    if rules and _ARCHIVE_DELETE_RE.search(text):
        _add_rule(rules, "encrypted_archive_then_delete_original")

    return {
        "rules": rules,
        "targets": [path for path in targets if path],
        "confidence": "high" if rules else "low",
    }


def _analyze_python(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"

    for path in re.findall(r"open\(\s*['\"]([^'\"]+)['\"]", text):
        if any(marker in path.lower() for marker in _CREDENTIAL_MARKERS):
            _add_rule(rules, "credential_read")
            confidence = _max_confidence(confidence, "high")
    for path in re.findall(r"open\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"][^'\"]*[wax+][^'\"]*['\"]", text):
        _add_effect(effects, "filesystem.write")
        targets.append(_target_for_path(path))
        _add_rule(rules, "python_file_write")
        confidence = "high"
    for path in re.findall(r"Path\(\s*['\"]([^'\"]+)['\"]\s*\)\.write_(?:text|bytes)\(", text):
        _add_effect(effects, "filesystem.write")
        targets.append(_target_for_path(path))
        _add_rule(rules, "python_file_write")
        confidence = "high"
    for path in re.findall(r"shutil\.(?:copy|copyfile|move)\([^,]+,\s*['\"]([^'\"]+)['\"]", text):
        _add_effect(effects, "filesystem.write")
        targets.append(_target_for_path(path))
        _add_rule(rules, "python_file_write")
        confidence = _max_confidence(confidence, "medium")
    if re.search(r"\b(?:requests|httpx|urllib)\.", text):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "python_network_fetch")
        confidence = _max_confidence(confidence, "high")
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _analyze_node(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    for path in re.findall(r"(?:writeFile|writeFileSync|appendFile|appendFileSync)\(\s*['\"]([^'\"]+)['\"]", text):
        _add_effect(effects, "filesystem.write")
        targets.append(_target_for_path(path))
        _add_rule(rules, "node_file_write")
        confidence = "high"
    if re.search(r"\b(?:fetch|axios\.)\s*\(", text):
        _add_effect(effects, "network.fetch")
        _add_rule(rules, "node_network_fetch")
        confidence = _max_confidence(confidence, "high")
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _analyze_powershell(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    patterns = [
        r"Set-Content\s+(?:-Path\s+)?(?:['\"]([^'\"]+)['\"]|([^\s;|]+))",
        r"Out-File\s+(?:-FilePath\s+)?(?:['\"]([^'\"]+)['\"]|([^\s;|]+))",
    ]
    for pattern in patterns:
        for match in re.findall(pattern, text, flags=re.IGNORECASE):
            path = next((item for item in match if item), "") if isinstance(match, tuple) else match
            if not path:
                continue
            _add_effect(effects, "filesystem.write")
            targets.append(_target_for_path(path))
            _add_rule(rules, "powershell_file_write")
            confidence = "high"
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _analyze_delegation(text: str) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    if re.search(r"\b(?:write|create|edit|save|generate)\b", text, re.IGNORECASE):
        paths = _paths(text)
        if paths:
            _add_effect(effects, "delegated_effect_request")
            _add_effect(effects, "filesystem.write")
            targets.extend(_target_for_path(path) for path in paths)
            _add_rule(rules, "delegated_write_request")
            confidence = "medium"
    return {"effects": effects, "targets": targets, "rules": rules, "confidence": confidence}


def _analyze_content_evidence(context: DecisionContext | None) -> dict[str, Any]:
    effects: list[str] = []
    targets: list[ActionEffectTarget] = []
    rules: list[str] = []
    confidence = "low"
    analysis_state = "complete"
    envelope = getattr(context, "content_evidence", None) if context is not None else None
    if envelope is None:
        return {
            "effects": effects,
            "targets": targets,
            "rules": rules,
            "confidence": confidence,
            "analysis_state": analysis_state,
        }
    for item in getattr(envelope, "items", []) or []:
        item_rules = [
            str(rule.get("rule_id"))
            for rule in getattr(item, "derived_rules", []) or []
            if isinstance(rule, dict) and rule.get("rule_id")
        ]
        for rule_id in item_rules:
            _add_rule(rules, rule_id)
        if str(getattr(item, "kind", "")) in {"skill_script", "script"}:
            targets.append(_content_target(getattr(item, "canonical_evidence_id", ""), "executed_script"))
        if "document_input_to_network_sink" in item_rules:
            _add_effect(effects, "network.upload")
            targets.append(_content_target(getattr(item, "canonical_evidence_id", ""), "document_input"))
            confidence = _max_confidence(confidence, "high")
        elif "associated_script_network_sink" in item_rules:
            _add_effect(effects, "network.upload")
            confidence = _max_confidence(confidence, "high")
        elif "associated_script_network_indicator" in item_rules:
            _add_effect(effects, "network.fetch")
            confidence = _max_confidence(confidence, "medium")
        if "content_evidence_incomplete" in item_rules:
            analysis_state = "incomplete"
            confidence = _max_confidence(confidence, "medium")
    return {
        "effects": effects,
        "targets": targets,
        "rules": rules,
        "confidence": confidence,
        "analysis_state": analysis_state,
    }


def _content_target(evidence_id: str, role: str) -> ActionEffectTarget:
    return ActionEffectTarget(
        kind="content_evidence",
        path_hash=_hash(str(evidence_id)),
        path_role=role,
        workspace_relation="gateway_content_evidence",
    )


def _payload_text(payload: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("command", "cmd", "script", "code", "input", "prompt", "instructions", "content", "path"):
        value = payload.get(key)
        if isinstance(value, str):
            parts.append(value)
    if not parts:
        try:
            parts.append(json.dumps(payload, sort_keys=True, default=str))
        except TypeError:
            parts.append(str(payload))
    return "\n".join(parts)


def _first_payload_path(payload: dict[str, Any]) -> str | None:
    for key in ("path", "file_path", "target", "destination", "destination_path", "output_path"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _redirection_paths(text: str) -> list[str]:
    paths: list[str] = []
    for match in re.finditer(r"(?<![A-Za-z0-9])(?:\d?>{1,2})\s*(['\"]?)([^'\"\s;|&]+)\1", text):
        path = match.group(2)
        if path and not path.startswith("&"):
            paths.append(path)
    return paths


def _tee_paths(text: str) -> list[str]:
    paths: list[str] = []
    for segment in re.split(r"[;&|]", text):
        if not re.search(r"\btee\b", segment):
            continue
        heredoc_match = re.search(r"\btee\b(?:\s+-[A-Za-z]+)*\s+(?:<<['\"]?\w+['\"]?\s+)?([^\s'\";|&]+)", segment)
        if heredoc_match:
            paths.append(heredoc_match.group(1))
            continue
        try:
            parts = shlex.split(segment)
        except ValueError:
            parts = segment.split()
        if "tee" not in parts:
            continue
        idx = parts.index("tee") + 1
        while idx < len(parts) and parts[idx].startswith("-"):
            idx += 1
        if idx < len(parts):
            paths.append(parts[idx])
    return paths


def _copy_like_targets(text: str) -> list[str]:
    targets: list[str] = []
    for segment in re.split(r"[;&|]", text):
        try:
            parts = shlex.split(segment)
        except ValueError:
            parts = segment.split()
        if len(parts) >= 3 and parts[0] in {"cp", "mv", "install"}:
            targets.append(parts[-1])
    return targets


def _network_download_targets(text: str) -> list[str]:
    targets: list[str] = []
    for segment in re.split(r"[;&|]", text):
        try:
            parts = shlex.split(segment)
        except ValueError:
            parts = segment.split()
        if not parts:
            continue
        command = parts[0]
        if command in {"curl", "wget"}:
            for index, part in enumerate(parts[:-1]):
                if part in {"-o", "--output"} or (command == "wget" and part == "-O"):
                    targets.append(parts[index + 1])
                elif part.startswith("--output="):
                    targets.append(part.split("=", 1)[1])
                elif part.startswith("--output-document="):
                    targets.append(part.split("=", 1)[1])
            continue
        if command in {"scp", "rsync"} and len(parts) >= 3:
            targets.append(parts[-1])
    return targets


def _paths(text: str) -> list[str]:
    return [match.group(0) for match in _PATH_RE.finditer(text or "")]


def _first_path(text: str) -> str | None:
    paths = _paths(text)
    return paths[0] if paths else None


def _target_for_path(path: str) -> ActionEffectTarget:
    normalized = str(path or "").strip().strip("'\"")
    role = _path_role(normalized)
    return ActionEffectTarget(
        kind="path",
        path_hash=_hash(normalized),
        path_role=role,
        workspace_relation=_workspace_relation(normalized),
    )


def _path_role(path: str) -> str:
    lowered = path.lower()
    if any(marker in lowered for marker in _PERSISTENCE_MARKERS):
        return "persistence_entrypoint"
    if "loader" in lowered or "bootstrap" in lowered:
        return "bootstrap_loader"
    if lowered.endswith(_EXECUTABLE_SUFFIXES) or "/bin/" in lowered:
        return "future_execution.artifact"
    return "workspace_file"


def _workspace_relation(path: str) -> str:
    if path.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", path):
        return "outside_workspace_or_absolute"
    return "inside_workspace"


def _disabled_capabilities(context: DecisionContext | None) -> set[str]:
    if context is None or context.session_scope_profile is None:
        return set()
    profile = context.session_scope_profile
    return {str(item) for item in getattr(profile.base_rules, "denied_capabilities", [])}


def _dedupe_targets(targets: list[ActionEffectTarget]) -> list[ActionEffectTarget]:
    seen: set[tuple[str | None, str | None]] = set()
    deduped: list[ActionEffectTarget] = []
    for target in targets:
        key = (target.path_hash, target.path_role)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(target)
    return deduped


def _looks_like_python(text: str) -> bool:
    return bool(re.search(r"\bpython(?:\d+(?:\.\d+)?)?\b|\bopen\(|\bpathlib\b|\brequests\.", text))


def _looks_like_node(text: str) -> bool:
    return bool(re.search(r"\bnode\b|\bfs\.|writeFileSync|fetch\(", text))


def _looks_like_powershell(text: str) -> bool:
    return bool(re.search(r"\b(?:powershell|pwsh|Set-Content|Out-File)\b", text, re.IGNORECASE))


def _add_effect(effects: list[str], effect: str) -> None:
    _add_unique(effects, effect)


def _add_rule(rules: list[str], rule: str) -> None:
    _add_unique(rules, rule)


def _add_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _merge(values: list[str], additions: list[str]) -> None:
    for addition in additions:
        _add_unique(values, addition)


def _max_confidence(left: str, right: str) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return left if order[left] >= order[right] else right


def _hash(value: str) -> str:
    return "sha256:" + hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def _hash_json(value: Any) -> str:
    return _hash(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")))
