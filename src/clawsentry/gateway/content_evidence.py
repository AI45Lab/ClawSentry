"""Request-local content evidence helpers for Gateway decisions.

This module keeps raw content bounded and local to the current request. Durable
records should use hashes, ranges, rule ids, and truncation metadata instead.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .content_scanners import scan_content
from .models import (
    CanonicalEvent,
    ContentEvidenceEnvelope,
    ContentEvidenceIntegrity,
    ContentEvidenceItem,
    ContentEvidenceRange,
)
from .tool_semantic_registry import derive_tool_semantics

CONTENT_EVIDENCE_EXTRACTOR_VERSION = "content_evidence.python_ast_token_scan@v1"


@dataclass(frozen=True)
class ResolvedContentPath:
    requested_path: Path
    resolved_path: Path | None
    resolved_realpath: Path | None
    resolver_status: str
    root: Path | None = None


def make_safe_evidence_id(source: str, *, ordinal: int) -> str:
    """Return a Gateway-generated id that never embeds path/content material."""

    if ordinal < 1:
        raise ValueError("ordinal must be >= 1")
    return f"ce_{ordinal:03d}"


def build_exact_ref_allowlist(envelope: ContentEvidenceEnvelope) -> list[str]:
    """Build exact evidence refs that L2/L3 may cite."""

    refs: list[str] = []
    for item in envelope.items:
        base = f"content_evidence.{item.canonical_evidence_id}"
        if item.content is not None:
            refs.append(f"{base}.content")
        if item.integrity.sha256 or item.integrity.sha256_full:
            refs.append(f"{base}.hash")
        for index, _range in enumerate(item.included_ranges):
            refs.append(f"{base}.range[{index}]")
        for index, _rule in enumerate(item.derived_rules):
            refs.append(f"{base}.derived_rules[{index}]")
    return refs


def strip_content_bodies(envelope: ContentEvidenceEnvelope) -> ContentEvidenceEnvelope:
    """Remove raw bodies and rebuild refs to match the remaining evidence."""

    stripped_items = [
        item.model_copy(update={"content": None, "content_persisted": False})
        for item in envelope.items
    ]
    stripped = envelope.model_copy(update={"items": stripped_items})
    return stripped.model_copy(update={"exact_ref_allowlist": build_exact_ref_allowlist(stripped)})


def hash_evidence_bytes(data: bytes) -> str:
    """Return the Gateway evidence hash format shared by content-style scanners."""

    return _sha256_bytes(data)


def hash_evidence_text(value: str) -> str:
    """Return a Gateway evidence hash for text without exposing the text itself."""

    return _sha256_text(value)


def resolve_under_approved_roots(
    path: str | Path,
    *,
    approved_roots: Iterable[str | Path],
) -> ResolvedContentPath:
    """Resolve a local path only when lexical and real paths stay under a root."""

    requested = Path(path).expanduser()
    requested_abs = Path(os.path.abspath(requested))
    roots = [Path(os.path.abspath(Path(root).expanduser())).resolve(strict=False) for root in approved_roots]
    if not roots:
        return ResolvedContentPath(requested_abs, None, None, "outside_approved_root")

    lexical_root = next((root for root in roots if _is_relative_to(requested_abs, root)), None)
    if lexical_root is None:
        return ResolvedContentPath(requested_abs, None, None, "outside_approved_root")

    try:
        realpath = requested_abs.resolve(strict=True)
    except FileNotFoundError:
        return ResolvedContentPath(requested_abs, requested_abs, None, "unresolved_path", lexical_root)
    except OSError:
        return ResolvedContentPath(requested_abs, requested_abs, None, "unresolved_path", lexical_root)

    if not _is_relative_to(realpath, lexical_root):
        return ResolvedContentPath(requested_abs, requested_abs, realpath, "symlink_escape", lexical_root)
    return ResolvedContentPath(requested_abs, requested_abs, realpath, "resolved_static_local_path", lexical_root)


def acquire_pinned_file(
    resolved: ResolvedContentPath,
    *,
    evidence_id: str,
    kind: str,
    max_bytes: int = 262_144,
    after_read_hook: Callable[[Path], None] | None = None,
) -> ContentEvidenceItem:
    """Read and hash a resolved file with stat-before/stat-after mismatch checks."""

    if resolved.resolver_status != "resolved_static_local_path" or resolved.resolved_realpath is None:
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status=resolved.resolver_status,
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
        )

    path = resolved.resolved_realpath
    try:
        stat_before = path.stat()
    except OSError:
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="unresolved_path",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
        )

    integrity = _integrity_from_stat(stat_before)
    if stat_before.st_size > max_bytes:
        integrity.size_bytes = int(stat_before.st_size)
        omitted = max(0, int(stat_before.st_size))
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="resolved_static_local_path",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
            integrity=integrity,
            omitted_bytes=omitted,
            truncated=True,
            oversize=True,
            derived_rules=[_rule("content_evidence_incomplete", "medium")],
        )

    try:
        data = path.read_bytes()
    except OSError:
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="unresolved_path",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
        )

    if after_read_hook is not None:
        after_read_hook(path)

    try:
        stat_after = path.stat()
    except OSError:
        stat_after = None

    integrity.sha256 = _sha256_bytes(data)
    integrity.sha256_full = integrity.sha256
    integrity.size_bytes = int(stat_before.st_size)
    integrity.stat_before = _stat_dict(stat_before)
    integrity.stat_after = _stat_dict(stat_after) if stat_after is not None else {}

    if stat_after is None or _stat_changed(stat_before, stat_after):
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="content_mismatch",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
            integrity=integrity,
            derived_rules=[_rule("content_mismatch", "high")],
        )

    if kind == "read_content" and _looks_binary_content(data, path):
        return _item(
            evidence_id=evidence_id,
            kind=kind,
            resolver_status="resolved_static_local_path",
            resolved_path=resolved.resolved_path,
            resolved_realpath=resolved.resolved_realpath,
            integrity=integrity,
            derived_rules=[_rule("read_content_unsupported_binary", "medium")],
        )

    try:
        content = data.decode("utf-8")
    except UnicodeDecodeError:
        content = data.decode("utf-8", errors="replace")

    return _item(
        evidence_id=evidence_id,
        kind=kind,
        resolver_status="resolved_static_local_path",
        resolved_path=resolved.resolved_path,
        resolved_realpath=resolved.resolved_realpath,
        integrity=integrity,
        included_ranges=[
            ContentEvidenceRange(
                start=0,
                end=len(data),
                reason="full_script_under_limit" if kind.endswith("script") else "full_content_under_limit",
            )
        ],
        content=content,
    )


def collect_script_content_evidence(
    script_path: str | Path,
    *,
    argv: list[str] | None = None,
    approved_roots: Iterable[str | Path],
    max_bytes: int = 262_144,
) -> ContentEvidenceEnvelope:
    """Collect evidence for a Python-like script and derive minimal source/sink rules."""

    evidence_id = make_safe_evidence_id(str(script_path), ordinal=1)
    resolved = resolve_under_approved_roots(script_path, approved_roots=approved_roots)
    item = acquire_pinned_file(
        resolved,
        evidence_id=evidence_id,
        kind="skill_script",
        max_bytes=max_bytes,
    )
    if item.content:
        rules = _scan_python_script(item.content, argv=argv or [])
        item = item.model_copy(update={"derived_rules": rules})
    elif (item.oversize or item.resolver_status != "resolved_static_local_path") and any(
        _looks_like_document_path(arg) for arg in (argv or [])
    ):
        rules = list(item.derived_rules)
        if not any(rule.get("rule_id") == "content_evidence_incomplete" for rule in rules):
            rules.append(_rule("content_evidence_incomplete", "medium"))
        if not any(rule.get("rule_id") == "possible_document_input_to_network_sink" for rule in rules):
            rules.append(_rule("possible_document_input_to_network_sink", "medium"))
        item = item.model_copy(update={"derived_rules": rules})
    envelope = ContentEvidenceEnvelope(items=[item])
    return envelope.model_copy(update={"exact_ref_allowlist": build_exact_ref_allowlist(envelope)})


def collect_for_event(
    event: CanonicalEvent,
    *,
    approved_roots: Iterable[str | Path] | None = None,
    max_bytes: int = 262_144,
) -> ContentEvidenceEnvelope | None:
    """Collect request-local content evidence for supported execution events."""

    if str(getattr(event, "event_type", "")) not in {"EventType.PRE_ACTION", "pre_action"}:
        return None
    read_evidence = collect_read_content_evidence([event], approved_roots=approved_roots, max_bytes=max_bytes)
    if read_evidence.items:
        return read_evidence
    payload = event.payload or {}
    command = str(payload.get("command") or payload.get("cmd") or "").strip()
    tool = str(event.tool_name or "").lower()
    if not command and tool not in {"python", "python3"}:
        return None
    cwd = Path(str(payload.get("cwd") or payload.get("working_dir") or os.getcwd())).expanduser()
    parts, cwd = _python_parts_from_command(command, cwd=cwd)
    if tool in {"python", "python3"} and not parts:
        script_value = str(payload.get("script") or payload.get("path") or "")
        parts = [tool, script_value] if script_value else []
    if len(parts) < 2:
        return _collect_inline_command_evidence(command, tool=tool)
    executable = Path(parts[0]).name.lower()
    if not re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable):
        return None
    script_index = _python_script_index(parts)
    if script_index is None:
        return _collect_inline_command_evidence(command, tool=tool)
    script = parts[script_index]

    script_path = Path(script).expanduser()
    if not script_path.is_absolute():
        script_path = cwd / script_path
    roots = list(approved_roots or [])
    if not roots:
        return None
    return collect_script_content_evidence(
        script_path,
        argv=parts[script_index + 1:],
        approved_roots=roots,
        max_bytes=max_bytes,
    )


def collect_read_content_evidence(
    tool_calls: Iterable[object],
    *,
    approved_roots: Iterable[str | Path] | None,
    max_bytes: int = 262_144,
) -> ContentEvidenceEnvelope:
    """Collect read-content evidence for Gateway-owned local file read tools."""

    roots = list(approved_roots or [])
    if not roots:
        return ContentEvidenceEnvelope()

    items: list[ContentEvidenceItem] = []
    for ordinal, call in enumerate(tool_calls, start=1):
        call_dict = _call_as_dict(call)
        payload = call_dict.get("payload") if isinstance(call_dict.get("payload"), dict) else {}
        semantics = derive_tool_semantics(call_dict)
        if semantics is None or "local_file_read" not in semantics.content_surfaces:
            continue
        path_value = _first_payload_value(payload, semantics.path_fields)
        if not path_value:
            continue
        evidence_id = make_safe_evidence_id(str(path_value), ordinal=ordinal)
        read_path = _path_with_payload_cwd(str(path_value), payload, roots)
        resolved = resolve_under_approved_roots(read_path, approved_roots=roots)
        source_metadata = {
            "native_tool_id": semantics.native_tool_id,
            "canonical_tool": semantics.canonical_tool,
            "kind": "read_content",
        }
        if _is_sensitive_read_path(str(path_value)):
            item = _sensitive_read_path_item(
                resolved,
                evidence_id=evidence_id,
                source_metadata=source_metadata,
            )
        else:
            item = acquire_pinned_file(
                resolved,
                evidence_id=evidence_id,
                kind="read_content",
                max_bytes=max_bytes,
            )
            rules = list(item.derived_rules)
            if item.content is not None:
                rules.extend(_scan_read_content_rules(item.content))
            elif item.oversize:
                rules.append(_rule("read_content_oversize", "medium"))
            elif item.resolver_status == "resolved_static_local_path":
                rules.append(_rule("read_content_unsupported_binary", "medium"))
            item = item.model_copy(update={
                "source_metadata": source_metadata,
                "derived_rules": _dedupe_rule_dicts(rules),
            })
        items.append(item)

    envelope = ContentEvidenceEnvelope(items=items)
    return envelope.model_copy(update={"exact_ref_allowlist": build_exact_ref_allowlist(envelope)})


def _collect_inline_command_evidence(command: str, *, tool: str) -> ContentEvidenceEnvelope | None:
    if not command:
        return None
    language = "shell"
    if tool in {"powershell", "pwsh"}:
        language = "powershell"
    elif tool in {"node", "nodejs", "javascript"} or re.search(r"\bnode\b", command):
        language = "shell"
    result = scan_content(command, language=language)
    if not result.derived_rules:
        return None
    item = _item(
        evidence_id="ce_001",
        kind="skill_script",
        resolver_status="inline_content",
        resolved_path=None,
        resolved_realpath=None,
        integrity=ContentEvidenceIntegrity(sha256=_sha256_text(command), sha256_full=_sha256_text(command), size_bytes=len(command.encode("utf-8"))),
        derived_rules=result.derived_rules,
        content=None,
    ).model_copy(update={
        "source": "gateway_inline_command",
        "source_metadata": {"language": language, "scanner": "content_scanners"},
    })
    envelope = ContentEvidenceEnvelope(items=[item])
    return envelope.model_copy(update={"exact_ref_allowlist": build_exact_ref_allowlist(envelope)})


def _python_parts_from_command(command: str, *, cwd: Path) -> tuple[list[str], Path]:
    if not command:
        return [], cwd
    for segment in _split_shell_segments(command):
        try:
            parts = shlex.split(segment)
        except ValueError:
            return [], cwd
        if not parts:
            continue
        executable = Path(parts[0]).name.lower()
        if executable == "cd" and len(parts) >= 2:
            next_cwd = Path(parts[1]).expanduser()
            cwd = next_cwd if next_cwd.is_absolute() else cwd / next_cwd
            continue
        if executable in {"bash", "sh", "zsh"} and len(parts) >= 3:
            for index, part in enumerate(parts[:-1]):
                if part in {"-c", "-lc"} or (part.startswith("-") and "c" in part):
                    return _python_parts_from_command(parts[index + 1], cwd=cwd)
        extracted = _extract_python_invocation(parts)
        if extracted and re.fullmatch(r"python(?:3(?:\.\d+)?)?", Path(extracted[0]).name.lower()):
            return extracted, cwd
    return [], cwd


def _call_as_dict(call: object) -> dict[str, object]:
    if isinstance(call, dict):
        return dict(call)
    return {
        "source_framework": getattr(call, "source_framework", None),
        "tool_name": getattr(call, "tool_name", None),
        "payload": getattr(call, "payload", None) or {},
    }


def _first_payload_value(payload: dict[str, object], fields: Iterable[str]) -> str | None:
    for field in fields:
        value: object = payload
        for part in str(field).split("."):
            if not isinstance(value, dict) or part not in value:
                value = None
                break
            value = value[part]
        if isinstance(value, str) and value.strip():
            return value
    return None


def _path_with_payload_cwd(value: str, payload: dict[str, object], roots: Iterable[str | Path]) -> str:
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path)
    cwd_raw = payload.get("cwd") or payload.get("working_dir")
    if not isinstance(cwd_raw, str) or not cwd_raw.strip():
        return value
    cwd = Path(cwd_raw).expanduser()
    if not cwd.is_absolute():
        return value
    cwd_abs = Path(os.path.abspath(cwd)).resolve(strict=False)
    approved = [Path(os.path.abspath(Path(root).expanduser())).resolve(strict=False) for root in roots]
    if not any(_is_relative_to(cwd_abs, root) for root in approved):
        return value
    return str(cwd_abs / path)


def _is_sensitive_read_path(value: str) -> bool:
    path_l = value.replace("\\", "/").lower()
    name = Path(path_l).name
    if "/.ssh/" in path_l or name in {".env", ".npmrc", ".pypirc", "credentials", "id_rsa", "id_ed25519"}:
        return True
    if re.search(r"(?:private[-_]?key|credential|secret|token|apikey|api_key)", name):
        return True
    return bool(re.search(r"\.(?:pem|key|p12|pfx)$", name))


def _looks_binary_content(data: bytes, path: Path) -> bool:
    suffix = path.suffix.lower()
    if suffix in {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".docx", ".pptx", ".xlsx"}:
        return True
    if b"\x00" in data[:4096]:
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return True
    return False


def _sensitive_read_path_item(
    resolved: ResolvedContentPath,
    *,
    evidence_id: str,
    source_metadata: dict[str, object],
) -> ContentEvidenceItem:
    integrity = ContentEvidenceIntegrity()
    if resolved.resolved_realpath is not None:
        try:
            stat_result = resolved.resolved_realpath.stat()
            integrity = _integrity_from_stat(stat_result)
        except OSError:
            pass
    return _item(
        evidence_id=evidence_id,
        kind="read_content",
        resolver_status=resolved.resolver_status,
        resolved_path=resolved.resolved_path,
        resolved_realpath=resolved.resolved_realpath,
        integrity=integrity,
        derived_rules=[
            _rule("sensitive_read_path", "high"),
            _rule("credential_read_content_skipped", "high"),
        ],
    ).model_copy(update={"source_metadata": source_metadata})


def _scan_read_content_rules(content: str) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    lower = content.lower()
    if re.search(r"ignore (?:all )?(?:previous|prior) instructions|system prompt|developer message|exfiltrat", lower):
        rules.append(_rule("read_content_prompt_injection", "high"))
    if re.search(r"<!--.*?(ignore|instruction|system prompt|exfiltrat).*?-->", content, re.IGNORECASE | re.DOTALL):
        rules.append(_rule("read_content_hidden_html_instruction", "high"))
    if re.search(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069]", content):
        rules.append(_rule("read_content_zero_width_or_bidi", "medium"))
    if re.search(r"!\[[^\]]*\]\(\s*https?://", content, re.IGNORECASE):
        rules.append(_rule("read_content_markdown_beacon", "medium"))
    if re.search(r"data:[^;]+;base64,|[A-Za-z0-9+/]{80,}={0,2}", content):
        rules.append(_rule("read_content_data_uri_or_base64_payload", "medium"))
    if re.search(r"\b(?:curl|wget|requests\.(?:post|put|patch)|fetch\(|subprocess\.|os\.system)\b", content):
        rules.append(_rule("read_content_execution_or_network_instruction", "high"))
    return _dedupe_rule_dicts(rules)


def _dedupe_rule_dicts(rules: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[str] = set()
    result: list[dict[str, object]] = []
    for rule in rules:
        rule_id = str(rule.get("rule_id") or "")
        if rule_id and rule_id not in seen:
            seen.add(rule_id)
            result.append(rule)
    return result


def _split_shell_segments(command: str) -> list[str]:
    return [segment.strip() for segment in re.split(r"\s*(?:&&|;)\s*", command) if segment.strip()]


def _python_script_index(parts: list[str]) -> int | None:
    index = 1
    options_with_values = {
        "-c",
        "-m",
        "-W",
        "-X",
        "--check-hash-based-pycs",
    }
    while index < len(parts):
        part = parts[index]
        if part == "--":
            index += 1
            break
        if not part.startswith("-"):
            break
        if part in {"-c", "-m"}:
            return None
        if part in options_with_values:
            index += 2
            continue
        index += 1
    if index >= len(parts) or parts[index].startswith("-"):
        return None
    return index


def _extract_python_invocation(parts: list[str]) -> list[str]:
    if not parts:
        return []
    executable = Path(parts[0]).name.lower()
    if re.fullmatch(r"python(?:3(?:\.\d+)?)?", executable):
        return parts
    if executable in {"bash", "sh", "zsh"} and len(parts) >= 3:
        for index, part in enumerate(parts[:-1]):
            if part in {"-c", "-lc"} or (part.startswith("-") and "c" in part):
                try:
                    nested = shlex.split(parts[index + 1])
                except ValueError:
                    return []
                return _extract_python_invocation(nested)
    return parts


def _scan_python_script(content: str, *, argv: list[str]) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    network_indicator = _has_network_indicator(content)
    network_sink = _has_network_upload_sink(content)
    document_read = _has_document_arg_read(content)
    has_document_arg = any(_looks_like_document_path(arg) for arg in argv)
    subprocess_transfer = _has_subprocess_file_transfer(content)

    if subprocess_transfer:
        rules.append(_rule("subprocess_file_transfer", "high"))
    if network_sink:
        rules.append(_rule("associated_script_network_sink", "high"))
    elif network_indicator:
        rules.append(_rule("associated_script_network_indicator", "low"))
    if network_sink and document_read:
        rules.append(_rule("document_input_to_network_sink", "high"))
    elif network_sink and has_document_arg:
        rules.append(_rule("possible_document_input_to_network_sink", "medium"))
    return rules


def _has_network_indicator(content: str) -> bool:
    return bool(re.search(r"\b(import|from)\s+(requests|httpx|urllib|aiohttp|socket)\b", content))


def _has_network_upload_sink(content: str) -> bool:
    try:
        tree = ast.parse(content)
    except SyntaxError:
        tree = None
    if tree is not None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)
            if name.endswith((".post", ".put", ".patch")) or name in {"post", "put", "patch"}:
                keyword_names = {kw.arg for kw in node.keywords if kw.arg}
                if keyword_names.intersection({"files", "data", "content", "json"}):
                    return True
            if name.startswith("urllib.") and any(kw.arg == "data" for kw in node.keywords):
                return True
    return bool(
        re.search(r"\b(?:requests|httpx|aiohttp)\.post\s*\([^)]*(?:files|data|content)\s*=", content, re.DOTALL)
        or re.search(r"\burllib\.request\.[A-Za-z_]+\s*\([^)]*data\s*=", content, re.DOTALL)
    )


def _has_document_arg_read(content: str) -> bool:
    return bool(
        re.search(r"open\(\s*sys\.argv\[\d+\]", content)
        or re.search(r"Path\(\s*sys\.argv\[\d+\]\s*\)\.read_(?:text|bytes)\(", content)
        or re.search(r"\.read_(?:text|bytes)\(\)", content)
    )


def _has_subprocess_file_transfer(content: str) -> bool:
    return bool(
        re.search(r"\bsubprocess\.", content)
        and re.search(r"\b(curl)\b.*(?:-F|--form|--data-binary|-d\s*@)|\b(scp)\b|\brsync\b.*:", content, re.DOTALL)
    )


def _looks_like_document_path(value: str) -> bool:
    return bool(re.search(r"\.(pptx|docx|xlsx|pdf|csv|json|env)\b", value, re.IGNORECASE))


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _item(
    *,
    evidence_id: str,
    kind: str,
    resolver_status: str,
    resolved_path: Path | None,
    resolved_realpath: Path | None,
    integrity: ContentEvidenceIntegrity | None = None,
    included_ranges: list[ContentEvidenceRange] | None = None,
    omitted_bytes: int = 0,
    truncated: bool = False,
    oversize: bool = False,
    derived_rules: list[dict[str, object]] | None = None,
    content: str | None = None,
) -> ContentEvidenceItem:
    return ContentEvidenceItem(
        canonical_evidence_id=evidence_id,
        kind=kind,
        source="gateway_resolved_path",
        path=_path_label(resolved_path),
        resolved_path_hash=_sha256_text(str(resolved_path)) if resolved_path is not None else None,
        resolved_realpath_hash=_sha256_text(str(resolved_realpath)) if resolved_realpath is not None else None,
        path_trust="gateway_resolved_workspace" if resolver_status == "resolved_static_local_path" else "unresolved",
        resolver_status=resolver_status,
        integrity=integrity or ContentEvidenceIntegrity(),
        included_ranges=included_ranges or [],
        omitted_bytes=omitted_bytes,
        truncated=truncated,
        oversize=oversize,
        derived_rules=derived_rules or [],
        content_persisted=False,
        content=content,
    )


def _integrity_from_stat(stat_result: os.stat_result) -> ContentEvidenceIntegrity:
    return ContentEvidenceIntegrity(
        size_bytes=int(stat_result.st_size),
        mtime_ns=int(stat_result.st_mtime_ns),
        file_identity=f"{stat_result.st_dev}:{stat_result.st_ino}",
        stat_before=_stat_dict(stat_result),
    )


def _stat_dict(stat_result: os.stat_result | None) -> dict[str, int | str]:
    if stat_result is None:
        return {}
    return {
        "size_bytes": int(stat_result.st_size),
        "mtime_ns": int(stat_result.st_mtime_ns),
        "file_identity": f"{stat_result.st_dev}:{stat_result.st_ino}",
    }


def _stat_changed(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        int(before.st_size) != int(after.st_size)
        or int(before.st_mtime_ns) != int(after.st_mtime_ns)
        or int(before.st_ino) != int(after.st_ino)
        or int(before.st_dev) != int(after.st_dev)
    )


def _rule(rule_id: str, severity: str) -> dict[str, object]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "extractor": CONTENT_EVIDENCE_EXTRACTOR_VERSION,
    }


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _path_label(path: Path | None) -> str | None:
    if path is None:
        return None
    return path.name


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))
