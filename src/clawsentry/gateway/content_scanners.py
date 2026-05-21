"""Normalized request-local content scanner plugins.

Scanners return evidence metadata only. They intentionally do not return policy
verdicts or decision recommendations.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


CONTENT_SCANNER_VERSION = "content_scanners.normalized@v1"


@dataclass(frozen=True)
class ContentScanResult:
    derived_rules: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    budget_truncated: bool = False
    policy_action: None = None


def scan_content(
    content: str | bytes,
    *,
    language: str,
    source_path: str | Path | None = None,
    local_module_roots: Iterable[str | Path] | None = None,
    max_bytes: int = 262_144,
    max_local_modules: int = 8,
) -> ContentScanResult:
    """Scan a bounded content fragment and return normalized evidence rules."""

    raw_len = len(content if isinstance(content, bytes) else content.encode("utf-8", errors="replace"))
    metadata: dict[str, Any] = {
        "language": language,
        "source_path_label": Path(source_path).name if source_path is not None else None,
    }
    if raw_len > max_bytes:
        metadata["omitted_bytes"] = raw_len
        return ContentScanResult(
            derived_rules=[_rule("content_evidence_incomplete", "medium")],
            metadata=metadata,
            budget_truncated=True,
        )

    if isinstance(content, bytes):
        metadata.update(_document_metadata(content, source_path))
        return ContentScanResult(
            derived_rules=[_rule("read_content_unsupported_binary", "medium")],
            metadata=metadata,
        )

    language_l = language.strip().lower()
    if language_l in {"shell", "bash", "sh", "zsh"}:
        text = _capture_shell_embedded(content)
        return ContentScanResult(derived_rules=_scan_text_rules(text, language="shell"), metadata=metadata)
    if language_l in {"javascript", "js", "node", "nodejs"}:
        return ContentScanResult(derived_rules=_scan_text_rules(content, language="javascript"), metadata=metadata)
    if language_l in {"powershell", "pwsh"}:
        return ContentScanResult(derived_rules=_scan_text_rules(content, language="powershell"), metadata=metadata)
    if language_l == "python":
        rules = _scan_text_rules(content, language="python")
        rules.extend(_python_syntax_rules(content))
        rules.extend(_local_module_rules(content, source_path=source_path, roots=local_module_roots, max_modules=max_local_modules))
        return ContentScanResult(derived_rules=_dedupe_rules(rules), metadata=metadata)
    if language_l in {"document", "binary"}:
        metadata.update(_document_metadata(content.encode("utf-8", errors="replace"), source_path))
        return ContentScanResult(derived_rules=[_rule("read_content_unsupported_binary", "medium")], metadata=metadata)
    return ContentScanResult(derived_rules=[_rule("content_evidence_incomplete", "medium")], metadata=metadata)


def _scan_text_rules(text: str, *, language: str) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []
    lower = text.lower()
    if re.search(r"\b(?:requests|httpx|fetch|curl|wget|invoke-webrequest|urllib)\b", lower):
        if re.search(r"\b(?:post|put|patch|body|data|files)\b|(?:^|\s)(?:-f|--form|--data)(?:\s|=|$)", lower):
            rules.append(_rule("associated_script_network_sink", "high"))
        else:
            rules.append(_rule("associated_script_network_indicator", "low"))
    if re.search(r"\b(?:hf_token|api[_-]?key|password|secret|token|\$env:)\b", lower) and rules:
        rules.append(_rule("credential_source_to_network_sink", "high"))
    if re.search(r"\b(?:rm\s+-rf|remove-item\s+-recurse|del\s+/f)\b", lower):
        rules.append(_rule("destructive_operation", "high"))
    if re.search(r"\b(?:crontab|launchagents|systemd|startup)\b", lower):
        rules.append(_rule("persistence_entrypoint", "medium"))
    return _dedupe_rules(rules)


def _python_syntax_rules(text: str) -> list[dict[str, Any]]:
    try:
        ast.parse(text)
    except SyntaxError:
        return [_rule("content_evidence_syntax_error", "low")]
    return []


def _local_module_rules(
    text: str,
    *,
    source_path: str | Path | None,
    roots: Iterable[str | Path] | None,
    max_modules: int,
) -> list[dict[str, Any]]:
    if source_path is None:
        return []
    root_paths = [Path(root).resolve(strict=False) for root in (roots or [])]
    if not root_paths:
        return []
    imported = re.findall(r"(?m)^\s*import\s+([A-Za-z_][A-Za-z0-9_]*)\s*$", text)
    rules: list[dict[str, Any]] = []
    for index, module_name in enumerate(imported):
        if index >= max_modules:
            rules.append(_rule("content_evidence_incomplete", "medium"))
            break
        candidate = Path(source_path).parent / f"{module_name}.py"
        try:
            real = candidate.resolve(strict=True)
        except OSError:
            continue
        if not any(_is_relative_to(real, root) for root in root_paths):
            rules.append(_rule("content_evidence_incomplete", "medium"))
            continue
        rules.extend(_scan_text_rules(real.read_text(encoding="utf-8", errors="replace"), language="python"))
    return rules


def _capture_shell_embedded(text: str) -> str:
    captures = [text]
    for match in re.finditer(r"\b(?:python|python3|node)\s+-[ce]\s+(['\"])(?P<body>.*?)(?<!\\)\1", text, re.DOTALL):
        captures.append(match.group("body"))
    heredoc = re.search(r"<<['\"]?(?P<tag>[A-Za-z_][A-Za-z0-9_]*)['\"]?\n(?P<body>.*?)\n(?P=tag)\b", text, re.DOTALL)
    if heredoc:
        captures.append(heredoc.group("body"))
    return "\n".join(captures)


def _document_metadata(data: bytes, source_path: str | Path | None) -> dict[str, Any]:
    path = Path(source_path) if source_path is not None else Path("")
    return {
        "extension": path.suffix.lower(),
        "size_bytes": len(data),
        "mime_guess": _mime_guess(path.suffix.lower()),
        "macro_indicator": path.suffix.lower() in {".docm", ".xlsm", ".pptm"},
    }


def _mime_guess(extension: str) -> str:
    return {
        ".pdf": "application/pdf",
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    }.get(extension, "application/octet-stream")


def _rule(rule_id: str, severity: str) -> dict[str, Any]:
    return {"rule_id": rule_id, "severity": severity, "extractor": CONTENT_SCANNER_VERSION}


def _dedupe_rules(rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result: list[dict[str, Any]] = []
    for rule in rules:
        rule_id = str(rule.get("rule_id") or "")
        if rule_id and rule_id not in seen:
            seen.add(rule_id)
            result.append(rule)
    return result


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False
