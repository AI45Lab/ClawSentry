"""Managed benchmark warning blocks that should not perturb review evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re


WORK5C_WARNING_PROFILE_ID = "fspr-warning-skill-md-shadow-v1"
WORK5C_WARNING_SCHEMA_VERSION = "clawsentry.work5c.skill_folder_warning.v1"
WORK5C_WARNING_NONCE_ENV = "CS_WORK5C_WARNING_NONCE"
_SAFE_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_SAFE_NONCE_RE = re.compile(r"[A-Za-z0-9_-]{16,160}\Z")
_MANAGED_BODY_PREFIXES = (
    "ClawSentry Work5C warning:",
    "FSPR review state:",
    "FSPR finding ",
    "Safety status unknown:",
    "Safe-use guidance:",
    "Do not discard the skill solely because of this warning;",
)

_WORK5C_WARNING_BLOCK_RE = re.compile(
    r"<!-- CLAWSENTRY_WORK5C_WARNING:BEGIN\s+"
    r"(?P<metadata>\{[^\r\n]*\})\s*-->\r?\n"
    r"(?P<body>.*?)"
    r"<!-- CLAWSENTRY_WORK5C_WARNING:END -->(?:\r?\n){0,2}",
    re.DOTALL,
)


def _sha256_text(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _body_looks_managed_work5c_warning(body: str) -> bool:
    normalized = body.replace("\r\n", "\n").rstrip("\n")
    if len(normalized) > 4096:
        return False
    lines = [line for line in normalized.split("\n") if line.strip()]
    if not lines or not lines[0].startswith("ClawSentry Work5C warning:"):
        return False
    return all(line.startswith(_MANAGED_BODY_PREFIXES) for line in lines)


def _expected_warning_nonce(expected_nonce: str | None) -> str | None:
    nonce = expected_nonce if expected_nonce is not None else os.environ.get(WORK5C_WARNING_NONCE_ENV)
    if nonce is None:
        return None
    nonce = nonce.strip()
    if not _SAFE_NONCE_RE.fullmatch(nonce):
        return None
    return nonce


def _valid_work5c_warning_block(
    metadata_raw: str,
    body: str,
    *,
    expected_nonce: str | None = None,
) -> bool:
    expected_nonce = _expected_warning_nonce(expected_nonce)
    if expected_nonce is None:
        return False
    try:
        metadata = json.loads(metadata_raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(metadata, dict):
        return False
    if metadata.get("schema") != WORK5C_WARNING_SCHEMA_VERSION:
        return False
    if metadata.get("profile") != WORK5C_WARNING_PROFILE_ID:
        return False
    if metadata.get("warning_nonce") != expected_nonce:
        return False
    normalized_body = body.replace("\r\n", "\n").rstrip("\n")
    if not _body_looks_managed_work5c_warning(normalized_body):
        return False
    if metadata.get("warning_text_hash") != _sha256_text(normalized_body):
        return False
    warning_kind = metadata.get("warning_kind")
    if warning_kind is not None and not _SAFE_TOKEN_RE.fullmatch(str(warning_kind)):
        return False
    return True


def strip_managed_work5c_warning_blocks(
    text: str,
    *,
    expected_nonce: str | None = None,
) -> str:
    """Remove only authenticated Work5C warning blocks.

    A skill-authored marker with different metadata or body remains visible to
    scanners so the marker cannot be used as a hiding primitive.
    """

    def replace(match: re.Match[str]) -> str:
        if _valid_work5c_warning_block(
            match.group("metadata"),
            match.group("body"),
            expected_nonce=expected_nonce,
        ):
            return ""
        return match.group(0)

    return _WORK5C_WARNING_BLOCK_RE.sub(replace, text)
