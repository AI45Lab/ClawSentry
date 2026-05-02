"""Session-scope evaluator for minimum task permission.

The evaluator is intentionally deterministic and AHP-native: it reads an
optional ``SessionScopeProfile`` from ``DecisionContext`` and returns a compact
summary. It never lowers an existing risk decision; policy composition decides
whether a non-dry-run, confirmed scope result may tighten ALLOW to DEFER/BLOCK.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from .models import (
    CanonicalEvent,
    DecisionContext,
    SessionScopeEvaluationSummary,
    SessionScopeProfile,
    SessionScopeVerdict,
)


_URL_RE = re.compile(r"https?://[^\s'\"<>|)]+", re.IGNORECASE)
_PATH_RE = re.compile(r"(?:~|/|\./|\.\./)[A-Za-z0-9._~:/@%+\-=]+")
_DESTRUCTIVE_COMMAND_RE = re.compile(
    r"\b(?:rm\s+-[^\s]*r|sudo|dd\b.*\bof\s*=\s*/dev/|mkfs|chmod\s+777)\b",
    re.IGNORECASE,
)
_NETWORK_WRITE_RE = re.compile(
    r"\b(?:curl|wget|http|httpie)\b.*\b(?:-d|--data|--data-binary|--post-data|-F|--form|--upload-file|-T)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SessionScopeEvaluation:
    profile: SessionScopeProfile
    verdict: SessionScopeVerdict
    reason_codes: tuple[str, ...]

    @property
    def enforced(self) -> bool:
        return bool(self.profile.confirmed and not self.profile.dry_run)

    def summary(self) -> SessionScopeEvaluationSummary:
        return SessionScopeEvaluationSummary(
            profile_id=self.profile.profile_id,
            source=self.profile.source,
            confirmed=self.profile.confirmed,
            dry_run=self.profile.dry_run,
            enforced=self.enforced,
            verdict=self.verdict,
            reason_codes=list(self.reason_codes),
        )


def scope_protection_statement(*, enforced: bool) -> str:
    """Return capability-honest user copy for session-scope surfaces."""

    if enforced:
        return (
            "Protected today: confirmed non-dry-run scope profiles can tighten "
            "Gateway decisions to defer or block actions. Not protected today: "
            "ClawSentry does not infer scopes automatically from LLM output."
        )
    return (
        "Protected today: scope preview validates rules and explains the decision "
        "that would apply. Not protected today: dry-run scope profiles do not "
        "block or defer actions until explicitly confirmed."
    )


def evaluate_session_scope(
    event: CanonicalEvent,
    context: DecisionContext | None,
) -> SessionScopeEvaluation | None:
    """Evaluate the optional session scope profile attached to *context*."""

    profile = context.session_scope_profile if context else None
    if profile is None:
        return None

    command = _event_command(event)
    tool = (event.tool_name or "").lower()
    paths = _event_paths(event, command)
    domains = _event_domains(event, command)

    deny_reasons = _base_deny_reasons(profile, tool, command, paths, domains)
    if deny_reasons:
        return SessionScopeEvaluation(
            profile=profile,
            verdict=SessionScopeVerdict.DENY,
            reason_codes=tuple(deny_reasons),
        )

    allow_reasons = _task_allow_reasons(profile, tool, command, paths, domains)
    defer_reasons = _task_defer_reasons(profile, event, tool, command, paths, domains)
    if defer_reasons:
        return SessionScopeEvaluation(
            profile=profile,
            verdict=SessionScopeVerdict.DEFER,
            reason_codes=tuple(defer_reasons),
        )
    if allow_reasons:
        return SessionScopeEvaluation(
            profile=profile,
            verdict=SessionScopeVerdict.ALLOW,
            reason_codes=tuple(allow_reasons),
        )
    return SessionScopeEvaluation(
        profile=profile,
        verdict=SessionScopeVerdict.NEUTRAL,
        reason_codes=("scope_neutral:no_applicable_rule",),
    )


def _event_command(event: CanonicalEvent) -> str:
    command = event.payload.get("command")
    if command is None:
        command = event.payload.get("cmd")
    return str(command or "")


def _event_paths(event: CanonicalEvent, command: str) -> tuple[str, ...]:
    paths: list[str] = []
    for key in ("path", "file_path", "target_path"):
        value = event.payload.get(key)
        if value:
            paths.append(str(value))
    paths.extend(match.group(0) for match in _PATH_RE.finditer(command))
    return tuple(dict.fromkeys(paths))


def _event_domains(event: CanonicalEvent, command: str) -> tuple[str, ...]:
    urls: list[str] = []
    for key in ("url", "uri", "endpoint"):
        value = event.payload.get(key)
        if value:
            urls.append(str(value))
    urls.extend(match.group(0) for match in _URL_RE.finditer(command))
    domains: list[str] = []
    for url in urls:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split("/", 1)[0]
        domain = domain.split("@")[-1].split(":")[0].lower()
        if domain:
            domains.append(domain)
    return tuple(dict.fromkeys(domains))


def _base_deny_reasons(
    profile: SessionScopeProfile,
    tool: str,
    command: str,
    paths: Iterable[str],
    domains: Iterable[str],
) -> list[str]:
    reasons: list[str] = []
    if tool and _contains_ci(profile.base_rules.denied_tools, tool):
        reasons.append(f"scope_deny:tool {tool}")
    for prefix in profile.base_rules.denied_command_prefixes:
        if command.strip().lower().startswith(prefix.lower()):
            reasons.append(f"scope_deny:command_prefix {prefix}")
    for path in paths:
        match = _match_path(profile.base_rules.denied_paths, path)
        if match:
            reasons.append(f"scope_deny:path {match}")
    for domain in domains:
        match = _match_domain(profile.base_rules.denied_domains, domain)
        if match:
            reasons.append(f"scope_deny:domain {match}")
    if _DESTRUCTIVE_COMMAND_RE.search(command):
        # User-friendly base invariant even when the profile author forgot the
        # exact command prefix.
        reasons.append("scope_deny:destructive_command")
    return reasons


def _task_allow_reasons(
    profile: SessionScopeProfile,
    tool: str,
    command: str,
    paths: Iterable[str],
    domains: Iterable[str],
) -> list[str]:
    reasons: list[str] = []
    if tool and _contains_ci(profile.task_rules.allowed_tools, tool):
        reasons.append(f"scope_allow:tool {tool}")
    for prefix in profile.task_rules.allowed_command_prefixes:
        if command.strip().lower().startswith(prefix.lower()):
            reasons.append(f"scope_allow:command_prefix {prefix}")
    for path in paths:
        match = _match_path(profile.task_rules.allowed_path_prefixes, path)
        if match:
            reasons.append(f"scope_allow:path_prefix {match}")
    for domain in domains:
        match = _match_domain(profile.task_rules.allowed_domains, domain)
        if match:
            reasons.append(f"scope_allow:domain {match}")
    return reasons


def _task_defer_reasons(
    profile: SessionScopeProfile,
    event: CanonicalEvent,
    tool: str,
    command: str,
    paths: Iterable[str],
    domains: Iterable[str],
) -> list[str]:
    reasons: list[str] = []
    task = profile.task_rules
    if task.allowed_tools and tool and not _contains_ci(task.allowed_tools, tool):
        reasons.append(f"scope_defer:unknown_tool {tool}")
    if task.allowed_domains:
        for domain in domains:
            if not _match_domain(task.allowed_domains, domain):
                reasons.append(f"scope_defer:unknown_domain {domain}")
    if task.allowed_path_prefixes:
        for path in paths:
            if not _match_path(task.allowed_path_prefixes, path):
                reasons.append(f"scope_defer:unknown_path {path}")
    if task.allowed_command_prefixes and command.strip():
        if not any(
            command.strip().lower().startswith(prefix.lower())
            for prefix in task.allowed_command_prefixes
        ):
            reasons.append("scope_defer:unknown_command")
    if _NETWORK_WRITE_RE.search(command):
        reasons.append("scope_defer:network_write")
    if (
        event.payload.get("url") or domains
    ) and not task.allowed_domains and "network" not in task.queued_categories:
        reasons.append("scope_defer:network_unscoped")
    return list(dict.fromkeys(reasons))


def _contains_ci(values: Iterable[str], value: str) -> bool:
    needle = value.lower()
    return any(item.lower() == needle for item in values)


def _match_domain(patterns: Iterable[str], domain: str) -> str | None:
    domain = domain.lower()
    for pattern in patterns:
        candidate = pattern.lower().lstrip(".")
        if domain == candidate or domain.endswith("." + candidate):
            return pattern
    return None


def _match_path(patterns: Iterable[str], path: str) -> str | None:
    normalized = path.replace("\\", "/")
    expanded = normalized.replace("~", "/home/user", 1) if normalized.startswith("~") else normalized
    for pattern in patterns:
        pat = pattern.replace("\\", "/")
        pat_expanded = pat.replace("~", "/home/user", 1) if pat.startswith("~") else pat
        if normalized.startswith(pat) or expanded.startswith(pat_expanded) or pat in normalized:
            return pattern
    return None
