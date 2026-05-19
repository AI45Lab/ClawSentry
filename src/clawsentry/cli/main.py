"""Unified CLI entry point for clawsentry."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .initializers import FRAMEWORK_INITIALIZERS


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="clawsentry",
        description="ClawSentry — AHP unified safety supervision framework.",
    )
    sub = parser.add_subparsers(dest="command")

    # --- init ---
    init_parser = sub.add_parser(
        "init",
        help="Initialize framework integration.",
    )
    init_parser.add_argument(
        "framework",
        choices=sorted(FRAMEWORK_INITIALIZERS.keys()),
        help="Target framework to initialize.",
    )
    init_parser.add_argument(
        "--dir",
        type=Path,
        default=Path("."),
        help="Directory to write config files (default: current dir).",
    )
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing config files.",
    )
    init_parser.add_argument(
        "--auto-detect",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Auto-detect existing framework configuration (default: on).",
    )
    init_parser.add_argument(
        "--setup",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Auto-configure framework settings for ClawSentry integration (default: off).",
    )
    init_parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview supported framework setup changes without applying (use with --setup).",
    )
    init_parser.add_argument(
        "--hardened-profile",
        action="store_true",
        default=False,
        help=(
            "Opt in to marker-managed OpenClaw native-tool hardening. "
            "Use with --setup; dry-run is recommended first."
        ),
    )
    init_parser.add_argument(
        "--openclaw-home",
        type=Path,
        default=None,
        help="Custom OpenClaw config directory (default: ~/.openclaw/).",
    )
    init_parser.add_argument(
        "--codex-home",
        type=Path,
        default=None,
        help="Custom Codex config directory (default: $CODEX_HOME or ~/.codex/).",
    )
    init_parser.add_argument(
        "--gemini-home",
        type=Path,
        default=None,
        help=(
            "Custom Gemini CLI config directory. By default --setup writes "
            "project-local .gemini/settings.json under --dir."
        ),
    )
    init_parser.add_argument(
        "--kimi-home",
        type=Path,
        default=None,
        help="Custom Kimi share/config directory (default: $KIMI_SHARE_DIR or ~/.kimi/).",
    )
    init_parser.add_argument(
        "--uninstall",
        action="store_true",
        default=False,
        help=(
            "Disable one framework integration in project env and remove "
            "supported framework hooks."
        ),
    )
    init_parser.add_argument(
        "--restore",
        action="store_true",
        default=False,
        help="Restore framework settings from ClawSentry backups (currently OpenClaw).",
    )

    # --- gateway ---
    sub.add_parser(
        "gateway",
        help="Start Supervision Gateway (auto-enables OpenClaw when configured).",
        add_help=False,
    )

    # --- stack ---
    sub.add_parser(
        "stack",
        help="Start full stack (Gateway + OpenClaw). Alias for gateway.",
        add_help=False,
    )

    # --- harness ---
    sub.add_parser(
        "harness",
        help="Start a3s-code stdio harness.",
        add_help=False,
    )

    # --- watch ---
    _watch_port = os.environ.get("CS_HTTP_PORT", "8080")
    _watch_default_url = f"http://127.0.0.1:{_watch_port}"
    watch_parser = sub.add_parser(
        "watch",
        help="Watch real-time SSE events from the Supervision Gateway.",
    )
    watch_parser.add_argument(
        "--gateway-url",
        default=_watch_default_url,
        help=f"Gateway base URL (default: {_watch_default_url}).",
    )
    watch_parser.add_argument(
        "--token",
        default=os.environ.get("CS_AUTH_TOKEN"),
        help="Bearer token for Gateway authentication [CS_AUTH_TOKEN].",
    )
    watch_parser.add_argument(
        "--filter",
        default=None,
        help="Comma-separated event types to subscribe to (e.g. decision,alert).",
    )
    watch_parser.add_argument(
        "--priority-only",
        action="store_true",
        default=False,
        help=(
            "Subscribe to an operator-priority watch profile "
            "(decision/alert/defer/enforcement/budget/L3-advisory events)."
        ),
    )
    watch_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output raw JSON instead of formatted text.",
    )
    watch_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in output.",
    )
    watch_parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        default=False,
        help="Prompt operator to Allow/Deny/Skip on DEFER decisions.",
    )
    watch_parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Show detailed information for all decisions (including ALLOW).",
    )
    watch_parser.add_argument(
        "--no-emoji",
        action="store_true",
        default=False,
        help="Disable emoji (for plain text / narrow terminal environments).",
    )
    watch_parser.add_argument(
        "--compact",
        action="store_true",
        default=False,
        help="Use compact format without Unicode box drawing for session groups.",
    )

    # --- scope ---
    scope_parser = sub.add_parser(
        "scope",
        help="Validate or preview deterministic session scope profiles.",
    )
    scope_sub = scope_parser.add_subparsers(dest="scope_command", required=True)
    scope_validate = scope_sub.add_parser(
        "validate",
        help="Validate a session scope profile JSON file.",
    )
    scope_validate.add_argument(
        "--profile",
        type=Path,
        required=True,
        help="Path to a SessionScopeProfile JSON file.",
    )
    scope_validate.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit machine-readable JSON.",
    )
    scope_preview = scope_sub.add_parser(
        "preview",
        help="Preview a session scope profile against one canonical event.",
    )
    scope_preview.add_argument(
        "--profile",
        type=Path,
        required=True,
        help="Path to a SessionScopeProfile JSON file.",
    )
    scope_preview.add_argument(
        "--event",
        type=Path,
        required=True,
        help="Path to a CanonicalEvent JSON file.",
    )
    scope_preview.add_argument(
        "--confirm",
        action="store_true",
        default=False,
        help="Preview as confirmed/enforced instead of dry-run.",
    )
    scope_preview.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Emit machine-readable JSON.",
    )

    # --- audit ---
    audit_parser = sub.add_parser(
        "audit",
        help="Query offline audit logs from trajectory database.",
    )
    audit_parser.add_argument(
        "--db",
        default=None,
        help="Database path (default: CS_TRAJECTORY_DB_PATH or /tmp/clawsentry-trajectory.db).",
    )
    audit_parser.add_argument(
        "--session",
        default=None,
        help="Filter by session ID.",
    )
    audit_parser.add_argument(
        "--since",
        default=None,
        help="Time window (e.g. 1h, 24h, 7d, 30m).",
    )
    audit_parser.add_argument(
        "--risk",
        default=None,
        choices=["low", "medium", "high", "critical"],
        help="Filter by risk level.",
    )
    audit_parser.add_argument(
        "--decision",
        default=None,
        choices=["allow", "block", "defer", "modify"],
        help="Filter by decision verdict.",
    )
    audit_parser.add_argument(
        "--tool",
        default=None,
        help="Filter by tool name.",
    )
    audit_parser.add_argument(
        "--format",
        default="table",
        choices=["table", "json", "csv"],
        dest="output_format",
        help="Output format (default: table).",
    )
    audit_parser.add_argument(
        "--stats",
        action="store_true",
        default=False,
        help="Show aggregate statistics only.",
    )
    audit_parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum records to return (default: 100).",
    )
    audit_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in output.",
    )

    # --- doctor ---
    doc_parser = sub.add_parser(
        "doctor",
        help="Audit configuration for security issues.",
    )
    doc_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON.",
    )
    doc_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in output.",
    )
    doc_parser.add_argument("--env-file", type=Path, default=None, help="Explicit local env file for diagnostics.")

    # --- test-llm ---
    test_llm_parser = sub.add_parser(
        "test-llm",
        help="Test LLM API connectivity, latency, and L2/L3 functionality.",
    )
    test_llm_parser.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output results as JSON.",
    )
    test_llm_parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour codes in output.",
    )
    test_llm_parser.add_argument(
        "--skip-l3",
        action="store_true",
        default=False,
        help="Skip L3 agent review test.",
    )
    test_llm_parser.add_argument("--env-file", type=Path, default=None, help="Explicit local env file for secrets/runtime values.")

    # --- l3 ---
    l3_parser = sub.add_parser(
        "l3",
        help="Operator-triggered L3 advisory actions.",
    )
    l3_sub = l3_parser.add_subparsers(dest="l3_command")
    l3_sub.required = True
    l3_full = l3_sub.add_parser(
        "full-review",
        help="Request a bounded advisory full review for one session.",
    )
    _l3_default_url = f"http://127.0.0.1:{os.environ.get('CS_HTTP_PORT', '8080')}"
    l3_full.add_argument("--gateway-url", default=_l3_default_url, help=f"Gateway base URL (default: {_l3_default_url}).")
    l3_full.add_argument("--token", default=os.environ.get("CS_AUTH_TOKEN"), help="Bearer token [CS_AUTH_TOKEN].")
    l3_full.add_argument("--session", required=True, dest="session_id", help="Session ID to review.")
    l3_full.add_argument("--trigger-event-id", default=None, help="Operator action/event ID.")
    l3_full.add_argument("--trigger-detail", default=None, help="Operator trigger detail.")
    l3_full.add_argument("--from-record-id", type=int, default=None, help="Optional frozen range start record ID.")
    l3_full.add_argument("--to-record-id", type=int, default=None, help="Optional frozen range end record ID.")
    l3_full.add_argument("--max-records", type=int, default=100, help="Maximum records to freeze (default: 100).")
    l3_full.add_argument("--max-tool-calls", type=int, default=0, help="Advisory evidence tool-call budget (default: 0).")
    l3_full.add_argument("--runner", default=None, choices=["llm_provider", "deterministic_local"], help="Optional runner to queue/execute (default: service llm_provider).")
    l3_full.add_argument("--queue-only", action="store_true", default=False, help="Freeze evidence and queue the job without running it.")
    l3_full.add_argument("--json", action="store_true", default=False, help="Output raw JSON.")
    l3_full.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout seconds (default: 30).")
    l3_jobs = l3_sub.add_parser(
        "jobs",
        help="List or explicitly run queued L3 advisory jobs.",
    )
    l3_jobs_sub = l3_jobs.add_subparsers(dest="l3_jobs_command")
    l3_jobs_sub.required = True
    l3_jobs_list = l3_jobs_sub.add_parser("list", help="List L3 advisory jobs.")
    l3_jobs_list.add_argument("--gateway-url", default=_l3_default_url, help=f"Gateway base URL (default: {_l3_default_url}).")
    l3_jobs_list.add_argument("--token", default=os.environ.get("CS_AUTH_TOKEN"), help="Bearer token [CS_AUTH_TOKEN].")
    l3_jobs_list.add_argument("--session", dest="session_id", default=None, help="Optional session ID filter.")
    l3_jobs_list.add_argument("--state", default="queued", choices=["queued", "running", "completed", "failed"], help="Job state filter (default: queued).")
    l3_jobs_list.add_argument("--runner", default=None, choices=["llm_provider", "deterministic_local"], help="Optional runner filter.")
    l3_jobs_list.add_argument("--json", action="store_true", default=False, help="Output raw JSON.")
    l3_jobs_list.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout seconds (default: 30).")
    l3_jobs_run_next = l3_jobs_sub.add_parser("run-next", help="Run the oldest queued L3 advisory job.")
    l3_jobs_run_next.add_argument("--gateway-url", default=_l3_default_url, help=f"Gateway base URL (default: {_l3_default_url}).")
    l3_jobs_run_next.add_argument("--token", default=os.environ.get("CS_AUTH_TOKEN"), help="Bearer token [CS_AUTH_TOKEN].")
    l3_jobs_run_next.add_argument("--runner", default="llm_provider", choices=["llm_provider", "deterministic_local"], help="Runner to execute (default: llm_provider).")
    l3_jobs_run_next.add_argument("--session", dest="session_id", default=None, help="Optional session ID filter.")
    l3_jobs_run_next.add_argument("--dry-run", action="store_true", default=False, help="Select without claiming/running.")
    l3_jobs_run_next.add_argument("--json", action="store_true", default=False, help="Output raw JSON.")
    l3_jobs_run_next.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout seconds (default: 30).")
    l3_jobs_drain = l3_jobs_sub.add_parser("drain", help="Run up to N queued L3 advisory jobs.")
    l3_jobs_drain.add_argument("--gateway-url", default=_l3_default_url, help=f"Gateway base URL (default: {_l3_default_url}).")
    l3_jobs_drain.add_argument("--token", default=os.environ.get("CS_AUTH_TOKEN"), help="Bearer token [CS_AUTH_TOKEN].")
    l3_jobs_drain.add_argument("--runner", default="llm_provider", choices=["llm_provider", "deterministic_local"], help="Runner to execute (default: llm_provider).")
    l3_jobs_drain.add_argument("--session", dest="session_id", default=None, help="Optional session ID filter.")
    l3_jobs_drain.add_argument("--max-jobs", type=int, default=1, help="Maximum queued jobs to run (1-10, default: 1).")
    l3_jobs_drain.add_argument("--dry-run", action="store_true", default=False, help="Select without claiming/running.")
    l3_jobs_drain.add_argument("--json", action="store_true", default=False, help="Output raw JSON.")
    l3_jobs_drain.add_argument("--timeout", type=float, default=30.0, help="HTTP timeout seconds (default: 30).")


    # --- benchmark ---
    benchmark_parser = sub.add_parser(
        "benchmark",
        help="Benchmark/autonomous no-human-defer helpers.",
    )
    benchmark_sub = benchmark_parser.add_subparsers(dest="benchmark_command")

    benchmark_env = benchmark_sub.add_parser("env", help="Print benchmark env vars.")
    benchmark_env.add_argument("--framework", default="codex", choices=["codex"])
    benchmark_env.add_argument("--mode", default="guarded", choices=["guarded", "permissive", "strict"])
    benchmark_env.add_argument("--output", type=Path, default=None)

    benchmark_enable = benchmark_sub.add_parser("enable", help="Persist benchmark env/hooks.")
    benchmark_enable.add_argument("--dir", type=Path, default=Path("."))
    benchmark_enable.add_argument("--framework", default="codex", choices=["codex"])
    benchmark_enable.add_argument("--mode", default="guarded", choices=["guarded", "permissive", "strict"])
    benchmark_enable.add_argument("--codex-home", type=Path, default=None)
    benchmark_enable.add_argument("--force-user-home", action="store_true", default=False)

    benchmark_disable = benchmark_sub.add_parser("disable", help="Remove benchmark env/hooks.")
    benchmark_disable.add_argument("--dir", type=Path, default=Path("."))
    benchmark_disable.add_argument("--framework", default="codex", choices=["codex"])
    benchmark_disable.add_argument("--codex-home", type=Path, default=None)
    benchmark_disable.add_argument("--force-user-home", action="store_true", default=False)

    benchmark_run = benchmark_sub.add_parser("run", help="Run a command with benchmark env.")
    benchmark_run.add_argument("--dir", type=Path, default=Path("."))
    benchmark_run.add_argument("--framework", default="codex", choices=["codex"])
    benchmark_run.add_argument("--mode", default="guarded", choices=["guarded", "permissive", "strict"])
    benchmark_run.add_argument("--codex-home", type=Path, default=None)
    benchmark_run.add_argument("--keep-artifacts", action="store_true", default=False)
    benchmark_run.add_argument("--force-user-home", action="store_true", default=False)
    benchmark_run.add_argument("benchmark_argv", nargs=argparse.REMAINDER)

    # --- service ---
    service_parser = sub.add_parser(
        "service",
        help="Manage auto-start system service (systemd/launchd).",
    )
    service_sub = service_parser.add_subparsers(dest="service_command")
    service_install = service_sub.add_parser("install", help="Install and enable auto-start service.")
    service_install.add_argument(
        "--no-enable",
        action="store_true",
        default=False,
        help="Install service file without enabling/starting.",
    )
    service_sub.add_parser("uninstall", help="Stop and remove auto-start service.")
    service_sub.add_parser("status", help="Show service status.")
    service_validate = service_sub.add_parser("validate", help="Validate service env/templates without host side effects.")
    service_validate.add_argument("--env-file", type=Path, default=None, help="Env file to validate.")

    # --- config ---
    config_parser = sub.add_parser(
        "config",
        help="Inspect and generate env-first ClawSentry configuration.",
    )
    config_parser.add_argument("--dir", type=Path, default=Path("."), help="Project directory (default: current directory).")
    config_sub = config_parser.add_subparsers(dest="config_command")

    config_init = config_sub.add_parser("init", help="Create an env-first template in current directory.")
    config_init.add_argument("--preset", default="medium", choices=["low", "medium", "high", "strict"])
    config_init.add_argument("--output", type=Path, default=None, help="Explicit env template path to write.")
    config_init.add_argument("--force", action="store_true", default=False)

    config_show = config_sub.add_parser("show", help="Show env-first effective config.")
    config_show.add_argument("--effective", action="store_true", default=False)
    config_show.add_argument("--env-file", type=Path, default=None, help="Explicit local env file for effective source resolution.")

    config_set = config_sub.add_parser("set", help="Print export instructions or update an explicit env file.")
    config_set.add_argument("key_or_preset")
    config_set.add_argument("value", nargs="?")
    config_set.add_argument("--env-file", type=Path, default=None, help="Explicit env file to update.")
    config_set.add_argument("--output", type=Path, default=None, help="Alias for --env-file for template/update workflows.")

    config_wizard = config_sub.add_parser("wizard", help="Guided ClawSentry configuration.")
    config_wizard.add_argument("--non-interactive", action="store_true", default=False)
    config_wizard.add_argument(
        "--interactive",
        action="store_true",
        default=None,
        help="Force the terminal question flow when stdin is a TTY.",
    )
    config_wizard.add_argument("--framework", default="codex")
    config_wizard.add_argument("--mode", default="normal", choices=["normal", "strict", "permissive", "benchmark"])
    config_wizard.add_argument("--llm-provider", default="", choices=["", "none", "openai", "anthropic"])
    config_wizard.add_argument("--llm-model", default="")
    config_wizard.add_argument("--llm-base-url", default="")
    config_wizard.add_argument("--l2", action=argparse.BooleanOptionalAction, default=None)
    config_wizard.add_argument("--l3", action=argparse.BooleanOptionalAction, default=False)
    config_wizard.add_argument("--token-budget", type=int, default=0)
    config_wizard.add_argument("--output", type=Path, default=None, help="Explicit env template path to write.")
    config_wizard.add_argument("--force", action="store_true", default=False)

    config_sub.add_parser("disable", help="Print env instruction to disable ClawSentry for a process.")
    config_sub.add_parser("enable", help="Print env instruction to enable ClawSentry for a process.")

    # --- rules ---
    rules_parser = sub.add_parser(
        "rules",
        help="Lint and dry-run rule authoring surfaces.",
    )
    rules_sub = rules_parser.add_subparsers(dest="rules_command")
    rules_sub.required = True

    rules_lint = rules_sub.add_parser("lint", help="Validate current rule surfaces.")
    rules_lint.add_argument("--attack-patterns", default=None, help="Path to attack patterns YAML.")
    rules_lint.add_argument("--evolved-patterns", default=None, help="Path to evolved patterns YAML.")
    rules_lint.add_argument("--skills-dir", default=None, help="Directory containing review skill YAML files.")
    rules_lint.add_argument("--json", action="store_true", default=False, help="Output lint report as JSON.")

    rules_dry_run = rules_sub.add_parser("dry-run", help="Dry-run rule matching against sample events.")
    rules_dry_run.add_argument("--events", required=True, help="JSON/JSONL file containing canonical sample events.")
    rules_dry_run.add_argument("--attack-patterns", default=None, help="Path to attack patterns YAML.")
    rules_dry_run.add_argument("--evolved-patterns", default=None, help="Path to evolved patterns YAML.")
    rules_dry_run.add_argument("--skills-dir", default=None, help="Directory containing review skill YAML files.")
    rules_dry_run.add_argument("--json", action="store_true", default=False, help="Output dry-run report as JSON.")

    rules_report = rules_sub.add_parser("report", help="Write a combined rule-governance CI report.")
    rules_report.add_argument("--output", required=True, help="Path to write the JSON report artifact.")
    rules_report.add_argument("--events", default=None, help="Optional JSON/JSONL file containing canonical sample events.")
    rules_report.add_argument("--attack-patterns", default=None, help="Path to attack patterns YAML.")
    rules_report.add_argument("--evolved-patterns", default=None, help="Path to evolved patterns YAML.")
    rules_report.add_argument("--skills-dir", default=None, help="Directory containing review skill YAML files.")
    rules_report.add_argument("--summary-markdown", default=None, help="Optional path to write a human-readable markdown dashboard.")
    rules_report.add_argument("--json", action="store_true", default=False, help="Also print report JSON to stdout.")

    # --- skill-trust ---
    skill_trust_parser = sub.add_parser(
        "skill-trust",
        help="Scan skill packages and update the Skill Trust registry.",
    )
    skill_trust_sub = skill_trust_parser.add_subparsers(dest="skill_trust_command")
    skill_trust_sub.required = True
    skill_trust_scan = skill_trust_sub.add_parser(
        "scan",
        help="Run deterministic admission scan for one local skill root.",
    )
    skill_trust_scan.add_argument("--skill-root", type=Path, required=True)
    skill_trust_scan.add_argument("--output", type=Path, default=None)
    skill_trust_scan.add_argument("--json", action="store_true", default=False)
    skill_trust_register = skill_trust_sub.add_parser(
        "register",
        help="Scan and persist a skill registry record plus transition event.",
    )
    skill_trust_register.add_argument("--skill-root", type=Path, required=True)
    skill_trust_register.add_argument("--registry", type=Path, required=True)
    skill_trust_register.add_argument("--framework", default="codex")
    skill_trust_register.add_argument(
        "--scope",
        default="workspace",
        choices=["workspace", "user_home", "project", "global"],
    )
    skill_trust_register.add_argument(
        "--list-state",
        default="auto",
        choices=["auto", "allowlist", "greylist", "blacklist"],
    )
    skill_trust_register.add_argument(
        "--operator-override",
        default=None,
        help="Operator review/override id required for allowlisting non-low-risk scans.",
    )
    skill_trust_register.add_argument("--json", action="store_true", default=False)
    skill_trust_register_dir = skill_trust_sub.add_parser(
        "register-dir",
        help="Scan a directory of skills and write Gateway registry plus runtime metadata.",
    )
    skill_trust_register_dir.add_argument("--skills-dir", type=Path, required=True)
    skill_trust_register_dir.add_argument("--registry", type=Path, required=True)
    skill_trust_register_dir.add_argument("--metadata", type=Path, required=True)
    skill_trust_register_dir.add_argument(
        "--allowed-runtime-parent",
        type=Path,
        action="append",
        default=[],
        help="Additional parent directory whose per-skill child roots may bind as runtime mirrors.",
    )
    skill_trust_register_dir.add_argument("--framework", default="codex")
    skill_trust_register_dir.add_argument(
        "--scope",
        default="workspace",
        choices=["workspace", "user_home", "project", "global"],
    )
    skill_trust_register_dir.add_argument("--json", action="store_true", default=False)
    skill_trust_transition = skill_trust_sub.add_parser(
        "transition",
        help="Apply an auditable operator lifecycle transition to one registry record.",
    )
    skill_trust_transition.add_argument("--registry", type=Path, required=True)
    skill_trust_transition.add_argument("--canonical-skill-id", required=True)
    skill_trust_transition.add_argument(
        "--target-state",
        required=True,
        choices=["allowlist", "greylist", "blacklist", "revoked", "disabled"],
    )
    skill_trust_transition.add_argument("--reason-code", required=True)
    skill_trust_transition.add_argument("--expected-registry-snapshot-id", required=True)
    skill_trust_transition.add_argument("--idempotency-key", required=True)
    skill_trust_transition.add_argument("--operator-id-hash", default=None)
    skill_trust_transition.add_argument("--override-id", default=None)
    skill_trust_transition.add_argument("--override-indefinite-reason", default=None)
    skill_trust_transition.add_argument("--expires-at", default=None)
    skill_trust_transition.add_argument("--disabled-until", default=None)
    skill_trust_transition.add_argument("--json", action="store_true", default=False)

    def _add_skill_trust_lifecycle_shortcut(
        name: str,
        *,
        help_text: str,
        restore: bool = False,
    ) -> None:
        shortcut = skill_trust_sub.add_parser(name, help=help_text)
        shortcut.add_argument("--registry", type=Path, required=True)
        shortcut.add_argument("--canonical-skill-id", required=True)
        shortcut.add_argument("--expected-registry-snapshot-id", required=True)
        shortcut.add_argument("--idempotency-key", required=True)
        shortcut.add_argument("--operator-id-hash", default=None)
        shortcut.add_argument("--override-id", default=None)
        shortcut.add_argument("--override-indefinite-reason", default=None)
        shortcut.add_argument("--expires-at", default=None)
        shortcut.add_argument("--disabled-until", default=None)
        if restore:
            shortcut.add_argument(
                "--restore-target-state",
                choices=["allowlist", "greylist", "blacklist", "unlisted"],
                default=None,
            )
        shortcut.add_argument("--json", action="store_true", default=False)

    _add_skill_trust_lifecycle_shortcut(
        "allowlist",
        help_text="Operator transition one skill to allowlist.",
    )
    _add_skill_trust_lifecycle_shortcut(
        "greylist",
        help_text="Operator transition one skill to greylist.",
    )
    _add_skill_trust_lifecycle_shortcut(
        "blacklist",
        help_text="Operator transition one skill to blacklist.",
    )
    _add_skill_trust_lifecycle_shortcut(
        "revoke",
        help_text="Operator revoke one skill identity.",
    )
    _add_skill_trust_lifecycle_shortcut(
        "disable",
        help_text="Operator disable one skill while preserving previous state.",
    )
    _add_skill_trust_lifecycle_shortcut(
        "restore",
        help_text="Operator restore a disabled skill to its previous or explicit active state.",
        restore=True,
    )
    _add_skill_trust_lifecycle_shortcut(
        "override",
        help_text="Operator override transition one skill to allowlist.",
    )

    # --- latch ---
    latch_parser = sub.add_parser(
        "latch",
        help="Manage Latch integration (install/uninstall/start/stop/status).",
    )
    latch_sub = latch_parser.add_subparsers(dest="latch_command")

    latch_install_parser = latch_sub.add_parser("install", help="Download and install Latch binary.")
    latch_install_parser.add_argument(
        "--no-shortcut",
        action="store_true",
        default=False,
        help="Skip desktop shortcut creation after install.",
    )

    _latch_default_gw_port = int(os.environ.get("CS_HTTP_PORT", "8080"))
    latch_start_parser = latch_sub.add_parser("start", help="Start Gateway + Latch Hub.")
    latch_start_parser.add_argument(
        "--gateway-port",
        type=int,
        default=_latch_default_gw_port,
        help=f"Gateway HTTP port (default: {_latch_default_gw_port}).",
    )
    latch_start_parser.add_argument(
        "--hub-port",
        type=int,
        default=3006,
        help="Latch Hub port (default: 3006).",
    )
    latch_start_parser.add_argument(
        "--no-browser",
        action="store_true",
        default=False,
        help="Don't open browser after start.",
    )

    latch_sub.add_parser("stop", help="Stop Gateway + Latch Hub.")
    latch_sub.add_parser("status", help="Show Latch stack status.")

    latch_uninstall_parser = latch_sub.add_parser("uninstall", help="Uninstall Latch binary and data.")
    latch_uninstall_parser.add_argument(
        "--keep-data",
        action="store_true",
        default=False,
        help="Keep data directories (only remove binary and shortcut).",
    )

    # --- integrations ---
    integrations_parser = sub.add_parser(
        "integrations",
        help="Inspect configured framework integrations.",
    )
    integrations_sub = integrations_parser.add_subparsers(dest="integrations_command")
    integrations_status = integrations_sub.add_parser(
        "status",
        help="Show enabled framework integrations.",
    )
    integrations_status.add_argument(
        "--dir",
        type=Path,
        default=Path("."),
        help="Project directory for framework-side readiness checks (default: current dir).",
    )
    integrations_status.add_argument(
        "--json",
        action="store_true",
        default=False,
        help="Output status as JSON.",
    )
    integrations_status.add_argument("--env-file", type=Path, default=None, help="Explicit local env file for readiness checks.")

    # --- start ---
    start_parser = sub.add_parser(
        "start",
        help="One-command launch: auto-init + gateway (background) + watch (foreground).",
    )
    start_parser.add_argument(
        "--framework",
        choices=sorted(FRAMEWORK_INITIALIZERS.keys()),
        default=None,
        help="Target framework (auto-detected if omitted).",
    )
    start_parser.add_argument(
        "--frameworks",
        default=None,
        help=(
            "Comma-separated frameworks to enable together "
            "(for example: a3s-code,codex,openclaw)."
        ),
    )
    start_parser.add_argument(
        "--setup-openclaw",
        action=argparse.BooleanOptionalAction,
        default=False,
        help=(
            "When OpenClaw is enabled, also update ~/.openclaw/ for "
            "gateway exec approvals (default: off)."
        ),
    )
    start_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Gateway bind host (default: 127.0.0.1).",
    )
    start_parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("CS_HTTP_PORT", "8080")),
        help="Gateway HTTP port (default: 8080 or CS_HTTP_PORT).",
    )
    start_parser.add_argument(
        "--no-watch",
        action="store_true",
        default=False,
        help="Start gateway in background only, without watch.",
    )
    start_parser.add_argument(
        "--interactive",
        "-i",
        action="store_true",
        default=False,
        help="Enable interactive DEFER handling in watch.",
    )
    start_parser.add_argument(
        "--open-browser",
        action="store_true",
        default=False,
        help="Open the Web UI in a browser after gateway starts.",
    )
    start_parser.add_argument(
        "--with-latch",
        action="store_true",
        default=False,
        help="Start with Latch Hub (requires 'clawsentry latch install' first).",
    )
    start_parser.add_argument(
        "--hub-port",
        type=int,
        default=3006,
        help="Latch Hub port (default: 3006). Only used with --with-latch.",
    )
    start_parser.add_argument("--env-file", type=Path, default=None, help="Explicit local env file for secrets/runtime values.")

    # --- stop ---
    sub.add_parser("stop", help="Stop running gateway.")

    # --- status ---
    sub.add_parser("status", help="Check gateway status.")

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args, remaining = parser.parse_known_args(argv)

    if args.command is None:
        parser.print_help()
        return
    if remaining and args.command not in {"gateway", "stack", "harness"}:
        parser.error(f"unrecognized arguments: {' '.join(remaining)}")

    if args.command == "init":
        # Handle --restore for openclaw
        if getattr(args, "restore", False):
            if args.framework == "openclaw":
                from .initializers.openclaw import OpenClawInitializer
                init = OpenClawInitializer()
                result = init.restore_openclaw_config(
                    openclaw_home=getattr(args, "openclaw_home", None),
                    dry_run=getattr(args, "dry_run", False),
                )
                if result.dry_run:
                    print("  [DRY RUN] The following restore changes would be applied:")
                else:
                    print("  OpenClaw configuration restore:")
                for change in result.changes_applied:
                    print(f"    - {change}")
                for w in result.warnings:
                    print(f"  WARNING: {w}")
                sys.exit(0)
            else:
                print(f"--restore is only supported for openclaw, got: {args.framework}", file=sys.stderr)
                sys.exit(1)

        # Handle --uninstall for framework env/hooks
        if getattr(args, "uninstall", False):
            from .init_command import run_uninstall
            code = run_uninstall(
                framework=args.framework,
                target_dir=args.dir,
                codex_home=getattr(args, "codex_home", None),
                gemini_home=getattr(args, "gemini_home", None),
                kimi_home=getattr(args, "kimi_home", None),
            )
            sys.exit(code)

        from .init_command import run_init

        code = run_init(
            framework=args.framework,
            target_dir=args.dir,
            force=args.force,
            auto_detect=getattr(args, "auto_detect", False),
            setup=getattr(args, "setup", False),
            dry_run=getattr(args, "dry_run", False),
            hardened_profile=getattr(args, "hardened_profile", False),
            openclaw_home=getattr(args, "openclaw_home", None),
            codex_home=getattr(args, "codex_home", None),
            gemini_home=getattr(args, "gemini_home", None),
            kimi_home=getattr(args, "kimi_home", None),
        )
        sys.exit(code)

    elif args.command == "gateway":
        from ..gateway.stack import main as stack_main
        # Replace sys.argv so the delegated main() can re-parse its own flags
        sys.argv = ["clawsentry-gateway"] + remaining
        stack_main()

    elif args.command == "stack":
        from ..gateway.stack import main as stack_main
        sys.argv = ["clawsentry-stack"] + remaining
        stack_main()

    elif args.command == "harness":
        from ..adapters.a3s_gateway_harness import main as harness_main
        sys.argv = ["clawsentry-harness"] + remaining
        harness_main()

    elif args.command == "watch":
        from .watch_command import run_watch

        run_watch(
            gateway_url=args.gateway_url,
            token=args.token,
            filter_types=args.filter,
            priority_only=args.priority_only,
            json_mode=args.json,
            color=not args.no_color,
            interactive=args.interactive,
            verbose=args.verbose,
            no_emoji=args.no_emoji,
            compact=args.compact,
        )

    elif args.command == "scope":
        from .scope_command import run_scope_preview, run_scope_validate

        if args.scope_command == "validate":
            code = run_scope_validate(
                profile_path=args.profile,
                json_mode=args.json,
            )
            sys.exit(code)
        if args.scope_command == "preview":
            code = run_scope_preview(
                profile_path=args.profile,
                event_path=args.event,
                confirm=args.confirm,
                json_mode=args.json,
            )
            sys.exit(code)
        parser.error("scope requires a subcommand")

    elif args.command == "audit":
        from .audit_command import run_audit

        code = run_audit(
            db_path=args.db,
            session_id=args.session,
            since=args.since,
            risk=args.risk,
            decision=args.decision,
            tool=args.tool,
            fmt=args.output_format,
            stats_mode=args.stats,
            limit=args.limit,
            color=not args.no_color,
        )
        sys.exit(code)

    elif args.command == "doctor":
        from .doctor_command import run_doctor

        code = run_doctor(
            json_mode=args.json,
            color=not args.no_color,
            env_file=args.env_file,
        )
        sys.exit(code)

    elif args.command == "test-llm":
        from .test_llm_command import run_test_llm

        code = run_test_llm(
            color=not args.no_color,
            skip_l3=args.skip_l3,
            json_mode=args.json,
            env_file=args.env_file,
        )
        sys.exit(code)

    elif args.command == "l3":
        from .l3_command import (
            run_l3_full_review,
            run_l3_jobs_drain,
            run_l3_jobs_list,
            run_l3_jobs_run_next,
        )

        if args.l3_command == "full-review":
            sys.exit(run_l3_full_review(
                gateway_url=args.gateway_url,
                token=args.token,
                session_id=args.session_id,
                trigger_event_id=args.trigger_event_id,
                trigger_detail=args.trigger_detail,
                from_record_id=args.from_record_id,
                to_record_id=args.to_record_id,
                max_records=args.max_records,
                max_tool_calls=args.max_tool_calls,
                runner=args.runner,
                queue_only=args.queue_only,
                json_mode=args.json,
                timeout=args.timeout,
            ))
        if args.l3_command == "jobs":
            if args.l3_jobs_command == "list":
                sys.exit(run_l3_jobs_list(
                    gateway_url=args.gateway_url,
                    token=args.token,
                    session_id=args.session_id,
                    state=args.state,
                    runner=args.runner,
                    json_mode=args.json,
                    timeout=args.timeout,
                ))
            if args.l3_jobs_command == "run-next":
                sys.exit(run_l3_jobs_run_next(
                    gateway_url=args.gateway_url,
                    token=args.token,
                    runner=args.runner,
                    session_id=args.session_id,
                    dry_run=args.dry_run,
                    json_mode=args.json,
                    timeout=args.timeout,
                ))
            if args.l3_jobs_command == "drain":
                sys.exit(run_l3_jobs_drain(
                    gateway_url=args.gateway_url,
                    token=args.token,
                    runner=args.runner,
                    session_id=args.session_id,
                    max_jobs=args.max_jobs,
                    dry_run=args.dry_run,
                    json_mode=args.json,
                    timeout=args.timeout,
                ))
        print("Usage: clawsentry l3 {full-review,jobs}")


    elif args.command == "benchmark":
        from .benchmark_command import (
            run_benchmark_disable,
            run_benchmark_enable,
            run_benchmark_env,
            run_benchmark_run,
        )

        try:
            if args.benchmark_command == "env":
                sys.exit(run_benchmark_env(
                    framework=args.framework,
                    mode=args.mode,
                    output_path=args.output,
                ))
            if args.benchmark_command == "enable":
                sys.exit(run_benchmark_enable(
                    target_dir=args.dir,
                    framework=args.framework,
                    mode=args.mode,
                    codex_home=args.codex_home,
                    force_user_home=args.force_user_home,
                ))
            if args.benchmark_command == "disable":
                sys.exit(run_benchmark_disable(
                    target_dir=args.dir,
                    framework=args.framework,
                    codex_home=args.codex_home,
                    force_user_home=args.force_user_home,
                ))
            if args.benchmark_command == "run":
                sys.exit(run_benchmark_run(
                    command=args.benchmark_argv,
                    target_dir=args.dir,
                    framework=args.framework,
                    mode=args.mode,
                    codex_home=args.codex_home,
                    keep_artifacts=args.keep_artifacts,
                    force_user_home=args.force_user_home,
                ))
            print("Usage: clawsentry benchmark {env,enable,disable,run}")
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            sys.exit(2)

    elif args.command == "service":
        from .service_command import (
            run_service_install, run_service_uninstall, run_service_status,
            run_service_validate,
        )
        if args.service_command == "install":
            sys.exit(run_service_install(no_enable=args.no_enable))
        elif args.service_command == "uninstall":
            sys.exit(run_service_uninstall())
        elif args.service_command == "status":
            sys.exit(run_service_status())
        elif args.service_command == "validate":
            from .service_command import run_service_validate
            sys.exit(run_service_validate(env_file=args.env_file))
        else:
            print("Usage: clawsentry service {install,uninstall,status,validate}")

    elif args.command == "config":
        from .config_command import (
            run_config_init, run_config_show, run_config_set,
            run_config_disable, run_config_enable, run_config_wizard,
        )
        target = args.dir
        if args.config_command == "init":
            run_config_init(target_dir=target, preset=args.preset, force=args.force, output=args.output)
        elif args.config_command == "show":
            run_config_show(target_dir=target, effective=args.effective, env_file=args.env_file)
        elif args.config_command == "set":
            if args.value is None:
                run_config_set(target_dir=target, preset=args.key_or_preset, env_file=args.env_file, output=args.output)
            else:
                run_config_set(target_dir=target, key=args.key_or_preset, value=args.value, env_file=args.env_file, output=args.output)
        elif args.config_command == "wizard":
            run_config_wizard(
                target_dir=target,
                non_interactive=args.non_interactive,
                interactive=args.interactive,
                framework=args.framework,
                mode=args.mode,
                llm_provider=args.llm_provider,
                llm_model=args.llm_model,
                llm_base_url=args.llm_base_url,
                l2=args.l2,
                l3=args.l3,
                token_budget=args.token_budget,
                force=args.force,
                output=args.output,
            )
        elif args.config_command == "disable":
            run_config_disable(target_dir=target)
        elif args.config_command == "enable":
            run_config_enable(target_dir=target)
        else:
            print("Usage: clawsentry config {init,show,set,wizard,disable,enable}")

    elif args.command == "rules":
        from .rules_command import run_rules_dry_run, run_rules_lint, run_rules_report

        if args.rules_command == "lint":
            sys.exit(
                run_rules_lint(
                    patterns_path=args.attack_patterns,
                    evolved_patterns_path=args.evolved_patterns,
                    skills_dir=args.skills_dir,
                    as_json=args.json,
                )
            )
        elif args.rules_command == "dry-run":
            sys.exit(
                run_rules_dry_run(
                    events_path=args.events,
                    patterns_path=args.attack_patterns,
                    evolved_patterns_path=args.evolved_patterns,
                    skills_dir=args.skills_dir,
                    as_json=args.json,
                )
            )
        elif args.rules_command == "report":
            sys.exit(
                run_rules_report(
                    output_path=args.output,
                    events_path=args.events,
                    patterns_path=args.attack_patterns,
                    evolved_patterns_path=args.evolved_patterns,
                    skills_dir=args.skills_dir,
                    summary_markdown_path=args.summary_markdown,
                    as_json=args.json,
                )
            )

    elif args.command == "skill-trust":
        from .skill_trust_command import run_skill_trust_command

        sys.exit(run_skill_trust_command(args))

    elif args.command == "latch":
        from .latch_command import (
            run_latch_install, run_latch_start, run_latch_stop, run_latch_status,
            run_latch_uninstall,
        )
        if args.latch_command == "install":
            sys.exit(run_latch_install(no_shortcut=args.no_shortcut))
        elif args.latch_command == "uninstall":
            sys.exit(run_latch_uninstall(keep_data=args.keep_data))
        elif args.latch_command == "start":
            sys.exit(run_latch_start(
                gateway_port=args.gateway_port,
                hub_port=args.hub_port,
                no_browser=args.no_browser,
            ))
        elif args.latch_command == "stop":
            sys.exit(run_latch_stop())
        elif args.latch_command == "status":
            sys.exit(run_latch_status())
        else:
            print("Usage: clawsentry latch {install,uninstall,start,stop,status}")

    elif args.command == "integrations":
        from .integrations_command import run_integrations_status

        if args.integrations_command == "status":
            sys.exit(run_integrations_status(
                target_dir=args.dir,
                json_mode=args.json,
                env_file=args.env_file,
            ))
        print("Usage: clawsentry integrations {status}")

    elif args.command == "start":
        from .start_command import detect_framework, run_start

        framework = args.framework
        enabled_frameworks = None
        if args.frameworks:
            enabled_frameworks = [
                item.strip() for item in args.frameworks.split(",") if item.strip()
            ]
            unknown = [
                item for item in enabled_frameworks
                if item not in FRAMEWORK_INITIALIZERS
            ]
            if unknown:
                print(
                    f"Unknown framework(s): {', '.join(unknown)}",
                    file=sys.stderr,
                )
                sys.exit(1)
            if not enabled_frameworks:
                print("--frameworks requires at least one framework.", file=sys.stderr)
                sys.exit(1)
            if framework is None:
                framework = enabled_frameworks[0]

        auto_detected = False
        if framework is None:
            from .dotenv_loader import (
                EnvFileError,
                discover_local_env_files,
                format_env_file_hint,
                overlay_env_file,
                resolve_explicit_env_file,
            )
            try:
                parsed_start_env = resolve_explicit_env_file(
                    cli_env_file=args.env_file,
                    environ=os.environ,
                )
            except EnvFileError as exc:
                print(str(exc), file=sys.stderr)
                sys.exit(2)
            framework = detect_framework(env_values=overlay_env_file(os.environ, parsed_start_env))
            if framework is None:
                for line in format_env_file_hint(discover_local_env_files()):
                    print(line, file=sys.stderr)
                print(
                    "Could not auto-detect framework.\n"
                    "Use: clawsentry start --framework <a3s-code|claude-code|codex|gemini-cli|kimi-cli|openclaw>",
                    file=sys.stderr,
                )
                sys.exit(1)
            auto_detected = True

        run_start(
            framework=framework,
            host=args.host,
            port=args.port,
            no_watch=args.no_watch,
            interactive=args.interactive,
            setup_openclaw=args.setup_openclaw,
            open_browser=args.open_browser,
            with_latch=args.with_latch,
            hub_port=args.hub_port,
            auto_detected=auto_detected,
            enabled_frameworks=enabled_frameworks,
            env_file=args.env_file,
        )

    elif args.command == "stop":
        from .start_command import run_stop
        run_stop()

    elif args.command == "status":
        from .start_command import run_status
        run_status()


if __name__ == "__main__":
    main()
