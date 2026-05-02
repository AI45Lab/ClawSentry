"""OpenClaw framework initializer."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from .base import LOCAL_ENV_FILE_EXAMPLE, InitResult, SetupResult, merge_project_framework_config

_DEFAULT_WS_PORT = 18789
HARDENED_MARKER = "clawsentry.hardened_profile.v1"
HARDENED_NATIVE_DENY_TOOLS = ("exec", "write", "edit", "apply_patch", "process")
HARDENED_WRAPPER_TOOLS = (
    "cs_execute_command",
    "cs_read_file",
    "cs_write_file",
    "cs_http_request",
)


class OpenClawInitializer:
    """Generate configuration for OpenClaw integration."""

    framework_name: str = "openclaw"

    # ------------------------------------------------------------------
    # Auto-detect helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_openclaw_config(
        openclaw_home: Path,
    ) -> tuple[dict, list[str]]:
        """Read and parse openclaw.json. Returns (config_dict, warnings)."""
        config_path = openclaw_home / "openclaw.json"
        warnings: list[str] = []
        if not config_path.exists():
            warnings.append(
                f"OpenClaw config not found at {config_path}; "
                "using empty defaults. "
                "Run OpenClaw at least once to generate the config."
            )
            return {}, warnings

        try:
            config = json.loads(config_path.read_text())
        except (json.JSONDecodeError, OSError) as exc:
            warnings.append(
                f"Failed to parse {config_path}: {exc}; using empty defaults."
            )
            return {}, warnings

        return config, warnings

    @staticmethod
    def _extract_auto_values(
        config: dict,
    ) -> tuple[str, int, list[str]]:
        """Extract token, port, and warnings from a parsed openclaw config.

        Returns (token, port, warnings).
        """
        warnings: list[str] = []

        # gateway.auth.token
        token = (
            config.get("gateway", {}).get("auth", {}).get("token", "")
        )

        # gateway.port (default 18789)
        port = config.get("gateway", {}).get("port", _DEFAULT_WS_PORT)

        # tools.exec.host check
        exec_host = (
            config.get("tools", {}).get("exec", {}).get("host", "")
        )
        if exec_host != "gateway":
            warnings.append(
                'tools.exec.host is not set to "gateway" in openclaw.json. '
                "Exec-approval events will NOT be broadcast over WebSocket. "
                'Set "tools": {"exec": {"host": "gateway"}} to enable enforcement.'
            )

        return token, port, warnings

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def generate_config(
        self,
        target_dir: Path,
        *,
        force: bool = False,
        auto_detect: bool = False,
        openclaw_home: Path | None = None,
    ) -> InitResult:
        warnings: list[str] = []

        # --- defaults ---
        token = ""
        ws_port = _DEFAULT_WS_PORT
        enforcement_enabled = "false"

        # --- auto-detect from ~/.openclaw/openclaw.json ---
        if auto_detect:
            home = openclaw_home or Path.home() / ".openclaw"
            config, read_warnings = self._read_openclaw_config(home)
            warnings.extend(read_warnings)

            if config:
                token, ws_port, extract_warnings = self._extract_auto_values(config)
                warnings.extend(extract_warnings)
                if token:
                    enforcement_enabled = "true"

        _, env_vars = merge_project_framework_config(
            target_dir,
            framework=self.framework_name,
            force=force,
        )
        env_vars.update({
            "OPENCLAW_WEBHOOK_TOKEN": secrets.token_urlsafe(32),
            "CS_HTTP_PORT": "8080",
            "OPENCLAW_WEBHOOK_PORT": "8081",
            # Enforcement (WebSocket approval callback)
            "OPENCLAW_ENFORCEMENT_ENABLED": enforcement_enabled,
            "OPENCLAW_WS_URL": f"ws://127.0.0.1:{ws_port}",
            "OPENCLAW_OPERATOR_TOKEN": token,
        })

        next_steps = [
            f"Put OpenClaw secrets in process env or pass --env-file {LOCAL_ENV_FILE_EXAMPLE}",
            "clawsentry stack",
            (
                "Configure OpenClaw webhook URL:\n"
                "  http://127.0.0.1:8081/webhook/openclaw"
            ),
            (
                "For enforcement mode (active blocking), install extras and configure:\n"
                '  pip install "clawsentry[enforcement]"\n'
                "  export OPENCLAW_ENFORCEMENT_ENABLED=true\n"
                "  export OPENCLAW_OPERATOR_TOKEN=<token from ~/.openclaw/openclaw.json>"
            ),
            (
                "Required OpenClaw-side configuration (in ~/.openclaw/):\n"
                '  openclaw.json: set "tools": {"exec": {"host": "gateway"}}\n'
                '  exec-approvals.json: set "security": "allowlist", "ask": "always"'
            ),
            "clawsentry watch    # real-time terminal monitoring",
        ]

        return InitResult(
            files_created=[],
            env_vars=env_vars,
            next_steps=next_steps,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # OpenClaw auto-setup (--setup)
    # ------------------------------------------------------------------

    def setup_openclaw_config(
        self,
        *,
        openclaw_home: Path | None = None,
        dry_run: bool = False,
        hardened_profile: bool = False,
    ) -> SetupResult:
        """Auto-configure OpenClaw files for Monitor integration.

        Modifies ``~/.openclaw/openclaw.json`` and ``exec-approvals.json``
        to enable exec-approval event broadcasting over WebSocket.

        When *dry_run* is True the files are left untouched and the
        returned :class:`SetupResult` describes what *would* change.
        """
        home = openclaw_home or Path.home() / ".openclaw"
        changes: list[str] = []
        files_modified: list[Path] = []
        files_backed_up: list[Path] = []
        warnings: list[str] = []

        if not home.exists():
            warnings.append(
                f"OpenClaw directory not found at {home}. "
                "Run OpenClaw at least once to generate the config directory."
            )
            return SetupResult(
                changes_applied=changes,
                files_modified=files_modified,
                files_backed_up=files_backed_up,
                warnings=warnings,
                dry_run=dry_run,
            )

        # --- openclaw.json ---
        oc_modified = self._setup_openclaw_json(
            home, changes=changes, dry_run=dry_run,
        )
        if oc_modified:
            files_modified.append(oc_modified)
            bak = home / "openclaw.json.bak"
            if bak.exists():
                files_backed_up.append(bak)

        # --- exec-approvals.json ---
        ea_modified = self._setup_exec_approvals(
            home, changes=changes, dry_run=dry_run,
        )
        if ea_modified:
            files_modified.append(ea_modified)
            bak = home / "exec-approvals.json.bak"
            if bak.exists():
                files_backed_up.append(bak)

        # --- optional hardened profile ---
        if hardened_profile:
            hp_modified = self._setup_hardened_profile(
                home, changes=changes, dry_run=dry_run,
            )
            if hp_modified:
                files_modified.append(hp_modified)
                bak = home / "openclaw.json.bak"
                if bak.exists() and bak not in files_backed_up:
                    files_backed_up.append(bak)

        # If nothing was modified, inform the user
        if not files_modified and not dry_run:
            changes.append("All OpenClaw settings already configured correctly.")

        return SetupResult(
            changes_applied=changes,
            files_modified=files_modified,
            files_backed_up=files_backed_up,
            warnings=warnings,
            dry_run=dry_run,
        )

    def restore_openclaw_config(
        self,
        *,
        openclaw_home: Path | None = None,
        dry_run: bool = False,
    ) -> SetupResult:
        """Restore OpenClaw config files from the .bak files created by setup."""
        home = openclaw_home or Path.home() / ".openclaw"
        changes: list[str] = []
        files_modified: list[Path] = []
        files_backed_up: list[Path] = []
        warnings: list[str] = []

        if not home.exists():
            warnings.append(
                f"OpenClaw directory not found at {home}. Nothing to restore."
            )
            return SetupResult(
                changes_applied=changes,
                files_modified=files_modified,
                files_backed_up=files_backed_up,
                warnings=warnings,
                dry_run=dry_run,
            )

        restore_pairs = (
            (home / "openclaw.json.bak", home / "openclaw.json"),
            (home / "exec-approvals.json.bak", home / "exec-approvals.json"),
        )
        for backup_path, target_path in restore_pairs:
            if not backup_path.exists():
                warnings.append(f"Backup not found: {backup_path}")
                continue

            if dry_run:
                changes.append(f"Would restore {target_path.name} from {backup_path.name}.")
                continue

            target_path.write_text(backup_path.read_text())
            files_modified.append(target_path)
            files_backed_up.append(backup_path)
            changes.append(f"Restored {target_path.name} from {backup_path.name}.")

        if not files_modified and not dry_run and not changes:
            changes.append("No OpenClaw backup files were restored.")

        return SetupResult(
            changes_applied=changes,
            files_modified=files_modified,
            files_backed_up=files_backed_up,
            warnings=warnings,
            dry_run=dry_run,
        )

    # ------------------------------------------------------------------
    # Setup helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _backup_once(path: Path) -> None:
        """Create ``<name>.bak`` once so restore keeps the original config."""

        if not path.exists():
            return
        bak_path = path.with_name(path.name + ".bak")
        if not bak_path.exists():
            bak_path.write_text(path.read_text())

    @staticmethod
    def _setup_openclaw_json(
        openclaw_home: Path,
        *,
        changes: list[str],
        dry_run: bool,
    ) -> Path | None:
        """Ensure ``tools.exec.host`` is ``"gateway"``.

        Returns the path if the file was modified, or None if no change
        was needed.
        """
        config_path = openclaw_home / "openclaw.json"
        config: dict = {}
        if config_path.exists():
            try:
                config = json.loads(config_path.read_text())
            except (json.JSONDecodeError, OSError):
                config = {}

        exec_host = (
            config.get("tools", {}).get("exec", {}).get("host", "")
        )

        if exec_host == "gateway":
            changes.append(
                'openclaw.json: tools.exec.host already configured as "gateway".'
            )
            return None

        # Need to set tools.exec.host = "gateway"
        changes.append(
            'openclaw.json: set tools.exec.host = "gateway" '
            "(enables exec-approval event broadcasting)."
        )

        if dry_run:
            return None

        # Backup
        OpenClawInitializer._backup_once(config_path)

        # Deep-set tools.exec.host
        config.setdefault("tools", {}).setdefault("exec", {})["host"] = "gateway"
        config_path.write_text(json.dumps(config, indent=2))
        return config_path

    @staticmethod
    def _setup_hardened_profile(
        openclaw_home: Path,
        *,
        changes: list[str],
        dry_run: bool,
    ) -> Path | None:
        """Enable marker-managed optional native deny/wrapper hardening."""

        config_path = openclaw_home / "openclaw.json"
        config: dict = {}
        if config_path.exists():
            try:
                config = json.loads(config_path.read_text())
            except (json.JSONDecodeError, OSError):
                config = {}

        existing = (config.get("clawsentry", {}) or {}).get("hardened_profile", {})
        if isinstance(existing, dict) and existing.get("marker") == HARDENED_MARKER:
            changes.append("openclaw.json: hardened profile already marker-managed.")
            return None

        changes.append(
            "openclaw.json: enable ClawSentry hardened profile "
            f"(marker {HARDENED_MARKER}; deny native tools: "
            f"{', '.join(HARDENED_NATIVE_DENY_TOOLS)}; wrappers: "
            f"{', '.join(HARDENED_WRAPPER_TOOLS)})."
        )
        if dry_run:
            return None

        OpenClawInitializer._backup_once(config_path)
        native_tools = config.setdefault("tools", {}).setdefault("native", {})
        existing_deny = native_tools.get("deny") or []
        if not isinstance(existing_deny, list):
            existing_deny = []
        combined_deny = list(dict.fromkeys([*existing_deny, *HARDENED_NATIVE_DENY_TOOLS]))
        native_tools["deny"] = combined_deny
        config.setdefault("clawsentry", {})["hardened_profile"] = {
            "marker": HARDENED_MARKER,
            "enabled": True,
            "mode": "ahp_mediated_wrappers",
            "native_tool_policy": {"deny": combined_deny},
            "wrappers": [
                {
                    "name": name,
                    "policy": "forward_to_clawsentry_ahp_gateway",
                    "enforcement_claim": "adapter_capability_required",
                }
                for name in HARDENED_WRAPPER_TOOLS
            ],
            "reversible": True,
        }
        config_path.write_text(json.dumps(config, indent=2))
        return config_path

    @staticmethod
    def _setup_exec_approvals(
        openclaw_home: Path,
        *,
        changes: list[str],
        dry_run: bool,
    ) -> Path | None:
        """Ensure ``security`` is ``"allowlist"`` and ``ask`` is ``"always"``.

        Returns the path if the file was modified, or None if no change
        was needed.
        """
        ea_path = openclaw_home / "exec-approvals.json"
        config: dict = {}
        existed = ea_path.exists()
        if existed:
            try:
                config = json.loads(ea_path.read_text())
            except (json.JSONDecodeError, OSError):
                config = {}

        need_security = config.get("security") != "allowlist"
        need_ask = config.get("ask") != "always"

        if not need_security and not need_ask:
            changes.append(
                "exec-approvals.json: security and ask already configured correctly."
            )
            return None

        if need_security:
            changes.append(
                'exec-approvals.json: set security = "allowlist" '
                "(all commands enter approval flow)."
            )
        if need_ask:
            changes.append(
                'exec-approvals.json: set ask = "always" '
                "(always prompt for approval)."
            )

        if dry_run:
            return None

        # Backup (only if file existed)
        if existed:
            OpenClawInitializer._backup_once(ea_path)

        # Apply changes
        if need_security:
            config["security"] = "allowlist"
        if need_ask:
            config["ask"] = "always"

        ea_path.write_text(json.dumps(config, indent=2))
        return ea_path
