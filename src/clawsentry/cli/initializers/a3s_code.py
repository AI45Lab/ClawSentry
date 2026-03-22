"""a3s-code framework initializer."""

from __future__ import annotations

import json
import secrets
from pathlib import Path

from .base import ENV_FILE_NAME, InitResult


class A3SCodeInitializer:
    """Generate configuration for a3s-code integration."""

    framework_name: str = "a3s-code"

    def generate_config(
        self, target_dir: Path, *, force: bool = False, **_kwargs: object
    ) -> InitResult:
        env_path = target_dir / ENV_FILE_NAME
        settings_dir = target_dir / ".a3s-code"
        settings_path = settings_dir / "settings.json"
        warnings: list[str] = []
        files_created: list[Path] = []

        if env_path.exists() and not force:
            raise FileExistsError(
                f"{env_path} already exists. Use --force to overwrite."
            )
        if env_path.exists() and force:
            warnings.append(f"Overwriting existing {env_path}")

        token = secrets.token_urlsafe(32)
        env_vars = {
            "CS_UDS_PATH": "/tmp/clawsentry.sock",
            "CS_AUTH_TOKEN": token,
        }

        lines = ["# ClawSentry — a3s-code integration config"]
        for key, val in env_vars.items():
            lines.append(f"{key}={val}")
        lines.append("")
        env_path.write_text("\n".join(lines))
        env_path.chmod(0o600)  # tokens are sensitive
        files_created.append(env_path)

        # Generate .a3s-code/settings.json with HTTP hooks (token embedded in URL)
        # ?token= is supported by all Gateway endpoints via _make_auth_dependency
        if not settings_path.exists() or force:
            settings_dir.mkdir(parents=True, exist_ok=True)
            gateway_url = f"http://127.0.0.1:8080/ahp/a3s?token={token}"
            settings = {
                "hooks": {
                    "PreToolUse": [{"type": "http", "url": gateway_url}],
                    "PostToolUse": [{"type": "http", "url": gateway_url}],
                }
            }
            settings_path.write_text(json.dumps(settings, indent=2) + "\n")
            files_created.append(settings_path)
        else:
            warnings.append(
                f"{settings_path} already exists, skipping (use --force to overwrite)"
            )

        next_steps = [
            f"source {ENV_FILE_NAME}",
            "clawsentry gateway    # starts on UDS + HTTP port 8080",
            "python your_agent_script.py    # .a3s-code/settings.json auto-loaded",
            "clawsentry watch --token \"$CS_AUTH_TOKEN\"    # real-time monitoring",
        ]

        return InitResult(
            files_created=files_created,
            env_vars=env_vars,
            next_steps=next_steps,
            warnings=warnings,
        )
