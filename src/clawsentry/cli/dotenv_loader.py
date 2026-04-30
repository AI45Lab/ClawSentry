"""Explicit env-file parsing for ClawSentry.

ClawSentry no longer implicitly discovers legacy env files.  Env files are a
local-secret convenience only when a user explicitly passes ``--env-file`` or
sets ``CLAWSENTRY_ENV_FILE``.  Parsing is intentionally non-mutating: callers
receive an isolated mapping and provenance, then decide how to pass those
values to child processes or compatibility adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, MutableMapping

ENV_FILE_NAME = ".env.clawsentry"
LOCAL_ENV_FILE_NAME = ".clawsentry.env.local"
ENV_TEMPLATE_NAME = ".clawsentry.env.example"
EXPLICIT_ENV_FILE_ENV = "CLAWSENTRY_ENV_FILE"


class EnvFileError(RuntimeError):
    """Raised when an explicitly requested env file cannot be loaded."""


@dataclass(frozen=True)
class EnvFileDiscovery:
    """Non-loading local env-file discovery result for UX hints."""

    local: Path | None = None
    legacy: Path | None = None
    template: Path | None = None

    @property
    def has_hint(self) -> bool:
        return self.local is not None or self.legacy is not None or self.template is not None

    @property
    def preferred_runtime_file(self) -> Path | None:
        return self.local or self.legacy


@dataclass(frozen=True)
class EnvFileValue:
    """Single parsed env-file value with source provenance."""

    value: str
    path: Path
    line: int

    @property
    def source_detail(self) -> str:
        return f"{self.path}:{self.line}"


@dataclass(frozen=True)
class ParsedEnvFile:
    """Isolated env-file parse result."""

    path: Path | None
    values: dict[str, str] = field(default_factory=dict)
    provenance: dict[str, EnvFileValue] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def source_detail_for(self, key: str) -> str | None:
        item = self.provenance.get(key)
        return item.source_detail if item else None


def _strip_env_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def parse_env_file(path: Path) -> ParsedEnvFile:
    """Parse a dotenv-style file into isolated values and provenance.

    The parser supports simple ``KEY=VALUE`` lines, comments, blank lines, and
    surrounding single/double quotes.  It never mutates ``os.environ``.
    """
    env_path = path.expanduser()
    if not env_path.is_file():
        raise EnvFileError(f"Explicit env file not found: {env_path}")

    values: dict[str, str] = {}
    provenance: dict[str, EnvFileValue] = {}
    warnings: list[str] = []
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise EnvFileError(f"Could not read explicit env file {env_path}: {exc}") from exc

    for line_no, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            warnings.append(f"Ignoring malformed env line {env_path}:{line_no}")
            continue
        key, _, raw_value = line.partition("=")
        key = key.strip()
        if not key:
            warnings.append(f"Ignoring empty env key {env_path}:{line_no}")
            continue
        value = _strip_env_value(raw_value)
        values[key] = value
        provenance[key] = EnvFileValue(value=value, path=env_path, line=line_no)

    if env_path.name == ENV_FILE_NAME:
        warnings.append(
            f"{ENV_FILE_NAME} is a legacy name; it is only loaded because it was explicit."
        )

    return ParsedEnvFile(path=env_path, values=values, provenance=provenance, warnings=warnings)


def resolve_explicit_env_file(
    *,
    cli_env_file: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> ParsedEnvFile:
    """Resolve ``--env-file`` / ``CLAWSENTRY_ENV_FILE`` and parse it.

    CLI choice wins over ``CLAWSENTRY_ENV_FILE``.  Missing input returns an
    empty parse result.  A selected-but-missing file raises ``EnvFileError``.
    """
    env = {} if environ is None else environ
    selected = cli_env_file
    if selected is None:
        env_value = str(env.get(EXPLICIT_ENV_FILE_ENV, "") or "").strip()
        selected = Path(env_value) if env_value else None
    if selected is None:
        return ParsedEnvFile(path=None)
    return parse_env_file(selected)


def discover_local_env_files(search_dir: Path | None = None) -> EnvFileDiscovery:
    """Find common ClawSentry env files without loading them.

    This powers migration/help text only.  It deliberately preserves the strict
    source model: callers must still pass ``--env-file`` or set
    ``CLAWSENTRY_ENV_FILE`` before any discovered file contributes values.
    """
    root = (search_dir or Path.cwd()).expanduser()
    local = root / LOCAL_ENV_FILE_NAME
    legacy = root / ENV_FILE_NAME
    template = root / ENV_TEMPLATE_NAME
    return EnvFileDiscovery(
        local=local if local.is_file() else None,
        legacy=legacy if legacy.is_file() else None,
        template=template if template.is_file() else None,
    )


def format_env_file_hint(
    discovery: EnvFileDiscovery,
    *,
    command: str = "clawsentry start",
) -> list[str]:
    """Return user-facing guidance for discovered-but-unloaded env files."""
    if not discovery.has_hint:
        return []
    lines = ["Env-file hint: no env file was loaded automatically."]
    if discovery.local is not None:
        lines.append(
            f"  Found {discovery.local.name}; use `{command} --env-file {discovery.local.name}` "
            "or set CLAWSENTRY_ENV_FILE."
        )
    if discovery.legacy is not None:
        lines.append(
            f"  Found legacy {discovery.legacy.name}; use `--env-file {discovery.legacy.name}` "
            f"or copy it to {LOCAL_ENV_FILE_NAME}."
        )
    if discovery.template is not None and discovery.local is None:
        lines.append(
            f"  Found {discovery.template.name}; it is a commit-safe template, not a runtime input. "
            f"Copy it to {LOCAL_ENV_FILE_NAME}, add local secrets, then pass `--env-file`."
        )
    return lines


def overlay_env_file(
    base: Mapping[str, str],
    parsed: ParsedEnvFile,
) -> dict[str, str]:
    """Return process-like env where real process values win over env-file values."""
    merged = dict(parsed.values)
    merged.update(base)
    return merged


def apply_env_file_to_legacy_environ(
    parsed: ParsedEnvFile,
    *,
    environ: MutableMapping[str, str],
) -> int:
    """Compatibility bridge for env-only runtime builders.

    This is deliberately named as a legacy adapter: it mutates only the mapping
    supplied by the caller and never overrides existing process/deployment env.
    """
    loaded = 0
    for key, value in parsed.values.items():
        if key not in environ:
            environ[key] = value
            loaded += 1
    return loaded


def load_dotenv(search_dir: Path | None = None) -> int:
    """Legacy no-op kept for import compatibility.

    Older code called ``load_dotenv()`` to implicitly load a cwd legacy env file.
    The redesigned source model forbids that behavior; explicit env files must
    use :func:`parse_env_file` / :func:`resolve_explicit_env_file`.
    """
    _ = search_dir
    return 0
