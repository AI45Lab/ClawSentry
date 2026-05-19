"""TOML reader compatibility for source-bundle benchmark runtimes."""

from __future__ import annotations

try:
    from tomllib import TOMLDecodeError, loads
except ModuleNotFoundError:  # pragma: no cover - exercised via subprocess test
    from tomli import TOMLDecodeError, loads  # type: ignore[import-not-found]
