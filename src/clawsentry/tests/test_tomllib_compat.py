"""Regression coverage for benchmark containers that run Python < 3.11."""

from __future__ import annotations

import subprocess
import sys
import textwrap
import os
from pathlib import Path


def test_tomllib_imports_fall_back_to_tomli() -> None:
    script = textwrap.dedent(
        """
        import importlib.abc
        import sys
        import types


        class BlockTomllib(importlib.abc.MetaPathFinder):
            def find_spec(self, fullname, path=None, target=None):
                if fullname == "tomllib":
                    raise ModuleNotFoundError("No module named 'tomllib'")
                return None


        tomli = types.ModuleType("tomli")


        class TOMLDecodeError(ValueError):
            pass


        tomli.TOMLDecodeError = TOMLDecodeError
        tomli.loads = lambda text: {"fallback": True}
        sys.modules["tomli"] = tomli
        sys.meta_path.insert(0, BlockTomllib())

        from clawsentry.cli.initializers import codex
        from clawsentry.gateway import first_use_skill_review, review_toolkit

        assert codex.tomllib.loads("x") == {"fallback": True}
        assert review_toolkit.tomllib.loads("x") == {"fallback": True}
        assert first_use_skill_review.tomllib.loads("x") == {"fallback": True}
        """
    )

    repo_src = Path(__file__).resolve().parents[2]
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{repo_src}:{env.get('PYTHONPATH', '')}"

    subprocess.run([sys.executable, "-c", script], check=True, env=env)
