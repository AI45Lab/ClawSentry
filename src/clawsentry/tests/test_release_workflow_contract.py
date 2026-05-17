"""Contracts for the public release automation workflow."""

from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_tag_publish_workflow_creates_github_release_after_pypi_publish() -> None:
    workflow = REPO_ROOT / ".github" / "workflows" / "publish.yml"
    source = workflow.read_text(encoding="utf-8")

    assert "tags:" in source
    assert "'v*'" in source or '"v*"' in source
    assert "workflow_dispatch:" in source
    assert "tag:" in source
    assert "RELEASE_TAG:" in source
    assert "contents: write" in source
    assert "Publish to PyPI" in source
    assert "skip-existing: true" in source
    assert "Create GitHub Release" in source
    assert "gh release create" in source
    assert "gh release edit" in source
    assert "CHANGELOG.md" in source
