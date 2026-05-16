"""Tests for ReadOnlyToolkit — comprehensive coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from clawsentry.gateway.review_toolkit import (
    ReadOnlyToolkit,
    ToolCallBudgetExhausted,
)
from .conftest import StubTrajectoryStore


class StubSessionRegistry:
    def get_session_risk(self, session_id: str, *, limit: int = 100, since_seconds=None) -> dict:
        return {
            "session_id": session_id,
            "current_risk_level": "high",
            "cumulative_score": 7,
            "risk_timeline": [
                {
                    "event_id": "evt-1",
                    "occurred_at": "2026-04-10T09:00:00+00:00",
                    "risk_level": "medium",
                    "composite_score": 3,
                    "tool_name": "read_file",
                    "decision": "allow",
                    "actual_tier": "L1",
                    "classified_by": "rule_based",
                },
                {
                    "event_id": "evt-2",
                    "occurred_at": "2026-04-10T09:01:00+00:00",
                    "risk_level": "high",
                    "composite_score": 7,
                    "tool_name": "bash",
                    "decision": "defer",
                    "actual_tier": "L3",
                    "classified_by": "agent_reviewer",
                },
            ][:limit],
        }


# ---------------------------------------------------------------------------
# Budget management
# ---------------------------------------------------------------------------


class TestBudget:
    @pytest.mark.asyncio
    async def test_initial_budget(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        assert tk.calls_remaining == tk.MAX_TOOL_CALLS

    @pytest.mark.asyncio
    async def test_budget_decrements(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("x", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        await tk.read_file("f.txt")
        assert tk.calls_remaining == tk.MAX_TOOL_CALLS - 1

    @pytest.mark.asyncio
    async def test_budget_exhaustion_raises(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("x", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        for _ in range(tk.MAX_TOOL_CALLS):
            await tk.read_file("f.txt")
        with pytest.raises(ToolCallBudgetExhausted):
            await tk.read_file("f.txt")

    @pytest.mark.asyncio
    async def test_reset_budget(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("x", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        for _ in range(tk.MAX_TOOL_CALLS):
            await tk.read_file("f.txt")
        tk.reset_budget()
        assert tk.calls_remaining == tk.MAX_TOOL_CALLS
        # Should be able to call again
        result = await tk.read_file("f.txt")
        assert result == "x"

    @pytest.mark.asyncio
    async def test_set_calls_remaining_is_bounded(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("x", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        await tk.read_file("f.txt")
        tk.set_calls_remaining(tk.MAX_TOOL_CALLS + 10)
        assert tk.calls_remaining == tk.MAX_TOOL_CALLS
        tk.set_calls_remaining(2)
        assert tk.calls_remaining == 2
        await tk.read_file("f.txt")
        await tk.read_file("f.txt")
        with pytest.raises(ToolCallBudgetExhausted):
            await tk.read_file("f.txt")


# ---------------------------------------------------------------------------
# _safe_path / path traversal
# ---------------------------------------------------------------------------


class TestSafePath:
    @pytest.mark.asyncio
    async def test_workspace_root_can_be_rebound(self, tmp_path: Path) -> None:
        original = tmp_path / "original"
        worker = tmp_path / "worker"
        original.mkdir()
        worker.mkdir()
        (worker / "README.md").write_text("worker workspace", encoding="utf-8")

        tk = ReadOnlyToolkit(original, StubTrajectoryStore())
        tk.set_workspace_root(worker)

        result = await tk.read_file("README.md")
        assert result == "worker workspace"
        assert tk.workspace_root == worker.resolve()

    @pytest.mark.asyncio
    async def test_rejects_dotdot(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("../outside.txt")
        assert "[error:" in result
        assert "escapes workspace_root" in result

    @pytest.mark.asyncio
    async def test_rejects_absolute_escape(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("/etc/passwd")
        # /etc/passwd gets lstripped to etc/passwd → resolves inside workspace
        # But since the file doesn't exist there, we get not-a-file error
        assert "[error:" in result

    @pytest.mark.asyncio
    async def test_leading_slash_stripped(self, tmp_path: Path) -> None:
        (tmp_path / "hello.txt").write_text("world", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("/hello.txt")
        assert result == "world"

    @pytest.mark.asyncio
    async def test_nested_dotdot_escape(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("sub/../../outside.txt")
        assert "[error:" in result
        assert "escapes workspace_root" in result


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------


class TestReadFile:
    @pytest.mark.asyncio
    async def test_happy_path(self, tmp_path: Path) -> None:
        (tmp_path / "hello.txt").write_text("hello world", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("hello.txt")
        assert result == "hello world"

    @pytest.mark.asyncio
    async def test_nonexistent_file(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("no_such_file.txt")
        assert "[error:" in result
        assert "not a file" in result

    @pytest.mark.asyncio
    async def test_directory_not_file(self, tmp_path: Path) -> None:
        (tmp_path / "subdir").mkdir()
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("subdir")
        assert "[error:" in result
        assert "not a file" in result

    @pytest.mark.asyncio
    async def test_truncation(self, tmp_path: Path) -> None:
        big_file = tmp_path / "big.txt"
        big_file.write_bytes(b"A" * (ReadOnlyToolkit.MAX_FILE_READ_BYTES + 100))
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("big.txt")
        assert f"[truncated at {ReadOnlyToolkit.MAX_FILE_READ_BYTES} bytes]" in result

    @pytest.mark.asyncio
    async def test_read_file_range_does_not_load_unbounded_content(self, tmp_path: Path) -> None:
        big_file = tmp_path / "big.txt"
        big_file.write_text("\n".join(f"line-{idx}" for idx in range(10000)), encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())

        result = await tk.read_file_range("big.txt", start_line=10, max_lines=3)

        assert result["content"] == "line-9\nline-10\nline-11"
        assert result["truncated"] is True

    @pytest.mark.asyncio
    async def test_binary_content_replaced(self, tmp_path: Path) -> None:
        """Binary bytes that aren't valid UTF-8 should be replaced, not crash."""
        (tmp_path / "bin.dat").write_bytes(b"\x80\x81\x82hello\xff")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("bin.dat")
        assert "hello" in result  # valid portion preserved
        assert "\ufffd" in result  # replacement character

    @pytest.mark.asyncio
    async def test_nested_path(self, tmp_path: Path) -> None:
        sub = tmp_path / "a" / "b"
        sub.mkdir(parents=True)
        (sub / "deep.txt").write_text("nested", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_file("a/b/deep.txt")
        assert result == "nested"


# ---------------------------------------------------------------------------
# read_trajectory
# ---------------------------------------------------------------------------


class TestReadTrajectory:
    def test_trajectory_store_replay_page_returns_cursor(self, tmp_path: Path) -> None:
        from clawsentry.gateway.trajectory_store import TrajectoryStore

        store = TrajectoryStore(db_path=str(tmp_path / "trajectory.db"))
        for idx in range(3):
            store.record(
                event={
                    "event_id": f"evt-{idx}",
                    "session_id": "sess-1",
                    "source_framework": "test",
                    "event_type": "pre_action",
                },
                decision={"decision": "allow", "risk_level": "low"},
                snapshot={"risk_level": "low"},
                meta={"actual_tier": "L1", "request_id": f"r-{idx}"},
            )

        first_page = store.replay_session_page("sess-1", limit=2)
        assert [record["event"]["event_id"] for record in first_page["records"]] == ["evt-1", "evt-2"]
        assert first_page["next_cursor"] is not None

        second_page = store.replay_session_page(
            "sess-1",
            limit=2,
            cursor=first_page["next_cursor"],
        )
        assert [record["event"]["event_id"] for record in second_page["records"]] == ["evt-0"]
        assert second_page["next_cursor"] is None

    @pytest.mark.asyncio
    async def test_caps_limit(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_trajectory("sess-1", limit=1000)
        assert len(result) == tk.MAX_TRAJECTORY_EVENTS

    @pytest.mark.asyncio
    async def test_small_limit(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_trajectory("sess-1", limit=3)
        assert len(result) == 3

    @pytest.mark.asyncio
    async def test_extracts_fields(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_trajectory("sess-1", limit=1)
        assert len(result) == 1
        rec = result[0]
        assert "recorded_at" in rec
        assert "event" in rec
        assert "decision" in rec
        assert "risk_level" in rec

    @pytest.mark.asyncio
    async def test_consumes_budget(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        before = tk.calls_remaining
        await tk.read_trajectory("sess-1", limit=1)
        assert tk.calls_remaining == before - 1

    @pytest.mark.asyncio
    async def test_read_trajectory_page_returns_records_and_cursor(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.read_trajectory_page("sess-1", limit=2)

        assert len(result["records"]) == 2
        assert result["next_cursor"] is not None


# ---------------------------------------------------------------------------
# transcript + session risk
# ---------------------------------------------------------------------------


class TestTranscriptAndSessionRisk:
    @pytest.mark.asyncio
    async def test_read_transcript_reads_bound_session_transcript(self, tmp_path: Path) -> None:
        transcript = tmp_path / ".codex" / "transcript.jsonl"
        transcript.parent.mkdir()
        transcript.write_text('{"role":"user","content":"cat secrets.env"}\n', encoding="utf-8")

        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore(), session_registry=StubSessionRegistry())
        tk = tk.fork(
            workspace_root=tmp_path,
            transcript_path=str(transcript),
            session_id="sess-1",
        )

        result = await tk.read_transcript()
        assert "cat secrets.env" in result

    @pytest.mark.asyncio
    async def test_read_transcript_rejects_outside_workspace(self, tmp_path: Path) -> None:
        outside = tmp_path.parent / "session.jsonl"
        outside.write_text("outside", encoding="utf-8")

        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore(), session_registry=StubSessionRegistry())
        tk = tk.fork(
            workspace_root=tmp_path,
            transcript_path=str(outside),
            session_id="sess-1",
        )

        result = await tk.read_transcript()
        assert "[error:" in result
        assert "escapes workspace_root" in result

    @pytest.mark.asyncio
    async def test_read_session_risk_returns_session_history(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore(), session_registry=StubSessionRegistry())
        tk = tk.fork(workspace_root=tmp_path, session_id="sess-risk")

        result = await tk.read_session_risk(limit=1)
        assert result["session_id"] == "sess-risk"
        assert result["current_risk_level"] == "high"
        assert len(result["risk_timeline"]) == 1
        assert result["risk_timeline"][0]["event_id"] == "evt-1"

    @pytest.mark.asyncio
    async def test_read_l3_trace_accepts_string_limit(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore(), session_registry=StubSessionRegistry())
        tk = tk.fork(workspace_root=tmp_path, session_id="sess-risk")

        result = await tk.read_l3_trace(limit="1")

        assert len(result["records"]) == 1
        assert result["records"][0]["event_id"] == "evt-2"


# ---------------------------------------------------------------------------
# search_codebase
# ---------------------------------------------------------------------------


class TestSearchCodebase:
    @pytest.mark.asyncio
    async def test_finds_matches(self, tmp_path: Path) -> None:
        (tmp_path / "code.py").write_text("def foo():\n    return 42\n", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        results = await tk.search_codebase(r"def\s+foo")
        assert len(results) == 1
        assert results[0]["file"] == "code.py"
        assert results[0]["line"] == 1
        assert "def foo" in results[0]["content"]

    @pytest.mark.asyncio
    async def test_invalid_regex(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        results = await tk.search_codebase("[invalid")
        assert len(results) == 1
        assert "error" in results[0]
        assert "Invalid regex" in results[0]["error"]

    @pytest.mark.asyncio
    async def test_max_results_capped(self, tmp_path: Path) -> None:
        # Create a file with many matching lines
        lines = "\n".join(f"match_{i}" for i in range(100))
        (tmp_path / "many.txt").write_text(lines, encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        results = await tk.search_codebase(r"match_\d+", max_results=5)
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_glob_filtering(self, tmp_path: Path) -> None:
        (tmp_path / "yes.py").write_text("target_line\n", encoding="utf-8")
        (tmp_path / "no.txt").write_text("target_line\n", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        results = await tk.search_codebase("target_line", glob="*.py")
        assert len(results) == 1
        assert results[0]["file"] == "yes.py"

    @pytest.mark.asyncio
    async def test_no_matches(self, tmp_path: Path) -> None:
        (tmp_path / "empty.txt").write_text("nothing here\n", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        results = await tk.search_codebase("ZZZZZ_NOPE")
        assert results == []

    @pytest.mark.asyncio
    async def test_case_insensitive(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("Hello World\n", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        results = await tk.search_codebase("hello world")
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_ignores_generated_and_vendor_dirs_by_default(self, tmp_path: Path) -> None:
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("target_line\n", encoding="utf-8")
        (tmp_path / "node_modules" / "pkg").mkdir(parents=True)
        (tmp_path / "node_modules" / "pkg" / "index.js").write_text("target_line\n", encoding="utf-8")
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("target_line\n", encoding="utf-8")

        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        results = await tk.search_codebase("target_line")

        assert [item["file"] for item in results] == ["src/app.py"]


# ---------------------------------------------------------------------------
# query_git_diff
# ---------------------------------------------------------------------------


class TestQueryGitDiff:
    @pytest.mark.asyncio
    async def test_unsafe_ref_rejected(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.query_git_diff("; rm -rf /")
        assert "[error: unsafe ref pattern]" in result

    @pytest.mark.asyncio
    async def test_unsafe_ref_backtick(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.query_git_diff("`whoami`")
        assert "[error: unsafe ref pattern]" in result

    @pytest.mark.asyncio
    async def test_safe_ref_patterns_accepted(self, tmp_path: Path) -> None:
        """Valid ref patterns should pass the safety check (may fail at git level)."""
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        for ref in ("HEAD", "HEAD~1", "main", "feature/branch", "v1.0.0"):
            result = await tk.query_git_diff(ref)
            # Should not be rejected by safety check (may have git errors though)
            assert "unsafe ref pattern" not in result

    @pytest.mark.asyncio
    async def test_read_package_manifest_structures_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            "[project]\nname = \"demo\"\ndependencies = [\"requests>=2\"]\n",
            encoding="utf-8",
        )
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())

        result = await tk.read_package_manifest("pyproject.toml")

        assert result["path"] == "pyproject.toml"
        assert result["manifest_type"] == "pyproject.toml"
        assert result["name"] == "demo"
        assert result["dependencies"] == ["requests>=2"]

    @pytest.mark.asyncio
    async def test_long_ref_rejected(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.query_git_diff("a" * 201)
        assert "[error: unsafe ref pattern]" in result


# ---------------------------------------------------------------------------
# list_directory
# ---------------------------------------------------------------------------


class TestListDirectory:
    @pytest.mark.asyncio
    async def test_happy_path(self, tmp_path: Path) -> None:
        (tmp_path / "file.txt").write_text("hi", encoding="utf-8")
        (tmp_path / "subdir").mkdir()
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.list_directory(".")
        assert any("file.txt" in e for e in result)
        assert any(e.endswith("/") for e in result)  # directory has trailing /

    @pytest.mark.asyncio
    async def test_nonexistent_dir(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.list_directory("no_such_dir")
        assert len(result) == 1
        assert "[error:" in result[0]
        assert "not a directory" in result[0]

    @pytest.mark.asyncio
    async def test_file_not_dir(self, tmp_path: Path) -> None:
        (tmp_path / "f.txt").write_text("hi", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.list_directory("f.txt")
        assert "[error:" in result[0]
        assert "not a directory" in result[0]

    @pytest.mark.asyncio
    async def test_path_escape(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.list_directory("../../")
        assert len(result) == 1
        assert "[error:" in result[0]
        assert "escapes workspace_root" in result[0]

    @pytest.mark.asyncio
    async def test_empty_dir(self, tmp_path: Path) -> None:
        (tmp_path / "empty").mkdir()
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.list_directory("empty")
        assert result == []

    @pytest.mark.asyncio
    async def test_nested_directory(self, tmp_path: Path) -> None:
        sub = tmp_path / "a" / "b"
        sub.mkdir(parents=True)
        (sub / "deep.txt").write_text("content", encoding="utf-8")
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        result = await tk.list_directory("a/b")
        assert any("deep.txt" in e for e in result)

    @pytest.mark.asyncio
    async def test_consumes_budget(self, tmp_path: Path) -> None:
        tk = ReadOnlyToolkit(tmp_path, StubTrajectoryStore())
        before = tk.calls_remaining
        await tk.list_directory(".")
        assert tk.calls_remaining == before - 1
