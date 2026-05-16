"""Read-only toolkit for Phase 5.2 L3 review agent."""

from __future__ import annotations

import asyncio
import json
import re
import time
import tomllib
from contextvars import ContextVar
from pathlib import Path
from typing import Any


class ToolCallBudgetExhausted(RuntimeError):
    """Raised when ReadOnlyToolkit exceeds MAX_TOOL_CALLS."""


class ReadOnlyToolkit:
    MAX_FILE_READ_BYTES = 512_000
    MAX_TOOL_CALLS = 20
    MAX_TRAJECTORY_EVENTS = 500
    MAX_TRAJECTORY_PAGE_SIZE = 100
    MAX_SESSION_RISK_EVENTS = 200
    MAX_SEARCH_FILES = 2000
    MAX_SEARCH_SECONDS = 2.0
    DEFAULT_SEARCH_IGNORES = {".git", "node_modules", ".venv", "dist", "ui/dist"}

    def __init__(
        self,
        workspace_root: Path,
        trajectory_store: Any,
        session_registry: Any = None,
    ) -> None:
        self._default_workspace_root = workspace_root.resolve()
        self._workspace_root_ctx: ContextVar[Path] = ContextVar(
            "clawsentry_review_toolkit_workspace_root",
            default=self._default_workspace_root,
        )
        self._transcript_path_ctx: ContextVar[str] = ContextVar(
            "clawsentry_review_toolkit_transcript_path",
            default="",
        )
        self._session_id_ctx: ContextVar[str] = ContextVar(
            "clawsentry_review_toolkit_session_id",
            default="",
        )
        self._trajectory_store = trajectory_store
        self._session_registry = session_registry
        self._calls_remaining = self.MAX_TOOL_CALLS

    @property
    def calls_remaining(self) -> int:
        return self._calls_remaining

    @property
    def workspace_root(self) -> Path:
        return self._workspace_root_ctx.get()

    @property
    def default_workspace_root(self) -> Path:
        return self._default_workspace_root

    @property
    def transcript_path(self) -> str:
        return self._transcript_path_ctx.get()

    @property
    def session_id(self) -> str:
        return self._session_id_ctx.get()

    def set_workspace_root(self, workspace_root: Path) -> None:
        self._workspace_root_ctx.set(workspace_root.resolve())

    def bind_session_context(
        self,
        *,
        workspace_root: Path | None = None,
        transcript_path: str | None = None,
        session_id: str | None = None,
    ) -> None:
        if workspace_root is not None:
            self.set_workspace_root(workspace_root)
        self._transcript_path_ctx.set(str(transcript_path or ""))
        self._session_id_ctx.set(str(session_id or ""))

    def fork(
        self,
        workspace_root: Path | None = None,
        transcript_path: str | None = None,
        session_id: str | None = None,
    ) -> "ReadOnlyToolkit":
        child = ReadOnlyToolkit(
            workspace_root or self._default_workspace_root,
            self._trajectory_store,
            session_registry=self._session_registry,
        )
        child.bind_session_context(
            workspace_root=workspace_root or self._default_workspace_root,
            transcript_path=transcript_path,
            session_id=session_id,
        )
        return child

    def reset_budget(self) -> None:
        self._calls_remaining = self.MAX_TOOL_CALLS

    def set_calls_remaining(self, calls_remaining: int) -> None:
        try:
            remaining = int(calls_remaining)
        except (TypeError, ValueError):
            remaining = 0
        self._calls_remaining = max(0, min(remaining, self.MAX_TOOL_CALLS))

    def _consume_call(self) -> None:
        if self._calls_remaining <= 0:
            raise ToolCallBudgetExhausted(
                f"ReadOnlyToolkit budget exhausted (max {self.MAX_TOOL_CALLS} calls)"
            )
        self._calls_remaining -= 1

    def _safe_path(self, relative_path: str) -> Path:
        clean = relative_path.lstrip("/")
        workspace_root = self.workspace_root
        target = (workspace_root / clean).resolve()
        try:
            target.relative_to(workspace_root)
        except ValueError as exc:
            raise ValueError(f"Path '{relative_path}' escapes workspace_root") from exc
        return target

    def _safe_bound_path(self, bound_path: str) -> Path:
        workspace_root = self.workspace_root
        candidate = Path(bound_path)
        target = (
            candidate.resolve()
            if candidate.is_absolute()
            else (workspace_root / candidate).resolve()
        )
        try:
            target.relative_to(workspace_root)
        except ValueError as exc:
            raise ValueError(f"Path '{bound_path}' escapes workspace_root") from exc
        return target

    async def read_trajectory(self, session_id: str, limit: int = 100) -> list[dict[str, Any]]:
        self._consume_call()
        if self._trajectory_store is None:
            return []
        capped_limit = min(limit, self.MAX_TRAJECTORY_EVENTS)
        records = self._trajectory_store.replay_session(session_id, limit=capped_limit)
        return [
            {
                "recorded_at": rec.get("recorded_at"),
                "event": rec.get("event", {}),
                "decision": rec.get("decision", {}),
                "risk_level": rec.get("decision", {}).get("risk_level"),
            }
            for rec in records
        ]

    async def read_trajectory_page(
        self,
        session_id: str,
        cursor: int | None = None,
        limit: int = 50,
    ) -> dict[str, Any]:
        self._consume_call()
        if self._trajectory_store is None:
            return {"records": [], "next_cursor": None}
        capped_limit = min(max(int(limit), 1), self.MAX_TRAJECTORY_PAGE_SIZE)
        return self._trajectory_store.replay_session_page(
            session_id,
            cursor=cursor,
            limit=capped_limit,
        )

    async def read_file(self, relative_path: str) -> str:
        self._consume_call()
        try:
            target = self._safe_path(relative_path)
            if not target.is_file():
                return f"[error: '{relative_path}' is not a file or does not exist]"
            with open(target, "rb") as fh:
                raw = fh.read(self.MAX_FILE_READ_BYTES)
            text = raw.decode("utf-8", errors="replace")
            if len(raw) == self.MAX_FILE_READ_BYTES:
                text += f"\n[truncated at {self.MAX_FILE_READ_BYTES} bytes]"
            return text
        except (ValueError, OSError) as exc:
            return f"[error: {exc}]"

    async def read_file_range(self, relative_path: str, start_line: int = 1, max_lines: int = 120) -> dict[str, Any]:
        self._consume_call()
        try:
            target = self._safe_path(relative_path)
            if not target.is_file():
                return {"error": f"'{relative_path}' is not a file or does not exist"}
            start = max(1, int(start_line))
            limit = min(max(int(max_lines), 1), 500)
            selected: list[str] = []
            truncated = False
            with open(target, "r", encoding="utf-8", errors="replace") as fh:
                for lineno, line in enumerate(fh, 1):
                    if lineno < start:
                        continue
                    if len(selected) >= limit:
                        truncated = True
                        break
                    selected.append(line.rstrip("\n\r"))
            return {
                "path": str(target.relative_to(self.workspace_root)),
                "start_line": start,
                "end_line": start + len(selected) - 1 if selected else start,
                "truncated": truncated,
                "content": "\n".join(selected),
            }
        except (ValueError, OSError) as exc:
            return {"error": str(exc)}

    async def read_transcript(self) -> str:
        self._consume_call()
        transcript_path = self.transcript_path
        if not transcript_path:
            return "[error: transcript_path is not bound for this analysis session]"
        try:
            target = self._safe_bound_path(transcript_path)
            if not target.is_file():
                return f"[error: '{transcript_path}' is not a file or does not exist]"
            with open(target, "rb") as fh:
                raw = fh.read(self.MAX_FILE_READ_BYTES)
            text = raw.decode("utf-8", errors="replace")
            if len(raw) == self.MAX_FILE_READ_BYTES:
                text += f"\n[truncated at {self.MAX_FILE_READ_BYTES} bytes]"
            return text
        except (ValueError, OSError) as exc:
            return f"[error: {exc}]"

    async def read_session_risk(self, limit: int = 50) -> dict[str, Any]:
        self._consume_call()
        if self._session_registry is None:
            return {"error": "session_registry is not configured"}
        session_id = self.session_id
        if not session_id:
            return {"error": "session_id is not bound for this analysis session"}
        try:
            effective_limit = min(max(int(limit), 1), self.MAX_SESSION_RISK_EVENTS)
        except (TypeError, ValueError):
            effective_limit = 50
        try:
            return self._session_registry.get_session_risk(session_id, limit=effective_limit)
        except Exception as exc:
            return {"error": str(exc)}

    async def search_codebase(self, pattern: str, glob: str = "**/*", max_results: int = 50) -> list[dict[str, Any]]:
        self._consume_call()
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return [{"error": f"Invalid regex: {exc}"}]
        results: list[dict[str, Any]] = []
        workspace_root = self.workspace_root
        scanned_files = 0
        deadline = time.monotonic() + self.MAX_SEARCH_SECONDS
        for path in sorted(workspace_root.glob(glob)):
            if time.monotonic() > deadline or scanned_files >= self.MAX_SEARCH_FILES:
                break
            if not path.is_file() or len(results) >= max_results:
                continue
            try:
                rel_parts = path.relative_to(workspace_root).parts
            except ValueError:
                continue
            if any(part in self.DEFAULT_SEARCH_IGNORES for part in rel_parts):
                continue
            scanned_files += 1
            try:
                with open(path, "rb") as fh:
                    raw = fh.read(self.MAX_FILE_READ_BYTES)
                for lineno, line in enumerate(raw.decode("utf-8", errors="replace").splitlines(), 1):
                    if compiled.search(line):
                        results.append(
                            {
                                "file": str(path.relative_to(workspace_root)),
                                "line": lineno,
                                "content": line.rstrip(),
                            }
                        )
                        if len(results) >= max_results:
                            break
            except OSError:
                continue
        return results

    async def query_git_diff(self, ref: str = "HEAD") -> str:
        self._consume_call()
        if not re.match(r"^[A-Za-z0-9_.^~\-/]{1,200}$", ref):
            return "[error: unsafe ref pattern]"
        try:
            proc = await asyncio.create_subprocess_exec(
                "git",
                "diff",
                ref,
                cwd=str(self.workspace_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            output = stdout.decode("utf-8", errors="replace")
            if len(output) > self.MAX_FILE_READ_BYTES:
                output = output[: self.MAX_FILE_READ_BYTES] + "\n[truncated]"
            return output if output else stderr.decode("utf-8", errors="replace")
        except (asyncio.TimeoutError, OSError, FileNotFoundError) as exc:
            return f"[error: {exc}]"

    async def query_git_status(self) -> str:
        self._consume_call()
        return await self._run_git("status", "--short")

    async def list_changed_files(self, ref: str = "HEAD") -> list[str]:
        self._consume_call()
        if not re.match(r"^[A-Za-z0-9_.^~\-/]{1,200}$", ref):
            return ["[error: unsafe ref pattern]"]
        output = await self._run_git("diff", "--name-only", ref)
        return [line for line in output.splitlines() if line.strip()]

    async def query_git_show(self, ref: str = "HEAD", path: str | None = None) -> str:
        self._consume_call()
        if not re.match(r"^[A-Za-z0-9_.^~\-/:]{1,240}$", ref):
            return "[error: unsafe ref pattern]"
        args = ["show", ref]
        if path:
            args.extend(["--", path])
        return await self._run_git(*args)

    async def read_package_manifest(self, relative_path: str) -> dict[str, Any]:
        self._consume_call()
        try:
            target = self._safe_path(relative_path)
            if not target.is_file():
                return {"error": f"'{relative_path}' is not a file or does not exist"}
            with open(target, "rb") as fh:
                raw = fh.read(self.MAX_FILE_READ_BYTES + 1)
            truncated = len(raw) > self.MAX_FILE_READ_BYTES
            raw = raw[: self.MAX_FILE_READ_BYTES]
            text = raw.decode("utf-8", errors="replace")
            if target.name == "package.json":
                data = json.loads(text)
                return {
                    "path": str(target.relative_to(self.workspace_root)),
                    "manifest_type": "package.json",
                    "name": data.get("name"),
                    "scripts": data.get("scripts", {}),
                    "dependencies": sorted((data.get("dependencies") or {}).keys())[:100],
                    "devDependencies": sorted((data.get("devDependencies") or {}).keys())[:100],
                    "truncated": truncated,
                }
            if target.name == "pyproject.toml":
                data = tomllib.loads(text)
                project = data.get("project") if isinstance(data, dict) else {}
                project = project if isinstance(project, dict) else {}
                optional = project.get("optional-dependencies") or {}
                optional_deps = {
                    str(group): [str(item) for item in deps[:100]]
                    for group, deps in optional.items()
                    if isinstance(deps, list)
                } if isinstance(optional, dict) else {}
                return {
                    "path": str(target.relative_to(self.workspace_root)),
                    "manifest_type": "pyproject.toml",
                    "name": project.get("name"),
                    "dependencies": [str(item) for item in (project.get("dependencies") or [])[:100]],
                    "optional_dependencies": optional_deps,
                    "truncated": truncated,
                }
            if target.name == "Cargo.toml":
                data = tomllib.loads(text)
                package = data.get("package") if isinstance(data, dict) else {}
                deps = data.get("dependencies") if isinstance(data, dict) else {}
                return {
                    "path": str(target.relative_to(self.workspace_root)),
                    "manifest_type": "Cargo.toml",
                    "name": package.get("name") if isinstance(package, dict) else None,
                    "dependencies": sorted(str(key) for key in deps.keys())[:100] if isinstance(deps, dict) else [],
                    "truncated": truncated,
                }
            lockfile_names = {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "poetry.lock"}
            return {
                "path": str(target.relative_to(self.workspace_root)),
                "manifest_type": target.name if target.name in lockfile_names else "raw",
                "content": text[: self.MAX_FILE_READ_BYTES],
                "truncated": truncated,
            }
        except (ValueError, OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
            return {"error": str(exc)}

    async def read_l3_trace(self, limit: int = 20) -> dict[str, Any]:
        self._consume_call()
        if self._session_registry is None:
            return {"records": [], "error": "session_registry is not configured"}
        try:
            effective_limit = min(max(int(limit), 1), 100)
        except (TypeError, ValueError):
            effective_limit = 20
        try:
            risk = self._session_registry.get_session_risk(
                self.session_id,
                limit=self.MAX_SESSION_RISK_EVENTS,
            )
        except Exception as exc:
            return {"records": [], "error": str(exc)}
        records = []
        for item in risk.get("risk_timeline", []) if isinstance(risk, dict) else []:
            if item.get("actual_tier") == "L3" or item.get("l3_reason_code"):
                records.append({
                    "event_id": item.get("event_id"),
                    "risk_level": item.get("risk_level"),
                    "l3_reason_code": item.get("l3_reason_code"),
                    "tool_name": item.get("tool_name"),
                })
        return {"records": records[:effective_limit]}

    async def _run_git(self, *args: str) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                "git",
                *args,
                cwd=str(self.workspace_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            output = stdout.decode("utf-8", errors="replace")
            if not output:
                output = stderr.decode("utf-8", errors="replace")
            if len(output) > self.MAX_FILE_READ_BYTES:
                output = output[: self.MAX_FILE_READ_BYTES] + "\n[truncated]"
            return output
        except (asyncio.TimeoutError, OSError, FileNotFoundError) as exc:
            return f"[error: {exc}]"

    async def list_directory(self, relative_path: str = ".") -> list[str]:
        self._consume_call()
        try:
            target = self._safe_path(relative_path)
            if not target.is_dir():
                return [f"[error: '{relative_path}' is not a directory]"]
            workspace_root = self.workspace_root
            return [
                str(entry.relative_to(workspace_root)) + ("/" if entry.is_dir() else "")
                for entry in sorted(target.iterdir())
            ]
        except (ValueError, OSError) as exc:
            return [f"[error: {exc}]"]
