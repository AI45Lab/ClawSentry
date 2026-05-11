#!/usr/bin/env python3
"""Reusable OpenAI-compatible API connectivity probe for benchmark experiments."""

from __future__ import annotations

import argparse
import json
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TIMEOUT_SECONDS = 10.0


@dataclass(frozen=True)
class NormalizedTarget:
    base_url: str
    model: str


@dataclass(frozen=True)
class ApiTarget:
    name: str
    provider: str
    base_url: str
    model: str
    source: str
    api_key: str = ""
    notes: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "provider": self.provider,
            "base_url": self.base_url,
            "model": self.model,
            "source": self.source,
            "api_key": "<redacted>" if self.api_key else "<not configured>",
            "notes": self.notes,
        }


def _hcl_string_value(source: str, key: str) -> str:
    match = re.search(rf"^\s*{re.escape(key)}\s*=\s*\"([^\"]*)\"", source, flags=re.MULTILINE)
    if match:
        return match.group(1).strip()
    match = re.search(rf"^\s*{re.escape(key)}\s*=\s*([^\s#]+)", source, flags=re.MULTILINE)
    return match.group(1).strip() if match else ""


def _model_id(default_model: str) -> str:
    default_model = default_model.strip()
    if "/" in default_model:
        return default_model.split("/", 1)[1].strip()
    return default_model


def _redacted_key(key: str) -> str:
    if not key:
        return "<not configured>"
    return "<redacted>"


def normalize_base_url(base_url: str) -> str:
    raw = base_url.strip().rstrip("/")
    if not raw:
        return raw
    parsed = urllib.parse.urlparse(raw)
    if not parsed.scheme or not parsed.netloc:
        return raw
    path = parsed.path.rstrip("/")
    if path.endswith("/v1"):
        new_path = path
    else:
        new_path = f"{path}/v1" if path else "/v1"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, new_path, "", "", ""))


def normalize_openai_target(url: str, *, fallback_model: str) -> NormalizedTarget:
    raw = url.strip()
    parsed = urllib.parse.urlparse(raw)
    path = parsed.path.rstrip("/")
    marker = "/v1/"
    if marker in path:
        before, after = path.split(marker, 1)
        base_path = f"{before}/v1"
        base_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, base_path, "", "", ""))
        model = after.strip("/").lstrip("-").strip()
        return NormalizedTarget(base_url=normalize_base_url(base_url), model=model or fallback_model.strip())
    return NormalizedTarget(base_url=normalize_base_url(raw), model=fallback_model.strip())


def target_from_agent_hcl(path: Path) -> ApiTarget:
    source = path.read_text(encoding="utf-8")
    provider = (_hcl_string_value(source, "name") or "openai").lower()
    api_key = _hcl_string_value(source, "api_key")
    base_url = normalize_base_url(_hcl_string_value(source, "base_url"))
    model = _model_id(_hcl_string_value(source, "default_model"))
    return ApiTarget(
        name="repo-agent-hcl",
        provider=f"{provider}-compatible" if provider == "openai" else provider,
        base_url=base_url,
        model=model,
        api_key=api_key,
        source=str(path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path),
        notes="Repo-local agent.hcl. API key is read for probing but never printed.",
    )


def _target_from_url(
    *,
    name: str,
    url: str,
    model: str,
    source: str,
    notes: str = "",
    api_key: str = "",
) -> ApiTarget:
    normalized = normalize_openai_target(url, fallback_model=model)
    return ApiTarget(
        name=name,
        provider="openai-compatible",
        base_url=normalized.base_url,
        model=normalized.model,
        api_key=api_key,
        source=source,
        notes=notes,
    )


def default_targets() -> list[ApiTarget]:
    targets: list[ApiTarget] = []
    key_by_base_url: dict[str, str] = {}
    agent_hcl = REPO_ROOT / "agent.hcl"
    if agent_hcl.exists():
        agent_target = target_from_agent_hcl(agent_hcl)
        if agent_target.api_key:
            key_by_base_url[agent_target.base_url] = agent_target.api_key
        targets.append(agent_target)
        targets.append(
            ApiTarget(
                name="boyue-gemini-3-flash-preview",
                provider="openai-compatible",
                base_url=agent_target.base_url,
                model="gemini-3-flash-preview",
                api_key=agent_target.api_key,
                source="user supplied 2026-05-11; key from agent.hcl",
                notes="Boyue endpoint/model smoke target sharing the local agent.hcl API key.",
            )
        )

    targets.extend(
        [
            _target_from_url(
                name="repo-example-kimi-k2.5",
                url="http://35.220.164.252:3888/v1/",
                model="kimi-k2.5",
                source="configs/agent.example.hcl; docs/operations/2026-03-23-internal-beta-testing-guide.md",
                notes="Documented OpenAI-compatible Kimi endpoint used by earlier benchmark smokes.",
            ),
            _target_from_url(
                name="user-minimax-2.7-w8a8",
                url="http://10.140.158.149:18027/v1/-MiniMax-2.7-w8a8",
                model="",
                source="user supplied 2026-05-11",
                notes="Input URL contained /v1/<model>; script records base_url=/v1 and model suffix separately.",
            ),
            _target_from_url(
                name="user-minimax-2.7-w8a8-alt-15002",
                url="http://10.140.158.149:15002/v1/",
                model="MiniMax-2.7-w8a8",
                source="user supplied 2026-05-11",
                notes="Alternative MiniMax-2.7-w8a8 endpoint supplied for comparison with the 18027 endpoint.",
            ),
            _target_from_url(
                name="user-ailab-202603-glm-5-actual-5.1",
                url="http://s-20260304151647-c9kjf.ailab-pj.pjh-service.org.cn/v1/",
                model="glm-5",
                source="user supplied 2026-05-11",
                notes="User note: glm-5 is actually 5.1.",
            ),
            _target_from_url(
                name="user-ailab-202603-kimi-k2.5",
                url="http://s-20260304151647-c9kjf.ailab-pj.pjh-service.org.cn/v1/",
                model="kimi-k2.5",
                source="user supplied 2026-05-11",
            ),
            _target_from_url(
                name="user-ailab-202602-glm-5-actual-5.1",
                url="http://s-20260204175507-cqflp.ailab-pj.pjh-service.org.cn/v1/",
                model="glm-5",
                source="user supplied 2026-05-11",
                notes="Model inferred from the adjacent user-supplied model list; verify before long experiments.",
            ),
            _target_from_url(
                name="user-ailab-202602-kimi-k2.5",
                url="http://s-20260204175507-cqflp.ailab-pj.pjh-service.org.cn/v1/",
                model="kimi-k2.5",
                source="user supplied 2026-05-11",
                notes="Model inferred from the adjacent user-supplied model list; verify before long experiments.",
            ),
        ]
    )
    if key_by_base_url:
        targets = [
            replace(target, api_key=key_by_base_url[target.base_url])
            if not target.api_key and target.provider == "openai-compatible" and target.base_url in key_by_base_url
            else target
            for target in targets
        ]
    return targets


def _opener(*, use_env_proxy: bool) -> urllib.request.OpenerDirector:
    if use_env_proxy:
        return urllib.request.build_opener()
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _request(
    url: str,
    *,
    method: str,
    api_key: str,
    timeout: float,
    use_env_proxy: bool,
    body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Accept": "application/json"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    start = time.monotonic()
    try:
        with _opener(use_env_proxy=use_env_proxy).open(request, timeout=timeout) as response:
            payload = response.read(600).decode("utf-8", errors="replace")
            return {
                "ok": 200 <= response.status < 300,
                "reachable": True,
                "status": response.status,
                "latency_ms": round((time.monotonic() - start) * 1000, 1),
                "detail": payload.replace("\n", " ")[:240],
            }
    except urllib.error.HTTPError as exc:
        payload = exc.read(600).decode("utf-8", errors="replace")
        return {
            "ok": False,
            "reachable": True,
            "status": exc.code,
            "latency_ms": round((time.monotonic() - start) * 1000, 1),
            "detail": payload.replace("\n", " ")[:240],
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "reachable": False,
            "status": None,
            "latency_ms": round((time.monotonic() - start) * 1000, 1),
            "detail": f"{type(exc).__name__}: {exc}",
        }


def probe_target(
    target: ApiTarget,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    chat: bool = False,
    use_env_proxy: bool = False,
) -> dict[str, Any]:
    parsed = urllib.parse.urlparse(target.base_url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    result: dict[str, Any] = {
        "target": target.to_public_dict(),
        "api_key_preview": _redacted_key(target.api_key),
        "dns": {"ok": False, "detail": ""},
        "tcp": {"ok": False, "detail": ""},
        "models": {"ok": False, "reachable": False, "detail": ""},
        "chat": None,
    }
    if not host:
        result["dns"] = {"ok": False, "detail": f"invalid base_url={target.base_url}"}
        result["ok"] = False
        return result

    try:
        ip = socket.gethostbyname(host)
        result["dns"] = {"ok": True, "detail": f"{host} -> {ip}"}
    except Exception as exc:  # noqa: BLE001
        result["dns"] = {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
        result["ok"] = False
        return result

    try:
        with socket.create_connection((host, port), timeout=timeout):
            result["tcp"] = {"ok": True, "detail": f"{host}:{port}"}
    except Exception as exc:  # noqa: BLE001
        result["tcp"] = {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
        result["ok"] = False
        return result

    models_url = f"{target.base_url.rstrip('/')}/models"
    result["models"] = _request(
        models_url,
        method="GET",
        api_key=target.api_key,
        timeout=timeout,
        use_env_proxy=use_env_proxy,
    )

    if chat:
        chat_url = f"{target.base_url.rstrip('/')}/chat/completions"
        result["chat"] = _request(
            chat_url,
            method="POST",
            api_key=target.api_key,
            timeout=timeout,
            use_env_proxy=use_env_proxy,
            body={
                "model": target.model,
                "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
                "max_tokens": 8,
                "temperature": 1,
            },
        )

    result["ok"] = bool(
        result["dns"]["ok"]
        and result["tcp"]["ok"]
        and result["models"]["reachable"]
        and (not chat or (result["chat"] or {}).get("ok"))
    )
    return result


def _select_targets(targets: list[ApiTarget], names: list[str]) -> list[ApiTarget]:
    if not names or names == ["all"]:
        return targets
    wanted = set(names)
    selected = [target for target in targets if target.name in wanted]
    missing = sorted(wanted - {target.name for target in selected})
    if missing:
        raise SystemExit(f"unknown target(s): {', '.join(missing)}")
    return selected


def _format_markdown(results: list[dict[str, Any]]) -> str:
    lines = [
        "# LLM API 连通性结果",
        "",
        "| 名称 | Model | DNS | TCP | /models | Chat |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in results:
        target = item["target"]
        models = item["models"]
        chat = item.get("chat")
        models_status = f"HTTP {models['status']}" if models.get("status") else models.get("detail", "")
        if chat is None:
            chat_status = "not run"
        else:
            chat_status = f"HTTP {chat['status']}" if chat.get("status") else chat.get("detail", "")
        lines.append(
            "| {name} | `{model}` | {dns} | {tcp} | {models} | {chat} |".format(
                name=target["name"],
                model=target["model"],
                dns="PASS" if item["dns"]["ok"] else "FAIL",
                tcp="PASS" if item["tcp"]["ok"] else "FAIL",
                models=models_status,
                chat=chat_status,
            )
        )
    return "\n".join(lines) + "\n"


def _print_results(results: list[dict[str, Any]]) -> None:
    for item in results:
        target = item["target"]
        print(f"\n[{target['name']}] {target['base_url']} model={target['model']}")
        print(f"  key: {item['api_key_preview']}")
        print(f"  dns: {'PASS' if item['dns']['ok'] else 'FAIL'} {item['dns']['detail']}")
        print(f"  tcp: {'PASS' if item['tcp']['ok'] else 'FAIL'} {item['tcp']['detail']}")
        models = item["models"]
        status = f"HTTP {models['status']}" if models.get("status") else models.get("detail", "")
        print(f"  /models: {'PASS' if models.get('reachable') else 'FAIL'} {status}")
        chat = item.get("chat")
        if chat is not None:
            chat_status = f"HTTP {chat['status']}" if chat.get("status") else chat.get("detail", "")
            print(f"  /chat/completions: {'PASS' if chat.get('ok') else 'FAIL'} {chat_status}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", action="append", default=[], help="target name to probe; repeatable; default all")
    parser.add_argument("--list", action="store_true", help="list configured targets and exit")
    parser.add_argument("--chat", action="store_true", help="also POST a minimal /chat/completions request")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--use-env-proxy", action="store_true", help="honor HTTP(S)_PROXY instead of direct connections")
    parser.add_argument("--json-output", type=Path, default=None)
    parser.add_argument("--markdown-output", type=Path, default=None)
    parser.add_argument("--soft-fail", action="store_true", help="always exit 0 after printing probe results")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    targets = default_targets()
    selected = _select_targets(targets, args.target)

    if args.list:
        print(json.dumps([target.to_public_dict() for target in selected], ensure_ascii=False, indent=2))
        return 0

    results = [
        probe_target(
            target,
            timeout=args.timeout,
            chat=args.chat,
            use_env_proxy=args.use_env_proxy,
        )
        for target in selected
    ]
    _print_results(results)

    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if args.markdown_output:
        args.markdown_output.parent.mkdir(parents=True, exist_ok=True)
        args.markdown_output.write_text(_format_markdown(results), encoding="utf-8")

    if args.soft_fail:
        return 0
    return 0 if all(item.get("ok") for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
