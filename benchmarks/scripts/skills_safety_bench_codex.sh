#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
BENCH_DIR="${WORKSPACE_ROOT}/skills-safety-bench"

RD=""
CASE_ID=""
CATEGORY=""
MODEL="${SSB_CODEX_MODEL:-openai/gpt-5.4}"
DEFENSE="raw"
REAL_RUN="0"
NETWORK_MODE_ARG=()
STRIP_PROXY_ENV="${SSB_STRIP_PROXY_ENV:-1}"
GUARD_HARBOR_CODEX_SETUP="${SSB_GUARD_HARBOR_CODEX_SETUP:-1}"
USE_CODEX_AUTH_JSON="${SSB_CODEX_AUTH_JSON:-0}"
FORCE_CODEX_API_KEY="${SSB_CODEX_FORCE_API_KEY:-1}"
SANITIZED_ENVRC=""
SANITIZED_CODEX_AUTH_JSON=""
SANITIZED_DOCKER_CONFIG=""
DRY_RUN_ENVRC=""
GUARDED_HARBOR_BIN_DIR=""

usage() {
  cat <<'EOF'
用法：
  bash scripts/skills_safety_bench_codex.sh --rd <1-6> [选项]

默认是 dry-run，不调用模型、不跑 Docker。真实执行必须显式加 --real-run。

选项：
  --rd <1-6>              选择 risk domain
  --case <case_id>        只跑一个 case
  --category <category>   只跑一个 category
  --model <model>         模型名，默认 $SSB_CODEX_MODEL 或 openai/gpt-5.4
  --defense <label>       结果目录标签，例如 raw 或 clawsentry
  --network-mode <mode>   传给上游 runner，例如 host
  --real-run              真实执行；不加时只 dry-run
  -h, --help              显示帮助

示例：
  bash scripts/skills_safety_bench_codex.sh --rd 1 --case travel_planning_skill_name_decoy_singular_alias
  bash scripts/skills_safety_bench_codex.sh --rd 1 --case travel_planning_skill_name_decoy_singular_alias --defense raw --real-run
EOF
}

die() {
  printf '错误：%s\n' "$*" >&2
  exit 1
}

sanitize_envrc_without_proxy() {
  local source_envrc=$1
  local target_envrc=$2
  python - "$source_envrc" "$target_envrc" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

source = Path(sys.argv[1])
target = Path(sys.argv[2])
proxy_assignment = re.compile(
    r"^\s*(?:export\s+)?(?:http_proxy|https_proxy|all_proxy|no_proxy|"
    r"HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY)\s*="
)
lines = source.read_text(encoding="utf-8").splitlines()
target.write_text(
    "\n".join(line for line in lines if not proxy_assignment.match(line)) + "\n",
    encoding="utf-8",
)
PY
}

write_codex_auth_json_from_envrc() {
  local source_envrc=$1
  local target_auth_json=$2
  bash - "$source_envrc" "$target_auth_json" <<'BASH'
set -euo pipefail
source_envrc=$1
target_auth_json=$2
set -a
# shellcheck source=/dev/null
source "${source_envrc}"
set +a
python - "$target_auth_json" <<'PY'
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

api_key = os.environ.get("OPENAI_API_KEY", "")
if not api_key:
    raise SystemExit("OPENAI_API_KEY is missing from sanitized envrc")
Path(sys.argv[1]).write_text(
    json.dumps({"OPENAI_API_KEY": api_key}, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
PY
BASH
}

patch_upstream_codex_task_staging() {
  local runner_path="${BENCH_DIR}/scripts/run_manifest_codex_batch.py"
  [[ -f "${runner_path}" ]] || return 0
  python - "${runner_path}" <<'PY'
from __future__ import annotations

import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

needle = '    original = dockerfile_path.read_text(encoding="utf-8")\n'
injection = '''    if "# SSB_CODEX_AGENT_SYSTEM_DEPS" not in original:
        lines = original.splitlines()
        for idx, line in enumerate(lines):
            if line.lstrip().startswith("FROM "):
                system_deps = """# SSB_CODEX_AGENT_SYSTEM_DEPS
RUN set -eux; \\
    apt-get update; \\
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ripgrep; \\
    rm -rf /var/lib/apt/lists/*
"""
                original = "\\n".join(lines[:idx + 1] + ["", system_deps.rstrip(), ""] + lines[idx + 1:]) + "\\n"
                dockerfile_path.write_text(original, encoding="utf-8")
                break

'''
if "SSB_CODEX_AGENT_SYSTEM_DEPS" not in text:
    if needle not in text:
        raise SystemExit(f"Could not patch upstream runner; missing needle in {path}")
    text = text.replace(needle, needle + injection)

harbor_needle = '        "harbor run -q",\n'
harbor_replacement = "        f\"{shlex.quote(os.environ.get('SSB_HARBOR_BIN', 'harbor'))} run -q\",\n"
broken_harbor_replacement = '        f"{shlex.quote(os.environ.get(\\"SSB_HARBOR_BIN\\", \\"harbor\\"))} run -q",\n'
if broken_harbor_replacement in text:
    text = text.replace(broken_harbor_replacement, harbor_replacement)
elif "SSB_HARBOR_BIN" not in text:
    if harbor_needle not in text:
        raise SystemExit(f"Could not patch upstream runner; missing harbor command needle in {path}")
    text = text.replace(harbor_needle, harbor_replacement)

path.write_text(text, encoding="utf-8")
PY
}

install_guarded_harbor_shim() {
  local harbor_path
  local harbor_python
  harbor_path="$(command -v harbor || true)"
  [[ -n "${harbor_path}" ]] || die "真实运行需要 harbor；可先执行：uv tool install harbor"
  harbor_python="$(head -n 1 "${harbor_path}" | sed 's/^#!//')"
  [[ -x "${harbor_python}" ]] || die "无法解析 harbor Python 解释器：${harbor_python}"

  GUARDED_HARBOR_BIN_DIR="$(mktemp -d)"
  cat > "${GUARDED_HARBOR_BIN_DIR}/harbor" <<EOF
#!/usr/bin/env bash
exec "${harbor_python}" "${SCRIPT_DIR}/harbor_codex_setup_guard.py" "\$@"
EOF
  chmod +x "${GUARDED_HARBOR_BIN_DIR}/harbor"
  export SSB_HARBOR_BIN="${GUARDED_HARBOR_BIN_DIR}/harbor"
  export PATH="${GUARDED_HARBOR_BIN_DIR}:${PATH}"
}

require_value() {
  local flag=$1
  local value=${2-}
  [[ -n "${value}" ]] || die "${flag} 需要参数值"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --rd)
      require_value "$1" "${2-}"
      RD="$2"
      shift 2
      ;;
    --case)
      require_value "$1" "${2-}"
      CASE_ID="$2"
      shift 2
      ;;
    --category)
      require_value "$1" "${2-}"
      CATEGORY="$2"
      shift 2
      ;;
    --model)
      require_value "$1" "${2-}"
      MODEL="$2"
      shift 2
      ;;
    --defense)
      require_value "$1" "${2-}"
      DEFENSE="$2"
      shift 2
      ;;
    --network-mode)
      require_value "$1" "${2-}"
      NETWORK_MODE_ARG=(--network-mode "$2")
      shift 2
      ;;
    --real-run)
      REAL_RUN="1"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "未知参数：$1"
      ;;
  esac
done

[[ -n "${RD}" ]] || die "缺少 --rd <1-6>"
[[ "${RD}" =~ ^[1-6]$ ]] || die "--rd 必须是 1 到 6"
[[ -d "${BENCH_DIR}" ]] || die "找不到 ${BENCH_DIR}"

short_commit="$(git -C "${BENCH_DIR}" rev-parse --short HEAD)"
date_tag="$(date +%F)"
model_tag="${MODEL##*/}"
model_tag="${model_tag//[^A-Za-z0-9._-]/_}"
scope="rd${RD}"
if [[ -n "${CASE_ID}" ]]; then
  scope="case-${CASE_ID}"
elif [[ -n "${CATEGORY}" ]]; then
  scope="category-${CATEGORY}"
fi

run_dir="${WORKSPACE_ROOT}/results/skills-safety-bench/${date_tag}_${model_tag}_codex_${DEFENSE}_${scope}_${short_commit}"
mkdir -p "${run_dir}"

cmd=(
  bash "${BENCH_DIR}/scripts/start_agent_batch.sh"
  --rd "${RD}"
  --jobs-dir "${run_dir}"
  --agent codex
  --model "${MODEL}"
)

if [[ -n "${CASE_ID}" ]]; then
  cmd+=(--case "${CASE_ID}")
fi
if [[ -n "${CATEGORY}" ]]; then
  cmd+=(--category "${CATEGORY}")
fi
if [[ "${#NETWORK_MODE_ARG[@]}" -gt 0 ]]; then
  cmd+=("${NETWORK_MODE_ARG[@]}")
fi

if [[ "${REAL_RUN}" != "1" ]]; then
  if [[ ! -f "${BENCH_DIR}/.envrc" ]]; then
    mkdir -p "${run_dir}/runtime"
    DRY_RUN_ENVRC="${run_dir}/runtime/dry-run.envrc"
    cat > "${DRY_RUN_ENVRC}" <<'EOF'
export OPENAI_API_KEY=dry-run-placeholder
EOF
    cmd+=(--envrc "${DRY_RUN_ENVRC}")
  fi
  cmd+=(--dry-run --skip-api-preflight)
else
  if [[ -d "${HOME}/.nvm" ]]; then
    export NVM_DIR="${HOME}/.nvm"
    # shellcheck source=/dev/null
    [[ -s "${NVM_DIR}/nvm.sh" ]] && . "${NVM_DIR}/nvm.sh" && nvm use 22 >/dev/null || true
  fi
  command -v harbor >/dev/null 2>&1 || die "真实运行需要 harbor；可先执行：uv tool install harbor"
  command -v docker >/dev/null 2>&1 || die "真实运行需要 docker"
  if [[ "${STRIP_PROXY_ENV}" == "1" || "${STRIP_PROXY_ENV}" == "true" || "${STRIP_PROXY_ENV}" == "yes" ]]; then
    SANITIZED_ENVRC="$(mktemp)"
    SANITIZED_DOCKER_CONFIG="$(mktemp -d)"
    trap '[[ -z "${SANITIZED_ENVRC}" ]] || rm -f "${SANITIZED_ENVRC}"; [[ -z "${SANITIZED_CODEX_AUTH_JSON}" ]] || rm -f "${SANITIZED_CODEX_AUTH_JSON}"; [[ -z "${SANITIZED_DOCKER_CONFIG}" ]] || rm -rf "${SANITIZED_DOCKER_CONFIG}"; [[ -z "${GUARDED_HARBOR_BIN_DIR}" ]] || rm -rf "${GUARDED_HARBOR_BIN_DIR}"' EXIT
    sanitize_envrc_without_proxy "${BENCH_DIR}/.envrc" "${SANITIZED_ENVRC}"
    if [[ "${USE_CODEX_AUTH_JSON}" == "1" || "${USE_CODEX_AUTH_JSON}" == "true" || "${USE_CODEX_AUTH_JSON}" == "yes" ]]; then
      SANITIZED_CODEX_AUTH_JSON="$(mktemp)"
      write_codex_auth_json_from_envrc "${SANITIZED_ENVRC}" "${SANITIZED_CODEX_AUTH_JSON}"
      export CODEX_AUTH_JSON_PATH="${SANITIZED_CODEX_AUTH_JSON}"
    fi
    printf '{}\n' > "${SANITIZED_DOCKER_CONFIG}/config.json"
    cmd+=(--envrc "${SANITIZED_ENVRC}")
    export DOCKER_CONFIG="${SANITIZED_DOCKER_CONFIG}"
    unset http_proxy https_proxy all_proxy no_proxy
    unset HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY
  fi
  if [[ "${FORCE_CODEX_API_KEY}" == "1" || "${FORCE_CODEX_API_KEY}" == "true" || "${FORCE_CODEX_API_KEY}" == "yes" ]]; then
    export CODEX_FORCE_API_KEY=1
  fi
  if [[ "${GUARD_HARBOR_CODEX_SETUP}" == "1" || "${GUARD_HARBOR_CODEX_SETUP}" == "true" || "${GUARD_HARBOR_CODEX_SETUP}" == "yes" ]]; then
    patch_upstream_codex_task_staging
    install_guarded_harbor_shim
  fi
fi

{
  printf '# skills-safety-bench 运行记录\n\n'
  printf '%s\n' "- 日期：\`${date_tag}\`"
  printf '%s\n' "- commit：\`${short_commit}\`"
  printf '%s\n' "- 模型：\`${MODEL}\`"
  printf '%s\n' "- 框架：\`codex\`"
  printf '%s\n' "- 防御标签：\`${DEFENSE}\`"
  printf '%s\n' "- 模式：\`$([[ "${REAL_RUN}" == "1" ]] && printf real-run || printf dry-run)\`"
  printf '%s\n\n%s\n' "- 命令：" '```bash'
  printf '%q ' "${cmd[@]}"
  printf '\n```\n'
} > "${run_dir}/run.md"

printf '结果目录：%s\n' "${run_dir}"
printf '执行命令：'
printf ' %q' "${cmd[@]}"
printf '\n'

"${cmd[@]}"
