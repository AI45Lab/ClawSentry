# skills-safety-bench 运行手册

## 当前可用状态

RD1-RD6 的 dry-run 已验证。2026-04-21 已安装 Harbor 并推进到真实 Codex RD1 单 case 执行。2026-04-22 已通过本地 wrapper guard 绕过 Harbor Codex setup 的容器内 `apt-get install curl ripgrep` exit 137；当前阻塞转移到 Codex CLI provider reconnect timeout，尚未得到有效 `/app/output/itinerary.json`。

2026-04-20 的环境检查：

| 依赖 | 观察结果 |
| --- | --- |
| Python | `3.12.7` |
| uv | `0.11.5` |
| Docker client/server | `29.1.5` |
| 当前 Node | `v20.18.1` |
| 已安装 Node 22 | `v22.22.2` |
| Harbor | 已通过 `uv tool install harbor` 安装，CLI 可用 |


### 2026-04-21 真实执行进展

已完成：

- `uv tool install harbor`，`harbor --version` = `0.4.0`。
- wrapper 真实执行时自动 `nvm use 22`。
- 已单独 `docker pull python:3.11-slim` 成功。
- `benchmarks/scripts/skills_safety_bench_codex.sh` 默认过滤 proxy env，并使用临时干净 `DOCKER_CONFIG`，避免 Docker build 继承宿主 `~/.docker/config.json` 中不可达的 `127.0.0.1:7897` proxy。
- RD1 单 case real-run 已进入 Harbor agent setup。

当前阻塞：

- 原 Harbor agent setup `apt-get update && apt-get install -y curl ripgrep` exit 137 已通过 wrapper guard 绕过：task Dockerfile staging 会预装 `curl` / `ripgrep`，Harbor Codex setup 检测依赖存在时跳过重复 apt。
- wrapper 默认使用 `CODEX_FORCE_API_KEY=1`，并通过 Docker env inheritance 传递 `OPENAI_API_KEY`，避免密钥值出现在进程 argv。
- 当前真实执行可进入 Codex agent execution，但 Codex CLI 对 OpenAI-compatible provider 持续 reconnect timeout；`--network-mode host` 复测仍超时。下一步先诊断 Codex CLI/provider endpoint/model 兼容性，不要扩展到全 RD。

重试建议：

```bash
export PATH="$HOME/.local/bin:$PATH"
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
nvm use 22
bash benchmarks/scripts/skills_safety_bench_codex.sh \
  --rd 1 \
  --case travel_planning_skill_name_decoy_singular_alias \
  --defense raw-api-inherit \
  --real-run
```

## 真实运行前需要准备

切换 Node 22：

```bash
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
nvm use 22
```

安装或暴露 Harbor：

```bash
uv tool install harbor
```

确认依赖：

```bash
harbor --help
python3 --version
docker info
node --version
```

## 最方便的本地入口

默认 dry-run，不调用模型：

```bash
bash scripts/skills_safety_bench_codex.sh \
  --rd 1 \
  --case travel_planning_skill_name_decoy_singular_alias
```

真实跑一个 Codex smoke case：

```bash
bash scripts/skills_safety_bench_codex.sh \
  --rd 1 \
  --case travel_planning_skill_name_decoy_singular_alias \
  --defense raw \
  --real-run
```

真实跑 ClawSentry 防御后的 Codex smoke case：

```bash
bash scripts/skills_safety_bench_codex.sh \
  --rd 1 \
  --case travel_planning_skill_name_decoy_singular_alias \
  --defense clawsentry \
  --real-run
```

注意：`--defense` 只是结果目录标签。真正是否经过 ClawSentry，取决于 `.envrc` 或 shell 环境中的 `OPENAI_BASE_URL` / `OPENAI_API_KEY` 是否指向 ClawSentry gateway。

## 上游原生命令

单 case dry-run：

```bash
bash skills-safety-bench/scripts/start_codex_batch.sh \
  --rd 1 \
  --case travel_planning_skill_name_decoy_singular_alias \
  --jobs-dir /tmp/ssb-dry-run-rd1-case \
  --dry-run \
  --skip-api-preflight
```

整个 risk domain dry-run：

```bash
bash skills-safety-bench/scripts/start_codex_batch.sh \
  --rd 1 \
  --jobs-dir /tmp/ssb-dry-run-rd1 \
  --dry-run \
  --skip-api-preflight
```

真实运行时去掉 `--dry-run --skip-api-preflight`，并把 `--jobs-dir` 指向 `results/skills-safety-bench/<run-id>/`。

## 四个框架的落地判断

| 目标 | 当前能否直接一键跑 | 需要补什么 |
| --- | --- | --- |
| Codex 裸执行 | 可以走现有 Harbor/Codex runner，但需先安装 Harbor | Node 22、Harbor、模型 endpoint |
| Codex + ClawSentry | 可以走同一 runner，但 endpoint 需指向 ClawSentry gateway | 启动 ClawSentry gateway，并配置 `.envrc` |
| Claude Code 裸执行 | 尚不能确认一键跑 | Claude Code runner/Harbor backend/适配器 |
| Claude Code + ClawSentry | 尚不能确认一键跑 | Claude Code runner + ClawSentry endpoint 配置 |
| OpenClaw 裸执行 | 尚不能确认一键跑 | OpenClaw runner/适配器 |
| OpenClaw + ClawSentry | 尚不能确认一键跑 | OpenClaw runner + ClawSentry endpoint 配置 |
| A3S-Code 裸执行 | 尚不能确认一键跑 | A3S-Code runner/适配器 |
| A3S-Code + ClawSentry | 尚不能确认一键跑 | A3S-Code runner + ClawSentry endpoint 配置 |

## 对 ClawSentry 的测试方式

建议使用同一批 case 做 A/B：

1. `raw`：框架直接访问模型 endpoint。
2. `clawsentry`：框架访问 ClawSentry gateway，ClawSentry 再访问模型 endpoint。

对比指标：

- `attack_success` 数量和 ASR。
- `task_output_missing` 数量。
- `evaluator_error` 数量。
- 基础任务完成率。
- 运行成本、超时、重试次数。
