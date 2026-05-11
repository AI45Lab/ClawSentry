# skill-inject 运行手册

## 运行入口

skill-inject 原生入口包括 `experiments/contextual.py`、`experiments/obvious.py`、`experiments/utility_baseline.py` 与 `scripts/smoke_test_all.py`。以下章节只给出干跑和小样本入口。

## 安全默认值

- 默认不运行真实 agent；先用 `--dry-run` 或 `--smoke-test`。
- 不修改当前开发者 `~/.codex`、当前 `CODEX_HOME` 或 OMX/user hooks。
- ClawSentry hooks/gateway 只放在 benchmark 容器内 home 或临时 `CODEX_HOME`。
- 不提交 `docker/.env`、agent stdout 中的 key、provider endpoint 或 token。

## 环境准备

```bash
cd benchmarks/skill-inject
python -m venv .venv
source .venv/bin/activate
pip install -e .
cp docker/.env.example docker/.env  # 手工填需要的 key；不要提交
bash docker/build.sh
```

## 只读/干跑检查

```bash
cd benchmarks/skill-inject
python scripts/smoke_test_all.py --agent codex --model gpt-5.2-codex --dry-run
python experiments/contextual.py --agent codex --model gpt-5.2-codex --smoke-test --skip-eval --runtime docker
python experiments/obvious.py --agent codex --model gpt-5.2-codex --smoke-test --skip-eval --runtime docker
```

注意：`--smoke-test` 仍会构建 sandbox 并可能运行容器；只有 `smoke_test_all.py --dry-run` 是纯命令预览。

## raw-vs-protected 目录建议

把正式结果复制/归档到外层统一目录：

```text
benchmarks/results/skill-inject/<run-id>/
  config.json
  raw/
  clawsentry/
  static-scan/
  summary.json
  summary.md
```

不要长期依赖上游 `final_results/` 作为唯一索引；它适合上游 runner resume，但不适合作为跨 benchmark 总索引。

## ClawSentry 容器内接入建议

### Codex

在容器命令前设置临时 `CODEX_HOME`，只在该路径安装 ClawSentry hooks：

```bash
export CODEX_HOME=/tmp/clawsentry-codex-home
# install ClawSentry managed hooks into $CODEX_HOME only
python experiments/contextual.py --agent codex --model gpt-5.2-codex --smoke-test
```

### Claude Code / Gemini CLI

同样在容器内 home 或临时配置目录安装 hook/gateway 配置。不要复用宿主机当前 session 的配置目录。

### Gateway-only 模式

如果先验证 provider gateway，可把容器内模型 endpoint 指向 ClawSentry OpenAI-compatible gateway；但这不能覆盖 agent 本地 skill loading/hook 阶段，因此只能作为低门槛 smoke。

## 指标

保留原生指标：

- ASR / attack_success rate。
- task completion / utility。
- technical failure rate。
- judge verdict 与 evidence。

新增 ClawSentry 指标：

- static scan recall：含恶意 injection 的 skill package 是否被标记。
- runtime block/defer/modify rate。
- unsafe recall 与 safe false-positive rate。
- pre-action/post-action coverage。
- latency、timeout、retry、L2/L3 cost。

## 当前路线位置

按当前总路线，skill-inject 是第二阶段：在 `skills-safety-bench` 单 case / 单 RD 路线稳定后，优先做 static scan 和容器内 Codex 小样本。仍然不要修改宿主当前 `~/.codex` 或当前 `CODEX_HOME`；真实运行前先用 `--dry-run` / `--smoke-test` 控制 API 成本和技术失败。
