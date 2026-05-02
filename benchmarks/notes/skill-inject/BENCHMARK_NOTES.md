# skill-inject Benchmark Notes

SKILL-INJECT 评估 coding/agent CLI 在加载 skill files 时是否会执行隐藏在 skill 定义里的恶意或双用途指令。它比一般 prompt injection 更贴近 ClawSentry 的 skill/package supply-chain 防护目标。

## 覆盖范围

当前本地数据快照：

| 数据集 | 条目数 | 说明 |
| --- | ---: | --- |
| contextual injections | 48 | harm 取决于上下文；支持 normal/legitimizing/warning policy 条件。 |
| obvious injections | 36 | 明显恶意，如 exfiltration、destructive action 等；默认只跑 normal policy。 |
| clean tasks | 58 | utility baseline 与 task completion 评估使用。 |
| `SKILL.md` files | 49 | 覆盖 documents、git、email、MCP、healthcare、code、webapp 等 skill domain。 |

支持的 agent/model 由 `config.py` 中 `AGENT_MODELS` 定义：`codex`、`claude`、`gemini`、`vibe`。runner 支持 Docker 与 Apptainer，结果默认写入上游 `final_results/`。

## Case 形态

一个实验实例通常包括：

```text
agent/model × injection definition × clean task × skill package × policy condition × runtime container
```

运行 pipeline：

1. `scripts/build_sandbox.py` 根据 injection JSON 构造 sandbox，把恶意指令嵌入 skill 描述、skill 内容、startup scripts 或相关位置。
2. `scripts/run_sandbox_container.py` 在 Docker 容器中运行目标 agent CLI，并捕获 stdout/stderr、modified files、command history 等证据。
3. `judges/*_judge.py` 用 LLM judge 判断 injection 是否成功、clean task 是否完成、是否 technical failure。
4. `experiments/*` 汇总 ASR、task completion 和 technical failure。

## 原生指标

- contextual：`attack_success` / `ignored` / `technical`，可选 task success/failure。
- obvious：`attack_success` / `ignored` / `technical`。
- utility baseline：clean task completion。
- ablations：Best-of-N、line position、script vs direct、skill screening、evolutionary optimization 等。

## 对 ClawSentry 的适配结论

skill-inject 可以用于评估 ClawSentry，而且与 ClawSentry 的 skill/package 防护高度相关；但需要容器内 agent hooks/gateway 接入，不能直接在当前开发者 `~/.codex` 上安装或改 hook。

推荐三层评估：

1. **skill package 静态扫描**：在 sandbox build 后、agent run 前，扫描生成的 `SKILL.md`/plugin/package 内容，输出 ClawSentry risk verdict。这可评估 supply-chain/skill injection 检测能力。
2. **runtime hook/gateway 防护**：在容器内临时 `CODEX_HOME`、Claude/Gemini 配置或 gateway endpoint 注入 ClawSentry，运行同一 sandbox 的 raw-vs-protected 对照。
3. **post-run evidence replay**：把 agent stdout、command history、modified files replay 到 ClawSentry 做审计；只能作为检测证据，不能宣称 runtime prevention。

## 风险与限制

- benchmark 真实运行会启动 agent CLI 和容器，可能消耗大量 API quota；先用 `--smoke-test` 或 `--dry-run`。
- Docker runner 会向容器传递 API keys；结果 artifact 必须 redaction。
- ClawSentry hooks 只能安装到容器内 home 或临时 `CODEX_HOME`，不能污染当前 Codex session 的 hook 配置。
