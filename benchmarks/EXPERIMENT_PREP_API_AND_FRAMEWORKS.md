# 实验前期准备：LLM API 与框架可用性清单

最后更新：2026-05-11

本文记录 benchmark 实验前需要确认的两类信息：

- LLM 调用 API：来源、`base_url`、model、key 状态、最近一轮可用性。
- 已安装框架/CLI：Codex、Claude Code、Gemini CLI、Kimi CLI、a3s-code 的安装状态和模型 smoke 结果。

安全约定：

- 明文 API key 只保留在本地配置或环境变量中。
- 本文档和结果文件只写 `<redacted>` 或 `<not configured>`。
- 不在当前活跃 `~/.codex`、`~/.claude`、`~/.gemini`、`~/.kimi` 中安装或修改 hook/config；本轮只做非破坏性 smoke。

## 使用优先级

| 场景 | 优先策略 |
| --- | --- |
| ailab 可用模型 | 优先使用 `ailab本地配置` 中最近测试可用的 API。 |
| GPT 系列模型 | 优先直接使用 Codex 已登录账号，不把 GPT key/base_url 写入 benchmark 配置。 |
| 博越 OpenAI-compatible 模型 | 使用 `http://35.220.164.252:3888/v1` 和本地 `agent.hcl` key；文档只记录 `<redacted>`。 |
| 长实验前 | 先运行 `benchmarks/scripts/api_connectivity.py --chat`，以最新结果为准。 |

## API 连通性脚本

列出当前登记的 LLM API：

```bash
python benchmarks/scripts/api_connectivity.py --list
```

测试所有登记 API 的连通性，并保存结果：

```bash
python benchmarks/scripts/api_connectivity.py --chat --soft-fail \
  --json-output benchmarks/results/api-connectivity/latest.json \
  --markdown-output benchmarks/results/api-connectivity/latest.md
```

默认走直连，不读取系统代理。内网/VPN endpoint 通常先用直连更可靠；确实需要代理时再加 `--use-env-proxy`。

脚本检查项：

| 检查项 | 含义 |
| --- | --- |
| DNS | 域名能否解析。 |
| TCP | host:port 能否建立连接。 |
| `GET /models` | OpenAI-compatible models endpoint 是否可访问。401/403 也说明 HTTP 路径可达，但 key 不可用或缺失。 |
| `POST /chat/completions` | 最小聊天请求是否能返回 2xx；这是能否实际调用模型的关键结果。 |

## 已登记的 LLM API

| 名称 | API 来源 | 最近测试可用 | 协议形态 | Base URL | Model | Key 状态 | Key 来源 | 备注 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `repo-agent-hcl` | 博越 | ✓ | OpenAI-compatible | `http://35.220.164.252:3888/v1` | `kimi-k2.5` | `<redacted>` | `agent.hcl` 本地值 | 当前仓库本地运行配置；脚本会读取 key 测试，但不会打印。 |
| `boyue-gemini-3-flash-preview` | 博越 | ✓ | OpenAI-compatible | `http://35.220.164.252:3888/v1` | `gemini-3-flash-preview` | `<redacted>` | `agent.hcl` 本地值 | 与 `repo-agent-hcl` 共用博越 base URL 和本地 key。 |
| `repo-example-kimi-k2.5` | 博越 | ✓ | OpenAI-compatible | `http://35.220.164.252:3888/v1` | `kimi-k2.5` | `<redacted>` | 与 `agent.hcl` 同 base URL 时继承本地 key | 修复后不再把同一 base URL 的示例 target 误判为未配置 key；chat HTTP 200。 |
| `user-minimax-2.7-w8a8` | ailab本地配置 | ✓ | OpenAI-compatible | `http://10.140.158.149:18027/v1` | `MiniMax-2.7-w8a8` | `<not configured>` | 未提供 | 原始 URL 带 `/v1/-MiniMax-2.7-w8a8`；脚本现在去掉 URL 分隔用的前导 `-`，chat HTTP 200。 |
| `user-minimax-2.7-w8a8-alt-15002` | ailab本地配置 | ✓ | OpenAI-compatible | `http://10.140.158.149:15002/v1` | `MiniMax-2.7-w8a8` | `<not configured>` | 未提供 | 15002 endpoint 可用；作为 18027 endpoint 的对照路径。 |
| `user-ailab-202603-glm-5-actual-5.1` | ailab本地配置 | ✓ | OpenAI-compatible | `http://s-20260304151647-c9kjf.ailab-pj.pjh-service.org.cn/v1` | `glm-5` | `<not configured>` | 未提供 | 用户说明：`glm-5` 实际为 5.1。 |
| `user-ailab-202603-kimi-k2.5` | ailab本地配置 | ✗ | OpenAI-compatible | `http://s-20260304151647-c9kjf.ailab-pj.pjh-service.org.cn/v1` | `kimi-k2.5` | `<not configured>` | 未提供 | 与上一个 endpoint 共用 base URL，换模型测试；chat HTTP 404。 |
| `user-ailab-202602-glm-5-actual-5.1` | ailab本地配置 | ✗ | OpenAI-compatible | `http://s-20260204175507-cqflp.ailab-pj.pjh-service.org.cn/v1` | `glm-5` | `<not configured>` | 未提供 | model 根据用户给出的相邻模型列表推断；chat HTTP 404。 |
| `user-ailab-202602-kimi-k2.5` | ailab本地配置 | △ | OpenAI-compatible | `http://s-20260204175507-cqflp.ailab-pj.pjh-service.org.cn/v1` | `kimi-k2.5` | `<not configured>` | 未提供 | 历史上通过；本轮 30s chat timeout，应在长实验前单独复测。 |

## 最新一轮可用 API 汇总

只收录最近一轮 `POST /chat/completions` 返回 HTTP 2xx 的条目。

| API 来源 | Base URL | Key | Model | 额外信息 |
| --- | --- | --- | --- | --- |
| 博越 | `http://35.220.164.252:3888/v1` | `<redacted>` | `kimi-k2.5` | 来自 `agent.hcl`；最近一轮 chat HTTP 200。 |
| 博越 | `http://35.220.164.252:3888/v1` | `<redacted>` | `gemini-3-flash-preview` | 最近一轮 chat HTTP 200。 |
| ailab本地配置 | `http://10.140.158.149:18027/v1` | `<not configured>` | `MiniMax-2.7-w8a8` | 修复 URL suffix 解析后最近一轮 chat HTTP 200。 |
| ailab本地配置 | `http://10.140.158.149:15002/v1` | `<not configured>` | `MiniMax-2.7-w8a8` | 最近一轮 chat HTTP 200。 |
| ailab本地配置 | `http://s-20260304151647-c9kjf.ailab-pj.pjh-service.org.cn/v1` | `<not configured>` | `glm-5` | 用户说明 `glm-5` 实际为 5.1；最近一轮 chat HTTP 200。 |

结果文件：

- JSON：`benchmarks/results/api-connectivity/2026-05-11.json`
- Markdown：`benchmarks/results/api-connectivity/2026-05-11.md`

## 已安装框架汇总

| 框架 | 安装状态 | 账号/认证状态 | 模型指定方式 | 备注 |
| --- | --- | --- | --- | --- |
| Codex | 已安装，`codex-cli 0.130.0` | `codex login status` 显示 `Logged in using ChatGPT` | `codex exec -m <model>` | GPT 系列优先用已登录账号；非 OpenAI 模型会被 ChatGPT 账号拒绝。 |
| Claude Code | 已安装，`2.1.119` | `claude auth status` 显示 `loggedIn: true`、`oauth_token` | `claude --model <model>` | Anthropic/Claude Code 协议可用；OpenAI-compatible endpoint 不能当作 Anthropic endpoint 直接塞给 Claude Code。 |
| Gemini CLI | 已安装，`0.25.0` | 存在缓存凭据，但本轮调用返回 Google Cloud API 未启用 403 | `gemini -m <model>` | 需要启用 `cloudaicompanion.googleapis.com` 或换可用 Gemini API 配置。 |
| Kimi CLI | 已安装，`1.41.0` | 存在 `~/.kimi/config.toml`；无明确 status 命令 | `kimi --model <model>` | `kimi/kimi-k2.6` 通过本地 `agent-hcl-openai` provider 可用；`kimi-k2.5` 绑定的 ailab 202602 endpoint 本轮失败。 |
| a3s-code | Python 包已安装，`a3s-code 1.7.2` | 非 CLI，未发现独立登录状态 | SDK transport / `Agent.create(...)` | 非 CLI 框架；实验中按 SDK/transport 集成，不按 CLI 登录模型测试。 |

## 框架与模型 Smoke 矩阵

测试 prompt 均为最小请求：`Reply exactly OK. Do not use tools.`

| 框架 | 模型/配置 | API 来源 | 测试结果 | 证据摘要 |
| --- | --- | --- | --- | --- |
| Codex | `gpt-5.4` | Codex 已登录账号 | ✓ 可用 | `codex exec -m gpt-5.4 ...` 返回 `OK`。 |
| Codex | `gpt-5.5` | Codex 已登录账号 | ✓ 可用 | `codex exec -m gpt-5.5 ...` 返回 `OK`。 |
| Codex | `glm-5` / `MiniMax-2.7-w8a8` | ailab OpenAI-compatible API | 不适用 | Codex 当前登录的是 ChatGPT/OpenAI provider；这些第三方模型应走 OpenAI-compatible API harness，而不是 `codex exec -m <third-party-model>`。 |
| Claude Code | `sonnet` | Claude Code OAuth | ✓ 可用 | `claude --bare --print --model sonnet ...` 返回 `OK.`。 |
| Claude Code | `glm-5` / `MiniMax-2.7-w8a8` + ailab base URL | ailab OpenAI-compatible API | 不适用 | 这些 endpoint 是 OpenAI-compatible，不是 Anthropic-compatible；直接改 `ANTHROPIC_BASE_URL` 会协议错配。 |
| Gemini CLI | `gemini-3-flash-preview` | Gemini CLI 登录/Google Cloud | ✗ 环境阻塞 | 返回 403：`Gemini for Google Cloud API ... disabled`；同名 OpenAI-compatible 模型在博越 API 直连可用。 |
| Kimi CLI | `kimi/kimi-k2.6` | 本地 `agent-hcl-openai` provider | ✓ 可用 | `kimi --print --final-message-only --model kimi/kimi-k2.6 ...` 返回 `OK`。 |
| Kimi CLI | `kimi-k2.5` | ailab 202602 OpenAI-compatible API | △ 远端/配置待复测 | `kimi --print --model kimi-k2.5 ...` 返回 502；同 endpoint 的直连 chat 本轮 timeout。 |
| a3s-code / ClawSentry LLM path | `kimi-k2.5`、`gemini-3-flash-preview`、`MiniMax-2.7-w8a8`、`glm-5` | OpenAI-compatible API | ✓ API 可用 | 使用 `CS_LLM_PROVIDER=openai`、`CS_LLM_BASE_URL`、`CS_LLM_MODEL` 走 provider path；本轮 direct chat smoke 为 2xx。 |

## ClawSentry 运行时环境变量

| 环境变量 | 用途 |
| --- | --- |
| `CS_LLM_PROVIDER` | `openai` 或 `anthropic`；OpenAI-compatible endpoint 填 `openai`。 |
| `CS_LLM_API_KEY` | 通用 LLM key，优先级高于 provider-specific key。 |
| `OPENAI_API_KEY` | `CS_LLM_PROVIDER=openai` 时的兼容 key 来源。 |
| `ANTHROPIC_API_KEY` | `CS_LLM_PROVIDER=anthropic` 时的兼容 key 来源。 |
| `CS_LLM_MODEL` | 模型名，例如 `kimi-k2.5`、`glm-5`、`MiniMax-2.7-w8a8`。 |
| `CS_LLM_BASE_URL` | 自定义 LLM API base URL。 |
| `CS_LLM_TEMPERATURE` | 可选 temperature。历史上 `kimi-k2.5` 更适合设为 `1`。 |
| `CS_LLM_PROVIDER_TIMEOUT_MS` | 可选 provider 请求超时。 |

## 仓库来源索引

| 内容 | 文件 |
| --- | --- |
| 当前本地 LLM 配置 | `agent.hcl` |
| 示例 LLM 配置 | `configs/agent.example.hcl` |
| Provider 抽象 | `src/clawsentry/gateway/llm_provider.py` |
| 环境变量解析 | `src/clawsentry/gateway/llm_settings.py` |
| Analyzer factory | `src/clawsentry/gateway/llm_factory.py` |
| AgentDoG benchmark env bridge | `benchmarks/scripts/agentdog_atbench_clawsentry.py` |
| 早期探索用 preflight | `explore_simulation_projects/api_connectivity_preflight.py` |
| Codex 集成 | `site-docs/integration/codex.md` |
| Claude Code 集成 | `site-docs/integration/claude-code.md` |
| Gemini CLI 集成 | `site-docs/integration/gemini-cli.md` |
| Kimi CLI 集成 | `site-docs/integration/kimi-cli.md` |
| a3s-code 集成 | `docs/guides/a3s-code-integration.md` |
