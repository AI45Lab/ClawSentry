# Gemini CLI 集成

<div class="cs-doc-hero" markdown>
<div class="cs-eyebrow">Integration · Gemini CLI</div>

## Gemini CLI 安全集成

ClawSentry 通过 native command hooks 接入 Gemini CLI，写入项目级 `.gemini/settings.json`，覆盖 session、prompt/model、tool preflight 和 tool result review 等阶段。v0.7.5 起 managed hook command 包含 Skill Trust runtime metadata 路径默认值。

<div class="cs-pill-row" markdown>
<span class="cs-pill">BeforeTool 同步阻断</span>
<span class="cs-pill">项目级 settings.json</span>
<span class="cs-pill">Skill Trust v0.7.5</span>
</div>
</div>

!!! tip "支持范围"
    Gemini CLI 通过 native command hooks 接入 ClawSentry。默认 setup 写入项目级 `.gemini/settings.json`，覆盖 session、prompt/model、tool preflight 和 tool result review 等阶段。自定义 provider 或代理前，请先确认它兼容 Gemini CLI 所需接口。

## 安装与初始化

默认 setup 只写项目级 `.gemini/settings.json`，不会修改真实用户 `~/.gemini`：

```bash
clawsentry init gemini-cli
clawsentry init gemini-cli --setup --dry-run
clawsentry init gemini-cli --setup
clawsentry start --env-file .clawsentry.env.local
clawsentry gateway
gemini --prompt "say hello"
```

如确实需要写某个用户级 Gemini 配置目录，必须显式传入路径：

```bash
clawsentry init gemini-cli --setup --gemini-home /tmp/safe-gemini-home
```

### `.gemini/settings.json` hook 格式

`clawsentry init gemini-cli --setup` 生成的 managed hook 条目格式如下：

```json
{
  "hooks": {
    "BeforeTool": [
      {
        "command": "clawsentry harness --framework gemini-cli CS_SKILL_TRUST_REGISTRY_PATH=.clawsentry/skill-trust-registry.json CS_SKILL_TRUST_METADATA_PATH=.clawsentry/skill-trust-runtime.json"
      }
    ],
    "AfterTool": [
      {
        "command": "clawsentry harness --framework gemini-cli"
      }
    ],
    "BeforeAgent": [
      {
        "command": "clawsentry harness --framework gemini-cli"
      }
    ]
  }
}
```

!!! note "Skill Trust runtime metadata binding（v0.7.5）"
    `clawsentry init gemini-cli --setup` 生成的 managed hook command 现在包含 `CS_SKILL_TRUST_REGISTRY_PATH` 和 `CS_SKILL_TRUST_METADATA_PATH` 环境变量默认值。若 metadata 文件不存在，harness 会自动回退，按 Gemini hook payload 的 `cwd` 向上查找 `.clawsentry/skill-trust-runtime.json`。

## Hook 覆盖范围

| Gemini hook | ClawSentry 命令 | 支持语义 | 适合用途 |
|---|---|---|---|
| `SessionStart` / `SessionEnd` | `clawsentry harness --framework gemini-cli --async` | 生命周期观察 / advisory | 审计会话边界 |
| `BeforeAgent` | `clawsentry harness --framework gemini-cli` | prompt 前置 gate / context 修改 | prompt 进入模型前的策略检查 |
| `BeforeModel` | `clawsentry harness --framework gemini-cli` | model request gate / 修改 | 模型请求前的策略检查 |
| `AfterAgent` / `AfterModel` | `clawsentry harness --framework gemini-cli` | response review / containment | fixture + harness supported |
| `BeforeTool` | `clawsentry harness --framework gemini-cli` | tool preflight deny / rewrite | 工具执行前阻断或改写 |
| `AfterTool` | `clawsentry harness --framework gemini-cli` | result review；不能撤销副作用 | 工具结果审查与 containment |
| `BeforeToolSelection` | `clawsentry harness --framework gemini-cli --async` | partial / degraded tool-selection advisory | fixture supported |
| `PreCompress` / `Notification` | `clawsentry harness --framework gemini-cli --async` | advisory observation | fixture supported |

Gateway 不可达、fallback policy 生效，或 `clawsentry harness` 进程本身启动失败时，Gemini native hook 默认 fail-open，避免把开发工作流整体卡死。安装器生成的 managed command 会把 hook 诊断写入 `CS_HARNESS_DIAG_LOG`（未设置时丢弃），避免 Gemini CLI 把普通 stderr 文本误解析成 hook 输出。

Skill Trust metadata 会优先读取 `CS_SKILL_TRUST_METADATA_PATH`，同时按 Gemini hook payload 的 `cwd` 向上查找项目 `.clawsentry/skill-trust-runtime.json` 作为 fallback。匹配到注册 skill 时，Gateway 可以使用真实 skill root path 执行 first-use scan；session replay 只保留 presented/canonical labels、framework/scope、metadata source 和 skill root hash。

## Gemini shell tool 规范化

真实 Gemini CLI 在 shell 执行前会把工具名上报为 `run_shell_command`。ClawSentry 在 Gemini adapter 中将已知 shell aliases 规范化为 policy-facing `bash`，并在 payload 中保留原始字段：

- `payload.tool_name`: `bash`
- `payload.gemini_tool_name`: `run_shell_command`
- `payload._clawsentry_meta.raw_tool_name`: `run_shell_command`

这样既不会丢失 Gemini 原始审计信息，又能复用已有的 shell 风险评分、`rm -rf`/`sudo` 等阻断规则。

!!! note "自定义 provider 兼容性"
    使用自定义 provider 或代理时，请确认它兼容 Gemini CLI 所需接口；ClawSentry 的 hook 集成与具体 LLM provider 无关，但 Gemini CLI 本身的 provider 配置需要单独验证。

## 诊断

```bash
clawsentry integrations status --json
clawsentry doctor
```

`doctor` 会检查：

- `GEMINI_CONFIG`：`CS_AUTH_TOKEN`、`CS_GEMINI_HOOKS_ENABLED` 等项目 env 是否齐全。
- `GEMINI_NATIVE_HOOKS`：`.gemini/settings.json` 是否启用 hooks，并包含 ClawSentry managed sync/async hook 形态。

## 卸载

只移除 ClawSentry managed entries，保留用户自己的 Gemini hooks 和其他设置：

```bash
clawsentry init gemini-cli --uninstall
```
