# Kimi CLI 集成

!!! tip "支持范围"
    Kimi CLI 通过 native `[[hooks]]` 接入 ClawSentry。它能在 `PreToolUse` 阶段阻断高危工具调用，也能在 `UserPromptSubmit` 阶段阻断 prompt 注入或敏感请求；同时会记录工具结果、会话、子代理、压缩和通知等生命周期事件。Kimi 原生 hook 目前不支持真正改写 tool input，也不提供可暂停等待人工审批的 native defer，因此 ClawSentry 不把它宣传成 `a3s-code` AHP 的等价 transport。

## 安装与初始化

Kimi 默认读取 `$KIMI_SHARE_DIR/config.toml`；未设置时读取 `~/.kimi/config.toml`。ClawSentry 只管理包含 `clawsentry harness --framework kimi-cli` marker 的 hook blocks，保留用户自己的 `[[hooks]]` 和其他 TOML 设置。

```bash
clawsentry init kimi-cli
clawsentry init kimi-cli --setup --dry-run
clawsentry init kimi-cli --setup
clawsentry gateway
kimi --help
```

安全预览或隔离测试时，显式传入 Kimi share/config 目录：

```bash
export KIMI_SHARE_DIR=/tmp/kimi-clawsentry-check
clawsentry init kimi-cli --setup --dry-run --kimi-home "$KIMI_SHARE_DIR"
clawsentry init kimi-cli --setup --kimi-home "$KIMI_SHARE_DIR"
```

Setup 生成的 managed hook command 会带上 Skill Trust 运行时默认路径：`CS_KIMI_SKILLS_DIR`、`CS_SKILL_TRUST_REGISTRY_PATH` 和 `CS_SKILL_TRUST_METADATA_PATH`。如果该 env 指向的 metadata 文件还不存在，harness 会继续按当前项目 `cwd` 向上查找 `.clawsentry/skill-trust-runtime.json`，因此隔离 benchmark、项目级注册和用户级 Kimi home 可以共用同一套 Gateway 风险上下文。

!!! note "KIMI_SHARE_DIR 与 metadata 路径回退"
    若 `KIMI_SHARE_DIR` 未设置，harness 会读取 `~/.kimi/config.toml`；若 metadata 路径不存在，Gateway 会从当前项目 `cwd` 向上查找 `.clawsentry/skill-trust-runtime.json`。

## Hook 覆盖范围

| Kimi hook | ClawSentry 命令 | 支持语义 | 适合用途 |
|---|---|---|---|
| `PreToolUse` | `clawsentry harness --framework kimi-cli` | allow / deny | 工具执行前阻断高危 shell、文件或外部调用 |
| `UserPromptSubmit` | `clawsentry harness --framework kimi-cli` | allow / deny | prompt 注入或敏感请求进入模型前阻断 |
| `Stop` | `clawsentry harness --framework kimi-cli` | allow / deny；没有完整 continuation 语义 | 会话结束前的同步 gate |
| `PostToolUse` / `PostToolUseFailure` | `clawsentry harness --framework kimi-cli --async` | observation only | 工具结果与失败审计；不能撤销副作用 |
| `SessionStart` / `SessionEnd` | `clawsentry harness --framework kimi-cli --async` | observation only | 会话边界审计 |
| `SubagentStart` / `SubagentStop` | `clawsentry harness --framework kimi-cli --async` | observation only | 子代理生命周期审计 |
| `PreCompact` / `PostCompact` | `clawsentry harness --framework kimi-cli --async` | observation only | 压缩前后上下文风险观察 |
| `Notification` | `clawsentry harness --framework kimi-cli --async` | observation only | 通知事件审计 |

Gateway 不可达、fallback policy 生效，或 harness 进程本身启动失败时，Kimi native hooks 默认 fail-open，避免把开发工作流整体卡死。同步 gate 返回 Kimi 支持的 `hookSpecificOutput.permissionDecision = "deny"`；ClawSentry 的 `defer` 会按阻断结果呈现，`modify` 只会记录降级结果，不会改写 Kimi 的工具输入。

## Shell tool 规范化

Kimi 的工具名会保留在 payload 中，同时对已知 shell aliases 规范化为 policy-facing `bash`，以复用现有 shell 风险评分与 `rm -rf` / `sudo` 等策略：

- `payload.tool_name`: `bash`
- `payload.kimi_tool_name`: 原始 Kimi 工具名，例如 `Shell`
- `payload._clawsentry_meta.raw_tool_name`: 原始工具名
- `payload._clawsentry_meta.kimi_effect_capability`: `native_allow_block_only`

当 tool command 或 prompt 文本能匹配已注册 skill 时，payload 还会包含 replay-safe 的 Skill Trust 摘要，例如 presented name、canonical identity、framework、scope、metadata source 和 skill root hash。原始 skill root path 只用于 Gateway 内部 first-use scan，不写入公开 replay。

## 能力边界

Kimi 集成面向用户时可以这样理解：

- **可以阻断 prompt**：`UserPromptSubmit` 返回 deny 时，请求不会继续进入模型。
- **可以阻断危险工具调用**：`PreToolUse` 返回 deny 时，高危 Shell / 文件 / 外部调用会在执行前停止。
- **可以观察生命周期事件**：post-tool、session、subagent、compact、notification 事件会进入审计与 Web UI 观察面。
- **不能原生修改 tool input**：Kimi hook 没有 ClawSentry `modify` 所需的 payload rewrite transport。
- **不能提供真正 native defer**：需要人工审批语义时，应使用支持 defer 的接入路径，或把 Kimi 结果作为 deny / observation 处理。

发布前的验证证据保留在 release evidence / validation 文档中；本用户页只描述可依赖的运行时能力和边界。

## 框架能力对比

| 能力 | Claude Code | a3s-code | Kimi CLI | Gemini CLI |
|---|---|---|---|---|
| PreToolUse 同步阻断 | ✅ | ✅ | ✅ | ✅ |
| UserPromptSubmit 阻断 | ✅ | ✅ | ✅ | ✅ |
| Modify tool input | ✅ | ✅ | ❌ | ❌ |
| Native DEFER（人工审批）| ✅ | ✅ | ❌ | ❌ |
| Post-action 观察 | ✅ | ✅ | ✅ | ✅ |

## 诊断

```bash
clawsentry integrations status --json
clawsentry start --framework kimi-cli --no-watch
```

`integrations status` 会报告：

- `kimi_cli_config_path` / `kimi_cli_config_present`：当前诊断到的 Kimi `config.toml`。
- `kimi_cli_hooks`：是否找到 ClawSentry marker-managed hook entries。
- `framework_readiness.kimi-cli.checks.native_modify_supported = false`。
- `framework_readiness.kimi-cli.checks.native_defer_supported = false`。

## 卸载

只移除 ClawSentry managed `[[hooks]]` blocks，保留用户自己的 Kimi hooks 和其他 TOML 设置：

```bash
clawsentry init kimi-cli --uninstall
clawsentry init kimi-cli --uninstall --kimi-home /tmp/kimi-clawsentry-check
```

## 边界声明

- 不 patch Kimi internals；只使用公开 config hook surface。
- 不声明 `a3s-code` AHP transport parity；`a3s-code` 仍是 explicit SDK transport reference path。
- Kimi post/session/subagent/compact/notification hooks 是观察面，不提供 side-effect rollback。
- 生产前建议先在隔离 `KIMI_SHARE_DIR` 下预览 managed hook 配置，再修改真实 `~/.kimi/config.toml`。
