---
title: 快速开始
description: 5 分钟内启动 ClawSentry 并对接 AI Agent 框架
---

# 快速开始

<section class="cs-doc-hero cs-doc-hero--quickstart" markdown>
<div class="cs-eyebrow">Quickstart</div>

## 5 分钟启动 Gateway、Web UI 与框架接入

选择你使用的 AI 框架，先启动 ClawSentry Gateway，再打开 Web UI。首次体验可以不接 LLM；团队或安全敏感仓库建议直接按 L2/L3-ready 路径配置 provider、token budget 与审计存储。

<div class="cs-actions" markdown>
[选择框架](#framework-capabilities){ .md-button .md-button--primary }
[查看 API Reference](../api/reference.md){ .md-button }
[Web 仪表板说明](../dashboard/index.md){ .md-button }
</div>
</section>


## 先选择一条路径：观察优先，还是 L2/L3 就绪 {#choose-first-path}

ClawSentry 的推荐新手路径不再把 “永远不接 LLM” 当成默认终点。你可以先用观察模式确认 Gateway / Web UI / 框架接入正常；如果你的目标是团队值守、语义分析或 L3 审查，请直接走 L2/L3-ready 路径，并把 provider、token budget 与延迟预期一次讲清。

<div class="cs-before-after" markdown>

<div markdown>
### 路径 A：观察优先 / 不接 LLM

适合第一次验证安装、Web UI 登录、framework/session/workspace 分组。不会调用外部 provider，也不会改变 Codex 默认拦截语义。

```bash
pip install clawsentry
clawsentry config wizard --interactive
clawsentry start --framework codex --open-browser
```

你会看到 Gateway 地址、Web UI token、`watch` 事件流和 L1 风险分。
</div>

<div markdown>
### 路径 B：推荐的 L2/L3-ready operator 路径

适合团队仓库、安全敏感项目或希望 Dashboard 显示语义/审查结果的用户。密钥只放环境变量，预算显式打开。

```bash
export CS_LLM_API_KEY = <api-key>
clawsentry config wizard --non-interactive \
  --mode strict \
  --llm-provider openai \
  --llm-model gpt-4o-mini \
  --l2 --l3 \
  --token-budget 200000 \
  --write-project-config
clawsentry test-llm --json
clawsentry start --framework codex --open-browser
```

你会看到 L2/L3 可用性、token budget 来源、Dashboard 的 L3 advisory / risk summary 字段。
</div>

</div>

!!! note "`config wizard` 的两种运行方式"
    本地终端推荐 `clawsentry config wizard --interactive`，它会用 5 步画面询问 framework、mode、LLM、L2/L3 与 token budget。CI、脚本和文档复制命令继续使用 `--non-interactive`，以保证输出可复现。

---

## 运行后确认什么 {#verify-first-run}

```bash
clawsentry config show --effective
curl http://127.0.0.1:8080/health
```

| 你要确认 | 观察优先路径 | L2/L3-ready 路径 | 在哪里看 |
|---|---|---|---|
| Gateway 存活 | `status=healthy` | 同左 | `/health`、终端 banner |
| Web UI 登录 | `?token=` 写入 sessionStorage | 同左 | `http://127.0.0.1:8080/ui?token=...` |
| L2 是否会运行 | 只跑 rule-based / L1+规则语义 | provider 可用时运行 LLMAnalyzer + RuleBasedAnalyzer | `clawsentry test-llm --json`、Session Detail |
| L3 是否会运行 | 默认关闭 | high/critical 或显式触发时运行同步 L3；full-review 为 advisory | L3 审查 Agent、L3 咨询审查页面 |
| 成本边界 | 无 provider 成本 | 由 token budget 和 timeout 控制 | [配置模板](../configuration/templates.md)、[LLM 配置](../configuration/llm-config.md) |

---

## 选择运行模式 {#choose-mode}

| 你要做什么 | 推荐配置 | 延迟/成本预期 | 下一步 |
|---|---|---|---|
| 本地先看审计/Web UI | `normal` + L1/规则语义 | 最低；无外部 provider | `clawsentry start --framework <name>` |
| 团队仓库语义分析 | `normal` + L2 + token budget | L2 只在 medium+ / 关键域事件触发 | [L2 预算模板](../configuration/templates.md#template-l2-budgeted) |
| 安全敏感变更审查 | `strict` + L2 + L3 | L3 可能带来 10s+ 审查延迟 | [严格 L3 模板](../configuration/templates.md#template-l3-strict) |
| 只想手动复盘高风险 session | 同步 L3 可不开；启用 L3 advisory | 不改历史判决；按需生成报告 | [L3 咨询审查](../decision-layers/l3-advisory.md) |
| CI 或安全 benchmark | `benchmark` + 临时 home | 无人值守；DEFER 确定性处理 | [Benchmark 模式](../operations/benchmark-mode.md) |

---

## 推荐阅读路线 {#reading-route}

第一次体验时，不建议从 API Reference 或环境变量表开始。按下面顺序阅读会更顺：

<div class="cs-card-grid" markdown>

<div class="cs-card" markdown>
### 1. 跑起来
从路径 A 或路径 B 复制命令，打开 Web UI，确认 Gateway 可访问。
</div>

<div class="cs-card" markdown>
### 2. 选框架
在本页的能力表里确认你的框架是“可阻断”还是“监控 + 可选增强”。
</div>

<div class="cs-card" markdown>
### 3. 理解配置来源
先读[配置概览](../configuration/configuration-overview.md)确认优先级、`.clawsentry.env.example` 与显式 env-file 边界，再用[配置模板](../configuration/templates.md)选择 L2/L3 / 预算。
</div>

<div class="cs-card" markdown>
### 4. 注入密钥并部署
本机/CI secrets 看[环境变量参考](../configuration/env-vars.md)；团队常驻看[生产部署](../operations/deployment.md)；遇到配置未生效看[故障排查](../operations/troubleshooting.md)。
</div>

</div>

---
## 框架能力对比 {#framework-capabilities}

| 能力 | Claude Code | a3s-code | OpenClaw | Codex |
|------|:-----------:|:--------:|:--------:|:-----:|
| 实时风险评估 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| **自动拦截高危操作** | :white_check_mark: | :white_check_mark: | :white_check_mark: | 默认 managed `PreToolUse(Bash)` / approval gate |
| 审计记录 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| clawsentry watch 监控 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| Web UI 仪表板 | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| DEFER 交互审批 | :white_check_mark: | :white_check_mark: | :white_check_mark: | Native hook approval gate 可返回 host deny |
| 集成方式 | Hook 注入 | 显式 AHP Transport | WebSocket | Session 日志监控 + managed native hooks |

!!! info "Codex 的默认防护边界"
    `clawsentry start --framework codex` 会默认非破坏式安装 managed native hooks，并同时启用 Codex session watcher。同步防护主要覆盖 Bash preflight / approval gate；其他 native events 仍按异步观察处理，生产上建议继续配合 `--approval-policy untrusted` 使用。

## 第一次打开 Web UI，先看什么？

如果你刚打开 `http://127.0.0.1:8080/ui?token=...`，先不要把它当成“图表页”，而要把它当成**安全监控台**：

- **Dashboard**：先回答“现在哪一类框架、哪一个工作空间最值得看”
- **Sessions**：再回答“同一框架下哪些 workspace 和 session 正在运行，哪些已经变危险”
- **Session Detail**：最后回答“这个 session 为什么危险，它具体发生了什么”

理解这三个层级最重要：

- **Framework**：Claude Code / a3s-code / OpenClaw / Codex 这类运行时来源
- **Workspace**：某个具体项目目录或工作区，例如 `/workspace/repo-alpha`
- **Session**：该工作区中的某一次具体 Agent 会话

:material-lightbulb-outline: 最简单的使用顺序可以记成：

```text
Dashboard -> Sessions -> Session Detail
```

- 如果你只盯一个框架，先找最危险的 workspace
- 如果你同时盯多个框架，先找当前风险最高的 framework

:material-arrow-right: 如果你想先把这个使用模型看懂，再看页面细节，直接读：[Web 安全仪表板说明](../dashboard/index.md)

### Web UI 登录与本地代理

`clawsentry start` 会在终端打印形如 `http://127.0.0.1:8080/ui?token=...` 的 Web UI 地址。页面会把 `?token=` 写入浏览器 `sessionStorage` 后立刻清理地址栏中的 token；如果手动登录，使用同一个 `CS_AUTH_TOKEN`（来自进程环境、显式 `--env-file`，或本次 `start` 生成的临时 token）。

- `401` 表示 invalid token：复制的 token 与 Gateway 启动时的 `CS_AUTH_TOKEN` 不一致。
- `Gateway unavailable` 表示浏览器或 CLI 连不上 Gateway，不等同于 token 错误；先确认 Gateway 地址、端口和本机代理设置。
- 如果你的 shell 配置了代理，访问本机 Gateway 前可设置：

```bash
export NO_PROXY=localhost,127.0.0.1,::1
```

---

## 接入步骤

=== "Claude Code"

    Claude Code 通过原生 Hook 系统接入，**自动拦截**高危操作。

    **前置条件**

    ```bash
    pip install clawsentry
    claude --version      # 确认 Claude Code 已安装
    ```

    ### 一键启动（推荐）

    ```bash
    clawsentry start --framework claude-code
    ```

    自动完成：初始化配置 → 注入 hooks → 启动 Gateway → 显示实时监控。

    ??? example "终端输出示例"
        ```
        ClawSentry starting...
          Framework:  claude-code
          Gateway:    http://127.0.0.1:8080 (background)
          Web UI:     http://127.0.0.1:8080/ui?token=xK7m9p2Q...
          Log file:   /tmp/clawsentry-gateway.log

        Gateway ready. Streaming events...

        ──────────────────────────────────────
        [14:23:05] DECISION  session=my-session
          verdict : ALLOW
          risk    : low
          command : cat README.md
        ──────────────────────────────────────
        ```

    !!! tip "可选参数"
        ```bash
        clawsentry start --framework claude-code --interactive   # 启用 DEFER 交互审批
        clawsentry start --framework claude-code --no-watch      # 仅启动 Gateway
        clawsentry start --framework claude-code --open-browser  # 自动打开 Web UI
        ```

    ??? note "分步操作（高级用户）"

        **步骤 1：初始化**

        ```bash
        clawsentry init claude-code
        ```

        输出 `CS_FRAMEWORK=claude-code` / `CS_ENABLED_FRAMEWORKS=claude-code` 建议；带 `--setup` 时可自动注入 hooks 到 `~/.claude/settings.json`。

        **步骤 2：启动 Gateway**

        ```bash
        clawsentry gateway --env-file .clawsentry.env.local
        ```

        **步骤 3：使用 Claude Code**

        ```bash
        claude   # hooks 自动生效，工具调用经过 ClawSentry 评估
        ```

        **步骤 4：实时监控（另一终端，可选）**

        ```bash
        clawsentry watch
        clawsentry watch --interactive   # 交互式 DEFER 审批
        ```

        **卸载**

        ```bash
        clawsentry init claude-code --uninstall
        ```

    ### 验证

    ```bash
    clawsentry doctor   # 检查配置、连接、hooks 等诊断项
    ```

    :material-arrow-right: 完整配置和高级用法：[Claude Code 集成指南](../integration/claude-code.md)

=== "a3s-code"

    a3s-code 通过显式 AHP Transport（HTTP / stdio）接入，**自动拦截**高危操作。

    **前置条件**

    ```bash
    pip install clawsentry a3s-code
    ```

    ### 一键启动（推荐）

    ```bash
    clawsentry start --framework a3s-code
    ```

    这条命令负责 ClawSentry 侧的运行环境：选择框架、启动 Gateway、显示实时事件流。

    ### 继续配置 a3s-code Agent

    a3s-code 侧仍需要在你的 Agent 代码中显式设置 `SessionOptions().ahp_transport`，然后运行 Agent 脚本。

    ```python
    from a3s_code import Agent, SessionOptions, StdioTransport

    agent = Agent.create("agent.hcl")
    opts = SessionOptions()
    opts.ahp_transport = StdioTransport(program="clawsentry-harness", args=[])
    session = agent.session(".", opts, permissive=True)
    ```

    如需 HTTP 方式，可改用 `HttpTransport` 直连 Gateway。注意：fresh `clawsentry start` 生成的临时 token 不会写入父 shell；HTTP 方式请先显式 `export CS_AUTH_TOKEN = ...` 或使用 `--env-file`，否则优先用上面的 stdio transport：

    ```python
    import os
    from a3s_code import Agent, HttpTransport, SessionOptions

    agent = Agent.create("agent.hcl")
    opts = SessionOptions()
    token = os.environ["CS_AUTH_TOKEN"]
    opts.ahp_transport = HttpTransport(
        f"http://127.0.0.1:8080/ahp/a3s?token={token}"
    )
    session = agent.session(".", opts, permissive=True)
    ```

    ??? example "终端输出示例"
        ```
        ClawSentry starting...
          Framework:  a3s-code
          Gateway:    http://127.0.0.1:8080 (background)
          Web UI:     http://127.0.0.1:8080/ui?token=xK7m9p2Q...
          Log file:   /tmp/clawsentry-gateway.log

        Gateway ready. Streaming events...
        ```

    ??? note "分步操作（高级用户）"

        如果你不想使用 `clawsentry start`，可以把它拆成下面几步。`init` 负责输出 env 建议或安装 managed hooks，`gateway` 只负责启动服务，`watch` 只负责观察事件。

        **步骤 1：初始化**

        ```bash
        clawsentry init a3s-code
        ```

        **步骤 2：启动 Gateway**

        ```bash
        clawsentry gateway
        ```

        **步骤 3：在 Agent 代码中显式配置 AHP Transport 并运行 Agent**

        ```python
        from a3s_code import Agent, SessionOptions, StdioTransport

        agent = Agent.create("agent.hcl")
        opts = SessionOptions()
        opts.ahp_transport = StdioTransport(program="clawsentry-harness", args=[])
        session = agent.session(".", opts, permissive=True)
        ```

        如需 HTTP 方式，可改用 `HttpTransport` 直连 Gateway。注意临时 token 不会写入父 shell；请显式设置 `CS_AUTH_TOKEN` / `--env-file`：

        ```python
        import os
        from a3s_code import Agent, HttpTransport, SessionOptions

        agent = Agent.create("agent.hcl")
        opts = SessionOptions()
        token = os.environ["CS_AUTH_TOKEN"]
        opts.ahp_transport = HttpTransport(
            f"http://127.0.0.1:8080/ahp/a3s?token={token}"
        )
        session = agent.session(".", opts, permissive=True)
        ```

        运行你的 a3s-code Agent 脚本后，如果你还想单独看事件流，可以在另一终端运行 `clawsentry watch`；如果 Gateway 使用临时 token，复制 `start --no-watch` 输出里的 `clawsentry watch --token ...`。

    ### 验证

    ```bash
    clawsentry doctor
    ```

    :material-arrow-right: 完整配置和高级用法：[a3s-code 集成指南](../integration/a3s-code.md)

=== "OpenClaw"

    OpenClaw 通过 WebSocket 实时事件流接入，**自动拦截**高危操作。

    **前置条件**

    ```bash
    pip install "clawsentry[enforcement]"
    # OpenClaw Gateway 已启动（默认端口 18789）
    ```

    ### 一键启动（推荐）

    ```bash
    clawsentry start --framework openclaw
    ```

    ??? example "终端输出示例"
        ```
        ClawSentry starting...
          Framework:  openclaw
          Gateway:    http://127.0.0.1:8080 (background)
          Web UI:     http://127.0.0.1:8080/ui?token=xK7m9p2Q...
          Log file:   /tmp/clawsentry-gateway.log

        Gateway ready. Streaming events...

        ──────────────────────────────────────
        [14:30:22] DECISION  session=demo-session
          verdict : DEFER (awaiting operator)
          risk    : medium
          command : pip install requests
          [A]llow  [D]eny  [S]kip >
        ──────────────────────────────────────
        ```

    ??? note "分步操作（高级用户）"

        **步骤 1：初始化（自动检测 OpenClaw 配置）**

        ```bash
        clawsentry init openclaw --auto-detect --setup
        ```

        `--auto-detect` 检查 `~/.openclaw/openclaw.json`，但不会把 Token 写入 `.clawsentry.env.example`。
        `--setup` 自动配置 `tools.exec.host = "gateway"`。

        **步骤 2：启动 Gateway**

        ```bash
        clawsentry gateway
        ```

        **步骤 3：运行 OpenClaw**

        ```bash
        openclaw agent --session-id demo-session
        ```

        **步骤 4：交互式审批（另一终端）**

        ```bash
        clawsentry watch --interactive
        ```

    ### 验证

    ```bash
    clawsentry doctor
    ```

    :material-arrow-right: 完整配置和高级用法：[OpenClaw 集成指南](../integration/openclaw.md)

=== "Codex"

    !!! warning "默认 managed hooks + watcher"
        `clawsentry start --framework codex` 默认安装/刷新 ClawSentry-managed Codex native hooks，并启用 session watcher。同步防护主要覆盖 `PreToolUse(Bash)` / `PermissionRequest(Bash|apply_patch|Edit|Write|mcp__.*)`；其他 Codex native events 仍为异步观察/建议。建议配合 `--approval-policy untrusted` 使用。

    **前置条件**

    ```bash
    pip install clawsentry
    ```

    ### 一键启动（推荐）

    ```bash
    clawsentry start --framework codex
    ```

    ??? note "分步操作（高级用户）"

        **步骤 1：初始化**

        ```bash
        clawsentry init codex
        # 修复/刷新 managed Codex native hooks
        # start --framework codex 已默认执行这一步
        clawsentry init codex --setup
        ```

        **步骤 2：启动 Gateway**

        ```bash
        clawsentry gateway
        ```

        Gateway 启动时自动开始监控 Codex session 日志目录。

        **步骤 3：使用 Codex**

        ```bash
        codex --approval-policy untrusted
        ```

        **步骤 4：查看安全建议（另一终端）**

        ```bash
        clawsentry watch
        ```

        `clawsentry watch` 会实时显示风险评估结果；默认 managed native hooks 让 `PreToolUse(Bash)` 在 Gateway 判为 block/defer 时可让 Codex host deny 该 Bash 调用。其他 native events 只做异步观察/建议。

    ### 验证

    ```bash
    clawsentry doctor
    ```

    :material-arrow-right: 完整配置和高级用法：[Codex 集成指南](../integration/codex.md)

---

## 多框架并存

同一个项目可以逐个初始化多个框架；`init` 会输出对应 `CS_FRAMEWORK` / `CS_ENABLED_FRAMEWORKS` 建议，`--setup` 只修改目标宿主工具的 managed hooks：

```bash
clawsentry init a3s-code
clawsentry init codex
clawsentry init openclaw --auto-detect --setup --dry-run
clawsentry init openclaw --auto-detect --setup
```

也可以在启动时一次声明要启用的框架：

```bash
clawsentry start --frameworks a3s-code,codex,openclaw --no-watch
```

这条命令除了显示 `Enabled: ...`，还会在启动 banner 里打印每个框架的 `Readiness` 摘要与 `Next actions`。例如，`a3s-code` 会提示仍需人工确认 `SessionOptions.ahp_transport` 是否已经在 agent 代码里接好，`openclaw` 会在宿主配置不完整时直接提醒你改用 `--setup-openclaw`。

不会写入或轮换 `CS_AUTH_TOKEN`。多框架启用请在显式 env file 或部署环境中写逗号分隔列表：

```bash title=".clawsentry.env.local"
CS_ENABLED_FRAMEWORKS=a3s-code,codex,openclaw
CS_FRAMEWORK=a3s-code
CS_CODEX_WATCH_ENABLED=true
OPENCLAW_ENFORCEMENT_ENABLED=true
```

!!! tip "OpenClaw 可恢复"
    OpenClaw 外部配置修改是显式 opt-in：`clawsentry init openclaw` 和 `clawsentry start --frameworks ...` 默认不会改 `~/.openclaw/`。`clawsentry init openclaw --setup` 修改 OpenClaw 配置前会创建 `.bak` 备份。需要回退时运行：
    ```bash
    clawsentry init openclaw --restore --dry-run
    clawsentry init openclaw --restore
    ```

如需只卸载某个框架的 managed hooks，使用同一个 `init` 入口的 `--uninstall`；环境变量列表请同步从你的 explicit env file / deployment env 中移除：

```bash
clawsentry init codex --uninstall
clawsentry init claude-code --uninstall
clawsentry init openclaw --uninstall
```

查看当前项目集成状态：

```bash
clawsentry integrations status
```

如果你需要脚本化检查或想看更细的排障线索，使用：

```bash
clawsentry integrations status --json
```

其中 `framework_readiness` 会按框架给出 `status / summary / checks / warnings / next_step`，适合 CI、自检脚本和 release 前人工复核。

---

## 安全预设与 env 配置

ClawSentry 提供 4 个内置安全预设。`config init` / `config wizard` 写的是 dotenv `KEY=VALUE` 模板；运行时仍需要显式 `--env-file` 或进程/部署环境。

**快速切换预设：**

```bash
clawsentry config init --preset high    # 在当前项目创建 .clawsentry.env.example
clawsentry config set strict --env-file .clawsentry.env.local  # 写入显式 env file
clawsentry config show --effective --env-file .clawsentry.env.local
export CS_PROJECT_ENABLED=false        # 单进程禁用
```

| 预设 | 适用场景 | 拦截力度 | DEFER 超时行为 |
|------|---------|---------|--------------|
| `low` | 个人项目、学习 | 宽松，仅拦截最危险操作 | 自动放行 |
| `medium` **(默认)** | 日常开发 | 平衡安全与效率 | 超时拒绝 |
| `high` | 团队项目、敏感数据 | 严格，更多操作触发拦截 | 超时拒绝 |
| `strict` | CI/CD、安全审计 | 最严格，D6 注入检测全力放大 | 超时拒绝 |

!!! info "dotenv 模板"
    `clawsentry config init` 在当前目录生成 `.clawsentry.env.example`，内容是 `CS_PRESET=high` 等 `KEY=VALUE`。它不会被自动读取；启动或检查时请显式 `--env-file .clawsentry.env.local`。

    ```bash title=".clawsentry.env.example"
    CS_PRESET=high
    CS_MODE=normal
    CS_FRAMEWORK=codex
    CS_ENABLED_FRAMEWORKS=codex
    ```

    :material-arrow-right: 预设参数全表 + 高级调优：[检测管线配置文档](../configuration/detection-config.md#presets)

---

## 下一步

- [核心概念](concepts.md) — 深入理解 AHP 协议和三层决策模型
- [检测管线配置](../configuration/detection-config.md) — 调整 L1 规则和检测阈值
- [启用 LLM 分析](../configuration/llm-config.md) — 开启 L2/L3 语义分析
- [Latch 移动监控](../integration/latch.md) — 手机端实时审批（可选）
- [常见问题](faq.md)


## Kimi CLI native-hook path

```bash
clawsentry init kimi-cli
clawsentry init kimi-cli --setup --dry-run
clawsentry init kimi-cli --setup
clawsentry start --framework kimi-cli --no-watch
```

Kimi CLI support is native-hook based: `PreToolUse` can block dangerous tool calls, `UserPromptSubmit` can block prompts before model submission, and post/session/subagent/compact/notification hooks are observation-only. Preview managed hooks with an isolated `KIMI_SHARE_DIR` before changing a real `~/.kimi/config.toml`.
