---
hide:
  - navigation
  - toc
---

<style>
  .md-typeset h1 { display: none; }

  .hero {
    text-align: center;
    padding: 2rem 1rem 1rem;
  }
  .hero h2 {
    font-size: 2.8rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
  }
  .hero .tagline {
    font-size: 1.25rem;
    opacity: 0.85;
    margin-bottom: 2rem;
  }

  .grid-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1rem;
    margin: 2rem 0;
  }
  .grid-cards .card {
    border: 1px solid var(--md-default-fg-color--lightest);
    border-radius: 8px;
    padding: 1.2rem;
    text-align: center;
  }
  .grid-cards .card h3 { margin-top: 0.5rem; }
  .framework-cards {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
  }
  .framework-card {
    border: 1px solid var(--md-default-fg-color--lightest);
    border-radius: 8px;
    padding: 1.2rem;
  }
  .framework-card h3 { margin-top: 0.5rem; }
  .latch-banner {
    background: var(--md-code-bg-color);
    border-left: 4px solid var(--md-accent-fg-color);
    border-radius: 4px;
    padding: 1rem 1.4rem;
    margin: 1rem 0 2rem;
  }
</style>

<div class="hero" markdown>

## :shield: ClawSentry

**ClawSentry 为 AI Agent 工具调用提供统一安全网关：能拦截的框架前置阻断，不能完全拦截的框架清晰标注为监控或可选增强。**
{ .tagline }

从本地体验到团队部署，按“安装 → 配置 → 接入框架 → 查看 Web UI → 调优/部署”的路线逐步完成。<br>
三层递进决策（规则 → 语义 → Agent 审查）帮助你在安全性、延迟和可解释性之间取得平衡。
{ .tagline }

[:octicons-rocket-16: 5 分钟快速开始](getting-started/quickstart.md){ .md-button .md-button--primary }
[:octicons-book-16: 查看文档](getting-started/quickstart.md){ .md-button }
[:octicons-code-square-16: API Reference](api/reference.md){ .md-button }
[:octicons-mark-github-16: GitHub](https://github.com/Elroyper/ClawSentry){ .md-button }

</div>

---


!!! tip "v0.7.1: Public release metadata correction"
    公开发布面现在使用公开仓库实际可复验的测试计数，并刷新了首页、配置页、API 文档和 PyPI/GitHub README 的版本说明。

!!! tip "v0.7.0: Runtime safety controls"
    Skill Trust registry/preflight、capability narrowing、agent safety feedback 和 policy drift traceability 已进入主线。Benchmark 模式的运行方式见 [部署运维 / Benchmark 模式](operations/benchmark-mode.md)。

<div class="grid-cards" markdown>

<div class="card" markdown>
### :shield: 拦截优先，监控兜底
Claude Code、a3s-code 和 OpenClaw 支持高危操作前阻断；Codex 通过默认 managed hooks + session watcher 接入；Gemini CLI 和 Kimi CLI 通过 native hooks 接入。每个集成页都会说明可阻断范围、监控范围和 fallback 行为。
</div>

<div class="card" markdown>
### :zap: 不拖慢你的工作流
L1 规则引擎 &lt;0.3ms 完成大多数决策；L2/L3 语义分析仅在必要时触发。
</div>

<div class="card" markdown>
### :eye: 从事件到证据
每条工具调用都有记录、决策原因和审计轨迹。你可以先用 CLI 观察，再在 Web 仪表板中按 framework / workspace / session 追踪风险。
</div>

</div>

---

## 选择你的框架 { #choose-framework }

<div class="framework-cards" markdown>

<div class="card framework-card" markdown>
### :material-console-line: Claude Code
通过原生 Hook 系统接入，支持高危操作前阻断。

- 零侵入注入，不改动 Claude Code 本身
- `PreToolUse` 阻塞式安全审查
- 一键初始化 + 一键卸载

[:octicons-arrow-right-24: Claude Code 快速开始](getting-started/quickstart.md)
</div>

<div class="card framework-card" markdown>
### :material-console: a3s-code
通过显式 SDK stdio / HTTP Transport 接入，支持高危操作前阻断。

- `StdioTransport` 通过 harness + UDS 本地决策
- `HttpTransport` 直连 `/ahp/a3s`
- 只通过显式 SDK 传输接入

[:octicons-arrow-right-24: a3s-code 快速开始](getting-started/quickstart.md)
</div>

<div class="card framework-card" markdown>
### :material-web: OpenClaw
通过 WebSocket 实时事件流接入，支持高危操作前阻断和人工审批。

- 监听 `exec.approval.requested` 事件
- 自动检测 OpenClaw 配置
- 支持交互式 DEFER 审批

[:octicons-arrow-right-24: OpenClaw 快速开始](getting-started/quickstart.md)
</div>

<div class="card framework-card" markdown>
### :material-code-braces: Codex
默认通过 session 日志监控接入，可选启用 Bash preflight / approval gate。

- 自动监控 session 日志目录
- `clawsentry init codex --setup` 非破坏式安装 managed native hooks
- 同步 host-deny / approval gate 范围：`PreToolUse(Bash)`、`PermissionRequest(Bash)`；其他 native events 默认仍为异步观察
- 建议继续配合 `--approval-policy untrusted`

[:octicons-arrow-right-24: Codex 快速开始](getting-started/quickstart.md)
</div>


<div class="card framework-card" markdown>
### :material-moon-waxing-crescent: Kimi CLI
通过 Kimi native `[[hooks]]` 接入，可阻断 prompt 和危险 Shell，并记录安全 Shell 与生命周期观察事件。

- `clawsentry init kimi-cli --setup` 写 `$KIMI_SHARE_DIR/config.toml` 或 `~/.kimi/config.toml`
- 保留非 ClawSentry hooks，只替换 marker-managed blocks
- 可阻断 `UserPromptSubmit` 和 `PreToolUse` 高危调用；post/session/subagent/compact/notification 作为观察面
- 不提供 native `modify` / true `defer` parity

[:octicons-arrow-right-24: Kimi CLI 集成指南](integration/kimi-cli.md)
</div>

<div class="card framework-card" markdown>
### :material-creation: Gemini CLI
通过 Gemini CLI native command hooks 接入，支持 prompt、model 与 tool 阶段的安全检查。

- `clawsentry init gemini-cli --setup` 默认只写项目 `.gemini/settings.json`
- 同步 hook 覆盖 prompt/model/tool 入口
- 自定义 provider 或代理前，请先确认它兼容 Gemini CLI 所需接口

[:octicons-arrow-right-24: Gemini CLI 集成指南](integration/gemini-cli.md)
</div>

</div>

<div class="latch-banner" markdown>

:material-cellphone: **Latch 移动监控（可选增强）**

随时随地在手机上查看安全事件，远程审批 DEFER 操作。支持所有框架，需单独安装。

[:octicons-arrow-right-24: 了解 Latch 集成](integration/latch.md)

</div>

---

## 核心亮点

<div class="grid-cards" markdown>

<div class="card" markdown>
### :zap: 深度防御
**L1 规则** (<0.3ms) → **L2 语义** (<3s) → **L3 Agent** (<30s)

逐层升级，绝大多数决策在 L1 毫秒级完成。
</div>

<div class="card" markdown>
### :link: 统一多种 AI 框架
**a3s-code** + **Claude Code** + **Codex** + **Gemini CLI** + **Kimi CLI** + **OpenClaw**

统一 AHP 协议归一化所有框架事件。
</div>

<div class="card" markdown>
### :satellite: 多端实时可见
**CLI 终端** + **Web 仪表板** + **移动端（Latch）**

决策/告警/会话三端同步，全链路可观测。v0.5.10 起 Web UI 优先显示 token usage / token limit、稳定的 Unbound workspace 分组、最新优先的 session timeline，以及 L3 advisory 自然语言分析。
</div>

<div class="card" markdown>
### :lock: 安全优先
**Fail-closed 高危** + **Bearer Token** + **HMAC 签名**

生产级安全加固
</div>

</div>

---

## 工作原理

```mermaid
flowchart LR
    A["AI Agent\n执行工具调用"] -->|"pre_action 事件"| B["ClawSentry\n风险评估 &lt;1ms"]
    B -->|"低风险"| C["✅ ALLOW\n正常执行"]
    B -->|"高风险"| D["❌ BLOCK\n自动拦截"]
    B -->|"中等风险"| E["⏸ DEFER\n等待审批"]
```

<figure markdown>
  ![ClawSentry 架构总览](assets/architecture-overview.png)
  <figcaption>ClawSentry — 统一 AI Agent 安全监督网关</figcaption>
</figure>

---

## 快速安装

=== "基础安装"

    ```bash
    pip install clawsentry
    ```

=== "含 LLM 支持"

    ```bash
    pip install clawsentry[llm]
    ```

=== "完整安装"

    ```bash
    pip install clawsentry[all]
    ```

=== "开发环境"

    ```bash
    git clone https://github.com/Elroyper/ClawSentry.git
    cd ClawSentry
    pip install -e ".[dev]"
    ```

!!! info "环境要求"
    - Python >= 3.11
    - 核心依赖：FastAPI, Uvicorn, Pydantic v2
    - 可选依赖组：`[llm]`（Anthropic / OpenAI）、`[enforcement]`（WebSocket）、`[dev]`（测试）

---

??? info "三层决策模型详解"
    | 层级 | 名称 | 延迟 | 机制 | 适用场景 |
    |:---:|:---|:---:|:---|:---|
    | **L1** | 规则引擎 | <0.3ms | D1-D6 六维评分（命令危险度/参数敏感度/命令模式/历史行为/作用域权限/注入检测） | 明确的黑白名单、已知危险模式、注入尝试 |
    | **L2** | 语义分析 | <3s | RuleBased / LLM / Composite 三种实现，SemanticAnalyzer 协议 | 需要上下文理解的灰度命令 |
    | **L3** | 审查 Agent | <30s | AgentAnalyzer + ReadOnlyToolkit + SkillRegistry，多轮工具调用推理 | 复杂意图判断、需要取证分析 |

    ```
                      ┌─ ALLOW/DENY ──→ 直接返回
      Event ──→ L1 ──┤
                      └─ 不确定 ──→ L2 ──┬─ ALLOW/DENY ──→ 返回
                                          └─ 不确定 ──→ L3 ──→ 最终判决
    ```

    !!! note "升级策略"
        每层仅在无法确定时才向上升级，保证绝大多数请求在 L1 毫秒级完成。L3 是终审，**永不降级**——任何 L3 内部失败将降级为 `confidence=0.0`（fail-closed）。

---

??? info "各框架接入详情"
    === "a3s-code"

        通过显式 SDK **StdioTransport** 或 **HttpTransport** 接入。

        ```python
        # stdio 模式 — SDK 启动 clawsentry-harness
        StdioTransport(program="clawsentry-harness", args=[])

        # HTTP 模式 — SDK 直连 POST /ahp/a3s
        HttpTransport("http://127.0.0.1:8080/ahp/a3s?token=...")
        ```

        详见 [a3s-code 集成指南](integration/a3s-code.md)

    === "Claude Code"

        通过 **Hook 系统** + **stdio harness** 接入，自动注入 `settings.json`。

        ```bash
        clawsentry init claude-code   # 一键配置 hooks
        clawsentry start --env-file .clawsentry.env.local
        clawsentry gateway &          # 启动 Gateway
        claude                        # 正常使用，所有工具调用自动监控
        ```

        详见 [Claude Code 集成指南](integration/claude-code.md)

    === "Codex CLI"

        默认通过 **Session 日志监控**接入；如需最小同步防护，可显式安装 managed native hooks。

        ```bash
        clawsentry init codex         # 生成 watcher 配置
        clawsentry init codex --setup # 可选：安装 PreToolUse(Bash) preflight + 异步观察 hooks
        clawsentry start --env-file .clawsentry.env.local
        clawsentry gateway            # 启动 Gateway
        codex --approval-policy untrusted
        ```

        同步 host 阻断主要覆盖 `PreToolUse(Bash)`；`PostToolUse`、`UserPromptSubmit`、`Stop`、`SessionStart` 默认保持异步观察，不承诺前置阻断。

        详见 [Codex CLI 集成指南](integration/codex.md)

    === "Gemini CLI"

        通过 **Gemini native command hooks** 接入；默认写项目级 `.gemini/settings.json`。

        ```bash
        clawsentry init gemini-cli
        clawsentry init gemini-cli --setup --dry-run
        clawsentry init gemini-cli --setup
        clawsentry start --env-file .clawsentry.env.local
        clawsentry gateway
        gemini --prompt "say hello"
        ```

        `SessionStart`、`BeforeAgent`、`BeforeModel`、`BeforeTool` 等 hook 可接入 Gateway；shell 工具会规范化为 policy tool `bash`，便于复用统一规则。

        详见 [Gemini CLI 集成指南](integration/gemini-cli.md)

    === "OpenClaw"

        通过 **WebSocket 实时监听** + **Webhook 接收** + **审批执行器** 接入。

        ```bash
        # 一键启动（自动检测 OpenClaw 配置）
        clawsentry gateway
        ```

        详见 [OpenClaw 集成指南](integration/openclaw.md)

---

## CLI 与 API

- [CLI 命令参考 →](cli/index.md) — `init / gateway / watch / l3 full-review / doctor / audit / config / rules / integrations / start / stop / latch`
- [REST API 文档 →](api/decisions.md) — 决策端点、报表监控、SSE 推送、认证

---


## Web 安全仪表板

内置 **React 18 + TypeScript + Vite** 单页应用，现已升级为面向值班人员扫描路径的 operator console。当前 UI 重点回答：现在先看哪个 framework / workspace / session、token pressure 是否接近上限、L3 advisory 给出的解释和下一步是什么。

| 页面 | 功能 |
|:---|:---|
| **Dashboard** | Operator Brief、实时决策 feed、token-first LLM usage、风险概览 |
| **Sessions** | Framework / workspace / session 分组；缺失 workspace 时使用稳定 Unbound workspace fallback |
| **Session Detail** | 最新优先决策时间线、D1-D6 风险构成、L3 narrative analysis、advisory-only 边界 |
| **Alerts** | 告警表格、过滤、确认、SSE 自动推送 |
| **DEFER Panel** | 审批倒计时、Allow/Deny 操作、503 降级提示 |

Gateway 在 `/ui` 路径自动挂载静态文件，无需额外配置。

详见 [Web 仪表板文档](dashboard/index.md)

---

## 项目数据

| 指标 | 数据 |
|:---:|:---:|
| 测试用例 | **3357 passed / 16 skipped**（v0.7.1 public Python release validation；Web UI 56 passed） |
| 测试耗时 | 随可选依赖与 smoke 范围变化 |
| 协议版本 | `sync_decision.1.0` |
| Python 版本 | >= 3.11 |
| 许可证 | MIT |

---

## 文档导航

<div class="grid-cards" markdown>

<div class="card" markdown>
### [:material-rocket-launch: 入门指南](getting-started/installation.md)
安装、快速开始、核心概念
</div>

<div class="card" markdown>
### [:material-connection: 集成接入](integration/a3s-code.md)
a3s-code / Claude Code / Codex / OpenClaw 集成
</div>

<div class="card" markdown>
### [:material-cog: 配置参考](configuration/env-vars.md)
环境变量、策略调优、LLM 配置
</div>

<div class="card" markdown>
### [:material-api: REST API](api/decisions.md)
决策端点、报表监控、认证
</div>

<div class="card" markdown>
### [:material-layers-triple: 决策详解](decision-layers/l1-rules.md)
L1 规则 / L2 语义 / L3 Agent
</div>

<div class="card" markdown>
### [:material-monitor-dashboard: Web 仪表板](dashboard/index.md)
浅色优先安全运营控制台
</div>

</div>
