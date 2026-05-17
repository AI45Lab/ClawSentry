---
title: 常见问题
description: ClawSentry 常见问题与解答
---

# 常见问题

---

## 基本概念

### ClawSentry 和 AHP 是什么关系？

**AHP (Agent Harness Protocol)** 是一套协议规范，定义了 AI Agent 安全监督的统一事件格式（CanonicalEvent）和决策模型（CanonicalDecision）。它是一个抽象的协议标准，本身不是软件实现。

**ClawSentry** 是 AHP 协议的 Python 参考实现。它实现了 AHP 规范中定义的所有接口，并提供了三层决策引擎、会话管理、实时监控等具体功能。

两者的关系类似于 HTTP 协议规范和 Nginx 的关系 — 前者定义标准，后者是实现。

| | AHP | ClawSentry |
|---|-----|-----------|
| 性质 | 协议规范 | 软件实现 |
| 定义 | 事件格式、决策接口、传输协议 | 规则引擎、LLM 分析、Web 仪表板 |
| 语言 | 无关 | Python 3.11+ |
| 可替换 | 否（标准） | 是（可以有其他实现） |

### 支持哪些 Agent 框架？

ClawSentry 当前公开支持四条接入路径：

| 框架 | 集成方式 | 自动拦截 | 状态 |
|------|---------|:--------:|------|
| **Claude Code** | Host hooks + `clawsentry-harness` | 是 | 已完成 |
| **a3s-code** | 显式 SDK Transport（stdio / HTTP） | 是 | 已完成 |
| **OpenClaw** | WebSocket / Webhook | 是 | 已完成 |
| **Codex** | Session JSONL watcher + 可选 managed native hooks | 默认否；已验证 `PreToolUse(Bash)` 可选 host deny | 已完成 |

!!! tip "扩展自定义框架"
    ClawSentry 的 Adapter 架构是可扩展的。要对接一个新的 Agent 框架，你需要：

    1. 编写 Adapter 类，将框架原始事件转换为 `CanonicalEvent`
    2. 将 `CanonicalDecision` 转换回框架能理解的响应格式
    3. 注册到 Gateway 的事件处理流程或 watcher 路径

    所有框架共享同一个策略引擎和决策流程，只有事件的归一化逻辑不同。

### ClawSentry 的三层决策是什么意思？

ClawSentry 实现了渐进式三层决策架构，按复杂度和延迟递增排列：

- **L1 规则引擎** (< 1ms)：基于规则的快速匹配，无需 LLM
- **L2 语义分析** (< 3s)：调用 LLM 理解命令意图和上下文
- **L3 审查 Agent** (< 30s)：运行完整的审查 Agent 进行多轮工具调用调查

大多数事件在 L1 即可完成判决。只有当 L1 无法确定风险时，才会逐层升级到 L2、L3。

---

## 部署与配置

### 不配 LLM 能用吗？

**可以。** L1 规则引擎完全基于规则和模式匹配，不需要任何 LLM 服务。它可以：

- 识别已知危险命令模式（如 `rm -rf /`、`fork bomb`）
- 基于工具类型进行白名单/黑名单判定
- 计算 D1-D5 五维风险评分
- 对只读操作快速放行

仅当你需要以下能力时才需要配置 LLM：

| 能力 | 需要 LLM | 层级 |
|------|---------|------|
| 命令模式匹配和规则评估 | 否 | L1 |
| 理解命令的语义意图（"这条命令是在做备份还是在删数据？"） | 是 | L2 |
| 多轮调查审查（读取文件、查询历史、综合研判） | 是 | L3 |

!!! success "L1 已覆盖大部分场景"
    在典型的开发工作流中，L1 规则引擎可以处理约 80% 的事件。对于个人开发或安全要求不极端的场景，仅 L1 已经提供了有效的安全防护。

### 支持哪些 LLM？

ClawSentry 通过环境变量配置 LLM Provider，支持以下选项：

=== "OpenAI / 兼容 API"

    ```bash
    CS_LLM_PROVIDER=openai
    CS_LLM_BASE_URL=https://api.openai.com/v1
    CS_LLM_MODEL=gpt-4
    OPENAI_API_KEY = sk-your-key-here
    ```

    任何兼容 OpenAI API 的服务都可以使用，包括：

    - OpenAI GPT-4 / GPT-4o
    - Azure OpenAI Service
    - 本地部署的 vLLM / Ollama（设置 `CS_LLM_BASE_URL` 即可）
    - 其他 OpenAI 兼容代理

=== "Anthropic Claude"

    ```bash
    CS_LLM_PROVIDER=anthropic
    CS_LLM_MODEL=claude-sonnet-4-20250514
    ANTHROPIC_API_KEY=sk-ant-your-key-here
    ```

    支持 Anthropic Claude 全系列模型。

!!! info "LLM 仅用于安全分析"
    ClawSentry 调用 LLM 仅用于分析命令的安全风险，不会将 LLM 响应传递给被监督的 Agent。LLM 的角色是安全审查员，而非代理执行者。

### 延迟影响大吗？

**对于大多数操作，影响极小。**

| 层级 | 延迟 | 触发频率 | 对 Agent 的影响 |
|------|------|---------|---------------|
| L1 | < 1ms | 约 80% 的事件 | 几乎无感知 |
| L2 | < 3s | 约 15% 的事件（中等风险） | 短暂等待 |
| L3 | < 30s | < 5% 的事件（高复杂度） | 需要等待，但仅针对确实需要深入调查的操作 |

由于 L1 处理了绝大多数事件，Agent 在执行常规安全操作（读文件、列目录、写代码）时几乎不会感受到 ClawSentry 的存在。只有在执行系统命令、网络请求等需要更深入审查的操作时，才可能经历 L2/L3 的等待。

!!! tip "post_action 不增加延迟"
    `post_action` 事件（工具调用后的审计）是异步处理的，完全不阻塞 Agent 的执行流。

### 数据存在哪里？

ClawSentry 使用 **SQLite** 作为本地存储后端，无需部署外部数据库。

```bash
# 默认路径
~/.clawsentry/trajectory.db

# 自定义路径
export CS_TRAJECTORY_DB_PATH=/path/to/custom.db
```

存储内容包括：

| 数据 | 说明 |
|------|------|
| 事件记录 | 所有 CanonicalEvent 的完整记录 |
| 决策记录 | 所有 CanonicalDecision 及其 RiskSnapshot |
| 会话轨迹 | 每个会话的事件序列和风险累积 |
| L3 推理过程 | 审查 Agent 的多轮对话和工具调用记录 |
| 告警记录 | 触发的安全告警及确认状态 |

数据会根据 `CS_TRAJECTORY_RETENTION_SECONDS` 配置进行自动清理（默认保留 30 天）。

---

## 运维与监控

### 如何处理 DEFER 决策？

当 ClawSentry 判定一个操作为中等风险时，会产生 DEFER 判决，等待运维人员的人工确认。你有三种方式处理 DEFER：

=== "命令行交互"

    ```bash
    clawsentry watch --interactive
    ```

    在终端中实时查看 DEFER 事件，并通过键盘选择 `[A]llow`、`[D]eny` 或 `[S]kip`。

=== "Web 仪表板"

    访问 `http://127.0.0.1:8080/ui`，在 DEFER Panel 页面中查看待审批的操作，点击按钮进行审批。

=== "REST API"

    ```bash
    # 批准操作
    curl -X POST http://127.0.0.1:8080/ahp/resolve \
      -H "Authorization: Bearer $CS_AUTH_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"approval_id": "apr-xxx", "action": "allow-once"}'

    # 拒绝操作
    curl -X POST http://127.0.0.1:8080/ahp/resolve \
      -H "Authorization: Bearer $CS_AUTH_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"approval_id": "apr-xxx", "action": "deny"}'
    ```

!!! warning "DEFER 超时机制"
    每个 DEFER 决策都有超时限制。如果在超时前未做出选择，系统会自动拒绝该操作（fail-closed）。这确保了即使运维人员不在线，Agent 也不会无限期等待。

### `clawsentry watch` 有哪些常用参数？

| 参数 | 说明 | 示例 |
|------|------|------|
| `--gateway-url` | Gateway 地址 | `--gateway-url http://10.0.0.1:8080` |
| `--token` | 认证令牌 | `--token my-secret-token` |
| `--filter` | 事件类型过滤 | `--filter decision,alert` |
| `--json` | 输出原始 JSON | `--json` |
| `--no-color` | 禁用彩色输出 | `--no-color` |
| `--interactive` / `-i` | 交互式 DEFER 审批 | `--interactive` |

---

## 生产环境

### 能在生产环境用吗？

ClawSentry 提供了多项生产级安全特性：

| 特性 | 说明 | 配置方式 |
|------|------|---------|
| **SSL/TLS** | HTTPS 加密传输 | `AHP_SSL_CERTFILE` / `AHP_SSL_KEYFILE` |
| **Bearer Token 认证** | 所有 API 请求必须携带令牌 | `CS_AUTH_TOKEN` |
| **速率限制** | 防止 API 滥用 | `CS_RATE_LIMIT_PER_MINUTE`（默认 300） |
| **IP 白名单** | Webhook 来源 IP 限制 | `AHP_WEBHOOK_IP_WHITELIST` |
| **Token TTL** | 令牌有效期控制 | `AHP_WEBHOOK_TOKEN_TTL_SECONDS` |
| **UDS 权限隔离** | Socket 文件 chmod 600 | 自动设置 |
| **重试预算分层** | 按风险等级限制重试次数 | 内置（CRITICAL/HIGH=1, MEDIUM=2, LOW=3） |

!!! note "生产环境建议"
    对于生产部署，建议：

    1. 启用 SSL/TLS 加密
    2. 设置强随机 Bearer Token
    3. 配置 IP 白名单限制 Webhook 来源
    4. 启用会话强制策略（`AHP_SESSION_ENFORCEMENT_ENABLED=true`）
    5. 配置 LLM 以获得 L2/L3 深度分析能力

### ClawSentry 本身会成为单点故障吗？

ClawSentry 的设计遵循 fail-safe 原则，即使自身出现故障也能维持安全基线：

- **Gateway 不可达时**：Agent 的行为取决于框架实现。a3s-code 和 OpenClaw 都有各自的 fallback 机制。
- **L2/L3 调用失败时**：自动回退到 L1 规则引擎结果，不会导致决策流程中断。
- **数据库写入失败时**：决策流程不受影响，仅审计记录丢失（日志中会告警）。

!!! danger "高危操作保障"
    无论发生何种故障，高危操作（`risk_level = high/critical`）始终会被拦截（fail-closed）。这是 ClawSentry 最核心的安全不变量。

---

## 自定义与扩展

### 如何自定义安全规则？

ClawSentry 在三个层级都提供了自定义能力：

=== "L1: 环境变量调优"

    通过环境变量调整 L1 引擎的行为：

    ```bash
    # 速率限制（每分钟最大请求数）
    CS_RATE_LIMIT_PER_MINUTE=500

    # 会话强制策略阈值
    AHP_SESSION_ENFORCEMENT_THRESHOLD=5
    AHP_SESSION_ENFORCEMENT_ACTION=block
    ```

    L1 的短路规则（SC-1/SC-2/SC-3）和 D1-D5 评分逻辑可通过修改源码中的 `risk_snapshot.py` 和 `policy_engine.py` 来自定义。

=== "L2: 自定义 Analyzer"

    L2 语义分析支持可插拔的 Analyzer 实现：

    ```python
    from clawsentry.gateway.semantic_analyzer import SemanticAnalyzer, L2Result

    class MyCustomAnalyzer:
        """自定义语义分析器"""

        async def analyze(self, event, risk_snapshot) -> L2Result:
            # 你的自定义分析逻辑
            ...
    ```

    通过 `LLM Factory`（`llm_factory.py`）注册你的自定义 Analyzer。

=== "L3: 自定义 Skills (YAML)"

    L3 审查 Agent 的能力通过 YAML 格式的 Skill 文件定义。你可以创建自定义 Skill：

    ```yaml
    # my-skills/database-audit.yaml
    name: database-audit
    description: 审查数据库相关操作的安全性
    enabled: true
    priority: 9
    system_prompt: |
      你是一个数据库安全审计专家。分析以下操作是否可能
      导致数据泄露、权限提升或数据损坏。
    triggers:
      - tool_names: ["sql", "psql", "mysql", "mongo"]
      - patterns: ["DROP", "TRUNCATE", "ALTER", "GRANT"]
    ```

    将自定义 Skills 目录设置到环境变量中：

    ```bash
    export AHP_SKILLS_DIR=/path/to/my-skills
    ```

    ClawSentry 内置了 6 个审计 Skill：

    | Skill | 优先级 | 用途 |
    |-------|--------|------|
    | `shell-audit` | 10 | Shell 命令安全审计 |
    | `credential-audit` | 10 | 凭证/密钥泄露检查 |
    | `code-review` | 8 | 代码变更安全审查 |
    | `file-system-audit` | 8 | 文件系统操作审计 |
    | `network-audit` | 8 | 网络请求安全审计 |
    | `general-review` | 0 | 通用安全审查（兜底） |

### 如何查看 ClawSentry 的实时状态？

ClawSentry 提供了丰富的 REST API 用于查询系统状态：

| 端点 | 方法 | 说明 |
|------|------|------|
| `/report/summary` | GET | 跨框架聚合统计 |
| `/report/sessions` | GET | 活跃会话列表（按风险排序） |
| `/report/session/{id}` | GET | 单个会话的完整轨迹 |
| `/report/session/{id}/risk` | GET | 会话风险详情和时间线 |
| `/report/session/{id}/enforcement` | GET | 会话强制策略状态 |
| `/report/alerts` | GET | 告警列表（支持过滤） |
| `/report/alerts/{id}/acknowledge` | POST | 确认告警 |
| `/report/stream` | GET | SSE 实时事件流 |

---

## 故障排查

### Gateway 启动失败，提示端口已占用

检查是否已有进程占用默认端口：

```bash
# 检查 HTTP 端口（默认 8080）
lsof -i :8080

# 检查 Webhook 端口（默认 8081）
lsof -i :8081
```

可通过环境变量更改端口：

```bash
export CS_HTTP_PORT=9090
clawsentry gateway
```

### `clawsentry watch` 连接失败

确认以下几点：

1. **Gateway 已启动**：`clawsentry gateway` 是否在运行
2. **端口一致**：watch 默认连接 `http://127.0.0.1:8080`，与 Gateway 的 `CS_HTTP_PORT` 一致
3. **Token 正确**：如果 Gateway 启用了认证，watch 需要提供 `--token` 参数

```bash
clawsentry watch --gateway-url http://127.0.0.1:9090 --token your-token
```

### OpenClaw WebSocket 连接失败

常见原因和解决方案：

??? question "提示 `scope` 为空"
    确保 WebSocket 连接使用了正确的参数：

    - `client.id` 必须为 `openclaw-control-ui`
    - `client.mode` 必须为 `backend`
    - 连接请求需要携带 `Origin` header
    - OpenClaw 配置中需要设置 `gateway.controlUi.allowedOrigins`

??? question "收不到 `exec.approval.requested` 事件"
    检查 OpenClaw 的 `tools.exec.host` 配置：

    ```json
    {
      "tools": {
        "exec": {
          "host": "gateway"
        }
      }
    }
    ```

    如果设置为 `"sandbox"`（默认值），所有命令会直接在沙箱中执行，跳过审批流程。必须设置为 `"gateway"` 才会触发审批事件。

    你可以使用 `clawsentry init openclaw --setup` 自动配置这些选项。

---

## 下一步

- 返回 [安装](installation.md) 查看安装和环境配置详情
- 阅读 [快速开始](quickstart.md) 跟随实战指南完成首次集成
- 深入了解 [核心概念](concepts.md) 掌握 AHP 协议和决策模型


## Kimi CLI 和 a3s-code 是同等能力吗？

不是。`a3s-code` 是 explicit SDK/AHP transport reference path，能表达 ClawSentry 的完整 allow/block/modify/defer 决策语义。`kimi-cli` 使用 Kimi native `[[hooks]]`：`PreToolUse` 可以阻断危险工具调用，`UserPromptSubmit` 可以阻断 prompt，post/session/subagent/compact/notification 可以观察；但 Kimi 没有原生 tool-input rewrite，也没有 true `defer` parity。

---

??? question "Kimi CLI 和 Gemini CLI 支持 defer（人工审批）吗？"
    Kimi CLI 和 Gemini CLI 的 native hook 目前不支持真正的暂停等待人工审批（defer）语义。ClawSentry 的 `defer` 对这两个框架会以 deny/block 形式呈现，并记录在审计日志中。需要完整 defer 审批语义，请使用 Claude Code、a3s-code 或 OpenClaw 接入路径。

??? question "什么是 Skill Trust？首次使用未注册的 skill 会发生什么？"
    Skill Trust 用来管理 agent skill 包的供应链风险。当一个 skill 首次被调用且尚未在 registry 中登记时，Gateway 会按 `CS_SKILL_TRUST_FIRST_USE_*_ACTION` 配置的动作处理：默认在 normal 模式下记录（`audit`），在 strict 模式下进入 DEFER，在 benchmark 模式下 BLOCK。可通过 `clawsentry skill-trust register` 命令将 skill 加入白名单。详见[Skill Trust / Registry](../advanced/skill-trust.md)。

??? question "L3 AgentAnalyzer 是单轮还是多轮审查？"
    从 v0.7.4 开始，L3 默认使用**多轮审查**模式（`CS_L3_MULTI_TURN=true`）。只有显式设置 `CS_L3_MULTI_TURN=false`、`0`、`no` 或 `off` 才会回退到旧版单轮模式。多轮模式允许 L3 agent 多次调用只读工具（读文件、查 git 历史、搜索代码）收集证据，再给出最终判决，通常准确性更高但延迟增加。
