---
title: 自定义 L2 Analyzer
description: 实现和集成自定义的 L2 语义分析器，扩展 ClawSentry 的风险评估能力
---

<div class="cs-doc-hero" markdown>
<div class="cs-eyebrow">Advanced · L2 Semantic Analysis</div>

## 自定义 L2 Analyzer

实现和集成自定义的 L2 语义分析器，通过 `SemanticAnalyzer` Protocol 扩展 ClawSentry 的风险评估能力。

<div class="cs-pill-row" markdown>
<span class="cs-pill">SemanticAnalyzer Protocol</span>
<span class="cs-pill">CompositeAnalyzer</span>
<span class="cs-pill">upgrade-only</span>
<span class="cs-pill">budget_ms 超时保护</span>
</div>
</div>

# 自定义 L2 Analyzer

L2 语义分析是 ClawSentry 三层决策模型的中间层，负责在 L1 规则引擎的基础上进行更深层的语义风险评估。ClawSentry 提供了 **可插拔的 Analyzer 架构**，你可以实现自定义的 `SemanticAnalyzer` 来引入特定领域的风险评估逻辑。

---

## 架构概览

L2 分析在决策流程中的位置：

```
事件 → L1 规则引擎（D1-D5 评分） → L2 语义分析 → 最终决策
                                      ↑
                              SemanticAnalyzer Protocol
                              ├── RuleBasedAnalyzer（内置）
                              ├── LLMAnalyzer（LLM 驱动）
                              ├── CompositeAnalyzer（组合多个）
                              └── YourCustomAnalyzer（自定义）
```

### L2 触发条件

并非所有事件都会经过 L2 分析。以下条件触发 L2：

1. Adapter 请求的 `decision_tier` 为 `L2`
2. L1 评估结果为 MEDIUM 风险的 `pre_action` 事件
3. 事件涉及关键领域资产（匹配 `prod`, `credential`, `secret`, `token`, `password`, `key` 等关键词）
4. DecisionContext 中设置了手动 L2 升级标志（`l2_escalate`, `force_l2`, `manual_l2_escalation`）

---

## SemanticAnalyzer Protocol

所有 L2 分析器必须满足 `SemanticAnalyzer` 协议。这是一个 Python `Protocol`（结构化子类型），使用 `@runtime_checkable` 装饰器支持运行时类型检查：

```python
from typing import Optional, Protocol, runtime_checkable

@runtime_checkable
class SemanticAnalyzer(Protocol):
    """L2 可插拔语义分析器协议。"""

    @property
    def analyzer_id(self) -> str:
        """分析器的唯一标识符。"""
        ...

    async def analyze(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        budget_ms: float,
    ) -> L2Result:
        """
        分析事件并返回风险评估结果。

        Args:
            event: 归一化后的 AHP 标准事件
            context: 可选的决策上下文（会话风险、Agent 信任等级等）
            l1_snapshot: L1 规则引擎产生的风险快照
            budget_ms: 时间预算（毫秒），分析器应在此时间内返回

        Returns:
            L2Result: 包含目标风险等级、原因、置信度等
        """
        ...
```

!!! note "关键约束"
    - `analyze()` 是 **async** 方法——支持 I/O 密集型操作（如 LLM 调用、外部 API 查询）
    - L2 分析结果**只能升级**风险等级，不能降级——PolicyEngine 会确保最终等级 >= L1 等级
    - 分析器应尊重 `budget_ms` 时间预算，超时应降级返回而非阻塞

---

## L2Result 结构

```python
from dataclasses import dataclass, field
from typing import Optional

@dataclass(frozen=True)
class L2Result:
    """L2 语义分析的不可变结果。"""

    target_level: RiskLevel
    """目标风险等级。PolicyEngine 会取 max(L1 等级, 此值)。"""

    reasons: list[str] = field(default_factory=list)
    """分析发现的风险原因列表。"""

    confidence: float = 0.0
    """置信度 (0.0-1.0)。confidence=0.0 表示分析降级/失败。"""

    analyzer_id: str = ""
    """产生此结果的分析器标识符。"""

    latency_ms: float = 0.0
    """分析耗时（毫秒）。"""

    trace: Optional[dict] = None
    """可选的调试/审计追踪信息。"""
```

### 关键字段说明

| 字段 | 说明 |
|------|------|
| `target_level` | 分析器建议的风险等级。PolicyEngine 会取 `max(l1_snapshot.risk_level, target_level)`，确保**只升不降** |
| `confidence` | 置信度。**`0.0` 有特殊含义**——CompositeAnalyzer 会忽略 confidence=0.0 的结果，视为分析降级 |
| `reasons` | 人类可读的原因列表，会包含在最终决策的 `reason` 字段中 |
| `trace` | 可选的追踪信息，会存储到 TrajectoryStore 的 `l3_trace_json` 列中供审计 |

---

## 内置 Analyzer 实现

### RuleBasedAnalyzer

基于规则的语义分析器，无需外部依赖，延迟亚毫秒级：

```python
class RuleBasedAnalyzer:
    @property
    def analyzer_id(self) -> str:
        return "rule-based"
```

**分析逻辑**：

1. 检查 `risk_hints` 是否包含已确认的高风险信号（`credential_exfiltration_confirmed`, `privilege_escalation_confirmed`）→ 升级到 CRITICAL
2. 检查 `risk_hints` 是否包含高风险信号（`credential_exfiltration`, `privilege_escalation`, `prompt_injection` 等）→ 升级到 HIGH
3. 检查是否在关键领域资产上使用了危险工具 → 升级到 HIGH
4. 检查是否同时存在关键领域关键词和危险意图关键词 → 升级到 CRITICAL
5. 检查是否有手动 L2 升级标志 → 升级到 HIGH

**特点**：

- 始终返回 `confidence=1.0`
- 延迟在微秒级
- 作为 L2 分析的基线，即使 LLM 不可用也能提供增强评估

### LLMAnalyzer

基于 LLM 的语义分析器，通过 LLM 提供商进行深度语义评估：

```python
class LLMAnalyzer:
    @property
    def analyzer_id(self) -> str:
        return f"llm-{self._provider.provider_id}"
```

**特点**：

- 使用预定义的安全分析系统提示词
- 将事件的工具名称、事件类型、payload、risk_hints、L1 评分等信息发送给 LLM
- 要求 LLM 以 JSON 格式返回 `{"risk_assessment": "...", "reasons": [...], "confidence": 0.0-1.0}`
- 超时或解析失败时降级为 L1 结果（confidence=0.0）
- 默认配置：超时 3000ms，max_tokens 256，temperature 0.0

### CompositeAnalyzer

组合分析器，递进运行多个分析器并取最高风险结果：

```python
class CompositeAnalyzer:
    @property
    def analyzer_id(self) -> str:
        ids = ",".join(a.analyzer_id for a in self._analyzers)
        return f"composite({ids})"
```

**行为**：

1. 先运行第一个子分析器
2. 若第一个结果已对 HIGH+ 风险给出高置信度结论，则跳过后续分析器
3. 否则再运行后续子分析器
4. 过滤掉 confidence=0.0 的结果（视为降级/失败）
5. 从有效结果中选择风险等级最高的；风险等级相同时选择 confidence 最高的
6. 如果所有分析器都降级（无有效结果），返回 L1 等级，confidence=0.0

---

## 实现自定义 Analyzer

### 步骤 1: 定义 Analyzer 类

```python title="company_blocklist_analyzer.py"
"""
基于公司内部黑名单的 L2 语义分析器。

检查 Agent 操作是否命中公司安全团队维护的命令/路径黑名单。
"""

import time
from typing import Optional

from clawsentry.gateway.models import (
    CanonicalEvent,
    DecisionContext,
    RiskLevel,
    RiskSnapshot,
)
from clawsentry.gateway.semantic_analyzer import L2Result


class CompanyBlocklistAnalyzer:
    """基于公司内部黑名单的 L2 语义分析器。"""

    # 公司安全团队维护的高危命令黑名单
    BLOCKED_COMMANDS = {
        "rm -rf /",
        "chmod -R 777 /",
        "curl | bash",
        "wget -O- | sh",
        "nc -e /bin/sh",
    }

    # 公司内部受保护路径
    PROTECTED_PATHS = {
        "/opt/production/",
        "/var/lib/secrets/",
        "/etc/company/",
        "/home/deploy/.ssh/",
    }

    # 公司特定的敏感环境变量名
    SENSITIVE_ENV_VARS = {
        "DATABASE_URL",
        "STRIPE_SECRET_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "COMPANY_API_MASTER_KEY",
    }

    @property
    def analyzer_id(self) -> str:
        return "company-blocklist"

    async def analyze(
        self,
        event: CanonicalEvent,
        context: Optional[DecisionContext],
        l1_snapshot: RiskSnapshot,
        budget_ms: float,
    ) -> L2Result:
        start = time.monotonic()
        reasons: list[str] = []
        target_level = l1_snapshot.risk_level

        # 提取命令文本
        command = str(event.payload.get("command", "")).strip()
        command_lower = command.lower()

        # 检查 1: 命令黑名单
        for blocked in self.BLOCKED_COMMANDS:
            if blocked in command_lower:
                target_level = RiskLevel.CRITICAL
                reasons.append(
                    f"Command matches company blocklist: '{blocked}'"
                )

        # 检查 2: 受保护路径
        payload_text = str(event.payload)
        for path in self.PROTECTED_PATHS:
            if path in payload_text:
                target_level = RiskLevel.HIGH
                reasons.append(
                    f"Operation targets protected path: {path}"
                )

        # 检查 3: 敏感环境变量
        for env_var in self.SENSITIVE_ENV_VARS:
            if env_var in payload_text:
                target_level = RiskLevel.HIGH
                reasons.append(
                    f"References sensitive env var: {env_var}"
                )

        elapsed_ms = (time.monotonic() - start) * 1000

        return L2Result(
            target_level=target_level,
            reasons=reasons,
            confidence=1.0 if reasons else 0.5,
            analyzer_id=self.analyzer_id,
            latency_ms=round(elapsed_ms, 3),
        )
```

### 步骤 2: 集成到 Gateway

目前 ClawSentry 通过 `llm_factory.py` 中的 `build_analyzer_from_env()` 函数构建 Analyzer 链。要集成自定义 Analyzer，你可以修改 `llm_factory.py` 或创建一个启动脚本：

```python title="custom_gateway.py"
"""使用自定义 Analyzer 启动 Gateway 的示例脚本。"""

import asyncio
from clawsentry.gateway.server import AHPSupervisionGateway
from clawsentry.gateway.policy_engine import L1PolicyEngine
from clawsentry.gateway.semantic_analyzer import (
    CompositeAnalyzer,
    RuleBasedAnalyzer,
)
from company_blocklist_analyzer import CompanyBlocklistAnalyzer


def main():
    # 构建自定义 Analyzer 链
    analyzers = [
        RuleBasedAnalyzer(),           # 内置规则分析
        CompanyBlocklistAnalyzer(),     # 公司黑名单分析
    ]
    composite = CompositeAnalyzer(analyzers)

    # 使用自定义 Analyzer 创建 PolicyEngine
    policy_engine = L1PolicyEngine(analyzer=composite)

    # 创建并启动 Gateway
    gateway = AHPSupervisionGateway(policy_engine=policy_engine)
    gateway.run()


if __name__ == "__main__":
    main()
```

### 步骤 3: 与 LLM 分析器组合

如果同时需要公司黑名单检查和 LLM 语义分析，使用 CompositeAnalyzer 组合：

```python
from clawsentry.gateway.semantic_analyzer import (
    CompositeAnalyzer,
    LLMAnalyzer,
    RuleBasedAnalyzer,
)
from clawsentry.gateway.llm_provider import OpenAIProvider, LLMProviderConfig

# 构建 LLM 提供商
config = LLMProviderConfig(api_key="sk-...", model="gpt-4")
provider = OpenAIProvider(config)

# 组合三个分析器
analyzers = [
    RuleBasedAnalyzer(),           # L2 规则分析（亚毫秒级）
    LLMAnalyzer(provider),          # LLM 语义分析（~1-3 秒）
    CompanyBlocklistAnalyzer(),     # 公司黑名单分析（亚毫秒级）
]
composite = CompositeAnalyzer(analyzers)
```

CompositeAnalyzer 会递进运行这些分析器，并最终取风险等级最高的有效结果。

---

## 最佳实践

### 1. 始终遵循 upgrade-only 原则

L2 分析器的结果应只升级风险等级，不应降级。即使你的分析器认为 L1 评估过高，也应返回与 L1 相同或更高的等级：

```python
# 正确：使用 l1_snapshot.risk_level 作为底线
target_level = l1_snapshot.risk_level
if some_condition:
    target_level = RiskLevel.HIGH  # 升级

# 错误：可能降级
target_level = RiskLevel.LOW  # 不要这样做
```

PolicyEngine 内部会强制执行 `max(l1_level, l2_level)`，但分析器自身遵循此原则可以避免混淆。

### 2. 正确使用 confidence

- `1.0` -- 确定性分析（规则匹配、黑名单命中）
- `0.5-0.9` -- LLM 或启发式分析结果
- `0.0` -- 分析失败或降级。**CompositeAnalyzer 会忽略 confidence=0.0 的结果**

### 3. 尊重时间预算

```python
async def analyze(self, event, context, l1_snapshot, budget_ms):
    # 如果需要调用外部服务，使用 asyncio.wait_for 限制超时
    try:
        result = await asyncio.wait_for(
            self._external_check(event),
            timeout=budget_ms / 1000,
        )
    except asyncio.TimeoutError:
        # 超时降级
        return L2Result(
            target_level=l1_snapshot.risk_level,
            reasons=["External check timed out; falling back to L1"],
            confidence=0.0,
            analyzer_id=self.analyzer_id,
        )
```

### 4. 异常处理与降级

分析器不应抛出异常到调用方。所有异常应在内部捕获并降级：

```python
async def analyze(self, event, context, l1_snapshot, budget_ms):
    try:
        # 正常分析逻辑
        ...
    except Exception:
        # 降级：返回 L1 等级 + confidence=0.0
        return L2Result(
            target_level=l1_snapshot.risk_level,
            reasons=["Analysis failed; falling back to L1"],
            confidence=0.0,
            analyzer_id=self.analyzer_id,
        )
```

### 5. 提供有意义的 reasons

`reasons` 列表会出现在决策结果和仪表板中。确保每个 reason 清晰描述发现了什么风险：

```python
# 好的 reason
reasons.append("Command matches company blocklist: 'rm -rf /'")
reasons.append("Operation targets protected production path: /opt/production/")

# 不好的 reason
reasons.append("suspicious")
reasons.append("blocked")
```

---

## 相关 API 参考

### CanonicalEvent 关键字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `tool_name` | `Optional[str]` | 工具名称（如 `bash`, `read_file`） |
| `event_type` | `EventType` | 事件类型（`pre_action`, `post_action` 等） |
| `risk_hints` | `list[str]` | 风险提示标签列表 |
| `payload` | `dict[str, Any]` | 事件载荷（包含 `command`, `tool` 等） |
| `session_id` | `str` | 会话标识符 |
| `agent_id` | `str` | Agent 标识符 |
| `source_framework` | `str` | 来源框架（`a3s-code`, `openclaw`） |

### RiskSnapshot 关键字段

| 字段 | 类型 | 说明 |
|------|------|------|
| `risk_level` | `RiskLevel` | L1 评估的风险等级 |
| `composite_score` | `int` (0-7) | 综合评分 = max(D1,D2,D3) + D4 + D5 |
| `dimensions` | `RiskDimensions` | D1-D5 各维度评分 |
| `short_circuit_rule` | `Optional[str]` | 短路规则（SC-1/SC-2/SC-3，跳过常规评分） |
| `classified_by` | `ClassifiedBy` | 评估来源（L1/L2/manual） |

### RiskLevel 枚举

```python
class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
```
