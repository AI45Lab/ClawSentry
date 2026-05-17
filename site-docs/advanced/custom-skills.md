---
title: 自定义 L3 技能
description: Write and load custom YAML domain-review skills for the L3 review agent.
---

<div class="cs-doc-hero" markdown>
<div class="cs-eyebrow">高级功能 · L3 审查代理</div>

## 自定义 L3 审查技能

编写 YAML 技能清单，使用自定义触发条件、提示词和评估标准，扩展 L3 代理的领域安全专业知识。

<div class="cs-pill-row" markdown>
<span class="cs-pill">Skill Schema v1</span>
<span class="cs-pill">SkillRegistry</span>
<span class="cs-pill">自定义技能目录</span>
<span class="cs-pill">规则检查</span>
</div>
</div>

L3 审查代理在运行时从注册表中选择最匹配的技能，并将其 `system_prompt` 和 `evaluation_criteria` 注入 LLM 调用。技能文件为纯 YAML 格式，无需编写任何 Python 代码。

---

## 技能清单字段参考

以下为顶层 YAML 字段及其类型、约束条件和默认值。

### 核心字段（所有 schema 版本适用）

| 字段 | 类型 | 是否必填 | 默认值 | 约束条件 |
|---|---|---|---|---|
| `name` | `string` | 是 | — | 非空；在内置技能与自定义技能中全局唯一。 |
| `description` | `string` | 是 | — | 非空的人类可读摘要。 |
| `system_prompt` | `string` | 是 | — | 非空；定义 LLM 审查员角色和输出格式。 |
| `triggers` | `dict` | 否 | `{}` | 必须为 dict；包含三个可选子列表：`risk_hints`、`tool_names`、`payload_patterns`。 |
| `evaluation_criteria` | `list[dict]` | 否 | `[]` | 每个条目必须包含 `name`、`description` 和 `severity`（`low`/`medium`/`high`/`critical`）。 |
| `enabled` | `bool` | 否 | `true` | 设为 `false` 可禁用技能而不删除文件。 |
| `priority` | `int` | 否 | `0` | 得分相同时的优先级决胜；值越高越优先。 |
| `schema_version` | `string` | 否 | `"legacy"` | 设为 `clawsentry.l3_skill.v1` 可启用严格的 v1 校验。 |

### 清单 v1 专属字段（`schema_version: clawsentry.l3_skill.v1`）

| 字段 | 类型 | v1 是否必填 | 默认值 | 约束条件 |
|---|---|---|---|---|
| `allowed_tools` | `list[string]` | 否 | 全部 `VALID_L3_TOOLS` | 必须是全局工具白名单的子集（见下文）。 |
| `required_evidence` | `list[string]` | **是** | — | 每个值必须在有效证据集内（见下文）。非空。 |
| `recommended_tools` | `list[dict]` | 否 | `[]` | 每个条目格式为 `{name, reason}`；`name` 必须在全局工具白名单中。 |
| `severity_rubric` | `dict` | **是** | — | 键：`low`/`medium`/`high`/`critical`；至少必须覆盖 `high` 或 `critical`。 |
| `benign_exceptions` | `list[string]` | 否 | `[]` | 展示给审查员的自由文本例外说明。 |
| `output_tags` | `list[string]` | **是** | — | 非空；不得重复；每个标签须匹配 `^[a-z][a-z0-9_]{1,63}$`。 |
| `field_notes` | `dict` | 否 | — | 键限于有效的 field-notes 集合（见下文），值为字符串。 |
| `example_policy` | `dict` | 否 | — | `{max_examples: int, max_chars_per_example: int（默认 900）}`。 |
| `example_cases` | `list[dict]` | 否 | `[]` | 每个条目必须包含 `synthetic: true` 和 `not_current_case: true`，不得含真实路径或类密钥文本，长度受 `example_policy` 限制。 |
| `max_tool_calls` | `int` | 否 | — | 加载时截断至 `[1, 20]`。 |

!!! 警告 "v1 比 legacy 更严格"
    当设置 `schema_version: clawsentry.l3_skill.v1` 时，加载器会强制要求 `required_evidence`、`severity_rubric`（须覆盖 `high` 或 `critical`）以及 `output_tags` 均存在且非空。未设置 `schema_version` 或设为 `"legacy"` 的旧版技能跳过上述检查，但不能安全使用 v1 专属字段。

### 全局工具白名单（`VALID_L3_TOOLS`）

`allowed_tools` 中的值必须来自以下集合，任何未列出的工具将在加载时抛出 `ValueError`。

```
read_trajectory          read_trajectory_page     read_file
read_file_range          read_transcript          read_session_risk
read_l3_trace            search_codebase          query_git_diff
query_git_status         query_git_show           list_changed_files
list_directory           read_package_manifest
```

### `required_evidence` 有效值

```
current_event    trigger          trajectory_summary    session_risk
workspace_context    l1_snapshot    prior_analysis    skill_trust
```

### `field_notes` 有效键

```
event    trigger    local_evidence    rule_hits    effect_summary
taint_flow_summary    skill_trust_findings    session_scope_summary
mcp_summary    tool_evidence    prior_analysis
```

---

## 技能评分算法

`SkillRegistry._ranked_skills()` 为每个已启用的非 `general-review` 技能计算 `(score, priority, -insertion_order)` 三元组，然后降序排列。当所有已启用技能的得分均为 `0` 时，`_ranked_skills()` 会将 `general-review` 以 `0` 分注入排名列表，确保列表永不为空。随后 `select_skill()` 返回列表中的第一个结果。

### 技能评分与选择流程

```mermaid
flowchart TD
    A([收到事件]) --> B{是否存在<br/>强制路由覆盖规则？}
    B -- 是 --> C[直接返回指定技能]
    B -- 否 --> D[遍历所有 enabled 且非 general-review 的技能]

    D --> E[计算每个技能的得分]

    subgraph scoring ["评分计算（每个技能）"]
        E1["检查 triggers.risk_hints<br/>事件 risk_hints 与技能列表取交集<br/>每命中 1 个 +10 分"]
        E2["检查 triggers.tool_names<br/>event.tool_name.lower() 是否在列表中<br/>最多命中一次 +5 分"]
        E3["检查 triggers.payload_patterns<br/>每个模式字符串作为子串匹配 payload<br/>每命中 1 个 +1 分"]
        E1 --> E2 --> E3
    end

    E --> scoring

    E3 --> F["按 (score DESC, priority DESC, insertion_order ASC) 排序"]
    F --> G{所有技能得分<br/>是否均为 0？}
    G -- 是 --> H["注入 general-review（score=0）作为兜底"]
    G -- 否 --> I[过滤掉得分为 0 的技能]
    H --> J[select_skill 取排名第一的技能]
    I --> J
    J --> K([返回选中技能])

    style scoring fill:#f0f4ff,stroke:#6b7fc4
    style C fill:#ffe4b5,stroke:#c4963b
    style H fill:#ffe4e4,stroke:#c44b4b
```

### 得分组成

| 来源 | 每次命中得分 | 匹配逻辑 |
|---|---|---|
| `triggers.risk_hints` | **+10** | 事件 `risk_hints`（小写）与技能 `risk_hints` 列表取交集。 |
| `triggers.tool_names` | **+5**（最多命中一次） | `event.tool_name.lower()` 是否在技能 `tool_names` 列表中。 |
| `triggers.payload_patterns` | **+1** 每个 | 每个模式字符串（小写）作为子串匹配 `str(event.payload).lower()`。 |

### 得分并列时的决胜规则

两个技能总分相同时，`priority` 字段值较高的技能获胜。若 `priority` 也相同，则按目录排序中较早出现的技能获胜（文件按字母顺序加载）。

### 兜底规则

得分为 `0` 的非 `general-review` 技能不会进入排名池，但 `_ranked_skills()` 会在无其他技能得分时将 `general-review` 以 `0` 分注入，作为最终兜底。

!!! 警告 "`general-review` 必须存在"
    若内置技能目录加载完成后不存在名为 `general-review` 的技能，`SkillRegistry.__init__` 将抛出 `ValueError`。删除或重命名该文件将导致网关无法启动。

### 技能生命周期

```mermaid
flowchart LR
    A([YAML 文件]) --> B[加载\nload_from_dir / load_additional]
    B --> C{schema 校验}
    C -- 通过 --> D[注册到 SkillRegistry\n检查 name 冲突]
    C -- 失败 --> E([抛出 ValueError\n跳过该文件])
    D --> F{name 是否已存在？}
    F -- 否 --> G[加入注册表]
    F -- 是 --> H([WARNING 日志\n跳过不覆盖])
    G --> I[运行时评分\n_ranked_skills]
    I --> J[select_skill\n返回最高分技能]
    J --> K([注入 system_prompt\n+ evaluation_criteria\n到 LLM 调用])

    style E fill:#ffe4e4,stroke:#c44b4b
    style H fill:#fff3cd,stroke:#c4963b
```

---

## 触发覆盖说明

`select_skill()` 路径没有超越得分机制的覆盖手段。若要强制某个技能处理特定事件类型，需为其 `risk_hints` 设置足够高的特异性，使其他竞争技能无法匹配。`priority` 字段仅用于并列决胜，不会叠加到得分上。

对于跨域事件，`secondary_criteria()` 从不同的非 `general-review` 技能中返回最多 `limit=2` 个接近匹配的评估标准，从而在单次 L3 调用中实现多域审查。

---

## 内置技能

所有内置技能位于 `src/clawsentry/gateway/skills/` 目录，均使用 `schema_version: clawsentry.l3_skill.v1`。

| 技能 | 优先级 | 关键 `risk_hints` 触发器 | 关键 `payload_patterns` |
|---|---|---|---|
| `shell-audit` | 10 | `privilege_escalation`, `sudo_usage`, `shell_injection`, `destructive_intent` | `sudo`, `rm -rf`, `curl \| sh`, `dd if=` |
| `credential-audit` | 10 | `credential_access`, `credential_exfiltration`, `secret_access`, `env_access` | `password`, `secret`, `.ssh`, `.env`, `credentials.json` |
| `skill-trust-audit` | 10 | `skill_trust`, `first_use_skill`, `provenance_conflict` | `SKILL.md`, `skill trust` |
| `code-review` | 8 | `code_injection`, `supply_chain_attack`, `malicious_code` | `eval(`, `exec(`, `pickle.loads`, `subprocess` |
| `file-system-audit` | 8 | `path_traversal`, `unauthorized_file_access`, `sensitive_file_write` | `/etc/`, `/root/`, `../`, `authorized_keys`, `sudoers` |
| `network-audit` | 8 | `data_exfiltration`, `network_exfiltration`, `suspicious_network` | `curl`, `wget`, `nc`, `socat`, `base64` |
| `persistence-audit` | 9 | persistence 相关 risk hints | crontab, systemd, launchctl, authorized_keys, .bashrc |
| `prompt-injection-transcript-audit` | — | 提示词注入相关 transcript hints | 注入标记模式 |
| `data-staging-exfil-chain-audit` | — | 数据暂存 + 外泄链路 hints | 先读后上传模式 |
| `dependency-supply-chain-audit` | — | 供应链相关 hints | pip/npm/cargo install 模式 |
| `general-review` | 0 | *（无触发器——仅作兜底）* | — |

---

## 带注释的示例技能

```yaml title="kubernetes-audit.yaml"
# Required: unique identifier across all loaded skills
name: kubernetes-audit

# Required: schema version — enables strict v1 validation
schema_version: clawsentry.l3_skill.v1

# Required: human-readable summary shown in lint output and dashboards
description: >
  Audit Kubernetes cluster operations for privilege escalation and
  destructive changes.

# Optional: set false to disable without deleting the file (default: true)
enabled: true

# Optional: tie-breaker when two skills have equal scores (default: 0)
priority: 9

# Trigger conditions — all comparison is lowercased
triggers:
  risk_hints:
    - cluster_admin            # +10 per match
    - pod_security_bypass
    - namespace_deletion
  tool_names:
    - bash                     # +5 if event.tool_name matches any entry
    - kubectl
  payload_patterns:
    - kubectl                  # +1 per pattern found as substring in payload
    - "--privileged"
    - hostnetwork
    - clusterrole
    - "create secret"
    - "delete namespace"

# Required (v1): at least "high" or "critical" must be present
severity_rubric:
  high:
    - Destructive cluster operations or privilege binding without justification
  critical:
    - Confirmed cluster-admin grant, pod escape, or namespace destruction

# Required (v1): non-empty; values must be in the valid evidence set
required_evidence:
  - current_event
  - trigger
  - trajectory_summary

# Required (v1): non-empty; each tag matches ^[a-z][a-z0-9_]{1,63}$
output_tags:
  - kubernetes
  - privilege

# Optional: restrict which L3 tools this skill may invoke
# Default: all 14 VALID_L3_TOOLS
allowed_tools:
  - read_trajectory
  - read_trajectory_page
  - read_session_risk
  - query_git_diff
  - search_codebase

# Optional: advisory suggestions shown to the LLM (do not expand allowed_tools)
recommended_tools:
  - name: read_trajectory_page
    reason: "Page through tool calls looking for kubectl privilege operations."

# Optional: max concurrent tool calls (clamped to [1, 20])
max_tool_calls: 8

# Optional: domain hints for specific evidence capsule fields
field_notes:
  effect_summary: "Check for ClusterRoleBinding creates and namespace-level deletes."
  taint_flow_summary: "Look for kubectl get secret piped to external network sinks."

# Optional: common benign cases to reduce false positives
benign_exceptions:
  - "kubectl get pods in a dev namespace by an authorized CI identity"
  - "namespace delete during known teardown pipeline"

# Optional: few-shot synthetic examples (never real cases)
example_policy:
  max_examples: 2
  max_chars_per_example: 900

example_cases:
  - synthetic: true
    not_current_case: true
    label: high_privilege_binding
    scenario: "Agent creates ClusterRoleBinding granting cluster-admin to unknown SA"
    expected_risk: high

# Required: LLM reviewer persona — must end with JSON output instruction
system_prompt: |
  You are a Kubernetes security auditor. Analyze the AI agent's cluster
  operations for:
  1. Privilege escalation (ClusterRoleBinding, cluster-admin grants)
  2. Pod Security bypass (privileged containers, hostNetwork, hostPID)
  3. Destructive operations (namespace deletion, force pod removal)
  4. Sensitive data access (get/describe secret, configmap with credentials)
  5. Insecure image sources (unknown registries, unverified images)

  Respond ONLY with JSON:
  {"risk_level": "low|medium|high|critical", "findings": ["..."], "confidence": 0.0}

# Required: evaluation dimensions — severity in {low, medium, high, critical}
evaluation_criteria:
  - name: privilege_escalation
    severity: critical
    description: ClusterRoleBinding or cluster-admin grant
  - name: pod_security_bypass
    severity: critical
    description: Privileged container, hostNetwork, or hostPID
  - name: destructive_cluster_ops
    severity: high
    description: Namespace deletion or forced pod removal
  - name: secret_exposure
    severity: high
    description: Kubernetes Secret accessed or exfiltrated
```

---

## 添加自定义技能

### 1. 创建 YAML 文件

将 `.yaml` 文件放置在任意目录中。文件名不影响技能名称——文件内的 `name:` 字段才是标识符。

### 2. 部署前先做校验

```bash
clawsentry rules lint --skills-dir /path/to/my-skills --json
clawsentry rules dry-run --skills-dir /path/to/my-skills \
    --events examples/sample-events.jsonl --json
```

`rules lint` 检测以下问题：非法的 `allowed_tools` 条目、未知的 `required_evidence` 值、重复的 `output_tags`、非合成示例、超长示例、真实路径以及类密钥字符串。

`rules dry-run` 显示每个示例事件选中了哪个技能及其得分。

### 3. 将网关指向技能目录

```bash
export AHP_SKILLS_DIR="/path/to/my-skills"
clawsentry gateway
```

启动日志会确认加载数量：

```
[ahp.llm-factory] Custom skills loaded from /path/to/my-skills (1 skills)
```

### 4. 了解名称冲突行为

`load_additional()` 按字母顺序处理文件。若自定义技能的 `name` 与已加载技能（内置或先前加载的自定义技能）重复，该文件将被**跳过并记录 WARNING 日志**，不会覆盖已有技能。

!!! 注意 "自定义技能无法替换内置技能"
    内置技能目录优先加载。名为 `shell-audit.yaml` 的自定义文件将被静默跳过。若需修改内置技能的行为，请 fork 对应的内置技能文件并使用不同的 `name`。

---

## 校验错误参考

| 触发条件 | 错误信息 |
|---|---|
| `name` 为空 | `skill missing name` |
| `description` 为空 | `skill missing description` |
| `system_prompt` 为空 | `skill missing system_prompt` |
| `triggers` 不是 dict | `skill triggers must be a dict` |
| `evaluation_criteria` 不是 list | `skill evaluation_criteria must be a list` |
| `evaluation_criteria[i].severity` 不在 `{low,medium,high,critical}` 中 | `invalid evaluation_criteria[i]` |
| `allowed_tools` 包含不在白名单的工具 | `skill allowed_tools contain non-whitelisted tools` |
| `required_evidence` 包含未知值 | `skill required_evidence contains unknown values` |
| `output_tags` 有重复值 | `skill output_tags must not contain duplicates` |
| `output_tags` 值不匹配 `^[a-z][a-z0-9_]{1,63}$` | `skill output_tags contain invalid tags` |
| `field_notes` 键不在有效集合中 | `skill field_notes references unknown fields` |
| `severity_rubric` 键不在 `{low,medium,high,critical}` 中 | `skill severity_rubric has invalid severity` |
| `example_cases[i]` 缺少 `synthetic: true` 或 `not_current_case: true` | `skill example_cases[i] must be synthetic and not_current_case` |
| `example_cases[i]` 包含真实路径或类密钥文本 | `skill example_cases[i] contains real path or secret-like text` |
| `example_cases` 数量超过 `example_policy.max_examples` | `skill example_cases exceed example_policy.max_examples` |
| `max_tool_calls` 不是整数 | `skill max_tool_calls must be an integer` |
| 同一目录中存在重复 `name` | `duplicate skill name` |
| `schema_version` 为 v1 且 `required_evidence` 为空 | `skill required_evidence is required for clawsentry.l3_skill.v1` |
| `schema_version` 为 v1 且 `severity_rubric` 未覆盖 `high` 或 `critical` | `skill severity_rubric must cover high or critical` |
| `schema_version` 为 v1 且 `output_tags` 为空 | `skill output_tags is required for clawsentry.l3_skill.v1` |
| `schema_version` 既非 `"legacy"` 也非 `clawsentry.l3_skill.v1` | `unsupported skill schema_version` |

!!! 警告 "`example_cases` 不属于证据"
    示例案例必须包含 `synthetic: true` 和 `not_current_case: true`，仅用于向 LLM 展示模式样例。它们不能出现在 L2/L3 `evidence_refs` 或 findings 输出中。
