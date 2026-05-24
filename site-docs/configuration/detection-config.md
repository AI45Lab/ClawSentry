---
title: 检测管线配置参考（DetectionConfig）
description: 统一调优所有检测参数的 DetectionConfig dataclass — 合成评分权重、风险阈值、D4 会话累积、L2 预算、攻击模式路径、Post-action 分层、轨迹分析、Anti-bypass guard、自进化模式库
---

# 检测管线配置参考（DetectionConfig）

## 概述 {#overview}

`DetectionConfig` 是 ClawSentry 检测管线的统一配置中心，定义于 `src/clawsentry/gateway/detection_config.py`。

它是一个 `@dataclass(frozen=True)` **不可变配置对象**，在 Gateway 启动时创建，此后不可修改。所有可调检测参数都集中在这一个对象中，消除了此前散落在各模块中的硬编码常量。

**设计原则：**

- **完全向后兼容**：所有字段的默认值与原始硬编码常量完全一致，不提供任何 `CS_` 环境变量时行为与旧版本相同。
- **env-first 运行时桥接**：底层 runtime 消费 `CS_*` 风格的有效值，适合 shell、CI、容器和 12-Factor 部署；团队共享策略可写成 dotenv 模板，但必须显式 `--env-file` 加载。
- **整体回退安全**：若环境变量的组合违反验证约束，整体回退至全默认配置，并记录 `ERROR` 日志，而不是以损坏配置启动。

**配置流转路径：**

```
CLI / deployment env / 显式 env file
       │
       ▼
合成缺失的 CS_* 有效值
       │
       ▼
build_detection_config_from_env()
       │
       ▼
DetectionConfig（frozen dataclass）
       │
       ├──▶ risk_snapshot.py       （权重 + 阈值 + D4）
       ├──▶ policy_engine.py       （L2 预算 + 攻击模式路径）
       ├──▶ semantic_analyzer.py   （攻击模式路径）
       ├──▶ post_action_analyzer.py（Post-action 分层阈值 + 白名单）
       ├──▶ trajectory_analyzer.py （轨迹缓存上限）
       └──▶ pattern_matcher.py     （攻击模式路径）
```

---

## 快速开始 {#quickstart}

将下列内容保存为 `.clawsentry.env.local`（不要提交），按需取消注释并修改；启动或检查时必须显式传入 `--env-file .clawsentry.env.local`：

```bash title=".clawsentry.env.local — 检测管线常用调优示例"
# ── 风险等级阈值（默认值已适合大多数场景）─────────────────────────────────
# CS_THRESHOLD_MEDIUM=0.8       # >= 此值 → MEDIUM
# CS_THRESHOLD_HIGH=1.5         # >= 此值 → HIGH
# CS_THRESHOLD_CRITICAL=2.2     # >= 此值 → CRITICAL

# ── L2 语义分析超时 ────────────────────────────────────────────────────────
# CS_L2_TIMEOUT_MS=60000        # 默认 60 秒，硬上限由 CS_HARD_TIMEOUT_MS 控制

# ── 自定义攻击模式库（启动时加载，修改后需重启）────────────────────────────
# CS_ATTACK_PATTERNS_PATH=/etc/clawsentry/attack_patterns.yaml

# ── Post-action 围栏（观察输出时触发告警的阈值）────────────────────────────
# CS_POST_ACTION_MONITOR=0.3
# CS_POST_ACTION_ESCALATE=0.6
# CS_POST_ACTION_EMERGENCY=0.9

# ── Post-action 白名单（逗号分隔正则，命中则跳过检测）─────────────────────
# CS_POST_ACTION_WHITELIST=^https://internal\.corp\.example\.com,^data:image/

# ── 自进化模式库（E-5，默认关闭）──────────────────────────────────────────
# CS_EVOLVING_ENABLED=false
# CS_EVOLVED_PATTERNS_PATH=/var/lib/clawsentry/evolved_patterns.yaml

# ── Anti-bypass follow-up guard（guard 默认关闭）──────────────────────────
# CS_ANTI_BYPASS_GUARD_ENABLED=false
# CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=block
# CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=defer
# CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=force_l3

# ── Skill Trust / capability narrowing / feedback（v0.7.0）──────────────
# CS_SKILL_TRUST_REGISTRY_PATH=.clawsentry/skill-trust-registry.json
# CS_SKILL_TRUST_FIRST_USE_NORMAL_POLICY=audit_only
# CS_SKILL_TRUST_FIRST_USE_STRICT_POLICY=defer_for_review
# CS_CAPABILITY_NARROWING_ENABLED=false
# CS_CAPABILITY_NARROWING_TRIGGER_RISK=high
# CS_CAPABILITY_NARROWING_ALLOWED_TOOL_PERMISSION_GROUPS=read_only
# CS_CAPABILITY_NARROWING_DENIED_TOOL_PERMISSION_GROUPS=write,network,credentialed,destructive,mcp_admin,unknown
# CS_CAPABILITY_NARROWING_ALLOWED_SKILL_TRUST_STATES=allowlist
# CS_CAPABILITY_NARROWING_DENIED_SKILL_TRUST_STATES=blacklist,revoked
# CS_CAPABILITY_NARROWING_ALLOWED_MCP_SERVERS=
# CS_CAPABILITY_NARROWING_DENIED_MCP_SERVERS=
# CS_CAPABILITY_NARROWING_ALLOWED_MCP_TOOLS=filesystem.read_file
# CS_CAPABILITY_NARROWING_DENIED_MCP_TOOLS=fetch.fetch
# CS_CAPABILITY_NARROWING_ALLOWED_MCP_STATUSES=
# CS_CAPABILITY_NARROWING_DENIED_MCP_STATUSES=blacklist,revoked,disabled
# CS_CAPABILITY_NARROWING_ALLOWED_MCP_TRUST_LEVELS=
# CS_CAPABILITY_NARROWING_DENIED_MCP_TRUST_LEVELS=untrusted,unknown,local_unreviewed
# CS_CAPABILITY_NARROWING_ALLOWED_CAPABILITIES=
# CS_CAPABILITY_NARROWING_DENIED_CAPABILITIES=
# CS_CAPABILITY_NARROWING_QUEUED_CAPABILITIES=
# CS_CAPABILITY_NARROWING_AUDIT_VERBOSITY=summary
# CS_CAPABILITY_NARROWING_GREYLIST_ACTION=defer
# CS_TOOL_PERMISSION_GROUP_OVERRIDES=custom_read=read_only
# CS_AGENT_SAFETY_FEEDBACK_ENABLED=false
```

!!! tip "显式 env-file"
    `.clawsentry.env.local` 不会自动加载。使用 `clawsentry start --env-file .clawsentry.env.local` 或 `clawsentry config show --effective --env-file .clawsentry.env.local`；系统/进程环境变量优先于文件中的值。

---

## v0.7.0 roadmap controls {#roadmap-controls}

这组字段连接 Skill Trust、capability narrowing 和 agent feedback。默认值保守：不会自动调用真实 LLM，不会启动后台 scheduler，也不会静默改写历史 canonical decision。

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `skill_trust_registry_path` | `str \| None` | `None` | `CS_SKILL_TRUST_REGISTRY_PATH` | Skill Trust registry JSON 路径 |
| `skill_trust_first_use_normal_policy` | `str` | `audit_only` | `CS_SKILL_TRUST_FIRST_USE_NORMAL_POLICY` | normal 模式 first-use/unbound skill admission policy |
| `skill_trust_first_use_benchmark_policy` | `str` | `scan_sync` | `CS_SKILL_TRUST_FIRST_USE_BENCHMARK_POLICY` | benchmark 模式 first-use/unbound skill admission policy |
| `skill_trust_first_use_strict_policy` | `str` | `defer_for_review` | `CS_SKILL_TRUST_FIRST_USE_STRICT_POLICY` | strict 模式 first-use/unbound skill admission policy |
| `skill_trust_first_use_permissive_policy` | `str` | `audit_only` | `CS_SKILL_TRUST_FIRST_USE_PERMISSIVE_POLICY` | permissive 模式 first-use/unbound skill admission policy |
| `skill_trust_runtime_normal_action` | `str` | `force_l3` | `CS_SKILL_TRUST_RUNTIME_NORMAL_ACTION` | legacy profile-level runtime binding config surface；per-condition evidence 由下方字段执法 |
| `skill_trust_runtime_benchmark_action` | `str` | `block` | `CS_SKILL_TRUST_RUNTIME_BENCHMARK_ACTION` | legacy profile-level runtime binding config surface；per-condition evidence 由下方字段执法 |
| `skill_trust_runtime_strict_action` | `str` | `block` | `CS_SKILL_TRUST_RUNTIME_STRICT_ACTION` | legacy profile-level runtime binding config surface；per-condition evidence 由下方字段执法 |
| `skill_trust_runtime_permissive_action` | `str` | `audit` | `CS_SKILL_TRUST_RUNTIME_PERMISSIVE_ACTION` | legacy profile-level runtime binding config surface；per-condition evidence 由下方字段执法 |
| `skill_trust_runtime_path_disallowed_normal_action` | `str` | `defer` | `CS_SKILL_TRUST_RUNTIME_PATH_DISALLOWED_NORMAL_ACTION` | normal 模式 disallowed runtime path 动作 |
| `skill_trust_runtime_path_disallowed_benchmark_action` | `str` | `block` | `CS_SKILL_TRUST_RUNTIME_PATH_DISALLOWED_BENCHMARK_ACTION` | benchmark 模式 disallowed runtime path 动作 |
| `skill_trust_runtime_path_disallowed_strict_action` | `str` | `block` | `CS_SKILL_TRUST_RUNTIME_PATH_DISALLOWED_STRICT_ACTION` | strict 模式 disallowed runtime path 动作 |
| `skill_trust_runtime_path_disallowed_permissive_action` | `str` | `audit` | `CS_SKILL_TRUST_RUNTIME_PATH_DISALLOWED_PERMISSIVE_ACTION` | permissive 模式 disallowed runtime path 动作 |
| `skill_trust_runtime_source_ambiguous_normal_action` | `str` | `defer` | `CS_SKILL_TRUST_RUNTIME_SOURCE_AMBIGUOUS_NORMAL_ACTION` | normal 模式 ambiguous runtime source 动作 |
| `skill_trust_runtime_source_ambiguous_benchmark_action` | `str` | `block` | `CS_SKILL_TRUST_RUNTIME_SOURCE_AMBIGUOUS_BENCHMARK_ACTION` | benchmark 模式 ambiguous runtime source 动作 |
| `skill_trust_runtime_source_ambiguous_strict_action` | `str` | `defer` | `CS_SKILL_TRUST_RUNTIME_SOURCE_AMBIGUOUS_STRICT_ACTION` | strict 模式 ambiguous runtime source 动作 |
| `skill_trust_runtime_source_ambiguous_permissive_action` | `str` | `audit` | `CS_SKILL_TRUST_RUNTIME_SOURCE_AMBIGUOUS_PERMISSIVE_ACTION` | permissive 模式 ambiguous runtime source 动作 |
| `skill_trust_runtime_path_unverified_normal_action` | `str` | `audit` | `CS_SKILL_TRUST_RUNTIME_PATH_UNVERIFIED_NORMAL_ACTION` | normal 模式 unverified runtime path 动作 |
| `skill_trust_runtime_path_unverified_benchmark_action` | `str` | `audit` | `CS_SKILL_TRUST_RUNTIME_PATH_UNVERIFIED_BENCHMARK_ACTION` | benchmark 模式 unverified runtime path 动作 |
| `skill_trust_runtime_path_unverified_strict_action` | `str` | `defer` | `CS_SKILL_TRUST_RUNTIME_PATH_UNVERIFIED_STRICT_ACTION` | strict 模式 unverified runtime path 动作 |
| `skill_trust_runtime_path_unverified_permissive_action` | `str` | `audit` | `CS_SKILL_TRUST_RUNTIME_PATH_UNVERIFIED_PERMISSIVE_ACTION` | permissive 模式 unverified runtime path 动作 |
| `skill_trust_runtime_content_unverified_normal_action` | `str` | `force_l3` | `CS_SKILL_TRUST_RUNTIME_CONTENT_UNVERIFIED_NORMAL_ACTION` | normal 模式 unverified runtime content 动作 |
| `skill_trust_runtime_content_unverified_benchmark_action` | `str` | `defer` | `CS_SKILL_TRUST_RUNTIME_CONTENT_UNVERIFIED_BENCHMARK_ACTION` | benchmark 模式 unverified runtime content 动作 |
| `skill_trust_runtime_content_unverified_strict_action` | `str` | `defer` | `CS_SKILL_TRUST_RUNTIME_CONTENT_UNVERIFIED_STRICT_ACTION` | strict 模式 unverified runtime content 动作 |
| `skill_trust_runtime_content_unverified_permissive_action` | `str` | `audit` | `CS_SKILL_TRUST_RUNTIME_CONTENT_UNVERIFIED_PERMISSIVE_ACTION` | permissive 模式 unverified runtime content 动作 |
| `skill_trust_runtime_content_mismatch_normal_action` | `str` | `defer` | `CS_SKILL_TRUST_RUNTIME_CONTENT_MISMATCH_NORMAL_ACTION` | normal 模式 runtime content mismatch 动作 |
| `skill_trust_runtime_content_mismatch_benchmark_action` | `str` | `block` | `CS_SKILL_TRUST_RUNTIME_CONTENT_MISMATCH_BENCHMARK_ACTION` | benchmark 模式 runtime content mismatch 动作 |
| `skill_trust_runtime_content_mismatch_strict_action` | `str` | `block` | `CS_SKILL_TRUST_RUNTIME_CONTENT_MISMATCH_STRICT_ACTION` | strict 模式 runtime content mismatch 动作 |
| `skill_trust_runtime_content_mismatch_permissive_action` | `str` | `audit` | `CS_SKILL_TRUST_RUNTIME_CONTENT_MISMATCH_PERMISSIVE_ACTION` | permissive 模式 runtime content mismatch 动作 |
| `skill_trust_mirror_hash_max_files` | `int` | `200` | `CS_SKILL_TRUST_MIRROR_HASH_MAX_FILES` | runtime mirror content hash 最大文件数 |
| `skill_trust_mirror_hash_max_file_bytes` | `int` | `1048576` | `CS_SKILL_TRUST_MIRROR_HASH_MAX_FILE_BYTES` | runtime mirror content hash 单文件最大字节数 |
| `skill_trust_mirror_hash_max_total_ms` | `int` | `1000` | `CS_SKILL_TRUST_MIRROR_HASH_MAX_TOTAL_MS` | runtime mirror content hash 总毫秒预算 |
| `skill_trust_fspr_enabled` | `bool` | `false` | `CS_SKILL_TRUST_FSPR_ENABLED` | 启用 First-Use Skill Package Review |
| `skill_trust_fspr_pre_use_enabled` | `bool` | `false` | `CS_SKILL_TRUST_FSPR_PRE_USE_ENABLED` | pre-use gate FSPR evidence |
| `skill_trust_fspr_post_action_enabled` | `bool` | `false` | `CS_SKILL_TRUST_FSPR_POST_ACTION_ENABLED` | post-action incremental FSPR evidence |
| `skill_trust_fspr_review_mode` | `str` | `agentic-readonly` | `CS_SKILL_TRUST_FSPR_REVIEW_MODE` | FSPR 审查路线；默认 agentic-readonly，`final-only` 为备用 |
| `skill_trust_fspr_role_set` | `str` | `default` | `CS_SKILL_TRUST_FSPR_ROLE_SET` | legacy role-set；仅 `final-only` 兼容保留 |
| `skill_trust_fspr_timeout_ms` | `int` | `120000` | `CS_SKILL_TRUST_FSPR_TIMEOUT_MS` | FSPR 超时预算 |
| `skill_trust_fspr_cache_enabled` | `bool` | `true` | `CS_SKILL_TRUST_FSPR_CACHE_ENABLED` | 启用 FSPR cache |
| `skill_trust_fspr_provider_enabled` | `bool` | `false` | `CS_SKILL_TRUST_FSPR_PROVIDER_ENABLED` | 允许 provider-backed FSPR review path |
| `capability_narrowing_enabled` | `bool` | `false` | `CS_CAPABILITY_NARROWING_ENABLED` | 高会话风险时应用收窄的 SessionScopeProfile |
| `capability_narrowing_trigger_risk` | `str` | `high` | `CS_CAPABILITY_NARROWING_TRIGGER_RISK` | 自动收窄触发阈值：`low`、`medium`、`high`、`critical` |
| `capability_narrowing_allowed_tool_permission_groups` | `tuple[str, ...]` | `("read_only",)` | `CS_CAPABILITY_NARROWING_ALLOWED_TOOL_PERMISSION_GROUPS` | 自动收窄后允许的工具权限组 |
| `capability_narrowing_denied_tool_permission_groups` | `tuple[str, ...]` | `("write","network","credentialed","destructive","mcp_admin","unknown")` | `CS_CAPABILITY_NARROWING_DENIED_TOOL_PERMISSION_GROUPS` | 自动收窄后拒绝的工具权限组 |
| `capability_narrowing_allowed_skill_trust_states` | `tuple[str, ...]` | `("allowlist",)` | `CS_CAPABILITY_NARROWING_ALLOWED_SKILL_TRUST_STATES` | 自动收窄后允许的 Skill Trust 状态 |
| `capability_narrowing_denied_skill_trust_states` | `tuple[str, ...]` | `("blacklist","revoked")` | `CS_CAPABILITY_NARROWING_DENIED_SKILL_TRUST_STATES` | 自动收窄后拒绝的 Skill Trust 状态 |
| `capability_narrowing_allowed_mcp_servers` | `tuple[str, ...]` | `()` | `CS_CAPABILITY_NARROWING_ALLOWED_MCP_SERVERS` | 自动收窄后允许的 MCP server |
| `capability_narrowing_denied_mcp_servers` | `tuple[str, ...]` | `()` | `CS_CAPABILITY_NARROWING_DENIED_MCP_SERVERS` | 自动收窄后拒绝的 MCP server |
| `capability_narrowing_allowed_mcp_tools` | `tuple[str, ...]` | `("filesystem.read_file",)` | `CS_CAPABILITY_NARROWING_ALLOWED_MCP_TOOLS` | 自动收窄后允许的 MCP tool |
| `capability_narrowing_denied_mcp_tools` | `tuple[str, ...]` | `("fetch.fetch",)` | `CS_CAPABILITY_NARROWING_DENIED_MCP_TOOLS` | 自动收窄后拒绝的 MCP tool |
| `capability_narrowing_allowed_mcp_statuses` | `tuple[str, ...]` | `()` | `CS_CAPABILITY_NARROWING_ALLOWED_MCP_STATUSES` | 自动收窄后允许的 MCP 状态 |
| `capability_narrowing_denied_mcp_statuses` | `tuple[str, ...]` | `("blacklist","revoked","disabled")` | `CS_CAPABILITY_NARROWING_DENIED_MCP_STATUSES` | 自动收窄后拒绝的 MCP 状态 |
| `capability_narrowing_allowed_mcp_trust_levels` | `tuple[str, ...]` | `()` | `CS_CAPABILITY_NARROWING_ALLOWED_MCP_TRUST_LEVELS` | 自动收窄后允许的 MCP trust level |
| `capability_narrowing_denied_mcp_trust_levels` | `tuple[str, ...]` | `("untrusted","unknown","local_unreviewed")` | `CS_CAPABILITY_NARROWING_DENIED_MCP_TRUST_LEVELS` | 自动收窄后拒绝的 MCP trust level |
| `capability_narrowing_allowed_capabilities` | `tuple[str, ...]` | `()` | `CS_CAPABILITY_NARROWING_ALLOWED_CAPABILITIES` | 自动收窄后允许的 action capability |
| `capability_narrowing_denied_capabilities` | `tuple[str, ...]` | `()` | `CS_CAPABILITY_NARROWING_DENIED_CAPABILITIES` | 自动收窄后拒绝的 action capability |
| `capability_narrowing_queued_capabilities` | `tuple[str, ...]` | `()` | `CS_CAPABILITY_NARROWING_QUEUED_CAPABILITIES` | 自动收窄后转人工复核的 action capability |
| `capability_narrowing_audit_verbosity` | `str` | `summary` | `CS_CAPABILITY_NARROWING_AUDIT_VERBOSITY` | 自动收窄审计元数据详细度：`minimal`、`summary`、`verbose` |
| `capability_narrowing_greylist_action` | `str` | `defer` | `CS_CAPABILITY_NARROWING_GREYLIST_ACTION` | 自动收窄中 greylist skill 的处理：`allow`、`defer`、`block` |
| `tool_permission_group_overrides` | `str` | `""` | `CS_TOOL_PERMISSION_GROUP_OVERRIDES` | `tool=group[,group]` 映射；用于 capability narrowing 和 scope preview |
| `agent_safety_feedback_enabled` | `bool` | `false` | `CS_AGENT_SAFETY_FEEDBACK_ENABLED` | critical block 后生成红线化 agent feedback；response delivery 对同一 session/surface 只投递一次，greylist warning 使用独立 advisory envelope |

Skill Trust 动作允许值为 `audit`、`force_l2`、`force_l3`、`defer`、`block`。如果需要登记 skill registry，先运行 `clawsentry skill-trust register-dir`，再把生成的 registry/metadata 路径写入 env。详见 [Skill Trust / Registry](../advanced/skill-trust.md)。

---

## 完整参数参考 {#reference}

### 合成评分权重 {#scoring-weights}

这组参数控制 L1 风险评分计算中各维度的贡献比例。基础合成评分公式为：

```
base  = composite_weight_max_d123 × max(D1, D2, D3)
      + composite_weight_d4       × D4
      + composite_weight_d5       × D5

composite = base × (1.0 + d6_injection_multiplier × D6 / 3.0)
```

其中 D1–D3 为工具类型/权限/影响维度，D4 为会话累积，D5 为 Agent 信任级别，D6 为注入检测得分（0.0–3.0 连续值）。

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `composite_weight_max_d123` | `float` | `0.4` | `CS_COMPOSITE_WEIGHT_MAX_D123` | max(D1, D2, D3) 的权重，代表最严重的单维度威胁 |
| `composite_weight_d4` | `float` | `0.25` | `CS_COMPOSITE_WEIGHT_D4` | D4 会话累积风险的权重 |
| `composite_weight_d5` | `float` | `0.15` | `CS_COMPOSITE_WEIGHT_D5` | D5 Agent 信任级别的权重 |
| `d6_injection_multiplier` | `float` | `0.5` | `CS_D6_INJECTION_MULTIPLIER` | D6 注入乘数系数 X，公式见上方，X=0 则禁用 D6 影响 |

!!! warning "权重约束"
    所有权重字段（`composite_weight_max_d123`、`composite_weight_d4`、`composite_weight_d5`、`d6_injection_multiplier`）必须 **>= 0**，否则抛出 `ValueError`。

---

### 风险等级阈值 {#risk-thresholds}

合成评分与这些阈值比较，决定事件的最终风险等级（LOW / MEDIUM / HIGH / CRITICAL）：

| 字段名 | 类型 | 默认值 | CS_ 变量 | 触发条件 |
|--------|------|--------|----------|----------|
| `threshold_medium` | `float` | `0.8` | `CS_THRESHOLD_MEDIUM` | `composite >= threshold_medium` → MEDIUM（否则 LOW） |
| `threshold_high` | `float` | `1.5` | `CS_THRESHOLD_HIGH` | `composite >= threshold_high` → HIGH |
| `threshold_critical` | `float` | `2.2` | `CS_THRESHOLD_CRITICAL` | `composite >= threshold_critical` → CRITICAL |

**判断逻辑（从高到低依次匹配）：**

```python
if composite >= threshold_critical:  # 默认 2.2
    level = "CRITICAL"
elif composite >= threshold_high:    # 默认 1.5
    level = "HIGH"
elif composite >= threshold_medium:  # 默认 0.8
    level = "MEDIUM"
else:
    level = "LOW"
```

!!! warning "阈值排序约束"
    必须满足 `threshold_medium ≤ threshold_high ≤ threshold_critical`，否则抛出 `ValueError`。

    **示例**：以下配置会触发 ValueError，因为 medium > high：
    ```bash
    CS_THRESHOLD_MEDIUM=2.0
    CS_THRESHOLD_HIGH=1.0   # 违反约束 → 整体 fallback 到默认值
    ```

!!! warning "CRITICAL 等级不可达警告"
    如果 `threshold_critical > 3.0`，由于合成评分的理论最大值约为 3.0（使用默认权重时），CRITICAL 等级在实践中将永远不可达。ClawSentry 会记录一条 `WARNING` 日志，但**不会**抛出错误。

    这通常是配置错误，请检查您的 `CS_THRESHOLD_CRITICAL` 设置。

---

### D4 会话累积阈值 {#d4-thresholds}

D4 维度反映同一会话内高风险事件的累积计数，用于检测持续性攻击模式。

| 字段名 | 类型 | 默认值 | CS_ 变量 | 触发条件 |
|--------|------|--------|----------|----------|
| `d4_high_threshold` | `int` | `5` | `CS_D4_HIGH_THRESHOLD` | 累积计数 `>= d4_high_threshold` → D4 = 2（高） |
| `d4_mid_threshold` | `int` | `2` | `CS_D4_MID_THRESHOLD` | 累积计数 `>= d4_mid_threshold` → D4 = 1（中） |

累积计数低于 `d4_mid_threshold` 时，D4 = 0。

!!! warning "D4 阈值排序约束"
    必须满足 `d4_mid_threshold ≤ d4_high_threshold`，否则抛出 `ValueError`。

**调优建议：**

- 高安全场景（如生产环境自动化 Agent）：可降低阈值（例如 `d4_mid_threshold=1`，`d4_high_threshold=3`）以更激进地标记重复风险。
- 开发/测试环境：可适当提高阈值避免频繁误报。

---

### L2 语义分析 {#l2-params}

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `l2_budget_ms` | `float` | `60000.0` | `CS_L2_TIMEOUT_MS` | L2 分析的超时上限（毫秒），超时则跳过 L2 结果，使用 L1 判决 |
| `attack_patterns_path` | `Optional[str]` | `None` | `CS_ATTACK_PATTERNS_PATH` | 自定义攻击模式 YAML 文件路径；`None` 表示使用内置模式库 |

!!! warning "L2 预算约束"
    `l2_budget_ms` 必须 **> 0**，否则抛出 `ValueError`。

**`attack_patterns_path` 启动加载说明：**

当设置 `CS_ATTACK_PATTERNS_PATH` 指向自定义 YAML 文件时：

- ClawSentry 的 `PatternMatcher` 和 `RuleBasedAnalyzer` 将加载该文件中的模式，**替代**内置模式库。
- 文件修改后，**重启 Gateway** 即可生效（当前版本不支持运行时热重载）。
- 格式需与内置 `attack_patterns.yaml` 兼容。

```bash
# 示例：使用自定义模式库
CS_ATTACK_PATTERNS_PATH=/etc/clawsentry/my_patterns.yaml
```

如需在内置模式库基础上**追加**模式（而非替换），请参考 [自进化模式库](#evolving-params) 功能。

---

### Post-action 围栏阈值 {#post-action-params}

Post-action 分析器（`post_action_analyzer.py`）在 Agent 工具调用完成后**异步**检测输出内容，识别间接注入、数据泄露和混淆行为。这是非阻塞分析，不影响主决策链路。

风险评分超过对应阈值时，触发不同响应级别：

| 字段名 | 类型 | 默认值 | CS_ 变量 | 触发级别 |
|--------|------|--------|----------|----------|
| `post_action_monitor` | `float` | `0.3` | `CS_POST_ACTION_MONITOR` | `>= post_action_monitor` → MONITOR（记录日志） |
| `post_action_escalate` | `float` | `0.6` | `CS_POST_ACTION_ESCALATE` | `>= post_action_escalate` → ESCALATE（SSE 告警广播） |
| `post_action_emergency` | `float` | `0.9` | `CS_POST_ACTION_EMERGENCY` | `>= post_action_emergency` → EMERGENCY（高优先级告警） |
| `post_action_whitelist` | `Optional[tuple[str, ...]]` | `None` | `CS_POST_ACTION_WHITELIST` | 白名单正则列表，命中则跳过 Post-action 检测 |
| `post_action_finding_action` | `str` | `"broadcast"` | `CS_POST_ACTION_FINDING_ACTION` | Post-action finding 的处理方式：`broadcast` / `defer` / `block`；非法值回退到 `broadcast` |

!!! warning "Post-action 阈值排序约束"
    必须满足 `post_action_monitor ≤ post_action_escalate ≤ post_action_emergency`，否则抛出 `ValueError`。

`post_action_finding_action` 默认为 `broadcast`，仅广播 finding；设为 `defer` 或 `block` 时，Gateway 会将非 `log_only` finding 转换为 session enforcement 更新。

**`CS_POST_ACTION_WHITELIST` 格式：**

逗号分隔的正则表达式列表。工具调用输出内容若匹配任意一条正则，则跳过 Post-action 检测。空字符串和纯空白项自动忽略。

```bash
# 示例：排除内部域名和 base64 图片数据
CS_POST_ACTION_WHITELIST=^https://internal\.corp\.example\.com,^data:image/
```

---

### 轨迹分析器 {#trajectory-params}

轨迹分析器（`trajectory_analyzer.py`）在会话级别缓存工具调用事件序列，检测跨步骤的多阶段攻击模式（如 recon-then-exploit、staged-exfil 等）。

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `trajectory_max_events` | `int` | `50` | `CS_TRAJECTORY_MAX_EVENTS` | 每个会话最多缓存的事件数，超出时丢弃最旧事件（滑动窗口） |
| `trajectory_max_sessions` | `int` | `10000` | `CS_TRAJECTORY_MAX_SESSIONS` | 内存中最多保留的会话数，超出时 LRU 驱逐最久未活跃的会话 |
| `trajectory_alert_action` | `str` | `"broadcast"` | `CS_TRAJECTORY_ALERT_ACTION` | 轨迹命中后的处理方式：`broadcast` / `defer` / `block`；非法值回退到 `broadcast` |

**内存估算参考：**

- 每条缓存事件约占 1–2 KB 内存（含工具名、参数摘要等元数据）。
- 默认配置（50 事件 × 10000 会话）理论上限约为 **500 MB**，实际远低于此（大多数会话事件数远少于上限）。

`trajectory_alert_action` 默认为 `broadcast`，仅通过 SSE/审计面告警；设为 `defer` 或 `block` 时，Gateway 会把命中的 trajectory match 作为当前请求 finalization 阶段的处理依据。
- 高并发场景可适当降低 `CS_TRAJECTORY_MAX_SESSIONS`；长会话场景可适当提高 `CS_TRAJECTORY_MAX_EVENTS`。

---

### 自进化模式库 {#evolving-params}

E-5 自进化功能允许 ClawSentry 在运行过程中积累新发现的攻击模式候选，通过人工或自动确认后提升为活跃检测规则。

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `evolving_enabled` | `bool` | `False` | `CS_EVOLVING_ENABLED` | 是否启用自进化模式库功能 |
| `evolved_patterns_path` | `Optional[str]` | `None` | `CS_EVOLVED_PATTERNS_PATH` | 自进化模式 YAML 的持久化存储路径 |

**`CS_EVOLVING_ENABLED` 布尔值解析规则：**

| 环境变量值 | 解析结果 |
|-----------|----------|
| `1`、`true`、`yes`（不区分大小写） | `True` |
| `0`、`false`、`no`（不区分大小写） | `False` |
| 其他或未设置 | 使用默认值 `False` |

**启用示例：**

```bash
# 启用自进化模式库，并指定持久化路径
CS_EVOLVING_ENABLED=true
CS_EVOLVED_PATTERNS_PATH=/var/lib/clawsentry/evolved_patterns.yaml
```

!!! note "evolved_patterns_path 与 attack_patterns_path 的关系"
    - `CS_ATTACK_PATTERNS_PATH`：指定**核心**攻击模式库（替代内置 YAML），影响 L2 分析。
    - `CS_EVOLVED_PATTERNS_PATH`：指定**自进化**模式的持久化文件，在核心模式库基础上**追加**检测规则。
    - 两者可同时使用，最终有效模式集 = 核心模式 + 状态为 `experimental` 或 `stable` 的自进化模式。

---

### Anti-bypass Follow-up Guard {#anti-bypass-guard}

Anti-bypass follow-up guard 是默认关闭的 `PRE_ACTION` 重试/绕过检测层。启用后，Gateway 会在 quarantine 与 session enforcement 之后、normal policy 之前检查当前操作是否复用了 prior final risky decision 的紧凑指纹。

如果你想先理解适用场景、匹配类型与动作选择，请先阅读 [Anti-bypass Guard 决策引擎说明](../decision-layers/anti-bypass-guard.md)。

它只保存 compact evidence：hashes / fingerprints / tool / policy id / risk / record ids / timestamps / labels；不会保存 raw payload、raw command、secret、完整路径内容或 L3 trace。

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `anti_bypass_guard_enabled` | `bool` | `False` | `CS_ANTI_BYPASS_GUARD_ENABLED` | 总开关；默认保持现有行为不变 |
| `anti_bypass_memory_ttl_s` | `float` | `86400.0` | `CS_ANTI_BYPASS_MEMORY_TTL_S` | compact memory 保留时间（秒） |
| `anti_bypass_memory_max_records_per_session` | `int` | `256` | `CS_ANTI_BYPASS_MEMORY_MAX_RECORDS_PER_SESSION` | 单会话记录上限，超出时淘汰最旧记录 |
| `anti_bypass_min_prior_risk` | `str` | `"high"` | `CS_ANTI_BYPASS_MIN_PRIOR_RISK` | 参与匹配的 prior final risk 下限：`low` / `medium` / `high` / `critical` |
| `anti_bypass_prior_verdicts` | `tuple[str, ...]` | `("block", "defer")` | `CS_ANTI_BYPASS_PRIOR_VERDICTS` | 参与匹配的 prior final verdict，逗号分隔：`allow` / `defer` / `block` |
| `anti_bypass_exact_repeat_action` | `str` | `"block"` | `CS_ANTI_BYPASS_EXACT_REPEAT_ACTION` | same session + same tool + same raw canonical payload fingerprint 的动作 |
| `anti_bypass_normalized_destructive_repeat_action` | `str` | `"defer"` | `CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION` | same tool + same normalized action fingerprint 的动作 |
| `anti_bypass_cross_tool_similarity_action` | `str` | `"force_l3"` | `CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION` | cross-tool/script similarity 的动作；`block` 无效并回退到 `force_l3` |
| `anti_bypass_similarity_threshold` | `float` | `0.92` | `CS_ANTI_BYPASS_SIMILARITY_THRESHOLD` | 非精确 cross-tool/script similarity 阈值，范围 `0.0..1.0` |
| `anti_bypass_same_tool_similarity_threshold` | `float` | `0.88` | `CS_ANTI_BYPASS_SAME_TOOL_SIMILARITY_THRESHOLD` | same-tool destructive feature Jaccard 阈值，范围 `0.0..1.0` |
| `anti_bypass_record_allow_decisions` | `bool` | `False` | `CS_ANTI_BYPASS_RECORD_ALLOW_DECISIONS` | 是否也记录 compact allow-decision fingerprints |
| `anti_bypass_llm_recognition_enabled` | `bool` | `False` | `CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED` | 显式覆盖 sanitized LLM recognizer；未设置 env 时，guard 已启用且共享 `CS_LLM_*` provider 配置有效则自动启用 |
| `anti_bypass_llm_candidate_threshold` | `float` | `0.55` | `CS_ANTI_BYPASS_LLM_CANDIDATE_THRESHOLD` | 生成跨工具 LLM 候选的弱相似阈值 |
| `anti_bypass_llm_confidence_threshold` | `float` | `0.75` | `CS_ANTI_BYPASS_LLM_CONFIDENCE_THRESHOLD` | LLM 命中生效的最低 confidence |
| `anti_bypass_llm_timeout_ms` | `float` | `800.0` | `CS_ANTI_BYPASS_LLM_TIMEOUT_MS` | LLM recognizer 单次调用超时 |
| `anti_bypass_llm_max_priors` | `int` | `3` | `CS_ANTI_BYPASS_LLM_MAX_PRIORS` | 单次最多发送多少条 sanitized prior capsules |
| `anti_bypass_llm_action` | `str` | `"force_l3"` | `CS_ANTI_BYPASS_LLM_ACTION` | LLM 命中或非法返回时采用的动作；`block` 无效并回退 |

**动作权限边界：**

| Match type | 可选动作 | 本地 BLOCK 权限 |
|------------|----------|----------------|
| `exact_raw_repeat` | `observe` / `force_l2` / `force_l3` / `defer` / `block` | 可按配置本地 BLOCK |
| `normalized_destructive_repeat` | `observe` / `force_l2` / `force_l3` / `defer` / `block` | 仅在显式配置 `block` 时可本地 BLOCK |
| `cross_tool_script_similarity` | `observe` / `force_l2` / `force_l3` / `defer` | 永不本地 hard-block；`block` 配置会被拒绝/回退 |

**LLM recognizer 条件：** 未显式设置 `CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED` 时，会随有效共享 `CS_LLM_PROVIDER` + API key 自动启用；benchmark / dry-run / no-network 模式不会自动启用外部 LLM recognition，除非显式 `true`。显式 `false` 强制关闭。实际调用仍要求 `CS_ANTI_BYPASS_GUARD_ENABLED=true`、事件为 `PRE_ACTION`、deterministic 路径未确认、当前动作不是 `non-destructive`、已生成跨工具候选、至少两个弱证据信号（scope-only 不够）、provider 可用且 LLM budget 未耗尽。它只判断 follow-up 关系，不做风险评分，也不能产生本地 `block`。请求只包含 sanitized semantic capsules，不包含 raw command、raw payload、secret、env value、deterministic token hashes 或 L3 trace；LLM 返回的 `action` 不参与执法，命中后使用 `CS_ANTI_BYPASS_LLM_ACTION`。

**Rollout 示例：**

```bash title="Observe only：只记录 metadata/counter，不改变 verdict"
CS_ANTI_BYPASS_GUARD_ENABLED=true
CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=observe
CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=observe
CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=observe
```

```bash title="Review：exact/normalized 进入人工确认，cross-tool 请求 L3"
CS_ANTI_BYPASS_GUARD_ENABLED=true
CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=defer
CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=defer
CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=force_l3
```

```bash title="Enforce：只对 exact repeat 本地阻断"
CS_ANTI_BYPASS_GUARD_ENABLED=true
CS_ANTI_BYPASS_EXACT_REPEAT_ACTION=block
CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION=defer
CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION=force_l3
```

!!! warning "与 Session Enforcement 的边界"
    `AHP_SESSION_ENFORCEMENT_*` 仍只表示旧的 session-threshold enforcement。Anti-bypass guard 只使用 `DetectionConfig` / `CS_ANTI_BYPASS_*` 配置，不新增 `AHP_*` anti-bypass 环境变量。

!!! note "Final canonical decision memory"
    Guard memory 在 trajectory override、benchmark auto-resolution 和 `_record_decision_path` 完成后记录 `decision.final=true` 的 canonical decision。若该 final decision 是 `defer`，后续 defer bridge 的 operator / timeout resolution 不会回溯删除已记录的 compact fingerprint。


---

### 安全预设等级 {#presets}

ClawSentry 提供 4 个内置安全预设，通过 `.clawsentry.env.example` 或 `clawsentry config set` 一键切换。

| 参数 | low | medium (默认) | high | strict |
|------|-----|---------------|------|--------|
| `threshold_critical` | 2.8 | 2.2 | 1.8 | 1.3 |
| `threshold_high` | 2.0 | 1.5 | 1.2 | 0.9 |
| `threshold_medium` | 1.2 | 0.8 | 0.5 | 0.3 |
| `d6_injection_multiplier` | 0.3 | 0.5 | 0.7 | 1.0 |
| `post_action_emergency` | 0.95 | 0.9 | 0.8 | 0.7 |
| `post_action_escalate` | 0.7 | 0.6 | 0.5 | 0.4 |
| `post_action_monitor` | 0.4 | 0.3 | 0.2 | 0.15 |
| `defer_timeout_action` | allow | block | block | block |
| `defer_bridge_enabled` | false | true | true | true |

!!! tip "选择建议"
    - **low**：开发/测试环境，最大宽容度，DEFER 超时自动放行
    - **medium**（默认）：平衡安全与可用性，适合大多数场景
    - **high**：生产环境，更低的阈值意味着更多操作触发拦截
    - **strict**：高安全场景，D6 注入乘数为 1.0（最大放大），阈值最低

---

### D4 频率异常检测 {#d4-freq}

除传统的会话累积高危事件计数外，D4 还支持三层频率异常检测：

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `d4_freq_enabled` | `bool` | `True` | `CS_D4_FREQ_ENABLED` | 启用频率异常检测 |
| `d4_freq_burst_count` | `int` | `10` | `CS_D4_FREQ_BURST_COUNT` | 突发阈值：窗口内同工具调用次数 |
| `d4_freq_burst_window_s` | `float` | `5.0` | `CS_D4_FREQ_BURST_WINDOW_S` | 突发检测时间窗口（秒） |
| `d4_freq_repetitive_count` | `int` | `20` | `CS_D4_FREQ_REPETITIVE_COUNT` | 重复阈值：窗口内同工具调用次数 |
| `d4_freq_repetitive_window_s` | `float` | `60.0` | `CS_D4_FREQ_REPETITIVE_WINDOW_S` | 重复检测时间窗口（秒） |
| `d4_freq_rate_limit_per_min` | `int` | `60` | `CS_D4_FREQ_RATE_LIMIT_PER_MIN` | 全局每分钟速率上限 |

**三层检测模型：**

```
突发检测: 同一工具 ≥10 次/5s  → D4 = 2（高危）
重复检测: 同一工具 ≥20 次/60s → D4 = 1（中危）
速率检测: 全部工具 ≥60 次/min → D4 = 1（中危）
```

三层独立运行，最终 D4 取最高值。与传统 D4 累积值也取最高值。

---

### 外部内容安全 {#external-content}

当检测到工具处理外部来源内容时，自动提升安全检测灵敏度。

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `external_content_d6_boost` | `float` | `0.3` | `CS_EXTERNAL_CONTENT_D6_BOOST` | 外部内容 D6 加成 |
| `external_content_post_action_multiplier` | `float` | `1.3` | `CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER` | 外部内容 Post-action 乘数 |

**内容来源推断：**

`infer_content_origin()` 通过 tool_name 和 payload 推断：

- `external`：fetch、http_request、curl、wget 等网络获取工具
- `user`：用户直接输入的内容
- `unknown`：无法判断时的默认值

外部内容的检测增强逻辑：
- D6 注入评分 += `external_content_d6_boost`（默认 +0.3）
- Post-action 评分 × `external_content_post_action_multiplier`（默认 ×1.3）

---

### DEFER 超时配置 {#defer-timeout}

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `defer_timeout_action` | `str` | `"block"` | `CS_DEFER_TIMEOUT_ACTION` | 超时动作：`block` 或 `allow` |
| `defer_timeout_s` | `float` | `86400.0` | `CS_DEFER_TIMEOUT_S` | normal mode 审批软超时（秒）；benchmark mode 不等待人工审批 |
| `defer_bridge_enabled` | `bool` | `True` | `CS_DEFER_BRIDGE_ENABLED` | 启用 DEFER 审批桥接 |

**生命周期：**

```
DEFER 决策产生
    │
    ├─ defer_bridge_enabled=true
    │   ├─ 注册审批请求，广播 defer_pending SSE 事件
    │   ├─ 等待运维响应（最多 defer_timeout_s 秒）
    │   ├─ 收到 allow → 转为 ALLOW（decision_source=OPERATOR）
    │   ├─ 收到 deny  → 转为 BLOCK（decision_source=OPERATOR）
    │   └─ 超时 → 执行 defer_timeout_action（block 或 allow）
    │
    └─ defer_bridge_enabled=false
        └─ 直接返回 DEFER 给调用方处理
```

---

### LLM Token 预算 {#llm-budget}

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `llm_token_budget_enabled` | `bool` | `false` | `CS_LLM_TOKEN_BUDGET_ENABLED` | 是否启用 token budget 执法 |
| `llm_daily_token_budget` | `int` | `0` | `CS_LLM_DAILY_TOKEN_BUDGET` | 每日 token 上限；启用时必须大于 `0` |
| `llm_token_budget_scope` | `str` | `total` | `CS_LLM_TOKEN_BUDGET_SCOPE` | `total`、`input` 或 `output` |
| `llm_daily_budget_usd` | `float` | 兼容旧字段 | `CS_LLM_DAILY_BUDGET_USD` | 旧版 USD 估算字段；不推荐继续作为执法依据 |

预算控制机制：
- UTC 00:00 每日自动重置
- 每次 LLM 调用后记录 provider 返回的真实 input/output token usage
- 预算耗尽后 L2/L3 自动降级或阻断（取决于模式/策略）
- usage 缺失时增加 `unknown_usage_calls`，不使用估算价格伪造用量

---

### L3 触发设计开关 {#l3-trigger-design}

| 字段名 | 类型 | 默认值 | CS_ 变量 | 说明 |
|--------|------|--------|----------|------|
| `l3_routing_mode` | `str` | `"normal"` | `CS_L3_ROUTING_MODE` | L3 路由模式：`normal` 保持现状，`replace_l2` 在命中 organic L2 入口时直接改走本地 L3 |
| `l3_trigger_profile` | `str` | `"default"` | `CS_L3_TRIGGER_PROFILE` | 正常模式下的高层触发档位：`default` 保持现状，`eager` 让 L3 更容易被提升到 |
| `l3_budget_tuning_enabled` | `bool` | `false` | `CS_L3_BUDGET_TUNING_ENABLED` | 是否允许基于 L3 模式启用更宽松的默认预算；关闭时默认预算行为不变 |
| `l3_advisory_async_enabled` | `bool` | `false` | `CS_L3_ADVISORY_ASYNC_ENABLED` | 在 high/critical decision、high+ trajectory alert，或 heartbeat-compatible 事件后自动创建 frozen advisory snapshot 并入队 advisory job；当前不启动后台 scheduler |
| `l3_heartbeat_review_enabled` | `bool` | `false` | `CS_L3_HEARTBEAT_REVIEW_ENABLED` | 允许 heartbeat-compatible 事件（`heartbeat` / `idle` / `success` / `rate_limit`）走聚合 snapshot + queued job；不启用 timer-only full review |

约束：

- **默认行为不变**：以上三个字段全部保持默认值时，L1/L2/L3 行为与旧版本一致。
- **`replace_l2` 不等于强制 L3 follow-up**：它只在命中 organic L2 入口时改写路由，不会把所有请求都视为显式 `requested_tier=L3`。
- **预算扩容必须显式 opt-in**：只有 `l3_budget_tuning_enabled=true` 时，模式感知预算默认值才会生效；显式 `CS_L3_BUDGET_MS` 或 `CS_L3_TIMEOUT_MS` / 旧别名 `CS_L3_BUDGET_MS` 仍然优先。
- **Advisory 自动化必须显式 opt-in**：L3 咨询审查提供 frozen evidence snapshot / queued advisory job / advisory result 流程；打开 `l3_advisory_async_enabled` 会自动创建 snapshot 并入队 job，但不会自动运行后台 L3 审查或改变 canonical decision。启用 heartbeat review 时，非 heartbeat-compatible 的高风险即时 snapshot queueing 会被抑制，避免和聚合路径重复。
- **无本地 L3 能力时保持诚实回退**：如果网关启动时没有本地 L3 能力，`replace_l2` / `eager` 会被视为 unsupported runtime，现有 L1/L2 路径继续运行，但运行态会明确暴露 `l3_available=false`、`effective_tier=L3`、`l3_state=skipped`、`l3_reason_code=local_l3_unavailable`。

---

## 从 env 到 DetectionConfig {#project-config}

当前版本不读取 ClawSentry 项目级 section 配置；`DetectionConfig` 的输入是已经合成好的环境变量映射。`DetectionConfig` 的输入是已经合成好的环境变量映射：

```text
CLI 参数 / 进程环境 / 显式 env file
    │
    ▼
规范化 CS_* / AHP_* 有效值
    │
    ▼
build_detection_config_from_env()
    │
    ▼
DetectionConfig(frozen=True)
```

因此本页的每个字段都可以用对应 `CS_*` 变量配置；如果你需要可复制的场景配置，请使用 [配置模板](templates.md)。典型 workflow：

```bash
# 1. 生成 dotenv 模板；不会写 section 配置
clawsentry config wizard --non-interactive --framework codex --mode normal --force

# 2. 按需编辑 KEY=VALUE；本机密钥放 .clawsentry.env.local，且不要提交
cp .clawsentry.env.example .clawsentry.env.local

# 3. 显式检查来源和最终值
clawsentry config show --effective --env-file .clawsentry.env.local

# 4. 显式启动
clawsentry start --env-file .clawsentry.env.local --framework codex
```

优先级保持简单：

```text
CLI 参数 > 进程/部署环境变量 > 显式 env file > 白名单旧别名 > 内置默认值
```

Fail-open 行为：

- 未传 `--env-file` → 只使用 CLI、进程/部署环境和默认值。
- 显式 env file 不存在 → 命令报错，避免误以为空文件运行。
- 单个变量类型错误 → 忽略该变量并记录 warning。
- 多个字段组合违反 `DetectionConfig` 约束 → 整体回退默认 `DetectionConfig()` 并记录 error。

!!! tip "复制配置的位置"
    Anti-bypass、DEFER、post-action、benchmark、生产部署等直接可用片段统一维护在 [配置模板](templates.md)，本页只保留字段语义、默认值和约束。

---

## 验证约束 {#validation}

`DetectionConfig` 在 `__post_init__` 中执行以下验证。违反时的行为分为两类：

### 直接抛出 ValueError

下列约束违反时，`DetectionConfig` 构造函数立即抛出 `ValueError`：

| 约束 | 错误条件 |
|------|----------|
| 阈值排序 | `threshold_medium > threshold_high` 或 `threshold_high > threshold_critical` |
| D4 阈值排序 | `d4_mid_threshold > d4_high_threshold` |
| 权重非负 | `composite_weight_max_d123 < 0` 或 `composite_weight_d4 < 0` 或 `composite_weight_d5 < 0` 或 `d6_injection_multiplier < 0` |
| L2 / L3 / hard timeout 正数 | `l2_budget_ms <= 0`、`hard_timeout_ms <= 0`、或已设置的 `l3_budget_ms <= 0` |
| Post-action 阈值非负与排序 | 任一 `post_action_*` 阈值 `< 0`，或 `post_action_monitor > post_action_escalate` / `post_action_escalate > post_action_emergency` |
| Hard timeout 覆盖预算 | `hard_timeout_ms < l2_budget_ms` 或 `hard_timeout_ms < l3_budget_ms`（当 L3 budget 已设置） |
| Defer timeout 正数 | `defer_timeout_s <= 0` |
| LLM 预算非负 | `llm_daily_budget_usd < 0` 或 `llm_daily_token_budget < 0` |
| Anti-bypass memory TTL | `anti_bypass_memory_ttl_s <= 0` |
| Anti-bypass per-session 上限 | `anti_bypass_memory_max_records_per_session < 1` |
| Anti-bypass similarity 阈值 | `anti_bypass_similarity_threshold`、`anti_bypass_same_tool_similarity_threshold`、`anti_bypass_llm_candidate_threshold` 或 `anti_bypass_llm_confidence_threshold` 不在 `0.0..1.0` 范围内 |
| Anti-bypass LLM timeout / priors | `anti_bypass_llm_timeout_ms <= 0` 或 `anti_bypass_llm_max_priors < 1` |

### 记录 Warning 日志（不抛出错误）

| 条件 | 警告内容 |
|------|----------|
| `threshold_critical > 3.0` | "CRITICAL level may be unreachable"（CRITICAL 等级在实践中可能永远不可达） |
| 任一 `post_action_*` 阈值 `> 3.0` | 该阈值超出 post-action score `0.0..3.0` 可达范围 |
| `mode`、`l3_routing_mode`、`l3_trigger_profile` 非法 | 回退到 `normal` / `normal` / `default` |
| `trajectory_alert_action` 或 `post_action_finding_action` 非法 | 回退到 `broadcast` |
| `defer_timeout_action` 非法 | 回退到 `block` |
| `llm_token_budget_scope` 非法 | 回退到 `total` |
| token budget 启用但 limit 非正 | 禁用 token budget enforcement |
| `benchmark_defer_action` / `benchmark_persist_scope` 非法 | 回退到 `block` / `project` |
| anti-bypass prior risk/verdict/action 非法 | prior risk 回退到 `high`；prior verdicts 回退到 `block,defer`；exact/normalized/cross-tool/LLM action 分别回退到安全默认值 |

### 环境变量整体回退机制

当通过 `build_detection_config_from_env()` 从环境变量构建配置时：

- **单个变量解析失败**（如类型不匹配）：静默忽略该变量，使用该字段的默认值，记录 `WARNING` 日志。
- **组合后违反验证约束**（如阈值排序错误）：**整体回退**到 `DetectionConfig()`（全默认值），记录 `ERROR` 日志。

```
[ERROR] CS_ env vars produce invalid DetectionConfig (<错误原因>); falling back to defaults
```

这意味着配置错误**不会**导致 Gateway 启动失败，而是以安全的默认配置运行。如果观察到此日志，请检查 `CS_` 环境变量的值和组合是否满足验证约束。

---

## 代码位置 {#code-locations}

| 文件 | 使用的配置字段 |
|------|----------------|
| `src/clawsentry/gateway/detection_config.py` | `DetectionConfig` dataclass 定义 + `build_detection_config_from_env()` 工厂函数 |
| `src/clawsentry/gateway/risk_snapshot.py` | `composite_weight_*`、`threshold_*`、`d4_*` |
| `src/clawsentry/gateway/policy_engine.py` | `l2_budget_ms`、`attack_patterns_path` |
| `src/clawsentry/gateway/semantic_analyzer.py` | `attack_patterns_path` |
| `src/clawsentry/gateway/post_action_analyzer.py` | `post_action_*`（阈值和白名单） |
| `src/clawsentry/gateway/trajectory_analyzer.py` | `trajectory_max_events`、`trajectory_max_sessions` |
| `src/clawsentry/gateway/server.py` | `trajectory_alert_action`、`post_action_finding_action`、`anti_bypass_*` decision path 集成 |
| `src/clawsentry/gateway/pattern_matcher.py` | `attack_patterns_path` |
| `src/clawsentry/gateway/project_config.py` | 兼容旧 import 的 env-first facade；实际解析委托给 `env_config.py` |
