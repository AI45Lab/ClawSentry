# 环境变量参考

ClawSentry 通过环境变量和显式 env file 配置，遵循 12-Factor App 原则。本页是变量索引：查默认值、含义和兼容旧名请看这里；复制成套配置请看[配置模板](templates.md)；理解来源优先级请看[配置总览](configuration-overview.md)。

---

## 显式 env file 支持

ClawSentry 不再自动加载当前目录的 `.env.clawsentry`，也不会在启动时自动读取 `.clawsentry.env.example`。本机密钥、端口覆盖、provider API key 等运行时值应来自进程/部署环境，或通过 `--env-file PATH` / `CLAWSENTRY_ENV_FILE=PATH` 显式传入。解析阶段是非突变的：命令先得到隔离的 key/value 和 provenance，再按优先级合成有效配置。

!!! info "显式加载规则"
    - 推荐本机文件名：`.clawsentry.env.local`（加入 `.gitignore`，不要提交）
    - `.clawsentry.env.example` 是可提交模板；复制到 `.clawsentry.env.local` 后再填本机值
    - 旧 `.env.clawsentry` 只作为 legacy/migration 文件名；需要复用时必须显式 `--env-file .env.clawsentry`
    - 已存在的进程环境变量优先于 env file
    - 支持 `#` 注释和引号包裹的值
    - 使用 Python 标准库实现，零外部依赖

```bash title=".clawsentry.env.local 示例"
# Gateway 核心配置
CS_HTTP_HOST=0.0.0.0
CS_HTTP_PORT=8080
CS_AUTH_TOKEN=my-secret-token

# LLM 配置
CS_LLM_PROVIDER=openai
CS_LLM_API_KEY=sk-xxx
CS_LLM_MODEL=gpt-4o-mini

# Token 预算（可选，基于 provider 真实 usage 执法）
CS_LLM_TOKEN_BUDGET_ENABLED=false
```

```bash
clawsentry start --env-file .clawsentry.env.local
clawsentry config show --effective --env-file .clawsentry.env.local
```

---

## Gateway 核心

控制 Gateway 服务的基本运行参数。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_HTTP_HOST` | `127.0.0.1` | HTTP 服务监听地址。设为 `0.0.0.0` 以接受外部连接 |
| `CS_HTTP_PORT` | `8080` | HTTP 服务端口 |
| `CS_AUTH_TOKEN` | (空=禁用认证) | Bearer Token 认证密钥。设置后所有 API 请求须携带 `Authorization: Bearer <token>` 头 |
| `CS_TRAJECTORY_DB_PATH` | `/tmp/clawsentry-trajectory.db` | SQLite 轨迹数据库路径。存储所有决策记录和审计轨迹 |
| `CS_UDS_PATH` | `/tmp/clawsentry.sock` | Unix Domain Socket 路径。主传输通道，延迟最低 |
| `CS_RATE_LIMIT_PER_MINUTE` | `300` | 每分钟最大请求数。设为 `0` 禁用速率限制。超限时返回 HTTP 429 |
| `AHP_TRAJECTORY_RETENTION_SECONDS` | `2592000` (30 天) | 轨迹数据保留时间（秒）。过期记录自动清理 |
| `CS_FRAMEWORK` | (空) | 默认 framework 名称；用于 `start`/harness/source framework 默认值 |
| `CS_ENABLED_FRAMEWORKS` | (空) | 逗号分隔的启用 framework 列表，例如 `codex,claude-code` |

!!! note "多框架配置"
    框架启用状态现在也是 env-first：使用 `CS_FRAMEWORK` / `CS_ENABLED_FRAMEWORKS`，或让 `clawsentry config wizard` 写入同名 `KEY=VALUE` 模板。

!!! tip "生产环境建议"
    - 必须设置 `CS_AUTH_TOKEN` 以启用认证
    - 将 `CS_TRAJECTORY_DB_PATH` 指向持久化存储（非 `/tmp`）
    - UDS 文件会自动设置 `chmod 600` 权限，仅限属主进程访问

---

## LLM / 决策层

配置 L2 语义分析和 L3 审查 Agent 的 LLM 提供商。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_LLM_PROVIDER` | (空=仅规则引擎) | LLM 提供商。可选值：`anthropic`、`openai`、留空 |
| `CS_LLM_MODEL` | (provider 默认) | 覆盖默认模型名称。如 `claude-sonnet-4-20250514`、`gpt-4o-mini` |
| `CS_LLM_BASE_URL` | (provider 默认) | OpenAI 兼容 API 基础 URL。用于自托管模型（Ollama、vLLM 等） |
| `CS_L3_ENABLED` | `false` | 启用 L3 审查 Agent。需要先配置 LLM provider。可选值：`true`/`1`/`yes` |
| `CS_L3_MULTI_TURN` | `true`（仅在 `CS_L3_ENABLED=true` 时生效） | 控制 L3 运行模式。默认标准多轮；仅 `false`/`0`/`no`/`off` 会强制 legacy 单轮；留空或其他值使用多轮 |
| `ANTHROPIC_API_KEY` | - | Anthropic API 密钥。`CS_LLM_PROVIDER=anthropic` 时必填 |
| `OPENAI_API_KEY` | - | OpenAI API 密钥。`CS_LLM_PROVIDER=openai` 时必填 |
| `CS_LLM_API_KEY` | - | 通用 LLM API 密钥。作为 `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` 的替代方案，`doctor` 检查时也会检测此变量 |
| `CS_LLM_API_KEY_ENV` | - | 指向自定义 API key 环境变量名；当 `CS_LLM_API_KEY` 为空时读取该变量，适合 secret manager 注入 |

!!! warning "API 密钥安全"
    API 密钥属于敏感信息，建议通过进程/部署环境、密钥管理系统，或显式 `--env-file .clawsentry.env.local` 注入，切勿写入 `.clawsentry.env.example`、脚本或版本控制。

### 决策层级关系

```
CS_LLM_PROVIDER 未设置  →  仅 L1 规则引擎（零延迟，零成本）
CS_LLM_PROVIDER 已设置  →  L1 + L2 语义分析（CompositeAnalyzer）
CS_L3_ENABLED=true       →  L1 + L2 + L3 审查 Agent（完整三层）
```

!!! note "L3 运行模式默认值"
    通过 `build_analyzer_from_env()` 装配时，只要 `CS_L3_ENABLED=true` 且未显式关闭，L3 默认以 `multi_turn` 模式运行。
    如需临时保留旧的单轮行为，请设置 `CS_L3_MULTI_TURN=false`。

---

## Skill Trust / capability narrowing / agent feedback

v0.7.0 新增的 Skill Trust / capability narrowing / agent feedback surfaces 默认关闭或 audit-only。它们用于 skill 供应链审计、会话风险后能力收紧，以及 critical block 后给支持的宿主返回红线化提示。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_SKILL_TRUST_REGISTRY_PATH` | (空) | Skill Trust registry JSON 路径；为空时仅使用请求上下文或 Gateway runtime metadata |
| `CS_SKILL_TRUST_METADATA_PATH` | (空) | Gateway-owned runtime metadata JSON 路径，通常由 `clawsentry skill-trust register-dir` 生成 |
| `CS_SKILL_TRUST_FIRST_USE_NORMAL_ACTION` | `audit` | normal 模式下首次/未绑定 skill 的动作：`audit`、`force_l2`、`force_l3`、`defer`、`block` |
| `CS_SKILL_TRUST_FIRST_USE_BENCHMARK_ACTION` | `audit` | benchmark 模式下首次/未绑定 skill 的动作 |
| `CS_SKILL_TRUST_FIRST_USE_STRICT_ACTION` | `audit` | strict 模式下首次/未绑定 skill 的动作 |
| `CS_SKILL_TRUST_FIRST_USE_PERMISSIVE_ACTION` | `audit` | permissive 模式下首次/未绑定 skill 的动作 |
| `CS_CAPABILITY_NARROWING_ENABLED` | `false` | 高会话风险时应用收窄的 SessionScopeProfile，不静默改写历史 canonical decision |
| `CS_AGENT_SAFETY_FEEDBACK_ENABLED` | `false` | critical `pre_action` block 时写入红线化 feedback；支持交互的宿主可收到 response feedback，否则 audit-only |

完整用法见 [Skill Trust / Registry](../advanced/skill-trust.md)、[Session scope 配置](session-scope.md) 和 [策略调优](policy-tuning.md#skill-trust-capability-narrowing-and-feedback)。

---

## 检测管线调优（DetectionConfig）

`DetectionConfig` 是 ClawSentry 检测管线的统一配置对象，所有参数均可通过 `CS_` 环境变量覆盖，完全向后兼容（默认值与原硬编码一致）。

!!! info "何时需要调整"
    默认配置适合绝大多数场景。仅在以下情况考虑调整：
    - 特定业务场景误报/漏报率过高
    - 需要更激进的注入检测灵敏度
    - 生产环境中需降低某类检测的资源消耗

### 合成评分权重

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_COMPOSITE_WEIGHT_MAX_D123` | `0.4` | max(D1,D2,D3) 的权重系数 |
| `CS_COMPOSITE_WEIGHT_D4` | `0.25` | D4 会话累积的权重系数 |
| `CS_COMPOSITE_WEIGHT_D5` | `0.15` | D5 信任等级的权重系数 |
| `CS_D6_INJECTION_MULTIPLIER` | `0.5` | D6 注入乘数 X（公式：base × (1.0 + X × D6/3.0)） |

### 风险阈值

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_THRESHOLD_CRITICAL` | `2.2` | composite_score >= 此值 → CRITICAL |
| `CS_THRESHOLD_HIGH` | `1.5` | composite_score >= 此值 → HIGH |
| `CS_THRESHOLD_MEDIUM` | `0.8` | composite_score >= 此值 → MEDIUM |

!!! warning "阈值约束"
    必须满足 `threshold_medium ≤ threshold_high ≤ threshold_critical`，否则启动时自动回退到默认值并记录错误日志。

### D4 会话累积阈值

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_D4_HIGH_THRESHOLD` | `5` | 高危事件数 >= 此值 → D4=2（最高级别） |
| `CS_D4_MID_THRESHOLD` | `2` | 高危事件数 >= 此值 → D4=1（中等级别） |

### L2 语义分析

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_L2_TIMEOUT_MS` | `60000` | L2 分析软超时（毫秒）。超时自动降级为 L1 结果 |
| `CS_L2_BUDGET_MS` | 兼容旧名 | 旧别名；新配置请改用 `CS_L2_TIMEOUT_MS` |
| `CS_ATTACK_PATTERNS_PATH` | (内置 25 条) | 自定义攻击模式 YAML 文件路径。设置后覆盖内置模式库 |

### Post-action 分析阈值

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_POST_ACTION_EMERGENCY` | `0.9` | score >= 此值 → EMERGENCY（触发 SSE 广播+紧急告警） |
| `CS_POST_ACTION_ESCALATE` | `0.6` | score >= 此值 → ESCALATE（上报人工审核） |
| `CS_POST_ACTION_MONITOR` | `0.3` | score >= 此值 → MONITOR（写入告警日志） |
| `CS_POST_ACTION_WHITELIST` | (空) | 白名单文件路径正则，逗号分隔。命中则跳过 post-action 分析 |

### 轨迹分析器

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_TRAJECTORY_MAX_EVENTS` | `50` | 每会话保留的最大事件数（滑动窗口容量上限） |
| `CS_TRAJECTORY_MAX_SESSIONS` | `10000` | 全局最大会话追踪数（超限按 LRU 淘汰最旧会话） |

### Anti-bypass Follow-up Guard（默认关闭） {#anti-bypass-guard-env}

Anti-bypass guard 用于检测 `PRE_ACTION` 中对 prior final risky decision 的重复/近似绕过尝试。默认完全关闭；启用后只保存 compact hashes/fingerprints/ids/labels，不保存 raw command、raw payload、secret 或 L3 trace。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_ANTI_BYPASS_GUARD_ENABLED` | `false` | 启用 anti-bypass follow-up guard |
| `CS_ANTI_BYPASS_MEMORY_TTL_S` | `86400` | compact memory 保留时间（秒） |
| `CS_ANTI_BYPASS_MEMORY_MAX_RECORDS_PER_SESSION` | `256` | 单会话 compact memory 上限 |
| `CS_ANTI_BYPASS_MIN_PRIOR_RISK` | `high` | 参与匹配的 prior final risk 下限：`low` / `medium` / `high` / `critical` |
| `CS_ANTI_BYPASS_PRIOR_VERDICTS` | `block,defer` | 参与匹配的 prior final verdict，逗号分隔 |
| `CS_ANTI_BYPASS_EXACT_REPEAT_ACTION` | `block` | same session + same tool + same raw payload fingerprint 的动作 |
| `CS_ANTI_BYPASS_NORMALIZED_DESTRUCTIVE_REPEAT_ACTION` | `defer` | same normalized destructive intent 的动作 |
| `CS_ANTI_BYPASS_CROSS_TOOL_SIMILARITY_ACTION` | `force_l3` | cross-tool/script similarity 的动作；`block` 无效并回退到 `force_l3` |
| `CS_ANTI_BYPASS_SIMILARITY_THRESHOLD` | `0.92` | cross-tool/script similarity 阈值，范围 `0.0..1.0` |
| `CS_ANTI_BYPASS_SAME_TOOL_SIMILARITY_THRESHOLD` | `0.88` | same-tool destructive soft similarity 阈值，范围 `0.0..1.0` |
| `CS_ANTI_BYPASS_RECORD_ALLOW_DECISIONS` | `false` | 是否记录 compact allow-decision fingerprints |
| `CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED` | unset / auto | 显式覆盖 sanitized LLM recognizer：`true` 强制启用（需 provider 可用），`false` 强制关闭；未设置时，guard 已启用且共享 `CS_LLM_PROVIDER` + API key 有效则自动启用，benchmark / dry-run / no-network 模式除外 |
| `CS_ANTI_BYPASS_LLM_CANDIDATE_THRESHOLD` | `0.55` | 生成跨工具 LLM 候选的弱相似阈值 |
| `CS_ANTI_BYPASS_LLM_CONFIDENCE_THRESHOLD` | `0.75` | LLM follow-up 判定生效的最低 confidence |
| `CS_ANTI_BYPASS_LLM_TIMEOUT_MS` | `800` | LLM recognizer 单次调用超时 |
| `CS_ANTI_BYPASS_LLM_MAX_PRIORS` | `3` | 单次最多发送多少条 sanitized prior capsules |
| `CS_ANTI_BYPASS_LLM_ACTION` | `force_l3` | LLM 命中或模型返回非法动作时采用的动作：`observe` / `force_l2` / `force_l3` / `defer` |

!!! warning "Cross-tool/script 不本地 hard-block"
    `cross_tool_script_similarity` 可 `observe` / `force_l2` / `force_l3` / `defer`，但不能本地 `block`。若 deterministic 或 LLM action 配置为 `block`，会被校验逻辑回退到 `force_l3`；LLM 返回的 `action` 不参与执法，Gateway 始终按 `CS_ANTI_BYPASS_LLM_ACTION` 处理 LLM-assisted match。

!!! note "LLM recognizer 的隐私边界"
    未显式设置 `CS_ANTI_BYPASS_LLM_RECOGNITION_ENABLED` 时，只有同时启用 guard、共享 `CS_LLM_*` provider 配置有效、非 benchmark / dry-run / no-network、命中跨工具候选且 LLM budget 未耗尽，Gateway 才会发送 sanitized semantic capsules。候选必须至少有两个弱证据信号，scope-only 不会触发；当前 `non-destructive` 动作不会触发 LLM-assisted force review。显式 `false` 会关闭该路径。capsule 不包含 raw command、raw payload、secret、env value 或 L3 trace；也不会包含 deterministic token hashes。

!!! note "与 AHP_SESSION_ENFORCEMENT_* 的关系"
    `AHP_SESSION_ENFORCEMENT_*` 仍只控制会话阈值执法；anti-bypass guard 只使用 `CS_ANTI_BYPASS_*`。

### 自进化模式库（E-5）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_EVOLVING_ENABLED` | `false` | 启用自进化模式库。可选值：`true`/`1`/`yes` |
| `CS_EVOLVED_PATTERNS_PATH` | (空) | 进化模式 YAML 文件存储路径（启用时必须配置） |

!!! example "启用自进化模式库"
    ```bash
    CS_EVOLVING_ENABLED=true
    CS_EVOLVED_PATTERNS_PATH=/var/lib/clawsentry/evolved_patterns.yaml
    ```
    启用后，Gateway 会从高风险事件中自动提取候选模式，并通过 `POST /ahp/patterns/confirm` API 接受人工反馈，推动模式从 CANDIDATE → EXPERIMENTAL → STABLE 升级。

---

## Scope 限制 {#scope-restrictions-env}

Scope 限制用来给 ClawSentry 配置默认任务边界。设置后，Gateway 会在每个没有显式 scope 的 `pre_action` 决策中自动套用这份 profile。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_SESSION_SCOPE_PROFILE_FILE` | (空) | 默认 `SessionScopeProfile` JSON 文件路径。设置后，`clawsentry start` 期间每个工具执行前决策都会自动进行 scope 检查 |
| `CS_SESSION_SCOPE_PROFILE` | (空) | 兼容别名；建议新配置使用 `CS_SESSION_SCOPE_PROFILE_FILE` |

!!! example "开启默认 scope 自动检查"
    ```bash
    CS_SESSION_SCOPE_PROFILE_FILE=scope.json clawsentry start --framework codex
    ```
    profile 内需要设置 `confirmed: true` 与 `dry_run: false` 才会真实收紧为 `defer` / `block`；否则只解释不阻断。

---

## 会话执法

当单个会话累积多次高危决策时，自动触发强制措施。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `AHP_SESSION_ENFORCEMENT_ENABLED` | `false` | 启用会话级强制策略。可选值：`true`/`1`/`yes` |
| `AHP_SESSION_ENFORCEMENT_THRESHOLD` | `3` | 触发强制措施的高危决策累积次数（最小值为 1） |
| `AHP_SESSION_ENFORCEMENT_ACTION` | `defer` | 强制措施类型。可选值见下表 |
| `AHP_SESSION_ENFORCEMENT_COOLDOWN_SECONDS` | `600` | 冷却期（秒）。到期后自动释放，允许会话恢复正常 |

**强制措施类型**

| 值 | 行为 |
|----|------|
| `defer` | 所有后续 `pre_action` 事件强制 DEFER，等待运维确认 |
| `block` | 所有后续 `pre_action` 事件直接 BLOCK |
| `l3_require` | 所有后续 `pre_action` 事件强制触发 L3 审查 Agent |

!!! example "配置示例"
    ```bash
    # 累积 5 次高危后阻断会话，冷却期 10 分钟
    AHP_SESSION_ENFORCEMENT_ENABLED=true
    AHP_SESSION_ENFORCEMENT_THRESHOLD=5
    AHP_SESSION_ENFORCEMENT_ACTION=block
    AHP_SESSION_ENFORCEMENT_COOLDOWN_SECONDS=600
    ```

---

## 安全

TLS 加密、Webhook 安全和 L3 Skills 扩展相关配置。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `AHP_SSL_CERTFILE` | - | SSL/TLS 证书文件路径（PEM 格式） |
| `AHP_SSL_KEYFILE` | - | SSL/TLS 私钥文件路径（PEM 格式） |
| `AHP_WEBHOOK_IP_WHITELIST` | (空=不限制) | Webhook 来源 IP 白名单，逗号分隔。设置后仅允许列表内 IP 发送 Webhook |
| `AHP_WEBHOOK_TOKEN_TTL_SECONDS` | `86400` (24h) | Webhook Token 有效期（秒）。设为 `0` 禁用过期检查 |
| `AHP_SKILLS_DIR` | - | 自定义 L3 Skills YAML 目录路径。加载后与内置 Skills 合并 |
| `AHP_HTTP_URL` | (自动计算) | a3s-code HTTP Transport 目标 URL。默认基于 `CS_HTTP_HOST`/`CS_HTTP_PORT` 自动生成 |

!!! note "TLS 配置"
    同时设置 `AHP_SSL_CERTFILE` 和 `AHP_SSL_KEYFILE` 后，Gateway 将以 HTTPS 模式启动。
    ```bash
    AHP_SSL_CERTFILE=/etc/ssl/certs/clawsentry.pem
    AHP_SSL_KEYFILE=/etc/ssl/private/clawsentry-key.pem
    ```

!!! note "IP 白名单格式"
    ```bash
    # 允许特定 IP
    AHP_WEBHOOK_IP_WHITELIST=10.0.0.1,10.0.0.2,192.168.1.100
    ```

---

## OpenClaw 集成

连接 OpenClaw Gateway 实现实时审批执行。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `OPENCLAW_WS_URL` | `ws://127.0.0.1:18789` | OpenClaw Gateway WebSocket URL |
| `OPENCLAW_OPERATOR_TOKEN` | - | OpenClaw 操作员认证 Token。在 `~/.openclaw/openclaw.json` 的 `gateway.auth.token` 中获取 |
| `OPENCLAW_ENFORCEMENT_ENABLED` | `false` | 启用 OpenClaw 审批执行（WS 监听 + 自动决策） |
| `OPENCLAW_WEBHOOK_HOST` | `127.0.0.1` | Webhook 接收器监听地址 |
| `OPENCLAW_WEBHOOK_PORT` | `8081` | Webhook 接收器端口 |
| `OPENCLAW_WEBHOOK_SECRET` | - | Webhook HMAC 签名密钥（用于验证请求完整性） |
| `OPENCLAW_WEBHOOK_TOKEN` | (内置默认) | Webhook Bearer Token（用于请求认证） |
| `OPENCLAW_MAPPING_GIT_SHA` | - | 归一化映射 Git SHA（事件归一化版本标识） |

### OpenClaw 自动检测

ClawSentry 会自动检测 OpenClaw 配置状态：

- 当 `OPENCLAW_WEBHOOK_TOKEN` 不等于内置默认值，或 `OPENCLAW_ENFORCEMENT_ENABLED=true` 时，自动启动 Webhook 接收器和 WS 事件监听
- 否则以 Gateway-only 模式运行

!!! warning "启用 Enforcement 前必读"
    设置 `OPENCLAW_ENFORCEMENT_ENABLED=true` 时，必须同时配置：

    - `OPENCLAW_OPERATOR_TOKEN` — 否则 WS 连接将失败
    - `OPENCLAW_WS_URL` — 必须以 `ws://` 或 `wss://` 开头

    启动时会执行预检验证，配置缺失将给出明确错误提示并退出。

---

## D4 频率异常检测

三层频率异常检测，捕获 Agent 行为中的突发、重复和速率异常。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_D4_FREQ_ENABLED` | `true` | 启用 D4 频率异常检测。可选值：`true`/`1`/`yes` |
| `CS_D4_FREQ_BURST_COUNT` | `10` | 突发检测：同一工具在窗口期内调用次数 ≥ 此值 → D4=2 |
| `CS_D4_FREQ_BURST_WINDOW_S` | `5.0` | 突发检测时间窗口（秒） |
| `CS_D4_FREQ_REPETITIVE_COUNT` | `20` | 重复检测：同一工具在窗口期内调用次数 ≥ 此值 → D4=1 |
| `CS_D4_FREQ_REPETITIVE_WINDOW_S` | `60.0` | 重复检测时间窗口（秒） |
| `CS_D4_FREQ_RATE_LIMIT_PER_MIN` | `60` | 全局速率限制：所有工具每分钟总调用数 ≥ 此值 → D4=1 |

!!! info "检测层级"
    三层检测独立运行，取最高 D4 值：

    - **突发（Burst）**：短时间内同一工具密集调用（如 5 秒内 ≥10 次） → D4=2
    - **重复（Repetitive）**：中等时间窗口内同一工具大量调用（如 60 秒内 ≥20 次） → D4=1
    - **速率（Rate）**：全局工具调用速率过高（如每分钟 ≥60 次） → D4=1

---

## 外部内容安全

当工具处理外部来源内容时（如 fetch、http_request 等），自动提升安全检测灵敏度。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_EXTERNAL_CONTENT_D6_BOOST` | `0.3` | 外部内容 D6 注入检测加成值。叠加在原始 D6 评分之上 |
| `CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER` | `1.3` | 外部内容 Post-action 分析乘数。放大输出检测评分 |

!!! example "内容来源推断"
    ClawSentry 通过 `infer_content_origin()` 函数从 tool_name 和 payload 推断内容来源：

    - `external`：fetch、http_request、curl、wget 等网络工具
    - `user`：用户直接输入
    - `unknown`：无法判断来源时使用默认值

---

## DEFER 桥接

DEFER 决策的运维审批桥接配置，控制超时行为和操作员交互。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_DEFER_TIMEOUT_ACTION` | `block` | DEFER 超时后的默认动作。可选值：`block`（安全优先）或 `allow`（可用性优先） |
| `CS_DEFER_TIMEOUT_S` | `86400` (24 小时) | normal mode 下 DEFER 等待运维审批的软超时（秒）；benchmark mode 不等待人工审批 |
| `CS_DEFER_BRIDGE_ENABLED` | `true` | 启用 DEFER→运维审批桥接。可选值：`true`/`1`/`yes` |

!!! warning "超时策略选择"
    - `block`（默认）：超时后阻断操作，**安全优先**。适合生产环境。
    - `allow`：超时后放行操作，**可用性优先**。适合开发/低安全场景。

---

## Latch Hub 集成

Latch Hub 是可选的远程监控组件，支持移动设备推送审批和跨设备事件转发。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_LATCH_HUB_URL` | (空) | Latch Hub 基础 URL（如 `http://127.0.0.1:3006`） |
| `CS_LATCH_HUB_PORT` | `3006` | Latch Hub 端口（当 `CS_LATCH_HUB_URL` 未设置时作为回退） |
| `CS_HUB_BRIDGE_ENABLED` | `auto` | Hub 事件转发开关。`auto` 在检测到 Hub 运行时自动启用，`true` 强制启用，`false` 禁用 |

---

## Prometheus 可观测性

Prometheus 指标导出配置，需安装 `clawsentry[metrics]` 可选依赖。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_METRICS_ENABLED` | `auto` | 指标端点启用模式。`auto` 在安装 prometheus_client 时自动启用 |
| `CS_METRICS_AUTH` | `true` | `/metrics` 端点是否需要 Bearer Token 认证。设为 `false` 允许 Prometheus 无认证抓取 |

---

## LLM Token 预算

限制 LLM API 每日 token 使用量，防止 L2/L3 决策层资源失控。执法只使用 provider 返回的真实 `LLMUsage`，不再用 USD 估算价格触发阻断。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_LLM_TOKEN_BUDGET_ENABLED` | `false` | 是否启用 token 预算执法 |
| `CS_LLM_DAILY_TOKEN_BUDGET` | `0` | 每日 token 上限；启用时必须大于 `0` |
| `CS_LLM_TOKEN_BUDGET_SCOPE` | `total` | 预算作用域：`total`、`input` 或 `output` |
| `CS_LLM_DAILY_BUDGET_USD` | 兼容旧名 | 旧版 USD 预算字段；仅用于迁移提示或估算 telemetry，新部署不要依赖它执法 |

!!! info "预算机制"
    - 按 UTC 日期计算，每天 00:00 UTC 自动重置
    - 预算耗尽后，L2/L3 自动降级或阻断（取决于当前模式和策略）
    - 通过 SSE 广播 `budget_exhausted` 兼容事件，并附带 token 字段
    - provider 未返回 usage 时增加 `unknown_usage_calls`，不伪造 token 用量

---

## Codex Session Watcher

`clawsentry start --framework codex` 默认启用 Session Watcher 并安装/刷新 managed native hooks；`clawsentry init codex --setup` 可作为修复或手动刷新入口。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_CODEX_SESSION_DIR` | *(空)* | Codex 会话 JSONL 目录路径。显式设置时直接启用 Watcher |
| `CODEX_HOME` | `~/.codex` | Codex 根目录。仅在 `CS_CODEX_WATCH_ENABLED=true` 时用于自动检测 session 目录 |
| `CS_CODEX_WATCH_ENABLED` | `false`（`init codex` 写入 `true`） | 启用 Codex Session Watcher 自动探测 |
| `CS_CODEX_WATCH_POLL_INTERVAL` | `1.0` | Watcher 轮询间隔（秒） |
| `CS_FRAMEWORK` | (空) | Codex watcher 事件的默认 source framework；通常设为 `codex` |

!!! note "Codex watcher 启用顺序"
    `CS_CODEX_SESSION_DIR` 显式设置时优先使用该目录；否则在 `CS_CODEX_WATCH_ENABLED=true` 时从 `CODEX_HOME`（默认 `~/.codex`）自动探测 `sessions/`。Watcher 会按 JSONL offset 追踪新增事件，重启后继续从已处理位置之后读取，避免重复广播旧事件。

---

## L3 审查 Agent 预算

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_L3_TIMEOUT_MS` | `300000` | L3 审查 Agent 独立软超时（毫秒） |
| `CS_L3_BUDGET_MS` | 兼容旧名 | 旧别名；新配置请改用 `CS_L3_TIMEOUT_MS` |
| `CS_L3_ROUTING_MODE` | `normal` | L3 路由模式：`normal` 保持现状；`replace_l2` 在命中 organic L2 入口时直接本地 L3 替换 L2 |
| `CS_L3_TRIGGER_PROFILE` | `default` | 正常模式触发档位：`default` 保持现状；`eager` 让 L3 更容易被正常模式提升到 |
| `CS_L3_BUDGET_TUNING_ENABLED` | `false` | 是否允许按 L3 模式启用更大的默认预算。显式 `CS_L3_BUDGET_MS` 仍然优先 |
| `CS_L3_ADVISORY_ASYNC_ENABLED` | `false` | 启用 advisory snapshot 自动创建：high/critical decision 或 high+ trajectory alert 后冻结当前 trajectory record range。当前不自动启动真实 L3 review scheduler |
| `CS_L3_HEARTBEAT_REVIEW_ENABLED` | `false` | 预留给 heartbeat/idle 聚合后的 advisory snapshot review。默认关闭，且不启用 timer-only full review |
| `CS_LLM_PROVIDER` | (空) | L2/L3 与 L3 advisory `llm_provider` 共用的 provider：`openai` / `anthropic` |
| `CS_LLM_MODEL` | (provider 默认) | L2/L3 与 L3 advisory `llm_provider` 共用模型名 |
| `CS_LLM_BASE_URL` | (provider 默认) | OpenAI-compatible endpoint；L3 advisory `llm_provider` 会继承 |
| `CS_LLM_TEMPERATURE` | `0.0` | L2/L3 与 L3 advisory provider 调用共用 temperature |
| `CS_LLM_PROVIDER_TIMEOUT_MS` | `3000` | L2/L3 与 L3 advisory provider 调用共用 timeout |
| `CS_L3_ADVISORY_RUN_REAL_SMOKE` | `false` | 仅用于测试套件里的真实 provider readiness gate；默认跳过真实网络调用 |
| `CS_L3_ADVISORY_SMOKE_STRIP_PROXY_ENV` | `true` | 手动 readiness check 默认剥离 proxy 环境变量，避免本地 SOCKS proxy 缺依赖污染 provider client；需经代理时可显式设为 `false` |

!!! note "多轮模式的延迟与成本"
    `CS_L3_ENABLED=true` 时，运行时默认使用多轮 L3。相比 legacy 单轮，这会增加平均延迟和 token 成本；若需要保守 rollout，可显式设置 `CS_L3_MULTI_TURN=false`。

!!! info "本地 L3 不可用时的运行态语义"
    如果配置了 `CS_L3_ROUTING_MODE=replace_l2` 或 `CS_L3_TRIGGER_PROFILE=eager`，但网关启动时没有本地 L3 能力，系统不会伪装成已执行 L3。它会保留原有 L1/L2 回退路径，同时明确输出：

    - `l3_available=false`
    - `effective_tier=L3`
    - `actual_tier=<真实执行层级>`
    - `l3_state=skipped`
    - `l3_reason_code=local_l3_unavailable`

!!! info "L3 咨询审查"
    `CS_L3_ADVISORY_ASYNC_ENABLED` 和 `CS_L3_HEARTBEAT_REVIEW_ENABLED`
    是 L3 咨询审查的显式 opt-in 开关。系统会持久化 frozen evidence snapshot 与 `advisory_only=true` review 结果，并通过 report / watch / UI 暴露状态；打开 `CS_L3_ADVISORY_ASYNC_ENABLED` 只会自动创建 snapshot，不会运行后台 L3 review，也不会修改 canonical decision。详见 [L3 咨询审查](../decision-layers/l3-advisory.md)。

!!! warning "Advisory provider 继承 CS_LLM_*"
    L3 advisory full-review 和 queued job 默认使用 `llm_provider`，并继承 `CS_LLM_PROVIDER`、provider API key、`CS_LLM_MODEL`、`CS_LLM_BASE_URL`、`CS_LLM_TEMPERATURE` 与 `CS_LLM_PROVIDER_TIMEOUT_MS`。如果这些配置缺失或无效，系统会写入 `l3_state=degraded` review 和 provider/config reason，而不是静默 fallback 到 `deterministic_local`。

!!! tip "手动 readiness check"
    如需验证 advisory provider 链路，可用随包提供的 devtools 模块做 operator-controlled
    readiness check。该流程会构造一个 frozen snapshot、排队并执行一个 `llm_provider` job，并可通过
    `--output-report <path>` 写出 markdown 证据。缺少 `CS_LLM_*` 时会生成 degraded 结果；`--require-completed` 用作真实 provider execution gate。测试套件里的真实网络 gate 还需要
    `CS_L3_ADVISORY_RUN_REAL_SMOKE=true`，否则默认跳过。

---

## 完整配置示例

### 最小配置（仅 L1 规则引擎）

```bash title="无需 env file"
# 无需任何配置，开箱即用
# 所有变量使用默认值
```

### 开发环境配置

```bash title=".clawsentry.env.local"
CS_HTTP_HOST=127.0.0.1
CS_HTTP_PORT=8080
CS_RATE_LIMIT_PER_MINUTE=0

# L2 语义分析
CS_LLM_PROVIDER=openai
OPENAI_API_KEY=sk-xxx
CS_LLM_BASE_URL=http://localhost:11434/v1
CS_LLM_MODEL=qwen2.5:7b
```

### 生产环境配置

```bash title="/etc/clawsentry/gateway.env"
# Gateway 核心
CS_HTTP_HOST=0.0.0.0
CS_HTTP_PORT=8080
CS_AUTH_TOKEN=prod-secret-token-xxxxx
CS_TRAJECTORY_DB_PATH=/var/lib/clawsentry/trajectory.db
CS_UDS_PATH=/var/run/clawsentry/gateway.sock
CS_RATE_LIMIT_PER_MINUTE=300

# TLS
AHP_SSL_CERTFILE=/etc/ssl/certs/clawsentry.pem
AHP_SSL_KEYFILE=/etc/ssl/private/clawsentry-key.pem

# 三层决策
CS_LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-xxx
CS_L3_ENABLED=true

# 会话执法
AHP_SESSION_ENFORCEMENT_ENABLED=true
AHP_SESSION_ENFORCEMENT_THRESHOLD=3
AHP_SESSION_ENFORCEMENT_ACTION=defer
AHP_SESSION_ENFORCEMENT_COOLDOWN_SECONDS=600

# Scope 限制：配置后每次 pre_action 自动检查任务边界
CS_SESSION_SCOPE_PROFILE_FILE=/etc/clawsentry/scope.json

# Webhook 安全
AHP_WEBHOOK_IP_WHITELIST=10.0.0.0/8
AHP_WEBHOOK_TOKEN_TTL_SECONDS=3600

# Prometheus + Token 预算
CS_LLM_TOKEN_BUDGET_ENABLED=true
CS_LLM_DAILY_TOKEN_BUDGET=200000
CS_LLM_TOKEN_BUDGET_SCOPE=total
CS_METRICS_AUTH=false

# DEFER 桥接
CS_DEFER_BRIDGE_ENABLED=true
CS_DEFER_TIMEOUT_S=86400
CS_DEFER_TIMEOUT_ACTION=block

# OpenClaw 集成
OPENCLAW_ENFORCEMENT_ENABLED=true
OPENCLAW_OPERATOR_TOKEN=your-openclaw-token
OPENCLAW_WS_URL=ws://127.0.0.1:18789
OPENCLAW_WEBHOOK_SECRET=your-hmac-secret
```

---

## 环境变量优先级

```
CLI 参数 > 进程/部署环境变量 > 显式 env file > 白名单旧别名 > 内置默认值
```

!!! tip "调试技巧"
    使用 `clawsentry config show --effective --env-file .clawsentry.env.local` 查看每个字段的来源。若旧 `.env.clawsentry` 短期仍需复用，必须显式传入 `--env-file .env.clawsentry`；没有这个参数时不会自动加载。
