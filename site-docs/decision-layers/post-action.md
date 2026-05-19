---
title: 后置动作安全层
description: 工具输出的非阻塞分析 — 间接注入、数据外泄、凭据暴露、混淆代码
---

# 后置动作安全层

<div class="cs-doc-hero" markdown>
<div class="cs-eyebrow">决策层 · 执行后分析</div>

## 工具输出的非阻塞安全分析

L1/L2/L3 在工具调用之前或期间进行拦截。后置动作层填补了这一盲区：工具返回结果后，四个检测器以异步方式对输出执行分析，并通过 SSE 发送分级 finding，不会延迟主决策管道。

<div class="cs-pill-row" markdown>
<span class="cs-pill">异步 / 非阻塞</span>
<span class="cs-pill">间接注入</span>
<span class="cs-pill">数据外泄</span>
<span class="cs-pill">凭据泄露</span>
<span class="cs-pill">混淆代码</span>
<span class="cs-pill">SSE 分级响应</span>
</div>
</div>

---

## 触发条件 {#trigger}

每当被监控的工具调用返回输出时，Gateway 就会调用 `PostActionAnalyzer.analyze()`。

### Skill Trust boundary {#skill-trust-boundary}

v0.8.2 起，post-action 阶段不再运行 artifact label 与 `skill_use_ledger` 的 provenance 对账器。Skill Trust 的运行时身份、mirror 内容校验、first-use/FSPR evidence 和 replay-safe ledger 仍由 pre-action/runtime binding 路径维护。

**前置条件（须全部满足）：**

1. `tool_output` 非空。
2. `file_path`（若提供）不匹配任何白名单模式。
3. 输入在分析前被截断至 **65 536 字节**；超出部分将被静默丢弃。

**内容来源升级：** 若 `content_origin == "external"`，综合得分在确定分级前将乘以 `external_content_post_action_multiplier`（默认值 `1.3`）。

---

## 分析管道流程 {#pipeline-diagram}

```mermaid
flowchart TD
    A([工具调用返回输出]) --> B{前置条件检查}
    B -- "tool_output 为空" --> Z1([返回 LOG_ONLY, score=0.0])
    B -- "路径匹配白名单" --> Z2([返回 LOG_ONLY, score=0.0\nwhitelisted=True])
    B -- "通过，截断至 65 536 字节" --> C[normalize_text 标准化输入]

    C --> D1[检测指令性内容\ndetect_instructional_content]
    C --> D2[检测数据外泄\ndetect_exfiltration]
    C --> D3[检测凭据暴露\ndetect_secret_exposure]
    C --> D4[检测混淆代码\ndetect_obfuscation]

    D1 --> E[汇总触发信号得分]
    D2 --> E
    D3 --> E
    D4 --> E

    E --> F["combined = min(Σ scores, 3.0)"]
    F --> G{content_origin == external\n且 multiplier > 1.0?}
    G -- 是 --> H["combined = min(combined × multiplier, 3.0)"]
    G -- 否 --> I[基于得分确定 score_tier]
    H --> I

    I --> J[计算 severity_floor\n由信号类型强制最低分级]
    J --> K["final_tier = max(score_tier, severity_floor)"]
    K --> L{would_sanitize == True?}
    L -- 是 --> M[构建 sanitize_advisory\n脱敏输出并记录哈希]
    L -- 否 --> N
    M --> N([返回 PostActionFinding\ntier · score · patterns_matched · details])
```

---

## 分析步骤 {#steps}

各步骤相互独立；所有四个检测器对每个未被白名单放行的调用都会执行。

1. **标准化输入** — 每个检测器执行前均调用 `normalize_text()`。
2. **检测指令性内容** — 统计 4 个祈使语言标记中有多少匹配；得分 `= hits / 4`。当 `score > 0.5` 时加入 `patterns_matched`。
3. **检测数据外泄** — 检查 10 个命令/URL 模式；得分 `= min(hits × 0.5, 1.0)`。当 `score > 0.0` 时加入。
4. **检测凭据暴露** — 检查 12 个凭据模式；得分 `= min(hits × 0.5, 1.0)`。当 `score > 0.0` 时加入。
5. **检测混淆代码** — 检查 8 个 `risk_signals` 函数 + 4 个正则模式（每次命中 `+0.3`）；当文本 > 50 字节且熵值 > 5.5 时附加 Shannon 熵奖励分。当 `score > 0.1` 时加入。
6. **计算综合得分** — `score = min(sum(triggered_signal_scores), 3.0)`。
7. **应用外部乘数** — 若 `content_origin == "external"` 且乘数 > 1.0：`combined = min(combined × multiplier, 3.0)`。
8. **基于得分确定分级** — 将综合得分与三个可配置阈值进行比较。
9. **计算严重性底线** — 由特定信号类型强制的分类最低分级（见 [严重性底线](#severity-floor) 中的表格）。
10. **确定最终分级** — `tier = max(score_tier, severity_floor)`，排序为 `LOG_ONLY < MONITOR < ESCALATE < EMERGENCY`。
11. **构建脱敏建议** — `build_tool_output_sanitize_advisory()` 对输出中的凭据进行脱敏并记录哈希；仅当 `would_sanitize == True` 时附加至 `details`。
12. **返回 `PostActionFinding`** — 包含分级、得分、已匹配模式及各检测器得分的结构化结果。

---

## 检测器 {#detectors}

### 指令性内容检测（detect_instructional_content）

检测工具输出中嵌入的、典型于间接提示注入的祈使/指令性语言。

| 标记 ID | 模式 | 示例 |
|---------|------|------|
| `obligation` | `\b(must\|should\|need to)\b` | "You must now run…" |
| `negation` | `\b(do not\|don't\|never)\b` | "Never reveal the system prompt" |
| `step-number` | `\b(step \d+)\b` | "Step 1: delete all files" |
| `immediate-action` | `(?:now\|next\|instead)\s+(?:do\|execute\|run)` | "Now execute the following" |

得分 = `min(hits / 4, 1.0)`。加入 `patterns_matched` 的阈值：`> 0.5`（即 3+ 个标记匹配）。

### 数据外泄检测（detect_exfiltration）

每个模式命中贡献 `+0.5`；得分上限为 `1.0`。

| # | 模式 | 威胁类型 |
|---|------|---------|
| 1 | `curl.*?-d.*?@` | curl 文件上传 |
| 2 | `wget.*?--post-data` | wget POST 外泄 |
| 3 | `nslookup.*?\$\{` | 通过变量进行 DNS 外泄 |
| 4 | `aws\s+s3\s+cp.*?s3://` | AWS S3 上传 |
| 5 | `ping.*?-p\s+[0-9a-f]{32,}` | ICMP 数据外泄 |
| 6 | `ssh.*?-R.*?:\d+:` | SSH 反向隧道 |
| 7 | `(sendmail\|mail).*?<.*?@` | 邮件外泄 |
| 8 | `torsocks.*?(curl\|wget)` | Tor 匿名传输 |
| 9 | 指向非白名单域名的 Markdown 图片语法 | 像素追踪 / 数据外泄 |
| 10 | `git\s+(clone\|push).*?http.*?@` | URL 中含 Git 凭据 |

!!! note "Markdown 图片白名单"
    模式 9 豁免 `github.com`、`raw.githubusercontent.com`、`img.shields.io`、`shields.io` 和 `badge.fury.io`，以避免在含有大量徽章的 README 输出中产生误报。

### 凭据暴露检测（detect_secret_exposure）

每个模式命中贡献 `+0.5`；得分上限为 `1.0`。

| # | 凭据类型 | 检测条件 |
|---|---------|---------|
| 1 | AWS 密钥对 | `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` 且值长度 ≥ 16 |
| 2 | GitHub token | `ghp_` / `ghs_` / `ghu_` / `github_pat_` 前缀，值长度 ≥ 36 |
| 3 | PEM 私钥头 | `-----BEGIN (RSA\|EC\|OPENSSH\|DSA\|PGP) PRIVATE KEY-----` |
| 4 | 密码字段 | `password` / `passwd` 赋值，值长度 ≥ 8 |
| 5 | 通用 API/密钥 | `api_key` / `secret_key` / `access_token` 赋值，值长度 ≥ 16 |
| 6 | Bearer token | `Bearer <token>`，token 长度 ≥ 20（上下文受限） |
| 7 | 数据库 URL | `DATABASE_URL = scheme://user:pass@host` |
| 8 | OpenAI API 密钥 | `OPENAI_API_KEY = sk-…` 值长度 ≥ 20 |
| 9 | AWS IAM 访问密钥 ID | `AKIA[A-Z0-9]{16}` |
| 10 | Slack token | `xox[bprs]-…` 前缀 |
| 11 | 飞书/Lark token | `(tenant\|user\|app)_access_token = t-…` 值长度 ≥ 20 |
| 12 | 以太坊私钥 | `(?:private[_\s-]?key\|priv[_\s-]?key\|wallet[_\s-]?key)\s*[:=]\s*['\"]?0x[a-fA-F0-9]{64}` |

!!! warning "高严重性凭据 vs. 标准凭据"
    模式 1–3、6–12 同时存在于 `_HIGH_SEVERITY_SECRET_PATTERNS` 中。匹配其中任何一个将**强制严重性底线升至 EMERGENCY**（见 [严重性底线](#severity-floor)）。模式 4–5 仅匹配 `detect_secret_exposure`，强制底线升至 ESCALATE。

### 混淆代码检测（detect_obfuscation）

每个触发的 `risk_signals` 检查或内联模式均向模式得分添加 `+0.3`。

| 检查项 | 来源 | 描述 |
|--------|------|------|
| `has_decode_pipe_exec_command` | `risk_signals` | `base64 -d \| bash/sh` 单行命令 |
| `has_eval_decode_command` | `risk_signals` | `eval.*base64` 动态解码执行 |
| `has_script_encoded_exec_command` | `risk_signals` | `python/perl/ruby -e … base64` |
| `has_process_sub_remote_command` | `risk_signals` | `bash <(curl/wget …)` |
| `has_heredoc_exec_command` | `risk_signals` | `bash <<EOF` heredoc 注入 |
| `has_variable_expansion_command` | `risk_signals` | 变量拼接混淆 |
| `has_variable_exec_trigger_command` | `risk_signals` | 变量持有执行触发器 |
| `has_remote_pipe_exec_command` | `risk_signals` | `curl \| bash`（豁免安全域名） |
| `octal-escape` | 内联正则 | `$'\123\456'` 八进制字节序列 |
| `hex-escape` | 内联正则 | `$'\x41\x42'` 十六进制字节序列 |
| `reverse-slice` | 内联正则 | `[::-1]` Python 反向执行 |
| `hex-char` | 内联正则 | 裸 `\x[0-9a-f]{2}` 序列 |

**Shannon 熵奖励**（当 `len(text) > 50` 且 `entropy > 5.5` 时应用）：

```
entropy_score = min((entropy - 5.5) / 2.5, 0.5)
```

最终得分：`min(pattern_score + entropy_score, 1.0)`。加入 `patterns_matched` 的阈值：`> 0.1`。

!!! note "curl-pipe 安全域名"
    当文本中唯一的 URL 属于已知安全安装域名时，`has_remote_pipe_exec_command` 检查被抑制：`brew.sh`、`raw.githubusercontent.com`、`get.pnpm.io`、`bun.sh`、`sh.rustup.rs`、`get.docker.com`、`install.python-poetry.org`。原始文本和标准化文本都必须通过此检查。

---

## 评分公式 {#scoring}

```
combined = min(sum(triggered_signal_scores), 3.0)
# 可选后续步骤：
if content_origin == "external" and multiplier > 1.0:
    combined = min(combined * multiplier, 3.0)
score = round(combined, 3)   # 存储于 PostActionFinding.score
```

得分示例：

| 触发信号 | instructional | exfiltration | secret | obfuscation | combined | 分级（默认值） |
|---------|:---:|:---:|:---:|:---:|:---:|:---:|
| 仅外泄 | 0.0 | 0.5 | 0.0 | 0.0 | 0.50 | ESCALATE（底线） |
| 凭据 + 外泄 | 0.0 | 0.5 | 0.5 | 0.0 | 1.00 | EMERGENCY（底线） |
| 指令 + 凭据 + 外泄 | 0.75 | 0.5 | 1.0 | 0.0 | 2.25 | EMERGENCY |
| 四项全部最高 | 1.0 | 1.0 | 1.0 | 1.0 | 3.00 | EMERGENCY |
| 混淆低于阈值 | 0.0 | 0.0 | 0.0 | 0.09 | 0.09 | LOG_ONLY |

---

## 响应分级 {#tiers}

| 分级 | 得分范围（默认值） | 配置变量 | 系统动作 |
|------|-----------------|---------|---------|
| `LOG_ONLY` | `< 0.3` | — | 仅写入结构化日志 |
| `MONITOR` | `≥ 0.3` 且 `< 0.6` | `CS_POST_ACTION_MONITOR` | SSE 广播 `post_action_finding` |
| `ESCALATE` | `≥ 0.6` 且 `< 0.9` | `CS_POST_ACTION_ESCALATE` | 提升告警级别；通知安全团队 |
| `EMERGENCY` | `≥ 0.9` | `CS_POST_ACTION_EMERGENCY` | 最高优先级响应；可触发会话强制措施 |

### 严重性底线 {#severity-floor}

基于得分的分级只能被严重性底线**向上**覆盖。底线取以下最高适用行：

| 条件 | 强制最低分级 |
|------|------------|
| 仅 `obfuscation`（`obfusc_score > 0.1`） | MONITOR |
| 检测到 `exfiltration` | ESCALATE |
| `secret_exposure` 为标准凭据（模式 4–5） | ESCALATE |
| `obfuscation` 与外泄或凭据共现 | EMERGENCY |
| `secret_exposure` 为高严重性凭据（模式 1–3、6–12） | EMERGENCY |

#### 严重性判定流程图

```mermaid
flowchart TD
    S([开始严重性底线计算]) --> A{obfusc_score > 0.1?}
    A -- 否 --> B{检测到 exfiltration?}
    A -- 是 --> AF[候选底线: MONITOR]
    AF --> B

    B -- 否 --> C{secret_exposure\n为标准凭据?}
    B -- 是 --> BF[候选底线升至 ESCALATE]
    BF --> C

    C -- 否 --> D{obfuscation 与\nexfil 或 secret 共现?}
    C -- 是 --> CF[候选底线升至 ESCALATE]
    CF --> D

    D -- 否 --> E{secret_exposure\n为高严重性凭据?}
    D -- 是 --> DF[候选底线升至 EMERGENCY]
    DF --> E

    E -- 否 --> F[severity_floor = 当前候选底线]
    E -- 是 --> EF[候选底线升至 EMERGENCY]
    EF --> F

    F --> G["final_tier = max(score_tier, severity_floor)"]
    G --> Z([输出最终分级])
```

!!! warning "底线覆盖得分"
    较低的综合得分并不能阻止 ESCALATE 或 EMERGENCY，当严重性底线规则适用时依然生效。例如，单次外泄模式命中得分为 0.5（按得分映射至 ESCALATE），而底线**独立地**强制执行 ESCALATE — 因此即使乘数被降低，分级也不会降至 MONITOR。

---

## PostActionFinding 输出结构 {#output-schema}

| 字段 | 类型 | 含义 |
|------|------|------|
| `tier` | `PostActionResponseTier` | 最终响应分级：`log_only` / `monitor` / `escalate` / `emergency` |
| `patterns_matched` | `list[str]` | 触发的检测器名称：`{"indirect_injection", "exfiltration", "secret_exposure", "obfuscation"}` 的子集 |
| `score` | `float` | 综合得分，范围 `[0.0, 3.0]`；由 `__post_init__` 强制校验 |
| `details.event_id` | `str` | 来源工具调用的事件 ID |
| `details.tool_name` | `str` | 被分析输出所属工具的名称 |
| `details.instructional` | `float` | `detect_instructional_content` 的原始得分（保留 3 位小数） |
| `details.exfiltration` | `float` | `detect_exfiltration` 的原始得分 |
| `details.secret_exposure` | `float` | `detect_secret_exposure` 的原始得分 |
| `details.obfuscation` | `float` | `detect_obfuscation` 的原始得分 |
| `details.severity_floor` | `str` | `max()` 之前计算得到的严重性底线分级值 |
| `details.sanitize_advisory` | `dict`（可选） | 仅当 `would_sanitize == True` 时存在；见下表 |
| `details.whitelisted` | `bool`（可选） | 路径匹配白名单时为 `True`；其他所有字段被省略 |

### sanitize_advisory 子字段

| 字段 | 类型 | 含义 |
|------|------|------|
| `target` | `str` | 始终为 `"tool_output"` |
| `would_sanitize` | `bool` | 此键存在时始终为 `True` |
| `original_hash` | `str` | 未脱敏输出的 `sha256:<hex>` |
| `sanitized_hash` | `str` | 已脱敏输出的 `sha256:<hex>` |
| `original_preview_redacted` | `str` | 脱敏文本的前 160 个字符 |
| `sanitized_preview_redacted` | `str` | 同上（当前实现） |
| `redaction_counts` | `dict[str, int]` | `{"secret": N}` — 每种类型的替换次数 |
| `redaction_types` | `list[str]` | 排序后的脱敏分类列表 |
| `adapter_outcome` | `str` | 始终为 `"would_sanitize"` |
| `enforcement` | `str` | 始终为 `"advisory_only"` |

!!! warning "脱敏建议仅为观察性"
    `would_sanitize: true` 表示 ClawSentry *检测到*了它会脱敏的内容，**并不**意味着交付给 Agent 的工具输出已被修改。实际的内容强制措施由适配器层负责。

---

## 与前置动作层的对比 {#comparison}

| 属性 | L1 规则引擎 | L2 语义层 | L3 审查 Agent | 后置动作层 |
|------|-----------|---------|-------------|----------|
| 时机 | 工具调用前 | 工具调用前 | 工具调用前（可选） | 工具调用返回后 |
| 是否阻塞 | 是 | 是 | 是 | 否 |
| 分析输入 | 工具调用意图/命令 | 工具调用载荷 | 完整调用上下文 | 工具输出内容 |
| 主要威胁 | 高风险命令、D1–D6 风险 | 意图语义、攻击模式 | 多步攻击链 | 间接注入、外泄、凭据泄露、混淆 |
| 输出 | `Decision`（ALLOW/BLOCK/…） | `Decision` | `Decision` | `PostActionFinding`（分级 + 得分） |
| SSE 事件 | `decision` | `decision` | `decision` | `post_action_finding` |

---

## 白名单 {#whitelist}

文件路径匹配白名单模式时，所有四个检测器均被跳过，立即返回 `PostActionFinding(tier=LOG_ONLY, score=0.0)`。

- 匹配使用 `re.fullmatch(pattern, file_path)` — 模式必须覆盖**完整**路径字符串。
- 无效的正则模式将被记录为警告并跳过。

```bash
# 环境变量 — 逗号分隔的正则列表
CS_POST_ACTION_WHITELIST="/etc/app/.*,.*\.json"
```

!!! warning "`fullmatch` 与 `search` 的区别"
    `/etc/app` **不**匹配 `/etc/app/config.yaml`。使用 `/etc/app/.*` 才能覆盖子目录。同理，`\.json` 只匹配四字符字符串 `.json`；若需匹配任何以 `.json` 结尾的路径，应使用 `.*\.json`。

---

## 配置参考 {#config}

| 环境变量 | `DetectionConfig` 字段 | 默认值 | 描述 |
|---------|----------------------|-------|------|
| `CS_POST_ACTION_MONITOR` | `post_action_monitor` | `0.3` | 得分达到或超过此值时分级变为 MONITOR |
| `CS_POST_ACTION_ESCALATE` | `post_action_escalate` | `0.6` | 得分达到或超过此值时分级变为 ESCALATE |
| `CS_POST_ACTION_EMERGENCY` | `post_action_emergency` | `0.9` | 得分达到或超过此值时分级变为 EMERGENCY |
| `CS_POST_ACTION_WHITELIST` | `post_action_whitelist` | `""` | 用于跳过路径的逗号分隔 `re.fullmatch` 模式 |
| `CS_POST_ACTION_FINDING_ACTION` | `post_action_finding_action` | `"broadcast"` | finding 的处理方式：`broadcast`、`defer` 或 `block` |
| `CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER` | `external_content_post_action_multiplier` | `1.3` | `content_origin == "external"` 时的得分乘数 |

!!! info "顺序约束"
    `DetectionConfig.__post_init__` 强制要求 `post_action_monitor ≤ post_action_escalate ≤ post_action_emergency`。违反此约束将在启动时抛出 `ValueError`。

---

## PostActionAnalyzer API {#api}

```python
class PostActionAnalyzer:
    def __init__(
        self,
        whitelist_patterns: list[str] | None = None,
        tier_emergency: float = 0.9,
        tier_escalate: float = 0.6,
        tier_monitor: float = 0.3,
    ) -> None: ...

    def analyze(
        self,
        tool_output: str,
        tool_name: str,
        event_id: str,
        file_path: str | None = None,
        content_origin: str | None = None,   # "external" | "user" | "unknown" | None
        external_multiplier: float = 1.0,
    ) -> PostActionFinding: ...
```

---

## 代码位置 {#code-locations}

| 模块 | 路径 | 职责 |
|------|------|------|
| 后置动作分析器 | `src/clawsentry/gateway/post_action_analyzer.py` | 四个检测器、评分、分级逻辑、脱敏建议 |
| 数据模型 | `src/clawsentry/gateway/models.py` | `PostActionFinding`、`PostActionResponseTier`、`SanitizeTarget` |
| 配置 | `src/clawsentry/gateway/detection_config.py` | `DetectionConfig` 数据类、`build_detection_config_from_env()` |
| 风险信号 | `src/clawsentry/gateway/risk_signals.py` | 混淆检测器使用的 `has_*_command` 辅助函数 |
| 文本工具 | `src/clawsentry/gateway/text_utils.py` | 所有检测器共用的 `normalize_text()` |

---

## 相关页面

- [轨迹分析器](trajectory-analyzer.md) — 异步跨事件多步攻击检测
- [L1 规则引擎 → D6](l1-rules.md#d6) — 同步注入信号（前置动作的补充）
- [检测配置](../configuration/detection-config.md) — 完整 `CS_*` 参数参考
- [报告与监控 → SSE](../api/reporting.md) — `post_action_finding` SSE 订阅格式
