# Changelog

本文件记录 ClawSentry 各版本的重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.2.3] — 2026-03-26

### 修复

#### Issue Batch 2026-03-26-2（2 Critical + 1 High + 1 feat, 12 tests）
- **[CS-012]** `_handle_sync_decision()` deadline exceeded 时 early return 跳过 `trajectory_store.record()` 和 `session_registry.record()`，导致 fallback 决策不落库 — 将 recording 移到 deadline 检查之前
- **[CS-011]** `_send_request()` 收到 OpenClaw 错误响应时返回 `False` 而非抛异常，导致 `resolve()` reason 降级重试永不触发 — 新增 `ResolveError` 异常 + 匹配 "unexpected property" 错误格式
- **[CS-009]** L2 budget cap 无 overhead margin，LLM 调用耗尽 budget 后刚好超过 deadline — 预留 200ms margin

### 新增
- **`CS_L3_BUDGET_MS`** 环境变量：独立配置 L3 最大预算（默认跟随 L2），解决 L3 场景下 deadline 不足问题
- 穿透链：`DetectionConfig` → `policy_engine` → `llm_factory` → `AgentAnalyzerConfig`

#### 测试新增
- 12 个新测试覆盖：deadline 下 recording / ResolveError + retry E2E / overhead margin / L3 budget 配置
- 测试总量：1277 → 1289（+12 tests）

---

## [0.2.2] — 2026-03-26

### 修复

#### Issue Batch 2026-03-26（3 High defects + 6 tests）
- **[CS-008]** `CompositeAnalyzer.analyze()` 返回 `L2Result` 时遗漏 `trace=best.trace`，导致 L3 trace 始终为 NULL 无法落库
- **[CS-009]** `policy_engine.evaluate()` L2 budget 不受请求 `deadline_ms` 约束，高延迟场景触发 `DEADLINE_EXCEEDED` — 新增 `deadline_budget_ms` 参数，以 `min(config, remaining)` 为上限
- **[CS-010]** `_build_openclaw_runtime()` 遗漏 `enforcement_enabled`/`openclaw_ws_url`/`openclaw_operator_token` 三字段，导致 WS 可用时 `/ahp/resolve` 仍返回 502
- **[CS-007]** LLM 超时日志改善：区分 `TimeoutError` 与其他 provider error，便于调参调试（WONTFIX，设计如此）

#### 测试新增
- 6 个新测试覆盖：trace 传递 / deadline budget 限制 / enforcement 参数穿透
- 测试总量：1271 → 1277（+6 tests）

---

## [0.2.1] — 2026-03-25

### 修复

#### OpenClaw 兼容性审查（12 defects + 31 tests，2026-03-25）
- **[C-1/C-2]** `run_gateway()` 未接入 `DetectionConfig` 和 LLM analyzer — 独立启动时 L1/L2 均回退默认值
- **[H-1]** OpenClaw POST_ACTION 事件缺少 `output` 字段映射（`toolOutput`/`command_output` 等别名未转换）
- **[H-2]** CompositeAnalyzer 热重载遍历失败 — `reload_patterns` 未递归查找内层 `_pattern_matcher`
- **[H-4]** Webhook 会话 ID 提取仅识别 `sessionKey`，缺少 `sessionId` 回退
- **[H-5/L-3]** WS Future 注册顺序错误（先 send 后 register 导致竞态）+ `get_event_loop()` 弃用
- **[M-1]** D6 注入检测遗漏 OpenClaw `message`/`transcript`/`userMessage`/`user_message` 字段
- **[M-2/M-4]** `extract_candidate()` 未持久化 + `store_path` 空路径未校验
- **[M-6]** `CS_EVOLVING_ENABLED` 非法值静默忽略，现增加 warning 日志
- **[L-1]** `post_action_finding` SSE 事件缺少 `source_framework` 字段

#### 测试新增
- 31 个 OpenClaw 集成测试：D6 注入检测 / post-action 围栏 / 轨迹序列 / 攻击模式匹配 / Gateway 配置接入
- 测试总量：1239 → 1271（+32 tests）

---

## [0.2.0] — 2026-03-24

### 新增

#### 核心安全增强（E-4 Phase 1-3，2026-03-24）
- **D6 注入检测维度**：`injection_detector.py`，Layer 1（10 弱+8 强 regex, <0.3ms）+ Layer 2（Canary Token 泄露检测）
- **Post-action 安全围栏**：`post_action_analyzer.py`，异步检测间接注入/数据泄露/凭据暴露/混淆，分级响应（LOG/MONITOR/ESCALATE/EMERGENCY）
- **攻击模式库**：`attack_patterns.yaml` v1.1，25 条模式覆盖 OWASP ASI01-04（含供应链/容器逃逸/反弹 shell）
- **EmbeddingBackend Protocol**：可插拔 L3 向量相似度接口（纯 Protocol，无模型依赖）
- **TrajectoryAnalyzer**：5 个多步攻击序列检测（凭据窃取/后门安装/侦察渗透/密钥收割/分阶段渗出）
- **DetectionConfig**：统一 frozen dataclass（20 可调字段）+ `build_detection_config_from_env()` + 19 CS_ 环境变量（含 bool 型 CS_EVOLVING_ENABLED）
- L1 评分重构：加权公式 `0.4*max(D1,D2,D3)+0.25*D4+0.15*D5` + D6 乘数，新阈值 LOW<0.8/MED<1.5/HIGH<2.2/CRIT≥2.2
- SSE 新事件类型：`post_action_finding`、`trajectory_alert`

#### 自进化模式库（E-5，2026-03-24）
- **PatternEvolutionManager**：从高危事件自动提取候选模式，SHA-256 命令去重，模式 ID `EV-{hash8}`
- **EvolvedPattern 生命周期**：CANDIDATE → EXPERIMENTAL → STABLE → DEPRECATED（FP 率 >30% 自动废弃）
- **EvolvedPatternStore**：YAML 原子持久化（tempfile + os.replace），max_patterns=500，LRU 驱逐
- **compute_confidence()**：5 因子信心评分（确认率 30% / 频率 20% / 跨框架 20% / 准确率 20% / 时效 10%）
- **双源加载**：`load_patterns(evolved_path=...)` 合并内置 core + evolved，过滤 inactive 模式
- **REST API**：`GET /ahp/patterns` + `POST /ahp/patterns/confirm`；SSE `pattern_evolved` 事件
- **配置门控**：`CS_EVOLVING_ENABLED`（默认 false）+ `CS_EVOLVED_PATTERNS_PATH`

#### 测试缺口修复（E-6，2026-03-24）
- 4 并行 Sonnet subagent 审查 E-4/E-5 全部测试，发现 6C+14H+10M+3L 缺口
- 10 个测试文件新增 59 个测试：64KB 截断边界、VectorLayer 除零保护、EvolvedPatternStore 驱逐优先级、STABLE 幂等性、compute_confidence 边界、API 400/404 路径、轨迹负面测试、D6/PostAction Gateway 集成等

#### 用户体验改进（E-1~E-3，2026-03-23）
- **`clawsentry start`**：一键启动命令（框架自动检测 → 初始化 → Gateway → watch），Ctrl+C 优雅关闭
- **Web UI 自动登录**：启动时输出带 token 的 URL，点击即可免密登录
- **watch 输出优化**：混合格式（ALLOW 单行/BLOCK-DEFER 树形展开）+ SessionTracker Unicode 分组框 + Emoji 视觉锚点
- **watch 新 CLI 参数**：`--verbose` / `--no-emoji` / `--compact`
- **Web UI 重构**：Linear/Vercel 设计语言，Inter 字体，紫色 accent（#a78bfa），新组件：EmptyState/SkeletonCard/ScoreBar/VerdictBar/AreaChart 渐变/HintTag/LatencyBadge/TierBadge/SVG 环形倒计时

#### 测试覆盖
- 测试总量：775 → 1239（+464 tests，覆盖 D6/Post-action/模式库/DetectionConfig/TrajectoryAnalyzer/E-5 进化模式/E-6 缺口修复）
- 1 skipped = E2E SDK 测试（需 `A3S_SDK_E2E=1` + LLM API key，预期行为）
- E2E 全量测试（含 LLM 调用）：1243 passed（safe/dangerous/alert/eventbus 四项）

### 修复

#### 第二轮代码审查（3 Critical + 16 Important + 16 Minor + 9 Nitpick）
- **[C-1]** PatternMatcher `_detection_match` 全扫描修复（不再 early-return 丢失最高 weight）
- **[C-2]** `copy.copy(pattern)` 防止共享 AttackPattern 对象 mutation
- **[C-3]** TrajectoryAnalyzer `_emitted` set 上限 + LRU 驱逐防止内存泄漏
- SSE `/report/stream` 白名单补充 `post_action_finding` / `trajectory_alert`（I-1）
- `build_detection_config_from_env()` try/except 降级 + `d6_injection_multiplier` 验证（I-2/I-3）
- `score_layer1` + `PostActionAnalyzer` 64KB 输入上限（I-4/I-6）
- ThreadPoolExecutor `asyncio.wait_for` 包装防线程泄漏（I-7）
- `detect_instructional_content` 收窄标记 + 阈值 >0.5（I-8）
- 触发器 command/path_patterns 递归预编译（I-11）
- max_weight ≥ 8 → HIGH 风险升级（I-12）
- RiskSnapshot `frozen=True` 不可变保证（I-10）
- 正则优化 / 防御性拷贝 / bidi 字符检测 / 文档完善（Minor/Nitpick）

#### 第一轮代码审查
- PatternMatcher 正则预编译 + 100KB 输入限制（H9/H10）
- Post-action 复合评分聚合：max + 0.15 per extra signal（H8）
- LLM prompt payload 脱敏（4KB 截断 + REDACTED 标注，H3/H4）
- CDN 白名单扩展 + Shannon 熵阈值 7.0→5.5（M12/M13）
- `event_text()` 64KB 上限防止 regex 性能退化（M5）
- `mount` 加入 DANGEROUS_TOOLS（M3）

---

## [0.1.0] — 2026-03-23

首个公开版本。ClawSentry 是 Agent Harness Protocol (AHP) 的 Python 参考实现——一个面向 AI Agent 运行时的统一安全监督网关，支持 a3s-code 和 OpenClaw 双框架接入。

### 新增

#### 核心架构
- 实现 AHP (Agent Harness Protocol) 统一协议规范，归一化多框架运行时事件
- Sidecar 架构 + UDS（主传输）+ HTTP（备传输）双通道入口
- 同步阻塞 `pre_action` + 异步审计 `post_action` 双通道处理
- 基于 Pydantic v2 的 CanonicalEvent / CanonicalDecision 协议模型
- JSON-RPC 2.0 同步决策接口 (`sync_decision.1.0`)

#### 三层决策模型
- **L1 规则引擎** (<1ms)：D1-D5 五维风险评分（命令危险度/参数敏感度/上下文合理性/历史行为/作用域权限）
- **L2 语义分析** (<3s)：SemanticAnalyzer Protocol + RuleBased / LLM / Composite 三种实现
- **L3 审查 Agent** (<30s)：AgentAnalyzer + ReadOnlyToolkit + SkillRegistry + 多轮工具调用推理
- L3 推理轨迹持久化到 TrajectoryStore (`l3_trace_json` 列)

#### 框架适配器
- **a3s-code Adapter**：stdio harness + HTTP Transport (`POST /ahp/a3s`) 双模式
- **OpenClaw Adapter**：WebSocket 实时事件监听 + Webhook 接收器 + 审批执行器
- LLM 工厂：环境变量驱动的 Anthropic/OpenAI/自定义 provider 构建

#### 安全加固
- Bearer Token HTTP 认证 (`CS_AUTH_TOKEN`)
- Webhook HMAC-SHA256 签名验证 + IP 白名单 + Token TTL
- UDS socket `chmod 0o600` 权限保护
- SSL/TLS 支持 (`AHP_SSL_CERTFILE` / `AHP_SSL_KEYFILE`)
- 速率限制 (`CS_RATE_LIMIT_PER_MINUTE`，默认 300/分钟)
- 幂等性缓存防重复决策
- 按风险等级分层的重试预算（CRITICAL/HIGH=1, MEDIUM=2, LOW=3）

#### 会话管理
- SessionRegistry：会话生命周期追踪 + 风险累积
- 会话级强制策略 (SessionEnforcementPolicy)：累积 N 次高危后自动 DEFER/BLOCK/L3
- 冷却期自动释放 + 手动释放 REST API

#### 实时监控
- EventBus：进程内事件广播
- SSE 实时推送：decision / session_start / session_risk_change / alert / session_enforcement_change
- AlertRegistry：告警聚合 + 过滤 + 确认
- `clawsentry watch` CLI：终端实时展示（彩色输出/JSON 模式/事件过滤）
- `clawsentry watch --interactive`：DEFER 运维确认 (Allow/Deny/Skip + 超时安全余量)

#### Web 安全仪表板
- React 18 + TypeScript + Vite SPA，暗色 SOC 主题
- Dashboard：实时决策 feed + 指标卡 + 饼图/柱状图
- Sessions：会话列表 + D1-D5 雷达图 + 风险曲线 + 决策时间线
- Alerts：告警表格 + 过滤 + 确认 + SSE 自动推送
- DEFER Panel：倒计时 + Allow/Deny 按钮 + 503 降级提示
- Gateway 在 `/ui` 路径提供静态文件 + SPA fallback

#### CLI 工具
- `clawsentry init <framework>`：零配置初始化（支持 `--auto-detect` / `--setup` / `--dry-run`）
- `clawsentry gateway`：智能启动（自动检测 OpenClaw 配置，按需启用 Webhook/WS）
- `clawsentry harness`：a3s-code stdio harness
- `clawsentry watch`：SSE 实时监控
- `.env` 文件自动加载（dotenv_loader）

#### REST API
- `POST /ahp` — OpenClaw Webhook 决策端点
- `POST /ahp/a3s` — a3s-code HTTP Transport
- `POST /ahp/resolve` — DEFER 决策代理 (allow-once/deny)
- `GET /health` — 健康检查
- `GET /report/summary` — 跨框架聚合统计
- `GET /report/stream` — SSE 实时推送（支持 `?token=` query param 认证）
- `GET /report/sessions` — 活跃会话列表 + 风险排序
- `GET /report/session/{id}` — 会话轨迹回放
- `GET /report/session/{id}/risk` — 会话风险详情 + 时间线
- `GET /report/session/{id}/enforcement` — 会话执法状态查询
- `POST /report/session/{id}/enforcement` — 会话执法手动释放
- `GET /report/alerts` — 告警列表 + 过滤
- `POST /report/alerts/{id}/acknowledge` — 确认告警

#### L3 Skills
- 6 个内置审查技能：shell-audit / credential-audit / code-review / file-system-audit / network-audit / general-review
- 自定义 Skills 支持 (`AHP_SKILLS_DIR` 环境变量)
- Skills Schema：enabled / priority 字段 + 双语 system_prompt + 扩展 triggers

#### 测试
- 775 个测试用例，覆盖单元测试 + 集成测试 + E2E 测试
- 测试通过时间 ~6.5s

[0.2.1]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.1
[0.2.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.0
[0.1.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.1.0
