# Changelog

本文件记录 ClawSentry 各版本的重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [0.2.0] — 2026-03-24

### 新增

#### 核心安全增强（E-4 Phase 1-3，2026-03-24）
- **D6 注入检测维度**：`injection_detector.py`，Layer 1（10 弱+8 强 regex, <0.3ms）+ Layer 2（Canary Token 泄露检测）
- **Post-action 安全围栏**：`post_action_analyzer.py`，异步检测间接注入/数据泄露/凭据暴露/混淆，分级响应（LOG/MONITOR/ESCALATE/EMERGENCY）
- **攻击模式库**：`attack_patterns.yaml` v1.1，25 条模式覆盖 OWASP ASI01-04（含供应链/容器逃逸/反弹 shell）
- **EmbeddingBackend Protocol**：可插拔 L3 向量相似度接口（纯 Protocol，无模型依赖）
- **TrajectoryAnalyzer**：5 个多步攻击序列检测（凭据窃取/后门安装/侦察渗透/密钥收割/分阶段渗出）
- **DetectionConfig**：统一 frozen dataclass（17 可调字段）+ `build_detection_config_from_env()` + 17 CS_ 环境变量
- L1 评分重构：加权公式 `0.4*max(D1,D2,D3)+0.25*D4+0.15*D5` + D6 乘数，新阈值 LOW<0.8/MED<1.5/HIGH<2.2/CRIT≥2.2
- SSE 新事件类型：`post_action_finding`、`trajectory_alert`

#### 用户体验改进（E-1~E-3，2026-03-23）
- **`clawsentry start`**：一键启动命令（框架自动检测 → 初始化 → Gateway → watch），Ctrl+C 优雅关闭
- **Web UI 自动登录**：启动时输出带 token 的 URL，点击即可免密登录
- **watch 输出优化**：混合格式（ALLOW 单行/BLOCK-DEFER 树形展开）+ SessionTracker Unicode 分组框 + Emoji 视觉锚点
- **watch 新 CLI 参数**：`--verbose` / `--no-emoji` / `--compact`
- **Web UI 重构**：Linear/Vercel 设计语言，Inter 字体，紫色 accent（#a78bfa），新组件：EmptyState/SkeletonCard/ScoreBar/VerdictBar/AreaChart 渐变/HintTag/LatencyBadge/TierBadge/SVG 环形倒计时

#### 测试覆盖
- 测试总量：775 → 1138（+363 tests，覆盖 D6/Post-action/模式库/DetectionConfig/TrajectoryAnalyzer）
- 1 skipped = E2E SDK 测试（需 `A3S_SDK_E2E=1` + LLM API key，预期行为）

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

[0.2.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.2.0
[0.1.0]: https://github.com/Elroyper/ClawSentry/releases/tag/v0.1.0
