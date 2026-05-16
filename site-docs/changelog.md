---
hide:
  - navigation
---

# 更新日志

本页只保留公开使用者需要看到的发布摘要。详细开发记录和内部进度说明保留在开发仓库文档中。

## v0.7.4

- L3 AgentAnalyzer 现在默认使用 multi-turn review；只有显式设置 `CS_L3_MULTI_TURN=false`、`0`、`no` 或 `off` 才会进入 legacy single-turn。
- Protected SkillsSafetyBench Docker sweep 固定环境改为 `CS_L3_MULTI_TURN=true`，与公开默认模式一致。
- 配置页、L3 决策层文档和 README 已刷新到多轮默认口径。
- 公开 Python release surface 验证为 `3446 passed, 16 skipped`；Web UI 验证仍为 `56 passed`。

## v0.7.3

- L2 现在输出结构化、脱敏的 semantic evidence capsule，L3 审查可以复用同一份动作、证据、skill context 和 redaction metadata。
- L3 Agent 审查提示词按 trigger reason、policy intent、review skill manifest 和 operator next steps 组织，并对只读工具结果使用统一 envelope。
- Review skills 扩展到 prompt-injection transcript、data-staging exfil chain、dependency supply-chain、persistence 与 skill-trust audit。
- 公开 Python release surface 验证为 `3444 passed, 16 skipped`；Web UI 验证仍为 `56 passed`。

## v0.7.2

- Anti-bypass L1 现在把高风险动作归一为脱敏 effect summary，并用 denied / pending effect ledger 追踪同一 session 内的等价绕过尝试。
- Defer approval 绑定被审批的 effect；缺失 binding、binding 不完整或审批后效果漂移时失败关闭。
- 新增 14-case anti-bypass L1 replay fixture，decision match、evidence、fallback、rule、schema-sync coverage 均为 `1.0`。

## v0.7.1

- 公开发布面与公开仓库可复验内容对齐，在线文档、PyPI 主页和 GitHub README 使用一致的版本与测试计数。
- API 文档、配置页和首页刷新到当前公开版本。
- Benchmark 模式的用户说明保留在 [Benchmark 模式](operations/benchmark-mode.md)。

## v0.7.0

- 新增 Skill Trust registry / preflight、capability narrowing、agent safety feedback 和 policy drift traceability 配置面。
- Codex、OpenClaw、Gemini CLI、Kimi CLI、Claude Code、a3s-code 等集成说明继续按可阻断范围、监控范围和 fallback 行为组织。
- Benchmark 模式作为无人值守安全测试入口保留 CLI、配置与运行方式说明。

## 更早版本

更早版本的用户入口仍在各功能页面中维护；需要排查某个具体命令或配置时，优先使用站内搜索。
