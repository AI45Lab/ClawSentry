---
hide:
  - navigation
---

# 更新日志

本页只保留公开使用者需要看到的发布摘要。详细开发记录和内部进度说明保留在开发仓库文档中。

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
