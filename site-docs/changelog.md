---
hide:
  - navigation
---

# 更新日志

本页只保留用户可见的发布要点。面向维护者的完整开发日志保留在仓库内部文档和 release validation 记录中。

## v0.6.9

- Persistence-write / SC-4 policy：将未来自动执行或自动重入入口写入抽象为通用 L1-L3 策略面。
- SC-4 动作可配置：`CS_PERSISTENCE_WRITE_ACTION` 支持 `audit`、`force_l3`、`defer` 和 `block`，strict 模式默认阻断，normal 模式默认进入同步 L3 verdict path。
- L3 复核使用脱敏 evidence summary，不发送原始文件 payload、secret 或环境值。
- 写入监督覆盖更多 pre-action payload 形态，包括 nested write/edit 字段。

## v0.6.8

- Anti-bypass Guard 增加隐私边界内的 LLM-assisted recognition，只发送脱敏 semantic capsule。
- Gateway 在安全 metadata 中补充紧凑的 anti-bypass probe 状态，便于定位 provider unavailable、timeout、预算跳过等降级原因。
- Shared LLM key indirection 支持 `CS_LLM_API_KEY_ENV`。
