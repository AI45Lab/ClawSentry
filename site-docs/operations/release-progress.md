---
title: 发布进度
description: ClawSentry 在线文档中的版本进度、验证摘要和发布边界
---

<section class="cs-doc-hero cs-doc-hero--ops" markdown>
<div class="cs-eyebrow">Release Progress</div>

## 发布进度

记录当前在线文档版本的功能范围、验证结果和发布边界。

<div class="cs-pill-row" markdown>
<span class="cs-pill">v0.8.4</span>
<span class="cs-pill">2026-05-24</span>
<span class="cs-pill">FSPR agentic-readonly default</span>
<span class="cs-pill">public validation passed</span>
</div>
</section>

## 当前版本 {#current}

`v0.8.4` 聚焦 FSPR 默认审查路线收口：Gateway 的 First-Use Skill Package Review 默认切到 `agentic-readonly`，先使用 deterministic inventory 和 agentic evidence digest 形成本地证据底线，只有需要语义判断时才进入只读 provider path。`final-only` 继续作为显式备用路线。

这次发布不改变 Skill Trust 的核心安全边界：

- FSPR inconsistent / toxic package verdict 仍是 hard evidence
- blocked skill lineage 仍然不能被继续读取、执行或复用
- anti-bypass denied-effect repeat 仍然 hard block
- L2/L3 只能清除与当前安全 recovery effect 精确绑定的上下文风险
- replay / protected evidence 只保留脱敏状态、hash、routing source 和 canonical decision
- 旧 `metadata-only` / `reduced` / `full` 顺序多 reviewer role-set 不再是生产路线；误传时 fail closed

## 已完成工作 {#done}

| 模块 | 进度 |
|---|---|
| Gateway FSPR routing | 默认路线改为 `agentic-readonly` |
| Backup route | `CS_SKILL_TRUST_FSPR_REVIEW_MODE=final-only` 保留单 adjudicator 备用路线 |
| Legacy role-set cleanup | 旧 `metadata-only` / `reduced` / `full` MAS role-set 从生产配置面移除并 fail closed |
| Benchmark runner | microbench 默认 review mode 改为 `agentic-readonly`，legacy `--role-set` 只保留 `final-only` |
| 在线文档 | 首页、更新日志、Skill Trust、配置页、Benchmark 配置和本页已更新 |
| Public release | public main、GitHub Release 和 PyPI `clawsentry==0.8.4` 发布待 public sync / tag / CI 确认 |

## 验收结果 {#validation}

| 验收项 | 结果 |
|---|---|
| Focused FSPR regression | 受影响 FSPR / microbench / config regression `381 passed` |
| Public release surface | `4026 passed, 9 skipped` |
| 72-case comparison | hardened `agentic-readonly` detection / healthy / minimum-quality `0.958333`，degraded `0` |
| final-only comparison | detection `0.861111`，healthy `0.777778`，degraded `6` |
| Execution path split | 59 deterministic floor / 5 digest floor / 8 provider path |
| Release gate | 本地与公开仓库 build/docs/diff gate 通过；public publish CI 待 tag 后确认 |

详细开发材料保留在开发仓库的 validation / materials 文档中。公开站点只保留可解释的发布摘要和验收边界，不公开内部 run directory、runner path 或私有结果目录。

## 发布边界 {#boundaries}

本版本的发布结论是：FSPR 默认审查路线已经从旧 final-only 默认切到 hardened `agentic-readonly`，同时保留 final-only 备用接口并移除早期 full MAS 生产配置面。

本版本不声明：

- 新的全量公开评测排名
- 所有 SkillsSafety / SKILL-INJECT case 的完整矩阵结论
- 新的私有 benchmark 原始结果目录或内部 runner 路径
- “纯模型能力优于 final-only”的结论；72-case 改善主要来自 deterministic / digest floor

## 下一步 {#next}

| 优先级 | 项目 |
|---|---|
| P0 | 完成 v0.8.4 public sync、tag、PyPI / GitHub Release / docs smoke |
| P1 | 基于 3 个 agentic provider-path miss 做 attack-surface catalog |
| P1 | 为 `agentic-readonly` 和 `final-only` 整理独立 timeout profile |
| P2 | 将 FSPR review mode / execution path 纳入运行报告筛选 |
