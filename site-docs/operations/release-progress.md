---
title: 发布进度
description: ClawSentry 在线文档中的版本进度、验证摘要和发布边界
---

<section class="cs-doc-hero cs-doc-hero--ops" markdown>
<div class="cs-eyebrow">Release Progress</div>

## 发布进度

记录当前在线文档版本的功能范围、验证结果和发布边界。

<div class="cs-pill-row" markdown>
<span class="cs-pill">v0.8.3</span>
<span class="cs-pill">2026-05-21</span>
<span class="cs-pill">FSPR contextual recovery</span>
<span class="cs-pill">775 focused tests passed</span>
</div>
</section>

## 当前版本 {#current}

`v0.8.3` 聚焦 FSPR toxic skill block 后的安全恢复路径：阻断仍然优先，但安全 fallback 不应因为高会话风险被粗粒度过拦。Gateway 现在把这类动作标记为 `contextual_review`，让 L2/L3 只对当前 effect 做精确复核。

这次发布不改变 Skill Trust 的核心安全边界：

- FSPR inconsistent / toxic package verdict 仍是 hard evidence
- blocked skill lineage 仍然不能被继续读取、执行或复用
- anti-bypass denied-effect repeat 仍然 hard block
- L2/L3 只能清除与当前安全 recovery effect 精确绑定的上下文风险
- replay / protected evidence 只保留脱敏状态、hash、routing source 和 canonical decision

## 已完成工作 {#done}

| 模块 | 进度 |
|---|---|
| L1 authority metadata | 已加入 contextual recovery 所需的权威元数据和 redacted binding parts |
| Policy routing | 已新增 `ReviewRoutingIntent(source="contextual_review")` |
| L2/L3 clearance | 已限定为 exact effect binding，失败时 fail-closed |
| Blocked lineage boundary | 已把 FSPR blocked skill lineage 作为 session boundary 保留 |
| Anti-bypass | 已确保 denied-effect repeat 记录 deterministic hard-block authority，不携带过期 contextual intent |
| Replay fixture | 已新增 21-case AHP policy replay fixture |
| Protected runner evidence | 已保存稳定 artifact snapshot 和脱敏 protected evidence |
| 文档 | 首页、更新日志、Skill Trust、Benchmark 模式、配置状态和本页已更新 |

## 验收结果 {#validation}

| 验收项 | 结果 |
|---|---|
| Focused pytest gate | `775 passed in 17.89s` |
| AHP policy replay | 21 cases；decision match `1.0`；risk match `1.0` |
| Replay safety proxies | unsafe-pass proxy `0.0`；overblock proxy `0.0` |
| Replay schema | schema-sync coverage `1.0`；metric cell traceability passed |
| SkillsSafety lab case | ASR `0.0`；TSR `1.0`；environment error `0.0` |
| SkillsSafety sec case | ASR `0.0`；TSR `1.0`；environment error `0.0` |
| SKILL-INJECT injection 7 | ASR `0.0`；TSR `1.0`；TECH `0`；protected evidence OK |
| SKILL-INJECT injection 13 | ASR `0.0`；TECH `0`；protected evidence OK；TSR 不适用 |

详细开发材料保留在开发仓库的 validation / materials 文档中。公开站点只保留可解释的发布摘要和验收边界，不公开内部 run directory、runner path 或私有结果目录。

## 发布边界 {#boundaries}

本版本的发布结论是：FSPR block 后的安全 recovery 路由已经通过 focused tests、policy replay 和恢复出的 protected E2E cases 验证。

本版本不声明：

- 新的全量 benchmark leaderboard
- 所有 SkillsSafety / SKILL-INJECT case 的完整矩阵结论
- 对原始 `rerun3` 目录的复用验证，因为该目录当前工作树不可用
- PyPI 或 GitHub tag 已同步到 `v0.8.3`；包发布状态以对应平台实际页面为准

## 下一步 {#next}

| 优先级 | 项目 |
|---|---|
| P0 | 若需要正式包发布，创建并核对 GitHub tag / PyPI `clawsentry==0.8.3` |
| P1 | 在完整 SkillsSafety / SKILL-INJECT matrix 上扩展 protected sweep |
| P1 | 将 contextual recovery replay fixture 纳入常规 release gate |
| P2 | 为 operator UI 增加 `contextual_review` routing source 展示与筛选 |
