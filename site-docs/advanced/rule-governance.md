---
title: 规则治理
description: YAML 规则与技能的上线前治理：lint、dry-run、fingerprint 与 发布前检查
---

<div class="cs-doc-hero" markdown>
<div class="cs-eyebrow">Advanced · Policy Governance</div>

## 规则治理

把 YAML 攻击模式库和 L3 review skills 的上线前治理补齐：在发布或策略变更前检查规则是否能加载、是否有冲突，以及 sample events 在当前规则面上会命中什么。

<div class="cs-pill-row" markdown>
<span class="cs-pill">rules lint</span>
<span class="cs-pill">rules dry-run</span>
<span class="cs-pill">rules report</span>
<span class="cs-pill">CI artifact</span>
</div>
</div>

# 规则治理

规则治理功能的目标不是把 ClawSentry 重写成一个横跨 L1/L2/L3 的全局运行时 DSL，而是把现有 YAML 规则和技能的**上线前治理**补齐：在 发布或策略变更前检查规则是否能加载、是否有冲突，以及 sample events 在当前规则面上会命中什么。

!!! abstract "本页快速导航"
    [边界](#scope) · [规则面组成](#rule-surfaces) · [clawsentry rules lint](#rules-lint) · [clawsentry rules dry-run](#rules-dry-run) · [clawsentry rules report](#rules-report) · [典型工作流](#workflow) · [输出字段](#outputs)

## 作用边界 {#scope}

当前版本的规则治理只管理以下规则资产：

- L2 attack patterns YAML
- 可选 evolved patterns YAML
- L3 review skills YAML

它**不**做这些事：

- 不引入新的运行时 scheduler
- 不替换 `PatternMatcher` / `SkillRegistry` / `L3TriggerPolicy`
- 不构造一个覆盖 L1/L2/L3 控制流的全局 DSL

更准确的理解是：

> 规则治理是“规则作者在上线前自检和预演”的治理层，不是“运行时策略解释器”。

## 规则面组成 {#rule-surfaces}

| 规则面 | 主要文件 | 作用 |
|--------|----------|------|
| Core attack patterns | `src/clawsentry/gateway/attack_patterns.yaml` | L2 规则库主干 |
| Evolved patterns | `CS_EVOLVED_PATTERNS_PATH` 指向的 YAML | E-5 提升后的 experimental / stable 模式 |
| Built-in review skills | `src/clawsentry/gateway/skills/*.yaml` | L3 内置审查技能 |
| Custom review skills | `--skills-dir` 指向的目录 | 上线前追加的自定义 L3 技能 |

默认情况下：

- built-in review skills 总是加载
- `--skills-dir` 会在 built-in 基础上叠加，而不是替换
- `--evolved-patterns` 会把 active evolved patterns 纳入治理报告

## `clawsentry rules lint` {#rules-lint}

```bash
clawsentry rules lint [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
```

`lint` 会输出当前规则面的治理报告，重点看：

- source 是否存在、是否可解析
- attack pattern 的 item-level schema 问题
- core/evolved 之间的重复 ID
- review skill 的重复名称与触发签名冲突
- 当前规则集的 deterministic fingerprint

### 示例

```bash
clawsentry rules lint --json
clawsentry rules lint \
  --attack-patterns /opt/clawsentry/patterns.yaml \
  --evolved-patterns /var/lib/clawsentry/evolved_patterns.yaml \
  --skills-dir /etc/clawsentry/skills \
  --json
```

## `clawsentry rules dry-run` {#rules-dry-run}

```bash
clawsentry rules dry-run --events FILE [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
```

`dry-run` 不会修改任何运行时状态，只会把 sample canonical events 放到当前规则面上预演：

- 哪些 attack pattern 会命中
- 最终会选中哪个 review skill
- 当前输入是否存在 parse / schema 问题

### 支持的输入格式

- 单个 JSON object
- JSON array
- JSONL

仓库内置了一个最小 sample fixture：

```bash
clawsentry rules dry-run --events examples/sample-events.jsonl --json
```

## `clawsentry rules report` {#rules-report}

```bash
clawsentry rules report --output FILE [--events FILE] [--summary-markdown FILE] [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
```

`report` 面向 CI 与 release checklist：它把 `lint` 结果和可选
`dry-run` 结果写入一个稳定 JSON 工件，包含：

- 顶层 `status` / `exit_code`
- deterministic `fingerprint`
- `checks.lint` 与 `checks.dry_run` 的状态、finding 数量和事件数量
- 完整 `lint` payload
- 可选的完整 `dry_run` payload

如果传入 `--summary-markdown`，`report` 还会写出一份面向 release / 策略变更审阅的人类可读 dashboard，列出总体状态、finding 数、fingerprint
以及 sample events 的 pattern / skill 覆盖情况。

如果同时传入 `--json`，报告也会输出到 stdout，便于流水线直接解析。

仓库还提供了可同步到公开仓库的 GitHub Actions 示例：
`examples/ci/rules-governance.yml`。公开仓库可将它复制到
`.github/workflows/rules-governance.yml` 后按需调整触发条件。模板会运行
`rules lint`、`rules dry-run`、`rules report`，并上传 JSON/Markdown artifact，
便于 reviewer 直接查看本次规则面是否可加载、样本是否按预期命中、fingerprint
是否与审核材料一致。

### 内置 sample events 覆盖范围 {#sample-events}

默认示例文件 `examples/sample-events.jsonl` 覆盖三类最小代表场景：

| 样本类型 | 用途 |
|----------|------|
| safe read | 验证普通读取不会被规则面误判为高风险 |
| credential upload | 验证凭证上传/外传类事件能命中预期 pattern |
| download and execute | 验证下载后执行类供应链风险能进入 dry-run/report 证据 |

你可以把这些样本作为 CI readiness checks 的起点，再追加自己组织里的 benign、expected-match
和 near-miss 事件。

### 示例

```bash
clawsentry rules report \
  --output artifacts/rules-report.json \
  --events examples/sample-events.jsonl \
  --summary-markdown artifacts/rules-dashboard.md
```

## 典型工作流 {#workflow}

### 调整 attack patterns 后

```bash
clawsentry rules lint --attack-patterns /opt/clawsentry/patterns.yaml --json
clawsentry rules dry-run --attack-patterns /opt/clawsentry/patterns.yaml \
  --events examples/sample-events.jsonl --json
```

### 调整自定义 L3 skills 后

```bash
clawsentry rules lint --skills-dir /etc/clawsentry/skills --json
clawsentry rules dry-run --skills-dir /etc/clawsentry/skills \
  --events examples/sample-events.jsonl --json
```

### 与 release checklist 一起使用

如果本次版本包含规则治理相关修改，发布前至少保留三条 readiness checks：

```bash
PYTHONPATH=src python -m clawsentry rules lint --json
PYTHONPATH=src python -m clawsentry rules dry-run --events examples/sample-events.jsonl --json
PYTHONPATH=src python -m clawsentry rules report \
  --output artifacts/rules-report.json \
  --events examples/sample-events.jsonl \
  --summary-markdown artifacts/rules-dashboard.md
```

### Policy-change review checklist {#policy-change-review-checklist}

在合并或发布任何 attack patterns、evolved patterns 或 L3 review skills 变更前，建议把以下 checklist 作为变更说明的一部分保存。它面向规则作者和发布 reviewer，目标是让“规则为什么变、会影响什么、如何回滚”可审计。

| 检查项 | 需要记录的内容 | 推荐证据 |
|--------|----------------|----------|
| 变更意图 | 新增、放宽、收紧还是删除规则；对应的风险场景 | PR/变更说明中的一句话目标 |
| 规则范围 | 影响 core attack pattern、evolved pattern、built-in skill 还是 custom skill | `clawsentry rules lint --json` 的 `source_summaries` |
| Fingerprint 变化 | 变更前后 fingerprint，确认 reviewer 看到的是同一规则面 | `clawsentry rules report --output ...` |
| 样本覆盖 | 至少一组 benign、一组 expected-match、一组 near-miss sample event | `clawsentry rules dry-run --events ... --json` |
| 冲突检查 | duplicate ID/name、skill signature conflict、schema finding 是否为 0 或已解释 | `findings` 与 report dashboard |
| 误报风险 | 哪些正常操作可能被新规则影响，是否需要 allowlist / 文档说明 | dry-run 样本和 reviewer 备注 |
| 回滚方式 | 回滚文件、关闭 evolved pattern、移除 custom skill 或恢复上一 fingerprint | 变更说明中的 rollback plan |

最小 review 命令模板：

```bash
clawsentry rules report \
  --output artifacts/rules-report.json \
  --events examples/sample-events.jsonl \
  --summary-markdown artifacts/rules-dashboard.md
```

如果 `status` 不是 `pass`，或 dashboard 中出现未解释的 FAIL finding，应先修规则或补充风险说明，再进入发布或策略变更。

## 输出字段 {#outputs}

### `fingerprint`

当前完整规则集的 deterministic digest。它会受以下内容影响：

- core attack patterns
- active evolved patterns
- built-in + custom review skills

这个值适合用于 rollout 记录和“当前实际规则面是不是同一版”的快速判断。

### `source_summaries`

按 source 列出当前加载了哪些规则资产，例如：

- `attack_patterns`
- `evolved_patterns`
- `review_skills`
- `custom_review_skills`

### `version_summary`

提供更适合记录的版本摘要，包括：

- attack patterns 版本
- evolved patterns 版本
- review skills 版本摘要
- active pattern / skill 数量
- inactive evolved pattern 数量

### `findings`

结构化治理结果。当前常见的 findings 包括：

- source 缺失
- YAML 解析失败
- item-level schema 问题
- duplicate attack pattern id
- duplicate review skill name
- review skill signature conflict
- invalid dry-run event

## 与其他页面的关系

- [CLI 命令参考](../cli/index.md) — `rules` 命令语法与退出码
- [攻击模式定制](attack-patterns.md) — attack patterns YAML 结构
- [自定义 L3 Skills](custom-skills.md) — review skills YAML 结构
- [自进化模式库](pattern-evolution.md) — evolved patterns 来源
