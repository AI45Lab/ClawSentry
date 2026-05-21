---
title: 交互式 API Reference
description: 使用 Scalar 风格界面浏览 ClawSentry OpenAPI 端点、schema、鉴权、示例和错误码
---

# 交互式 API Reference {#interactive-api-reference}

<section class="cs-doc-hero cs-doc-hero--reference" markdown>
<div class="cs-eyebrow">Interactive Reference</div>

## 查字段、schema、示例与错误码

本页加载静态 `openapi.json` 并用 Scalar 渲染。若你还在判断“该调用哪类 API”，先看 [API 概览](overview.md)；若你已经知道端点，留在本页查请求体、响应示例、鉴权和错误码。

<div class="cs-actions" markdown>
[原始 OpenAPI JSON](openapi.json){ .md-button .md-button--primary }
[覆盖矩阵](api-coverage.json){ .md-button }
[有效性报告](validity-report.md){ .md-button }
[机器可读报告](api-validity.json){ .md-button }
</div>
</section>

!!! info "文档生成策略"
    下面的 OpenAPI artifact 是**文档侧静态产物**，由 route inventory + curated semantic overlay 生成。它不会修改 ClawSentry 运行时 API 行为。

!!! warning "Scalar 资源权衡"
    本阶段不引入新的构建依赖。页面使用 pinned CDN 版本加载 Scalar API Reference；`mkdocs build --strict` 不依赖远程 JS 是否可达。若你的环境无法访问 CDN，请直接查看 [原始 OpenAPI JSON](openapi.json)。页面还对 Scalar 1.52.5 的 `Invalid YAML object` 已知 false-positive 做了窄范围 console 兼容处理；源 JSON 与有效性报告仍是核验依据。

<div class="cs-reference-toolbar" markdown>
| 交接包 | 用途 |
| --- | --- |
| [`openapi.json`](openapi.json) | 前端/SDK/HTTP client 生成与字段核对 |
| [`api-coverage.json`](api-coverage.json) | 查看 service、auth、source、Markdown ref 和示例覆盖 |
| [`validity-report.md`](validity-report.md) | 人类可读的 API 真实性核验结果 |
| [`api-validity.json`](api-validity.json) | 可导入脚本或 CI 的机器可读核验结果 |
</div>

<div
  id="api-reference"
  data-url="../openapi.json"
  data-configuration='{ "theme": "purple", "layout": "modern", "hideDownloadButton": false, "hideModels": false, "defaultHttpClient": { "targetKey": "shell", "clientKey": "curl" } }'>
</div>

<noscript>
  JavaScript 未启用。请打开 <a href="../openapi.json">原始 OpenAPI JSON</a>。
</noscript>

<script>
  window.__clawsentryScalarConsoleError = console.error.bind(console)
  console.error = function filterScalarInvalidYamlObject() {
    const message = Array.from(arguments).map(String).join(' ')
    if (message.includes('Invalid YAML object')) {
      console.info('Scalar parser notice filtered: OpenAPI JSON is valid; see api-validity.json for traceability.')
      return
    }
    window.__clawsentryScalarConsoleError.apply(console, arguments)
  }
</script>
<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference@1.52.5"></script>

## 如何给前端开发使用

| 场景 | 推荐做法 |
| --- | --- |
| 生成类型或 client | 使用 [`openapi.json`](openapi.json)，只把 `public` 和明确启用的 `enterprise` 端点纳入目标环境。 |
| 构建 Dashboard 首屏 | 先接 `GET /report/summary`、`GET /report/sessions`、`GET /report/session/{session_id}/page`。 |
| 构建 Enterprise OS 20 类风险统计 | 企业模式下先接 `GET /enterprise/report/live?cached=true`；需要审计窗口时再接 `GET /enterprise/report/summary?window_seconds=3600`，读取 `by_trinityguard_subtype` / `by_trinityguard_tier` 或 `trinityguard.by_subtype` / `trinityguard.by_tier`。 |
| 构建实时流 | 使用 `GET /report/stream`；浏览器侧可用 query token，服务端集成优先 Bearer token。 |
| 构建处置动作 | acknowledge / enforcement / quarantine / L3 advisory 写入端点都按 contract 验证，不在报告生成时盲目 live 调用。 |
| 核对 API 是否真实存在 | 打开 [API 有效性报告](validity-report.md)，查看 source file:line、Markdown anchor 和 OpenAPI operation。 |

## 如何阅读这个 Reference

| 分组 | 适合读者 | 你能查到什么 |
| --- | --- | --- |
| AHP 决策 | 二次开发者 | `POST /ahp`、`POST /ahp/a3s`、`POST /ahp/codex`、`POST /ahp/resolve` 的请求/响应结构 |
| 报表与监控 | 运维 / 前端 | 会话、风险、告警、SSE 事件流 |
| L3 Advisory | 运维 / 安全审查 | snapshot、job、review、full-review 的 advisory-only 边界 |
| Enterprise 条件端点 | 企业部署运维 | `/enterprise/*` 的条件注册状态，不代表默认环境开启 |
| Excluded | 文档维护者 | `GET /ui`、`GET /ui/{path:path}` 和 webhook-local `GET /health` 不进入共享 OpenAPI 的原因 |
| Webhook | OpenClaw 集成方 | token、HMAC、timestamp、IP allowlist、idempotency 行为 |

## Skill Trust Operator API

OpenAPI 中的 Skill Trust 端点是 operator surface，不是 adapter 决策路径。它们使用与其他本地 HTTP operator 端点相同的 Bearer token 规则。

| Endpoint | 用途 | 关键字段 |
| --- | --- | --- |
| `GET /skill-trust/registry` | 查看 Gateway-owned registry/runtime metadata、grade、snapshot id 和 transition history | `registry_snapshot_id`、`metadata_records`、`transition_events` |
| `GET /skill-trust/transition/recommendations` | 查看 FSPR/P2 等 evidence-only 推荐 | recommendation source、target state、evidence refs |
| `POST /skill-trust/transition` | 写入 allowlist/greylist/blacklist/revoke/disable/restore/override transition | `idempotency_key`、`expected_registry_snapshot_id`、`target_state`、`reason_code`、`evidence_refs`、`operator_id_hash`、`override_id` |

Runtime binding and contextual recovery evidence remains in AHP decisions and replay metadata: `runtime_path_status`、`runtime_root_path_hash`、`runtime_content_status`、`metadata_record_id`、`skill_use_ledger`、`routing_intents[].source` and contextual clearance summaries. v0.8.3 adds `contextual_review` as a Gateway-owned routing source for safe recovery effects after FSPR blocks; v0.8.2 removed the post-action artifact provenance validator, so completed canonical decisions are not revisited through artifact label claims.

Agent-facing safety feedback appears in decision responses only for supported critical-block delivery modes. Unsupported hosts record audit metadata instead of claiming prompt injection delivery.
