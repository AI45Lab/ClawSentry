---
title: API 有效性报告
description: ClawSentry API 文档、源码 route、OpenAPI 与示例的可溯源核验结果
---

# API 有效性报告

生成时间：`2026-05-19T03:14:17+00:00`
核验状态：**通过**

本报告从同一份 docs-owned inventory 生成，核对源码 route decorator/registration、Markdown anchor、OpenAPI operation 和端点提及规则。它不修改后端 API 行为，也不会对写入型 API 做盲目 live 调用。

## 摘要

| 指标 | 数值 |
| --- | ---: |
| Coverage entries | 54 |
| OpenAPI operations | 51 |
| Docs endpoint mentions matched | 146 |
| Docs endpoint mentions unmatched | 0 |

## 状态分布

| 状态 | 数量 |
| --- | ---: |
| `enterprise` | 10 |
| `excluded` | 3 |
| `public` | 41 |

## 反向验证规则

- Exact METHOD /path mentions map directly to coverage.
- GET /report/* is treated as a group alias for concrete report routes, not a runtime route.
- Parameter aliases such as {id} are normalized by route-template shape when the method/path is unambiguous.
- GET /ui and GET /ui/{path:path} map to excluded dashboard static routes.
- Duplicate GET /health is service-disambiguated: API pages default to gateway; webhooks.md maps webhook health.

## 端点核验矩阵

| Service | Method | Path | Status | Source line | Markdown | OpenAPI | Runtime check |
| --- | --- | --- | --- | --- | --- | --- | --- |
| gateway | `POST` | `/ahp` | `public` | `src/clawsentry/gateway/server.py:5008` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/a3s` | `public` | `src/clawsentry/gateway/server.py:5106` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/codex` | `public` | `src/clawsentry/gateway/server.py:5140` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/adapter-effect-result` | `public` | `src/clawsentry/gateway/server.py:5029` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/scope/preview` | `public` | `src/clawsentry/gateway/server.py:5058` | yes | yes | `contract-verified` |
| stack | `POST` | `/ahp/resolve` | `public` | `src/clawsentry/gateway/stack.py:207` | yes | yes | `contract-verified` |
| gateway | `GET` | `/health` | `public` | `src/clawsentry/gateway/server.py:5179` | yes | yes | `contract-verified` |
| gateway | `GET` | `/skill-trust/registry` | `public` | `src/clawsentry/gateway/server.py:5183` | yes | yes | `contract-verified` |
| gateway | `GET` | `/skill-trust/transition/recommendations` | `public` | `src/clawsentry/gateway/server.py:5216` | yes | yes | `contract-verified` |
| gateway | `POST` | `/skill-trust/transition` | `public` | `src/clawsentry/gateway/server.py:5270` | yes | yes | `contract-verified` |
| gateway | `GET` | `/metrics` | `public` | `src/clawsentry/gateway/server.py:5426` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/summary` | `public` | `src/clawsentry/gateway/server.py:5438` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/policy-drift` | `public` | `src/clawsentry/gateway/server.py:5451` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/stream` | `public` | `src/clawsentry/gateway/server.py:5520` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/sessions` | `public` | `src/clawsentry/gateway/server.py:5634` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/risk` | `public` | `src/clawsentry/gateway/server.py:5728` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/post-action` | `public` | `src/clawsentry/gateway/server.py:5751` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}` | `public` | `src/clawsentry/gateway/server.py:6186` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/page` | `public` | `src/clawsentry/gateway/server.py:6234` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/alerts` | `public` | `src/clawsentry/gateway/server.py:6298` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/alerts/{alert_id}/acknowledge` | `public` | `src/clawsentry/gateway/server.py:6381` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/enforcement` | `public` | `src/clawsentry/gateway/server.py:6405` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/enforcement` | `public` | `src/clawsentry/gateway/server.py:6412` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/quarantine` | `public` | `src/clawsentry/gateway/server.py:6449` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/quarantine` | `public` | `src/clawsentry/gateway/server.py:6459` | yes | yes | `contract-verified` |
| gateway | `GET` | `/ahp/patterns` | `public` | `src/clawsentry/gateway/server.py:6504` | yes | yes | `contract-verified` |
| gateway | `POST` | `/ahp/patterns/confirm` | `public` | `src/clawsentry/gateway/server.py:6518` | yes | yes | `contract-verified` |
| openclaw-webhook | `POST` | `/webhook/openclaw` | `public` | `src/clawsentry/adapters/openclaw_webhook_receiver.py:45` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/l3-advisory/snapshots` | `public` | `src/clawsentry/gateway/server.py:5774` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/session/{session_id}/l3-advisory/snapshots` | `public` | `src/clawsentry/gateway/server.py:5814` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/l3-advisory/snapshot/{snapshot_id}` | `public` | `src/clawsentry/gateway/server.py:5827` | yes | yes | `contract-verified` |
| gateway | `GET` | `/report/l3-advisory/jobs` | `public` | `src/clawsentry/gateway/server.py:5847` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/jobs/run-next` | `public` | `src/clawsentry/gateway/server.py:5870` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/jobs/drain` | `public` | `src/clawsentry/gateway/server.py:5897` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/snapshot/{snapshot_id}/jobs` | `public` | `src/clawsentry/gateway/server.py:5925` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/reviews` | `public` | `src/clawsentry/gateway/server.py:5948` | yes | yes | `contract-verified` |
| gateway | `PATCH` | `/report/l3-advisory/review/{review_id}` | `public` | `src/clawsentry/gateway/server.py:5997` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/snapshot/{snapshot_id}/run-local-review` | `public` | `src/clawsentry/gateway/server.py:6054` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/job/{job_id}/run-local` | `public` | `src/clawsentry/gateway/server.py:6073` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/l3-advisory/job/{job_id}/run-worker` | `public` | `src/clawsentry/gateway/server.py:6092` | yes | yes | `contract-verified` |
| gateway | `POST` | `/report/session/{session_id}/l3-advisory/full-review` | `public` | `src/clawsentry/gateway/server.py:6117` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/health` | `enterprise` | `src/clawsentry/gateway/server.py:5416` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/summary` | `enterprise` | `src/clawsentry/gateway/server.py:5471` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/policy-drift` | `enterprise` | `src/clawsentry/gateway/server.py:5491` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/live` | `enterprise` | `src/clawsentry/gateway/server.py:5511` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/stream` | `enterprise` | `src/clawsentry/gateway/server.py:5578` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/sessions` | `enterprise` | `src/clawsentry/gateway/server.py:5679` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/session/{session_id}/risk` | `enterprise` | `src/clawsentry/gateway/server.py:6160` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/session/{session_id}` | `enterprise` | `src/clawsentry/gateway/server.py:6209` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/session/{session_id}/page` | `enterprise` | `src/clawsentry/gateway/server.py:6265` | yes | yes | `contract-verified` |
| gateway-enterprise | `GET` | `/enterprise/report/alerts` | `enterprise` | `src/clawsentry/gateway/server.py:6338` | yes | yes | `contract-verified` |
| gateway-ui | `GET` | `/ui` | `excluded` | `src/clawsentry/gateway/server.py:6585` | yes | yes | `excluded-from-reference` |
| gateway-ui | `GET` | `/ui/{path:path}` | `excluded` | `src/clawsentry/gateway/server.py:6574` | yes | yes | `excluded-from-reference` |
| openclaw-webhook | `GET` | `/health` | `excluded` | `src/clawsentry/adapters/openclaw_webhook_receiver.py:41` | yes | yes | `excluded-from-reference` |

## 复跑命令

```bash
python scripts/docs_api_inventory.py validate
python scripts/docs_api_inventory.py report --output-dir .omx/reports --docs-output site-docs/api
```

机器可读副本：[`api-validity.json`](api-validity.json)。
