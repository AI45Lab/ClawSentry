---
title: 认证与安全
description: ClawSentry 的认证机制、传输安全和安全最佳实践
---

<section class="cs-doc-hero cs-doc-hero--api" markdown>
<div class="cs-eyebrow">ClawSentry 认证与安全</div>
## 认证与安全
ClawSentry 提供多层安全机制保护 API 端点和传输通道。本页详细介绍所有认证方式及其配置方法。
<div class="cs-actions" markdown>
[API 概览](overview.md){ .md-button .md-button--primary }
[Webhook API](webhooks.md){ .md-button }
[配置参考](../configuration/configuration-overview.md){ .md-button }
</div>
</section>

---

## Bearer Token 认证 {#bearer-token}

HTTP API 端点（`/ahp`、`/ahp/a3s`、`/ahp/resolve`、`/report/*`）默认使用 Bearer Token 认证。

### 配置

通过环境变量设置认证令牌：

```bash
export CS_AUTH_TOKEN = "your-secure-token-at-least-32-chars"
```

或在显式 env file 中配置，并在启动时传入 `--env-file`：

```ini title=".clawsentry.env.local"
CS_AUTH_TOKEN = your-secure-token-at-least-32-chars
```

```bash
clawsentry start --env-file .clawsentry.env.local
```

### 使用方式

在 HTTP 请求中添加 `Authorization` 头：

```bash
curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
  http://127.0.0.1:8080/report/summary
```

### 令牌验证

- 使用 `hmac.compare_digest()` 进行常量时间比较，防止时序攻击
- 令牌长度不足 32 字符时，Gateway 启动日志会输出警告

### 无认证端点

以下端点**不需要认证**：

| 端点 | 说明 |
|------|------|
| `GET /health` | 健康检查 |

---

## SSE Query Param 认证 {#sse-query-param}

浏览器 `EventSource` API 不支持自定义 HTTP 头。为了支持浏览器端的 SSE 连接，`/report/stream` 端点额外支持 query param 认证。

### 使用方式

```
GET /report/stream?token=your-secure-token
```

### JavaScript 示例

```javascript
// 浏览器中使用 EventSource
const token = sessionStorage.getItem("cs_auth_token");
const es = new EventSource(
  `http://127.0.0.1:8080/report/stream?token=${token}`
);

es.addEventListener("decision", (event) => {
  console.log(JSON.parse(event.data));
});
```

### 认证优先级

当 Header 和 Query Param 同时存在时，按以下顺序验证：

1. 优先检查 `Authorization: Bearer <token>` 头
2. 头部验证失败后，检查 `?token=<token>` 参数
3. 两者均失败 → 返回 `401 Unauthorized`

```
Authorization: Bearer xxx  ──  匹配？ → 通过
          │
          └── 不匹配
                │
                ▼
      ?token=xxx  ──  匹配？ → 通过
          │
          └── 不匹配
                │
                ▼
          401 Unauthorized
```

!!! warning "安全注意"
    URL 中的 token 可能被记录到 Web 服务器日志或浏览器历史。生产环境建议使用 HTTPS 加密传输，并定期轮换令牌。

---

## Webhook 安全 {#webhook-security}

OpenClaw Webhook 端点（`/webhook/openclaw`）提供独立的多层安全验证。

### 验证流水线

Webhook 请求按以下顺序验证，任一步骤失败则立即拒绝：

```
TLS 检查 → IP 白名单 → Token 验证 → Token TTL
→ 时间戳检查 → 请求体大小 → Content-Type → JSON 解析
→ HMAC 签名 → 必填字段
```

### 1. Token 认证

Webhook 使用独立的令牌体系（非 `CS_AUTH_TOKEN`）：

```bash
export OPENCLAW_WEBHOOK_TOKEN="webhook-primary-token"
```

支持双令牌轮换——主令牌和备用令牌同时有效：

| 环境变量 | 说明 |
|----------|------|
| `OPENCLAW_WEBHOOK_TOKEN` | 主令牌 |
| `OPENCLAW_WEBHOOK_TOKEN_SECONDARY` | 备用令牌（用于无缝轮换） |

令牌验证同样使用 `hmac.compare_digest()` 常量时间比较。

### 2. HMAC-SHA256 签名验证

当配置了 Webhook Secret 时，启用请求签名验证：

```bash
export OPENCLAW_WEBHOOK_SECRET="your-hmac-secret"
```

**签名格式：**

请求头：
```
X-AHP-Signature: v1=<hex-digest>
X-AHP-Timestamp: <unix-timestamp>
```

签名计算方式：
```
HMAC-SHA256(secret, "{timestamp}.{raw_body}")
```

预期签名格式：`v1={hex_digest}`

**验证模式：**

| 模式 | 行为 |
|------|------|
| `strict`（默认） | 缺少签名 → 拒绝 |
| `permissive` | 缺少签名 → 警告但放行，签名存在则必须正确 |

**时间戳容差：** 默认 300 秒（5 分钟），超过容差范围的请求被拒绝。

### 3. IP 白名单

限制允许发送 Webhook 的源 IP 地址：

```bash
export AHP_WEBHOOK_IP_WHITELIST="127.0.0.1,10.0.0.5,192.168.1.100"
```

| 配置值 | 行为 |
|--------|------|
| 未设置 | 禁用 IP 白名单（不限制来源 IP） |
| 空字符串 `""` | 拒绝所有 IP |
| `"127.0.0.1,10.0.0.5"` | 仅接受列表中的 IP |

### 4. Token TTL

为 Webhook 令牌设置有效期：

```bash
export AHP_WEBHOOK_TOKEN_TTL_SECONDS=86400  # 24 小时
```

| 配置值 | 行为 |
|--------|------|
| `0` | 令牌永不过期 |
| `86400`（默认） | 自令牌签发起 24 小时后过期 |

### 5. 请求限制

| 限制 | 默认值 | 环境变量 |
|------|--------|----------|
| 请求体大小 | 1 MB | `--webhook-max-body-bytes` |
| Content-Type | 必须为 `application/json` | — |
| HTTPS 要求 | 开启（localhost 豁免） | `--webhook-require-https` |

### Webhook 安全配置完整示例

```bash
# .clawsentry.env.local（使用 --env-file 显式传入）

# Webhook 令牌
OPENCLAW_WEBHOOK_TOKEN=primary-token-32-chars-minimum
OPENCLAW_WEBHOOK_TOKEN_SECONDARY=secondary-token-for-rotation

# HMAC 签名
OPENCLAW_WEBHOOK_SECRET=hmac-secret-key

# IP 白名单
AHP_WEBHOOK_IP_WHITELIST=127.0.0.1,10.0.0.1

# 令牌有效期（24 小时）
AHP_WEBHOOK_TOKEN_TTL_SECONDS=86400
```

---

## UDS 权限控制 {#uds-permissions}

Unix Domain Socket 通过文件系统权限实现访问控制。

### 文件权限

Gateway 启动时自动将 Socket 文件权限设为 `0600`：

```
srw------- 1 user user 0 Mar 23 10:00 /tmp/clawsentry.sock
```

- `0600` = 仅所有者可读写
- 其他用户无法连接到 Socket

### 安全含义

| 特性 | 说明 |
|------|------|
| 仅本地访问 | UDS 不可跨网络访问 |
| 进程隔离 | 仅相同用户的进程可连接 |
| 无需额外认证 | 文件系统权限即为认证 |

!!! tip "生产部署建议"
    在多用户系统中，确保 ClawSentry Gateway 进程和 Agent 进程使用相同的 Unix 用户运行，否则 Harness 无法连接到 UDS。

---

## SSL/TLS 加密 {#ssl-tls}

为 HTTP 端点启用 HTTPS 传输加密。

### 配置

```bash
export AHP_SSL_CERTFILE=/etc/ssl/certs/clawsentry.pem
export AHP_SSL_KEYFILE=/etc/ssl/private/clawsentry-key.pem
```

| 环境变量 | 说明 |
|----------|------|
| `AHP_SSL_CERTFILE` | SSL 证书文件路径（PEM 格式） |
| `AHP_SSL_KEYFILE` | SSL 私钥文件路径（PEM 格式） |

两个变量必须同时设置，否则 SSL 不会启用。

### 自签名证书生成（开发环境）

```bash
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout clawsentry-key.pem \
  -out clawsentry.pem \
  -days 365 \
  -subj "/CN=localhost"
```

### 验证

```bash
# 使用 HTTPS 访问
curl -k https://127.0.0.1:8080/health

# 使用自签名证书
curl --cacert clawsentry.pem https://127.0.0.1:8080/health
```

---

## 速率限制 {#rate-limiting}

HTTP 端点支持基于客户端 IP 的滑动窗口速率限制。

### 配置

```bash
export CS_RATE_LIMIT_PER_MINUTE=300  # 默认值
```

| 配置值 | 行为 |
|--------|------|
| `300`（默认） | 每个 IP 每分钟最多 300 个请求 |
| `0` | 禁用速率限制 |

### 超限响应

```json
HTTP/1.1 429 Too Many Requests

{
  "rpc_version": "sync_decision.1.0",
  "request_id": "rate-limited",
  "rpc_status": "error",
  "rpc_error_code": "RATE_LIMITED",
  "rpc_error_message": "Rate limit exceeded",
  "retry_eligible": true,
  "retry_after_ms": 1000
}
```

---

## 无认证模式 {#no-auth}

当 `CS_AUTH_TOKEN` 为空（未设置或设为空字符串）时，所有 HTTP 端点的认证检查被禁用。

!!! danger "仅限开发环境"
    无认证模式下，任何能访问 Gateway 端口的客户端都可以：

    - 提交伪造事件获取虚假决策
    - 读取所有会话和告警数据
    - 确认或操纵告警
    - 解析 DEFER 决策（影响 Agent 行为）

    **生产环境必须设置 `CS_AUTH_TOKEN`。**

Gateway 启动时会输出明确警告：

```
WARNING CS_AUTH_TOKEN not set — HTTP endpoints are UNAUTHENTICATED.
Set CS_AUTH_TOKEN for production deployments.
```

---

## 安全最佳实践 {#best-practices}

### 必须

- [x] **始终设置 `CS_AUTH_TOKEN`**（至少 32 字符）
- [x] **生产环境启用 HTTPS**（设置 `AHP_SSL_CERTFILE` + `AHP_SSL_KEYFILE`）
- [x] **OpenClaw Webhook 启用签名验证**（设置 `OPENCLAW_WEBHOOK_SECRET`）
- [x] **限制 Gateway 监听地址**（默认 `127.0.0.1`，不要绑定 `0.0.0.0`）

### 建议

- [x] **配置 Webhook IP 白名单**（`AHP_WEBHOOK_IP_WHITELIST`）
- [x] **定期轮换令牌**（利用双令牌机制无缝切换）
- [x] **设置 Token TTL**（`AHP_WEBHOOK_TOKEN_TTL_SECONDS`）
- [x] **启用速率限制**（`CS_RATE_LIMIT_PER_MINUTE`）
- [x] **日志审计**——Gateway 记录所有认证失败事件

### 令牌轮换流程

```bash
# 1. 生成新令牌
NEW_TOKEN=$(openssl rand -hex 32)

# 2. 将新令牌设为备用令牌（此时新旧令牌均有效）
export OPENCLAW_WEBHOOK_TOKEN_SECONDARY=$NEW_TOKEN
# 重启 Gateway

# 3. 更新 OpenClaw 使用新令牌
# 编辑 openclaw.json，更新 webhook token

# 4. 将新令牌升级为主令牌，移除旧令牌
export OPENCLAW_WEBHOOK_TOKEN=$NEW_TOKEN
unset OPENCLAW_WEBHOOK_TOKEN_SECONDARY
# 重启 Gateway
```

### 环境变量安全总览

| 变量 | 作用域 | 必填 | 说明 |
|------|--------|------|------|
| `CS_AUTH_TOKEN` | HTTP API | 生产必填 | HTTP 端点认证令牌 |
| `OPENCLAW_WEBHOOK_TOKEN` | Webhook | 使用 OpenClaw 时必填 | Webhook 主令牌 |
| `OPENCLAW_WEBHOOK_SECRET` | Webhook | 建议 | HMAC 签名密钥 |
| `OPENCLAW_OPERATOR_TOKEN` | WebSocket | 使用 WS 时必填 | OpenClaw WS 操作令牌 |
| `AHP_WEBHOOK_IP_WHITELIST` | Webhook | 建议 | IP 白名单 |
| `AHP_WEBHOOK_TOKEN_TTL_SECONDS` | Webhook | 可选 | 令牌有效期 |
| `AHP_SSL_CERTFILE` | HTTP | 生产建议 | SSL 证书路径 |
| `AHP_SSL_KEYFILE` | HTTP | 生产建议 | SSL 私钥路径 |
| `CS_RATE_LIMIT_PER_MINUTE` | HTTP | 可选 | 速率限制阈值 |
