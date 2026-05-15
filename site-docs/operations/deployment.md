---
title: 生产部署
description: ClawSentry 生产环境部署指南，涵盖安全配置、SSL、系统服务和运维最佳实践
---

# 生产部署

本指南涵盖 ClawSentry 在生产环境中的部署配置。ClawSentry 设计为轻量级单进程服务，适合以 Sidecar 模式运行在 AI Agent 旁边。

!!! important "生产配置分层"
    - `.clawsentry.env.example`：可提交的非密钥 dotenv 模板，例如 `CS_ENABLED_FRAMEWORKS`、`CS_MODE`、`CS_L2_ENABLED`、budgets、DEFER policy。
    - `/etc/clawsentry/gateway.env` / Docker secrets / systemd `Environment=`：密钥和本机 runtime 值，例如 `CS_AUTH_TOKEN`、provider API key、host/port、DB path、OpenClaw token。
    - 不要依赖隐式 env-file。需要读取部署 env file 时，显式使用 `--env-file /etc/clawsentry/gateway.env`，并用 `config show --effective --env-file ...` 检查最终来源。

---

## 单机部署

### 安装

```bash
pip install "clawsentry[llm]"
```

`[llm]` 可选依赖组包含 `anthropic` 和 `openai` SDK，如果你只需要 L1 规则引擎，可以省略：

```bash
pip install clawsentry
```

### 验证安装

```bash
clawsentry --version
clawsentry gateway --help
```

---

## 部署环境变量配置

以下是生产环境推荐的 secrets/runtime 环境变量文件；项目策略仍建议放在 `.clawsentry.env.example`：

```bash title="/etc/clawsentry/env"
# ===== 核心配置 =====
# 认证令牌（必须设置，生成方法见下文）
CS_AUTH_TOKEN = your-strong-token-here

# HTTP 服务器
CS_HTTP_HOST=127.0.0.1
CS_HTTP_PORT=8080

# UDS 路径
CS_UDS_PATH=/tmp/clawsentry.sock

# ===== 数据持久化 =====
# 轨迹数据库路径（SQLite）
CS_TRAJECTORY_DB_PATH=/var/lib/clawsentry/trajectory.db

# ===== LLM 配置（可选，启用 L2/L3 分析） =====
CS_LLM_PROVIDER=openai
OPENAI_API_KEY = sk-your-api-key-here
CS_LLM_BASE_URL=https://api.openai.com/v1
CS_LLM_MODEL=gpt-4o-mini

# 启用 L3 审查 Agent（可选）
CS_L3_ENABLED=false

# LLM Token 预算（可选；基于 provider 真实 usage 执法）
CS_LLM_TOKEN_BUDGET_ENABLED=true
CS_LLM_DAILY_TOKEN_BUDGET=500000
CS_LLM_TOKEN_BUDGET_SCOPE=total

# ===== SSL/TLS（推荐） =====
AHP_SSL_CERTFILE=/etc/clawsentry/ssl/cert.pem
AHP_SSL_KEYFILE=/etc/clawsentry/ssl/key.pem

# ===== 速率限制 =====
CS_RATE_LIMIT_PER_MINUTE=300

# ===== 会话执法策略 =====
AHP_SESSION_ENFORCEMENT_ENABLED=true
AHP_SESSION_ENFORCEMENT_THRESHOLD=3
AHP_SESSION_ENFORCEMENT_ACTION=defer
AHP_SESSION_ENFORCEMENT_COOLDOWN_SECONDS=600

# ===== DEFER 配置 =====
# DEFER 等待超时后的默认行为：block（默认）或 allow
CS_DEFER_TIMEOUT_ACTION=block
# DEFER 审批等待软超时秒数（默认 86400s；benchmark mode 不等待）
CS_DEFER_TIMEOUT_S=86400
# 启用 DEFER Bridge（接入 Latch Hub 移动端审批）
CS_DEFER_BRIDGE_ENABLED=false

# ===== Latch Hub 集成（移动端监控与推送审批） =====
# CS_LATCH_HUB_URL=http://127.0.0.1:3006
# CS_LATCH_HUB_PORT=3006
# CS_HUB_BRIDGE_ENABLED=auto    # auto/true/false

# ===== Codex Session Watcher（自动监控 OpenAI Codex 会话） =====
# CS_CODEX_SESSION_DIR=/home/user/.codex/sessions
# CS_CODEX_WATCH_ENABLED=true
# CS_CODEX_WATCH_POLL_INTERVAL=0.5

# ===== 自进化模式库（可选，默认关闭） =====
# CS_EVOLVING_ENABLED=false
# CS_EVOLVED_PATTERNS_PATH=/var/lib/clawsentry/evolved_patterns.yaml

# ===== OpenClaw 集成（如果使用） =====
# OPENCLAW_WS_URL=ws://127.0.0.1:18789
# OPENCLAW_OPERATOR_TOKEN=your-openclaw-token
# OPENCLAW_ENFORCEMENT_ENABLED=true

# ===== Prometheus 指标 =====
# CS_METRICS_AUTH=false         # 指标端点认证开关（默认 false；生产建议设为 true）
```

---

## 认证配置

### 生成强认证令牌

```bash
# 使用 openssl 生成 32 字节随机令牌
openssl rand -hex 32
```

或使用 Python：

```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

将生成的令牌设置为 `CS_AUTH_TOKEN` 环境变量。

!!! danger "生产环境必须启用认证"
    如果 `CS_AUTH_TOKEN` 为空或未设置，Gateway 的 HTTP API 将不进行认证检查。在生产环境中这是严重的安全风险。

### 认证方式

所有 HTTP API 请求需要在 Header 中携带 Bearer Token：

```
Authorization: Bearer <CS_AUTH_TOKEN>
```

SSE 连接使用 URL Query 参数：

```
/report/stream?token=<CS_AUTH_TOKEN>
```

---

## SSL/TLS 配置

生产环境强烈建议启用 HTTPS，特别是当 SSE 连接通过 URL 参数传递认证令牌时。

### 生成自签名证书（测试用）

```bash
sudo mkdir -p /etc/clawsentry/ssl

openssl req -x509 -newkey rsa:4096 \
  -keyout /etc/clawsentry/ssl/key.pem \
  -out /etc/clawsentry/ssl/cert.pem \
  -days 365 -nodes \
  -subj "/CN=clawsentry.local"

sudo chmod 600 /etc/clawsentry/ssl/key.pem
sudo chown clawsentry:clawsentry /etc/clawsentry/ssl/*.pem
```

### 使用 Let's Encrypt 证书

如果 Gateway 暴露在公网（不推荐，但某些场景需要）：

```bash
# 使用 certbot 获取证书
sudo certbot certonly --standalone -d your-domain.example.com

# 配置环境变量
AHP_SSL_CERTFILE=/etc/letsencrypt/live/your-domain.example.com/fullchain.pem
AHP_SSL_KEYFILE=/etc/letsencrypt/live/your-domain.example.com/privkey.pem
```

### 配置环境变量

```bash
AHP_SSL_CERTFILE=/etc/clawsentry/ssl/cert.pem
AHP_SSL_KEYFILE=/etc/clawsentry/ssl/key.pem
```

Gateway 启动时会自动检测这两个环境变量，如果都已设置则启用 HTTPS。

!!! note "UDS 通信不受 SSL 影响"
    Unix Domain Socket 通信不经过网络层，因此不需要 SSL。UDS 的安全性通过文件权限控制（`chmod 600`）。

---

## 数据库配置

ClawSentry 使用 SQLite 存储决策轨迹数据。

### 路径配置

```bash
CS_TRAJECTORY_DB_PATH=/var/lib/clawsentry/trajectory.db
```

默认路径为 `/tmp/clawsentry-trajectory.db`，生产环境应指向持久化存储。

### 数据保留

默认保留 30 天的轨迹数据。过期数据会在 Gateway 运行时定期清理。

### 备份策略

SQLite 数据库可以通过简单的文件复制进行备份：

```bash title="/etc/cron.daily/clawsentry-backup"
#!/bin/bash
# ClawSentry 轨迹数据库每日备份
BACKUP_DIR=/var/backups/clawsentry
DB_PATH=/var/lib/clawsentry/trajectory.db
DATE=$(date +%Y%m%d)

mkdir -p "$BACKUP_DIR"

# 使用 sqlite3 的 .backup 命令确保一致性
sqlite3 "$DB_PATH" ".backup '$BACKUP_DIR/trajectory-$DATE.db'"

# 保留最近 7 天的备份
find "$BACKUP_DIR" -name "trajectory-*.db" -mtime +7 -delete
```

```bash
sudo chmod +x /etc/cron.daily/clawsentry-backup
```

!!! tip "在线备份"
    使用 `sqlite3 .backup` 命令可以在 Gateway 运行时安全地进行备份，无需停止服务。

---

## 日志配置

ClawSentry 使用 Python 标准 `logging` 模块。生产环境建议配置结构化日志：

### 基础配置

```python title="logging_config.py"
import logging
import logging.handlers

# 配置根日志器
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# 或使用文件日志 + 轮转
handler = logging.handlers.RotatingFileHandler(
    "/var/log/clawsentry/gateway.log",
    maxBytes=50 * 1024 * 1024,  # 50MB
    backupCount=5,
)
handler.setFormatter(
    logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
)
logging.getLogger("clawsentry").addHandler(handler)
```

### 关键日志名称

| Logger 名称 | 用途 |
|-------------|------|
| `clawsentry` | Gateway 核心（决策、API 请求） |
| `a3s-adapter` | a3s-code 适配器 |
| `openclaw-adapter` | OpenClaw 适配器 |
| `ahp.review-skills` | L3 Skill 加载 |
| `ahp.llm-factory` | LLM 分析器构建 |

### systemd 日志查看

```bash
# 查看实时日志
sudo journalctl -u clawsentry -f

# 查看最近 100 行
sudo journalctl -u clawsentry -n 100

# 按时间范围过滤
sudo journalctl -u clawsentry --since "2026-03-23 10:00" --until "2026-03-23 11:00"
```

---

## 资源需求

ClawSentry 设计为轻量级单进程服务，资源需求很低。

### 最低要求

| 资源 | 最低 | 推荐 |
|------|------|------|
| CPU | 1 核 | 2 核 |
| 内存 | 128 MB | 256 MB |
| 磁盘 | 100 MB | 1 GB（含轨迹数据库） |
| Python | 3.10+ | 3.12+ |

### 性能参考

| 指标 | 典型值 |
|------|--------|
| L1 决策延迟 | < 1 ms |
| L2 规则分析延迟 | < 5 ms |
| L2 LLM 分析延迟 | 1-3 秒 |
| L3 Agent 审查延迟 | 5-30 秒 |
| 内存占用（基础） | ~50 MB |
| 内存占用（含 Web UI） | ~80 MB |
| SQLite 写入速率 | > 1000 records/sec |

!!! info "L2/L3 延迟取决于 LLM 提供商"
    L2 LLM 分析和 L3 Agent 审查的延迟主要取决于 LLM API 的响应速度。本地部署的小模型可以显著降低延迟。

---

## 健康检查

Gateway 提供 `GET /health` 端点用于健康检查：

```bash
curl http://localhost:8080/health
```

```json
{
  "status": "healthy",
  "uptime_seconds": 3600.5,
  "cache_size": 12,
  "trajectory_count": 4523,
  "trajectory_backend": "sqlite",
  "policy_engine": "L1+L2",
  "rpc_version": "sync_decision.1.0",
  "auth_enabled": true
}
```

### systemd 健康检查

在服务单元文件中添加 Watchdog：

```ini
[Service]
WatchdogSec=30
ExecStartPost=/bin/bash -c 'sleep 2 && curl -sf http://127.0.0.1:8080/health || exit 1'
```

### 负载均衡器健康检查

如果在 Nginx/HAProxy 后面：

```nginx title="nginx.conf 示例"
upstream clawsentry {
    server 127.0.0.1:8080;
}

server {
    location /health {
        proxy_pass http://clawsentry;
    }

    location / {
        proxy_pass http://clawsentry;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # SSE 支持
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        chunked_transfer_encoding off;
        proxy_buffering off;
        proxy_cache off;
    }
}
```

!!! warning "SSE 代理注意事项"
    反向代理 SSE 连接时，必须禁用缓冲（`proxy_buffering off`）并使用 HTTP/1.1。否则 SSE 事件会被缓冲，导致客户端无法实时接收。

---

## IP 白名单

如果使用 OpenClaw Webhook 接收方式，可以配置 IP 白名单限制来源：

```bash
# 只允许本地和内网地址
AHP_WEBHOOK_IP_WHITELIST=127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

支持单个 IP 和 CIDR 网段表示法。

---

## 速率限制

Gateway 内置速率限制，防止过载：

```bash
# 每分钟最大请求数（默认 300）
CS_RATE_LIMIT_PER_MINUTE=300
```

超过限制时，API 返回 `RATE_LIMITED` 错误码，RPC 响应包含 `retry_after_ms` 字段。

---

## DEFER Bridge 与 Latch Hub

DEFER Bridge 和 Latch Hub Bridge 是两个可选组件，将人工审批和实时推送集成到 ClawSentry 决策流中。

### DEFER 超时配置

当 Agent 操作被 DEFER 判决（等待人工审批）时，`CS_DEFER_TIMEOUT_ACTION` 决定超时后的默认行为：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_DEFER_TIMEOUT_ACTION` | `block` | 超时后默认行为：`block`（拒绝）或 `allow`（放行） |
| `CS_DEFER_TIMEOUT_S` | `86400` | normal mode 等待超时秒数；benchmark mode 不等待人工审批 |
| `CS_DEFER_BRIDGE_ENABLED` | `true` | 是否启用 Latch Hub 审批桥接 |

!!! tip "安全默认"
    生产环境推荐保持 `CS_DEFER_TIMEOUT_ACTION=block`（默认），即超时未审批时拒绝操作。仅在测试或低风险场景下使用 `allow`。

### Latch Hub 集成

[Latch](../integration/latch.md) 是可选的移动端监控组件，通过 Hub Bridge 将 ClawSentry 事件推送至手机/Web PWA，并支持远程 DEFER 审批。

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_LATCH_HUB_URL` | (空) | Hub 基础 URL，如 `http://127.0.0.1:3006` |
| `CS_LATCH_HUB_PORT` | `3006` | URL 未设置时的回退端口 |
| `CS_HUB_BRIDGE_ENABLED` | `auto` | 事件转发开关：`auto`/`true`/`false` |

`auto` 模式下，Bridge 仅在能连通 Hub 时自动启动；设为 `false` 则完全禁用推送。

### Codex Session Watcher

OpenAI Codex 没有原生 Hook 接口，ClawSentry 通过轮询 Codex Session JSONL 文件实现监控：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_CODEX_SESSION_DIR` | *(空)* | Codex sessions 目录路径；显式设置时直接启用 Watcher |
| `CS_CODEX_WATCH_ENABLED` | `false`（`init codex` 写入 `true`） | 是否自动探测并启动 Watcher |
| `CS_CODEX_WATCH_POLL_INTERVAL` | `0.5` | 轮询间隔（秒） |

运行 `clawsentry init codex` 可自动检测 Codex 安装路径并生成配置。

---

## Docker 部署

!!! note "参考配置"
    ClawSentry 尚未提供官方 Docker 镜像，以下为参考 Dockerfile。

```dockerfile title="Dockerfile"
FROM python:3.12-slim

# 安装 ClawSentry
RUN pip install --no-cache-dir "clawsentry[llm]"

# 创建非 root 用户
RUN useradd --system --no-create-home clawsentry
USER clawsentry

# 数据目录
RUN mkdir -p /var/lib/clawsentry
VOLUME /var/lib/clawsentry

# 暴露端口
EXPOSE 8080

# 健康检查
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD curl -sf http://127.0.0.1:8080/health || exit 1

# 启动 Gateway
ENTRYPOINT ["clawsentry", "gateway"]
```

```bash title="docker-compose.yml"
services:
  clawsentry:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - clawsentry-data:/var/lib/clawsentry
    environment:
      CS_AUTH_TOKEN: ${CS_AUTH_TOKEN}
      CS_TRAJECTORY_DB_PATH: /var/lib/clawsentry/trajectory.db
      CS_HTTP_HOST: 0.0.0.0
      # 如果需要 LLM 分析
      # CS_LLM_PROVIDER: openai
      # OPENAI_API_KEY: ${OPENAI_API_KEY}
    restart: unless-stopped

volumes:
  clawsentry-data:
```

---

## Prometheus 可观测性

ClawSentry 通过 `/metrics` 端点导出 Prometheus 格式指标，支持决策延迟、LLM 成本、活跃会话等关键运营指标的监控和告警。

### 安装

```bash
# 安装 metrics 可选依赖
pip install "clawsentry[metrics]"

# 或使用 uv
uv pip install "clawsentry[metrics]"
```

### 指标端点

安装 `prometheus_client` 后，`GET /metrics` 自动启用。

```bash
# 验证指标端点
curl http://127.0.0.1:8080/metrics
```

未安装时返回降级提示（HTTP 200）：
```
# ClawSentry metrics disabled (prometheus_client not installed)
```

### 认证配置

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_METRICS_AUTH` | `true` | 指标端点认证开关 |

- `true`（默认）：需要 Bearer Token（与 `CS_AUTH_TOKEN` 相同）
- `false`：允许 Prometheus 无认证抓取

```bash title="/etc/clawsentry/gateway.env"
# 允许 Prometheus 无认证抓取
CS_METRICS_AUTH=false
```

### 关键指标

| 指标名 | 类型 | 说明 |
|--------|------|------|
| `clawsentry_decisions_total` | Counter | 决策总数（按 verdict/risk_level/tier/source_framework） |
| `clawsentry_decision_latency_seconds` | Histogram | 决策延迟分布 |
| `clawsentry_llm_calls_total` | Counter | LLM API 调用总数 |
| `clawsentry_llm_tokens_total` | Counter | Token 消耗总量 |
| `clawsentry_llm_cost_usd_total` | Counter | 预估 LLM 成本（美元） |
| `clawsentry_active_sessions` | Gauge | 当前活跃会话数 |
| `clawsentry_defers_pending` | Gauge | 等待审批的 DEFER 数 |
| `clawsentry_risk_score` | Histogram | 风险评分分布 |

### 常用 PromQL

```promql
# 每分钟决策速率
rate(clawsentry_decisions_total[5m])

# 高风险决策占比
sum(rate(clawsentry_decisions_total{risk_level=~"high|critical"}[5m]))
/ sum(rate(clawsentry_decisions_total[5m]))

# P99 决策延迟
histogram_quantile(0.99, rate(clawsentry_decision_latency_seconds_bucket[5m]))

# 每小时 LLM 成本
increase(clawsentry_llm_cost_usd_total[1h])

# DEFER 积压
clawsentry_defers_pending
```

---

## Docker Compose 可观测性栈

ClawSentry 提供预配置的 Docker Compose 文件，一键部署 Gateway + Prometheus + Grafana 三服务可观测性栈。

### 架构

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Gateway    │────▶│  Prometheus  │────▶│   Grafana    │
│  :8080       │     │  :9090       │     │  :3000       │
│  /metrics    │     │  15s scrape  │     │  dashboards  │
└──────────────┘     └──────────────┘     └──────────────┘
```

### 快速启动

```bash
cd docker/
cp .env.example .env
# 编辑 .env 设置 CS_AUTH_TOKEN 等参数

docker compose up -d
```

### 服务配置

#### Gateway

```yaml
gateway:
  build: .
  ports:
    - "${CS_HTTP_PORT:-8080}:8080"
  volumes:
    - clawsentry-data:/data
  environment:
    - CS_HTTP_HOST=0.0.0.0
    - CS_HTTP_PORT=8080
    - CS_TRAJECTORY_DB_PATH=/data/clawsentry-trajectory.db
  env_file: .env
  healthcheck:
    test: ["CMD", "curl", "-f", "http://127.0.0.1:8080/health"]
    interval: 30s
    timeout: 5s
    retries: 3
  restart: unless-stopped
```

#### Prometheus

```yaml
prometheus:
  image: prom/prometheus:v2.53.0
  ports:
    - "${CS_PROMETHEUS_PORT:-9090}:9090"
  volumes:
    - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
    - prometheus-data:/prometheus
  depends_on:
    gateway:
      condition: service_healthy
  restart: unless-stopped
```

#### Grafana

```yaml
grafana:
  image: grafana/grafana:11.1.0
  ports:
    - "${CS_GRAFANA_PORT:-3000}:3000"
  environment:
    - GF_SECURITY_ADMIN_PASSWORD=${CS_GRAFANA_PASSWORD:-clawsentry}
    - GF_AUTH_ANONYMOUS_ENABLED=true
    - GF_AUTH_ANONYMOUS_ORG_ROLE=Viewer
  volumes:
    - ./grafana/provisioning:/etc/grafana/provisioning:ro
    - grafana-data:/var/lib/grafana
  depends_on:
    - prometheus
  restart: unless-stopped
```

### Prometheus 抓取配置

```yaml title="docker/prometheus.yml"
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'clawsentry-gateway'
    static_configs:
      - targets: ['gateway:8080']
```

!!! tip "认证配置"
    如果将 `CS_METRICS_AUTH=true`（生产建议）启用，需要在 Prometheus 抓取配置中添加 Bearer Token：
    ```yaml
    scrape_configs:
      - job_name: 'clawsentry-gateway'
        bearer_token: 'your-cs-auth-token'
        static_configs:
          - targets: ['gateway:8080']
    ```

    或设置 `CS_METRICS_AUTH=false` 允许无认证抓取。

### 环境变量

```bash title="docker/.env"
CS_HTTP_PORT=8080
CS_AUTH_TOKEN = your-secret-token
CS_PROMETHEUS_PORT=9090
CS_GRAFANA_PORT=3000
CS_GRAFANA_PASSWORD=clawsentry
CS_METRICS_AUTH=false
```

### 持久化卷

| 卷名 | 用途 |
|------|------|
| `clawsentry-data` | Gateway SQLite 轨迹数据库 |
| `prometheus-data` | Prometheus 时序数据 |
| `grafana-data` | Grafana 仪表板和配置 |

### 管理命令

```bash
# 查看服务状态
docker compose ps

# 查看 Gateway 日志
docker compose logs -f gateway

# 重启单个服务
docker compose restart gateway

# 停止并清理
docker compose down

# 停止并清理数据卷
docker compose down -v
```

---

## systemd 服务配置

在 Linux 生产环境中，推荐使用 systemd 管理 ClawSentry Gateway 进程。

### 完整 service 文件

```ini title="/etc/systemd/system/clawsentry-gateway.service"
[Unit]
Description=ClawSentry AHP Supervision Gateway
After=network.target
Documentation=https://elroyper.github.io/ClawSentry/

[Service]
Type=simple
User=clawsentry
Group=clawsentry
EnvironmentFile=/etc/clawsentry/gateway.env
ExecStart=/usr/local/bin/clawsentry-gateway --host 127.0.0.1 --port 8080
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

# 安全加固
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/clawsentry /tmp/clawsentry.sock
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

### 安全加固说明

| 指令 | 说明 |
|------|------|
| `User=clawsentry` | 以专用非 root 用户运行 |
| `NoNewPrivileges=yes` | 禁止进程获取新权限 |
| `ProtectSystem=strict` | `/` 挂载为只读 |
| `ProtectHome=yes` | `/home` 挂载为只读 |
| `ReadWritePaths=` | 仅允许写入指定路径 |
| `PrivateTmp=yes` | 隔离 `/tmp` 命名空间 |

### 环境文件

```bash title="/etc/clawsentry/gateway.env"
CS_HTTP_HOST=127.0.0.1
CS_HTTP_PORT=8080
CS_AUTH_TOKEN = your-production-token
CS_TRAJECTORY_DB_PATH=/var/lib/clawsentry/trajectory.db
CS_UDS_PATH=/tmp/clawsentry.sock

# LLM 配置（可选）
CS_LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-xxx

# Prometheus 指标
CS_METRICS_AUTH=false
CS_LLM_TOKEN_BUDGET_ENABLED=true
CS_LLM_DAILY_TOKEN_BUDGET=500000
CS_LLM_TOKEN_BUDGET_SCOPE=total
```

!!! warning "文件权限"
    环境文件包含敏感信息（API 密钥、认证令牌）：
    ```bash
    chmod 600 /etc/clawsentry/gateway.env
    chown clawsentry:clawsentry /etc/clawsentry/gateway.env
    ```


### 配置验证（dry-run）

生产变更前先验证环境文件、认证 token、密钥脱敏和服务模板，不需要直接修改宿主 systemd/launchd 状态：

```bash
clawsentry service validate --env-file /etc/clawsentry/gateway.env --dry-run
clawsentry config show --effective --env-file /etc/clawsentry/gateway.env
clawsentry doctor --env-file /etc/clawsentry/gateway.env
```

验证输出应至少说明：监听地址、认证是否启用、LLM provider/key/model 是否就绪、token budget 是否启用/剩余、DEFER 行为、轨迹数据库路径和健康检查 URL。

### 安装步骤

```bash
# 1. 创建专用用户
sudo useradd -r -s /sbin/nologin clawsentry

# 2. 创建数据目录
sudo mkdir -p /var/lib/clawsentry /etc/clawsentry
sudo chown clawsentry:clawsentry /var/lib/clawsentry

# 3. 安装 ClawSentry
sudo pip install "clawsentry[metrics,llm]"

# 4. 复制配置文件
sudo cp gateway.env /etc/clawsentry/gateway.env
sudo chmod 600 /etc/clawsentry/gateway.env
sudo chown clawsentry:clawsentry /etc/clawsentry/gateway.env

# 5. 安装 systemd 服务
sudo cp clawsentry-gateway.service /etc/systemd/system/
sudo systemctl daemon-reload

# 6. 启用并启动
sudo systemctl enable clawsentry-gateway
sudo systemctl start clawsentry-gateway

# 7. 检查状态
sudo systemctl status clawsentry-gateway
sudo journalctl -u clawsentry-gateway -f
```

---

## 安全清单

部署到生产环境前，请逐项确认以下检查项：

### 认证与授权

- [x] `CS_AUTH_TOKEN` 已设置为强随机令牌（>= 32 字节）
- [x] 不使用默认或示例令牌
- [x] 令牌不出现在代码仓库或日志中

### 传输安全

- [x] 启用 SSL/TLS（`AHP_SSL_CERTFILE` + `AHP_SSL_KEYFILE`）
- [x] SSL 私钥文件权限为 600
- [x] UDS 路径在受限目录下，权限为 600

### 网络

- [x] Gateway 不直接暴露在公网（通过反向代理或 VPN）
- [x] 如果使用 Webhook，配置了 IP 白名单
- [x] 速率限制已配置

### 数据

- [x] `CS_TRAJECTORY_DB_PATH` 指向持久化存储
- [x] 数据库文件有定期备份
- [x] 数据目录权限仅限运行用户

### 运行时

- [x] 以非 root 用户运行（systemd `User=clawsentry`）
- [x] systemd 安全加固选项已启用（`NoNewPrivileges`, `ProtectSystem`）
- [x] 日志输出到文件或 journald，有轮转策略
- [x] 健康检查已配置

### LLM 安全

- [x] LLM API Key 通过环境变量注入，不硬编码
- [x] LLM 请求软超时已配置（例如 `CS_L2_TIMEOUT_MS=60000`、`CS_L3_TIMEOUT_MS=300000`）
- [x] L3 Agent 的 ReadOnlyToolkit 确保只读访问
- [x] 如需预算执法，已启用 `CS_LLM_TOKEN_BUDGET_ENABLED` 并设置真实 token 上限

### DEFER 与 Latch

- [x] `CS_DEFER_TIMEOUT_ACTION=block` 确保超时后默认拒绝（推荐）
- [x] `CS_DEFER_TIMEOUT_S` 已按运维响应能力配置合适软超时值；benchmark 任务使用 [Benchmark 模式](benchmark-mode.md) 避免人工等待
- [x] 若启用 Latch Hub，`CS_AUTH_TOKEN` 与 Hub `CLI_API_TOKEN` 已同步（`clawsentry doctor` 检查 `LATCH_TOKEN_SYNC`）

### 监控

- [x] 健康检查端点 `/health` 已加入监控系统
- [x] SSE 事件流可观测（通过仪表板或 `clawsentry watch`）
- [x] 告警通知渠道已配置
- [x] Prometheus 指标端点已接入告警规则（高风险决策率、DEFER 积压）
- [x] 运行 `clawsentry doctor` 确认所有检查项 PASS
