---
title: Latch 集成
description: Latch 移动监控与推送审批集成指南
---

# Latch 集成

<div class="cs-doc-hero" markdown>
<div class="cs-eyebrow">Integration · Latch · 移动端可选增强</div>

## Latch 移动端监控与审批

Latch 是 ClawSentry 的可选增强组件，通过 Hub 将安全事件推送到移动端，支持远程 DEFER 审批。核心 Gateway 无需 Latch 即可正常工作；仅在需要移动端/远程审批时安装。

<div class="cs-pill-row" markdown>
<span class="cs-pill">可选增强</span>
<span class="cs-pill">移动端推送</span>
<span class="cs-pill">远程 DEFER 审批</span>
</div>
</div>

!!! tip "本页怎么读"
    Latch 是可选增强，适合移动端查看告警和远程审批。先确认核心 Gateway 已跑通，再接入 Latch。

Latch 是 ClawSentry 的可选增强组件，提供移动端实时监控、跨设备事件推送和远程 DEFER 审批能力。通过 Latch Hub，运维人员可以在手机或平板上实时查看安全事件并审批高风险操作。

!!! info "Latch 是可选的"
    ClawSentry 核心功能（L1/L2/L3 决策、CLI watch、Web UI）无需 Latch 即可正常工作。Latch 仅在需要移动端/远程审批场景时才需要安装。

---

## 架构概览

```
┌─────────────────┐     ┌──────────────┐     ┌──────────────┐
│  ClawSentry     │     │  Latch Hub   │     │  移动端/Web  │
│  Gateway        │────▶│  :3006       │────▶│  PWA         │
│  EventBus       │     │  CLI Session │     │  推送审批    │
│  DEFER Bridge   │     │  HTTP API    │     │              │
└─────────────────┘     └──────────────┘     └──────────────┘
     ▲                       ▲
     │                       │
LatchHubBridge          process_manager
(事件转发)              (进程生命周期)
```

**组件职责：**

| 组件 | 说明 |
|------|------|
| `binary_manager` | 跨平台 Latch 二进制安装、SHA-256 校验、版本管理 |
| `process_manager` | Gateway + Hub 进程 PID 管理、健康检查、优雅关闭 |
| `hub_bridge` | EventBus 订阅 → HTTP 转发到 Hub CLI Session API |
| `desktop` | Linux/macOS 桌面快捷方式创建（可选） |

---

## 前置条件

!!! info "环境要求"
    - Python 3.11+
    - ClawSentry >= 0.2.8（含 Latch 支持）
    - 可访问 GitHub Release（用于下载 Latch 二进制）
    - ClawSentry Gateway 已正常运行

```bash
# 安装含 Latch 支持的 ClawSentry
pip install "clawsentry[latch]"

# 验证安装
clawsentry latch --help
```

---

## 快速开始

### 安装

```bash
# 安装 Latch 可选依赖
pip install "clawsentry[latch]"

# 下载并安装 Latch 二进制
clawsentry latch install
```

!!! note "跨平台支持"
    `latch install` 自动检测操作系统和架构，从 GitHub Release 下载对应版本：

    - **Linux**: x64, ARM64
    - **macOS**: x64 (Intel), ARM64 (Apple Silicon)
    - **Windows**: x64

### 启动

```bash
# 一键启动 Gateway + Latch Hub
clawsentry start --with-latch

# 或分步启动
clawsentry latch start
```

### 验证

```bash
# 查看状态
clawsentry latch status

# 检查健康
clawsentry doctor
```

---

## 安装详解

### BinaryManager

`BinaryManager` 管理 Latch 二进制的完整生命周期：

1. **平台检测**：识别 OS（linux/darwin/windows）和架构（x64/arm64）
2. **下载**：从 GitHub Release（`github.com/Zhongan-Wang/latch`）下载对应压缩包
3. **校验**：SHA-256 校验和验证（对比 `checksums.txt`）
4. **解压**：`.tar.gz`（Linux/macOS）或 `.zip`（Windows）
5. **权限**：Unix 系统自动 `chmod +x`

**安装目录结构：**

```
~/.clawsentry/
├── bin/           # Latch 二进制
│   └── latch      # (或 latch.exe)
├── run/           # PID 文件和日志
│   ├── gateway.pid
│   ├── gateway.log
│   ├── latch-hub.pid
│   └── latch-hub.log
└── data/          # Hub 数据存储
```

### 安装选项

```bash
# 标准安装（含桌面快捷方式）
clawsentry latch install

# 跳过桌面快捷方式
clawsentry latch install --no-shortcut
```

### 卸载

```bash
# 完全卸载（停止服务 + 删除二进制 + 删除快捷方式 + 删除数据）
clawsentry latch uninstall

# 保留数据目录
clawsentry latch uninstall --keep-data
```

---

## 进程管理

### ProcessManager

`ProcessManager` 管理两个服务的 PID 生命周期：

| 服务 | 启动命令 | PID 文件 | 日志文件 |
|------|----------|----------|----------|
| Gateway | `python -m clawsentry.gateway.stack` | `gateway.pid` | `gateway.log` |
| Latch Hub | `latch hub --no-relay --port <port>` | `latch-hub.pid` | `latch-hub.log` |

### 服务状态

```python
class ServiceStatus(Enum):
    RUNNING = "running"    # 进程存活，PID 有效
    STOPPED = "stopped"    # 无 PID 文件
    STALE   = "stale"      # PID 文件存在但进程已死
```

### 健康检查

`wait_for_health()` 在服务启动后轮询 `GET /health` 端点：

- 默认超时：5 秒
- 轮询间隔：0.1 秒
- 失败时返回 `False`，调用方负责清理和报告错误

### 优雅关闭

`stop_all()` 执行两阶段关闭：

1. 发送 SIGTERM 信号
2. 等待进程退出（默认 5 秒）
3. 超时后升级为 SIGKILL
4. 清理 PID 文件

---

## Hub 事件转发

### LatchHubBridge

`LatchHubBridge` 订阅 Gateway EventBus 并将事件通过 HTTP 转发到 Latch Hub。

### 订阅的事件类型

| 事件 | 转发消息格式 |
|------|-------------|
| `decision` | `[ALLOW/BLOCK/DEFER] tool_name (risk: level)` |
| `session_start` | `[SESSION START] Agent: id (framework)` |
| `session_risk_change` | `[RISK CHANGE] prev → curr` |
| `alert` | `[ALERT:severity] message` |
| `defer_pending` | `[DEFER PENDING] tool — awaiting operator approval (timeout: Ns)` |
| `defer_resolved` | `[DEFER RESOLVED] allow/block` |
| `post_action_finding` | `[POST_ACTION_FINDING] {event JSON}` |
| `session_enforcement_change` | `[SESSION_ENFORCEMENT_CHANGE] {event JSON}` |

### 自动启动条件

Bridge 在以下条件满足时自动启动：

- `CS_HUB_BRIDGE_ENABLED=true`（或 `auto` 且检测到 Hub 运行）
- Hub 基础 URL 可达

### Hub 会话映射

Bridge 为每个 ClawSentry 会话自动创建对应的 Hub CLI 会话：

1. `_register_gateway()` — 向 Hub 注册 Gateway URL 和认证信息
2. `_ensure_hub_session()` — 创建带 ClawSentry 元数据的 Hub 会话
3. `_forward_event()` — 将事件转换为结构化 Hub 消息
4. `_hub_request()` — HTTP 请求，含 2 次尝试（0.5s 退避间隔）

---

## 桌面集成

### 支持平台

| 平台 | 快捷方式位置 | 格式 |
|------|-------------|------|
| Linux | `~/.local/share/applications/clawsentry.desktop` | freedesktop .desktop |
| macOS | `~/Applications/ClawSentry.app` | App Bundle（含 Info.plist + launcher 脚本） |
| Windows | 不支持（抛出 `UnsupportedPlatformError`） | — |

### 管理

```bash
# 安装时自动创建快捷方式
clawsentry latch install

# 跳过快捷方式
clawsentry latch install --no-shortcut

# 卸载时自动移除
clawsentry latch uninstall
```

---

## CLI 命令

完整 CLI 参考见 [CLI 命令参考 > clawsentry latch](../cli/index.md#clawsentry-latch)。

| 命令 | 说明 |
|------|------|
| `clawsentry latch install` | 下载安装 Latch 二进制 |
| `clawsentry latch start` | 启动 Gateway + Hub |
| `clawsentry latch stop` | 停止所有服务 |
| `clawsentry latch status` | 查看服务状态 |
| `clawsentry latch uninstall` | 卸载 Latch |

---

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CS_LATCH_HUB_URL` | (空) | Hub 基础 URL（如 `http://127.0.0.1:3006`） |
| `CS_LATCH_HUB_PORT` | `3006` | Hub 端口（URL 未设置时回退） |
| `CS_HUB_BRIDGE_ENABLED` | `auto` | 事件转发开关：`auto`/`true`/`false` |
| `CS_DEFER_BRIDGE_ENABLED` | `true` | DEFER 审批桥接开关 |
| `CLAWSENTRY_HOME` | `~/.clawsentry` | Latch 安装基础目录 |

---

## Doctor 检查项

`clawsentry doctor` 包含 3 个 Latch 相关检查：

| 检查 ID | 说明 |
|---------|------|
| `LATCH_BINARY` | Latch 二进制已安装且可执行 |
| `LATCH_HUB_HEALTH` | Hub 健康端点响应正常 |
| `LATCH_TOKEN_SYNC` | `CS_AUTH_TOKEN` 与 Hub `CLI_API_TOKEN` 匹配 |

---

## 故障排查

??? question "latch install 失败：下载超时"
    检查网络连接和 GitHub 可访问性。如果在中国大陆，可能需要设置代理：
    ```bash
    export HTTPS_PROXY=http://proxy:port
    clawsentry latch install
    ```

??? question "latch start 后 Hub 未启动"
    1. 检查 Latch 二进制是否已安装：`clawsentry latch status`
    2. 查看 Hub 日志：`cat ~/.clawsentry/run/latch-hub.log`
    3. 检查端口是否被占用：`lsof -i :3006`

??? question "事件未转发到 Hub"
    1. 确认 Bridge 已启用：`CS_HUB_BRIDGE_ENABLED=true`
    2. 确认 Hub 健康：`curl http://127.0.0.1:3006/health`
    3. 运行 `clawsentry doctor` 检查 `LATCH_HUB_HEALTH` 和 `LATCH_TOKEN_SYNC`

??? question "DEFER 推送审批不工作"
    1. 确认 `CS_DEFER_BRIDGE_ENABLED=true`
    2. 确认 Hub Bridge 正常转发 `defer_pending` 事件
    3. 使用 `clawsentry watch --filter defer_pending,defer_resolved` 验证事件流

---

## 下一步

- [核心概念 — EventBus/SSE](../getting-started/concepts.md#eventbus-sse) — 理解 Latch 如何订阅事件流
- [clawsentry latch 命令详解](../cli/index.md#clawsentry-latch) — 完整 CLI 参考
- [Claude Code 集成](claude-code.md) — 配合 Claude Code 使用 Latch
- [OpenClaw 集成](openclaw.md) — 配合 OpenClaw 使用 Latch
- [检测管线配置](../configuration/detection-config.md) — 调整 Emergency 告警阈值（触发 Latch 推送）
