---
title: CLI 命令参考
description: ClawSentry 全部命令行工具的完整使用手册
---

# CLI 命令参考

ClawSentry 提供统一的命令行入口 `clawsentry`，通过子命令完成框架初始化、网关启动、事件监控等操作。

## 调用方式

安装后，以下三种方式等价：

```bash
# 推荐方式
clawsentry <subcommand> [options]

# Python 模块调用
python -m clawsentry <subcommand> [options]

# 直接调用入口脚本（由 pip install 注册）
clawsentry-gateway   # 等价于 clawsentry gateway
clawsentry-harness   # 等价于 clawsentry harness
clawsentry-stack     # 等价于 clawsentry stack
```

!!! info "配置来源：env-first + 显式 env file"
    ClawSentry 不自动发现任何项目 env file。`.clawsentry.env.example` 只是可提交的 dotenv 模板；需要生效时请显式传入 `--env-file PATH` 或设置 `CLAWSENTRY_ENV_FILE=PATH`。`clawsentry gateway`、`stack`、`start` 不再自动读取当前目录的 `.env.clawsentry`。

    本机 secrets/runtime 值请用进程环境、部署环境，或显式 env file：
    ```bash
    # .clawsentry.env.local（不要提交）
    CS_AUTH_TOKEN=my-secret-token
    CS_HTTP_PORT=9100
    OPENCLAW_OPERATOR_TOKEN=quoted-value
    ```

## 命令速查表

| 命令 | 用途 | 典型用法 |
|------|------|---------|
| [`start`](#clawsentry-start) | **一键启动**（推荐） | `clawsentry start --framework claude-code` |
| [`stop`](#clawsentry-stop) | 停止 Gateway | `clawsentry stop` |
| [`status`](#clawsentry-status) | 查看运行状态 | `clawsentry status` |
| [`init`](#clawsentry-init) | 初始化框架配置 | `clawsentry init claude-code` |
| [`gateway`](#clawsentry-gateway) | 直接启动 Gateway（高级） | `clawsentry gateway` |
| [`stack`](#clawsentry-stack) | 直接启动完整栈（高级） | `clawsentry stack` |
| [`harness`](#clawsentry-harness) | stdio hook 处理器 | 由框架自动调用，通常无需手动使用 |
| [`watch`](#clawsentry-watch) | 实时监控事件流 | `clawsentry watch --interactive` |
| [`scope`](#clawsentry-scope) | 校验/预览 session scope 配置 | `clawsentry scope preview --profile profile.json --event event.json` |
| [`audit`](#clawsentry-audit) | 离线查询审计日志 | `clawsentry audit --risk high --since 1h` |
| [`doctor`](#clawsentry-doctor) | 诊断配置和连接（20 项检查） | `clawsentry doctor` |
| [`test-llm`](#clawsentry-test-llm) | 验证 L2/L3 连通性、时延与当前运行模式 | `clawsentry test-llm --json` |
| [`l3`](#clawsentry-l3) | Operator-triggered L3 advisory actions | `clawsentry l3 full-review --session sess-123` |
| [`service`](#clawsentry-service) | 安装或检查常驻服务（systemd/launchd） | `clawsentry service status` |
| [`config`](#clawsentry-config) | 管理项目安全预设 | `clawsentry config init --preset high` |
| [`rules`](#clawsentry-rules) | 规则治理（lint / dry-run / report） | `clawsentry rules lint --json` |
| [`skill-trust`](#clawsentry-skill-trust) | 扫描并登记本地 skill trust registry | `clawsentry skill-trust register-dir --skills-dir ~/.codex/skills --registry .clawsentry/skill-trust-registry.json --metadata .clawsentry/skill-trust-runtime.json` |
| [`latch`](#clawsentry-latch) | 管理 Latch 移动监控 | `clawsentry latch install` |

> **新用户推荐路径：** 先运行 `clawsentry start --framework <你的框架>`。它会启动 Gateway，并在前台显示 `watch` 事件流；只有需要安装宿主 managed hooks 或排障时，再单独使用 `init`、`gateway`、`watch`。

!!! tip "这些命令是什么关系？"
    | 命令 | 你什么时候用 | 与 `start` 的关系 |
    |------|---------------|-------------------|
    | `clawsentry start` | 日常启动和新用户接入 | 推荐入口；内部会按需调用初始化、启动 Gateway、接上事件流 |
    | `clawsentry init` | 输出 framework env 建议，或在 `--setup` 时安装框架 hook | 手动配置步骤；`start` 不写项目配置 |
    | `clawsentry gateway` | 只启动后台服务、systemd/Docker/调试 transport | `start --no-watch` 的底层服务部分 |
    | `clawsentry watch` | Gateway 已经在跑，只想另开终端看实时事件 | `start` 的前台监控部分 |
    | `clawsentry-harness` | a3s-code stdio transport 自动调用 | 不是普通用户入口，通常只出现在 SDK transport 配置里 |

!!! abstract "本页快速导航"
    [start](#clawsentry-start) · [stop](#clawsentry-stop) · [status](#clawsentry-status) · [init](#clawsentry-init) · [gateway](#clawsentry-gateway) · [stack](#clawsentry-stack) · [harness](#clawsentry-harness) · [watch](#clawsentry-watch) · [scope](#clawsentry-scope) · [audit](#clawsentry-audit) · [doctor](#clawsentry-doctor) · [test-llm](#clawsentry-test-llm) · [l3](#clawsentry-l3) · [service](#clawsentry-service) · [config](#clawsentry-config) · [rules](#clawsentry-rules) · [skill-trust](#clawsentry-skill-trust) · [integrations](#clawsentry-integrations) · [latch](#clawsentry-latch)

---

## clawsentry start

**一键启动 ClawSentry 监督网关**（推荐方式）。通过显式 `--framework` / `--frameworks`、进程环境或显式 `--env-file` 选择框架，启动 Gateway，并显示实时监控。

### 语法

```bash
clawsentry start [--framework {a3s-code,claude-code,codex,gemini-cli,kimi-cli,openclaw}]
                 [--frameworks a3s-code,codex,openclaw]
                 [--setup-openclaw | --no-setup-openclaw]
                 [--host HOST] [--port PORT] [--env-file PATH]
                 [--no-watch] [--interactive | -i]
                 [--open-browser] [--with-latch] [--hub-port PORT]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--framework` | `codex` | 目标框架：`a3s-code`、`claude-code`、`codex`、`gemini-cli`、`kimi-cli`、`openclaw`；新用户建议显式传入 |
| `--frameworks` | 空 | 逗号分隔的多框架启用列表，如 `a3s-code,codex,openclaw` |
| `--setup-openclaw` | `false` | 当本次启动涉及 `openclaw` 时，同时显式修改 `~/.openclaw/` 中的审批配置 |
| `--host` | `127.0.0.1` | Gateway HTTP 监听地址 |
| `--port` | `8080` 或 `CS_HTTP_PORT` | Gateway HTTP 监听端口 |
| `--no-watch` | `false` | 仅启动 Gateway，不显示实时监控 |
| `--interactive` / `-i` | `false` | 启用 DEFER 决策交互式审批 |
| `--open-browser` | `false` | 启动后在浏览器中打开 Web UI |
| `--with-latch` | `false` | 同时启动 Latch Hub（需先运行 `clawsentry latch install`） |
| `--hub-port` | `3006` | Latch Hub 端口，配合 `--with-latch` 使用 |
| `--env-file PATH` | 空 | 显式读取本机 secrets/runtime env file；不会自动发现 `.env.clawsentry` |

### 工作流程

`clawsentry start` 会自动执行以下步骤：

1. **框架选择**：显式 `--framework` / `--frameworks` 优先；否则读取进程环境或显式 env file 中的 `CS_FRAMEWORK` / `CS_ENABLED_FRAMEWORKS`
2. **集成提示**：`start` 不写项目配置；需要宿主 managed hooks 时单独运行 `clawsentry init <framework> --setup`
3. **显式 env 合成**：只在传入 `--env-file` / `CLAWSENTRY_ENV_FILE` 时读取本机 runtime 值；进程环境优先
4. **Gateway 启动**：后台启动 Gateway 进程，等待健康检查通过；缺少 `CS_AUTH_TOKEN` 时使用本次进程内临时 token
5. **实时监控**：前台显示 `clawsentry watch` 输出（除非使用 `--no-watch`）
6. **优雅关闭**：按 `Ctrl+C` 时，先发送 SIGTERM，5 秒后降级为 SIGKILL

### 示例

#### 显式框架启动

```bash
clawsentry start --framework codex
clawsentry start --frameworks a3s-code,codex,openclaw --no-watch
clawsentry start --env-file .clawsentry.env.local
```

??? example "终端输出"
    ```
    ClawSentry starting...
      Framework:  codex
      Gateway:    http://127.0.0.1:8080 (background)
      Web UI:     http://127.0.0.1:8080/ui?token=xK7m9p2QaB3...
      Log file:   /tmp/clawsentry-gateway.log

    Gateway ready. Streaming events...

    ──────────────────────────────────────────────────────────────
    [14:23:05] DECISION  session=my-session
      verdict : ALLOW
      risk    : low
      command : cat README.md
    ──────────────────────────────────────────────────────────────
    ```

#### 指定框架和端口

```bash
clawsentry start --framework a3s-code --port 9100
```

#### 多框架一起启用

```bash
clawsentry start --frameworks a3s-code,codex,openclaw --no-watch
```

此命令按参数启用多个框架，启动 banner 会显示 `Enabled: a3s-code, codex, openclaw`。默认不会修改 `~/.openclaw/`；如需在启动时一并配置 OpenClaw 侧审批文件，显式添加 `--setup-openclaw`。
启动 banner 会打印 `Readiness` 摘要，把每个框架是 `ready`、`needs attention` 还是 `manual verification required` 直接讲明白，并给出 `Next actions`。

如果加上 `--with-latch`，`start` 会在 Gateway 之外编排 Latch Hub，并把 Web UI / watch / Latch 的启动信息放进同一份 banner；如果 Latch 二进制或 token 尚未就绪，readiness 会给出具体 next step，而不是把多框架启动误报为完全可用。

#### 启动时同时设置 OpenClaw

```bash
clawsentry start --frameworks codex,openclaw --setup-openclaw --no-watch
```

当启用了 `openclaw` 且显式传入 `--setup-openclaw` 时，`start` 会继续尝试更新 `~/.openclaw/openclaw.json` 与 `exec-approvals.json`。启用来源可以是 `--frameworks`、进程环境或显式 env file。

#### 仅启动 Gateway（不显示监控）

```bash
clawsentry start --no-watch
```

此模式下，Gateway 在后台运行，命令立即返回。你可以稍后手动运行 `clawsentry watch` 查看事件；如果本次使用的是临时 token，启动输出会打印可复制的 `clawsentry watch --token ...` 命令。
停止后台 Gateway 时运行 `clawsentry stop`。

#### 启用交互式 DEFER 审批

```bash
clawsentry start --interactive
```

当收到 DEFER 决策时，终端会提示你输入 `[A]llow`、`[D]eny` 或 `[S]kip`。

### Web UI 自动登录

启动时，终端会显示带 token 的 Web UI URL：

```
Web UI: http://127.0.0.1:8080/ui?token=xK7m9p2QaB3...
```

点击该 URL 即可自动登录，无需手动输入 token。
前端会把 `?token=` 保存到 `sessionStorage` 后清理地址栏；后续手动登录时使用同一个 `CS_AUTH_TOKEN`。如果看到 invalid token / `401`，重新复制启动 banner，或检查进程环境 / 显式 `--env-file` 中的 `CS_AUTH_TOKEN`；如果看到 `Gateway unavailable`，这表示本机 Gateway 无法访问而不是凭证错误。代理环境下可先设置：

```bash
export NO_PROXY=localhost,127.0.0.1,::1
```

### 错误处理

- **框架检测失败**：如果无法自动检测框架，命令会报错并提示使用 `--framework` 参数
- **初始化失败**：如果 `clawsentry init` 失败（如权限问题），命令会抛出 `RuntimeError`
- **Gateway 启动失败**：如果 Gateway 进程在 0.1 秒内退出，命令会报错并显示日志路径
- **健康检查超时**：如果 5 秒内 Gateway 未响应健康检查，命令会报错

### 日志位置

Gateway 的 stdout/stderr 输出会写入临时日志文件：

```
/tmp/clawsentry-gateway.log
```

如果启动失败，命令会提示查看该日志文件。

---

## clawsentry init

初始化框架集成配置。默认输出目标框架所需的 `CS_FRAMEWORK` / `CS_ENABLED_FRAMEWORKS` 建议，并在显式 `--setup` 时配置所需的框架侧设置文件。

### 语法

```bash
clawsentry init <framework> [--dir PATH] [--force] [--auto-detect] [--setup] [--dry-run]
                             [--openclaw-home PATH] [--codex-home PATH]
                             [--uninstall] [--restore]
```

### 参数

| 参数 | 说明 |
|------|------|
| `framework` | 目标框架，可选值：`a3s-code`、`claude-code`、`codex`、`gemini-cli`、`kimi-cli`、`openclaw` |

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--dir PATH` | `.`（当前目录） | 配置文件写入目录 |
| `--force` | `false` | 覆盖 ClawSentry 管理的宿主 hook/config 段（如适用） |
| `--auto-detect` | `true` | 自动检测已有的框架配置（如 `~/.openclaw/` 中的 Gateway Token） |
| `--setup` | `false` | 自动配置框架设置以支持 ClawSentry 集成（隐含 `--auto-detect`；OpenClaw 写宿主审批配置，Codex 写 managed native hooks） |
| `--dry-run` | `false` | 预览 `--setup` 将要执行的配置变更，但不实际应用 |
| `--uninstall` | `false` | 移除 ClawSentry 管理的宿主 hooks（如适用）；不会编辑你的 env file |
| `--openclaw-home PATH` | `~/.openclaw` | 指定 OpenClaw 配置目录（用于 `--setup` / `--restore`） |
| `--codex-home PATH` | `$CODEX_HOME` 或 `~/.codex` | 指定 Codex 配置目录（用于 `--setup` / `--uninstall`） |
| `--restore` | `false` | 从 ClawSentry 备份恢复框架设置（目前支持 `openclaw`） |

!!! info "env 建议与 hook 安装分离"
    `clawsentry init <framework>` 默认不写 `.clawsentry.env.example`、不写 `.env.clawsentry`、不写密钥；它会打印 `CS_FRAMEWORK` / `CS_ENABLED_FRAMEWORKS` 建议。需要持久化时，把这些 `KEY=VALUE` 放到显式 env file 或部署环境中。

!!! info "按框架安全卸载"
    `clawsentry init <framework> --uninstall` 会清理 ClawSentry 管理的框架侧 hook（如适用）。它不会删除本机 env file，也不会轮换 `CS_AUTH_TOKEN`。

!!! warning "OpenClaw setup 是显式 opt-in"
    `clawsentry init openclaw` 默认只打印 env 建议，不会修改 `~/.openclaw/openclaw.json` 或 `exec-approvals.json`。需要自动修改 OpenClaw 侧配置时，显式加上 `--setup`；建议先运行 `--setup --dry-run`.

### 示例

#### 初始化 a3s-code 集成

```bash
clawsentry init a3s-code
```

??? example "终端输出"
    ```
    [clawsentry] a3s-code integration initialized

      Environment variables:
        CS_FRAMEWORK=a3s-code
        CS_ENABLED_FRAMEWORKS=a3s-code

      Next steps:
        1. export CS_AUTH_TOKEN = <your-dev-token>   # optional; start can create an ephemeral token
        2. clawsentry gateway --env-file .clawsentry.env.local
        3. Configure a3s-code AHP transport explicitly in your agent script
        4. clawsentry watch --token "$CS_AUTH_TOKEN"
    ```

#### 初始化 OpenClaw 集成（自动检测令牌）

```bash
clawsentry init openclaw --auto-detect
```

此命令会检测 `~/.openclaw/openclaw.json`，但不会把 token 写入 `.clawsentry.env.example`。需要复用 OpenClaw token 时，请通过进程环境或显式 env file 提供。

它不会修改 OpenClaw 侧配置文件；需要自动设置 `tools.exec.host` 和审批策略时使用下一节的 `--setup`。

#### 自动配置 OpenClaw + 预览变更

```bash
clawsentry init openclaw --setup --dry-run
```

??? example "终端输出"
    ```
    [clawsentry] openclaw integration initialized

      Files updated:
        .clawsentry.env.example

      Runtime values (not persisted):
        OPENCLAW_WS_URL=ws://127.0.0.1:18789
        OPENCLAW_OPERATOR_TOKEN=<set in env or --env-file>
        CS_AUTH_TOKEN = <set in env or ephemeral at start>

      Next steps:
        1. clawsentry gateway --env-file .clawsentry.env.local
        2. clawsentry watch

      [DRY RUN] The following changes would be applied:
        - Set tools.exec.host = "gateway" in openclaw.json
        - Set exec-approvals security = "allowlist", ask = "always"
    ```

`--setup` 会自动配置以下 OpenClaw 关键设置：

- `tools.exec.host = "gateway"` —— 启用 Gateway 审批流程（默认 `sandbox` 跳过审批）
- `exec-approvals.json` —— 设置 `security: "allowlist"`, `ask: "always"`

!!! warning "备份机制"
    `--setup`（不带 `--dry-run`）会在修改前自动创建 `.bak` 备份文件。

#### 自动配置 Codex native hooks

```bash
clawsentry init codex --setup
```

`--setup` 会启用 `$CODEX_HOME/config.toml`（或 `~/.codex/config.toml`）
中的 `[features].codex_hooks = true`，并在 `$CODEX_HOME/hooks.json`（或 `~/.codex/hooks.json`）中追加
ClawSentry 管理的 hook entries。已有用户 hooks 和 OMX hooks 会被保留；
`clawsentry init codex --uninstall` 只移除 ClawSentry 管理的 entries。
如需测试临时目录或非默认安装位置，可加 `--codex-home PATH`。
`clawsentry doctor` 会逐项显示 managed hook 形态，便于确认
`PreToolUse(Bash): sync` 与其他 native events 的 `async` 观察模式是否仍符合预期。

#### 恢复 OpenClaw 配置

```bash
# 预览恢复操作
clawsentry init openclaw --restore --dry-run

# 从 openclaw.json.bak / exec-approvals.json.bak 恢复
clawsentry init openclaw --restore
```

`--restore` 只读取 ClawSentry `--setup` 创建的 `.bak` 文件；找不到备份时只输出 warning，不会写入新文件。

#### 卸载某个框架

```bash
# 移除 ClawSentry managed native hooks；如使用 env file，请手动移除 codex
clawsentry init codex --uninstall

# 移除 Claude Code hooks；如使用 env file，请手动移除 claude-code
clawsentry init claude-code --uninstall

# 禁用 OpenClaw framework 配置；如需恢复 OpenClaw 侧文件，另用 --restore
clawsentry init openclaw --uninstall
```

`--uninstall` 不编辑 env file；如你用 `CS_ENABLED_FRAMEWORKS` 持久化框架列表，请同步修改对应 explicit env file 或部署环境。

---

## clawsentry gateway

启动 Supervision Gateway（监督网关）。自动检测 OpenClaw 配置，按需启用 Webhook/WebSocket 组件。

### 语法

```bash
clawsentry gateway [--gateway-host HOST] [--gateway-port PORT] [--uds-path PATH]
                    [--trajectory-db-path PATH] [--trajectory-retention-seconds N]
                    [--webhook-host HOST] [--webhook-port PORT]
                    [--webhook-token TOKEN] [--webhook-secret SECRET]
                    [--gateway-transport-preference PREF]
```

此命令委托给 `clawsentry.gateway.stack:main()`，等价于 `clawsentry stack`。

### 选项

#### 网关核心

| 选项 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `--gateway-host` | `CS_HTTP_HOST` | `127.0.0.1` | HTTP 服务监听地址 |
| `--gateway-port` | `CS_HTTP_PORT` | `8080` | HTTP 服务监听端口 |
| `--uds-path` | `CS_UDS_PATH` | `/tmp/clawsentry.sock` | Unix Domain Socket 路径 |
| `--trajectory-db-path` | `CS_TRAJECTORY_DB_PATH` | `/tmp/clawsentry-trajectory.db` | 轨迹数据库路径（SQLite） |
| `--trajectory-retention-seconds` | `AHP_TRAJECTORY_RETENTION_SECONDS` | `2592000`（30 天） | 轨迹记录保留时间 |

#### OpenClaw Webhook

| 选项 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `--webhook-host` | `OPENCLAW_WEBHOOK_HOST` | `127.0.0.1` | Webhook 接收器监听地址 |
| `--webhook-port` | `OPENCLAW_WEBHOOK_PORT` | `8081` | Webhook 接收器监听端口 |
| `--webhook-token` | `OPENCLAW_WEBHOOK_TOKEN` | （内置默认值） | Webhook 认证令牌 |
| `--webhook-secret` | `OPENCLAW_WEBHOOK_SECRET` | `None` | HMAC 签名密钥 |
| `--webhook-require-https` | — | `false` | 要求 Webhook 使用 HTTPS（localhost 豁免） |
| `--webhook-max-body-bytes` | — | `1048576`（1 MB） | Webhook 请求体大小限制 |

#### 高级选项

| 选项 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `--gateway-transport-preference` | — | `uds_first` | OpenClaw Gateway 客户端传输顺序：`uds_first` 或 `http_first` |
| `--source-protocol-version` | — | （自动检测） | OpenClaw 协议版本 |
| `--git-short-sha` | — | （自动检测） | OpenClaw Git 版本标识 |
| `--profile-version` | — | `1` | 映射规则版本号 |

### 运行模式自动检测

Gateway 通过以下条件判断是否启用 OpenClaw 集成：

- `OPENCLAW_WEBHOOK_TOKEN` 不等于内置默认值，**或者**
- `OPENCLAW_ENFORCEMENT_ENABLED=true`

满足任一条件时，自动启动 Webhook 接收器和 WebSocket 事件监听。否则仅启动 Gateway 核心（UDS + HTTP）。

### 示例

#### 仅 Gateway 模式

```bash
clawsentry gateway
```

??? example "启动日志"
    ```
    2026-03-23T10:00:00 [ahp-stack] Gateway-only starting:
      gateway=http://127.0.0.1:8080/ahp
      uds=/tmp/clawsentry.sock
      (no OpenClaw config detected)
    ```

#### 完整模式（含 OpenClaw 集成）

```bash
export OPENCLAW_WEBHOOK_TOKEN=my-webhook-token
export OPENCLAW_ENFORCEMENT_ENABLED=true
export OPENCLAW_OPERATOR_TOKEN=xxxxxxxxxxxxxxxx...
export OPENCLAW_WS_URL=ws://127.0.0.1:18789

clawsentry gateway --gateway-port 9100 --webhook-port 9101
```

??? example "启动日志"
    ```
    2026-03-23T10:00:00 [ahp-stack] Full stack starting:
      gateway=http://127.0.0.1:9100/ahp
      uds=/tmp/clawsentry.sock
      webhook=http://127.0.0.1:9101/webhook/openclaw
    2026-03-23T10:00:00 [ahp-stack] OpenClaw WS enforcement listener active
    ```

#### 指定 SSL 证书启动

```bash
export AHP_SSL_CERTFILE=/etc/ssl/certs/clawsentry.pem
export AHP_SSL_KEYFILE=/etc/ssl/private/clawsentry-key.pem

clawsentry gateway
```

---

## clawsentry stack

`clawsentry gateway` 的别名。语法和选项完全相同。

```bash
clawsentry stack [options]
```

保留此命令是为了向后兼容早期版本。推荐使用 `clawsentry gateway`。

---

## clawsentry harness

启动 a3s-code stdio Harness（AHP 钩子进程）。该进程通过 stdin/stdout 与 a3s-code 通信，将 Hook 事件转发到 ClawSentry Gateway 进行安全评估。

### 语法

```bash
clawsentry harness [--uds-path PATH] [--default-deadline-ms MS]
                    [--max-rpc-retries N] [--retry-backoff-ms MS]
                    [--default-session-id ID] [--default-agent-id ID]
```

### 选项

| 选项 | 环境变量 | 默认值 | 说明 |
|------|----------|--------|------|
| `--uds-path` | `CS_UDS_PATH` | `/tmp/clawsentry.sock` | Gateway UDS 路径 |
| `--default-deadline-ms` | `A3S_GATEWAY_DEFAULT_DEADLINE_MS` | `4500` | RPC 请求超时（毫秒） |
| `--max-rpc-retries` | `A3S_GATEWAY_MAX_RPC_RETRIES` | `1` | RPC 最大重试次数 |
| `--retry-backoff-ms` | `A3S_GATEWAY_RETRY_BACKOFF_MS` | `50` | 重试间隔退避（毫秒） |
| `--default-session-id` | `A3S_GATEWAY_DEFAULT_SESSION_ID` | `ahp-session` | 默认会话 ID |
| `--default-agent-id` | `A3S_GATEWAY_DEFAULT_AGENT_ID` | `ahp-agent` | 默认 Agent ID |

### 工作原理

1. 从 stdin 逐行读取 JSON-RPC 2.0 消息
2. 将 a3s-code Hook 事件归一化为 AHP `CanonicalEvent`
3. 通过 UDS 转发至 Gateway 获取决策
4. 将 `CanonicalDecision` 转换为 a3s-code 可识别的响应格式
5. 将响应写入 stdout

### 支持的 Hook 事件类型

| a3s-code Hook | AHP EventType | 阻塞 | 说明 |
|---------------|---------------|------|------|
| `PreToolUse` | `pre_action` | :material-check: | 工具调用前拦截 |
| `PostToolUse` | `post_action` | :material-close: | 工具调用后审计 |
| `PrePrompt` | `pre_prompt` | :material-check: | Prompt 发送前检查 |
| `GenerateStart` | `pre_prompt` | :material-check: | LLM 生成前检查 |
| `SessionStart` | `session` | :material-close: | 会话启动通知 |
| `SessionEnd` | `session` | :material-close: | 会话结束通知 |
| `OnError` | `error` | :material-close: | 错误事件审计 |

!!! note "未映射事件"
    `GenerateEnd`、`SkillLoad`、`SkillUnload` 事件不会被映射，Harness 会静默忽略。

### 本地降级

当 Gateway 不可达时（UDS 连接失败或超时），Harness 会自动执行本地降级决策：

- 包含 `destructive_pattern` 或 `shell_execution` 风险提示 → **BLOCK**
- 其他 `pre_action` → **DEFER**（等待人工或上游重试）
- `pre_prompt` / `post_action` / `post_response` / `session` / `error` → **ALLOW**（观察型事件 fail-open）

### 示例

```bash
# 直接启动（通常由 a3s-code 自动调用）
clawsentry harness --uds-path /tmp/clawsentry.sock

# 手动测试：发送 handshake
echo '{"jsonrpc":"2.0","id":1,"method":"ahp/handshake","params":{}}' | clawsentry harness
```

??? example "Handshake 响应"
    ```json
    {
      "jsonrpc": "2.0",
      "id": 1,
      "result": {
        "protocol_version": "2.0",
        "harness_info": {
          "name": "a3s-gateway-harness",
          "version": "1.0.0",
          "capabilities": [
            "pre_action",
            "post_action",
            "pre_prompt",
            "session",
            "error"
          ]
        }
      }
    }
    ```

---

## clawsentry watch

实时监控 Gateway 的 SSE（Server-Sent Events）事件流，在终端以彩色格式化输出或原始 JSON 展示。

### 语法

```bash
clawsentry watch [--gateway-url URL] [--token TOKEN] [--filter TYPES]
                 [--json] [--no-color] [--interactive | -i]
                 [--verbose | -v] [--no-emoji] [--compact]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--gateway-url URL` | `http://127.0.0.1:{CS_HTTP_PORT}` | Gateway 基础 URL |
| `--token TOKEN` | `None` | Bearer 认证令牌 |
| `--filter TYPES` | `None`（全部） | 逗号分隔的事件类型过滤器 |
| `--json` | `false` | 输出原始 JSON（适合管道处理） |
| `--no-color` | `false` | 禁用 ANSI 颜色代码 |
| `--interactive` / `-i` | `false` | DEFER 决策交互确认模式 |
| `--verbose` / `-v` | `false` | 显示所有决策详情，包括 ALLOW |
| `--no-emoji` | `false` | 禁用 emoji 输出（适合纯文本/窄终端环境） |
| `--compact` | `false` | 紧凑格式，不使用 Unicode 边框绘制会话分组 |

### 支持的事件类型

用于 `--filter` 的可选值：

| 事件类型 | 说明 |
|----------|------|
| `decision` | 每次决策结果（ALLOW/BLOCK/DEFER/MODIFY） |
| `alert` | 高风险告警 |
| `session_start` | 新会话创建 |
| `session_risk_change` | 会话风险等级变更 |
| `session_enforcement_change` | 会话强制策略状态变更 |
| `defer_pending` / `defer_resolved` | DEFER 审批创建与完成 |
| `post_action_finding` | Post-action 围栏发现 |
| `trajectory_alert` | 多步轨迹命中 |
| `pattern_candidate` / `pattern_evolved` | 自进化模式候选与生命周期变化 |
| `l3_advisory_snapshot` | L3 advisory frozen evidence snapshot 已创建 |
| `l3_advisory_review` | L3 advisory review 状态/结果 |
| `l3_advisory_job` | L3 advisory job 队列/worker 状态 |

### 终端输出格式

#### 决策事件

```
[10:30:45]  BLOCK     rm -rf /data                             risk=high    D1: destructive pattern
[10:30:46]  ALLOW     cat README.md                            risk=low
[10:30:47]  DEFER     sudo chmod 777 /etc/passwd               risk=high    Requires operator approval
```

颜色编码：:large_red_square: BLOCK（红色）| :large_green_square: ALLOW（绿色）| :large_yellow_square: DEFER（黄色）| :large_blue_square: MODIFY（青色）

#### 告警事件

```
[10:30:45]  ALERT     sess=sess-001  severity=high  Risk escalation detected
```

#### 会话事件

```
[10:30:45]  SESSION   started  sess=sess-001  agent=agent-1  framework=a3s-code
[10:31:00]  RISK      sess=sess-001  low -> high
```

#### L3 advisory 事件

当启用 advisory snapshot 或 operator 手动触发 full review 时，`watch` 会把底层 ID 保留，同时给出 operator-readable 状态：

```text
[10:31:12] 🧊 L3 ADVISORY SNAPSHOT  l3snap-abc  Session=sess-001 Trigger=operator_full_review Range=4->8
[10:31:13] 🧠 L3 ADVISORY JOB       l3job-abc   Session=sess-001 State=Completed (completed) Runner=Deterministic local (deterministic_local)
            └─ Boundary: frozen snapshot; explicit run only
[10:31:13] 🧠 L3 ADVISORY REVIEW    l3adv-abc   Session=sess-001 Risk=high State=Completed (completed) Action=Inspect (inspect)
            └─ Boundary: advisory only; canonical unchanged
```

这些事件表示“冻结证据并生成咨询结论”，不代表历史 canonical decision 被重写。

### 交互模式

使用 `--interactive` 或 `-i` 启动交互模式。当收到 DEFER 决策时，运维人员可以实时做出允许或拒绝的决定：

```
  Command: sudo rm -rf /var/log
  Reason:  Destructive operation on system logs
  [A]llow  [D]eny  [S]kip (timeout in 25s) >
```

- 输入 `a` —— 允许执行（resolve 为 `allow-once`）
- 输入 `d` —— 拒绝执行（resolve 为 `deny`，附带原因 `operator denied via watch CLI`）
- 输入 `s` 或直接回车 —— 跳过不处理
- 超时未响应 —— 自动跳过（保留 5 秒安全余量防止竞态）

### 示例

#### 基础监控

```bash
clawsentry watch --token my-secret-token
```

#### 仅监控决策和告警

```bash
clawsentry watch --filter decision,alert --token my-secret-token
```

#### JSON 输出（适合管道）

```bash
clawsentry watch --json --token my-secret-token | jq '.decision'
```

#### 运维交互确认

```bash
clawsentry watch --interactive --token my-secret-token
```

### 连接行为

- 启动时显示 `Connected to <url>`
- 连接断开后自动重连（间隔 3 秒）
- `Ctrl+C` 优雅退出

---

## clawsentry scope

在启用 session scope 前，对 `SessionScopeProfile` JSON 做本地校验，或用一条 canonical event 预览会命中的 allow/defer/deny 结果。完整 profile 写法与调试流程见 [Session scope 配置](../configuration/session-scope.md)。该命令默认保持 dry-run 语义：它解释规则、状态和 reason codes，不声称已阻断动作；只有显式 `--confirm` 预览才展示 confirmed/enforced 边界。

### 语法

```bash
clawsentry scope validate --profile profile.json [--json]
clawsentry scope preview --profile profile.json --event event.json [--confirm] [--json]
```

### 选项

| 选项 | 适用子命令 | 说明 |
|------|------------|------|
| `--profile PATH` | `validate`, `preview` | `SessionScopeProfile` JSON 文件 |
| `--event PATH` | `preview` | `CanonicalEvent` JSON 文件 |
| `--confirm` | `preview` | 以 confirmed/non-dry-run 边界预览，不写入任何配置 |
| `--json` | `validate`, `preview` | 输出机器可读 JSON，便于 CI 或 runbook 记录 |

### 示例

```bash
clawsentry scope validate --profile ./scope-profile.json
clawsentry scope preview --profile ./scope-profile.json --event ./event.json --json
clawsentry scope preview --profile ./scope-profile.json --event ./event.json --confirm
```

输出会包含 `dry_run` / `enforced`、命中的 `reason_codes` 与一段用户可读 protection statement。若需要 HTTP 预览入口，可使用 [Decision API 的 `/ahp/scope/preview`](../api/decisions.md#post-ahp-scope-preview)。

---

## clawsentry stop

停止正在运行的 Gateway 进程。

### 语法

```bash
clawsentry stop
```

此命令通过读取 PID 文件定位 Gateway 进程，发送 SIGTERM 信号实现优雅关闭。

### 行为

- 读取 `/tmp/clawsentry-gateway.pid` 获取进程 ID
- 发送 SIGTERM 信号
- 如果 PID 文件不存在或进程未运行，输出提示信息并退出

### 示例

```bash
clawsentry stop
```

??? example "终端输出"
    ```
    Gateway (PID 12345) stopped.
    ```

---

## clawsentry status

查看 Gateway 运行状态。

### 语法

```bash
clawsentry status
```

### 输出

显示 Gateway 进程状态（running / not running / stale）和 PID 信息。

### 示例

```bash
clawsentry status
```

??? example "终端输出 — 运行中"
    ```
    Gateway: running (PID 12345)
    ```

??? example "终端输出 — 未运行"
    ```
    Gateway: not running
    ```

??? example "终端输出 — PID 文件过期"
    ```
    Gateway: stale PID file (PID 12345 not found)
    ```

---

## clawsentry audit

离线查询轨迹数据库（Trajectory DB）中的审计记录，支持多维度过滤和聚合统计。

### 语法

```bash
clawsentry audit [--db PATH] [--session ID] [--since DURATION]
                 [--risk LEVEL] [--decision VERDICT] [--tool NAME]
                 [--format {table|json|csv}] [--stats] [--limit N]
                 [--no-color]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--db PATH` | `CS_TRAJECTORY_DB_PATH` 或 `/tmp/clawsentry-trajectory.db` | SQLite 数据库文件路径 |
| `--session ID` | `None` | 按会话 ID 过滤 |
| `--since DURATION` | `None` | 时间窗口过滤，支持格式：`30m`、`1h`、`24h`、`7d` |
| `--risk LEVEL` | `None` | 按风险等级过滤：`low`、`medium`、`high`、`critical` |
| `--decision VERDICT` | `None` | 按决策结果过滤：`allow`、`block`、`defer`、`modify` |
| `--tool NAME` | `None` | 按工具名称过滤 |
| `--format` | `table` | 输出格式：`table`（表格）、`json`、`csv` |
| `--stats` | `false` | 仅显示聚合统计信息 |
| `--limit N` | `100` | 最大返回记录数 |
| `--no-color` | `false` | 禁用 ANSI 颜色代码 |

### 示例

#### 查询最近 1 小时的高风险事件

```bash
clawsentry audit --since 1h --risk high
```

??? example "终端输出"
    ```
    ┌──────────────────────┬────────────┬─────────┬──────────┬────────────────────────────┐
    │ timestamp            │ session    │ risk    │ decision │ command                    │
    ├──────────────────────┼────────────┼─────────┼──────────┼────────────────────────────┤
    │ 2026-03-31T14:23:05  │ sess-001   │ high    │ BLOCK    │ rm -rf /data               │
    │ 2026-03-31T14:25:12  │ sess-001   │ high    │ DEFER    │ sudo chmod 777 /etc/passwd │
    └──────────────────────┴────────────┴─────────┴──────────┴────────────────────────────┘
    2 records found
    ```

#### 查看统计概览

```bash
clawsentry audit --since 24h --stats
```

??? example "终端输出"
    ```
    Audit Statistics (last 24h)
    ───────────────────────────
    Total events:     142
    Sessions:         8

    By decision:
      ALLOW:          128 (90.1%)
      BLOCK:          8   (5.6%)
      DEFER:          4   (2.8%)
      MODIFY:         2   (1.4%)

    By risk:
      low:            115 (81.0%)
      medium:         19  (13.4%)
      high:           7   (4.9%)
      critical:       1   (0.7%)
    ```

#### 导出 JSON 格式

```bash
clawsentry audit --since 7d --format json --limit 500 > audit-report.json
```

#### 按会话和工具过滤

```bash
clawsentry audit --session sess-001 --tool bash
```

---

## clawsentry doctor

离线检查 ClawSentry 配置安全性，共执行 20 项检查，涵盖认证、网络、LLM、Latch 等类别。

### 语法

```bash
clawsentry doctor [--json] [--no-color]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--json` | `false` | 以 JSON 格式输出检查结果 |
| `--no-color` | `false` | 禁用 ANSI 颜色代码 |

### 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 所有检查均为 PASS |
| `1` | 存在至少一项 FAIL |
| `2` | 存在 WARN 但无 FAIL |

### 检查项一览

| 检查 ID | 类别 | 说明 |
|---------|------|------|
| `AUTH_PRESENCE` | 认证 | `CS_AUTH_TOKEN` 已设置 |
| `AUTH_LENGTH` | 认证 | Token 长度 >= 32（16-31 警告，<16 失败） |
| `AUTH_ENTROPY` | 认证 | Token 熵 >= 3.5 bits/char |
| `AUTH_WEAK_VALUE` | 认证 | Token 非常见弱值/占位符 |
| `UDS_PERMISSIONS` | UDS | Socket 权限为 `0o600`（仅属主可访问） |
| `THRESHOLD_ORDERING` | 配置 | `CS_THRESHOLD_MEDIUM` <= `HIGH` <= `CRITICAL` |
| `WEIGHT_BOUNDS` | 配置 | 所有权重 >= 0 |
| `LLM_CONFIG` | LLM | LLM 提供商与 API 密钥一致性 |
| `OPENCLAW_SECRET` | OpenClaw | 已设置 `CS_OPENCLAW_WEBHOOK_SECRET` |
| `LISTEN_ADDRESS` | 网络 | 监听 localhost（公网地址警告） |
| `WHITELIST_REGEX` | 正则 | Post-action 白名单正则可编译 |
| `L2_TIMEOUT` | LLM | `CS_L2_TIMEOUT_MS` 为正数（旧 `CS_L2_BUDGET_MS` 仅兼容） |
| `TRAJECTORY_DB` | 数据库 | 数据库目录可写 |
| `CODEX_CONFIG` | Codex | `CS_FRAMEWORK=codex` 或 `CS_ENABLED_FRAMEWORKS` 包含 `codex` 时 hooks / watcher 配置可用 |
| `LATCH_BINARY` | Latch | Latch 二进制已安装且可执行 |
| `LATCH_HUB_HEALTH` | Latch | Latch Hub 健康端点响应正常 |
| `LATCH_TOKEN_SYNC` | Latch | `CS_AUTH_TOKEN` 与 `CLI_API_TOKEN` 匹配 |
| `DEFER_BRIDGE` | 桥接 | DEFER 桥接超时配置有效 |
| `HUB_BRIDGE` | 桥接 | Latch Hub 桥接可达（如启用） |

### 示例

```bash
clawsentry doctor
```

??? example "终端输出"
    ```
    ClawSentry Doctor — 20 checks
    ══════════════════════════════

    [PASS] AUTH_PRESENCE      CS_AUTH_TOKEN is set
    [PASS] AUTH_LENGTH        Token length >= 32
    [PASS] AUTH_ENTROPY       Token entropy >= 3.5 bits/char
    [PASS] AUTH_WEAK_VALUE    Token is not a common weak value
    [WARN] UDS_PERMISSIONS    Socket file not found (will be created on start)
    [PASS] THRESHOLD_ORDERING Thresholds are in correct order
    [PASS] WEIGHT_BOUNDS      All weights >= 0
    [PASS] LLM_CONFIG         LLM provider/key consistency OK
    [WARN] OPENCLAW_SECRET    CS_OPENCLAW_WEBHOOK_SECRET not set
    [PASS] LISTEN_ADDRESS     Listening on localhost
    [PASS] WHITELIST_REGEX    All whitelist patterns compile OK
    [PASS] L2_TIMEOUT         CS_L2_TIMEOUT_MS is positive
    [PASS] TRAJECTORY_DB      Database directory is writable
    [PASS] CODEX_CONFIG       Codex config OK
    [PASS] CODEX_NATIVE_HOOKS Codex native hooks installed
           PreToolUse(Bash): sync
           PostToolUse(Bash): async
           UserPromptSubmit: async
           Stop: async
           SessionStart(startup|resume): async
    [WARN] LATCH_BINARY       Latch binary not installed
    [WARN] LATCH_HUB_HEALTH   Latch Hub not running
    [WARN] LATCH_TOKEN_SYNC   Latch not configured, skipped
    [PASS] DEFER_BRIDGE       DEFER bridge config OK
    [PASS] HUB_BRIDGE         Hub bridge not enabled, skipped

    ──────────────────────────────
    Result: 14 PASS, 6 WARN, 0 FAIL
    ```

#### JSON 输出

```bash
clawsentry doctor --json
```

??? example "JSON 输出"
    ```json
    {
      "checks": [
        {"id": "AUTH_PRESENCE", "category": "auth", "status": "PASS", "message": "CS_AUTH_TOKEN is set"},
        {"id": "AUTH_LENGTH", "category": "auth", "status": "PASS", "message": "Token length >= 32"}
      ],
      "summary": {"pass": 14, "warn": 5, "fail": 0}
    }
    ```

---

## clawsentry test-llm

`clawsentry test-llm` 用于做一轮实时 LLM 探针，确认当前 provider 配置、基础连通性、L2 语义分析链路，以及可选的 L3 审查链路是否正常。

### 语法

```bash
clawsentry test-llm [--json] [--no-color] [--skip-l3]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--json` | `false` | 输出结构化 JSON 结果 |
| `--no-color` | `false` | 禁用 ANSI 颜色输出 |
| `--skip-l3` | `false` | 跳过 L3 probe，只验证 provider reachability 与 L2 |

### 它会检查什么

1. provider API reachability
2. 单次调用时延
3. L2 semantic analysis 对 sample suspicious event 的响应
4. 当 `CS_L3_ENABLED=true` 且未传 `--skip-l3` 时，额外执行一次 L3 review probe

### 示例

```bash
clawsentry test-llm
clawsentry test-llm --skip-l3
clawsentry test-llm --json
```

---

## clawsentry l3

Operator-triggered L3 advisory actions. 当前子命令是 `full-review`：对一个已记录的 session 冻结 bounded evidence snapshot，排队一个 advisory job，并可选择立即执行一次显式 runner。完整概念说明见 [L3 咨询审查](../decision-layers/l3-advisory.md)。

!!! warning "advisory-only 边界"
    `clawsentry l3 full-review` 不会修改历史 canonical decision，不会启动后台 scheduler，也不会把 advisory 结果变成新的 enforcement。它的输出用于 operator 复盘和下一步处置判断。

### 语法

```bash
clawsentry l3 full-review --session SESSION_ID
                            [--gateway-url URL] [--token TOKEN]
                            [--trigger-event-id ID] [--trigger-detail TEXT]
                            [--from-record-id N] [--to-record-id N]
                            [--max-records N] [--max-tool-calls N]
                            [--runner llm_provider|deterministic_local]
                            [--queue-only] [--json] [--timeout SECONDS]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--session` | 必填 | 要 review 的 session ID |
| `--gateway-url` | `http://127.0.0.1:${CS_HTTP_PORT:-8080}` | Gateway 基础 URL |
| `--token` | `CS_AUTH_TOKEN` | Bearer token |
| `--trigger-event-id` | `operator_full_review` | 记录这次 operator action 的事件 ID |
| `--trigger-detail` | `operator_requested_full_review` | 写入 snapshot 的触发详情 |
| `--from-record-id` / `--to-record-id` | 空 | 冻结的 trajectory record 范围；为空时按当前 session bounded range 选择 |
| `--max-records` | `100` | 最大冻结记录数 |
| `--max-tool-calls` | `0` | advisory evidence 工具预算；默认不额外读取 live workspace |
| `--runner` | 服务端默认 `llm_provider` | 执行 runner：默认 LLM provider 复盘；显式 `deterministic_local` 用于本地/离线支持路径 |
| `--queue-only` | `false` | 只创建 snapshot/job，不执行 worker |
| `--json` | `false` | 输出原始 JSON |
| `--timeout` | `30` | HTTP 超时时间（秒） |

### 示例

```bash
# 冻结证据并执行一次 LLM provider advisory review
clawsentry l3 full-review --session sess-001 --token "$CS_AUTH_TOKEN"

# 只排队，不执行 worker
clawsentry l3 full-review --session sess-001 --queue-only --json

# 明确限定 record 边界，并使用共享 CS_LLM_* provider runner
CS_LLM_PROVIDER=openai \
CS_LLM_MODEL=gpt-advisory \
OPENAI_API_KEY = sk-... \
clawsentry l3 full-review \
  --session sess-001 \
  --from-record-id 4 \
  --to-record-id 8 \
  --runner llm_provider
```

典型文本输出：

```text
L3 advisory full review requested
snapshot: l3snap-...
job:      l3job-... (completed)
review:   l3adv-... (completed, risk=high)
advisory_only: true
canonical_decision_mutated: false
```

---

## clawsentry service

`clawsentry service` 用于把 Gateway 安装成用户级常驻服务，适合长期运行或系统登录后自动拉起。

### 语法

```bash
clawsentry service install [--no-enable]
clawsentry service uninstall
clawsentry service status
```

### 子命令

| 子命令 | 说明 |
|--------|------|
| `install` | 写入平台服务定义，并默认启用/启动 |
| `uninstall` | 停止并移除服务定义 |
| `status` | 查看当前服务状态 |

### 平台行为

- Linux：安装为 `systemd --user` service
- macOS：安装为 `~/Library/LaunchAgents` 下的 `launchd` user agent
- 环境变量文件：`~/.config/clawsentry/gateway.env`

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--no-enable` | `false` | 只写入服务文件，不立即 enable/start |

### 示例

```bash
clawsentry service install
clawsentry service install --no-enable
clawsentry service status
clawsentry service uninstall
```

更多部署细节见：[Deployment](../operations/deployment.md)。

---

## clawsentry config

管理 dotenv 模板、交互式 `config wizard` 和最终生效配置。新部署可以直接运行 `clawsentry config wizard --interactive` 进入终端向导；CI、文档复制命令和批量初始化继续使用 `--non-interactive` 生成可复现骨架。写入后用 `config show --effective` 检查来源；旧的 preset 命令继续保留。

### 语法

```bash
clawsentry config <subcommand> [options]
```

### 子命令

| 子命令 | 说明 |
|--------|------|
| `init` | 在当前目录创建 `.clawsentry.env.example` |
| `show` | 显示默认/有效配置；加 `--effective` 展示来源和密钥脱敏 |
| `wizard` | 在 TTY 中提供分步配置向导；`--non-interactive` 使用 supplied/default values，适合 CI |
| `set <preset>` | 更新预设等级或单个配置字段 |
| `disable` | 打印单进程禁用方式（`CS_PROJECT_ENABLED=false`） |
| `enable` | 打印单进程启用方式（`CS_PROJECT_ENABLED=true`） |

!!! info "`config wizard` 的两种模式"
    在支持 TTY 的终端中，`--interactive` 会显示分步画面并逐项询问 framework、mode、LLM provider、L2/L3 与 token budget。当 stdin 不是 TTY 或传入 `--non-interactive` 时，wizard 保持确定性行为：使用命令行传入值和默认值写出 `.clawsentry.env.example`，便于 CI 复现。

### `config init` 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--preset` | `medium` | 预设等级：`low`、`medium`、`high`、`strict` |
| `--force` | `false` | 覆盖已存在的 `.clawsentry.env.example` |

### 预设等级

| 预设 | 说明 | 适用场景 |
|------|------|----------|
| `low` | 低灵敏度，仅拦截明确高危操作 | 个人开发、受信环境 |
| `medium` | 平衡灵敏度（推荐） | 日常开发 |
| `high` | 高灵敏度，更严格的阈值 | 团队协作、生产相关代码 |
| `strict` | 最严格模式，几乎所有可疑操作均触发审查 | 安全敏感项目 |

### 示例

#### 交互式终端向导

```bash
clawsentry config wizard --interactive
clawsentry config show --effective
```

向导会按 5 步展示：

1. 选择 agent framework。
2. 选择安全模式。
3. 配置可选 LLM provider / model。
4. 选择 L2 semantic analysis 和 L3 advisory review。
5. 设置每日 LLM token budget。

#### 生成 L2/L3-ready 配置骨架

```bash
export CS_LLM_API_KEY = sk-...
clawsentry config wizard --non-interactive \
  --framework codex \
  --mode strict \
  --llm-provider openai \
  --llm-model gpt-4o-mini \
  --l2 --l3 \
  --token-budget 200000 \
  --write-project-config
clawsentry config show --effective
clawsentry test-llm --json
```

如果你只想先观察 Gateway / Web UI，不调用外部 provider：

```bash
clawsentry config wizard --non-interactive \
  --framework codex \
  --mode normal \
  --llm-provider none \
  --write-project-config
```

#### 初始化配置

```bash
clawsentry config init --preset high
```

??? example "终端输出"
    ```
    Created .clawsentry.env.example (preset: high)
    ```

#### 查看当前配置

```bash
clawsentry config show --effective
```

??? example "终端输出"
    ```
      project.mode: normal (source: project)
      llm.provider: openai (source: env)
      llm.api_key: ******** (source: env)
      budgets.llm_token_budget_enabled: true (source: project)
      budgets.llm_daily_token_budget: 200000 (source: project)
      budgets.llm_token_budget_scope: total (source: project)
      defer.timeout_s: 86400 (source: default)
    ```

#### 更改预设等级

```bash
clawsentry config set strict
```

#### 临时禁用 / 启用

```bash
clawsentry config disable
clawsentry config enable
```

### dotenv 模板格式

`clawsentry config init` / `config wizard` 写入的是 dotenv `KEY=VALUE` 模板。它不会自动生效；请显式 `--env-file`。

```bash title=".clawsentry.env.example"
CS_FRAMEWORK=codex
CS_ENABLED_FRAMEWORKS=codex
CS_MODE=normal
CS_PRESET=high
CS_LLM_TOKEN_BUDGET_ENABLED=false
CS_L2_TIMEOUT_MS=60000
CS_L3_TIMEOUT_MS=300000
CS_HARD_TIMEOUT_MS=600000
CS_DEFER_TIMEOUT_S=86400
CS_DEFER_TIMEOUT_ACTION=block
```

密钥和本机 runtime 值仍应通过进程/部署环境或显式 `.clawsentry.env.local` 注入。更多可复制片段见 [配置模板](../configuration/templates.md)。

---

## clawsentry benchmark

管理显式 benchmark/autonomous 模式。该模式面向 CI 和安全评测：不会等待人工 DEFER，不会修改真实 `~/.codex`，除非人工显式传入 `--force-user-home`。完整说明见 [Benchmark 模式](../operations/benchmark-mode.md)。

### 语法

```bash
clawsentry benchmark env --framework codex --mode guarded > .clawsentry.benchmark.env
clawsentry benchmark enable --dir . --framework codex --codex-home /tmp/cs-codex-home
clawsentry benchmark run --framework codex --codex-home /tmp/cs-codex-home -- <command>
clawsentry benchmark disable --dir . --framework codex --codex-home /tmp/cs-codex-home
```

### 安全规则

- `run` 默认使用临时配置并清理，`--keep-artifacts` 才保留证据。
- 自动化测试必须传入临时 `--codex-home`。
- would-DEFER 默认转换为 `block`，并写入 `auto_resolved=true`、`original_verdict=defer` 等 metadata。


## clawsentry rules

`clawsentry rules` 是规则治理入口，用于检查和预演当前 YAML 规则面。它刻意保持为窄范围治理层：管理的是 attack patterns / evolved patterns / review skills 这些规则资产，而不是跨 L1/L2/L3 的统一运行时策略语言。

### 语法

```bash
clawsentry rules lint [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
clawsentry rules dry-run --events FILE [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
clawsentry rules report --output FILE [--events FILE] [--summary-markdown FILE] [--attack-patterns PATH] [--evolved-patterns PATH] [--skills-dir DIR] [--json]
```

### 子命令

| 子命令 | 说明 |
|--------|------|
| `lint` | 加载当前规则资产，输出 schema / duplicate / conflict / source 问题 |
| `dry-run` | 用 sample canonical events 预演 pattern 命中与 skill 选择结果 |
| `report` | 写入组合 JSON 工件和可选 markdown dashboard，便于 CI / release checklist 保存治理证据 |

### 输入与输出

- `lint` 默认读取内置 `attack_patterns.yaml` 与 `skills/`，可额外叠加 `--evolved-patterns` 和 `--skills-dir`
- `dry-run --events` 接受三种输入：单个 JSON object、JSON array、JSONL
- `report --output` 会把 lint 结果与可选 dry-run 结果写成稳定 JSON 工件；加 `--summary-markdown` 时会额外写出人类可读 rollout dashboard；加 `--json` 时也会输出到 stdout
- `--json` 会返回 machine-readable 报告，包含 `fingerprint`、`source_summaries`、`version_summary`、`findings`

### 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 无 findings / 输入有效 |
| `1` | 存在规则治理 findings |
| `2` | CLI 调用错误或输入文件错误 |

### 示例

```bash
clawsentry rules lint --json
clawsentry rules dry-run --events examples/sample-events.jsonl --json
clawsentry rules report --output artifacts/rules-report.json --events examples/sample-events.jsonl --summary-markdown artifacts/rules-dashboard.md
clawsentry rules dry-run --events my-events.json --skills-dir /etc/clawsentry/skills
```

!!! tip "和 L3 自定义 Skill 的关系"
    `clawsentry rules` 不会替换 L3 的运行时选择逻辑；它只是帮助你在 rollout 之前确认当前 YAML 规则面是否可加载、是否有冲突，以及 sample events 在当前规则面上会命中什么。

更多 authoring 细节见：[规则治理](../advanced/rule-governance.md)。

---

## clawsentry skill-trust

扫描本地 skill 包、写入 Skill Trust registry，并生成 Gateway-owned runtime metadata。该命令面向 Codex/Claude Code 等 skill 包供应链治理：它登记 identity/provenance/hash 证据，让 Gateway 在 `pre_action` 中按 profile 对首次使用或不可信 skill 执行 audit、L2/L3、DEFER 或 BLOCK。完整机制见 [Skill Trust / Registry](../advanced/skill-trust.md)。

### 语法

```bash
clawsentry skill-trust scan --skill-root PATH [--output FILE] [--json]
clawsentry skill-trust register --skill-root PATH --registry FILE [--framework codex] [--scope workspace] [--list-state auto|allowlist|greylist|blacklist] [--operator-override ID] [--json]
clawsentry skill-trust register-dir --skills-dir DIR --registry FILE --metadata FILE [--framework codex] [--scope workspace] [--json]
```

### 子命令

| 子命令 | 说明 |
|---|---|
| `scan` | 对单个 skill root 做 deterministic admission scan，不写 registry |
| `register` | 扫描单个 skill root，并写入 registry transition event |
| `register-dir` | 扫描目录下的 skill 包，生成 registry 与 runtime metadata |

### 示例

```bash
clawsentry skill-trust register-dir \
  --skills-dir ~/.codex/skills \
  --registry .clawsentry/skill-trust-registry.json \
  --metadata .clawsentry/skill-trust-runtime.json \
  --framework codex \
  --scope workspace \
  --json
```

运行时启用：

```bash
CS_SKILL_TRUST_REGISTRY_PATH=.clawsentry/skill-trust-registry.json
CS_SKILL_TRUST_METADATA_PATH=.clawsentry/skill-trust-runtime.json
CS_SKILL_TRUST_FIRST_USE_STRICT_ACTION=defer
```

---

## clawsentry integrations

查看当前项目中已启用的框架集成状态。

### 语法

```bash
clawsentry integrations status [--dir PATH] [--env-file PATH] [--json]
```

### 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--dir PATH` | `.`（当前目录） | 包含 `.clawsentry.env.example` 的项目目录 |
| `--env-file PATH` | 空 | 显式本机 env file，用于 readiness 检查，不自动发现 `.env.clawsentry` |
| `--json` | `false` | 输出 JSON，便于脚本或 CI 检查 |

### 示例

```bash
clawsentry integrations status
```

??? example "终端输出"
    ```
    ClawSentry Integrations
    ============================================================
    Project config: .clawsentry.env.example
    Explicit env file: none
    Enabled frameworks: openclaw, codex, claude-code
    Default framework: openclaw
    Codex watcher: enabled
    OpenClaw env: configured
    OpenClaw restore: available
    OpenClaw restore files: /home/user/.openclaw/openclaw.json.bak
    a3s transport env: not configured
    Claude hooks: not present
    Claude hooks files: (none)
    Codex session dir: /home/user/.codex/sessions (reachable)
    Framework readiness:
    openclaw: ready | project env and host approval files are aligned
      next step: No action required.
    codex: ready | watcher enabled and session directory is reachable
      next step: No action required.
    claude-code: needs attention | host hooks are missing, so Claude Code can bypass ClawSentry
      next step: Run clawsentry init claude-code to reinstall the required Claude hooks.
    ============================================================
    ```

`--json` 输出包含适合脚本消费的诊断字段，例如：

- `framework_readiness.<framework>.status / summary / checks / warnings / next_step`
- `openclaw_restore_available` / `openclaw_restore_files`
- `claude_code_hook_files`
- `codex_session_dir` / `codex_session_dir_reachable`

---

## clawsentry latch

管理 Latch 集成（下载安装、启停、状态查看）。Latch 提供跨设备手机监控、推送审批等增强功能。

### 语法

```bash
clawsentry latch <subcommand> [options]
```

### 子命令

| 子命令 | 说明 |
|--------|------|
| `install` | 下载并安装 Latch 二进制文件 |
| `start` | 启动 Gateway + Latch Hub |
| `stop` | 停止 Gateway + Latch Hub |
| `status` | 查看 Latch 栈运行状态 |
| `uninstall` | 卸载 Latch 二进制和数据 |

### `latch install` 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--no-shortcut` | `false` | 跳过桌面快捷方式创建 |

安装流程：

1. 从 GitHub Release 下载对应平台的 Latch 二进制压缩包
2. SHA-256 校验文件完整性
3. 解压到 `~/.clawsentry/latch/bin/`（支持 `tar.gz` 和 `zip`）
4. 设置可执行权限
5. 创建桌面快捷方式（可通过 `--no-shortcut` 跳过）

支持平台：Linux (x86_64, aarch64)、macOS (x86_64, arm64)、Windows (x86_64)

### `latch start` 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--gateway-port` | `8080` 或 `CS_HTTP_PORT` | Gateway HTTP 端口 |
| `--hub-port` | `3006` | Latch Hub 端口 |
| `--no-browser` | `false` | 启动后不自动打开浏览器 |

### `latch stop`

停止 Gateway 和 Latch Hub 进程。

```bash
clawsentry latch stop
```

### `latch status`

查看 Gateway 和 Latch Hub 的运行状态。

```bash
clawsentry latch status
```

### `latch uninstall` 选项

| 选项 | 默认值 | 说明 |
|------|--------|------|
| `--keep-data` | `false` | 仅移除二进制和快捷方式，保留数据目录 |

### 示例

#### 安装 Latch

```bash
clawsentry latch install
```

??? example "终端输出"
    ```
    Downloading Latch v1.0.0 for linux-x86_64...
    Verifying SHA-256 checksum... OK
    Extracting to ~/.clawsentry/latch/bin/
    Latch installed successfully.
    ```

#### 启动完整栈

```bash
clawsentry latch start --hub-port 3006
```

??? example "终端输出"
    ```
    Starting Gateway on 127.0.0.1:8080...
    Starting Latch Hub on 127.0.0.1:3006...
    Gateway + Latch Hub ready.
    ```

#### 查看状态

```bash
clawsentry latch status
```

#### 卸载（保留数据）

```bash
clawsentry latch uninstall --keep-data
```

---

## 独立入口点

以下命令由 `pip install clawsentry` 注册为独立可执行文件，无需使用 `clawsentry` 前缀：

| 命令 | 等价于 | 入口模块 |
|------|--------|----------|
| `clawsentry-gateway` | `clawsentry gateway` | `clawsentry.gateway.server:main` |
| `clawsentry-harness` | `clawsentry harness` | `clawsentry.adapters.a3s_gateway_harness:main` |
| `clawsentry-stack` | `clawsentry stack` | `clawsentry.gateway.stack:main` |

!!! tip "何时使用独立入口"
    在 a3s-code SDK 代码中显式指定 `clawsentry-harness` 作为 `StdioTransport` 程序路径：
    ```python
    from a3s_code import Agent, SessionOptions, StdioTransport

    agent = Agent.create("agent.hcl")
    opts = SessionOptions()
    opts.ahp_transport = StdioTransport(program="clawsentry-harness", args=[])
    session = agent.session(".", opts, permissive=True)
    ```

---

## 环境变量速查

以下环境变量影响 CLI 行为。完整列表参见 [环境变量配置](../configuration/env-vars.md)。

| 变量 | 影响的命令 | 说明 |
|------|-----------|------|
| `CS_AUTH_TOKEN` | gateway, watch | HTTP API 认证令牌 |
| `CS_HTTP_HOST` | gateway | HTTP 监听地址 |
| `CS_HTTP_PORT` | gateway, watch | HTTP 监听端口 |
| `CS_UDS_PATH` | gateway, harness | UDS Socket 路径 |
| `CS_TRAJECTORY_DB_PATH` | gateway | 轨迹数据库路径 |
| `CS_RATE_LIMIT_PER_MINUTE` | gateway | 每 IP 每分钟请求限额 |
| `OPENCLAW_WEBHOOK_TOKEN` | gateway | OpenClaw Webhook 令牌 |
| `OPENCLAW_ENFORCEMENT_ENABLED` | gateway | 启用 OpenClaw WS 强制执行 |
| `OPENCLAW_OPERATOR_TOKEN` | gateway | OpenClaw WS 操作令牌 |
| `OPENCLAW_WS_URL` | gateway | OpenClaw WebSocket URL |
| `AHP_SESSION_ENFORCEMENT_ENABLED` | gateway | 启用会话级强制策略 |
| `AHP_SSL_CERTFILE` | gateway | SSL 证书文件路径 |
| `AHP_SSL_KEYFILE` | gateway | SSL 私钥文件路径 |
| `CS_FRAMEWORK` | start, gateway, harness | 默认 framework 名称，如 `codex` |
| `CS_CODEX_SESSION_DIR` | gateway | Codex 会话目录路径（用于 Session Watcher） |
| `CS_DEFER_TIMEOUT_ACTION` | gateway, harness | DEFER 超时后的动作：`block`（默认）或 `allow` |
| `CS_DEFER_TIMEOUT_S` | gateway, harness | normal mode DEFER 软超时（秒），默认 `86400`；benchmark mode 不等待 |
| `CS_LLM_TOKEN_BUDGET_ENABLED` | gateway | 是否启用基于真实 provider usage 的 token 预算 |
| `CS_LLM_DAILY_TOKEN_BUDGET` | gateway | 每日 token 上限，启用时必须大于 `0` |
| `CS_LLM_DAILY_BUDGET_USD` | gateway | 旧版兼容字段；仅迁移/估算提示，不推荐执法 |
| `CS_METRICS_ENABLED` | gateway | 启用 Prometheus `/metrics` 端点 |
| `CS_LATCH_HUB_URL` | gateway, doctor | Latch Hub 地址（如 `http://127.0.0.1:3006`） |
| `CS_ENABLED_FRAMEWORKS` | start, gateway, harness | 逗号分隔的启用 framework 列表，如 `a3s-code,codex` |


### Kimi CLI managed hooks

```bash
clawsentry init kimi-cli
clawsentry init kimi-cli --setup --dry-run
clawsentry init kimi-cli --setup
clawsentry init kimi-cli --uninstall
```

`--setup` writes marker-managed `[[hooks]]` blocks to `$KIMI_SHARE_DIR/config.toml` or `~/.kimi/config.toml`; use `--kimi-home <dir>` to target an isolated config directory. Non-ClawSentry Kimi hooks are preserved.
