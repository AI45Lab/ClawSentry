---
title: 故障排查
description: ClawSentry 常见问题诊断与解决方案
---

<section class="cs-doc-hero cs-doc-hero--ops" markdown>
<div class="cs-eyebrow">ClawSentry 运维</div>
## 故障排查
常见问题诊断与解决方案，覆盖启动错误、连接失败和 hook 集成问题。
<div class="cs-actions" markdown>
[生产部署](deployment.md){ .md-button .md-button--primary }
[Benchmark 模式](benchmark-mode.md){ .md-button }
[CLI 命令](../cli/index.md){ .md-button }
</div>
</section>

本页列出 ClawSentry 运行中常见的问题、诊断步骤和解决方案。每个问题以可折叠卡片呈现，点击展开查看详情。

---

## 启动与连接

??? question "Gateway 无法启动：端口冲突"

    **症状**：启动时报错 `Address already in use` 或 `OSError: [Errno 98]`

    **诊断**：
    ```bash
    # 检查端口占用
    lsof -i :8080
    # 或
    ss -tlnp | grep 8080
    ```

    **解决方案**：

    1. **停止占用端口的进程**：
       ```bash
       kill <PID>
       ```

    2. **更换端口**：
       ```bash
       export CS_HTTP_PORT=9090
       clawsentry gateway
       ```

    3. **如果是残留的 ClawSentry 进程**：
       ```bash
       pkill -f "clawsentry gateway"
       ```

??? question "Gateway 无法启动：UDS 路径问题"

    **症状**：启动时报错 `Address already in use` 但端口未被占用，或 `PermissionError`

    **诊断**：
    ```bash
    # 检查 UDS 文件是否存在
    ls -la /tmp/clawsentry.sock

    # 检查文件权限
    stat /tmp/clawsentry.sock
    ```

    **解决方案**：

    1. **删除残留的 UDS 文件**（上次 Gateway 非正常退出时可能残留）：
       ```bash
       rm -f /tmp/clawsentry.sock
       ```

    2. **更换 UDS 路径**：
       ```bash
       export CS_UDS_PATH=/tmp/my-clawsentry.sock
       clawsentry gateway
       ```

    3. **检查目录权限**（如果使用自定义路径）：
       ```bash
       # 确保目录存在且可写
       mkdir -p /run/clawsentry
       chmod 755 /run/clawsentry
       ```

??? question "Gateway 无法启动：缺少依赖"

    **症状**：`ModuleNotFoundError: No module named 'fastapi'` 或类似错误

    **诊断**：
    ```bash
    pip show clawsentry
    pip show fastapi uvicorn
    ```

    **解决方案**：

    ```bash
    # 重新安装（含所有依赖）
    pip install "clawsentry[llm,dev]"

    # 或仅安装核心依赖
    pip install clawsentry
    ```

    如果使用虚拟环境，确保已激活：
    ```bash
    # conda 环境
    conda activate a3s_code

    # venv 环境
    source /path/to/venv/bin/activate
    ```

---

## 配置来源与 env-file

??? question "`.clawsentry.env.local` / `.env.clawsentry` 中的配置没有生效"

    **症状**：`CS_AUTH_TOKEN` 为空、LLM provider 未加载、端口/预算仍是默认值，或 `config show --effective` 显示来源不是你预期的文件。

    **诊断**：
    ```bash
    clawsentry config show --effective --env-file .clawsentry.env.local
    clawsentry config show --effective --env-file .env.clawsentry  # 仅迁移旧文件时使用
    ```

    **原因**：

    1. 没有自动发现的 ClawSentry env file；`.clawsentry.env.example` 也必须显式传入。
    2. `.clawsentry.env.local` 和旧 `.env.clawsentry` 都不会自动加载；必须显式 `--env-file PATH` 或设置 `CLAWSENTRY_ENV_FILE=PATH`。
    3. 进程/部署环境变量优先于 env-file；如果 shell 已经 export 同名 `CS_*`，文件中的值不会覆盖它。
    4. `CS_FRAMEWORK` / `CS_ENABLED_FRAMEWORKS` 只用于旧脚本迁移，框架启用请看 `CS_FRAMEWORK / CS_ENABLED_FRAMEWORKS`。

    **解决方案**：
    ```bash
    clawsentry start --env-file .clawsentry.env.local
    clawsentry test-llm --env-file .clawsentry.env.local --json
    clawsentry doctor --env-file .clawsentry.env.local
    ```

    如果只是本地体验且未设置 `CS_AUTH_TOKEN`，`clawsentry start` 会生成仅本次进程内有效的临时 token，并在启动 banner / Web UI URL 中展示；它不会写入 env file。

---

## 认证问题

??? question "认证失败：401 Unauthorized"

    **症状**：API 请求返回 `401 Unauthorized`，Web 仪表板登录失败

    **诊断**：
    ```bash
    # 检查 CS_AUTH_TOKEN 是否设置
    echo $CS_AUTH_TOKEN

    # 测试认证
    curl -v -H "Authorization: Bearer $CS_AUTH_TOKEN" http://localhost:8080/health
    ```

    **解决方案**：

    1. **Token 不匹配**：确保客户端使用的 Token 与 Gateway 环境变量中的完全一致（注意空格和换行符）
       ```bash
       # 检查是否有隐藏字符
       echo -n "$CS_AUTH_TOKEN" | xxd | head
       ```

    2. **Token 未设置**：如果 `CS_AUTH_TOKEN` 为空，Gateway 不进行认证检查。一旦设置了非空值，所有请求必须携带 Token

    3. **Header 格式错误**：必须是 `Authorization: Bearer <token>`，注意 `Bearer` 后有一个空格

    4. **Web 仪表板登录失败**：
       - 清除浏览器的 `sessionStorage`
       - 确认在登录表单中输入的是完整的 Token 值
       - 如果页面提示 `Gateway unavailable`，先检查 Gateway 是否启动、端口是否正确以及本机代理是否拦截；这不是 bad token
       - 代理环境下为本机 Gateway 设置：`export NO_PROXY=localhost,127.0.0.1,::1`

??? question "SSE 连接认证失败"

    **症状**：SSE 连接返回 401 或立即断开

    **诊断**：
    ```bash
    # 测试 SSE 端点
    curl -N "http://localhost:8080/report/stream?token=$CS_AUTH_TOKEN"
    ```

    **解决方案**：

    SSE 使用 URL Query 参数传递 Token（因为浏览器 `EventSource` API 不支持自定义 Header）：

    ```
    /report/stream?token=<your-token>
    ```

    Web 仪表板会自动从 `sessionStorage` 读取 Token 并附加到 SSE URL。如果 Token 已过期或被清除，需要重新登录。

---

## OpenClaw 连接

??? question "OpenClaw WebSocket 连接失败"

    **症状**：日志显示 `WebSocket connection failed` 或 `Connection refused`

    **诊断**：
    ```bash
    # 检查 OpenClaw Gateway 是否运行
    docker ps | grep openclaw

    # 检查端口是否可达
    curl http://127.0.0.1:18789

    # 检查 WebSocket URL 配置
    echo $OPENCLAW_WS_URL
    ```

    **解决方案**：

    1. **URL 格式**：确保使用 `ws://` 或 `wss://` 前缀
       ```bash
       export OPENCLAW_WS_URL=ws://127.0.0.1:18789
       ```

    2. **Docker 网络**：如果 OpenClaw 在 Docker 中运行，确保使用 `--network host` 或正确的端口映射
       ```bash
       docker run --network host openclaw:local ...
       ```

    3. **防火墙**：检查端口是否被防火墙阻拦
       ```bash
       sudo ufw status
       sudo iptables -L | grep 18789
       ```

??? question "OpenClaw 连接后事件无法接收：scope 问题"

    **症状**：WebSocket 连接成功，但收不到 `exec.approval.requested` 事件

    **诊断**：检查 WebSocket 连接参数。

    **解决方案**：

    这是一个已知的 OpenClaw 行为。ClawSentry 连接 OpenClaw Gateway 时必须使用特定参数：

    | 参数 | 必需值 | 说明 |
    |------|--------|------|
    | `client.id` | `openclaw-control-ui` | 保留完整 scope，否则非 device 连接 scope 会被清空 |
    | `client.mode` | `backend` | 后端模式 |
    | `role` | `operator` | 运维角色 |
    | `Origin` header | 已配置的 origin | 必须匹配 `gateway.controlUi.allowedOrigins` 配置 |

    在 OpenClaw 配置中：
    ```json title="openclaw.json"
    {
      "gateway": {
        "controlUi": {
          "allowedOrigins": ["http://localhost:8080"],
          "dangerouslyDisableDeviceAuth": true
        }
      }
    }
    ```

??? question "OpenClaw sandbox 模式跳过审批"

    **症状**：Agent 执行命令时完全不触发审批流程，日志中无 `exec.approval.requested`

    **诊断**：检查 OpenClaw 的 `tools.exec.host` 配置。

    **解决方案**：

    **必须**将 `tools.exec.host` 设为 `"gateway"`。默认的 `"sandbox"` 模式会跳过所有审批检查：

    ```json title="openclaw.json"
    {
      "tools": {
        "exec": {
          "host": "gateway"
        }
      }
    }
    ```

    可以使用 `clawsentry init openclaw --setup` 自动配置：
    ```bash
    clawsentry init openclaw --setup --dry-run  # 预览变更
    clawsentry init openclaw --setup            # 应用配置
    ```

---

## LLM 问题

??? question "LLM 调用失败：API Key 缺失"

    **症状**：日志显示 `CS_LLM_PROVIDER=openai but OPENAI_API_KEY is empty; falling back to rule-based`

    **诊断**：
    ```bash
    echo $CS_LLM_PROVIDER
    echo $OPENAI_API_KEY  # 或 $ANTHROPIC_API_KEY
    ```

    **解决方案**：

    根据选择的提供商设置对应的 API Key：

    === "OpenAI / 兼容 API"
        ```bash
        export CS_LLM_PROVIDER=openai
        export OPENAI_API_KEY = <openai-api-key>
        # 如果使用兼容 API（如 Kimi、DeepSeek）
        export CS_LLM_BASE_URL=https://api.deepseek.com/v1
        export CS_LLM_MODEL=deepseek-chat
        ```

    === "Anthropic"
        ```bash
        export CS_LLM_PROVIDER=anthropic
        export ANTHROPIC_API_KEY=<anthropic-api-key>
        ```

    !!! info "仅 L1 模式"
        如果不设置 `CS_LLM_PROVIDER`，ClawSentry 将只使用 L1 规则引擎和内置的 L2 RuleBasedAnalyzer。这对于大多数场景已经足够。

??? question "LLM 调用超时"

    **症状**：日志显示 `LLM analysis failed; falling back to L1` 且延迟接近 3000ms

    **诊断**：
    ```bash
    # 测试 LLM API 可达性
    curl -w "\n%{time_total}s" "$OPENAI_BASE_URL/models" \
      -H "Authorization: Bearer $OPENAI_API_KEY"
    ```

    **解决方案**：

    1. **网络问题**：检查 DNS 解析和网络连接
    2. **代理配置**：如果使用代理，设置 `HTTP_PROXY` / `HTTPS_PROXY`
    3. **提供商限流**：检查 LLM 提供商的速率限制配额
    4. **降级正常**：LLM 超时时 ClawSentry 会自动降级到 L1 等级，这是预期行为（fail-safe）

??? question "LLM 返回解析失败"

    **症状**：日志显示 `LLM response parse failed; falling back to L1`

    **解决方案**：

    这通常发生在：

    1. **模型不遵循 JSON 输出格式** -- 尝试更换模型（推荐 GPT-4 或 Claude 3）
    2. **temperature 设置过高** -- ClawSentry 默认使用 `temperature=0.0`，确保未被覆盖
    3. **max_tokens 不足** -- 默认 256 tokens，如果响应被截断可能导致 JSON 不完整

    降级行为是安全的：L2 LLM 分析失败时，决策回退到 L1 规则引擎的结果。

---

## SSE 与实时推送

??? question "SSE 连接频繁断开"

    **症状**：Web 仪表板数据更新不及时，控制台显示 `EventSource` 连接错误

    **诊断**：
    ```bash
    # 直接测试 SSE 连接
    curl -N "http://localhost:8080/report/stream?token=$CS_AUTH_TOKEN"
    ```

    **解决方案**：

    1. **网络不稳定**：SSE 基于 HTTP 长连接，网络抖动会导致断开。浏览器的 `EventSource` API 有自动重连机制

    2. **反向代理超时**：如果通过 Nginx 等反向代理，配置超长超时：
       ```nginx
       proxy_read_timeout 3600s;
       proxy_send_timeout 3600s;
       proxy_buffering off;
       ```

    3. **认证 Token 过期**：重新登录 Web 仪表板获取新 Token

    4. **浏览器限制**：浏览器对同一域名的 SSE 连接数有限制（通常 6 个）。避免打开过多标签页

??? question "clawsentry watch 无法连接"

    **症状**：`clawsentry watch` 命令无输出或报错 `Connection refused`

    **诊断**：
    ```bash
    # 检查 Gateway 端口
    curl http://localhost:8080/health
    ```

    **解决方案**：

    1. **端口不匹配**：`clawsentry watch` 默认连接 `localhost:8080`。如果 Gateway 使用了自定义端口：
       ```bash
       clawsentry watch --gateway-url http://127.0.0.1:9090
       ```

    2. **Gateway 未启动**：先启动 Gateway
       ```bash
       clawsentry gateway &
       clawsentry watch
       ```

    3. **认证问题**：如果 Gateway 启用了认证，watch 需要通过环境变量获取 Token：
       ```bash
       export CS_AUTH_TOKEN = your-token
       clawsentry watch
       ```

??? question "已启用自进化模式库，但一直看不到候选模式或确认结果"

    **症状**：已经设置 `CS_EVOLVING_ENABLED=true`，但 `clawsentry watch`、SSE 或 `/ahp/patterns` 看不到 `pattern_candidate` / `pattern_evolved` 事件，列表也始终为空。

    **诊断**：
    ```bash
    echo $CS_EVOLVING_ENABLED
    echo $CS_EVOLVED_PATTERNS_PATH

    curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
      http://127.0.0.1:8080/ahp/patterns

    curl -N -H "Authorization: Bearer $CS_AUTH_TOKEN" \
      "http://127.0.0.1:8080/report/stream?types=pattern_candidate,pattern_evolved"
    ```

    **解决方案**：

    1. **先看 `/ahp/patterns` 顶层状态字段**：
       - `enabled=false`：说明 Gateway 当前并未启用自进化模式库。
       - `store_path=""`：说明没有配置持久化路径。
       - `count=0` 且 `candidate_count=0`：说明还没有候选模式被成功提取。

    2. **确认功能确实已启用且可持久化**：
       ```bash
       export CS_EVOLVING_ENABLED=true
       export CS_EVOLVED_PATTERNS_PATH=/var/lib/clawsentry/evolved_patterns.yaml
       ```
       `CS_EVOLVED_PATTERNS_PATH` 所在目录必须对 Gateway 进程可写；否则候选模式无法落盘。

    3. **确认触发条件满足**：
       只有在自进化已启用时，且事件被判为 `high` / `critical`，Gateway 才会提取候选模式并广播 `pattern_candidate`。普通 `low` / `medium` 事件不会触发。

    4. **区分“候选已提取”和“模式已确认”**：
       - `pattern_candidate`：说明刚刚提取出候选模式。
       - `pattern_evolved`：说明有人通过 `POST /ahp/patterns/confirm` 提交了确认/误报反馈，状态发生了生命周期变化。

    5. **手动确认反馈链路**：
       ```bash
       curl -X POST http://127.0.0.1:8080/ahp/patterns/confirm \
         -H "Authorization: Bearer $CS_AUTH_TOKEN" \
         -H "Content-Type: application/json" \
         -d '{"pattern_id":"EV-XXXXXXXX","confirmed":true}'
       ```
       成功后应看到 `pattern_evolved` 事件，同时 `/ahp/patterns` 中对应模式的 `status`、`confirmed_count`、`candidate_count` / `active_count` 会变化。

---

## DEFER 与审批

??? question "DEFER 决策超时无人处理"

    **症状**：DEFER 决策在倒计时结束后自动过期，Agent 操作被拒绝

    **诊断**：确认是否有运维人员在监控 DEFER 决策。

    **解决方案**：

    1. **启动交互式 watch**：
       ```bash
       clawsentry watch --interactive
       ```
       运维人员可以实时看到 DEFER 决策并按 `[A]llow / [D]eny / [S]kip` 响应

    2. **使用 Web 仪表板**：
       打开 `http://localhost:8080/ui` 的 DEFER Panel 页面

    3. **调整策略减少 DEFER**：
       如果 DEFER 过多，考虑调整 L1 规则阈值或 L2 策略，将确定性高的事件直接 ALLOW 或 BLOCK

    4. **配置会话执法策略**：
       通过 `AHP_SESSION_ENFORCEMENT_*` 环境变量，在累积多次高危事件后自动 BLOCK，减少对人工审批的依赖

??? question "DEFER Panel 显示 503 降级提示"

    **症状**：Web 仪表板 DEFER Panel 显示 "Resolve not available -- OpenClaw enforcement is not connected"

    **诊断**：
    ```bash
    # 检查 OpenClaw 连接状态
    curl http://localhost:8080/health
    ```

    **解决方案**：

    此提示表示 Gateway 无法将 allow/deny 决策回传给 OpenClaw Gateway。原因可能是：

    1. **OpenClaw 未连接**：检查 `OPENCLAW_WS_URL` 和 `OPENCLAW_OPERATOR_TOKEN` 配置
    2. **OpenClaw 已断开**：检查 OpenClaw Gateway 是否仍在运行
    3. **仅使用 a3s-code**：a3s-code 的审批机制通过显式 SDK Transport（stdio 或 HTTP）接入 ClawSentry，不需要 OpenClaw 连接。此提示可以忽略

    !!! info "DEFER 仍然可以查看"
        即使无法 resolve，运维人员仍可以在 DEFER Panel 中查看决策详情，了解 Agent 的操作请求。

---

## Claude Code 集成

??? question "Claude Code hook 未被触发"

    **症状**：ClawSentry 运行正常，但执行 Claude Code 操作时 Gateway 无事件进入

    **诊断**：
    ```bash
    # 检查 hooks 配置
    cat ~/.claude/settings.json | python3 -m json.tool
    # 查看 harness 入口
    which clawsentry-harness
    ```

    **解决方案**：

    1. **重新初始化**：
       ```bash
       clawsentry init claude-code
       ```
       此命令自动写入 `~/.claude/settings.json` 的 `hooks` 配置。

    2. **手动检查 hooks 结构**：确认 `settings.json` 包含以下字段：
       ```json
       {
         "hooks": {
           "PreToolUse": [{"type": "command", "command": "clawsentry-harness"}],
           "PostToolUse": [{"type": "command", "command": "clawsentry-harness --async"}]
         }
       }
       ```

    3. **harness 路径错误**：如果 Python 环境不在 PATH 中：
       ```bash
       # 使用绝对路径
       which clawsentry-harness  # 获取完整路径
       # 然后在 settings.json 中填入完整路径
       ```

??? question "clawsentry-harness 每次调用都返回非零退出码"

    **症状**：Claude Code 执行操作时报错 `hook exited with non-zero status`

    **诊断**：
    ```bash
    # 手动测试 harness（模拟 Claude Code hook 调用）
    echo '{"hook_event_name":"PreToolUse","tool_name":"bash","tool_input":{"command":"ls"}}' | \
      CS_AUTH_TOKEN = $CS_AUTH_TOKEN clawsentry-harness
    ```

    **解决方案**：

    1. **Gateway 未运行**：先启动 Gateway
       ```bash
       clawsentry start --framework claude-code
       ```

    2. **Auth Token 不匹配**：确保进程环境或显式 `--env-file` 中的 `CS_AUTH_TOKEN` 与 Gateway 使用的一致；若未设置 token，请复制本次 `start` banner 打印的 URL/token
       ```bash
       clawsentry doctor
       ```

    3. **harness 降级模式**：harness 默认在无法连接 Gateway 时降级为 `ALLOW`（不退出非零码）。若仍失败，检查 Python 环境

??? question "DEFER 超时后 Agent 操作被意外放行"

    **症状**：DEFER 决策超时未审批，但 Agent 操作仍被执行（未被拒绝）

    **诊断**：
    ```bash
    echo $CS_DEFER_TIMEOUT_ACTION
    ```

    **解决方案**：

    将 `CS_DEFER_TIMEOUT_ACTION` 设置为 `block`（默认值即为 `block`）：
    ```bash
    export CS_DEFER_TIMEOUT_ACTION=block
    ```
    若设为 `allow`，超时后会自动放行——仅在本地测试场景下使用此设置。

---

## Codex Session Watcher

??? question "Codex 操作未被监控"

    **症状**：Codex Agent 执行命令时 Gateway 无事件，`clawsentry watch` 无输出

    **诊断**：
    ```bash
    # 检查 Codex session 目录
    ls ~/.codex/sessions/
    echo $CS_CODEX_SESSION_DIR
    echo $CS_CODEX_WATCH_ENABLED
    ```

    **解决方案**：

    1. **重新初始化 Codex 集成**：
       ```bash
       clawsentry init codex
       ```
       自动检测 Codex 安装路径；如果 session 目录尚不存在，会写入 `CS_CODEX_WATCH_ENABLED=true`，让 Gateway 后续从 `$CODEX_HOME/sessions` 自动探测。

    2. **手动指定 session 目录**：
       ```bash
       export CS_CODEX_SESSION_DIR=~/.codex/sessions
       clawsentry start
       ```

    3. **Watcher 未启用自动探测**：如果没有显式设置 `CS_CODEX_SESSION_DIR`，确认 `CS_CODEX_WATCH_ENABLED=true`

??? question "Codex Session Watcher 日志显示 'session dir does not exist'"

    **症状**：Gateway 启动时日志警告 `CS_CODEX_SESSION_DIR=... does not exist`

    **解决方案**：

    1. 确认 Codex 已安装且已运行过至少一次（首次运行才会创建 sessions 目录）
    2. 手动创建目录并重启：
       ```bash
       mkdir -p ~/.codex/sessions
       clawsentry start
       ```

---

## Latch Hub 与 DEFER Bridge

??? question "Latch Hub 无法连接"

    **症状**：`clawsentry doctor` 的 `LATCH_HUB_HEALTH` 检查失败，或 `clawsentry latch status` 显示 Hub 已停止

    **诊断**：
    ```bash
    curl http://127.0.0.1:3006/health
    clawsentry latch status
    cat ~/.clawsentry/run/latch-hub.log
    ```

    **解决方案**：

    1. **Hub 未启动**：
       ```bash
       clawsentry latch start
       ```

    2. **端口冲突**：
       ```bash
       lsof -i :3006
       export CS_LATCH_HUB_PORT=3007
       clawsentry latch start
       ```

    3. **Latch 二进制未安装**：
       ```bash
       clawsentry latch install
       ```

??? question "DEFER Bridge 已启用但 Hub 未收到推送"

    **症状**：`CS_DEFER_BRIDGE_ENABLED=true` 且 Hub 运行正常，但手机/Web PWA 未收到 DEFER 推送通知

    **诊断**：
    ```bash
    clawsentry doctor  # 检查 LATCH_TOKEN_SYNC
    curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
      http://127.0.0.1:8080/events  # 确认 SSE 流正常
    ```

    **解决方案**：

    1. **Token 不匹配**：Hub 的 `CLI_API_TOKEN` 必须与 Gateway 的 `CS_AUTH_TOKEN` 一致。运行 `clawsentry doctor` 查看 `LATCH_TOKEN_SYNC` 检查结果

    2. **HubBridge 未启用**：
       ```bash
       export CS_HUB_BRIDGE_ENABLED=true
       # 重启 Gateway
       clawsentry stop && clawsentry start --with-latch
       ```

    3. **Hub URL 配置错误**：确认 `CS_LATCH_HUB_URL=http://127.0.0.1:3006`（默认）或自定义端口

    4. **Bridge 在 `auto` 模式下未自动启用**：
       如果 Hub 启动后才检测到，Bridge 可能在 Gateway 启动时未自动连接，尝试：
       ```bash
       export CS_HUB_BRIDGE_ENABLED=true
       ```
       而非 `auto`。

??? question "clawsentry doctor 的 LATCH_TOKEN_SYNC 失败"

    **症状**：doctor 输出 `LATCH_TOKEN_SYNC: FAIL — CS_AUTH_TOKEN does not match Hub CLI_API_TOKEN`

    **解决方案**：

    重新同步 Token（ClawSentry 安装时会自动完成此步骤，但手动修改 Token 后需要重新同步）：

    ```bash
    # 更新 .clawsentry/run/latch-hub.env 或重新安装
    clawsentry latch uninstall --keep-data
    clawsentry latch install
    ```

    或手动在 Latch Hub 配置文件中将 `CLI_API_TOKEN` 设置为与 `CS_AUTH_TOKEN` 相同的值。

---

## 误报与策略调优

??? question "高误报率：安全操作被标记为高风险"

    **症状**：正常的开发操作频繁触发 BLOCK 或 DEFER

    **解决方案**：

    1. **查看决策原因**：通过 `clawsentry watch` 或 Web 仪表板查看每个决策的具体原因（D1-D5 评分和 short_circuit 规则）

    2. **理解 D1-D5 评分**：

        | 维度 | 含义 | 调优方向 |
        |------|------|----------|
        | D1 | 工具危险性 | 如果特定工具被高估，检查 `DANGEROUS_TOOLS` 列表 |
        | D2 | 目标路径敏感度 | 工作目录中的 `.env` 等可能触发 |
        | D3 | 命令模式 | `rm`、`sudo` 等关键词触发 |
        | D4 | 会话累积风险 | 高危事件会累积，降低后续阈值 |
        | D5 | Agent 信任等级 | 默认为 untrusted |

    3. **调整 Agent 信任等级**：通过 `DecisionContext.agent_trust_level` 提升受信 Agent 的信任等级

    4. **参考[策略调优指南](../configuration/policy-tuning.md)**

??? question "低报率：危险操作未被拦截"

    **症状**：已知的危险命令（如 `rm -rf /`）未被 BLOCK

    **诊断**：
    ```bash
    # 查看决策日志
    clawsentry watch --json
    ```

    **解决方案**：

    1. **检查事件类型**：只有 `pre_action` 类型的事件会产生 BLOCK 决策。`post_action` 等观察型事件始终 ALLOW
    2. **检查 risk_hints**：Adapter 是否正确提取了 risk_hints
    3. **启用 L2 分析**：配置 `CS_LLM_PROVIDER` 启用 LLM 语义分析
    4. **启用会话执法**：
       ```bash
       export AHP_SESSION_ENFORCEMENT_ENABLED=true
       export AHP_SESSION_ENFORCEMENT_THRESHOLD=3
       export AHP_SESSION_ENFORCEMENT_ACTION=block
       ```

---

## 性能问题

??? question "响应延迟高"

    **症状**：决策延迟 > 100ms（L1）或 > 5s（L2/L3）

    **诊断**：
    ```bash
    # 查看决策延迟
    clawsentry watch --json | jq '.decision_latency_ms'
    ```

    **解决方案**：

    1. **L1 延迟高 (> 10ms)**：
       - 检查 SQLite 写入性能（可能磁盘 I/O 瓶颈）
       - 将 `CS_TRAJECTORY_DB_PATH` 放在 SSD 上
       - 检查系统负载

    2. **L2 LLM 延迟高 (> 3s)**：
       - LLM API 超时默认 3 秒，超时后降级到 L1
       - 考虑使用更快的 LLM 提供商或本地模型
       - 检查网络延迟

    3. **L3 Agent 延迟高 (> 30s)**：
       - L3 涉及多轮 LLM 调用，延迟取决于工具调用次数
       - L3 永不降级，这是设计决策（安全优先于性能）

??? question "速率限制触发"

    **症状**：API 返回 `RATE_LIMITED` 错误，Agent 操作被延迟

    **诊断**：
    ```bash
    # 查看当前速率限制配置
    echo $CS_RATE_LIMIT_PER_MINUTE
    ```

    **解决方案**：

    1. **提高限制**（如果硬件允许）：
       ```bash
       export CS_RATE_LIMIT_PER_MINUTE=1000
       ```

    2. **检查是否有异常流量**：大量事件可能表示 Agent 行为异常或配置错误

    3. **批量操作优化**：如果 Agent 框架支持，考虑批量发送事件减少请求频率

??? question "SQLite 写入竞争"

    **症状**：日志出现 `database is locked` 错误

    **解决方案**：

    ClawSentry 使用单进程架构，SQLite 写入竞争通常不会发生。如果出现：

    1. **检查是否有多个 Gateway 实例**共用同一个数据库文件
    2. **检查外部工具**是否在读取数据库（如备份脚本未使用 `.backup` 命令）
    3. **升级 SQLite 版本**：确保系统 SQLite >= 3.35（WAL 模式支持）

---

## Web 仪表板

??? question "Web 仪表板无法访问"

    **症状**：浏览器访问 `http://localhost:8080/ui` 返回 404 或空白页

    **诊断**：
    ```bash
    # 检查 UI 文件是否存在
    python -c "from pathlib import Path; p = Path(__import__('clawsentry').__file__).parent / 'ui' / 'dist' / 'index.html'; print(f'{p}: exists={p.exists()}')"
    ```

    **解决方案**：

    1. **UI 文件缺失**：确保安装了包含 UI 的完整包
       ```bash
       pip install --force-reinstall clawsentry
       ```

    2. **路径未挂载**：检查 Gateway 启动日志中是否有 `UI directory mounted` 相关信息

    3. **SPA 路由问题**：直接访问 `/ui` 应该返回 `index.html`。如果通过反向代理，确保 SPA fallback 配置正确

??? question "仪表板图表不显示数据"

    **症状**：仪表板页面加载正常，但图表显示 "No data yet"

    **诊断**：
    ```bash
    # 检查是否有决策数据
    curl -H "Authorization: Bearer $CS_AUTH_TOKEN" \
      http://localhost:8080/report/summary
    ```

    **解决方案**：

    1. **无事件数据**：Gateway 刚启动且没有 Agent 连接时，没有数据是正常的
    2. **时间窗口**：Summary API 默认查询最近一段时间的数据。如果数据已过期，图表为空
    3. **认证问题**：浏览器控制台检查 API 请求是否返回 401

---

## 日志分析

### 关键日志消息

以下是需要关注的关键日志消息及其含义：

| 日志消息 | 级别 | 含义 |
|----------|------|------|
| `Gateway request failed` | ERROR | 事件无法送达 Gateway，正在降级 |
| `Falling back to local decision` | WARNING | 使用本地降级决策 |
| `LLM analysis failed; falling back to L1` | WARNING | L2 LLM 分析失败，回退到 L1 |
| `LLM response parse failed` | WARNING | LLM 返回格式不正确 |
| `Enforcement callback failed` | ERROR | 无法将决策回传到 Agent 框架 |
| `WS approval event received` | INFO | 收到 OpenClaw 审批请求 |
| `Custom skills loaded` | INFO | 自定义 Skills 加载成功 |
| `L3 AgentAnalyzer enabled` | INFO | L3 审查 Agent 初始化成功 |
| `Unknown hook type` | WARNING | 收到无法映射的事件类型 |
| `duplicate skill name` | WARNING | 自定义 Skill 名称与内置冲突 |
| `Codex watcher started` | INFO | Codex Session Watcher 已启动，开始轮询 |
| `CS_CODEX_SESSION_DIR=... does not exist` | WARNING | Codex sessions 目录不存在，Watcher 未启动 |
| `LatchHubBridge: hub not reachable` | WARNING | Hub URL 不可达，Bridge 未自动启用 |
| `LatchHubBridge: token mismatch` | ERROR | CS_AUTH_TOKEN 与 Hub CLI_API_TOKEN 不一致 |
| `DEFER timed out, applying timeout action` | INFO | DEFER 超时，按 CS_DEFER_TIMEOUT_ACTION 处理 |
| `LLM budget exceeded` | WARNING | LLM token budget exhausted；基于 provider 真实 usage 降级/阻断，旧 `CS_LLM_DAILY_BUDGET_USD` 仅兼容提示 |

### 日志级别建议

| 环境 | 建议级别 | 说明 |
|------|----------|------|
| 开发 | `DEBUG` | 查看所有事件处理细节 |
| 测试 | `INFO` | 查看关键操作和配置信息 |
| 生产 | `WARNING` | 只关注异常和降级事件 |

### 增加日志详细度

```bash
# 临时增加日志详细度
export PYTHONPATH_LOG_LEVEL=DEBUG
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
" && clawsentry gateway
```

或在 Python 代码中：

```python
import logging
logging.getLogger("clawsentry").setLevel(logging.DEBUG)
logging.getLogger("a3s-adapter").setLevel(logging.DEBUG)
logging.getLogger("openclaw-adapter").setLevel(logging.DEBUG)
```
