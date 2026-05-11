---
title: 配置概览
description: ClawSentry env-first 配置来源、页面导览、优先级和诊断入口
---

# 配置概览

ClawSentry 当前配置模型是 **env-first**：运行时只消费 `KEY=VALUE` 形式的环境变量、显式 env file、CLI 参数和内置默认值。ClawSentry 不再读取或生成项目级 section 配置。`.clawsentry.env.example` 是可提交的 dotenv 模板，正常启动不会读取它；本机运行时通常先复制成 `.clawsentry.env.local`，再把本机 token / API key / 端口覆盖写进去，并通过 `--env-file` 或 `CLAWSENTRY_ENV_FILE` 显式加载。

```bash
clawsentry config wizard --interactive
clawsentry config show --effective
```

没有 TTY 或需要 CI 可复现时使用确定性参数：

```bash
clawsentry config wizard --non-interactive --framework codex --mode normal --llm-provider none --force
cp .clawsentry.env.example .clawsentry.env.local
clawsentry config show --effective --env-file .clawsentry.env.local
```

`config show --effective` 是排障第一入口：它展示最终生效值、来源标签，并对密钥脱敏。

---

## 先看哪个页面？ {#choose-page}

| 你要做什么 | 应该看 | 不应该从哪里开始 |
|---|---|---|
| 第一次理解配置从哪里来、谁覆盖谁 | 本页 | 环境变量长表 |
| 复制一套可运行配置 | [配置模板](templates.md) | DetectionConfig 详表 |
| 查某个 `CS_*` / `AHP_*` 的默认值和含义 | [环境变量索引](env-vars.md) | 策略调优 |
| 精确理解某个检测字段、校验约束、代码位置 | [DetectionConfig 详表](detection-config.md) | 配置模板 |
| 判断误报/漏报应该调哪些旋钮 | [策略调优方法](policy-tuning.md) | 环境变量索引 |
| 配置 LLM provider、L2/L3 成本和降级语义 | [LLM 配置](llm-config.md) | Gateway 核心变量 |
| 为单次任务限制工具、路径、域名、命令前缀 | [Session scope 配置](session-scope.md) | 全局环境变量 |

---

## 配置来源与优先级 {#precedence}

ClawSentry 会把多个来源合成为一份有效配置。优先级从高到低：

1. **CLI 参数**：例如 `clawsentry start --mode benchmark --port 9100`
2. **进程/部署环境变量**：当前 shell、CI secret、systemd/Docker 注入的 `CS_*` / `AHP_*`
3. **显式 env file**：只在传入 `--env-file PATH` 或设置 `CLAWSENTRY_ENV_FILE=PATH` 时读取
4. **白名单旧别名**：迁移兼容，例如旧预算变量；只在规范名称缺失时读取
5. **内置默认值**

!!! important "没有自动加载的 ClawSentry env file"
    `.clawsentry.env.example`、`.clawsentry.env.local`、旧 `.env.clawsentry` 都不会被正常启动流程自动加载。`.clawsentry.env.example` 的用途是提交模板和复制起点，不是运行时输入；需要真实生效时，把它复制到 `.clawsentry.env.local` 或部署 env file，填入本机值后显式传入 `--env-file PATH`。旧 `.env.clawsentry` 只作为迁移文件名保留；命令会标记其 legacy 来源。

显式 env file 的解析是**非突变**的：解析阶段只返回隔离的 key/value 与来源路径，不直接写入 `os.environ`。启动入口会按优先级把它们合成到子进程环境中。

规范名称优先于旧别名。例如同时设置：

```bash
CS_L2_BUDGET_MS=5000      # 旧名；只作迁移兼容
CS_L2_TIMEOUT_MS=60000    # 新名，生效
```

最终使用 `60000`。`config show --effective` 会把这类情况以 warning 展示。

---

## 模板文件长什么样？ {#env-template-shape}

`.clawsentry.env.example` 和 `.clawsentry.env.local` 都是 dotenv 格式：每行一个 `KEY=VALUE`。不要写 section、数组或嵌套表。

```bash title=".clawsentry.env.example（可提交，非密钥）"
CS_FRAMEWORK=codex
CS_ENABLED_FRAMEWORKS=codex
CS_MODE=normal
CS_PRESET=medium
CS_LLM_PROVIDER=
CS_LLM_MODEL=
CS_L2_ENABLED=false
CS_L3_ENABLED=false
CS_LLM_TOKEN_BUDGET_ENABLED=false
CS_LLM_DAILY_TOKEN_BUDGET=0
CS_DEFER_BRIDGE_ENABLED=true
CS_DEFER_TIMEOUT_S=86400
CS_DEFER_TIMEOUT_ACTION=block
```

```bash title=".clawsentry.env.local（不要提交，显式加载）"
CS_AUTH_TOKEN=dev-only-token
CS_LLM_API_KEY=sk-...
CS_HTTP_PORT=9100
```

推荐使用方式：

```bash
cp .clawsentry.env.example .clawsentry.env.local
$EDITOR .clawsentry.env.local
clawsentry config show --effective --env-file .clawsentry.env.local
clawsentry start --env-file .clawsentry.env.local
```

如果同时需要共享模板和本机密钥，推荐把共享模板复制为本机文件再补密钥，或由部署系统把二者合并后作为一个 explicit env file 传入。只有在你显式把 `.clawsentry.env.example` 传给 `--env-file` 时，它才会被解析；这通常只适合检查模板，不适合作为真实启动方式。

---

## 任务范围配置：Session scope {#session-scope}

当你想限制“这次任务”能访问的工具、路径、域名或命令前缀时，使用 [Session scope 配置](session-scope.md)。推荐先在 `dry_run: true` 下运行 `clawsentry scope validate/preview`，读懂 `scope_allow:*`、`scope_defer:*`、`scope_deny:*` reason codes；只有确认不会误伤后，才把 `confirmed: true` 与 `dry_run: false` 用到真实决策上下文中。

Session scope 是任务级约束，不是全局 env 配置。AHP / Gateway 集成需要把 profile 显式放入决策上下文；CLI preview 只负责离线校验和预览。

---

## 常用检查命令 {#checks}

```bash
# 查看最终生效配置、来源、脱敏密钥
clawsentry config show --effective
clawsentry config show --effective --env-file .clawsentry.env.local

# 验证 LLM provider、模型、L2/L3 可用性
clawsentry test-llm --env-file .clawsentry.env.local --json

# 验证 service env/template，不修改宿主服务
clawsentry service validate --env-file /etc/clawsentry/gateway.env
```

如果输出与你预期不一致，按顺序检查：

1. 是否有 CLI 参数或 shell/部署环境变量覆盖了 env file
2. 是否忘记显式传入 `--env-file` 或 `CLAWSENTRY_ENV_FILE`
3. env file 是否是 `KEY=VALUE` 格式，而不是 `[section]` 格式
4. 是否同时设置了旧名和新名
5. 是否启用了 token budget 但 limit 仍为 `0`
6. Gateway 是否重启以读取新的进程环境或 env file

---

## 发布状态核对 {#release-status}

截至 2026-05-11，本仓库发布面刷新到 `v0.6.7`：

- GitHub latest release / tags：`v0.6.7 — Codex managed hooks by default`
- PyPI：`clawsentry` 最新版本为 `0.6.7`
- 运行时配置来源仍保持 env-first strict split；Codex hooks 由 `clawsentry start --framework codex` 默认安装到 Codex host 配置，并只管理 ClawSentry-owned hook/trust entries

若你看到更早版本，优先清浏览器/CDN 缓存，并确认访问的是 <https://github.com/Elroyper/ClawSentry> 与 <https://pypi.org/project/clawsentry/>。
