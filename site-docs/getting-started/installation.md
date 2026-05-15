---
title: 安装
description: ClawSentry 的安装与环境配置指南
---

# 安装

ClawSentry 是 AHP (Agent Harness Protocol) 的 Python 参考实现，提供面向 AI Agent 运行时的统一安全监督网关。本页介绍如何在你的开发或生产环境中安装和配置 ClawSentry。

---

## 前置条件

| 依赖项 | 最低版本 | 说明 |
|--------|---------|------|
| **Python** | >= 3.11 | 推荐 3.12+，需支持 `typing` 及 `tomllib` |
| **pip** | >= 21.0 | 用于安装 PyPI 包 |
| **操作系统** | Linux / macOS | UDS (Unix Domain Socket) 传输需要类 Unix 系统 |

!!! tip "推荐使用虚拟环境"
    强烈建议使用 **conda** 或 **venv** 隔离 Python 环境，避免依赖冲突。

=== "conda（推荐）"

    ```bash
    conda create -n clawsentry python=3.12 -y
    conda activate clawsentry
    ```

=== "venv"

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

---

## 安装方式

=== "pip (标准)"

    ```bash
    pip install clawsentry
    ```

    最小安装仅包含核心运行时依赖，适合仅使用 L1 规则引擎的场景。

=== "uv (推荐，无需管理 Python 环境)"

    [uv](https://docs.astral.sh/uv/) 是新一代 Python 包管理器，可以自动管理 Python 版本，无需预装 Python。

    ```bash
    # 安装 uv（如果还没有）
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # 安装 ClawSentry（uv 自动下载并管理 Python 3.12）
    uv tool install clawsentry
    ```

    安装后 `clawsentry` / `clawsentry-gateway` / `clawsentry-harness` 会自动加入 PATH。

=== "Homebrew (macOS)"

    ```bash
    brew tap Elroyper/clawsentry
    brew install clawsentry
    ```

    安装后 `clawsentry` / `clawsentry-gateway` / `clawsentry-harness` / `clawsentry-stack` 自动加入 PATH。

    !!! tip "升级"
        ```bash
        brew update && brew upgrade clawsentry
        ```

### 基础安装

核心依赖包括：

| 包名 | 用途 |
|------|------|
| `fastapi >= 0.100` | HTTP 网关服务框架 |
| `uvicorn[standard] >= 0.23` | ASGI 服务器 |
| `pydantic >= 2.0` | 数据模型验证 |

### 可选依赖组

ClawSentry 采用分层依赖设计，你可以根据实际需求选择安装：

=== "LLM 语义分析"

    ```bash
    pip install clawsentry[llm]
    ```

    安装 `anthropic` 和 `openai` SDK，启用 L2 语义分析和 L3 审查 Agent 功能。

    | 包名 | 用途 |
    |------|------|
    | `anthropic >= 0.20` | Anthropic Claude API 客户端 |
    | `openai >= 1.10` | OpenAI / 兼容 API 客户端 |

=== "实时执法"

    ```bash
    pip install clawsentry[enforcement]
    ```

    安装 WebSocket 客户端库，启用 OpenClaw WS 实时事件监听与执法功能。

    | 包名 | 用途 |
    |------|------|
    | `websockets >= 12.0, < 16.0` | OpenClaw WebSocket 连接 |

=== "Prometheus 可观测性"

    ```bash
    pip install clawsentry[metrics]
    ```

    安装 `prometheus_client`，启用 `/metrics` Prometheus 端点和 LLM 成本追踪功能。

    | 包名 | 用途 |
    |------|------|
    | `prometheus_client >= 0.20` | Prometheus 指标采集与暴露 |

=== "全部安装"

    ```bash
    pip install clawsentry[all]
    ```

    安装所有可选依赖，包含 LLM、执法和开发测试工具。适合开发者或需要完整功能的用户。

!!! info "依赖组说明"
    | 依赖组 | 包含内容 | 适用场景 |
    |--------|---------|---------|
    | *(core)* | fastapi, uvicorn, pydantic | 仅 L1 规则引擎，无需 LLM |
    | `[llm]` | anthropic, openai | 需要 L2 语义分析 / L3 审查 Agent |
    | `[enforcement]` | websockets | 对接 OpenClaw WS 实时执法 |
    | `[metrics]` | prometheus_client | Prometheus 可观测性 + LLM 成本追踪 |
    | `[dev]` | pytest, pytest-asyncio, httpx, websockets | 本地开发与运行测试 |
    | `[all]` | 以上全部 | 完整功能 + 可观测性 + 开发环境 |

---

## 从源码安装（开发模式）

如果你需要参与开发或调试 ClawSentry，可以从 GitHub 克隆源码并以可编辑模式安装：

```bash
# 1. 克隆仓库
git clone https://github.com/Elroyper/ClawSentry.git
cd ClawSentry

# 2. 创建并激活虚拟环境
conda create -n clawsentry python=3.12 -y
conda activate clawsentry

# 3. 以开发模式安装（含所有开发依赖）
pip install -e ".[dev]"
```

!!! note "`-e` 参数"
    `-e` (editable) 模式会将源码目录直接链接到 Python 环境中。修改源码后无需重新安装即可生效。

!!! warning "editable 安装与 stale global 包"
    如果你同时装过全局 `clawsentry`（例如 `pip install clawsentry` 或 `uv tool install clawsentry`）又在源码目录里调试，可能会遇到 stale global package：命令行实际加载的是旧的全局包，而不是当前仓库。排查时先运行 `python -c "import clawsentry, pathlib; print(pathlib.Path(clawsentry.__file__).resolve())"`，确认路径指向本仓库；开发调试优先使用 `pip install -e ".[dev]"` 并激活对应虚拟环境。

---

## 验证安装

### 检查 CLI 是否可用

安装成功后，以下 CLI 命令应当可用：

```bash
clawsentry --help
```

预期输出：

```
usage: clawsentry [-h] {init,gateway,stack,harness,watch,audit,doctor,test-llm,l3,service,config,rules,latch,integrations,start,stop,status} ...

ClawSentry — AHP unified safety supervision framework.
```

### CLI 入口一览

| 命令 | 用途 |
|------|------|
| `clawsentry` | 统一入口 |
| `clawsentry start` | 一键启动（auto-init + gateway + watch） |
| `clawsentry stop` | 停止运行中的 Gateway |
| `clawsentry status` | 查看 Gateway 运行状态 |
| `clawsentry init <framework>` | 初始化框架集成配置 |
| `clawsentry config init/show/set/disable/enable` | 管理项目级 `.clawsentry.env.example` 配置 |
| `clawsentry rules lint/dry-run` | 作者期规则治理：lint YAML 规则面、预演 sample events |
| `clawsentry integrations status` | 查看多框架 readiness / 诊断状态 |
| `clawsentry gateway` | 启动 Supervision Gateway |
| `clawsentry watch` | 实时 SSE 事件监控 |
| `clawsentry doctor` | 配置安全审计 |
| `clawsentry audit` | 离线审计日志查询 |
| `clawsentry test-llm` | 验证 L2/L3 连通性、时延与当前运行模式 |
| `clawsentry l3 full-review` | operator-triggered advisory full review |
| `clawsentry-gateway` | 直接启动 HTTP 网关服务 |
| `clawsentry-harness` | 启动 stdio 协议桥接进程 |
| `clawsentry-stack` | 启动完整栈（网关 + OpenClaw 集成） |

### 运行测试套件

如果从源码安装，可运行完整测试套件验证环境正确性：

```bash
python -m pytest src/clawsentry/tests/ -v --tb=short
```

预期看到类似输出（具体数量以当前发布的 CI/验证报告为准）：

```
========================= test session starts ==========================
collected 3483 items

src/clawsentry/tests/test_models.py::test_valid_canonical_event PASSED
src/clawsentry/tests/test_models.py::test_schema_version_format PASSED
...
========================= 3357 passed, 16 skipped ===============
```

!!! success "全部通过即安装成功"
    如果所有测试通过，说明 ClawSentry 及其依赖已正确安装。

---

## 常见安装问题

??? question "安装时提示 `Python >= 3.11 is required`"
    ClawSentry 使用了 Python 3.11+ 的类型标注特性。请确认你的 Python 版本：

    ```bash
    python --version
    ```

    如果版本过低，请升级 Python 或使用 conda 创建新环境：

    ```bash
    conda create -n clawsentry python=3.12 -y
    ```

??? question "`pip install clawsentry[llm]` 报错 `zsh: no matches found`"
    在 zsh shell 中，方括号 `[]` 会被解析为 glob 模式。使用引号包裹：

    ```bash
    pip install "clawsentry[llm]"
    ```

??? question "UDS 路径权限错误"
    ClawSentry 默认使用 `/tmp/clawsentry.sock` 作为 Unix Domain Socket 路径。确保当前用户对该路径有读写权限。可通过环境变量自定义：

    ```bash
    export CS_UDS_PATH=/path/to/custom.sock
    ```

---

## 下一步

安装完成后，继续阅读 [快速开始](quickstart.md) 了解如何在 5 分钟内启动 ClawSentry 监督网关并对接你的 AI Agent 框架。
