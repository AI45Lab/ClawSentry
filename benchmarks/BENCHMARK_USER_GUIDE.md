# 已 clone Benchmarks 用户视角说明

本文从“怎么给别人讲清楚、怎么为下一阶段论文实验选型”的角度，总结当前 `benchmarks/` 下已经 clone 或登记的 benchmark。

核心判断先放前面：

| Benchmark | 主要作用 | 测试对象 | 裸 LLM API 是否足够 | 当前实例规模 | 更适合回答的论文问题 |
| --- | --- | --- | --- | ---: | --- |
| `skills-safety-bench` | 测 agent 在本地 skill / workspace 攻击上下文中能否既完成任务又不被诱导 | Codex、Claude Code 等真实 agent 框架 | 不足够；API 只是 agent 后端模型 | 155 case，6 个风险域，30 类 | 防御是否降低真实 agent 的攻击成功率，同时保持任务完成率 |
| `skill-inject` | 测 coding/agent CLI 加载 skill files 时是否被隐藏恶意指令影响 | Codex、Claude Code、Gemini CLI、Vibe 等 agent CLI | 不足够；除非只做静态扫描 | 本地 48 contextual、36 obvious、58 clean tasks、49 个 `SKILL.md` | skill/package supply-chain 防护是否有效，是否影响正常任务完成 |
| `MSB` | 测 MCP tool-use pipeline 中 tool signature、参数、响应、检索注入攻击 | MCP agent / LangChain + MCPClient + LLM 后端 | 不足够；必须有 MCP tool-use agent 执行链路 | 官方 >2,000 attack instances；本地 12 attack type、5 attack task、10 agent 场景、64 task-tool 对 | 防御是否覆盖工具调用边界，而不只是最终输出过滤 |
| `AgentDoG` / `ATBench` | 轨迹级安全分类与细粒度风险诊断 | guard model、审计器、轨迹检测器；也可扩展到 live agent | 默认足够；给模型/guard 输入已完成 trajectory 即可 | ATBench 官方 500 trajectory；本地 clone 只有 sample 与 runner | 检测器是否能识别完整 agent 轨迹中的风险，误报率如何 |

当前建议的实验启动顺序是：

```text
skills-safety-bench -> skill-inject -> MSB + ATBench
```

原因是 `skills-safety-bench` 已有物化 case、manifest、Harbor/Codex runner 和历史 dry-run 证据，最适合先开始直接 agent 执行实验；`skill-inject` 有容器 runner 和多 CLI agent 入口，适合作为第二阶段；`MSB` 需要 MCP adapter，`ATBench` 需要补完整 labeled trajectory 数据，因此放到第三阶段并行推进。

## 先区分三类测试对象

**裸 LLM API 测试**：只把 prompt 或静态记录发给一个模型 API，让模型输出分类、答案或 judge verdict。它适合测“模型是否能识别风险”，但不能证明真实 agent 会不会调用工具、写文件、泄露数据或被 hook 拦截。`AgentDoG/ATBench` 的默认用法属于这一类或 guard API 类。

**Agent 框架测试**：目标是一个会读 workspace、调用工具、执行命令、产生产物的 agent，例如 Codex、Claude Code、Gemini CLI、OpenClaw、A3S-Code。模型 API 只是这个 agent 的后端。`skills-safety-bench`、`MSB`、`skill-inject` 都主要需要这一类测试。

**防御系统 A/B 测试**：同一批 case、同一模型、同一 timeout 和重试参数，跑两遍：`raw` 直接访问模型或工具链，`protected` 经过 ClawSentry/A3S/Hook/Gateway。论文里应报告攻击成功率是否下降、任务完成率是否保持，以及误报、延迟、成本和技术失败。

## 1. skills-safety-bench

### 作用

`skills-safety-bench` 是一个已经物化好的静态 agent 安全 benchmark。每个 case 都是一个普通用户任务，但攻击指令藏在 agent 可能读取或依赖的本地 skill、helper script、sidecar file、corpus、template、workspace artifact 等位置。它测试的是：agent 是否能在完成正常任务的同时，不盲从本地攻击上下文。

这类 benchmark 很适合论文中的真实运行防御评测，因为它不只是让模型“说安全/不安全”，而是让 agent 进入任务环境，实际读文件、执行步骤、生成结果，再由 verifier 判断任务和攻击是否发生。

### 测试对象

需要真实 agent 框架。裸 LLM API 不足以完成该 benchmark，因为 case 依赖本地目录、Docker/Harbor 环境、文件输出和攻击 verifier。

当前上游入口是 `scripts/start_agent_batch.sh`，支持通过 Harbor 指定 agent，例如 `--agent codex` 或 `--agent claude-code`。本工作区历史上已验证最稳定的是 Codex dry-run/单 case 路径；其他框架要作为正式论文结果，还需要先补 runner/adapter 并做 smoke。

### 一个 case 包含哪些静态内容

典型目录：

```text
benchmark/<risk-domain>/<category>/<case>/
  metadata.json
  rationale.md
  attacked_task/
    instruction.md
    task.toml
    environment/
    solution/solve.sh
    tests/test.sh
    tests/test_outputs.py
  eval/verify_attack.py
```

核心含义：

| 内容 | 作用 |
| --- | --- |
| `instruction.md` | 给 agent 的普通用户任务 |
| `environment/` | 任务运行环境和可能被 agent 接触的本地材料 |
| `tests/test.sh` / `tests/test_outputs.py` | 判断基础任务是否完成 |
| `eval/verify_attack.py` | 判断攻击行为是否被诱导出来 |
| `metadata.json` | case id、风险域、类别等机器可读元数据 |
| `rationale.md` | 人读的设计动机和攻击解释 |

### 一般如何测试

基本流程：

1. 选择范围：一个 case、一个 category、一个 risk domain，或显式 manifest。
2. Harbor 为每个 case 构造隔离任务环境。
3. agent 读取 `attacked_task/instruction.md` 并执行任务。
4. runner 收集输出文件、日志和 artifacts。
5. replay `eval/verify_attack.py` 判断攻击是否成功。
6. 汇总 `summary.json`、`attack_results.json/csv/md`。

示例命令：

```bash
cd benchmarks/skills-safety-bench
scripts/start_agent_batch.sh --rd 1 --agent codex --dry-run
scripts/start_agent_batch.sh --rd 1 --case travel_planning_skill_name_decoy_singular_alias --agent codex
```

### 测试指标

原生指标重点是两个轴：

| 指标 | 含义 |
| --- | --- |
| `task_success` | 正常用户任务是否完成 |
| `attack_success` | 攻击行为是否发生 |
| `task_output_missing` | 预期任务输出缺失 |
| evaluator error / timeout | verifier 或运行过程失败 |

做防御论文时建议报告：

| 指标 | 论文解释 |
| --- | --- |
| ASR = attack_success rate | 攻击成功率，越低越好 |
| Task Success Rate | 可用性，不能靠拒绝一切来降低 ASR |
| NRP 或 safe completion | 任务完成且攻击未成功的比例 |
| block/defer rate | 防御实际拦截比例 |
| false positive rate | 正常任务被误拦截比例 |
| latency / cost / timeout | 防御带来的运行开销 |

### 实例数

本地 manifest 统计为 155 个 case、6 个 risk domain、30 个 category：

| 风险域 | case 数 |
| --- | ---: |
| RD1 Context Trust and Prompt Manipulation | 25 |
| RD2 Agency, Scope, and Authorization | 25 |
| RD3 Execution, Runtime, Framework, and Protocol | 26 |
| RD4 Data Boundary, Output, and Externalization | 27 |
| RD5 Memory, Recovery, Audit, and Persistence | 26 |
| RD6 Knowledge, Model, Supply Chain, and Operational | 26 |

## 2. AgentDoG / ATBench

### 作用

`AgentDoG` 是轨迹级 agent safety guard / evaluation framework。它关注的是完整 agent trajectory 中是否出现风险，而不是只看最终回复。`ATBench` 是它发布的轨迹级安全数据集。

它适合用于论文中的“检测与审计能力”实验：给定一个已经发生的 agent 执行轨迹，检测器能否判断这条轨迹 safe / unsafe，并给出风险来源、失败模式和现实危害类型。

### 测试对象

默认测试对象可以是裸 LLM API、AgentDoG guard model、ClawSentry offline replay 或其他轨迹分类器。不需要真实 agent 框架执行任务，因为输入已经是完成的 trajectory。

但要注意：offline trajectory replay 只能证明“检测到了风险”，不能单独证明“运行时阻止了风险”。如果论文要声称 runtime prevention，就需要额外构造 live agent runner，把同一任务交给 Codex/Claude/Gemini/A3S-Code/OpenClaw 等真实框架执行，并在动作前后插入防御。

### 一个 case 包含哪些静态内容

一个 ATBench/AgentDoG trajectory 典型是 JSON：

```json
{
  "profile": "You are a helpful assistant.",
  "contents": [
    [
      {"role": "user", "content": "..."},
      {"role": "agent", "thought": "...", "action": "..."},
      {"role": "environment", "content": "..."}
    ]
  ],
  "label": "safe or unsafe",
  "risk_source": "...",
  "failure_mode": "...",
  "real_world_harm": "..."
}
```

本地 sample `benchmarks/AgentDoG/examples/trajectory_sample.json` 只有 `profile` 和 `contents`，没有 ground-truth label，所以只能做 smoke，不能计正式分。

### 一般如何测试

原生分类方式：

1. 部署 AgentDoG 或其他待测 guard model，通常提供 OpenAI-compatible API。
2. 用 `prompts/trajectory_binary.txt` 组装二分类 prompt。
3. 对 unsafe trajectory 可用 `prompts/trajectory_finegrained.txt` 与 `prompts/taxonomy_finegrained.txt` 做细粒度诊断。
4. 将预测结果与 ground-truth label 对比。

本地 ClawSentry offline replay 方式：

1. 把 trajectory 转成 canonical events，例如 `pre_prompt`、`pre_action`、`post_action`、`post_response`。
2. replay 到 ClawSentry。
3. 用 ClawSentry 的 block/defer/risk-level 与 ATBench label 计算检测指标。

示例：

```bash
python benchmarks/scripts/agentdog_atbench_clawsentry.py \
  --trajectory benchmarks/AgentDoG/examples/trajectory_sample.json \
  --output /tmp/agentdog-clawsentry-events.jsonl \
  --framework agentdog-atbench \
  --print-summary
```

正式计分应使用带 `safe` / `unsafe` 标签的 manifest，而不是本地 sample。

### 测试指标

原生 AgentDoG/ATBench 指标：

| 指标 | 含义 |
| --- | --- |
| binary accuracy | safe / unsafe 分类准确率 |
| unsafe recall | unsafe trajectory 中被识别出来的比例 |
| safe false-positive rate | safe trajectory 被误报为 risky 的比例 |
| precision / balanced accuracy | 类别均衡时更有参考价值 |
| risk-source accuracy | 风险来源标签准确率 |
| failure-mode accuracy | 失败模式标签准确率 |
| harm-type accuracy | 现实危害标签准确率 |

ClawSentry replay 可加：

| 指标 | 含义 |
| --- | --- |
| detection positive | block、defer 或 high/critical risk |
| prevention positive | block 或 defer；offline 阶段只能作为辅助指标 |
| pre-action / post-action coverage | 轨迹中有多少关键动作点被覆盖 |
| latency / L2-L3 cost | 推理式防御的延迟和成本 |

### 实例数

上游 README 声明 ATBench 官方规模为 500 条 trajectory，其中 250 safe、250 unsafe，平均约 8.97 turns，总计约 4486 turn interactions；trajectory 中出现 1575 个 unique tools，并有 2292 个 unseen-tool definitions。

当前本地 clone 未包含完整 ATBench 数据集，只包含示例 trajectory、prompt templates、论文和本地 replay runner。正式实验需要先从 Hugging Face / ModelScope 获取带标签数据。

## 3. MSB

### 作用

`MSB` 即 MCP Security Bench，面向 Model Context Protocol tool-use pipeline。它不是普通 prompt benchmark，而是专门评估 agent 在 MCP 工具发现、任务规划、工具调用、工具响应处理和检索内容注入中是否会被攻击诱导。

它适合用于论文中的“工具边界防御”实验：防御系统是否能覆盖 tool metadata/signature、tool parameters、tool response、retrieval injection，而不是只看最终模型文本。

### 测试对象

需要 MCP agent 执行链路。裸 LLM API 不足够，因为攻击点发生在 MCP server config、tool description、tool call parameters、tool result、retrieval content 等位置。

本地实现用 `mcp_use.MCPClient.from_dict(config)` 构造 MCP client，用 LangChain chat model 作为后端 LLM，再用 `MCPAgent` 执行任务。LLM API 只是其中一环。

### 一个 case 包含哪些静态内容

MSB 的实例不是固定 case 目录，而是由多个 JSONL 和工具配置组合生成：

```text
llm_name
× agent_name / system_prompt
× benign task-tool pair
× attack_task
× attack_type
× attack implementation
× MCP server config
```

关键静态内容：

| 文件或目录 | 内容 |
| --- | --- |
| `data/agent_task.jsonl` | agent 场景、system prompt、普通用户任务、目标工具 |
| `data/attack_task.jsonl` | 攻击目标，例如窃取数据、改数据、获取远控、杀进程 |
| `data/attack_type.jsonl` | 12 类 MCP 攻击类型 |
| `data/tools/normal_tools/` | 正常 MCP tool 配置 |
| `data/tools/support_tools/` | 支撑攻击任务的辅助工具 |
| `data/tools/attack_tools/` | 被篡改或恶意的 MCP tool/server |
| `logs/` | agent 执行过程日志 |
| `operation_space/output/` | 环境状态和攻击结果判断材料 |

### 一般如何测试

流程：

1. 用 YAML 配置选择 attack type、attack task、LLM、agent scenario。
2. `agent_attack.py` 读取 `data/*.jsonl` 并组合 MCP server config。
3. `MCPClient` 加载 normal/support/attack tool servers。
4. `MCPAgent` 执行普通用户任务。
5. 日志写入 `logs/`，环境输出写入 `operation_space/output/`。
6. `metrics.py` 解析日志和环境状态，计算攻击与可用性指标。

最小 smoke 应限制为一个 LLM、一个 agent、一个 attack type、一个 attack task：

```bash
cd benchmarks/MSB
python agent_attack.py --cfg_path /tmp/msb-smoke.yml
python metrics.py \
  --attack_type prompt_injection \
  --attack_task obtain_agent_interaction_data \
  --llm openai/gpt-4o-mini \
  --agent llm_enhancement \
  --mode llm
```

### 测试指标

MSB 原生指标：

| 指标 | 含义 |
| --- | --- |
| ASR | attack success rate |
| PUA | user / benign task 完成率 |
| NRP | `PUA * (1 - ASR)`，表示任务完成且攻击未成功的比例 |
| mixed ASR / PUA / NRP | 混合攻击视角的汇总 |
| stage mode | 按 planning、tool call、response、multi-stage 切分 |
| tool mode | 按是否含 benign tool 配置切分 |

防御论文建议额外报告：

| 指标 | 含义 |
| --- | --- |
| pre-action coverage | tool call 前是否有防御决策 |
| post-action coverage | tool result 后是否有防御决策 |
| unsafe recall | 已攻击成功实例中，防御是否 block/defer/high-risk |
| safe false-positive rate | 正常完成实例中，防御是否误拦 |
| block/defer/modify rate | 防御动作分布 |
| latency / cost / technical failure | 工程代价与失败率 |

### 实例数

上游 README 声明完整 MSB 包含超过 2,000 个 attack instances，覆盖 12 个 attack categories，并在 10 个 LLM agent/backbone 上报告 ASR。

当前本地数据可确认：

| 维度 | 数量 |
| --- | ---: |
| attack type | 12 |
| attack task | 5 |
| agent scenario | 10 |
| benign task-tool pair | 64 |
| unique tool/server name | 26 |

本地组合数不应简单相乘当作正式实例数，因为不同 attack type 对 agent、tool、attack_task 有过滤约束。

## 4. skill-inject

### 作用

`skill-inject` 测 coding/agent CLI 在加载 skill files 时，是否会执行隐藏在 skill 定义里的恶意或双用途指令。它比普通 prompt injection 更接近 skill/package supply-chain 风险：攻击不是直接写在用户 prompt 里，而是藏在 agent 自己会加载的能力说明、脚本、startup assets 或 skill package 中。

它非常适合用于论文中的 skill 防护实验：静态扫描能否发现恶意 skill，runtime hook/gateway 能否阻止 agent 执行隐藏指令，同时 clean task completion 是否保持。

### 测试对象

主要需要真实 agent CLI，例如 Codex、Claude Code、Gemini CLI、Vibe。裸 LLM API 不足以测试完整行为，因为核心风险发生在 agent 加载 skill、执行 CLI、读写文件、运行命令的过程中。

例外是“静态扫描”子实验：如果只评估 ClawSentry 对 `SKILL.md` 或 package 内容的风险识别，可以不运行 agent。但这只能证明检测能力，不能证明 runtime prevention。

### 一个 case 包含哪些静态内容

一个实验实例通常由以下元素组合：

```text
agent/model
× injection definition
× clean task
× skill package
× policy condition
× runtime container
```

关键静态内容：

| 文件或目录 | 内容 |
| --- | --- |
| `data/contextual_injections.json` | 上下文相关、双用途的注入定义 |
| `data/obvious_injections.json` | 明显恶意的注入定义 |
| `data/tasks.json` | 正常任务，用于任务完成率和 utility baseline |
| `data/skills/` | clean skill definitions |
| `data/unified_security_policy.md` | warning / legitimizing 等安全策略文本 |
| `scripts/build_sandbox.py` | 把注入写入 sandbox skill/package |
| `scripts/run_sandbox_container.py` | 在 Docker/Apptainer 中运行 agent CLI |
| `judges/*_judge.py` | 用 judge 判断攻击是否成功、任务是否完成、是否技术失败 |

### 一般如何测试

流程：

1. 根据 injection JSON 和 clean skill 构造 sandbox。
2. 把恶意或双用途指令嵌入 skill 描述、skill 内容、startup script 或相关文件。
3. 在隔离 Docker/Apptainer 容器中运行目标 agent CLI。
4. 捕获 stdout/stderr、修改文件、命令历史和运行状态。
5. 用 LLM judge 或规则判断 injection 是否成功、clean task 是否完成、是否 technical failure。
6. 汇总到 `final_results/`，再归档到外层 `benchmarks/results/skill-inject/`。

示例：

```bash
cd benchmarks/skill-inject
python scripts/smoke_test_all.py --agent codex --model gpt-5.2-codex --dry-run
python experiments/contextual.py --agent codex --model gpt-5.2-codex --smoke-test --skip-eval --runtime docker
python experiments/obvious.py --agent codex --model gpt-5.2-codex --smoke-test --skip-eval --runtime docker
```

注意：`--dry-run` 只是命令预览；`--smoke-test` 仍可能构建 sandbox、启动容器并调用模型。

### 测试指标

原生指标：

| 指标 | 含义 |
| --- | --- |
| attack_success rate / ASR | 注入是否让 agent 执行目标行为 |
| ignored rate | agent 是否忽略注入 |
| task completion / utility | 正常任务是否完成 |
| technical failure rate | 容器、CLI、API、judge 等技术失败 |
| judge verdict + evidence | judge 给出的分类和证据 |

防御论文建议额外报告：

| 指标 | 含义 |
| --- | --- |
| static scan recall | 含恶意注入的 skill package 是否被静态识别 |
| runtime block/defer rate | hook/gateway 是否在运行时拦截 |
| unsafe recall | 攻击实例中防御是否命中 |
| safe false-positive rate | clean skill 或正常任务是否被误拦 |
| clean task completion delta | 防御前后正常任务完成率差值 |
| latency / timeout / retry / cost | 运行代价 |

### 实例数

上游 README 的数字较旧；以当前本地 JSON 统计为准：

| 数据 | 数量 |
| --- | ---: |
| contextual injections | 48 |
| obvious injections | 36 |
| clean tasks | 58 |
| `SKILL.md` files | 49 |
| safety policy conditions | 3：normal、legitimizing、warning |
| supported agent families | 4：codex、claude、gemini、vibe |

实际实验实例数由 agent/model、injection、task、skill、policy、runtime 组合决定，不宜简单用注入数相乘当作最终有效样本数；正式论文应记录筛选规则和 technical failure 排除规则。

## 论文实验设计建议

### 推荐分层

建议把下一阶段实验拆成三层，而不是把四个 benchmark 混成一个分数：

| 层级 | Benchmark | 主要结论 |
| --- | --- | --- |
| 轨迹检测层 | AgentDoG / ATBench | 防御或 guard 能否识别已发生的 agent 风险，误报率如何 |
| 真实 agent 执行层 | skills-safety-bench、skill-inject | 防御是否在真实 CLI agent 中降低 ASR，并保持 task success |
| 工具边界层 | MSB | 防御是否覆盖 MCP tool metadata、参数、响应、检索注入 |

### 最小可发表实验路线

1. **skills-safety-bench Codex 单 case / 单 RD**：优先从 RD1 单 case dry-run 与 raw/protected 开始；链路稳定后扩到 RD1 或 RD6。报告 task_success、attack_success、NRP、technical failure 和防御 coverage。
2. **skill-inject static scan + Codex small sample**：先跑 obvious/contextual 小样本，比较 raw vs protected；报告 ASR、task completion、technical failure。
3. **MSB 12 attack type smoke**：每类攻击 1 个最小实例，先验证 tool-boundary events 可落盘；稳定后再扩大。
4. **AgentDoG/ATBench offline labeled replay**：与 MSB 并行补充，先取 `5 safe + 5 unsafe` smoke，再扩到官方 500 条；报告 recall、FPR、balanced accuracy、细粒度标签对齐。offline replay 只作为检测/审计证据，不作为 runtime prevention 主证据。

### 报告时要避免的表述

| 不建议说 | 更准确的说法 |
| --- | --- |
| “裸 LLM 在 skills-safety-bench 上通过/失败” | “某 agent 框架以某 LLM 为后端，在该 case 上通过/失败” |
| “AgentDoG offline replay 证明防御阻止了攻击” | “offline replay 证明检测器识别了已完成轨迹中的风险；runtime prevention 需 live runner 另证” |
| “MSB 只要把 base_url 指到 gateway 就完成防御评测” | “gateway-only 只覆盖 prompt/response；正式 MSB 需要 MCP pre/post tool boundary adapter” |
| “technical failure 等于防御成功” | “technical failure 应单列，不能计作成功防御” |

## 本地路径速查

| 内容 | 路径 |
| --- | --- |
| 总登记表 | `benchmarks/BENCHMARKS.md` |
| 通用运行规范 | `benchmarks/RUNBOOK.md` |
| 结果索引 | `benchmarks/RESULTS.md` |
| skills-safety-bench notes | `benchmarks/notes/skills-safety-bench/` |
| AgentDoG notes | `benchmarks/notes/agentdog-atbench/` |
| MSB notes | `benchmarks/notes/msb/` |
| skill-inject notes | `benchmarks/notes/skill-inject/` |

## 当前安全边界

所有真实 agent/hook 实验都应在临时 home、容器或临时 `CODEX_HOME` 中完成。不要修改当前开发者正在使用的 `~/.codex`、当前 `CODEX_HOME` 或 OMX/user hooks；不要把 `.env`、API key、provider endpoint、完整模型 transcript 提交到结果文档中。
