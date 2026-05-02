# MSB Benchmark Notes

MSB（MCP Security Bench）是面向 Model Context Protocol / MCP tool-use pipeline 的端到端安全 benchmark。它评估 agent 在任务规划、工具调用、工具响应处理和检索注入场景下是否会被 MCP 特定攻击诱导。

## 覆盖范围

上游 README 说明完整 MSB 包含 `>2,000` attack instances、12 个 attack categories，并在 10 个 LLM agent/backbone 上报告 ASR。当前本地 JSONL 快照可确认：

| 维度 | 本地数据 |
| --- | ---: |
| attack type | 12 |
| attack task | 5 |
| agent scenario | 10 |
| benign task-tool pair | 64 |
| unique tool/server name | 26 |

12 个 attack type：

| MCP 阶段 | attack type |
| --- | --- |
| Tool Signature Attack | `name_overlap`、`preference_manipulation`、`prompt_injection` |
| Tool Parameters Attack | `out_of_scope_parameter` |
| Tool Response Attack | `simulated_user`、`false_error`、`tool_transfer` |
| Retrieval Injection Attack | `search_term_deception` |
| Mixed Attack | `prompt_injection-simulated_user`、`prompt_injection-false_error`、`preference_manipulation-simulated_user`、`preference_manipulation-out_of_scope_parameter` |

## Case 形态

MSB 不是静态目录型 case。一个实例由这些元素组合生成：

```text
llm_name × agent_name/system_prompt × benign task/tool × attack_task × attack_type × attack implementation
```

运行时 `main.py` 会：

1. 从 `data/agent_task.jsonl` 读取 agent persona、用户任务和目标 MCP server。
2. 从 `data/attack_task.jsonl` 读取攻击目标与实现文本。
3. 按 attack type 组合 support/normal/attack MCP server config。
4. 用 `mcp_use.MCPClient.from_dict(config)` 构建 MCP client。
5. 用 LangChain `ChatOpenAI` / `ChatDeepSeek` / `ChatTongyi` 等构建 LLM。
6. 用 `MCPAgent` 执行用户任务，日志写入 `logs/`，环境状态写入 `operation_space/output/`。
7. 用 `metrics.py` 从日志和环境状态计算 `attack_success`、`mixed_attack_success`、`user_task_success`，再汇总 ASR、PUA、NRP。

## 原生指标

- `ASR`：attack success rate。
- `PUA`：benign/user task 完成率。
- `NRP`：`PUA * (1 - ASR)`，代表任务可用且未被攻击成功的比例。
- `mixed#ASR/PUA/NRP`：mixed attack 汇总视角。
- `stage` / `tool` mode：按 tool-use stage 或是否含 benign tool 配置切分指标。

## 对 ClawSentry 的适配结论

MSB 可以用于评估 ClawSentry，但不是开箱即跑。它天然适合评估 ClawSentry 的 MCP/tool-use 边界，因为攻击点正好覆盖：

- tool metadata / signature：适合接 `pre_action` 或 tool registry 扫描。
- tool parameters：适合接 `pre_action` 参数级检查。
- tool response：适合接 `post_action` / tool-result 检查。
- retrieval injection：适合接 `post_action` 文档/检索内容检查和 `pre_prompt` 上下文污染检查。

推荐接入层：

1. **OpenAI-compatible gateway 对照**：先把 `ChatOpenAI(base_url, api_key)` 指到 ClawSentry gateway，观察 prompt/response 层风险，但这只能覆盖 LLM 输入输出，不能完整覆盖 MCP tool boundary。
2. **MCP adapter 对照**：在 `MCPClient` / `MCPAgent` tool 调用前后插入 ClawSentry canonical events，分别生成 `pre_action` 和 `post_action` 决策；这是正式评估路线。
3. **offline log replay**：对现有 `logs/` 与 `operation_space/output/` 做 replay，只能证明检测/审计能力，不能宣称 runtime prevention。

## 风险与限制

- 当前本地 `.env` 可能含敏感 provider 配置，不应进入结果 artifact。
- 上游运行依赖 LangChain provider、uv、MCP server 子环境和本地 `data/tools/*`，真实运行前要先做小样本 smoke。
- `agent_attack.py` 会按配置组合大量实例；正式跑前必须显式限制 `attack_type` / `attack_task` / `llms` / `agents`，避免无意发起大批量 API 调用。
