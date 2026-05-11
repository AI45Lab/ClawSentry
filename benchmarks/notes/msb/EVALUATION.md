# MSB × ClawSentry 评估结论

## 结论

MSB 可以作为 ClawSentry 的 MCP/tool-use 安全评测源，优先价值是验证 ClawSentry 能否覆盖 tool metadata、tool parameters、tool response 和 retrieval injection 四类边界。按当前路线，它放在第三阶段，与 ATBench 并行推进：原因是它需要先实现 MCP adapter 或至少 gateway/log replay 层，不如 `skills-safety-bench` 和 `skill-inject` 方便直接启动。

## 第三阶段推荐步骤

1. **本地数据审计**：固定当前 commit `c1d6a70`，记录 12 attack type、5 attack task、10 agent 场景、64 task-tool 对。
2. **12 attack type smoke**：每类 attack type 选 1 个最小实例，raw 与 ClawSentry gateway 各跑一次，确认日志和指标可落盘。
3. **MCP adapter**：在 tool call 前后生成 ClawSentry canonical events；该阶段才可报告 pre-action/post-action coverage。
4. **raw-vs-protected 对照**：同一配置、同一模型、同一 timeout，比较 ASR/PUA/NRP 与 ClawSentry block/defer/false-positive。
5. **扩展到论文规模**：小样本稳定后再扩大到更多 agent/task/LLM 组合。

## 成功判据

- raw 与 protected 的 case selection 完全一致。
- 每个实例都有 MSB 原生日志、operation output、ClawSentry events/decisions 和 summary。
- protected 模式降低 ASR，同时不显著牺牲 PUA。
- ClawSentry 对 tool boundary 的覆盖率可计算，而不是只依赖最终文本审计。

## 当前阻塞

- 未实现 MSB-specific ClawSentry MCP adapter。
- 未跑真实 raw/protected smoke。
- 本地 `.env` 与 provider 可用性未纳入可复现实验配置。

因此当前只能登记为“可评估 / 待适配 / 未出正式分数”。
