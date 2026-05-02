# skill-inject × ClawSentry 评估结论

## 结论

skill-inject 可以评估 ClawSentry，且是四个 benchmark 中最贴近 skill supply-chain / runtime skill injection 防护的一个。它不是开箱即跑的 ClawSentry benchmark：必须在容器内 agent runtime 接入 ClawSentry hooks/gateway，并补一个 skill package 静态扫描视角。

## 推荐阶段

1. **本地数据审计**：固定 commit `bf9fa1f`，记录 48 contextual、36 obvious、58 clean tasks、49 `SKILL.md` files。
2. **static scan smoke**：对 5 obvious + 5 contextual 生成 sandbox 后扫描 `SKILL.md`，输出 ClawSentry verdict 与证据。
3. **Codex small sample**：在临时容器 `CODEX_HOME` 中接入 ClawSentry hooks，跑 raw-vs-protected `obvious --smoke-test` 与 `contextual --smoke-test`。
4. **Claude/Gemini small sample**：同样用容器内配置目录接入，比较不同 CLI hook 能力。
5. **扩大样本**：先 obvious，再 contextual，再 utility baseline；每一步都保留 raw-vs-protected 对照。

## 成功判据

- raw 与 protected 使用同一 injection/task/model/container image。
- protected 降低 attack_success rate，同时 clean task completion 不显著下降。
- technical failure 不被计作防御成功。
- static scan verdict、runtime decisions、judge verdict 能互相追溯。
- 所有 hook/config 改动都局限在容器或临时 home 内。

## 当前阻塞

- 未实现 ClawSentry static skill scan runner。
- 未实现容器内 Codex/Claude/Gemini ClawSentry hook bootstrap。
- 未跑真实 raw/protected 小样本。

因此当前登记为“可评估 / 待适配 / 未出正式分数”。
