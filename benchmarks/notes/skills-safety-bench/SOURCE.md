# skills-safety-bench 来源记录

| 字段 | 值 |
| --- | --- |
| 来源仓库 | `git@github.com:jinchang1223/skills-safety-bench.git` |
| 本地路径 | `../../skills-safety-bench` |
| 分支 | `main` |
| commit | `148133b9db931419a72d203a78b7c17d8bbfea70` |
| clone 日期 | `2026-04-20` |
| 本地策略 | 保持上游 clone 干净；本地说明和结果放在 clone 外侧。 |

## 已验证

- `git -C benchmarks/skills-safety-bench status --short` 无输出，说明当前本地工作树干净；远端更新尝试见下方。
- `git -C benchmarks/skills-safety-bench rev-parse HEAD` 输出 `148133b9db931419a72d203a78b7c17d8bbfea70`。

## 敏感文件

`skills-safety-bench/.envrc` 包含看起来是真实的 API 配置。不要把其中的 key 或 endpoint 写入文档、提交记录或公开日志。


## 2026-05-01 更新尝试

计划中要求把 `skills-safety-bench` 更新到远端 HEAD。实际执行结果：

- `git -C benchmarks/skills-safety-bench fetch origin` 失败：SSH 22 端口连接被关闭。
- `git -C benchmarks/skills-safety-bench fetch https://github.com/jinchang1223/skills-safety-bench.git main` 失败：HTTPS 需要凭据，非交互环境无法读取用户名。

因此本地仍停留在 `148133b9db931419a72d203a78b7c17d8bbfea70`，未伪造远端 commit，也未覆盖本地工作树。
