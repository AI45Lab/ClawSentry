---
title: API 维护说明
description: ClawSentry API 文档校验的维护者说明
---

# API 维护说明

公开用户通常不需要阅读 API 校验矩阵。请优先使用：

- [API 概览](overview.md)
- [交互式 API Reference](reference.md)
- [OpenAPI JSON](openapi.json)
- [鉴权与安全](authentication.md)
- [模型与错误码](models-errors.md)

维护者可在源码仓库中运行以下命令，检查路由、OpenAPI artifact 和 Markdown 引用是否一致：

```bash
python scripts/docs_api_inventory.py validate
```

该检查只验证文档与源码表面的一致性，不会修改运行时 API 行为，也不会对写入型 API 做真实调用。
