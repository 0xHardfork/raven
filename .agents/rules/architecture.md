---
trigger: always_on
---

# 架构设计与分层规范 (Hexagonal Architecture)

## 1. 六边形架构约束
- **核心隔离原则**：`internal/core` 必须保持纯粹。领域模型（Domain Entities）与业务用例（Services）严禁导入任何驱动适配器代码（如 `internal/adapter/cli` 或 `internal/adapter/api`）。
- **依赖倒置原则**：
  - Core 层只依赖抽象接口（`internal/core/port`）。
  - 所有外部依赖（PostgreSQL 存储、Python 脚本子进程调度器、Slack 推送）必须通过实现 Ports 接口以适配器形式注入。

## 2. 适配器职责划分
- **Driving Adapters (主动/接入适配器)**：
  - `cli/`: 负责处理命令行参数（Cobra）、终端渲染与交互；仅调用 Service 层方法，不包含任何业务计算。
  - `api/`: 负责 HTTP 路由（Gin/Fiber）、请求参数校验与 JSON 响应封装。
- **Driven Adapters (被动/基础设施适配器)**：
  - `storage/postgres/`: 仅负责 SQL 执行、事务处理与数据库模型到领域实体的转换。
  - `runner/python/`: 仅负责子进程启动、Context 超时控制与 Stdin/Stdout JSON 管道序列化。
  - `notifier/`: 仅负责组装各平台（Slack 等）富文本报文并执行异步推送，网络异常不得 panic。

## 3. 并发与上下文传递
- 所有 Service 和 Port 接口的方法首参数必须为 `ctx context.Context`。
- 严禁忽略 context 取消信号；长周期操作（爬虫调用、数据库查询、定时轮询）必须挂载 Context 超时控制。

## 4。 禁止对代码添加注释 所有代码要可以自解释
