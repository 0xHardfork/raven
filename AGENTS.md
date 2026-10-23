# Raven Agent 指南与规则大纲 (AGENTS.md)

本文档为 AI Agent 与协作者在 **Raven 威胁收集工具** 工程中的全局导航总览。
具体实施规范与技术细则已全部模块化归档于 `.agents/rules/` 目录中，在执行具体任务时请查阅对应细则。

---

## 1. 规范规则目录索引 (Rules Index)

所有 Agent 在进行架构设计、编写 Go 核心代码、开发 Python 爬虫脚本或配置告警时，必须严格遵守以下规则：

| 领域 / 职责 | 规范大纲说明 | 详细规则文件位置 |
| :--- | :--- | :--- |
| **六边形架构与分层** | 核心域与适配器解耦、依赖倒置、Context 链路传递 | [.agents/rules/architecture.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.agents/rules/architecture.md) |
| **Golang 编码标准** | Go 1.22+ 编码风格、错误包装、并发管控、无全局可变状态 | [.agents/rules/golang-standards.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.agents/rules/golang-standards.md) |
| **Python 采集脚本契约** | 子进程标准输入输出 JSON 管道、脚本自声明分类、日志隔离至 stderr | [.agents/rules/python-scraper-contract.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.agents/rules/python-scraper-contract.md) |
| **安全防护与凭据合规** | 零硬编码 Secret、参数化防 SQL 注入、SSRF 校验与内网 IP 阻断 | [.agents/rules/security-practices.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.agents/rules/security-practices.md) |

---

## 2. 关键架构与工程文件位置 (Key Documents)

- **系统全局架构方案**：[ARCHITECTURE.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/ARCHITECTURE.md)
  - 详细定义了核心管道、PostgreSQL 数据表结构、Upsert 合并算法、CLI 子命令、Web API 端点及 Slack 推送卡片设计。
- **项目工程宪章**：[.specify/memory/constitution.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.specify/memory/constitution.md)
  - 确立了 SDD（规范驱动开发）最高治理原则。
- **环境与版本忽略规则**：[.gitignore](file:///Users/peigen/Documents/dev/0xHardfork/raven/.gitignore)

---

## 3. 工作流与协作原则

1. **规范优先 (Spec-First)**：先确认接口与数据模型契约，再进入代码编写。
2. **轻量管道通信**：Go 与 Python 间严禁直接引入侵入式 RPC/复杂依赖，一律遵循 Stdin/Stdout JSON 流。
3. **闭环自测**：每个新增模块或脚本必须提供自包含的验证方式（单元测试或自测输出）。
