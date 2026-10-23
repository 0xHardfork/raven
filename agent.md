# Raven Agent 指南与规则大纲 (agent.md)

> 注：详细指南与全局大纲同见 [AGENTS.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/AGENTS.md)。

## 规则目录与位置映射 (Rules Location)

所有详细执行规范均位于 `.agents/rules/` 目录下：

- 📐 **架构设计与分层规范**：[.agents/rules/architecture.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.agents/rules/architecture.md)
  - 核心业务域封闭，Driving (CLI/API) 与 Driven (Postgres/Runner/Notifier) 适配器解耦。
- 🐹 **Golang 编码与工程质量**：[.agents/rules/golang-standards.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.agents/rules/golang-standards.md)
  - 错误包装 `fmt.Errorf("%w")`，零忽略 error，并发管控与 Context 取消。
- 🐍 **Python 采集脚本契约与分类**：[.agents/rules/python-scraper-contract.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.agents/rules/python-scraper-contract.md)
  - Subprocess 纯 JSON stdout 输出，stderr 输出日志，脚本自声明生态分类 `categories`。
- 🛡️ **安全防护与凭据合规**：[.agents/rules/security-practices.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.agents/rules/security-practices.md)
  - 零硬编码 Secret，SQL 参数化查询，防范 SSRF。

## 全局核心参考
- **完整架构方案**：[ARCHITECTURE.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/ARCHITECTURE.md)
- **工程宪章**：[.specify/memory/constitution.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.specify/memory/constitution.md)
