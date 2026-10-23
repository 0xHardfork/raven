# Raven Engineering Constitution

## Core Principles

### I. Hexagonal Architecture (Ports & Adapters)
- 核心业务逻辑（威胁聚合、去重、调度、检索）必须严格封闭在 `internal/core` 域内，绝不直接依赖具体命令行框架或 Web 框架。
- 接入层（Driving Adapters）以独立适配器存在于 `internal/adapter/`：
  - `cli/`: 终端命令行交互（Cobra），提供 `collect`、`query`、`watch`、`server` 等子命令。
  - `api/`: Web API 接口（RESTful），提供标准 HTTP 服务供外部系统调用。
- 基础设施层（Driven Adapters）通过接口（Ports）依赖倒置：
  - `storage/postgres/`: 数据库持久化实现。
  - `runner/python/`: Python 采集脚本调度器。
  - `notifier/`: 告警与通知推送实现（首发支持 Slack Bot，预留企业微信、飞书、钉钉、邮件接口）。

### II. 脚本契约化通信与自声明分类 (Script Contract & Taxonomy)
- 外部采集脚本（放置于 `scripts/`）作为独立子进程执行，通过标准输入输出传递 JSON 数据（`Stdin/Stdout JSON Pipe`），杜绝直接进程内内存污染或强制常驻端口。
- 脚本自主声明分类：由脚本输出中的 `categories` 字段（如 `["java", "spring"]`、`["golang"]`、`["php"]`）决定生态分类，Go 核心原样归档入库，不做二次篡改。

### III. CVE 唯一聚合与增量合并 (Upsert & Fusion)
- 以 `cve_id`（如 `CVE-2024-4577`）作为唯一聚合主键。
- 多源或多次采集同一 CVE 时，遵循幂等合并策略：
  - 分类合并：取多源 `categories` 的并集并去重；
  - PoC 聚合：按 `poc.url` 唯一去重追加；
  - 风险评级：若有更高置信度或更严重 CVSS/Severity 则覆盖更新；
  - 在野利用：若任一情报源（如 CISA KEV）标记为在野利用，状态提升为 `is_exploited = true`。

### IV. 双一等公民输出层 (Dual First-Class Outputs)
- 命令行（CLI）与 Web API 是系统的平级输出界面，两者共享相同的底层业务服务（Service Layer）。
- CLI 提供终端表格、JSON、Markdown 多格式展示与即时触发能力；Web API 提供标准 RESTful 资源操作与状态接口。

### V. 多渠道解耦告警推送 (Multi-Channel Notification)
- 核心调度与巡检通过 `NotifierPort` 触发威胁告警，不与具体通讯平台强绑定。
- 当前优先支持 Slack Bot（富文本 Block Kit），后续平滑扩展企业微信、飞书、钉钉、SMTP 邮件，支持按漏洞危害等级与技术栈进行规则过滤，推送异常不得阻塞核心采集流水线。

### VI. 可测试性与工程质量 (Quality & Testability)
- 核心领域服务必须面向接口（Port Interfaces）编写单元测试，支持内存 Mock 测试（如 Mock Storage Repository、Mock Script Runner、Mock Notifier）。
- 关键数据处理链路（JSON 解析、CVE 归一化、Upsert 合并）必须包含完整的边界测试用例。

---

## 技术规范与技术约束

- **开发语言**：
  - 核心服务：Go 1.22+（严格遵循标准 Go 风格、无全局变量滥用）
  - 采集脚本：Python 3.10+（轻量依赖，自带 `requirements.txt`）
- **持久化存储**：
  - PostgreSQL 14+（采用 GIN 索引加速 `categories TEXT[]` 与 JSONB 检索，预留 pgvector 扩展空间）
- **进程间通信**：
  - 子进程模式，超时时间默认 60 秒，支持 Context 优雅取消与超长输出防假死限制。

---

## 治理与演进规则

- 本宪章定义的内容高于日常实现细节，任何关于分层架构、存储模型、脚本协议的改动均须记录在此。
- 遵循 SDD（规范驱动开发）流程：所有新功能必须先有 Specification，再生成 Plan 和 Tasks，最后编码实现与验证收敛。

**Version**: 1.0.0 | **Ratified**: 2026-10-24 | **Last Amended**: 2026-10-24
