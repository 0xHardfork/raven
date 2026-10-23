# Feature Specification: 001-threat-collector

**Feature Directory**: `specs/001-threat-collector`

**Created**: 2026-10-24

**Status**: Ready for Planning

**Input**: 构建具备多源采集、生态分类存储、CVE 唯一聚合、双接入层 (CLI/Web API) 及 Slack 告警推送的开源威胁情报收集系统。

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - 多源情报采集与 CVE 聚合入库 (Priority: P1)

作为一名安全工程师，我希望工具能从 GitHub PoC、CISA KEV、Exploit-DB 与 NVD 等公开威胁源自动化拉取漏洞与 PoC 数据，按技术栈生态（如 Java、Golang、PHP）进行分类存储，并自动将多源信息按唯一 CVE 编号进行合并，从而获取单一漏洞的完整全景视图。

**Why this priority**: 数据收集与准确聚合去重是整个威胁系统的基石。没有高质量的结构化数据，后续的检索与推送均无意义。

**Independent Test**:
- 运行针对测试源的采集流程，能够成功获取多源数据；
- 针对相同 CVE 编号（如存在多份 GitHub PoC 或来自不同源）执行合并，验证最终记录中技术栈标签为并集、PoC 链接完整且无重复。

**Acceptance Scenarios**:
1. **Given** 存在未采集的外部漏洞情报源，**When** 执行数据收集，**Then** 系统自动拉取记录、解析自声明的技术栈分类并持久化入库。
2. **Given** 系统数据库中已存在某 CVE 记录，**When** 采集脚本从另一数据源发现同一 CVE 的新 PoC 链接与新分类，**Then** 系统自动将新 PoC 追加至主记录、合并分类标签，且不破坏已有字段。

---

### User Story 2 - 终端交互与即时多维检索 CLI (Priority: P1)

作为一名一线安全研究员，我希望能够在终端通过命令行一键触发采集（`collect`），并通过指定 CVE 编号、技术生态分类（`--category java`）、是否有 PoC（`--has-poc`）或威胁等级进行快速多维过滤检索，并以美观的表格形式展示。

**Why this priority**: 命令行是安全研究员最直接、最高频的工作界面，必须提供低延迟、高可读性的即时交互能力。

**Independent Test**:
- 执行查询命令（如 `raven query --category java --has-poc`），能够即时返回过滤后的漏洞列表，并在终端以结构化表格打印。

**Acceptance Scenarios**:
1. **Given** 数据库中存在不同技术生态的漏洞，**When** 用户执行 `raven query --category golang`，**Then** 终端仅展示包含 `golang` 分类标签的漏洞及 PoC 统计。
2. **Given** 用户想要查询特定漏洞详情，**When** 用户执行 `raven query --cve CVE-XXXX-YYYY`，**Then** 终端完整输出该漏洞的描述、CVSS 评级、在野利用状态及所有可用 PoC 链接。

---

### User Story 3 - 标准 RESTful Web API 接入层 (Priority: P2)

作为一名系统架构师或自动化运维人员，我希望系统提供标准的 HTTP REST API，以便内部安全运营平台、自动化编排流水线或前端系统能够检索威胁数据并按需触发采集。

**Why this priority**: 满足系统对外集成和微服务化调用的核心诉求，使 Raven 不仅仅是一个单机脚本，而是一个威胁情报服务。

**Independent Test**:
- 启动服务后调用 `GET /api/v1/threats?category=php&has_poc=true`，验证返回符合过滤条件的 JSON 结构体与分页元数据。

**Acceptance Scenarios**:
1. **Given** 服务已启动，**When** 第三方系统请求 `GET /api/v1/threats`，**Then** 返回状态码 200 及标准化 JSON 数组，包含总数、页码与威胁列表。
2. **Given** 服务已启动，**When** 调用 `POST /api/v1/collect/trigger` 提交采集源参数，**Then** 系统异步启动采集流程并返回任务执行状态。

---

### User Story 4 - 守护巡检与 Slack Bot 实时告警推送 (Priority: P2)

作为安全响应团队成员，我希望系统能够在后台定时轮询最新披露的情报，一旦发现匹配关注条件的高危漏洞、新增 PoC 或命中 CISA 在野利用时，自动将富文本卡片推送到团队的 Slack 频道，以便团队在第一时间响应。

**Why this priority**: 降低情报滞后时间，实现从「人找情报」向「情报找人」的转变。

**Independent Test**:
- 触发一条标记为在野利用或 CRITICAL 的威胁，验证配置的 Slack Webhook 能收到包含 CVE、严重度色彩、分类标签及可点击 PoC 链接的 Block Kit 消息。

**Acceptance Scenarios**:
1. **Given** 系统运行在 `watch` 守护模式，**When** 巡检发现新增的高危 CVE 或新 PoC，**Then** 判定符合过滤规则后向 Slack 频道推送预警卡片。
2. **Given** 新增漏洞属于低危且无 PoC，**When** 触发告警检查，**Then** 系统依据过滤策略抑制该消息，避免群聊告警风暴。

---

### User Story 5 - 自定义采集脚本扩展 (Priority: P3)

作为工具维护者，我希望能通过在特定脚本目录下直接新增 Python 采集脚本，脚本自声明分类，系统核心无缝加载并纳管，无须重构核心代码。

**Why this priority**: 保证威胁情报源的长效生命力与社区共建扩展能力。

**Independent Test**:
- 新增一个测试脚本并输出 JSON，Go 核心成功调用并把脚本自声明的特定分类完整入库。

**Acceptance Scenarios**:
1. **Given** 新增 Python 脚本放置于 `scripts/` 目录，**When** Go 核心调用执行，**Then** 系统通过标准输出解析其 JSON 结果，将脚本自声明的 `categories` 原样存入数据库。

---

### Edge Cases

- **极端并发与重复采集**：两个不同脚本同时抓取到相同的 CVE 记录时，数据库层必须通过原子锁/冲突更新（`ON CONFLICT (cve_id) DO UPDATE`）保证数据完整性，不发生主键冲突或死锁。
- **爬虫网络超时与异常字符**：当目标情报源连接超时、网络中断或返回异常非 JSON 字符时，执行器必须设定硬超时并在 stderr 捕获异常，绝不阻塞主进程。
- **告警通道网络抖动**：当 Slack 服务端出现网络波动或不可达时，告警推送以异步重试或错误日志记录，绝不导致当次情报采集与入库失败。

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: 系统必须支持以 CVE 编号为主键的幂等合并存储（分类并集、PoC 去重追加、危害度更新）。
- **FR-002**: 外部采集脚本必须作为独立子进程调度，通过标准输入输出（Stdin/Stdout）以统一 JSON Schema 通信。
- **FR-003**: 系统必须严格保留脚本自声明的 `categories` 标签（如 `java`、`golang`、`php`），禁止核心硬编码规则二次篡改。
- **FR-004**: 命令行工具必须提供 `collect`（即时采集）、`query`（多维检索）、`watch`（定时巡检）与 `server`（启动 API）子命令。
- **FR-005**: 检索命令与接口必须支持按 `category`、`severity`、`has_poc`、`is_exploited` 以及关键词模糊搜索过滤。
- **FR-006**: Web API 必须提供符合 RESTful 规范的端点，包括威胁列表查询、CVE 单条详情、分类标签统计与触发采集。
- **FR-007**: 系统必须实现可插拔的 `NotifierPort`，首发支持 Slack Bot Block Kit 富文本卡片推送。
- **FR-008**: 告警模块必须支持基于最低危险等级、技术栈关注白名单、是否有 PoC 的灵活过滤规则。
- **FR-009**: 系统默认内置覆盖 GitHub PoC、CISA KEV、Exploit-DB 与 NVD 4 大情报源的采集实现。
- **FR-010**: 系统必须保证所有数据库查询使用参数化操作，杜绝 SQL 注入隐患。

### Key Entities

- **Vulnerability (漏洞实体)**: 包含 `cve_id` (唯一标识)、`title`、`description`、`severity` (CRITICAL/HIGH/MEDIUM/LOW)、`cvss_score`、`categories` (技术栈标签数组)、`is_exploited` (布尔值)、`pocs` (PoC 列表)、`sources` (来源列表)、时间戳。
- **PoC (概念验证实体)**: 包含 `url`、`author`、`description`、`published_at`。
- **ThreatFilter (检索过滤条件)**: 包含 `Categories`、`MinSeverity`、`HasPoC`、`IsExploited`、`Keyword`、`Page`、`PageSize`。

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 针对已有数据重复执行相同数据源的采集，数据库主记录数量零膨胀，验证 Upsert 100% 幂等。
- **SC-002**: 终端查询与 Web API 列表检索在 10,000 条漏洞数据规模下，95% 的请求响应时间低于 100 毫秒。
- **SC-003**: 发现匹配告警规则的高危漏洞或新 PoC 后，告警卡片在 3 秒内送达指定 Slack 频道。
- **SC-004**: 任意单个采集脚本因网络故障或源端结构变更崩溃时，系统其他采集源与核心服务保持 100% 正常运行。

---

## Assumptions

- 运行主机具备 Go 1.22+ 与 Python 3.10+ 执行环境，或通过 Docker 容器化运行。
- 数据持久化依赖 PostgreSQL 14+ 实例，支持本地 Docker 或外部远程数据库连接。
- 外部情报源网络访问通畅（访问 GitHub API 或 NVD API 建议配置对应 Token 以避免触发频率限制）。
