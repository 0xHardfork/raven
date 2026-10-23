# Raven 威胁收集工具 (CTI / Vulnerability & PoC Intelligence) 设计方案

## 1. 项目愿景与定位

**Raven** 是一套高性能、可扩展的开源威胁情报（CTI）与漏洞/PoC 收集分析工具。
专注于监控、聚合和结构化存储全球最新的 **CVE 披露、GitHub PoC、CISA 在野利用 (KEV) 与 Exploit-DB 成果**。
支持按语言/生态分类（如 Java、Golang、PHP 等）智能归档，并通过松耦合架构同时提供 **命令行（CLI）** 与 **Web API** 两种核心输出交互能力，并可进一步扩展 MCP (AI Agent) 协议。

---

## 2. 总体技术栈与协作模式

| 层次 | 技术选型 | 说明 |
| :--- | :--- | :--- |
| **主控核心引擎** | **Golang** (Go 1.22+) | 负责调度管道、数据聚合/去重、PostgreSQL 存储、配置管理 |
| **爬虫与特定采集源** | **Python 3.10+** | 负责动态解析、网络爬虫、复杂文本清洗，以独立脚本存在 |
| **进程间通信 (IPC)** | **Subprocess + Stdin/Stdout JSON** | Go 动态调用 Python 脚本，以 JSON 流管道交互，无常驻端口占用 |
| **存储基础设施** | **PostgreSQL** | 统一数据持久化存储，支持 JSONB、全文检索，预留 pgvector 向量检索能力 |
| **输出接入层 1: CLI** | **Cobra + Lipgloss/Bubbletea** | 优雅终端交互、一键采集与多维筛选、常驻监控、彩色格式输出 |
| **输出接入层 2: Web API** | **Gin / Fiber REST API** | 提供标准 HTTP REST 接口，支持情报检索、分页、分类查询与触发采集 |
| **告警与通知推送层** | **Notifier (Slack Bot)** | 首发支持 Slack Bot (Block Kit 富文本)，预留企业微信、飞书、钉钉、邮件接口 |

---

## 3. 系统架构设计 (Ports & Adapters / 六边形架构)

系统的核心业务逻辑与外部接入完全解耦，**CLI** 与 **Web API** 作为对等的 Driving Adapters 接入同一套 Core Service；**PostgreSQL**、**Python 爬虫执行器** 与 **推送适配器 (Slack 等)** 作为 Driven Adapters 支撑业务：

```
                    ┌─────────────────────────┐
                    │    Driving Adapters     │
                    │   (接入层 - 核心输出形态)  │
                    ├───────────┬─────────────┤
                    │ CLI Cobra │   Web API   │
                    │ (命令行交互)│ (REST 接口) │
                    ├───────────┴─────────────┤
                    │  (未来可扩: MCP Server)  │
                    └─────┬─────────────┬─────┘
                          │            │
                          ▼            ▼
             ┌────────────────────────────────────┐
             │       Inbound Ports (接口)         │
             │   - CollectorService               │
             │   - ThreatQueryService             │
             │   - WatcherService                 │
             └────────────────┬───────────────────┘
                              │
                              ▼
             ┌────────────────────────────────────┐
             │            Core Domain             │
             │   - Vulnerability / PoC Entity     │
             │   - Aggregator & Deduplication     │
             │   - Category & Tag Normalizer      │
             └────────────────┬───────────────────┘
                              │
                              ▼
             ┌────────────────────────────────────┐
             │       Outbound Ports (接口)        │
             │   - StorageRepository (Postgres)   │
             │   - ScriptRunner (Python IPC)      │
             │   - NotifierPort (Alerts)          │
             └────────────────┬───────────────────┘
                              │
                    ┌─────────┴─────────────────────────┐
                    │          Driven Adapters          │
                    │       (存储、执行与外部推送)       │
                    ├────────────┬────────────┬─────────┤
                    │ PostgreSQL │ Python IPC │ Notifier│
                    │ Repository │   Runner   │ (Slack) │
                    └────────────┴────────────┴─────────┘
```

---

## 4. 目录组织结构

```
raven/
├── cmd/
│   └── raven/
│       └── main.go                 # 程序入口
├── configs/
│   └── config.example.yaml         # 配置文件模板（DB连接、Token、调度周期）
├── internal/
│   ├── adapter/
│   │   ├── cli/                    # 命令行接入层 (Cobra 子命令定义: collect, query, watch, server)
│   │   │   ├── root.go
│   │   │   ├── collect.go
│   │   │   ├── query.go
│   │   │   ├── watch.go
│   │   │   └── server.go           # 启动 Web API 服务的子命令
│   │   ├── api/                    # Web API 接入层 (Gin/HTTP 路由与控制器)
│   │   │   ├── router.go
│   │   │   └── handler/
│   │   │       ├── threat.go       # 威胁情报检索、详情、统计 Handler
│   │   │       └── collector.go    # 触发即时采集 Handler
│   │   ├── mcp/                    # (预留) Model Context Protocol Adapter
│   │   ├── storage/
│   │   │   └── postgres/           # PostgreSQL 数据持久化驱动
│   │   ├── runner/
│   │   │   └── python/             # Python 子进程执行器 (JSON 管道通信)
│   │   └── notifier/               # 告警与通知推送层 (Driven Adapter)
│   │       ├── notifier.go         # 统一推送分发 Manager
│   │       ├── slack/              # Slack Bot / Webhook 推送实现
│   │       │   └── slack.go
│   │       ├── wechat/             # (预留) 企业微信机器人
│   │       ├── feishu/             # (预留) 飞书机器人
│   │       ├── dingtalk/           # (预留) 钉钉机器人
│   │       └── email/              # (预留) 邮件通知
│   ├── core/
│   │   ├── domain/                 # 核心实体 (Vulnerability, PoC, SourceRecord)
│   │   ├── port/                   # 抽象接口 (Repository, ScriptRunner, Service)
│   │   └── service/                # 核心业务逻辑 (采集调度、聚合去重、查询)
│   └── pkg/
│       ├── config/                 # 配置解析
│       └── logger/                 # 统一日志
├── scripts/                        # 可扩展收集脚本目录 (Python)
│   ├── github_pocs.py              # GitHub PoC 监控脚本
│   ├── cisa_kev.py                 # CISA KEV 官方已知在野利用同步
│   ├── exploit_db.py               # Exploit-DB 采集脚本
│   └── nvd_cve.py                  # NVD/CVE 元数据采集
├── go.mod
├── go.sum
└── README.md
```

---

## 5. 脚本标准协议与分类机制 (Script Contract)

任何放置在 `scripts/` 下的 Python 脚本，只需遵循以下输入输出规范即可被 Raven 自动发现并执行：

### 5.1 脚本执行规范
```bash
python scripts/my_custom_script.py --since 24h
```

### 5.2 脚本输出 JSON Schema (Stdout)
```json
[
  {
    "cve_id": "CVE-2024-4577",
    "title": "PHP CGI Argument Injection Remote Code Execution",
    "description": "PHP CGI argument injection vulnerability leading to arbitrary code execution...",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "categories": ["php", "rce", "cgi"],
    "pocs": [
      {
        "url": "https://github.com/example/cve-2024-4577-poc",
        "author": "example",
        "description": "PoC exploit for CVE-2024-4577",
        "published_at": "2024-06-07T12:00:00Z"
      }
    ],
    "is_exploited": true,
    "source": "github_pocs",
    "published_at": "2024-06-07T00:00:00Z",
    "raw_data": {
      "stars": 128
    }
  }
]
```

### 5.3 字段约束与契约定义
契约 JSON Schema 校验文件位于：[contracts/scraper-schema.json](file:///Users/peigen/Documents/dev/0xHardfork/raven/specs/001-threat-collector/contracts/scraper-schema.json)

| 字段名 | 类型 | 必填 | 说明与示例 |
| :--- | :--- | :---: | :--- |
| `cve_id` | `string` | **是** | 大写标准 CVE 格式，如 `"CVE-2024-4577"`（系统聚合主键） |
| `title` | `string` | **是** | 漏洞标题或利用简述 |
| `description` | `string` | 否 | 漏洞详细描述（无则填 `""`） |
| `severity` | `string` | 否 | 评级：`"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"LOW"`, `"UNKNOWN"` |
| `cvss_score` | `float` | 否 | `0.0 ~ 10.0` 浮点数，无评分时可为 `null` |
| `categories` | `string[]`| **是** | **自声明生态分类**，如 `["java", "spring"]`、`["golang"]`、`["php"]` |
| `is_exploited` | `bool` | 否 | 是否在野被利用（CISA KEV 源填 `true`，其他源默认 `false`） |
| `pocs` | `object[]`| 否 | PoC 列表，每项含 `url` (必填), `author`, `description`, `published_at` |
| `source` | `string` | **是** | 采集源标识，如 `"github_pocs"`, `"cisa_kev"`, `"exploit_db"`, `"nvd"` |
| `published_at` | `string` | 否 | ISO8601 时间戳，如 `"2024-06-07T00:00:00Z"` |
| `raw_data` | `object` | 否 | 原始扩展键值对字典（用于审计追溯） |

> **分类规则遵循用户要求**：纯脚本自声明分类。脚本输出中的 `categories` 字段（如 `["java", "spring"]` 或 `["php"]`）由 Go 核心原样入库索引，不作二次强制修改。

---

## 6. 数据存储模型 (PostgreSQL)

### 6.1 核心漏洞主表 (`vulnerabilities`)
```sql
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(64) UNIQUE NOT NULL,      -- 主键/唯一聚合键
    title TEXT NOT NULL,
    description TEXT,
    severity VARCHAR(32),                    -- CRITICAL, HIGH, MEDIUM, LOW
    cvss_score NUMERIC(3, 1),
    categories TEXT[] DEFAULT '{}',          -- 语言与生态标签 (如 ['java', 'spring'])
    is_exploited BOOLEAN DEFAULT FALSE,      -- 是否已在野被利用 (CISA KEV 标记)
    pocs JSONB DEFAULT '[]'::jsonb,          -- 聚合的 PoC 列表 (去重追加)
    sources TEXT[] DEFAULT '{}',             -- 涉及的情报源 (github, cisa, exploit-db...)
    raw_data JSONB DEFAULT '{}'::jsonb,
    published_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_vuln_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vuln_categories ON vulnerabilities USING GIN (categories);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_exploited ON vulnerabilities(is_exploited);
```

### 6.2 聚合合并规则 (Upsert & Merge)
当多脚本采集到相同 `CVE-xxxx` 时：
1. **分类合并**：`categories = array_cat_unique(old.categories, new.categories)`
2. **PoC 追加**：按 PoC URL 去重后追加至 `pocs` 数组。
3. **评级覆盖**：若新记录存在更准确的 CVSS/Severity 则更新。
### 6.3 数据库版本化迁移与一键初始化 (Flyway 风格)
借鉴 Java 生态 **Flyway** 的设计思想，Raven 采用标准版本化迁移（Versioned Migrations）管理数据库生命周期：
1. **版本化 SQL 脚本目录 (`migrations/`)**：
   - 命名规范：`000001_init_vulnerabilities.up.sql`（创建表与索引）、`000001_init_vulnerabilities.down.sql`（回滚）。
   - 内嵌至二进制：使用 Go `embed.FS` 将 SQL 文件编译进二进制，实现单文件独立运行无外部文件依赖。
2. **迁移版本记录表 (`schema_migrations`)**：
   - 对应 Flyway 的 `flyway_schema_history`，自动记录当前应用的 migration version、脏状态（dirty flag）与执行耗时。
3. **开发环境与部署初始化方案**：
   - **方式 A（CLI 一键迁移）**：`raven migrate up` 执行未完成的迁移，`raven migrate status` 查看迁移状态。
   - **方式 B（Docker 一键挂载）**：`docker-compose.yaml` 将 `migrations/` 映射到 `/docker-entrypoint-initdb.d`，本地 `docker compose up` 启动 Postgres 时自动完成建表。
   - **方式 C（启动自检）**：服务启动时支持自动执行轻量级迁移校验。

---

## 7. CLI 命令设计

```bash
# 1. 数据库版本迁移与初始化 (Flyway 式一键初始化)
raven migrate up          # 应用所有待执行的 SQL 迁移
raven migrate status      # 查看当前数据库版本与迁移记录
raven migrate down 1      # 回滚上一个版本 (开发调试用)

# 2. 执行一键采集 (支持全源或指定源/脚本/分类)
raven collect
raven collect --source github
raven collect --script scripts/github_pocs.py --category java

# 3. 终端情报检索与多维筛选
raven query --cve CVE-2024-4577
raven query --category java --has-poc --severity CRITICAL
raven query --keyword "Spring Cloud" --output table    # 支持 table / json / markdown

# 4. 定时轮询守护模式
raven watch --interval 15m --category java,golang

# 5. 启动 Web API 服务
raven server --port 8080 --host 0.0.0.0
```

---

## 8. Web API 接口设计 (RESTful)

Web API 与 CLI 共享底层的 `ThreatQueryService` 与 `CollectorService`，对外提供标准的 JSON REST API：

| HTTP 方法 | 接口路径 | 描述 | 请求参数 / Body |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/threats` | 多维查询漏洞列表 | `?category=java&has_poc=true&severity=CRITICAL&page=1&limit=20&keyword=...` |
| `GET` | `/api/v1/threats/:cve_id` | 获取单条漏洞详情 | 路径参数：`cve_id` (如 `CVE-2024-4577`) |
| `GET` | `/api/v1/threats/categories` | 获取当前所有已分类标签及计数 | 无 |
| `GET` | `/api/v1/stats` | 总体威胁数据大盘统计 | 包含总 CVE 数、高危占比、有 PoC 数量、各语言分类占比 |
| `POST` | `/api/v1/collect/trigger` | 异步触发即时采集任务 | `{"source": "github", "categories": ["java"]}` |
| `GET` | `/api/v1/collect/status` | 查询当前后台采集任务状态 | 无 |

## 9. 推送与告警层设计 (Notification Layer)

Raven 提供高度可配置的告警推送机制，用于在 `raven watch` 周期巡检发现新漏洞、新 PoC 或通过 API/CLI 触发采集后，及时向团队群聊发送富文本预警。

### 9.1 接口抽象 (`NotifierPort`)
```go
type NotifierPort interface {
    // 发送单条高危威胁预警
    SendThreatAlert(ctx context.Context, vuln *domain.Vulnerability) error
    // 批量发送摘要预警
    SendBatchAlert(ctx context.Context, vulns []*domain.Vulnerability) error
}
```

### 9.2 首发支持：Slack Bot (Block Kit 富文本卡片)
- **接入形式**：支持 Slack Incoming Webhook 或 Slack Bot User OAuth Token (`chat.postMessage`)。
- **消息结构**：
  - **Header**：🚨 `[CRITICAL/HIGH]` CVE 编号 + 漏洞简述
  - **Fields**：
    - 危险评级：`CVSS 9.8 (CRITICAL)`
    - 生态分类：`java` / `spring` / `golang`
    - 在野利用：`CISA KEV 确认`
    - 首发情报源：`GitHub / Exploit-DB`
  - **PoC Section**：直接附带可点击的 PoC 仓库/代码链接。
  - **Actions**：可点击跳转至 NVD 详情页或本地 Web API 详情链接。

### 9.3 告警过滤规则配置 (`config.yaml`)
支持按需配置告警策略，防止低危漏洞产生告警风暴：
```yaml
notifier:
  enabled: true
  min_severity: "HIGH"           # 最低告警级别：CRITICAL | HIGH | MEDIUM | LOW
  only_with_poc: false           # 是否仅在存在有效 PoC 时推送
  always_notify_exploited: true  # 命中 CISA KEV (在野利用) 无论等级无条件推送
  filter_categories:             # 仅关注特定技术栈 (为空则不过滤)
    - "java"
    - "golang"
    - "php"
  channels:
    slack:
      enabled: true
      webhook_url: "https://hooks.slack.com/services/xxx/yyy/zzz"
      channel: "#security-threats"
      bot_token: ""              # 可选
    # 未来可扩展通道
    wechat:
      enabled: false
      webhook_url: ""
    feishu:
      enabled: false
      webhook_url: ""
    dingtalk:
      enabled: false
      webhook_url: ""
      secret: ""
    email:
      enabled: false
      smtp_host: ""
      to: []
```

### 9.4 多渠道分发架构
由 `NotifierManager` 实现 `NotifierPort`，根据配置文件中各通道的 `enabled` 状态，采用并发 Goroutine 向激活的通道扇出分发，任一外部通道网络抖动不阻塞核心采集流程。

---

## 10. 未来接入层演进规划

- **MCP Server Adapter (`internal/adapter/mcp`)**：直接注册为 Claude Desktop / Cursor / Antigravity 的 Tool（如 `raven_search_threats`, `raven_collect`），允许大模型在对话中直接查阅最新威胁。
