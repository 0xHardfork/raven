# Implementation Plan: 001-threat-collector

**Feature Directory**: `specs/001-threat-collector` | **Date**: 2026-10-24 | **Spec**: [spec.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/specs/001-threat-collector/spec.md)

**Input**: [spec.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/specs/001-threat-collector/spec.md) 结合 [ARCHITECTURE.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/ARCHITECTURE.md) 与 [.specify/memory/constitution.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/.specify/memory/constitution.md)

---

## Summary

构建 **Raven 威胁情报收集与预警工具** 的核心系统：
以 Golang 1.22+ 编写调度核心、数据聚合/去重与领域服务；
以 Python 3.10+ 子进程编写 4 大情报源（GitHub PoCs、CISA KEV、Exploit-DB、NVD）采集脚本，通过 Stdin/Stdout JSON 通信；
在 PostgreSQL 14+ 中建立基于 `cve_id` 唯一主键的幂等 Upsert 机制，对生态分类（`java`、`golang`、`php` 等）与 PoC 链接进行自动合并去重；
提供 CLI 命令行交互与 RESTful Web API 双接入层，以及 Slack Bot Block Kit 富文本预警推送。

---

## Technical Context

- **Language/Version**: Golang 1.22+ (核心调度与服务), Python 3.10+ (采集爬虫)
- **Primary Dependencies**:
  - Go: `github.com/spf13/cobra` (CLI), `github.com/gin-gonic/gin` (Web API), `github.com/lib/pq` 或 `pgx` (PostgreSQL), `github.com/charmbracelet/lipgloss` (终端美化)
  - Python: `httpx`, `beautifulsoup4`
- **Storage**: PostgreSQL 14+ (JSONB + GIN 索引加速 `categories TEXT[]`)
- **Testing**: Go 标准测试库 `testing`, `testify` (Mock Storage & Runner)
- **Target Platform**: macOS / Linux (单二进制可执行文件 + Docker 容器)
- **Project Type**: CLI 工具 + RESTful Web API 混合微服务
- **Performance Goals**: 10,000+ 漏洞检索 p95 < 100ms；子进程采集与入库单批耗时 < 10s；Slack 推送延迟 < 3s
- **Constraints**: 纯 Stdin/Stdout JSON 进程通信；零硬编码凭据；参数化防 SQL 注入

---

## Constitution Check

- [x] **I. Hexagonal Architecture**: Core 纯净独立，通过 `port` 抽象接口与 `adapter`（cli, api, postgres, runner, notifier）解耦。
- [x] **II. Script Contract**: Python 脚本作为子进程，只向 stdout 打印合法 JSON，自声明分类标签。
- [x] **III. CVE Upsert & Fusion**: 数据库使用 `ON CONFLICT (cve_id) DO UPDATE` 幂等合并分类并集与去重 PoC。
- [x] **IV. Dual First-Class Outputs**: 同时实现 CLI 与 Web API 双接入形态。
- [x] **V. Multi-Channel Alerting**: `NotifierPort` 适配器架构，优先交付 Slack Bot，预留企微/飞书/钉钉。
- [x] **VI. Quality & Security**: 参数化防 SQL 注入，零硬编码敏感凭据。

---

## Project Structure

```text
raven/
├── cmd/
│   └── raven/
│       └── main.go                         # 应用程序唯一入口
├── configs/
│   ├── config.example.yaml                 # 配置文件模板
│   └── config.yaml                         # (git-ignored) 本地配置文件
├── internal/
│   ├── adapter/
│   │   ├── cli/                            # Driving Adapter: 终端命令行
│   │   │   ├── root.go
│   │   │   ├── collect.go
│   │   │   ├── query.go
│   │   │   ├── query.go
│   │   │   ├── watch.go
│   │   │   ├── server.go
│   │   │   └── migrate.go                  # Flyway 式数据库一键初始化/迁移命令
│   │   ├── api/                            # Driving Adapter: RESTful Web API
│   │   │   ├── router.go
│   │   │   └── handler/
│   │   │       ├── threat.go
│   │   │       └── collector.go
│   │   ├── storage/
│   │   │   └── postgres/                   # Driven Adapter: PostgreSQL 持久化
│   │   │       ├── db.go
│   │   │       ├── migrator.go             # 嵌入式版本化迁移引擎 (Flyway 风格)
│   │   │       └── repository.go
│   │   ├── runner/
│   │   │   └── python/                     # Driven Adapter: Python 子进程管道
│   │   │       └── runner.go
│   │   └── notifier/                       # Driven Adapter: 告警推送
│   │       ├── notifier.go                 # 多通道分发 Manager
│   │       └── slack/                      # Slack Block Kit 推送
│   │           └── slack.go
│   ├── core/
│   │   ├── domain/                         # 领域核心实体
│   │   │   ├── vulnerability.go
│   │   │   ├── poc.go
│   │   │   └── filter.go
│   │   ├── port/                           # 核心输入输出接口
│   │   │   ├── repository.go
│   │   │   ├── runner.go
│   │   │   └── notifier.go
│   │   └── service/                        # 核心业务用例
│   │       ├── threat_service.go
│   │       ├── collector_service.go
│   │       └── watcher_service.go
│   └── pkg/
│       ├── config/                         # 配置读取
│       └── logger/                         # 结构化日志
├── migrations/                             # Flyway 风格版本化 SQL 迁移文件
│   ├── 000001_init_vulnerabilities.up.sql  # 初始 DDL (表结构与 GIN 索引)
│   └── 000001_init_vulnerabilities.down.sql
├── scripts/                                # Python 采集脚本
│   ├── requirements.txt
│   ├── github_pocs.py
│   ├── cisa_kev.py
│   ├── exploit_db.py
│   └── nvd_cve.py
├── docker-compose.yaml                     # 本地一键启动 PostgreSQL
├── go.mod
├── go.sum
└── README.md
```
