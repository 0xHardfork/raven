# Tasks: 001-threat-collector

**Input**: [spec.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/specs/001-threat-collector/spec.md), [plan.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/specs/001-threat-collector/plan.md), [ARCHITECTURE.md](file:///Users/peigen/Documents/dev/0xHardfork/raven/ARCHITECTURE.md)

---

## Phase 1: Setup & Foundational Infrastructure

**Purpose**: 初始化 Go 核心环境、基础配置与数据持久层基础设施

- [x] T001 Initialize Go 1.22+ module (`go.mod`) with dependencies (`cobra`, `gin-gonic/gin`, `lib/pq`, `lipgloss`, `golang-migrate/migrate` or embedded migration engine)
- [x] T002 [P] Implement configuration parser in `internal/pkg/config/config.go` and provide template `configs/config.example.yaml`
- [x] T003 [P] Implement structured logger in `internal/pkg/logger/logger.go`
- [x] T004 Create Core domain entities in `internal/core/domain/`: `vulnerability.go`, `poc.go`, `filter.go`
- [x] T005 Create Core Port interfaces in `internal/core/port/`: `repository.go`, `runner.go`, `notifier.go`
- [x] T006 Provide `docker-compose.yaml` to spin up PostgreSQL 14+ locally with preconfigured volume and credentials
- [x] T007 Implement Flyway-style versioned migrations in `migrations/` (`000001_init_vulnerabilities.up.sql`) and embedded migrator in `internal/adapter/storage/postgres/migrator.go` (tracking migration history, auto-migration on boot)
- [x] T008 Implement `raven migrate` CLI command in `internal/adapter/cli/migrate.go` (`raven migrate up`, `down`, `status` for one-click dev DB initialization)
- [x] T009 Implement PostgreSQL connection pool & schema verification in `internal/adapter/storage/postgres/db.go`

---

## Phase 2: User Story 1 - 多源情报采集与 CVE 聚合入库 (Priority: P1) 🎯 MVP Core

**Goal**: 实现以 CVE 唯一键为核心的幂等合并存储，并建立 Go-Python 管道

- [x] T010 [US1] Implement Upsert & Merge in `internal/adapter/storage/postgres/repository.go` (union of categories, dedup append PoCs, update severity & exploited status)
- [x] T011 [US1] Write unit tests for PostgreSQL repository Upsert & Merge logic in `internal/adapter/storage/postgres/repository_test.go`
- [x] T012 [US1] Implement Python Subprocess IPC Runner in `internal/adapter/runner/python/runner.go` (Stdout JSON pipe, Stderr log isolation, Context timeout)
- [x] T013 [US1] Implement CollectorService in `internal/core/service/collector_service.go` coordinating runners and repository persistence

---

## Phase 3: User Story 5 & 1 - 内置 4 大数据源 Python 采集脚本 (Priority: P1/P3)

**Goal**: 编写符合自声明分类协议的 4 大开源威胁数据源采集脚本

- [x] T014 [P] [US1/US5] Create `scripts/requirements.txt` with minimal dependencies (`httpx`, `beautifulsoup4`)
- [x] T015 [P] [US1/US5] Implement GitHub PoC scraper in `scripts/github_pocs.py` (auto-tagging `java`, `golang`, `php`, etc. based on repo metadata)
- [x] T016 [P] [US1/US5] Implement CISA KEV synchronization script in `scripts/cisa_kev.py` (tagging `kev`, `exploited`)
- [x] T017 [P] [US1/US5] Implement Exploit-DB scraper in `scripts/exploit_db.py`
- [x] T018 [P] [US1/US5] Implement NVD/CVE metadata scraper in `scripts/nvd_cve.py`

---

## Phase 4: User Story 2 - 终端交互与即时检索 CLI (Priority: P1) 🎯 MVP Delivery

**Goal**: 交付可直接使用的命令行工具，支持一键采集与终端彩色格式检索

- [x] T019 [US2] Implement ThreatQueryService in `internal/core/service/threat_service.go` (multi-dimensional filter, search by CVE/category/severity/has_poc)
- [x] T020 [US2] Implement Cobra Root command & `cmd/raven/main.go`
- [x] T021 [US2] Implement `raven collect` command in `internal/adapter/cli/collect.go` (supports `--source`, `--category`, `--script`)
- [x] T022 [US2] Implement `raven query` command in `internal/adapter/cli/query.go` with Lipgloss table, JSON, and Markdown formatting

---

## Phase 5: User Story 4 - 告警推送与守护监听 (Priority: P2)

**Goal**: 实现 Slack Bot Block Kit 富文本预警卡片与后台巡检模式

- [x] T023 [US4] Implement Slack Notifier adapter in `internal/adapter/notifier/slack/slack.go` (Block Kit rich card layout)
- [x] T024 [US4] Implement NotifierManager in `internal/adapter/notifier/notifier.go` with rule filter (min_severity, only_with_poc, category filter)
- [x] T025 [US4] Implement WatcherService in `internal/core/service/watcher_service.go` (scheduled interval polling and alerting on new threats)
- [x] T026 [US4] Implement `raven watch` command in `internal/adapter/cli/watch.go`

---

## Phase 6: User Story 3 - 标准 RESTful Web API 服务 (Priority: P2)

**Goal**: 暴露标准 HTTP REST 接口，支持服务化调用

- [x] T027 [US3] Setup Gin HTTP engine and router in `internal/adapter/api/router.go`
- [x] T028 [US3] Implement Threat Handlers in `internal/adapter/api/handler/threat.go` (`GET /api/v1/threats`, `GET /api/v1/threats/:cve_id`, `GET /api/v1/threats/categories`, `GET /api/v1/stats`)
- [x] T029 [US3] Implement Collector Handler in `internal/adapter/api/handler/collector.go` (`POST /api/v1/collect/trigger`, `GET /api/v1/collect/status`)
- [x] T030 [US3] Implement `raven server` command in `internal/adapter/cli/server.go`

---

## Phase 7: Verification & Quickstart

**Goal**: 端到端验证与工程交付

- [x] T031 Create `README.md` with installation, PostgreSQL setup, CLI usage, and Web API documentation
- [x] T032 End-to-end integration test (collect sample data, verify Postgres Upsert, query via CLI, query via Web API, test Slack alert mock)
