# 🦅 Raven (威胁情报与漏洞 PoC 聚合工具)

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python)](https://www.python.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat&logo=postgresql)](https://www.postgresql.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Raven** 是一套面向企业安全响应中心（SRC）、红蓝对抗团队与安全研究人员的高性能开源威胁情报（CTI/OSINT）收集系统。

系统专注于全球最新 **CVE 披露、GitHub PoC 源码、CISA KEV 在野利用标记以及 Exploit-DB 成果** 的多源监控与聚合。核心引擎采用 Golang 六边形架构（Hexagonal Architecture）构建，爬虫模块采用即插即用的自声明 Python 脚本管道（JSON Stdin/Stdout），存储基于 PostgreSQL GIN 倒排索引实现标签检索与基于 `cve_id` 的幂等合并（Upsert）。

---

## 🌟 核心特性 (Key Features)

- **六边形架构解耦 (Hexagonal Architecture)**：业务领域模型（Domain）完全独立于外部协议与存储适配器，具备极高的扩展性与可维护性。
- **无侵入式采集管道 (Zero-Intrusion Pipeline)**：Go 核心引擎与 Python 采集脚本通过子进程 `stdout` JSON 管道解耦，日志严格隔离至 `stderr`，支持自包含离线 Mock 演练。
- **自声明技术生态分类 (Self-Declared Taxonomy)**：爬虫脚本自主识别并输出技术生态标签（如 `java`, `golang`, `php`, `spring`, `wordpress`），Go 核心引擎予以忠实保留并建立 GIN 倒排索引。
- **原子幂等合并 (Atomic Upsert & Merge)**：同 CVE 多源碰撞时，自动合并分类标签并集、去重追加最新 PoC 链接、动态更新在野利用状态与危害评级。
- **Flyway 式版本化数据库迁移**：内置 `//go:embed` 迁移引擎，支持单行命令 `raven migrate up/status/down`，开发环境开箱即用。
- **多端触达与告警 (Dual Drivers & Rich Alerts)**：
  - **CLI**：基于 Cobra 与 Lipgloss 的现代化全彩交互式终端（表格、JSON、Markdown 多格式渲染）。
  - **Web API**：基于 Gin 构建的标准 RESTful 服务，支持多维过滤、分页与异步触发采集。
  - **Slack Bot**：Block Kit 富文本卡片推送，支持规则引擎过滤（最低评级、必须含 PoC、技术栈白名单、Dry-Run 演练）。

---

## 🏗️ 架构拓扑 (Architecture Overview)

```
                       [ 驱动适配器 (Driving Adapters) ]
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
      [ Cobra CLI ]             [ Gin REST API ]        [ Cron Watcher ]
              │                       │                       │
              └───────────────────────┼───────────────────────┘
                                      ▼
                        [ 核心业务域 (Domain & Services) ]
                        - Vulnerability / PoC / Filter
                        - CollectorService / ThreatQueryService
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
              ▼                       ▼                       ▼
    [ Python Runner ]      [ PostgreSQL Repository ]   [ Slack Notifier ]
    (Stdout JSON Pipe)     (Upsert Merge & GIN Index)  (Block Kit Alert)
                                      │
                       [ 被驱动适配器 (Driven Adapters) ]
```

---

## 🚀 快速上手 (Quickstart)

### 1. 运行环境准备

- **Go**: 1.22 及以上版本
- **Python**: 3.10 及以上版本
- **Docker & Docker Compose**: 用于一键启动 PostgreSQL 数据库

安装 Python 采集脚本依赖：
```bash
pip3 install -r scripts/requirements.txt
```

### 2. 一键启动本地数据库

项目根目录下提供了针对开发环境优化的 `docker-compose.yaml`，已自动挂载 `./migrations` 目录至 `/docker-entrypoint-initdb.d`：

```bash
docker compose up -d
```

### 3. 执行数据库迁移 (Flyway 风格)

使用 Raven 内置的迁移引擎快速初始化或检查数据库表结构：

```bash
# 编译二进制工具
go build -o bin/raven ./cmd/raven

# 查看当前迁移版本状态
./bin/raven migrate status

# 执行向前迁移至最新版本
./bin/raven migrate up
```

### 4. 离线/演练模式 (无需数据库即可体验)

Raven 全面支持 `--dry-run` 标志，在无数据库、无网络 Token 环境下使用内置高质量威胁数据集进行端到端演练：

```bash
# 演练全量采集并预览聚合威胁
./bin/raven collect --dry-run

# 演练仅采集 Java 相关的 GitHub PoC
./bin/raven collect --dry-run --source github --category java
```

---

## 💻 CLI 命令手册 (CLI Usage)

```bash
# 查看全局帮助
./bin/raven --help

# 1. 触发数据源采集 (入库)
./bin/raven collect                                      # 全量采集入库
./bin/raven collect --source cisa_kev                    # 采集指定源
./bin/raven collect --category java,spring               # 仅采集指定分类
./bin/raven collect --dry-run                            # 离线演练不写库

# 2. 威胁情报多维检索
./bin/raven query --category java                        # 检索包含 Java 标签的漏洞
./bin/raven query --cve CVE-2024-4577                    # 精准查询特定 CVE 详情
./bin/raven query --severity CRITICAL --has-poc          # 查询含有 PoC 的严重级别漏洞
./bin/raven query --format json                          # 以结构化 JSON 格式输出
./bin/raven query --format markdown                      # 输出为 Markdown 报表

# 3. 启动后台巡检监听与告警
./bin/raven watch --interval 10m                         # 每 10 分钟自动轮询采集一次
./bin/raven watch --dry-run                              # 演练监听并在终端打印 Slack 卡片预览

# 4. 启动 RESTful Web API HTTP 服务
./bin/raven server --port 8080                           # 监听 8080 端口
```

---

## 🌐 Web API 端点规范 (RESTful Web API)

启动服务：
```bash
./bin/raven server --port 8080
```

### 接口清单

| 请求方式 | 路径 | 功能说明 | 请求参数 / Body |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | 健康检查探针 | 无 |
| `GET` | `/api/v1/threats` | 多维查询漏洞列表 | `?category=java&has_poc=true&severity=CRITICAL&page=1&limit=20&keyword=...` |
| `GET` | `/api/v1/threats/:cve_id` | 获取单条漏洞详情 | 路径参数：`cve_id` (如 `CVE-2024-4577`) |
| `GET` | `/api/v1/threats/categories` | 获取当前所有已分类标签及计数 | 无 |
| `GET` | `/api/v1/stats` | 总体威胁数据大盘统计 | 包含总 CVE 数、高危占比、有 PoC 数量、各语言分类占比 |
| `POST` | `/api/v1/collect/trigger` | 异步触发即时采集任务 | `{"source": "github", "categories": ["java"]}` |
| `GET` | `/api/v1/collect/status` | 查询当前后台采集任务状态 | 无 |

### API 调用示例

```bash
# 1. 查询严重级别且有 PoC 的 Java 漏洞
curl -s "http://localhost:8080/api/v1/threats?category=java&has_poc=true&severity=CRITICAL" | jq .

# 2. 查询单个 CVE 完整漏洞与 PoC 详情
curl -s "http://localhost:8080/api/v1/threats/CVE-2024-4577" | jq .

# 3. 查看威胁大盘统计
curl -s "http://localhost:8080/api/v1/stats" | jq .

# 4. 异步触发 GitHub PoC 采集任务
curl -X POST "http://localhost:8080/api/v1/collect/trigger" \
     -H "Content-Type: application/json" \
     -d '{"source": "github", "categories": ["java"]}'

# 5. 查看采集任务运行状态
curl -s "http://localhost:8080/api/v1/collect/status" | jq .
```

---

## 🐍 Python 爬虫扩展契约 (Scraper Contract)

编写新数据源采集脚本仅需遵循 **标准输入/输出 JSON 契约**：

1. **放置目录**：将脚本放置于 `scripts/` 目录下（如 `scripts/my_source.py`）。
2. **标准输入/参数**：支持 `--mock`（离线演练）与 `--categories`（可选技术分类过滤）。
3. **标准输出 (Stdout)**：**必须且仅输出** 合法的 JSON 数组；严禁输出调试文本。
4. **日志隔离 (Stderr)**：所有过程日志、报错、调试信息必须输出至 `sys.stderr`。
5. **自声明分类**：脚本必须根据规则自主声明提取的 `categories` 标签列表。

### 数据项 JSON 契约范例

```json
[
  {
    "cve_id": "CVE-2024-4577",
    "title": "PHP-CGI 远程代码执行漏洞",
    "description": "Windows 环境下 PHP-CGI 模块最佳字符集编码绕过漏洞，导致参数注入与 RCE。",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "categories": ["php", "windows"],
    "is_exploited": true,
    "pocs": [
      {
        "url": "https://github.com/watchtowrlabs/CVE-2024-4577",
        "description": "WatchTowr Labs 概念验证 Exploit",
        "author": "watchtowrlabs",
        "source": "github",
        "stars": 340
      }
    ],
    "sources": ["github", "cisa_kev"],
    "published_at": "2024-06-06T00:00:00Z"
  }
]
```

---

## ⚙️ 配置文件说明 (`configs/config.yaml`)

参考 `configs/config.example.yaml`：

```yaml
app:
  env: "production"
  log_level: "INFO"

database:
  host: "127.0.0.1"
  port: 5432
  user: "postgres"
  password: "password"
  dbname: "raven"
  ssl_mode: "disable"

python:
  binary_path: "python3"
  scripts_dir: "scripts"
  timeout_sec: 120

notifier:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/xxx/yyy/zzz"
    channel: "#security-threats"
  rules:
    min_severity: "HIGH"
    only_with_poc: false
    category_whitelist: []
  dry_run: false

watcher:
  interval: "30m"
  categories: []
```

---

## 🧪 单元测试与验证 (Testing)

```bash
# 运行全套单元测试
go test -v ./...

# 验证所有 Python 脚本契约
python3 scripts/github_pocs.py --mock > /dev/null
python3 scripts/cisa_kev.py --mock > /dev/null
python3 scripts/exploit_db.py --mock > /dev/null
python3 scripts/nvd_cve.py --mock > /dev/null
```

---

## 📄 License

Apache License 2.0. Detailed in [LICENSE](LICENSE).
