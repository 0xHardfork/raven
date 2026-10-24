# 🦅 Raven (Threat Intelligence & Vulnerability/PoC Collector)

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Python Version](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat&logo=python)](https://www.python.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat&logo=postgresql)](https://www.postgresql.org)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Raven** is a high-performance open-source threat intelligence (CTI/OSINT) collection and aggregation system designed for Security Response Centers (SRCs), red/blue teaming, and security researchers.

The system focuses on multi-source monitoring and aggregation of global **CVE disclosures, GitHub PoC source code, CISA KEV in-the-wild exploitation tags, and Exploit-DB exploits**. Built with Golang Hexagonal Architecture (Ports & Adapters), it incorporates modular Python scraper pipelines (JSON Stdin/Stdout) and PostgreSQL GIN inverted indexing for tag retrieval and idempotent upsert on `cve_id`.

---

## 🌟 Key Features

- **Hexagonal Architecture**: Domain models and core services are completely decoupled from external adapters (PostgreSQL, CLI, Web API, Slack).
- **Non-Intrusive Scraper Pipeline**: Golang core orchestrates Python scrapers via subprocess `stdout` JSON pipes, with execution logs isolated to `stderr`.
- **Self-Declared Ecosystem Taxonomy**: Scrapers identify and output technical ecosystem tags (e.g. `java`, `golang`, `php`, `spring`, `wordpress`), which are indexed via PostgreSQL GIN arrays.
- **Atomic Upsert & Merge**: Multi-source collision resolution on identical `cve_id` automatically unions category tags, appends deduplicated PoC URLs, and updates severity and in-the-wild status.
- **Flyway-Style Versioned Migrations**: Embedded `//go:embed` SQL migration engine supporting `raven migrate up/status` with zero external dependencies.
- **Dual Drivers & Alerting**:
  - **CLI**: Interactive terminal interface powered by Cobra and Lipgloss (Table, JSON, and Markdown rendering).
  - **RESTful Web API**: Standard HTTP API built on Gin supporting multi-dimensional filtering, pagination, and asynchronous ingestion triggers.
  - **Slack Bot**: Block Kit rich card notifications with rule-based filtering (minimum severity, PoC availability, and category whitelist).

---

## 🏗️ Architecture Overview

```
                       [ Driving Adapters ]
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
 [ Cobra CLI ]             [ Gin REST API ]        [ Cron Watcher ]
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                  [ Core Domain & Services ]
                  - Vulnerability / PoC / Filter
                  - CollectorService / ThreatQueryService
                                │
        ┌───────────────────────┼───────────────────────┐
        │                       │                       │
        ▼                       ▼                       ▼
 [ Python Runner ]      [ PostgreSQL Repository ]   [ Slack Notifier ]
 (Stdout JSON Pipe)     (Upsert Merge & GIN Index)  (Block Kit Alert)
                                │
                       [ Driven Adapters ]
```

---

## 🚀 Quickstart

### 1. Prerequisites

- **Go**: 1.22+
- **Python**: 3.10+
- **Docker & Docker Compose**: For local PostgreSQL setup

Install Python scraper dependencies:
```bash
pip3 install -r scripts/requirements.txt
```

### 2. Start PostgreSQL Database

Use the optimized development `docker-compose.yaml`, with `./migrations` mounted to `/docker-entrypoint-initdb.d`:

```bash
docker compose up -d
```

### 3. Run Database Migrations

Use Raven's built-in migration engine to initialize or check database schema status:

```bash
# Build binary
go build -o bin/raven ./cmd/raven

# Check migration status
./bin/raven migrate status

# Apply all pending migrations
./bin/raven migrate up
```

### 4. Dry-Run / Offline Mode

Raven supports `--dry-run` to test collection and query workflows offline without database or network tokens:

```bash
# Dry-run full collection with preview
./bin/raven collect --dry-run

# Dry-run collection filtered by category and source
./bin/raven collect --dry-run --source github --category java
```

---

## 💻 CLI Usage

```bash
# View global help
./bin/raven --help

# 1. Ingest threat intelligence from external sources
./bin/raven collect                                      # Collect from all sources
./bin/raven collect --source cisa_kev                    # Ingest specific source
./bin/raven collect --category java,spring               # Filter by ecosystem
./bin/raven collect --dry-run                            # Offline dry-run

# 2. Query threat intelligence
./bin/raven query --category java                        # Filter by category
./bin/raven query --cve CVE-2024-4577                    # Exact CVE query
./bin/raven query --severity CRITICAL --has-poc          # Filter Critical with PoC
./bin/raven query --format json                          # Output as JSON
./bin/raven query --format markdown                      # Output as Markdown table

# 3. Watcher daemon and live alert monitoring
./bin/raven watch --interval 10m                         # Poll every 10 minutes
./bin/raven watch --dry-run                              # Terminal preview of alerts

# 4. Start RESTful Web API HTTP server
./bin/raven server --port 8080                           # Listen on port 8080
```

---

## 🌐 RESTful Web API Specification

Start the API server:
```bash
./bin/raven server --port 8080
```

### Endpoints

| Method | Path | Description | Parameters / Payload |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Health check probe | None |
| `GET` | `/api/v1/threats` | Query threat list | `?category=java&has_poc=true&severity=CRITICAL&page=1&limit=20&keyword=...` |
| `GET` | `/api/v1/threats/:cve_id` | Get single threat detail | Path parameter: `cve_id` (e.g. `CVE-2024-4577`) |
| `GET` | `/api/v1/threats/categories` | List all categories with count | None |
| `GET` | `/api/v1/stats` | Global dashboard statistics | Total CVE count, Critical count, PoC count, categories |
| `POST` | `/api/v1/collect/trigger` | Trigger async collection job | `{"source": "github", "categories": ["java"]}` |
| `GET` | `/api/v1/collect/status` | Query background job status | None |

### Curl Examples

```bash
# 1. Query Critical Java vulnerabilities with public PoCs
curl -s "http://localhost:8080/api/v1/threats?category=java&has_poc=true&severity=CRITICAL" | jq .

# 2. Query vulnerability details by CVE
curl -s "http://localhost:8080/api/v1/threats/CVE-2024-4577" | jq .

# 3. View global threat statistics
curl -s "http://localhost:8080/api/v1/stats" | jq .

# 4. Trigger asynchronous GitHub PoC collection
curl -X POST "http://localhost:8080/api/v1/collect/trigger" \
     -H "Content-Type: application/json" \
     -d '{"source": "github", "categories": ["java"]}'

# 5. Check collection job status
curl -s "http://localhost:8080/api/v1/collect/status" | jq .
```

---

## 🐍 Python Scraper Contract

Adding new threat source scrapers requires adhering to the **Stdin/Stdout JSON Contract**:

1. **Location**: Place scripts in the `scripts/` directory (e.g. `scripts/my_source.py`).
2. **Parameters**: Support `--mock` (offline testing) and `--categories` (category filtering).
3. **Stdout**: Output **only** a valid JSON array; no debug text on stdout.
4. **Stderr**: Route all logs, errors, and debug messages to `sys.stderr`.
5. **Self-Declared Categories**: Scrapers declare extracted `categories` tags.

### JSON Schema Contract Example

```json
[
  {
    "cve_id": "CVE-2024-4577",
    "title": "PHP-CGI Remote Code Execution Vulnerability",
    "description": "Bypass character encoding in Windows PHP-CGI module leading to command injection.",
    "severity": "CRITICAL",
    "cvss_score": 9.8,
    "categories": ["php", "windows"],
    "is_exploited": true,
    "pocs": [
      {
        "url": "https://github.com/watchtowrlabs/CVE-2024-4577",
        "description": "WatchTowr Labs proof of concept exploit",
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

## ⚙️ Configuration (`configs/config.yaml`)

Reference `configs/config.example.yaml`:

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

## 🧪 Testing

```bash
# Run all unit tests
go test -v ./...

# Verify Python scraper contracts
python3 scripts/github_pocs.py --mock > /dev/null
python3 scripts/cisa_kev.py --mock > /dev/null
python3 scripts/exploit_db.py --mock > /dev/null
python3 scripts/nvd_cve.py --mock > /dev/null
```

---

## 📄 License

Apache License 2.0. Detailed in [LICENSE](LICENSE).
