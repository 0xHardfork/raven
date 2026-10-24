---
trigger: always_on
---

# Python 采集脚本标准契约与分类规范

## 1. 运行与环境隔离
- 采集脚本均独立存放于 `scripts/` 目录。
- 脚本必须作为独立子进程被 Go 核心调度执行（通过 `exec.CommandContext`）。
- 依赖项统一维护在 `scripts/requirements.txt` 中，尽量精简，优先使用标准库或轻量网络库（如 `httpx`、`requests`、`beautifulsoup4`）。

## 2. 输入输出交互契约 (Stdin/Stdout JSON)
- **命令行参数**：脚本应支持标准命令行参数，例如 `--since 24h`、`--limit 50`。
- **输出格式**：
  - 成功时：**必须且仅在 stdout 输出符合 Schema 的 JSON 数组**。
  - 调试日志：任何调试、进度信息严禁打印到 stdout，必须输出至 **stderr**（`sys.stderr.write(...)` 或 `logging` 模块），避免污染 Go 的 JSON 解码管道。
  - 退出码：正常完成退出码为 `0`；异常失败非 0，并在 stderr 输出异常原因。
- **契约定义文件**：见 [contracts/scraper-schema.json](file:///Users/peigen/Documents/dev/0xHardfork/raven/specs/001-threat-collector/contracts/scraper-schema.json)。

### 2.1 字段约束规范与映射表
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

## 3. 自声明分类规则 (Taxonomy)
- 脚本输出的每个漏洞实体中，必须包含 `categories` 列表（例如 `["java", "spring"]` 或 `["golang"]`、`["php"]`）。
- 分类定义权完全归属于具体脚本作者，系统核心不干预篡改，直接索引归档入库。

## 4. 容错与超时机制
- 单次抓取必须设置 HTTP 请求超时（建议不超过 15 秒）。
- 具备基本的防风控意识：合理设置 User-Agent，控制并发与请求频次，避免触发目标数据源 IP 封禁。

## 5. 禁止对代码添加注释 所有代码要可以自解释