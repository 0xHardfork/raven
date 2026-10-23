# 安全防护与凭据合规规范 (Security & Compliance)

## 1. 凭据与敏感信息防泄露
- **禁止硬编码任何 Secret**：代码库中严禁包含任何明文密码、API Key、Token（如 GitHub Token、Slack Webhook URL、PostgreSQL 密码）。
- 所有敏感信息必须通过环境变量或受 `.gitignore` 保护的 `configs/config.yaml` 注入。
- 提交代码前，严防测试用例中夹带真实生产凭据。

## 2. 数据库与查询安全
- 严格使用参数化查询（Parameterized Queries / Prepared Statements），严禁直接拼接 SQL 字符串，坚决杜绝 SQL 注入隐患。
- GIN 数组索引字段查询使用 PostgreSQL 原生操作符（如 `@>`、`&&`）。

## 3. 网络请求与 SSRF 防护
- Python 爬虫和 Go HTTP 客户端只向受信任的白名单或官方情报 API 发起请求。
- 接收外部输入的 URL（如 PoC 链接验证）时，必须校验协议类型（仅允许 `http`、`https`），禁止访问内网保留 IP 地址（`127.0.0.1`、`10.0.0.0/8`、`192.168.0.0/16`、`172.16.0.0/12`、云厂商元数据服务 `169.254.169.254`）。
