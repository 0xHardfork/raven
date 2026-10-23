-- 000001_init_vulnerabilities.down.sql
-- 回滚脚本：删除索引与表

DROP INDEX IF EXISTS idx_vuln_published_at;
DROP INDEX IF EXISTS idx_vuln_exploited;
DROP INDEX IF EXISTS idx_vuln_severity;
DROP INDEX IF EXISTS idx_vuln_categories;
DROP INDEX IF EXISTS idx_vuln_cve;
DROP TABLE IF EXISTS vulnerabilities;
