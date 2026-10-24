CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    cve_id VARCHAR(64) UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    severity VARCHAR(32) DEFAULT 'UNKNOWN',
    cvss_score NUMERIC(3, 1),
    categories TEXT[] DEFAULT '{}',
    is_exploited BOOLEAN DEFAULT FALSE,
    pocs JSONB DEFAULT '[]'::jsonb,
    sources TEXT[] DEFAULT '{}',
    raw_data JSONB DEFAULT '{}'::jsonb,
    published_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vuln_categories ON vulnerabilities USING GIN (categories);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_exploited ON vulnerabilities(is_exploited);
CREATE INDEX IF NOT EXISTS idx_vuln_published_at ON vulnerabilities(published_at DESC NULLS LAST);
