package domain

// ThreatFilter 威胁情报多维检索过滤条件
type ThreatFilter struct {
	CveID       string   // 特定 CVE 编号精准搜索
	Keyword     string   // 标题或描述全文关键词模糊匹配
	Categories  []string // 技术生态分类筛选 (如 java, golang, php)
	Severity    string   // 危害等级过滤
	HasPoC      *bool    // 是否过滤存在 PoC 的漏洞
	IsExploited *bool    // 是否过滤已在野利用漏洞 (CISA KEV)
	Source      string   // 特定情报源过滤
	Page        int      // 分页页码 (从 1 开始)
	PageSize    int      // 每页数量 (默认 20，最大 100)
}

// PaginationResult 统一分页结果包装结构
type PaginationResult[T any] struct {
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Items    []T   `json:"items"`
}

// CategoryCount 分类标签及关联漏洞数量
type CategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

// SystemStats 全局威胁统计大盘指标
type SystemStats struct {
	TotalVulnerabilities int64           `json:"total_vulnerabilities"`
	TotalPoCs            int64           `json:"total_pocs"`
	TotalExploited       int64           `json:"total_exploited"`
	CriticalCount        int64           `json:"critical_count"`
	HighCount            int64           `json:"high_count"`
	TopCategories        []CategoryCount `json:"top_categories"`
}
