package domain

type ThreatFilter struct {
	CveID       string
	Keyword     string
	Categories  []string
	Severity    string
	HasPoC      *bool
	IsExploited *bool
	Source      string
	Page        int
	PageSize    int
}

type PaginationResult[T any] struct {
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Items    []T   `json:"items"`
}

type CategoryCount struct {
	Category string `json:"category"`
	Count    int64  `json:"count"`
}

type SystemStats struct {
	TotalVulnerabilities int64           `json:"total_vulnerabilities"`
	TotalPoCs            int64           `json:"total_pocs"`
	TotalExploited       int64           `json:"total_exploited"`
	CriticalCount        int64           `json:"critical_count"`
	HighCount            int64           `json:"high_count"`
	TopCategories        []CategoryCount `json:"top_categories"`
}
