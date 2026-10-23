package domain

import "time"

// PoC 代表针对特定漏洞的概念验证或利用代码实体
type PoC struct {
	URL         string     `json:"url"`
	Author      string     `json:"author,omitempty"`
	Description string     `json:"description,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}
