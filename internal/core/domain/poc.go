package domain

import "time"

type PoC struct {
	URL         string     `json:"url"`
	Author      string     `json:"author,omitempty"`
	Description string     `json:"description,omitempty"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
}
