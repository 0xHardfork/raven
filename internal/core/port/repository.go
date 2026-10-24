package port

import (
	"context"

	"raven/internal/core/domain"
)

type RepositoryPort interface {
	UpsertVuln(ctx context.Context, vuln *domain.Vulnerability) error
	BatchUpsert(ctx context.Context, vulns []*domain.Vulnerability) (inserted int, updated int, err error)
	GetByCVE(ctx context.Context, cveID string) (*domain.Vulnerability, error)
	Query(ctx context.Context, filter domain.ThreatFilter) (*domain.PaginationResult[*domain.Vulnerability], error)
	ListCategories(ctx context.Context) ([]domain.CategoryCount, error)
	GetStats(ctx context.Context) (*domain.SystemStats, error)
	Close() error
}
