package service

import (
	"context"
	"fmt"
	"strings"

	"raven/internal/core/domain"
	"raven/internal/core/port"
)

type ThreatQueryService struct {
	repo port.RepositoryPort
}

func NewThreatQueryService(repo port.RepositoryPort) *ThreatQueryService {
	return &ThreatQueryService{repo: repo}
}

func (s *ThreatQueryService) GetThreat(ctx context.Context, cveID string) (*domain.Vulnerability, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("cve_id cannot be empty")
	}
	return s.repo.GetByCVE(ctx, cveID)
}

func (s *ThreatQueryService) SearchThreats(ctx context.Context, filter domain.ThreatFilter) (*domain.PaginationResult[*domain.Vulnerability], error) {
	if filter.Page <= 0 {
		filter.Page = 1
	}
	if filter.PageSize <= 0 {
		filter.PageSize = 20
	} else if filter.PageSize > 100 {
		filter.PageSize = 100
	}
	return s.repo.Query(ctx, filter)
}

func (s *ThreatQueryService) GetCategories(ctx context.Context) ([]domain.CategoryCount, error) {
	return s.repo.ListCategories(ctx)
}

func (s *ThreatQueryService) GetStats(ctx context.Context) (*domain.SystemStats, error) {
	return s.repo.GetStats(ctx)
}
