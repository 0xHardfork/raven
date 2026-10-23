package service

import (
	"context"
	"fmt"
	"strings"

	"raven/internal/core/domain"
	"raven/internal/core/port"
)

// ThreatQueryService 威胁情报多维检索服务
type ThreatQueryService struct {
	repo port.RepositoryPort
}

// NewThreatQueryService 创建威胁查询服务
func NewThreatQueryService(repo port.RepositoryPort) *ThreatQueryService {
	return &ThreatQueryService{repo: repo}
}

// GetThreat 根据唯一 CVE 编号获取完整威胁视图
func (s *ThreatQueryService) GetThreat(ctx context.Context, cveID string) (*domain.Vulnerability, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	if cveID == "" {
		return nil, fmt.Errorf("cve_id cannot be empty")
	}
	return s.repo.GetByCVE(ctx, cveID)
}

// SearchThreats 多维过滤分页检索威胁
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

// GetCategories 获取所有生态标签统计
func (s *ThreatQueryService) GetCategories(ctx context.Context) ([]domain.CategoryCount, error) {
	return s.repo.ListCategories(ctx)
}

// GetStats 获取全局威胁统计大盘
func (s *ThreatQueryService) GetStats(ctx context.Context) (*domain.SystemStats, error) {
	return s.repo.GetStats(ctx)
}
