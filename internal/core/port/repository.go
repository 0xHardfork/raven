package port

import (
	"context"

	"raven/internal/core/domain"
)

// RepositoryPort 数据持久化存储接口
type RepositoryPort interface {
	// UpsertVuln 幂等合并保存单条漏洞（合并分类并集、去重追加 PoC、更新危害评级与在野利用状态）
	UpsertVuln(ctx context.Context, vuln *domain.Vulnerability) error

	// BatchUpsert 批量幂等合并保存漏洞列表
	BatchUpsert(ctx context.Context, vulns []*domain.Vulnerability) (inserted int, updated int, err error)

	// GetByCVE 按唯一 CVE 编号查询单条漏洞详情
	GetByCVE(ctx context.Context, cveID string) (*domain.Vulnerability, error)

	// Query 根据多维过滤条件分页检索漏洞
	Query(ctx context.Context, filter domain.ThreatFilter) (*domain.PaginationResult[*domain.Vulnerability], error)

	// ListCategories 获取当前数据库中已存在的所有分类标签及对应漏洞数
	ListCategories(ctx context.Context) ([]domain.CategoryCount, error)

	// GetStats 获取全局威胁大盘指标统计
	GetStats(ctx context.Context) (*domain.SystemStats, error)

	// Close 关闭数据库连接池
	Close() error
}
