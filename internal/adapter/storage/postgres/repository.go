package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"raven/internal/core/domain"
	"raven/internal/core/port"
)

// Repository PostgreSQL 存储库实现
type Repository struct {
	db *sql.DB
}

var _ port.RepositoryPort = (*Repository)(nil)

// NewRepository 创建持久化存储库
func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

// Close 关闭连接池
func (r *Repository) Close() error {
	return r.db.Close()
}

// UpsertVuln 幂等合并插入/更新单条漏洞
func (r *Repository) UpsertVuln(ctx context.Context, vuln *domain.Vulnerability) error {
	if r == nil || r.db == nil {
		return nil
	}
	vuln.Normalize()

	pocsJSON, err := json.Marshal(vuln.PoCs)
	if err != nil {
		pocsJSON = []byte("[]")
	}

	rawDataJSON, err := json.Marshal(vuln.RawData)
	if err != nil {
		rawDataJSON = []byte("{}")
	}

	// 核心 Upsert & Merge SQL：
	// 1. categories 取并集去重
	// 2. pocs 按 url 唯一键去重追加
	// 3. sources 取并集去重
	// 4. is_exploited 只要有任一源确认即为 true
	query := `
	INSERT INTO vulnerabilities (
		cve_id, title, description, severity, cvss_score,
		categories, is_exploited, pocs, sources, raw_data,
		published_at, created_at, updated_at
	) VALUES (
		$1, $2, $3, $4, $5,
		$6, $7, $8::jsonb, $9, $10::jsonb,
		$11, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
	)
	ON CONFLICT (cve_id) DO UPDATE SET
		title = CASE WHEN EXCLUDED.title != '' THEN EXCLUDED.title ELSE vulnerabilities.title END,
		description = CASE WHEN EXCLUDED.description != '' THEN EXCLUDED.description ELSE vulnerabilities.description END,
		severity = CASE WHEN EXCLUDED.severity != 'UNKNOWN' THEN EXCLUDED.severity ELSE vulnerabilities.severity END,
		cvss_score = COALESCE(EXCLUDED.cvss_score, vulnerabilities.cvss_score),
		categories = (
			SELECT COALESCE(array_agg(DISTINCT elem), '{}')
			FROM unnest(vulnerabilities.categories || EXCLUDED.categories) AS elem
			WHERE elem != ''
		),
		is_exploited = vulnerabilities.is_exploited OR EXCLUDED.is_exploited,
		pocs = (
			SELECT COALESCE(jsonb_agg(p), '[]'::jsonb)
			FROM (
				SELECT DISTINCT ON (elem->>'url') elem as p
				FROM jsonb_array_elements(vulnerabilities.pocs || EXCLUDED.pocs) as elem
				WHERE elem->>'url' IS NOT NULL AND elem->>'url' != ''
			) s
		),
		sources = (
			SELECT COALESCE(array_agg(DISTINCT s), '{}')
			FROM unnest(vulnerabilities.sources || EXCLUDED.sources) AS s
			WHERE s != ''
		),
		raw_data = vulnerabilities.raw_data || EXCLUDED.raw_data,
		published_at = COALESCE(vulnerabilities.published_at, EXCLUDED.published_at),
		updated_at = CURRENT_TIMESTAMP
	RETURNING id, created_at, updated_at;
	`

	err = r.db.QueryRowContext(ctx, query,
		vuln.CveID,
		vuln.Title,
		vuln.Description,
		string(vuln.Severity),
		vuln.CvssScore,
		pq.Array(vuln.Categories),
		vuln.IsExploited,
		string(pocsJSON),
		pq.Array(vuln.Sources),
		string(rawDataJSON),
		vuln.PublishedAt,
	).Scan(&vuln.ID, &vuln.CreatedAt, &vuln.UpdatedAt)

	if err != nil {
		return fmt.Errorf("upsert vuln '%s' failed: %w", vuln.CveID, err)
	}
	return nil
}

// BatchUpsert 批量幂等更新漏洞列表
func (r *Repository) BatchUpsert(ctx context.Context, vulns []*domain.Vulnerability) (int, int, error) {
	if r == nil || r.db == nil || len(vulns) == 0 {
		return 0, 0, nil
	}

	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin batch upsert tx failed: %w", err)
	}
	defer tx.Rollback()

	inserted := 0
	updated := 0

	for _, v := range vulns {
		if err := r.UpsertVuln(ctx, v); err != nil {
			return inserted, updated, err
		}
		// 根据 created_at 和 updated_at 是否在同一毫秒判断是否为全新插入
		if v.UpdatedAt.Sub(v.CreatedAt) < 50*time.Millisecond {
			inserted++
		} else {
			updated++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit batch upsert failed: %w", err)
	}

	return inserted, updated, nil
}

// GetByCVE 按 CVE 编号精准查询
func (r *Repository) GetByCVE(ctx context.Context, cveID string) (*domain.Vulnerability, error) {
	cveID = strings.ToUpper(strings.TrimSpace(cveID))
	query := `
	SELECT id, cve_id, title, description, severity, cvss_score,
	       categories, is_exploited, pocs, sources, raw_data,
	       published_at, created_at, updated_at
	FROM vulnerabilities
	WHERE cve_id = $1;
	`
	row := r.db.QueryRowContext(ctx, query, cveID)

	v := &domain.Vulnerability{}
	var (
		severityStr string
		pocsBytes   []byte
		rawBytes    []byte
	)

	err := row.Scan(
		&v.ID, &v.CveID, &v.Title, &v.Description, &severityStr, &v.CvssScore,
		pq.Array(&v.Categories), &v.IsExploited, &pocsBytes, pq.Array(&v.Sources), &rawBytes,
		&v.PublishedAt, &v.CreatedAt, &v.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query vuln by cve '%s' failed: %w", cveID, err)
	}

	v.Severity = domain.NormalizeSeverity(severityStr)
	_ = json.Unmarshal(pocsBytes, &v.PoCs)
	_ = json.Unmarshal(rawBytes, &v.RawData)

	return v, nil
}

// Query 根据多维过滤条件分页查询
func (r *Repository) Query(ctx context.Context, filter domain.ThreatFilter) (*domain.PaginationResult[*domain.Vulnerability], error) {
	var whereClauses []string
	var args []any
	argIndex := 1

	if filter.CveID != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("cve_id = $%d", argIndex))
		args = append(args, strings.ToUpper(strings.TrimSpace(filter.CveID)))
		argIndex++
	}

	if filter.Keyword != "" {
		kw := "%" + strings.TrimSpace(filter.Keyword) + "%"
		whereClauses = append(whereClauses, fmt.Sprintf("(title ILIKE $%d OR description ILIKE $%d OR cve_id ILIKE $%d)", argIndex, argIndex, argIndex))
		args = append(args, kw)
		argIndex++
	}

	if len(filter.Categories) > 0 {
		whereClauses = append(whereClauses, fmt.Sprintf("categories && $%d", argIndex))
		args = append(args, pq.Array(filter.Categories))
		argIndex++
	}

	if filter.Severity != "" {
		whereClauses = append(whereClauses, fmt.Sprintf("severity = $%d", argIndex))
		args = append(args, strings.ToUpper(filter.Severity))
		argIndex++
	}

	if filter.HasPoC != nil {
		if *filter.HasPoC {
			whereClauses = append(whereClauses, "jsonb_array_length(pocs) > 0")
		} else {
			whereClauses = append(whereClauses, "jsonb_array_length(pocs) = 0")
		}
	}

	if filter.IsExploited != nil {
		whereClauses = append(whereClauses, fmt.Sprintf("is_exploited = $%d", argIndex))
		args = append(args, *filter.IsExploited)
		argIndex++
	}

	whereSQL := ""
	if len(whereClauses) > 0 {
		whereSQL = "WHERE " + strings.Join(whereClauses, " AND ")
	}

	// 1. 查询总条数
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM vulnerabilities %s", whereSQL)
	var total int64
	if err := r.db.QueryRowContext(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, fmt.Errorf("query total count failed: %w", err)
	}

	// 2. 分页处理
	page := filter.Page
	if page <= 0 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize <= 0 {
		pageSize = 20
	} else if pageSize > 100 {
		pageSize = 100
	}
	offset := (page - 1) * pageSize

	dataQuery := fmt.Sprintf(`
	SELECT id, cve_id, title, description, severity, cvss_score,
	       categories, is_exploited, pocs, sources, raw_data,
	       published_at, created_at, updated_at
	FROM vulnerabilities
	%s
	ORDER BY published_at DESC NULLS LAST, id DESC
	LIMIT $%d OFFSET $%d;`, whereSQL, argIndex, argIndex+1)

	args = append(args, pageSize, offset)

	rows, err := r.db.QueryContext(ctx, dataQuery, args...)
	if err != nil {
		return nil, fmt.Errorf("query vulnerabilities list failed: %w", err)
	}
	defer rows.Close()

	var items []*domain.Vulnerability
	for rows.Next() {
		v := &domain.Vulnerability{}
		var (
			severityStr string
			pocsBytes   []byte
			rawBytes    []byte
		)
		if err := rows.Scan(
			&v.ID, &v.CveID, &v.Title, &v.Description, &severityStr, &v.CvssScore,
			pq.Array(&v.Categories), &v.IsExploited, &pocsBytes, pq.Array(&v.Sources), &rawBytes,
			&v.PublishedAt, &v.CreatedAt, &v.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan vulnerability row failed: %w", err)
		}
		v.Severity = domain.NormalizeSeverity(severityStr)
		_ = json.Unmarshal(pocsBytes, &v.PoCs)
		_ = json.Unmarshal(rawBytes, &v.RawData)
		items = append(items, v)
	}

	return &domain.PaginationResult[*domain.Vulnerability]{
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		Items:    items,
	}, nil
}

// ListCategories 获取所有标签及数量
func (r *Repository) ListCategories(ctx context.Context) ([]domain.CategoryCount, error) {
	query := `
	SELECT unnest(categories) AS category, COUNT(*) AS count
	FROM vulnerabilities
	GROUP BY category
	ORDER BY count DESC, category ASC;`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query categories failed: %w", err)
	}
	defer rows.Close()

	var list []domain.CategoryCount
	for rows.Next() {
		var c domain.CategoryCount
		if err := rows.Scan(&c.Category, &c.Count); err != nil {
			return nil, fmt.Errorf("scan category row failed: %w", err)
		}
		list = append(list, c)
	}
	return list, nil
}

// GetStats 获取总体威胁统计大盘
func (r *Repository) GetStats(ctx context.Context) (*domain.SystemStats, error) {
	stats := &domain.SystemStats{}

	query := `
	SELECT 
		COUNT(*),
		COALESCE(SUM(jsonb_array_length(pocs)), 0),
		COUNT(*) FILTER (WHERE is_exploited = TRUE),
		COUNT(*) FILTER (WHERE severity = 'CRITICAL'),
		COUNT(*) FILTER (WHERE severity = 'HIGH')
	FROM vulnerabilities;`

	err := r.db.QueryRowContext(ctx, query).Scan(
		&stats.TotalVulnerabilities,
		&stats.TotalPoCs,
		&stats.TotalExploited,
		&stats.CriticalCount,
		&stats.HighCount,
	)
	if err != nil {
		return nil, fmt.Errorf("query system stats failed: %w", err)
	}

	categories, err := r.ListCategories(ctx)
	if err == nil {
		if len(categories) > 10 {
			stats.TopCategories = categories[:10]
		} else {
			stats.TopCategories = categories
		}
	}

	return stats, nil
}
