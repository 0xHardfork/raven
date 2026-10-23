package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"raven/internal/adapter/api"
	"raven/internal/core/domain"
	"raven/internal/core/port"
	"raven/internal/core/service"
)

// mockRepo 模拟持久层接口用于 API 测试
type mockRepo struct {
	vulns []*domain.Vulnerability
}

var _ port.RepositoryPort = (*mockRepo)(nil)

func (m *mockRepo) UpsertVuln(ctx context.Context, vuln *domain.Vulnerability) error {
	m.vulns = append(m.vulns, vuln)
	return nil
}

func (m *mockRepo) BatchUpsert(ctx context.Context, vulns []*domain.Vulnerability) (int, int, error) {
	m.vulns = append(m.vulns, vulns...)
	return len(vulns), 0, nil
}

func (m *mockRepo) GetByCVE(ctx context.Context, cveID string) (*domain.Vulnerability, error) {
	for _, v := range m.vulns {
		if v.CveID == cveID {
			return v, nil
		}
	}
	return nil, nil
}

func (m *mockRepo) Query(ctx context.Context, filter domain.ThreatFilter) (*domain.PaginationResult[*domain.Vulnerability], error) {
	var items []*domain.Vulnerability
	for _, v := range m.vulns {
		if filter.CveID != "" && v.CveID != filter.CveID {
			continue
		}
		items = append(items, v)
	}
	return &domain.PaginationResult[*domain.Vulnerability]{
		Total:    int64(len(items)),
		Page:     filter.Page,
		PageSize: filter.PageSize,
		Items:    items,
	}, nil
}

func (m *mockRepo) ListCategories(ctx context.Context) ([]domain.CategoryCount, error) {
	return []domain.CategoryCount{
		{Category: "java", Count: 10},
		{Category: "golang", Count: 5},
	}, nil
}

func (m *mockRepo) GetStats(ctx context.Context) (*domain.SystemStats, error) {
	return &domain.SystemStats{
		TotalVulnerabilities: 15,
		TotalPoCs:            8,
		TotalExploited:       2,
		CriticalCount:        4,
		HighCount:            7,
		TopCategories: []domain.CategoryCount{
			{Category: "java", Count: 10},
		},
	}, nil
}

func (m *mockRepo) Close() error {
	return nil
}

func TestRouterEndpoints(t *testing.T) {
	cvss := 9.8
	repo := &mockRepo{
		vulns: []*domain.Vulnerability{
			{
				CveID:       "CVE-2024-4577",
				Title:       "PHP CGI Argument Injection",
				Severity:    domain.SeverityCritical,
				CvssScore:   &cvss,
				Categories:  []string{"php"},
				IsExploited: true,
			},
		},
	}

	threatSvc := service.NewThreatQueryService(repo)
	router := api.SetupRouter(api.RouterConfig{
		ThreatService: threatSvc,
		Debug:         false,
	})

	t.Run("Health check /health", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/health", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Query threats /api/v1/threats", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/threats", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		var resp struct {
			Code int `json:"code"`
			Data struct {
				Total int64                   `json:"total"`
				Items []*domain.Vulnerability `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to unmarshal response: %v", err)
		}
		if resp.Data.Total != 1 {
			t.Errorf("expected 1 item, got %d", resp.Data.Total)
		}
	})

	t.Run("Get single threat detail /api/v1/threats/:cve_id", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/threats/CVE-2024-4577", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Get not found threat", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/threats/CVE-9999-0000", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", w.Code)
		}
	})

	t.Run("Get categories /api/v1/threats/categories", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/threats/categories", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})

	t.Run("Get stats /api/v1/stats", func(t *testing.T) {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodGet, "/api/v1/stats", nil)
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
	})
}
