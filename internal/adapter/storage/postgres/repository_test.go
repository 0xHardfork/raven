package postgres

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"raven/internal/core/domain"
)

func getTestDB(t *testing.T) *sql.DB {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "host=127.0.0.1 port=5432 user=postgres password=postgres dbname=raven sslmode=disable"
	}

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Skip("PostgreSQL open failed, skipping integration test")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		t.Skip("PostgreSQL not running locally, skipping integration test")
		return nil
	}
	return db
}

func TestRepositoryUpsertAndMerge(t *testing.T) {
	db := getTestDB(t)
	if db == nil {
		return
	}
	defer db.Close()

	ctx := context.Background()
	migrator := NewMigrator(db)
	_, _ = migrator.Up(ctx)

	repo := NewRepository(db)

	cve := "CVE-2099-9999"
	v1 := &domain.Vulnerability{
		CveID:       cve,
		Title:       "Test Spring RCE",
		Severity:    domain.SeverityHigh,
		Categories:  []string{"java", "spring"},
		Sources:     []string{"github_pocs"},
		PoCs:        []domain.PoC{{URL: "https://github.com/poc1"}},
		IsExploited: false,
	}

	if err := repo.UpsertVuln(ctx, v1); err != nil {
		t.Fatalf("first upsert failed: %v", err)
	}

	v2 := &domain.Vulnerability{
		CveID:       cve,
		Title:       "Test Spring RCE Exploit in Wild",
		Severity:    domain.SeverityCritical,
		Categories:  []string{"java", "framework"},
		Sources:     []string{"cisa_kev"},
		PoCs:        []domain.PoC{{URL: "https://github.com/poc1"}, {URL: "https://github.com/poc2"}},
		IsExploited: true,
	}

	if err := repo.UpsertVuln(ctx, v2); err != nil {
		t.Fatalf("second upsert failed: %v", err)
	}

	fetched, err := repo.GetByCVE(ctx, cve)
	if err != nil {
		t.Fatalf("get by cve failed: %v", err)
	}
	if fetched == nil {
		t.Fatalf("fetched record should not be nil")
	}

	if !fetched.IsExploited {
		t.Errorf("expected is_exploited=true")
	}

	if fetched.Severity != domain.SeverityCritical {
		t.Errorf("expected severity=CRITICAL, got %s", fetched.Severity)
	}

	if len(fetched.PoCs) != 2 {
		t.Errorf("expected 2 PoCs, got %d", len(fetched.PoCs))
	}

	_, _ = db.ExecContext(ctx, "DELETE FROM vulnerabilities WHERE cve_id = $1;", cve)
}
