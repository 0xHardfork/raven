package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"raven/internal/pkg/logger"
	"raven/migrations"
)

type MigrationRecord struct {
	Version     int64     `json:"version"`
	Name        string    `json:"name"`
	AppliedAt   time.Time `json:"applied_at"`
	ExecutionMs int64     `json:"execution_ms"`
}

type Migrator struct {
	db *sql.DB
}

func NewMigrator(db *sql.DB) *Migrator {
	return &Migrator{db: db}
}

func (m *Migrator) EnsureHistoryTable(ctx context.Context) error {
	query := `
	CREATE TABLE IF NOT EXISTS schema_migrations (
		version BIGINT PRIMARY KEY,
		name VARCHAR(255) NOT NULL,
		applied_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		execution_ms BIGINT DEFAULT 0
	);`
	_, err := m.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("ensure schema_migrations table failed: %w", err)
	}
	return nil
}

func (m *Migrator) GetAppliedVersions(ctx context.Context) (map[int64]MigrationRecord, error) {
	if err := m.EnsureHistoryTable(ctx); err != nil {
		return nil, err
	}

	query := `SELECT version, name, applied_at, execution_ms FROM schema_migrations ORDER BY version ASC;`
	rows, err := m.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query applied migrations failed: %w", err)
	}
	defer rows.Close()

	applied := make(map[int64]MigrationRecord)
	for rows.Next() {
		var r MigrationRecord
		if err := rows.Scan(&r.Version, &r.Name, &r.AppliedAt, &r.ExecutionMs); err != nil {
			return nil, fmt.Errorf("scan migration row failed: %w", err)
		}
		applied[r.Version] = r
	}
	return applied, nil
}

type migrationFile struct {
	version int64
	name    string
	upSQL   string
	downSQL string
}

func parseVersion(filename string) (int64, string, error) {
	base := filepath.Base(filename)
	parts := strings.SplitN(base, "_", 2)
	if len(parts) < 2 {
		return 0, "", fmt.Errorf("invalid migration filename: %s", filename)
	}
	v, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, "", fmt.Errorf("invalid version number in '%s': %w", filename, err)
	}
	name := strings.TrimSuffix(parts[1], ".up.sql")
	name = strings.TrimSuffix(name, ".down.sql")
	return v, name, nil
}

func loadMigrationFiles() ([]migrationFile, error) {
	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return nil, fmt.Errorf("read migrations embedded fs failed: %w", err)
	}

	fileMap := make(map[int64]*migrationFile)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}

		v, cleanName, err := parseVersion(name)
		if err != nil {
			continue
		}

		if _, exists := fileMap[v]; !exists {
			fileMap[v] = &migrationFile{version: v, name: cleanName}
		}

		content, err := fs.ReadFile(migrations.FS, name)
		if err != nil {
			return nil, fmt.Errorf("read embedded file %s failed: %w", name, err)
		}

		if strings.HasSuffix(name, ".up.sql") {
			fileMap[v].upSQL = string(content)
		} else if strings.HasSuffix(name, ".down.sql") {
			fileMap[v].downSQL = string(content)
		}
	}

	var list []migrationFile
	for _, mf := range fileMap {
		list = append(list, *mf)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].version < list[j].version
	})

	return list, nil
}

func (m *Migrator) Up(ctx context.Context) (int, error) {
	applied, err := m.GetAppliedVersions(ctx)
	if err != nil {
		return 0, err
	}

	files, err := loadMigrationFiles()
	if err != nil {
		return 0, err
	}

	appliedCount := 0
	for _, f := range files {
		if _, already := applied[f.version]; already {
			continue
		}

		start := time.Now()
		tx, err := m.db.BeginTx(ctx, nil)
		if err != nil {
			return appliedCount, fmt.Errorf("begin tx for migration %d failed: %w", f.version, err)
		}

		if _, err := tx.ExecContext(ctx, f.upSQL); err != nil {
			_ = tx.Rollback()
			return appliedCount, fmt.Errorf("execute migration %d (%s) failed: %w", f.version, f.name, err)
		}

		duration := time.Since(start).Milliseconds()
		insertRecord := `INSERT INTO schema_migrations (version, name, applied_at, execution_ms) VALUES ($1, $2, $3, $4);`
		if _, err := tx.ExecContext(ctx, insertRecord, f.version, f.name, time.Now(), duration); err != nil {
			_ = tx.Rollback()
			return appliedCount, fmt.Errorf("record migration history for %d failed: %w", f.version, err)
		}

		if err := tx.Commit(); err != nil {
			return appliedCount, fmt.Errorf("commit migration %d failed: %w", f.version, err)
		}

		logger.L().Info("migration applied successfully",
			"version", f.version,
			"name", f.name,
			"duration_ms", duration,
		)
		appliedCount++
	}

	return appliedCount, nil
}

func (m *Migrator) Status(ctx context.Context) ([]MigrationRecord, []int64, error) {
	applied, err := m.GetAppliedVersions(ctx)
	if err != nil {
		return nil, nil, err
	}

	files, err := loadMigrationFiles()
	if err != nil {
		return nil, nil, err
	}

	var appliedList []MigrationRecord
	var pendingList []int64

	for _, f := range files {
		if rec, ok := applied[f.version]; ok {
			appliedList = append(appliedList, rec)
		} else {
			pendingList = append(pendingList, f.version)
		}
	}

	return appliedList, pendingList, nil
}
