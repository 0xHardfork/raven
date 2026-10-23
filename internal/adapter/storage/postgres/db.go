package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	_ "github.com/lib/pq"
	"raven/internal/pkg/config"
	"raven/internal/pkg/logger"
)

// Connect 初始化 PostgreSQL 数据库连接池
func Connect(ctx context.Context, cfg config.DatabaseConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("open postgres connection failed: %w", err)
	}

	// 设置连接池参数
	maxOpen := cfg.MaxOpenConns
	if maxOpen <= 0 {
		maxOpen = 25
	}
	maxIdle := cfg.MaxIdleConns
	if maxIdle <= 0 {
		maxIdle = 5
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(30 * time.Minute)

	// 验证连通性
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres database failed: %w", err)
	}

	logger.L().Info("postgresql connected successfully",
		"host", cfg.Host,
		"port", cfg.Port,
		"dbname", cfg.DBName,
	)

	// 若开启了 auto_migrate，则执行 Flyway 风格自检与迁移
	if cfg.AutoMigrate {
		migrator := NewMigrator(db)
		count, err := migrator.Up(ctx)
		if err != nil {
			logger.L().Warn("auto migration warning", "error", err)
		} else if count > 0 {
			logger.L().Info("auto migration completed", "applied_count", count)
		}
	}

	return db, nil
}
