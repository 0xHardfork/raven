package cli

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	"raven/internal/adapter/storage/postgres"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Flyway 风格的数据库版本化迁移与一键初始化工具",
	Long:  "管理 PostgreSQL 数据库表结构版本，支持一键执行初始建表、索引创建及迁移状态查看。",
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "一键执行所有待处理的 SQL 迁移",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		db, err := sql.Open("postgres", cfg.Database.DSN())
		if err != nil {
			return fmt.Errorf("connect postgres error: %w", err)
		}
		defer db.Close()

		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("ping postgres error: %w (请确保 PostgreSQL 已启动并配置正确)", err)
		}

		migrator := postgres.NewMigrator(db)
		applied, err := migrator.Up(ctx)
		if err != nil {
			return fmt.Errorf("migration up failed: %w", err)
		}

		successStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#04B575"))
		if applied == 0 {
			fmt.Println(successStyle.Render("✔ 数据库已是最新版本，无需执行迁移。"))
		} else {
			fmt.Println(successStyle.Render(fmt.Sprintf("✔ 成功应用 %d 个迁移版本，数据库初始化完成！", applied)))
		}
		return nil
	},
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "查看当前数据库迁移历史与待执行版本",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		db, err := sql.Open("postgres", cfg.Database.DSN())
		if err != nil {
			return fmt.Errorf("connect postgres error: %w", err)
		}
		defer db.Close()

		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("ping postgres error: %w", err)
		}

		migrator := postgres.NewMigrator(db)
		applied, pending, err := migrator.Status(ctx)
		if err != nil {
			return fmt.Errorf("check status failed: %w", err)
		}

		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4"))
		fmt.Println(titleStyle.Render("=== 数据库迁移状态 (Schema History) ==="))

		for _, r := range applied {
			fmt.Printf(" [已应用] 版本 %06d: %-30s (耗时: %dms, 时间: %s)\n",
				r.Version, r.Name, r.ExecutionMs, r.AppliedAt.Format("2006-01-02 15:04:05"))
		}

		warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500"))
		for _, p := range pending {
			fmt.Println(warnStyle.Render(fmt.Sprintf(" [待执行] 版本 %06d (执行 'raven migrate up' 应用)", p)))
		}

		if len(pending) == 0 && len(applied) > 0 {
			successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575"))
			fmt.Println(successStyle.Render("所有迁移均已正确应用。"))
		}
		return nil
	},
}

func init() {
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	RootCmd.AddCommand(migrateCmd)
}
