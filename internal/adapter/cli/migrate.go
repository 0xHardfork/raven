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
	Short: "Database versioned migration and initialization tool",
	Long:  "Manage PostgreSQL schema versions, execute initial schema setup, and view migration history.",
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Execute all pending SQL migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		db, err := sql.Open("postgres", cfg.Database.DSN())
		if err != nil {
			return fmt.Errorf("connect postgres error: %w", err)
		}
		defer db.Close()

		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("ping postgres error: %w (ensure PostgreSQL is running and accessible)", err)
		}

		migrator := postgres.NewMigrator(db)
		applied, err := migrator.Up(ctx)
		if err != nil {
			return fmt.Errorf("migration up failed: %w", err)
		}

		successStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#04B575"))
		if applied == 0 {
			fmt.Println(successStyle.Render("✔ Database schema is up to date."))
		} else {
			fmt.Println(successStyle.Render(fmt.Sprintf("✔ Successfully applied %d migrations.", applied)))
		}
		return nil
	},
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "View current database migration history and pending versions",
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
		fmt.Println(titleStyle.Render("=== Database Migration Schema History ==="))

		for _, r := range applied {
			fmt.Printf(" [APPLIED] Version %06d: %-30s (duration: %dms, at: %s)\n",
				r.Version, r.Name, r.ExecutionMs, r.AppliedAt.Format("2006-01-02 15:04:05"))
		}

		warnStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#FFA500"))
		for _, p := range pending {
			fmt.Println(warnStyle.Render(fmt.Sprintf(" [PENDING] Version %06d (run 'raven migrate up' to apply)", p)))
		}

		if len(pending) == 0 && len(applied) > 0 {
			successStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#04B575"))
			fmt.Println(successStyle.Render("All migrations are up to date."))
		}
		return nil
	},
}

func init() {
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	RootCmd.AddCommand(migrateCmd)
}
