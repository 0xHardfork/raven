package cli

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	"raven/internal/adapter/notifier"
	"raven/internal/adapter/runner/python"
	"raven/internal/adapter/storage/postgres"
	"raven/internal/core/port"
	"raven/internal/core/service"
)

var (
	watchInterval string
	watchCategory string
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Start background scheduled inspection and alert watcher daemon",
	Long:  "Periodically poll threat intelligence sources, evaluate alert rules, and dispatch notifications via Slack.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		interval := cfg.Watcher.ParseInterval()
		if watchInterval != "" {
			d, err := time.ParseDuration(watchInterval)
			if err == nil && d >= time.Second {
				interval = d
			}
		}

		var categories []string
		if watchCategory != "" {
			for _, c := range strings.Split(watchCategory, ",") {
				if t := strings.TrimSpace(c); t != "" {
					categories = append(categories, t)
				}
			}
		} else if len(cfg.Watcher.Categories) > 0 {
			categories = cfg.Watcher.Categories
		} else if len(cfg.Notifier.AllTargetCategories()) > 0 {
			categories = cfg.Notifier.AllTargetCategories()
		}

		runner := python.NewRunner(cfg.Python, cfg.Scrapers)

		var repo port.RepositoryPort
		db, err := sql.Open("postgres", cfg.Database.DSN())
		if err == nil {
			pingCtx, pingCancel := context.WithTimeout(ctx, 2*time.Second)
			if err := db.PingContext(pingCtx); err == nil {
				repo = postgres.NewRepository(db)
				defer db.Close()
			}
			pingCancel()
		}

		notifierMgr := notifier.NewManager(cfg.Notifier)

		collectorSvc := service.NewCollectorService(runner, repo, notifierMgr)
		watcherSvc := service.NewWatcherService(collectorSvc, notifierMgr)

		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4"))
		infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00D7D7"))

		fmt.Println(titleStyle.Render("Raven Threat Watcher daemon starting..."))
		fmt.Println(infoStyle.Render(fmt.Sprintf("  • Interval:   %s", interval)))
		fmt.Println(infoStyle.Render(fmt.Sprintf("  • Categories: %v", categories)))
		if cfg.Notifier.DryRun {
			fmt.Println(infoStyle.Render("  • Mode:       Dry-Run (terminal preview, no outbound webhook)"))
		} else {
			fmt.Println(infoStyle.Render("  • Mode:       Live Notifications (Slack)"))
		}
		fmt.Println("Press Ctrl+C to stop...")

		if err := watcherSvc.Start(ctx, interval, categories); err != nil && err != context.Canceled {
			return err
		}

		fmt.Println("\nRaven Watcher stopped gracefully.")
		return nil
	},
}

func init() {
	watchCmd.Flags().StringVarP(&watchInterval, "interval", "i", "", "polling interval (e.g. 1m, 15m, 1h)")
	watchCmd.Flags().StringVarP(&watchCategory, "category", "k", "", "filter categories for watcher (e.g. java,golang)")
	RootCmd.AddCommand(watchCmd)
}
