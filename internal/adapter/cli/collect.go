package cli

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	"raven/internal/adapter/runner/python"
	"raven/internal/adapter/storage/postgres"
	"raven/internal/core/domain"
	"raven/internal/core/port"
	"raven/internal/core/service"
)

var (
	collectSource   string
	collectCategory string
	collectScript   string
	collectMock     bool
)

var collectCmd = &cobra.Command{
	Use:   "collect",
	Short: "Ingest threat intelligence and PoCs from external sources",
	Long: `Fetch latest vulnerability disclosures from GitHub PoCs, CISA KEV,
Exploit-DB, and NVD, categorizing by technical ecosystem and upserting into PostgreSQL.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		runner := python.NewRunner(cfg.Python)

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

		if repo == nil && !dryRun && !collectMock {
			return fmt.Errorf("unable to connect to PostgreSQL (DSN: %s); use --dry-run or --mock for offline mode", cfg.Database.DSN())
		}

		collectorSvc := service.NewCollectorService(runner, repo, nil)

		var categories []string
		if collectCategory != "" {
			for _, c := range strings.Split(collectCategory, ",") {
				if t := strings.TrimSpace(c); t != "" {
					categories = append(categories, t)
				}
			}
		}

		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4"))
		infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00D7D7"))
		successStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#04B575"))

		fmt.Println(titleStyle.Render("Raven Threat Collector starting..."))

		var (
			collected []*domain.Vulnerability
			summary   *service.CollectSummary
		)

		extraArgs := []string{}
		if dryRun || collectMock {
			extraArgs = append(extraArgs, "--mock")
			fmt.Println(infoStyle.Render("ℹ Running in dry-run/mock mode; using test dataset"))
		}

		if collectScript != "" {
			fmt.Printf("Executing script: %s\n", collectScript)
			vulns, err := runner.RunScript(ctx, collectScript, extraArgs...)
			if err != nil {
				return err
			}
			collected = vulns
		} else if collectSource != "" {
			fmt.Printf("Collecting from source: %s\n", collectSource)
			vulns, err := collectorSvc.CollectSource(ctx, collectSource, categories)
			if err != nil {
				return err
			}
			collected = vulns
		} else {
			fmt.Println("Collecting from all sources (GitHub PoCs, CISA KEV, Exploit-DB, NVD)...")
			res, err := collectorSvc.CollectAll(ctx, categories)
			if err != nil {
				return err
			}
			summary = res
			collected = res.Vulns
		}

		if repo != nil && len(collected) > 0 {
			ins, upd, err := repo.BatchUpsert(ctx, collected)
			if err != nil {
				return fmt.Errorf("database persistence failed: %w", err)
			}
			summary = &service.CollectSummary{
				TotalScripts: 1,
				TotalFound:   len(collected),
				Inserted:     ins,
				Updated:      upd,
			}
		} else if summary == nil {
			summary = &service.CollectSummary{
				TotalScripts: 1,
				TotalFound:   len(collected),
			}
		}

		fmt.Println("\n" + successStyle.Render("=== Collection Summary ==="))
		fmt.Printf("  • Scripts executed: %d\n", summary.TotalScripts)
		fmt.Printf("  • Total records:    %d\n", summary.TotalFound)
		if repo != nil {
			fmt.Printf("  • DB Inserted:      %d\n", summary.Inserted)
			fmt.Printf("  • DB Updated:       %d (merged categories/PoCs)\n", summary.Updated)
		} else {
			fmt.Println(infoStyle.Render("  • Storage:          [Skipped DB write - Dry-run mode]"))
		}

		if len(collected) > 0 {
			fmt.Println("\n" + titleStyle.Render("Recent Threats Preview (Top 3):"))
			for i, v := range collected {
				if i >= 3 {
					break
				}
				pocCount := len(v.PoCs)
				exploitedTag := ""
				if v.IsExploited {
					exploitedTag = " 🚨[EXPLOITED]"
				}
				fmt.Printf("  [%d] %s (%s)%s | Categories: %v | PoCs: %d\n      Title: %s\n",
					i+1, v.CveID, v.Severity, exploitedTag, v.Categories, pocCount, v.Title)
			}
		}

		return nil
	},
}

func init() {
	collectCmd.Flags().StringVarP(&collectSource, "source", "s", "", "filter by data source (e.g. github, cisa, exploitdb, nvd)")
	collectCmd.Flags().StringVarP(&collectCategory, "category", "k", "", "filter by ecosystem category (e.g. java,golang,php)")
	collectCmd.Flags().StringVar(&collectScript, "script", "", "execute specific scraper script path")
	collectCmd.Flags().BoolVar(&collectMock, "mock", false, "run with mock test dataset")
	RootCmd.AddCommand(collectCmd)
}
