package cli

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	"raven/internal/adapter/storage/postgres"
	"raven/internal/core/domain"
	"raven/internal/core/service"
)

var (
	queryCVE       string
	queryCategory  string
	querySeverity  string
	queryHasPoC    bool
	queryExploited bool
	queryKeyword   string
	queryOutput    string
	queryPage      int
	queryLimit     int
)

var queryCmd = &cobra.Command{
	Use:   "query",
	Short: "Query and inspect stored threat intelligence",
	Long: `Filter and inspect vulnerabilities by CVE ID, ecosystem categories,
CVSS severity, in-the-wild exploitation status, and PoC availability.
Supports Table, JSON, and Markdown output formats.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		db, err := sql.Open("postgres", cfg.Database.DSN())
		if err != nil {
			return fmt.Errorf("connect postgres error: %w", err)
		}
		defer db.Close()

		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("unable to connect to database: %w (start PostgreSQL or run 'raven migrate up')", err)
		}

		repo := postgres.NewRepository(db)
		threatSvc := service.NewThreatQueryService(repo)

		if queryCVE != "" {
			vuln, err := threatSvc.GetThreat(ctx, queryCVE)
			if err != nil {
				return err
			}
			if vuln == nil {
				fmt.Printf("No vulnerability record found for '%s'.\n", queryCVE)
				return nil
			}
			renderSingleVuln(vuln, queryOutput)
			return nil
		}

		filter := domain.ThreatFilter{
			Keyword:  queryKeyword,
			Severity: querySeverity,
			Page:     queryPage,
			PageSize: queryLimit,
		}

		if cmd.Flags().Changed("has-poc") {
			filter.HasPoC = &queryHasPoC
		}
		if cmd.Flags().Changed("exploited") {
			filter.IsExploited = &queryExploited
		}

		if queryCategory != "" {
			for _, c := range strings.Split(queryCategory, ",") {
				if t := strings.TrimSpace(c); t != "" {
					filter.Categories = append(filter.Categories, strings.ToLower(t))
				}
			}
		}

		result, err := threatSvc.SearchThreats(ctx, filter)
		if err != nil {
			return err
		}

		renderVulnList(result, queryOutput)
		return nil
	},
}

func renderSingleVuln(v *domain.Vulnerability, format string) {
	if strings.ToLower(format) == "json" {
		data, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(data))
		return
	}

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4"))
	cveStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D7D7"))
	labelStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#A0A0A0"))

	fmt.Println(titleStyle.Render("\n=== Threat Intelligence Details ==="))
	fmt.Printf("%s %s\n", labelStyle.Render("CVE ID:       "), cveStyle.Render(v.CveID))
	fmt.Printf("%s %s\n", labelStyle.Render("Title:        "), v.Title)
	fmt.Printf("%s %s\n", labelStyle.Render("Severity:     "), formatSeverity(v.Severity))
	if v.CvssScore != nil {
		fmt.Printf("%s %.1f\n", labelStyle.Render("CVSS Score:   "), *v.CvssScore)
	}
	fmt.Printf("%s %v\n", labelStyle.Render("Categories:   "), v.Categories)
	fmt.Printf("%s %t\n", labelStyle.Render("Exploited:    "), v.IsExploited)
	fmt.Printf("%s %v\n", labelStyle.Render("Sources:      "), v.Sources)
	if v.PublishedAt != nil {
		fmt.Printf("%s %s\n", labelStyle.Render("Published:    "), v.PublishedAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Printf("%s\n  %s\n", labelStyle.Render("Description:"), v.Description)

	fmt.Printf("\n%s (%d total):\n", labelStyle.Render("Available PoCs"), len(v.PoCs))
	if len(v.PoCs) == 0 {
		fmt.Println("  (No public exploit available)")
	} else {
		for i, p := range v.PoCs {
			fmt.Printf("  [%d] %s (author: %s)\n", i+1, p.URL, p.Author)
		}
	}
}

func renderVulnList(res *domain.PaginationResult[*domain.Vulnerability], format string) {
	if strings.ToLower(format) == "json" {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}

	if strings.ToLower(format) == "markdown" {
		fmt.Printf("### Threat Intelligence List (%d records, page %d/%d)\n\n",
			res.Total, res.Page, (res.Total+int64(res.PageSize)-1)/int64(res.PageSize))
		fmt.Println("| CVE | Severity | In-Wild | Categories | PoCs | Title |")
		fmt.Println("| :--- | :--- | :---: | :--- | :---: | :--- |")
		for _, v := range res.Items {
			exploited := "No"
			if v.IsExploited {
				exploited = "**YES(KEV)**"
			}
			fmt.Printf("| `%s` | %s | %s | `%s` | %d | %s |\n",
				v.CveID, v.Severity, exploited, strings.Join(v.Categories, ","), len(v.PoCs), v.Title)
		}
		return
	}

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4"))
	fmt.Println(titleStyle.Render(fmt.Sprintf("\n=== Threat Query Results (%d records, Page %d) ===", res.Total, res.Page)))

	if len(res.Items) == 0 {
		fmt.Println("No matching vulnerabilities found.")
		return
	}

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#DCDCDC"))
	fmt.Println(headerStyle.Render(fmt.Sprintf("%-16s %-10s %-8s %-20s %-8s %s",
		"CVE ID", "SEVERITY", "IN-WILD", "CATEGORIES", "POCS", "TITLE")))
	fmt.Println(strings.Repeat("-", 100))

	for _, v := range res.Items {
		cveText := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D7D7")).Render(fmt.Sprintf("%-16s", v.CveID))
		sevText := formatSeverityFixed(v.Severity, 10)
		wildText := "No      "
		if v.IsExploited {
			wildText = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF4500")).Render("YES(KEV)")
		}

		cats := strings.Join(v.Categories, ",")
		if len(cats) > 18 {
			cats = cats[:15] + "..."
		}
		catText := fmt.Sprintf("%-20s", cats)
		pocText := fmt.Sprintf("%-8d", len(v.PoCs))

		title := v.Title
		if len(title) > 35 {
			title = title[:32] + "..."
		}

		fmt.Printf("%s %s %s %s %s %s\n", cveText, sevText, wildText, catText, pocText, title)
	}
}

func formatSeverity(s domain.Severity) string {
	switch s {
	case domain.SeverityCritical:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF0055")).Render(string(s))
	case domain.SeverityHigh:
		return lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF8700")).Render(string(s))
	case domain.SeverityMedium:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Render(string(s))
	case domain.SeverityLow:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#00D7AF")).Render(string(s))
	default:
		return string(s)
	}
}

func formatSeverityFixed(s domain.Severity, width int) string {
	formatted := formatSeverity(s)
	rawLen := len(string(s))
	if rawLen < width {
		return formatted + strings.Repeat(" ", width-rawLen)
	}
	return formatted
}

func init() {
	queryCmd.Flags().StringVar(&queryCVE, "cve", "", "exact match by CVE identifier")
	queryCmd.Flags().StringVarP(&queryCategory, "category", "k", "", "filter by ecosystem category (e.g. java,golang,php)")
	queryCmd.Flags().StringVarP(&querySeverity, "severity", "s", "", "filter by severity (CRITICAL, HIGH, MEDIUM, LOW)")
	queryCmd.Flags().BoolVar(&queryHasPoC, "has-poc", false, "only return vulnerabilities with public PoCs")
	queryCmd.Flags().BoolVar(&queryExploited, "exploited", false, "only return vulnerabilities with CISA in-the-wild exploitation")
	queryCmd.Flags().StringVarP(&queryKeyword, "keyword", "q", "", "search keyword in title and description")
	queryCmd.Flags().StringVarP(&queryOutput, "output", "o", "table", "output format: table | json | markdown")
	queryCmd.Flags().IntVar(&queryPage, "page", 1, "page number")
	queryCmd.Flags().IntVar(&queryLimit, "limit", 20, "items per page")
	RootCmd.AddCommand(queryCmd)
}
