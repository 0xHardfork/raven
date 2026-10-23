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
	Short: "多维检索与格式化展示威胁情报",
	Long: `支持按 CVE 编号、技术生态分类 (Java/Golang/PHP 等)、CVSS 评级、
在野利用标志与 PoC 存在性进行快速筛选，支持 Table 彩色表格、JSON 与 Markdown 格式输出。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		db, err := sql.Open("postgres", cfg.Database.DSN())
		if err != nil {
			return fmt.Errorf("connect postgres error: %w", err)
		}
		defer db.Close()

		if err := db.PingContext(ctx); err != nil {
			return fmt.Errorf("无法连接数据库: %w (请先启动 PostgreSQL 或通过 'raven migrate up' 初始化数据库)", err)
		}

		repo := postgres.NewRepository(db)
		threatSvc := service.NewThreatQueryService(repo)

		// 1. 如果指定了单条 CVE 精准查询
		if queryCVE != "" {
			vuln, err := threatSvc.GetThreat(ctx, queryCVE)
			if err != nil {
				return err
			}
			if vuln == nil {
				fmt.Printf("未检索到编号为 '%s' 的漏洞记录。\n", queryCVE)
				return nil
			}
			renderSingleVuln(vuln, queryOutput)
			return nil
		}

		// 2. 多维列表过滤查询
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

	fmt.Println(titleStyle.Render("\n=== 漏洞威胁全景详情 ==="))
	fmt.Printf("%s %s\n", labelStyle.Render("CVE 编号:   "), cveStyle.Render(v.CveID))
	fmt.Printf("%s %s\n", labelStyle.Render("漏洞标题:   "), v.Title)
	fmt.Printf("%s %s\n", labelStyle.Render("严重级别:   "), formatSeverity(v.Severity))
	if v.CvssScore != nil {
		fmt.Printf("%s %.1f\n", labelStyle.Render("CVSS 评分:  "), *v.CvssScore)
	}
	fmt.Printf("%s %v\n", labelStyle.Render("生态分类:   "), v.Categories)
	fmt.Printf("%s %t\n", labelStyle.Render("在野利用:   "), v.IsExploited)
	fmt.Printf("%s %v\n", labelStyle.Render("情报源:     "), v.Sources)
	if v.PublishedAt != nil {
		fmt.Printf("%s %s\n", labelStyle.Render("披露时间:   "), v.PublishedAt.Format("2006-01-02 15:04:05"))
	}
	fmt.Printf("%s\n  %s\n", labelStyle.Render("描述信息:"), v.Description)

	fmt.Printf("\n%s (%d 个):\n", labelStyle.Render("可用 PoC 列表"), len(v.PoCs))
	if len(v.PoCs) == 0 {
		fmt.Println("  (暂无公开验证代码)")
	} else {
		for i, p := range v.PoCs {
			fmt.Printf("  [%d] %s (作者: %s)\n", i+1, p.URL, p.Author)
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
		fmt.Printf("### 威胁情报列表 (共 %d 条，第 %d/%d 页)\n\n", res.Total, res.Page, (res.Total+int64(res.PageSize)-1)/int64(res.PageSize))
		fmt.Println("| CVE | 危险等级 | 在野利用 | 分类 | PoC 数量 | 标题 |")
		fmt.Println("| :--- | :--- | :---: | :--- | :---: | :--- |")
		for _, v := range res.Items {
			exploited := "否"
			if v.IsExploited {
				exploited = "**是(KEV)**"
			}
			fmt.Printf("| `%s` | %s | %s | `%s` | %d | %s |\n",
				v.CveID, v.Severity, exploited, strings.Join(v.Categories, ","), len(v.PoCs), v.Title)
		}
		return
	}

	// 终端表格输出
	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4"))
	fmt.Println(titleStyle.Render(fmt.Sprintf("\n=== 威胁检索结果 (共 %d 条记录，当前第 %d 页) ===", res.Total, res.Page)))

	if len(res.Items) == 0 {
		fmt.Println("未检索到符合条件的漏洞。")
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
	queryCmd.Flags().StringVar(&queryCVE, "cve", "", "按特定 CVE 编号精准查询")
	queryCmd.Flags().StringVarP(&queryCategory, "category", "k", "", "按生态分类筛选 (如 java,golang,php)")
	queryCmd.Flags().StringVarP(&querySeverity, "severity", "s", "", "按危害等级筛选 (CRITICAL, HIGH, MEDIUM, LOW)")
	queryCmd.Flags().BoolVar(&queryHasPoC, "has-poc", false, "仅展示存在 PoC 验证代码的漏洞")
	queryCmd.Flags().BoolVar(&queryExploited, "exploited", false, "仅展示 CISA 在野已利用漏洞")
	queryCmd.Flags().StringVarP(&queryKeyword, "keyword", "q", "", "关键词模糊搜索 (匹配标题与描述)")
	queryCmd.Flags().StringVarP(&queryOutput, "output", "o", "table", "输出格式: table | json | markdown")
	queryCmd.Flags().IntVar(&queryPage, "page", 1, "分页页码")
	queryCmd.Flags().IntVar(&queryLimit, "limit", 20, "每页条数")
	RootCmd.AddCommand(queryCmd)
}
