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
	Short: "一键执行威胁与 PoC 数据采集入库",
	Long: `从 GitHub PoC、CISA KEV、Exploit-DB 与 NVD 等数据源拉取最新威胁情报，
按自声明技术分类归档并幂等合并存储到 PostgreSQL。支持指定源、分类与指定脚本执行。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()

		runner := python.NewRunner(cfg.Python)

		// 检查数据库连接；若数据库未连接且开启了 dry-run/mock，则降级为纯终端展示模式
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
			return fmt.Errorf("无法连接 PostgreSQL (DSN: %s)。如需离线体验采集，请加 --dry-run 或 --mock 参数", cfg.Database.DSN())
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

		fmt.Println(titleStyle.Render("🦅 Raven Threat Collector 启动中..."))

		var (
			collected []*domain.Vulnerability
			summary   *service.CollectSummary
		)

		extraArgs := []string{}
		if dryRun || collectMock {
			extraArgs = append(extraArgs, "--mock")
			fmt.Println(infoStyle.Render("ℹ 当前运行于 Dry-Run / Mock 演练模式，使用预置高质量威胁数据集"))
		}

		if collectScript != "" {
			fmt.Printf("执行指定脚本: %s\n", collectScript)
			vulns, err := runner.RunScript(ctx, collectScript, extraArgs...)
			if err != nil {
				return err
			}
			collected = vulns
		} else if collectSource != "" {
			fmt.Printf("执行指定数据源采集: %s\n", collectSource)
			vulns, err := collectorSvc.CollectSource(ctx, collectSource, categories)
			if err != nil {
				return err
			}
			collected = vulns
		} else {
			fmt.Println("执行全量数据源采集 (GitHub PoCs, CISA KEV, Exploit-DB, NVD)...")
			res, err := collectorSvc.CollectAll(ctx, categories)
			if err != nil {
				return err
			}
			summary = res
			collected = res.Vulns
		}

		// 若指定单源或单脚本，且 DB 存在，写入 DB
		if repo != nil && len(collected) > 0 {
			ins, upd, err := repo.BatchUpsert(ctx, collected)
			if err != nil {
				return fmt.Errorf("持久化入库失败: %w", err)
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

		// 终端输出统计
		fmt.Println("\n" + successStyle.Render("=== 采集执行完成统计 ==="))
		fmt.Printf("  • 涉及脚本数:  %d\n", summary.TotalScripts)
		fmt.Printf("  • 抓取漏洞数:  %d 条\n", summary.TotalFound)
		if repo != nil {
			fmt.Printf("  • 数据库新增:  %d 条\n", summary.Inserted)
			fmt.Printf("  • 数据库更新:  %d 条 (多源标签/PoC自动合并)\n", summary.Updated)
		} else {
			fmt.Println(infoStyle.Render("  • 存储状态:    [跳过数据库写入 - 离线/演练模式]"))
		}

		// 如果有抓取到的样例，打印前 3 条展示格式
		if len(collected) > 0 {
			fmt.Println("\n" + titleStyle.Render("最新情报预览 (Top 3):"))
			for i, v := range collected {
				if i >= 3 {
					break
				}
				pocCount := len(v.PoCs)
				exploitedTag := ""
				if v.IsExploited {
					exploitedTag = " 🚨[在野利用]"
				}
				fmt.Printf("  [%d] %s (%s)%s | 分类: %v | PoC: %d个\n      标题: %s\n",
					i+1, v.CveID, v.Severity, exploitedTag, v.Categories, pocCount, v.Title)
			}
		}

		return nil
	},
}

func init() {
	collectCmd.Flags().StringVarP(&collectSource, "source", "s", "", "指定采集数据源 (如 github, cisa, exploitdb, nvd)")
	collectCmd.Flags().StringVarP(&collectCategory, "category", "k", "", "按生态分类过滤 (如 java,golang,php)")
	collectCmd.Flags().StringVar(&collectScript, "script", "", "指定执行特定 Python 脚本路径")
	collectCmd.Flags().BoolVar(&collectMock, "mock", false, "使用内置 Mock 仿真数据集进行演练测试")
	RootCmd.AddCommand(collectCmd)
}
