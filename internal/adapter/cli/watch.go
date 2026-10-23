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
	Short: "启动后台定时巡检与实时预警守护进程",
	Long:  "按照指定周期定期轮询 GitHub PoC、CISA KEV 等数据源，发现高危漏洞或新 PoC 自动触发 Slack 等渠道告警。",
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
		} else {
			categories = cfg.Watcher.Categories
		}

		runner := python.NewRunner(cfg.Python)

		// 检查数据库
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

		// 初始化告警推送管理器
		notifierMgr := notifier.NewManager(cfg.Notifier)

		collectorSvc := service.NewCollectorService(runner, repo, notifierMgr)
		watcherSvc := service.NewWatcherService(collectorSvc, notifierMgr)

		titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7D56F4"))
		infoStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#00D7D7"))

		fmt.Println(titleStyle.Render("🦅 Raven Threat Watcher 守护进程启动"))
		fmt.Println(infoStyle.Render(fmt.Sprintf("  • 轮询周期: %s", interval)))
		fmt.Println(infoStyle.Render(fmt.Sprintf("  • 目标生态分类: %v", categories)))
		if cfg.Notifier.DryRun {
			fmt.Println(infoStyle.Render("  • 告警模式: Dry-Run 演练模式 (终端打印预览，不外发网络请求)"))
		} else {
			fmt.Println(infoStyle.Render("  • 告警模式: 实时推送 (Slack)"))
		}
		fmt.Println("按 Ctrl+C 优雅退出...")

		if err := watcherSvc.Start(ctx, interval, categories); err != nil && err != context.Canceled {
			return err
		}

		fmt.Println("\n已优雅停止 Raven Watcher。")
		return nil
	},
}

func init() {
	watchCmd.Flags().StringVarP(&watchInterval, "interval", "i", "", "巡检周期 (如 1m, 15m, 1h)")
	watchCmd.Flags().StringVarP(&watchCategory, "category", "k", "", "限定巡检技术分类 (如 java,golang)")
	RootCmd.AddCommand(watchCmd)
}
