package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/charmbracelet/lipgloss"
	_ "github.com/lib/pq"
	"github.com/spf13/cobra"
	"raven/internal/adapter/api"
	"raven/internal/adapter/notifier"
	"raven/internal/adapter/runner/python"
	"raven/internal/adapter/storage/postgres"
	"raven/internal/core/port"
	"raven/internal/core/service"
	"raven/internal/pkg/logger"
)

var (
	serverPort  int
	serverHost  string
	serverDebug bool
)

// serverCmd 启动 Web API 服务命令
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "启动 Raven RESTful Web API HTTP 服务",
	Long: `启动 Raven 标准 RESTful Web API 服务，支持外部系统通过 HTTP 检索威胁情报、
查询分类大盘以及远程触发采集调度任务。`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var repo port.RepositoryPort
		if !dryRun {
			dbConn, err := sql.Open("postgres", cfg.Database.DSN())
			if err != nil {
				logger.L().Warn("failed to connect to postgresql, starting in mock mode", "error", err)
			} else {
				dbConn.SetMaxOpenConns(cfg.Database.MaxOpenConns)
				dbConn.SetMaxIdleConns(cfg.Database.MaxIdleConns)

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				if err := dbConn.PingContext(ctx); err != nil {
					logger.L().Warn("postgresql ping failed, server will start without persistent storage", "error", err)
					_ = dbConn.Close()
				} else {
					repo = postgres.NewRepository(dbConn)
					defer repo.Close()
				}
			}
		}

		// 初始化依赖组件
		runner := python.NewRunner(cfg.Python)
		notifierMgr := notifier.NewManager(cfg.Notifier)
		collectorSvc := service.NewCollectorService(runner, repo, notifierMgr)
		var threatSvc *service.ThreatQueryService
		if repo != nil {
			threatSvc = service.NewThreatQueryService(repo)
		}

		// 构建 Gin 路由
		router := api.SetupRouter(api.RouterConfig{
			ThreatService:    threatSvc,
			CollectorService: collectorSvc,
			Debug:            serverDebug,
		})

		addr := fmt.Sprintf("%s:%d", serverHost, serverPort)
		srv := &http.Server{
			Addr:         addr,
			Handler:      router,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		// 打印终端横幅
		printServerBanner(addr, dryRun || repo == nil)

		// 后台启动 HTTP 监听
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.L().Error("http server listen failed", "error", err)
				os.Exit(1)
			}
		}()

		// 捕获系统退出信号实现优雅停机
		quit := make(chan os.Signal, 1)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit

		fmt.Println("\nShutting down server gracefully...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := srv.Shutdown(ctx); err != nil {
			return fmt.Errorf("server forced to shutdown: %w", err)
		}

		fmt.Println("Server exiting complete.")
		return nil
	},
}

func printServerBanner(addr string, isMock bool) {
	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("#FAFAFA")).
		Background(lipgloss.Color("#5A56E0")).
		Padding(0, 1)

	infoStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00D8A0"))

	warnStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFB020"))

	fmt.Println()
	fmt.Printf("%s Raven Web API Service is running at http://%s\n", titleStyle.Render(" SERVER "), addr)
	if isMock {
		fmt.Printf("%s Database disconnected or in Dry-Run mode; API running in mock/transient mode.\n", warnStyle.Render("ℹ NOTE:"))
	}

	fmt.Printf("\n%s\n", infoStyle.Render("Available Endpoints:"))
	fmt.Println("  GET  /health                  - Health check probe")
	fmt.Println("  GET  /api/v1/health           - API v1 health status")
	fmt.Println("  GET  /api/v1/threats          - Query threat intelligence list")
	fmt.Println("  GET  /api/v1/threats/:cve_id  - Get threat details by CVE ID")
	fmt.Println("  GET  /api/v1/threats/categories - Get tags & categories count")
	fmt.Println("  GET  /api/v1/stats            - Global threat dashboard statistics")
	fmt.Println("  POST /api/v1/collect/trigger  - Trigger async threat ingestion")
	fmt.Println("  GET  /api/v1/collect/status   - Ingestion task status & summary")
	fmt.Println("\nPress Ctrl+C to stop the server.")
}

func init() {
	serverCmd.Flags().IntVarP(&serverPort, "port", "p", 8080, "HTTP 服务监听端口")
	serverCmd.Flags().StringVar(&serverHost, "host", "0.0.0.0", "HTTP 服务监听地址")
	serverCmd.Flags().BoolVar(&serverDebug, "debug", false, "启用 Gin 调试模式")
	RootCmd.AddCommand(serverCmd)
}
