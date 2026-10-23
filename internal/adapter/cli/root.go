package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"raven/internal/pkg/config"
	"raven/internal/pkg/logger"
)

var (
	cfgPath string
	dryRun  bool
	cfg     *config.Config
)

// RootCmd 全局根命令
var RootCmd = &cobra.Command{
	Use:   "raven",
	Short: "Raven - 高性能开源漏洞与 PoC 威胁情报收集工具",
	Long: `Raven 是一套专注于监控、聚合和结构化存储全球最新 CVE 披露、
GitHub PoC、CISA 在野利用与 Exploit-DB 成果的高性能威胁情报收集系统。
支持自声明语言/生态分类归档，支持 CLI、Web API 与 Slack Bot 告警推送。`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		loadedCfg, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("load config error: %w", err)
		}
		cfg = loadedCfg

		// 命令行显式指定 --dry-run 时覆盖配置
		if cmd.Flags().Changed("dry-run") {
			cfg.Notifier.DryRun = dryRun
		}

		logger.Init("INFO", false)
		return nil
	},
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", "", "配置文件路径 (默认自动探测 configs/config.yaml)")
	RootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "演练/Mock 模式 (不触发真实网络写入与推送)")
}

// Execute 执行根命令入口
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
