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

var RootCmd = &cobra.Command{
	Use:   "raven",
	Short: "Raven - High-performance threat intelligence and vulnerability/PoC collector",
	Long: `Raven is a threat intelligence gathering system designed to monitor,
aggregate, and structure CVE disclosures, GitHub PoCs, CISA KEV entries,
and Exploit-DB exploits with self-declared ecosystem categorization.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		loadedCfg, err := config.Load(cfgPath)
		if err != nil {
			return fmt.Errorf("load config error: %w", err)
		}
		cfg = loadedCfg

		if cmd.Flags().Changed("dry-run") {
			cfg.Notifier.DryRun = dryRun
		}

		logger.Init("INFO", false)
		return nil
	},
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", "", "config file path (default: configs/config.yaml)")
	RootCmd.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "dry-run/mock mode (skip database write and live notification dispatch)")
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
