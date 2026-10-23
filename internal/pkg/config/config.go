package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 定义 Raven 全局配置结构体
type Config struct {
	Database DatabaseConfig `yaml:"database"`
	Server   ServerConfig   `yaml:"server"`
	Watcher  WatcherConfig  `yaml:"watcher"`
	Notifier NotifierConfig `yaml:"notifier"`
	Python   PythonConfig   `yaml:"python"`
}

// DatabaseConfig 数据库连接配置
type DatabaseConfig struct {
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	DBName       string `yaml:"dbname"`
	SSLMode      string `yaml:"sslmode"`
	MaxOpenConns int    `yaml:"max_open_conns"`
	MaxIdleConns int    `yaml:"max_idle_conns"`
	AutoMigrate  bool   `yaml:"auto_migrate"`
}

// DSN 返回 PostgreSQL 连接串
func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode)
}

// ServerConfig Web API 服务配置
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// WatcherConfig 定时巡检守护配置
type WatcherConfig struct {
	Interval   string   `yaml:"interval"`
	Categories []string `yaml:"categories"`
	Sources    []string `yaml:"sources"`
}

// ParseInterval 解析巡检周期
func (w *WatcherConfig) ParseInterval() time.Duration {
	d, err := time.ParseDuration(w.Interval)
	if err != nil || d < time.Minute {
		return 15 * time.Minute
	}
	return d
}

// NotifierConfig 告警与通知推送配置
type NotifierConfig struct {
	Enabled               bool           `yaml:"enabled"`
	DryRun                bool           `yaml:"dry_run"` // 本地调试无需真实 Webhook，打印富文本到终端
	MinSeverity           string         `yaml:"min_severity"`
	OnlyWithPoC           bool           `yaml:"only_with_poc"`
	AlwaysNotifyExploited bool           `yaml:"always_notify_exploited"`
	FilterCategories      []string       `yaml:"filter_categories"`
	Channels              ChannelsConfig `yaml:"channels"`
}

// ChannelsConfig 各推送通道配置
type ChannelsConfig struct {
	Slack SlackConfig `yaml:"slack"`
}

// SlackConfig Slack Bot 与 Webhook 配置
type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
	BotToken   string `yaml:"bot_token"`
}

// PythonConfig Python 采集器子进程配置
type PythonConfig struct {
	BinaryPath string `yaml:"binary_path"` // 默认 "python3"
	ScriptsDir string `yaml:"scripts_dir"` // 默认 "scripts"
	TimeoutSec int    `yaml:"timeout_sec"` // 默认 60 秒
}

// DefaultConfig 提供开箱即用的默认配置
func DefaultConfig() *Config {
	return &Config{
		Database: DatabaseConfig{
			Host:         "127.0.0.1",
			Port:         5432,
			User:         "postgres",
			Password:     "postgres",
			DBName:       "raven",
			SSLMode:      "disable",
			MaxOpenConns: 25,
			MaxIdleConns: 5,
			AutoMigrate:  true,
		},
		Server: ServerConfig{
			Host: "0.0.0.0",
			Port: 8080,
		},
		Watcher: WatcherConfig{
			Interval:   "15m",
			Categories: []string{},
			Sources:    []string{},
		},
		Notifier: NotifierConfig{
			Enabled:               false,
			DryRun:                true, // 默认开启 dry-run 保护本地测试
			MinSeverity:           "HIGH",
			OnlyWithPoC:           false,
			AlwaysNotifyExploited: true,
			FilterCategories:      []string{},
			Channels: ChannelsConfig{
				Slack: SlackConfig{
					Enabled:    false,
					WebhookURL: "",
					Channel:    "#security-threats",
					BotToken:   "",
				},
			},
		},
		Python: PythonConfig{
			BinaryPath: "python3",
			ScriptsDir: "scripts",
			TimeoutSec: 60,
		},
	}
}

// Load 读取并解析配置文件；若文件不存在则返回默认配置
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	// 若未指定路径，探测默认位置
	if path == "" {
		candidates := []string{
			"configs/config.yaml",
			"config.yaml",
			"configs/config.local.yaml",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				path = c
				break
			}
		}
	}

	// 没有找到配置文件，使用安全默认配置
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file '%s' failed: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config yaml '%s' failed: %w", path, err)
	}

	return cfg, nil
}
