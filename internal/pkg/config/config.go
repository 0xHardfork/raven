package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database DatabaseConfig `yaml:"database"`
	Server   ServerConfig   `yaml:"server"`
	Watcher  WatcherConfig  `yaml:"watcher"`
	Notifier NotifierConfig `yaml:"notifier"`
	Python   PythonConfig   `yaml:"python"`
}

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

func (d *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		d.Host, d.Port, d.User, d.Password, d.DBName, d.SSLMode)
}

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type WatcherConfig struct {
	Interval   string   `yaml:"interval"`
	Categories []string `yaml:"categories"`
	Sources    []string `yaml:"sources"`
}

func (w *WatcherConfig) ParseInterval() time.Duration {
	d, err := time.ParseDuration(w.Interval)
	if err != nil || d < time.Minute {
		return 15 * time.Minute
	}
	return d
}

type NotifierConfig struct {
	Enabled               bool           `yaml:"enabled"`
	DryRun                bool           `yaml:"dry_run"`
	MinSeverity           string         `yaml:"min_severity"`
	OnlyWithPoC           bool           `yaml:"only_with_poc"`
	AlwaysNotifyExploited bool           `yaml:"always_notify_exploited"`
	FilterCategories      []string       `yaml:"filter_categories"`
	Channels              ChannelsConfig `yaml:"channels"`
}

type ChannelsConfig struct {
	Slack SlackConfig `yaml:"slack"`
}

type SlackConfig struct {
	Enabled    bool   `yaml:"enabled"`
	WebhookURL string `yaml:"webhook_url"`
	Channel    string `yaml:"channel"`
	BotToken   string `yaml:"bot_token"`
}

type PythonConfig struct {
	BinaryPath string `yaml:"binary_path"`
	ScriptsDir string `yaml:"scripts_dir"`
	TimeoutSec int    `yaml:"timeout_sec"`
}

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
			DryRun:                true,
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

func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

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
