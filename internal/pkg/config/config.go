package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Database DatabaseConfig `yaml:"database"`
	Server   ServerConfig   `yaml:"server"`
	Watcher  WatcherConfig  `yaml:"watcher"`
	Notifier NotifierConfig `yaml:"notifier"`
	Python   PythonConfig   `yaml:"python"`
	Scrapers ScrapersConfig `yaml:"scrapers"`
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

func (n NotifierConfig) AllTargetCategories() []string {
	if len(n.FilterCategories) > 0 {
		return n.FilterCategories
	}
	set := make(map[string]struct{})
	var res []string
	for _, ep := range n.Channels.Slack.Endpoints {
		for _, cat := range ep.FilterCategories {
			trimmed := strings.TrimSpace(cat)
			if trimmed != "" {
				if _, ok := set[trimmed]; !ok {
					set[trimmed] = struct{}{}
					res = append(res, trimmed)
				}
			}
		}
	}
	return res
}

type ChannelsConfig struct {
	Slack SlackConfig `yaml:"slack"`
}

type SlackEndpointConfig struct {
	Name             string   `yaml:"name"`
	WebhookURL       string   `yaml:"webhook_url"`
	FilterCategories []string `yaml:"filter_categories"`
	MinSeverity      string   `yaml:"min_severity"`
}

type SlackConfig struct {
	Enabled          bool                  `yaml:"enabled"`
	WebhookURL       string                `yaml:"webhook_url"`
	WebhookURLs      []string              `yaml:"webhook_urls"`
	Endpoints        []SlackEndpointConfig `yaml:"endpoints"`
	Channel          string                `yaml:"channel"`
	BotToken         string                `yaml:"bot_token"`
	Template         string                `yaml:"template"`
	FilterCategories []string              `yaml:"filter_categories"`
}

func (s SlackConfig) AllEndpoints(defaultFilters []string, defaultMinSev string) []SlackEndpointConfig {
	if len(s.Endpoints) > 0 {
		var res []SlackEndpointConfig
		for _, ep := range s.Endpoints {
			if strings.TrimSpace(ep.WebhookURL) == "" {
				continue
			}
			item := ep
			if len(item.FilterCategories) == 0 && len(defaultFilters) > 0 {
				item.FilterCategories = defaultFilters
			}
			if item.MinSeverity == "" {
				item.MinSeverity = defaultMinSev
			}
			res = append(res, item)
		}
		return res
	}

	var res []SlackEndpointConfig
	for i, u := range s.AllWebhookURLs() {
		res = append(res, SlackEndpointConfig{
			Name:             fmt.Sprintf("slack-%d", i+1),
			WebhookURL:       u,
			FilterCategories: defaultFilters,
			MinSeverity:      defaultMinSev,
		})
	}
	return res
}

func (s SlackConfig) AllWebhookURLs() []string {
	var urls []string
	if strings.TrimSpace(s.WebhookURL) != "" {
		urls = append(urls, strings.TrimSpace(s.WebhookURL))
	}
	for _, u := range s.WebhookURLs {
		trimmed := strings.TrimSpace(u)
		if trimmed != "" && trimmed != strings.TrimSpace(s.WebhookURL) {
			urls = append(urls, trimmed)
		}
	}
	return urls
}

type PythonConfig struct {
	BinaryPath string `yaml:"binary_path"`
	ScriptsDir string `yaml:"scripts_dir"`
	TimeoutSec int    `yaml:"timeout_sec"`
}

type ScrapersConfig struct {
	GitHub    GitHubScraperConfig `yaml:"github"`
	NVD       NVDScraperConfig    `yaml:"nvd"`
	CISA      CISAScraperConfig   `yaml:"cisa"`
	ExploitDB EDBScraperConfig    `yaml:"exploitdb"`
}

func (s ScrapersConfig) AllKeywords() []string {
	set := make(map[string]struct{})
	var res []string
	add := func(word string) {
		w := strings.ToLower(strings.TrimSpace(word))
		if w != "" {
			if _, exists := set[w]; !exists {
				set[w] = struct{}{}
				res = append(res, w)
			}
		}
	}
	for _, k := range s.GitHub.Keywords {
		add(k)
	}
	for _, k := range s.NVD.Keywords {
		add(k)
	}
	for _, k := range s.CISA.Keywords {
		add(k)
	}
	for _, k := range s.ExploitDB.Keywords {
		add(k)
	}
	return res
}

type GitHubScraperConfig struct {
	Query    string   `yaml:"query"`
	Keywords []string `yaml:"keywords"`
	Limit    int      `yaml:"limit"`
	Token    string   `yaml:"token"`
}

type NVDScraperConfig struct {
	Days     int      `yaml:"days"`
	Limit    int      `yaml:"limit"`
	APIKey   string   `yaml:"api_key"`
	Keywords []string `yaml:"keywords"`
}

type CISAScraperConfig struct {
	FeedURL  string   `yaml:"feed_url"`
	Limit    int      `yaml:"limit"`
	Keywords []string `yaml:"keywords"`
}

type EDBScraperConfig struct {
	CSVURL   string   `yaml:"csv_url"`
	Keywords []string `yaml:"keywords"`
	Limit    int      `yaml:"limit"`
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
					Template:   "",
				},
			},
		},
		Python: PythonConfig{
			BinaryPath: "python3",
			ScriptsDir: "scripts",
			TimeoutSec: 60,
		},
		Scrapers: ScrapersConfig{
			GitHub: GitHubScraperConfig{
				Query:    "CVE in:name,description fork:false",
				Keywords: []string{"php", "java", "spring", "golang", "python", "rust", "wordpress", "apache", "nginx", "rce", "ssrf"},
				Limit:    30,
			},
			NVD: NVDScraperConfig{
				Days:  120,
				Limit: 30,
			},
			CISA: CISAScraperConfig{
				FeedURL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
				Limit:   30,
			},
			ExploitDB: EDBScraperConfig{
				CSVURL:   "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
				Keywords: []string{"php", "java", "golang", "python", "linux", "windows", "rce", "sqli"},
				Limit:    30,
			},
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
