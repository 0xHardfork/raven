package slack_test

import (
	"context"
	"testing"
	"time"

	"raven/internal/adapter/notifier/slack"
	"raven/internal/core/domain"
	"raven/internal/pkg/config"
)

func TestSendLiveSlackAlert(t *testing.T) {
	cfg, err := config.Load("../../../../configs/config.yaml")
	if err != nil {
		t.Skip("config.yaml not found, skipping")
	}

	if !cfg.Notifier.Channels.Slack.Enabled || cfg.Notifier.Channels.Slack.WebhookURL == "" {
		t.Skip("Slack webhook not configured, skipping")
	}

	notifier := slack.NewNotifier(cfg.Notifier.Channels.Slack, false)

	cvss := 9.8
	now := time.Now()
	vuln := &domain.Vulnerability{
		CveID:       "CVE-2026-109618",
		Title:       "PHP-CGI Argument Injection Remote Code Execution (php2shell)",
		Description: "A critical remote code execution vulnerability in PHP-CGI module allowing unauthenticated command injection via crafted query parameters on Linux and Windows servers.",
		Severity:    domain.SeverityCritical,
		CvssScore:   &cvss,
		Categories:  []string{"php", "rce", "poc"},
		IsExploited: true,
		Sources:     []string{"github_pocs", "cisa_kev"},
		PublishedAt: &now,
		PoCs: []domain.PoC{
			{
				URL:         "https://github.com/Suleman-Elahi/php2shell-sentinel",
				Author:      "Suleman-Elahi",
				Description: "php2shell defense and mitigation daemon",
			},
			{
				URL:         "https://github.com/walt3rblake/php2shell-scanner",
				Author:      "walt3rblake",
				Description: "php2shell scanner exploit",
			},
		},
	}

	if err := notifier.SendThreatAlert(context.Background(), vuln); err != nil {
		t.Fatalf("send live alert failed: %v", err)
	}
}
