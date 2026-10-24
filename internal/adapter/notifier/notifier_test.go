package notifier

import (
	"testing"

	"raven/internal/core/domain"
	"raven/internal/pkg/config"
)

func TestShouldNotifyFilterCategoriesAND(t *testing.T) {
	cfg := config.NotifierConfig{
		Enabled:                true,
		AlwaysNotifyExploited:  true,
		MinSeverity:            "HIGH",
		FilterCategories: []string{
			"java+rce",
			"golang+rce",
			"spring+rce",
		},
	}

	mgr := NewManager(cfg)

	javaRCE := &domain.Vulnerability{
		CveID:      "CVE-2023-46604",
		Severity:   domain.SeverityCritical,
		Categories: []string{"java", "rce", "activemq"},
	}
	if !mgr.ShouldNotify(javaRCE) {
		t.Fatalf("expected java+rce to pass ShouldNotify")
	}

	springRCE := &domain.Vulnerability{
		CveID:      "CVE-2022-22965",
		Severity:   domain.SeverityCritical,
		Categories: []string{"spring", "rce", "poc"},
	}
	if !mgr.ShouldNotify(springRCE) {
		t.Fatalf("expected spring+rce to pass ShouldNotify")
	}

	phpRCE := &domain.Vulnerability{
		CveID:      "CVE-2024-4577",
		Severity:   domain.SeverityCritical,
		Categories: []string{"php", "rce"},
	}
	if mgr.ShouldNotify(phpRCE) {
		t.Fatalf("expected php+rce to be blocked by ShouldNotify")
	}

	javaSQLI := &domain.Vulnerability{
		CveID:      "CVE-2021-1234",
		Severity:   domain.SeverityCritical,
		Categories: []string{"java", "sqli"},
	}
	if mgr.ShouldNotify(javaSQLI) {
		t.Fatalf("expected java+sqli to be blocked by ShouldNotify")
	}

	ciscoExploited := &domain.Vulnerability{
		CveID:       "CVE-2020-9999",
		Severity:    domain.SeverityCritical,
		IsExploited: true,
		Categories:  []string{"cisco", "kev"},
	}
	if mgr.ShouldNotify(ciscoExploited) {
		t.Fatalf("expected unrelated exploited CVE to be blocked by ShouldNotify when FilterCategories is active")
	}
}

func TestMultiEndpointDifferentFilters(t *testing.T) {
	cfg := config.NotifierConfig{
		Enabled: true,
		Channels: config.ChannelsConfig{
			Slack: config.SlackConfig{
				Enabled: true,
				Endpoints: []config.SlackEndpointConfig{
					{
						Name:             "java-team",
						WebhookURL:       "https://mock.slack/java",
						FilterCategories: []string{"java+rce"},
					},
					{
						Name:             "php-team",
						WebhookURL:       "https://mock.slack/php",
						FilterCategories: []string{"php+rce"},
					},
				},
			},
		},
	}

	mgr := NewManager(cfg)

	allCats := cfg.AllTargetCategories()
	if len(allCats) != 2 {
		t.Fatalf("expected 2 target categories, got %d (%v)", len(allCats), allCats)
	}

	javaVuln := &domain.Vulnerability{
		CveID:      "CVE-2023-46604",
		Severity:   domain.SeverityCritical,
		Categories: []string{"java", "rce"},
	}
	if !mgr.ShouldNotify(javaVuln) {
		t.Fatalf("expected manager to allow javaVuln when java endpoint exists")
	}

	ciscoVuln := &domain.Vulnerability{
		CveID:      "CVE-2020-1111",
		Severity:   domain.SeverityCritical,
		Categories: []string{"cisco", "router"},
	}
	if mgr.ShouldNotify(ciscoVuln) {
		t.Fatalf("expected manager to block ciscoVuln since no endpoint watches cisco")
	}
}
