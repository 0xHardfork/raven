package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"raven/internal/core/domain"
	"raven/internal/pkg/config"
	"raven/internal/pkg/logger"
)

type Notifier struct {
	cfg        config.SlackConfig
	dryRun     bool
	httpClient *http.Client
}

func NewNotifier(cfg config.SlackConfig, dryRun bool) *Notifier {
	return &Notifier{
		cfg:    cfg,
		dryRun: dryRun,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (n *Notifier) SendThreatAlert(ctx context.Context, vuln *domain.Vulnerability) error {
	payload := n.buildBlockKitPayload(vuln)

	if n.dryRun || n.cfg.WebhookURL == "" {
		n.renderTerminalPreview(vuln)
		return nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create slack request failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("send slack webhook failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("slack webhook returned non-2xx status: %d", resp.StatusCode)
	}

	logger.L().Info("slack threat alert delivered", "cve", vuln.CveID)
	return nil
}

func (n *Notifier) SendBatchAlert(ctx context.Context, vulns []*domain.Vulnerability) error {
	for _, v := range vulns {
		if err := n.SendThreatAlert(ctx, v); err != nil {
			logger.L().Error("send slack alert failed", "cve", v.CveID, "error", err)
		}
	}
	return nil
}

func (n *Notifier) buildBlockKitPayload(v *domain.Vulnerability) map[string]any {
	severityEmoji := "⚠️"
	if v.Severity == domain.SeverityCritical {
		severityEmoji = "🚨"
	}

	exploitedStr := "No"
	if v.IsExploited {
		exploitedStr = "🔥 YES (Confirmed by CISA KEV)"
	}

	cvssStr := "N/A"
	if v.CvssScore != nil {
		cvssStr = fmt.Sprintf("%.1f", *v.CvssScore)
	}

	categoriesStr := strings.Join(v.Categories, ", ")
	if categoriesStr == "" {
		categoriesStr = "General"
	}

	sourcesStr := strings.Join(v.Sources, ", ")

	blocks := []map[string]any{
		{
			"type": "header",
			"text": map[string]any{
				"type":  "plain_text",
				"text":  fmt.Sprintf("%s [%s] %s", severityEmoji, v.Severity, v.CveID),
				"emoji": true,
			},
		},
		{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Title:* %s\n%s", v.Title, v.Description),
			},
		},
		{
			"type": "section",
			"fields": []map[string]any{
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Severity:* `%s` (CVSS: %s)", v.Severity, cvssStr),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*In-The-Wild:* %s", exploitedStr),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Ecosystem:* `%s`", categoriesStr),
				},
				{
					"type": "mrkdwn",
					"text": fmt.Sprintf("*Sources:* %s", sourcesStr),
				},
			},
		},
	}

	if len(v.PoCs) > 0 {
		var pocLines []string
		for i, p := range v.PoCs {
			if i >= 3 {
				pocLines = append(pocLines, fmt.Sprintf("... (%d exploits total)", len(v.PoCs)))
				break
			}
			author := p.Author
			if author == "" {
				author = "Community"
			}
			pocLines = append(pocLines, fmt.Sprintf("• <%s|%s> (by `%s`)", p.URL, p.URL, author))
		}

		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Available Exploits / PoCs:*\n%s", strings.Join(pocLines, "\n")),
			},
		})
	}

	blocks = append(blocks, map[string]any{
		"type": "context",
		"elements": []map[string]any{
			{
				"type": "mrkdwn",
				"text": fmt.Sprintf("Raven Threat Intelligence Alert • %s", time.Now().Format("2006-01-02 15:04:05 UTC")),
			},
		},
	})

	return map[string]any{
		"blocks": blocks,
	}
}

func (n *Notifier) renderTerminalPreview(v *domain.Vulnerability) {
	cardStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#7D56F4")).
		Padding(0, 1).
		MarginBottom(1)

	cveStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FF0055"))
	fieldStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00D7D7"))

	content := fmt.Sprintf(
		"🔔 [Slack Block Kit Preview]\n%s: %s\n%s %s | %s %v | %s %t\n",
		cveStyle.Render(fmt.Sprintf("[%s] %s", v.Severity, v.CveID)),
		v.Title,
		fieldStyle.Render("Severity:"), v.Severity,
		fieldStyle.Render("Categories:"), v.Categories,
		fieldStyle.Render("Exploited:"), v.IsExploited,
	)

	if len(v.PoCs) > 0 {
		content += fieldStyle.Render(fmt.Sprintf("Available PoCs (%d):\n", len(v.PoCs)))
		for _, p := range v.PoCs {
			content += fmt.Sprintf("  ↳ %s\n", p.URL)
		}
	}

	fmt.Print(cardStyle.Render(content) + "\n")
}
