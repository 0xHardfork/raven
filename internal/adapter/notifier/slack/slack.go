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
	endpoint   config.SlackEndpointConfig
	dryRun     bool
	httpClient *http.Client
}

func NewNotifier(cfg config.SlackConfig, dryRun bool, endpoints ...config.SlackEndpointConfig) *Notifier {
	var ep config.SlackEndpointConfig
	if len(endpoints) > 0 {
		ep = endpoints[0]
	} else {
		ep = config.SlackEndpointConfig{
			Name:             "slack-default",
			WebhookURL:       cfg.WebhookURL,
			FilterCategories: cfg.FilterCategories,
		}
	}
	return &Notifier{
		cfg:        cfg,
		endpoint:   ep,
		dryRun:     dryRun,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (n *Notifier) SendThreatAlert(ctx context.Context, vuln *domain.Vulnerability) error {
	if len(n.endpoint.FilterCategories) > 0 {
		if !domain.MatchAnyCategoryRule(n.endpoint.FilterCategories, vuln.Categories) {
			return nil
		}
	}

	if n.endpoint.MinSeverity != "" {
		minWeight := domain.NormalizeSeverity(n.endpoint.MinSeverity).Weight()
		if vuln.Severity.Weight() < minWeight {
			return nil
		}
	}

	payload := n.buildBlockKitPayload(vuln)
	targetURL := n.endpoint.WebhookURL
	if targetURL == "" {
		targetURL = n.cfg.WebhookURL
	}

	if n.dryRun || targetURL == "" {
		n.renderTerminalPreview(vuln)
		return nil
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal slack payload failed: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
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

	logger.L().Info("slack threat alert delivered", "cve", vuln.CveID, "endpoint", n.endpoint.Name)
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

const defaultSlackTemplate = `*{{severity_emoji}} [{{severity}}] <{{nvd_url}}|{{cve_id}}>* — *{{title}}*
> {{description}}

• *Severity:* *{{severity}}* (CVSS: {{cvss}})
• *In-The-Wild:* {{in_the_wild}}
• *Categories:* {{categories}}
• *CVE Links:* <{{nvd_url}}|NVD> • <{{cve_org_url}}|CVE.org>

*🔥 Available Exploits / PoCs:*
{{pocs}}`

func (n *Notifier) buildBlockKitPayload(v *domain.Vulnerability) map[string]any {
	severityEmoji := "⚠️"
	color := "#E8912D"

	switch v.Severity {
	case domain.SeverityCritical:
		severityEmoji = "🚨"
		color = "#E01E5A"
	case domain.SeverityHigh:
		severityEmoji = "🔥"
		color = "#ECB22E"
	case domain.SeverityMedium:
		severityEmoji = "⚡"
		color = "#2EB886"
	case domain.SeverityLow:
		severityEmoji = "ℹ️"
		color = "#4A154B"
	default:
		severityEmoji = "🔍"
		color = "#808080"
	}

	exploitedStr := "No"
	if v.IsExploited {
		exploitedStr = "🚨 *YES (Confirmed Exploited in the Wild)*"
	}

	cvssStr := "N/A"
	if v.CvssScore != nil {
		cvssStr = fmt.Sprintf("%.1f", *v.CvssScore)
	}

	var catBadges []string
	for _, c := range v.Categories {
		catBadges = append(catBadges, fmt.Sprintf("*`%s`*", c))
	}
	categoriesStr := strings.Join(catBadges, " ")
	if categoriesStr == "" {
		categoriesStr = "*`General`*"
	}

	sourcesStr := strings.Join(v.Sources, ", ")
	if sourcesStr == "" {
		sourcesStr = "Unknown"
	}

	nvdURL := fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CveID)
	cveOrgURL := fmt.Sprintf("https://www.cve.org/CVERecord?id=%s", v.CveID)

	desc := strings.TrimSpace(v.Description)
	if len(desc) > 300 {
		desc = desc[:297] + "..."
	}
	desc = strings.ReplaceAll(desc, "\n", " ")

	var pocLines []string
	for i, p := range v.PoCs {
		if i >= 4 {
			pocLines = append(pocLines, fmt.Sprintf("_...and %d more exploits available_", len(v.PoCs)-4))
			break
		}

		label := p.URL
		if strings.Contains(p.URL, "github.com/") {
			parts := strings.Split(p.URL, "github.com/")
			if len(parts) > 1 && parts[1] != "" {
				label = parts[1]
			}
		} else if strings.Contains(p.URL, "exploit-db.com/exploits/") {
			parts := strings.Split(p.URL, "exploit-db.com/exploits/")
			if len(parts) > 1 && parts[1] != "" {
				label = "Exploit-DB #" + parts[1]
			}
		}

		line := fmt.Sprintf("• <%s|*%s*>", p.URL, label)
		if p.Author != "" {
			line += fmt.Sprintf(" (by `%s`)", p.Author)
		}
		pocLines = append(pocLines, line)
	}

	pocsText := strings.Join(pocLines, "\n")
	if pocsText == "" {
		pocsText = "_No public PoC released yet._"
	}

	replacements := map[string]string{
		"{{cve_id}}":         v.CveID,
		"{{title}}":          v.Title,
		"{{description}}":    desc,
		"{{severity}}":       string(v.Severity),
		"{{severity_emoji}}": severityEmoji,
		"{{color}}":          color,
		"{{cvss}}":           cvssStr,
		"{{in_the_wild}}":    exploitedStr,
		"{{categories}}":     categoriesStr,
		"{{sources}}":        sourcesStr,
		"{{nvd_url}}":        nvdURL,
		"{{cve_org_url}}":    cveOrgURL,
		"{{pocs}}":           pocsText,
		"{{time_utc}}":       time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	}

	tmpl := n.cfg.Template
	if strings.TrimSpace(tmpl) == "" {
		tmpl = defaultSlackTemplate
	}

	rendered := tmpl
	for k, val := range replacements {
		rendered = strings.ReplaceAll(rendered, k, val)
	}

	return map[string]any{
		"attachments": []map[string]any{
			{
				"color":     color,
				"text":      strings.TrimSpace(rendered),
				"mrkdwn_in": []string{"text"},
				"footer":    fmt.Sprintf("Raven Threat Intelligence • Sources: %s • %s", sourcesStr, time.Now().UTC().Format("2006-01-02 15:04:05 UTC")),
			},
		},
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

	header := "🔔 [Slack Block Kit Preview]"
	if n.endpoint.Name != "" {
		header = fmt.Sprintf("🔔 [Slack Preview: %s]", n.endpoint.Name)
	}

	content := fmt.Sprintf(
		"%s\n%s: %s\n%s %s | %s %v | %s %t\n",
		header,
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
