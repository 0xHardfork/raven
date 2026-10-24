package python

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"raven/internal/core/domain"
	"raven/internal/core/port"
	"raven/internal/pkg/config"
	"raven/internal/pkg/logger"
)

type Runner struct {
	cfg      config.PythonConfig
	scrapers config.ScrapersConfig
}

var _ port.ScriptRunnerPort = (*Runner)(nil)

func NewRunner(cfg config.PythonConfig, scrapers ...config.ScrapersConfig) *Runner {
	if cfg.BinaryPath == "" {
		cfg.BinaryPath = "python3"
	}
	if cfg.ScriptsDir == "" {
		cfg.ScriptsDir = "scripts"
	}
	if cfg.TimeoutSec <= 0 {
		cfg.TimeoutSec = 60
	}
	var sc config.ScrapersConfig
	if len(scrapers) > 0 {
		sc = scrapers[0]
	}
	return &Runner{cfg: cfg, scrapers: sc}
}

func (r *Runner) appendConfigArgs(scriptPath string, args []string) []string {
	hasFlag := func(flag string) bool {
		for _, a := range args {
			if a == flag || strings.HasPrefix(a, flag+"=") {
				return true
			}
		}
		return false
	}

	result := append([]string{}, args...)
	globalKeywords := r.scrapers.AllKeywords()

	if strings.Contains(scriptPath, "github_pocs") {
		if r.scrapers.GitHub.Query != "" && !hasFlag("--query") {
			result = append(result, "--query", r.scrapers.GitHub.Query)
		}
		keywords := r.scrapers.GitHub.Keywords
		if len(keywords) == 0 {
			keywords = globalKeywords
		}
		if len(keywords) > 0 && !hasFlag("--keywords") {
			result = append(result, "--keywords", strings.Join(keywords, ","))
		}
		if r.scrapers.GitHub.Token != "" && !hasFlag("--token") {
			result = append(result, "--token", r.scrapers.GitHub.Token)
		}
		if r.scrapers.GitHub.Limit > 0 && !hasFlag("--limit") {
			result = append(result, "--limit", strconv.Itoa(r.scrapers.GitHub.Limit))
		}
	} else if strings.Contains(scriptPath, "cisa_kev") {
		if r.scrapers.CISA.FeedURL != "" && !hasFlag("--url") {
			result = append(result, "--url", r.scrapers.CISA.FeedURL)
		}
		keywords := r.scrapers.CISA.Keywords
		if len(keywords) == 0 {
			keywords = globalKeywords
		}
		if len(keywords) > 0 && !hasFlag("--keywords") {
			result = append(result, "--keywords", strings.Join(keywords, ","))
		}
		if r.scrapers.CISA.Limit > 0 && !hasFlag("--limit") {
			result = append(result, "--limit", strconv.Itoa(r.scrapers.CISA.Limit))
		}
	} else if strings.Contains(scriptPath, "exploit_db") {
		if r.scrapers.ExploitDB.CSVURL != "" && !hasFlag("--csv-url") {
			result = append(result, "--csv-url", r.scrapers.ExploitDB.CSVURL)
		}
		keywords := r.scrapers.ExploitDB.Keywords
		if len(keywords) == 0 {
			keywords = globalKeywords
		}
		if len(keywords) > 0 && !hasFlag("--keywords") {
			result = append(result, "--keywords", strings.Join(keywords, ","))
		}
		if r.scrapers.ExploitDB.Limit > 0 && !hasFlag("--limit") {
			result = append(result, "--limit", strconv.Itoa(r.scrapers.ExploitDB.Limit))
		}
	} else if strings.Contains(scriptPath, "nvd_cve") {
		if r.scrapers.NVD.Days > 0 && !hasFlag("--days") {
			result = append(result, "--days", strconv.Itoa(r.scrapers.NVD.Days))
		}
		keywords := r.scrapers.NVD.Keywords
		if len(keywords) == 0 {
			keywords = globalKeywords
		}
		if len(keywords) > 0 && !hasFlag("--keywords") {
			result = append(result, "--keywords", strings.Join(keywords, ","))
		}
		if r.scrapers.NVD.APIKey != "" && !hasFlag("--api-key") {
			result = append(result, "--api-key", r.scrapers.NVD.APIKey)
		}
		if r.scrapers.NVD.Limit > 0 && !hasFlag("--limit") {
			result = append(result, "--limit", strconv.Itoa(r.scrapers.NVD.Limit))
		}
	}

	return result
}

func (r *Runner) RunScript(ctx context.Context, scriptPath string, args ...string) ([]*domain.Vulnerability, error) {
	timeout := time.Duration(r.cfg.TimeoutSec) * time.Second
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	fullArgs := r.appendConfigArgs(scriptPath, args)
	cmdArgs := append([]string{scriptPath}, fullArgs...)
	cmd := exec.CommandContext(execCtx, r.cfg.BinaryPath, cmdArgs...)

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	logger.L().Info("executing python scraper",
		"script", scriptPath,
		"args", fullArgs,
		"timeout", timeout.String(),
	)

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	stderrStr := strings.TrimSpace(stderrBuf.String())
	if stderrStr != "" {
		logger.L().Debug("python script stderr output",
			"script", scriptPath,
			"stderr", stderrStr,
		)
	}

	if err != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("python script '%s' timed out after %v", scriptPath, timeout)
		}
		return nil, fmt.Errorf("python script '%s' execution failed (%v): %s (err: %w)",
			scriptPath, duration, stderrStr, err)
	}

	stdoutBytes := stdoutBuf.Bytes()
	if len(bytes.TrimSpace(stdoutBytes)) == 0 {
		logger.L().Warn("python script output empty", "script", scriptPath)
		return []*domain.Vulnerability{}, nil
	}

	var rawItems []struct {
		CveID       string         `json:"cve_id"`
		Title       string         `json:"title"`
		Description string         `json:"description"`
		Severity    string         `json:"severity"`
		CvssScore   *float64       `json:"cvss_score"`
		Categories  []string       `json:"categories"`
		IsExploited bool           `json:"is_exploited"`
		PoCs        []domain.PoC   `json:"pocs"`
		Source      string         `json:"source"`
		PublishedAt *string        `json:"published_at"`
		RawData     map[string]any `json:"raw_data"`
	}

	if err := json.Unmarshal(stdoutBytes, &rawItems); err != nil {
		return nil, fmt.Errorf("unmarshal python script json output failed: %w (raw output snippet: %s)",
			err, string(stdoutBytes[:min(len(stdoutBytes), 200)]))
	}

	result := make([]*domain.Vulnerability, 0, len(rawItems))
	for _, item := range rawItems {
		cve := strings.ToUpper(strings.TrimSpace(item.CveID))
		if cve == "" {
			continue
		}

		v := &domain.Vulnerability{
			CveID:       cve,
			Title:       item.Title,
			Description: item.Description,
			Severity:    domain.NormalizeSeverity(item.Severity),
			CvssScore:   item.CvssScore,
			Categories:  item.Categories,
			IsExploited: item.IsExploited,
			PoCs:        item.PoCs,
			RawData:     item.RawData,
		}

		if item.Source != "" {
			v.Sources = []string{item.Source}
		} else {
			v.Sources = []string{filepath.Base(scriptPath)}
		}

		if item.PublishedAt != nil && *item.PublishedAt != "" {
			if t, err := time.Parse(time.RFC3339, *item.PublishedAt); err == nil {
				v.PublishedAt = &t
			}
		}

		v.Normalize()
		result = append(result, v)
	}

	logger.L().Info("python scraper completed",
		"script", scriptPath,
		"records_found", len(result),
		"duration", duration.String(),
	)

	return result, nil
}

func (r *Runner) ListScripts(ctx context.Context) ([]string, error) {
	dir := r.cfg.ScriptsDir
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return []string{}, nil
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read scripts dir '%s' failed: %w", dir, err)
	}

	var scripts []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".py") && !strings.HasPrefix(name, "_") {
			scripts = append(scripts, filepath.Join(dir, name))
		}
	}
	return scripts, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
