package service

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"raven/internal/core/domain"
	"raven/internal/core/port"
	"raven/internal/pkg/logger"
)

type CollectSummary struct {
	TotalScripts int                     `json:"total_scripts"`
	TotalFound   int                     `json:"total_found"`
	Inserted     int                     `json:"inserted"`
	Updated      int                     `json:"updated"`
	Vulns        []*domain.Vulnerability `json:"vulns,omitempty"`
}

type CollectorService struct {
	runner   port.ScriptRunnerPort
	repo     port.RepositoryPort
	notifier port.NotifierPort
}

func NewCollectorService(runner port.ScriptRunnerPort, repo port.RepositoryPort, notifier port.NotifierPort) *CollectorService {
	return &CollectorService{
		runner:   runner,
		repo:     repo,
		notifier: notifier,
	}
}

func (s *CollectorService) CollectAll(ctx context.Context, targetCategories []string) (*CollectSummary, error) {
	scripts, err := s.runner.ListScripts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list scripts failed: %w", err)
	}

	summary := &CollectSummary{
		TotalScripts: len(scripts),
	}

	var allVulns []*domain.Vulnerability
	for _, script := range scripts {
		vulns, err := s.CollectScript(ctx, script, targetCategories)
		if err != nil {
			logger.L().Error("script collection error, skipping",
				"script", script,
				"error", err,
			)
			continue
		}
		allVulns = append(allVulns, vulns...)
	}

	summary.TotalFound = len(allVulns)
	summary.Vulns = allVulns

	if s.repo != nil && len(allVulns) > 0 {
		ins, upd, err := s.repo.BatchUpsert(ctx, allVulns)
		if err != nil {
			return summary, fmt.Errorf("batch upsert failed: %w", err)
		}
		summary.Inserted = ins
		summary.Updated = upd
	}

	if s.notifier != nil && len(allVulns) > 0 {
		for _, v := range allVulns {
			_ = s.notifier.SendThreatAlert(ctx, v)
		}
	}

	return summary, nil
}

func (s *CollectorService) CollectScript(ctx context.Context, scriptPath string, targetCategories []string) ([]*domain.Vulnerability, error) {
	var args []string
	if len(targetCategories) > 0 {
		args = append(args, "--categories", strings.Join(targetCategories, ","))
	}

	vulns, err := s.runner.RunScript(ctx, scriptPath, args...)
	if err != nil {
		return nil, err
	}

	if len(targetCategories) > 0 {
		targetMap := make(map[string]struct{})
		for _, c := range targetCategories {
			targetMap[strings.ToLower(strings.TrimSpace(c))] = struct{}{}
		}

		filtered := make([]*domain.Vulnerability, 0, len(vulns))
		for _, v := range vulns {
			matched := false
			for _, cat := range v.Categories {
				if _, ok := targetMap[strings.ToLower(cat)]; ok {
					matched = true
					break
				}
			}
			if matched {
				filtered = append(filtered, v)
			}
		}
		vulns = filtered
	}

	return vulns, nil
}

func (s *CollectorService) CollectSource(ctx context.Context, source string, targetCategories []string) ([]*domain.Vulnerability, error) {
	scripts, err := s.runner.ListScripts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list scripts failed: %w", err)
	}

	sourceLower := strings.ToLower(strings.TrimSpace(source))
	var matchedScript string
	for _, sc := range scripts {
		base := strings.ToLower(filepath.Base(sc))
		if strings.Contains(base, sourceLower) {
			matchedScript = sc
			break
		}
	}

	if matchedScript == "" {
		return nil, fmt.Errorf("no scraper script found matching source '%s'", source)
	}

	return s.CollectScript(ctx, matchedScript, targetCategories)
}
