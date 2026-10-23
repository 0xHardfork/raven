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

// CollectSummary 采集结果汇总
type CollectSummary struct {
	TotalScripts int                     `json:"total_scripts"`
	TotalFound   int                     `json:"total_found"`
	Inserted     int                     `json:"inserted"`
	Updated      int                     `json:"updated"`
	Vulns        []*domain.Vulnerability `json:"vulns,omitempty"`
}

// CollectorService 核心采集调度服务
type CollectorService struct {
	runner   port.ScriptRunnerPort
	repo     port.RepositoryPort
	notifier port.NotifierPort
}

// NewCollectorService 创建采集服务
func NewCollectorService(runner port.ScriptRunnerPort, repo port.RepositoryPort, notifier port.NotifierPort) *CollectorService {
	return &CollectorService{
		runner:   runner,
		repo:     repo,
		notifier: notifier,
	}
}

// CollectAll 执行全量或指定生态分类的脚本采集
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

	// 若存在持久化仓库，执行批量 Upsert 存储
	if s.repo != nil && len(allVulns) > 0 {
		ins, upd, err := s.repo.BatchUpsert(ctx, allVulns)
		if err != nil {
			return summary, fmt.Errorf("batch upsert failed: %w", err)
		}
		summary.Inserted = ins
		summary.Updated = upd
	}

	// 若配置了通知且发现了新威胁，触发推送检查
	if s.notifier != nil && len(allVulns) > 0 {
		for _, v := range allVulns {
			_ = s.notifier.SendThreatAlert(ctx, v)
		}
	}

	return summary, nil
}

// CollectScript 执行单个脚本采集
func (s *CollectorService) CollectScript(ctx context.Context, scriptPath string, targetCategories []string) ([]*domain.Vulnerability, error) {
	var args []string
	if len(targetCategories) > 0 {
		args = append(args, "--categories", strings.Join(targetCategories, ","))
	}

	vulns, err := s.runner.RunScript(ctx, scriptPath, args...)
	if err != nil {
		return nil, err
	}

	// 若设置了分类过滤，过滤出包含目标分类的条目
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

// CollectSource 根据数据源名称定位并执行脚本 (如 source="github" -> "github_pocs.py")
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
