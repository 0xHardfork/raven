package notifier

import (
	"context"
	"strings"
	"sync"

	"raven/internal/adapter/notifier/slack"
	"raven/internal/core/domain"
	"raven/internal/core/port"
	"raven/internal/pkg/config"
	"raven/internal/pkg/logger"
)

// Manager 多渠道告警推送统一分发管理器
type Manager struct {
	cfg      config.NotifierConfig
	channels []port.NotifierPort
}

var _ port.NotifierPort = (*Manager)(nil)

// NewManager 根据配置初始化推送管理器
func NewManager(cfg config.NotifierConfig) *Manager {
	m := &Manager{
		cfg:      cfg,
		channels: make([]port.NotifierPort, 0),
	}

	// 注册 Slack 适配器
	if cfg.Channels.Slack.Enabled || cfg.DryRun {
		m.channels = append(m.channels, slack.NewNotifier(cfg.Channels.Slack, cfg.DryRun))
	}

	return m
}

// ShouldNotify 判定当前漏洞是否满足告警过滤规则
func (m *Manager) ShouldNotify(v *domain.Vulnerability) bool {
	if !m.cfg.Enabled && !m.cfg.DryRun {
		return false
	}

	// 1. 如果命中在野利用且配置了无条件推送
	if v.IsExploited && m.cfg.AlwaysNotifyExploited {
		return true
	}

	// 2. 评级门槛过滤
	if m.cfg.MinSeverity != "" {
		minWeight := domain.NormalizeSeverity(m.cfg.MinSeverity).Weight()
		if v.Severity.Weight() < minWeight {
			return false
		}
	}

	// 3. PoC 存在性过滤
	if m.cfg.OnlyWithPoC && len(v.PoCs) == 0 {
		return false
	}

	// 4. 生态技术栈关注过滤
	if len(m.cfg.FilterCategories) > 0 {
		match := false
		for _, target := range m.cfg.FilterCategories {
			targetLower := strings.ToLower(strings.TrimSpace(target))
			for _, c := range v.Categories {
				if strings.ToLower(c) == targetLower {
					match = true
					break
				}
			}
			if match {
				break
			}
		}
		if !match {
			return false
		}
	}

	return true
}

// SendThreatAlert 扇出异步推送至所有已激活渠道
func (m *Manager) SendThreatAlert(ctx context.Context, vuln *domain.Vulnerability) error {
	if !m.ShouldNotify(vuln) {
		return nil
	}

	var wg sync.WaitGroup
	for _, ch := range m.channels {
		wg.Add(1)
		go func(channel port.NotifierPort) {
			defer wg.Done()
			if err := channel.SendThreatAlert(ctx, vuln); err != nil {
				logger.L().Error("notify channel dispatch failed",
					"cve", vuln.CveID,
					"error", err,
				)
			}
		}(ch)
	}
	wg.Wait()
	return nil
}

// SendBatchAlert 批量发送预警
func (m *Manager) SendBatchAlert(ctx context.Context, vulns []*domain.Vulnerability) error {
	for _, v := range vulns {
		_ = m.SendThreatAlert(ctx, v)
	}
	return nil
}
