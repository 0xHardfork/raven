package notifier

import (
	"context"
	"sync"

	"raven/internal/adapter/notifier/slack"
	"raven/internal/core/domain"
	"raven/internal/core/port"
	"raven/internal/pkg/config"
	"raven/internal/pkg/logger"
)

type Manager struct {
	cfg      config.NotifierConfig
	channels []port.NotifierPort
}

var _ port.NotifierPort = (*Manager)(nil)

func NewManager(cfg config.NotifierConfig) *Manager {
	m := &Manager{
		cfg:      cfg,
		channels: make([]port.NotifierPort, 0),
	}

	if cfg.Channels.Slack.Enabled || cfg.DryRun {
		endpoints := cfg.Channels.Slack.AllEndpoints(cfg.FilterCategories, cfg.MinSeverity)
		if len(endpoints) == 0 && cfg.DryRun {
			m.channels = append(m.channels, slack.NewNotifier(cfg.Channels.Slack, cfg.DryRun))
		} else {
			for _, ep := range endpoints {
				m.channels = append(m.channels, slack.NewNotifier(cfg.Channels.Slack, cfg.DryRun, ep))
			}
		}
	}

	return m
}

func (m *Manager) ShouldNotify(v *domain.Vulnerability) bool {
	if !m.cfg.Enabled && !m.cfg.DryRun {
		return false
	}

	if len(m.cfg.FilterCategories) > 0 {
		if !domain.MatchAnyCategoryRule(m.cfg.FilterCategories, v.Categories) {
			return false
		}
	} else if len(m.cfg.Channels.Slack.Endpoints) > 0 {
		allCats := m.cfg.AllTargetCategories()
		if len(allCats) > 0 && !domain.MatchAnyCategoryRule(allCats, v.Categories) {
			return false
		}
	}

	if v.IsExploited && m.cfg.AlwaysNotifyExploited {
		return true
	}

	if m.cfg.MinSeverity != "" {
		minWeight := domain.NormalizeSeverity(m.cfg.MinSeverity).Weight()
		if v.Severity.Weight() < minWeight {
			return false
		}
	}

	if m.cfg.OnlyWithPoC && len(v.PoCs) == 0 {
		return false
	}

	return true
}

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

func (m *Manager) SendBatchAlert(ctx context.Context, vulns []*domain.Vulnerability) error {
	for _, v := range vulns {
		_ = m.SendThreatAlert(ctx, v)
	}
	return nil
}
