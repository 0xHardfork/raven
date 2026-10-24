package service

import (
	"context"
	"time"

	"raven/internal/core/port"
	"raven/internal/pkg/logger"
)

type WatcherService struct {
	collector *CollectorService
	notifier  port.NotifierPort
}

func NewWatcherService(collector *CollectorService, notifier port.NotifierPort) *WatcherService {
	return &WatcherService{
		collector: collector,
		notifier:  notifier,
	}
}

func (w *WatcherService) Start(ctx context.Context, interval time.Duration, categories []string) error {
	logger.L().Info("starting threat watcher daemon",
		"interval", interval.String(),
		"categories", categories,
	)

	w.runOnce(ctx, categories)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.L().Info("threat watcher daemon stopped")
			return ctx.Err()
		case <-ticker.C:
			w.runOnce(ctx, categories)
		}
	}
}

func (w *WatcherService) runOnce(ctx context.Context, categories []string) {
	logger.L().Info("running scheduled threat poll cycle")
	start := time.Now()

	summary, err := w.collector.CollectAll(ctx, categories)
	if err != nil {
		logger.L().Error("scheduled collection cycle error", "error", err)
		return
	}

	logger.L().Info("scheduled poll cycle finished",
		"scripts", summary.TotalScripts,
		"found", summary.TotalFound,
		"inserted", summary.Inserted,
		"updated", summary.Updated,
		"duration", time.Since(start).String(),
	)
}
