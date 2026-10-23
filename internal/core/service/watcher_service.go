package service

import (
	"context"
	"time"

	"raven/internal/core/port"
	"raven/internal/pkg/logger"
)

// WatcherService 定时守护巡检服务
type WatcherService struct {
	collector *CollectorService
	notifier  port.NotifierPort
}

// NewWatcherService 创建守护巡检服务
func NewWatcherService(collector *CollectorService, notifier port.NotifierPort) *WatcherService {
	return &WatcherService{
		collector: collector,
		notifier:  notifier,
	}
}

// Start 启动定时轮询监听循环
func (w *WatcherService) Start(ctx context.Context, interval time.Duration, categories []string) error {
	logger.L().Info("starting threat watcher daemon",
		"interval", interval.String(),
		"categories", categories,
	)

	// 启动时立即执行一次巡检
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
