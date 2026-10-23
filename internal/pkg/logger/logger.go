package logger

import (
	"log/slog"
	"os"
	"strings"
)

var defaultLogger *slog.Logger

func init() {
	// 默认初始化 Text 结构化 Logger
	opts := &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}
	handler := slog.NewTextHandler(os.Stderr, opts)
	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
}

// Init 根据环境初始化全局 Logger
func Init(levelStr string, jsonFormat bool) *slog.Logger {
	var level slog.Level
	switch strings.ToUpper(levelStr) {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}

	var handler slog.Handler
	if jsonFormat {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	defaultLogger = slog.New(handler)
	slog.SetDefault(defaultLogger)
	return defaultLogger
}

// L 返回默认全局 logger 实例
func L() *slog.Logger {
	return defaultLogger
}
