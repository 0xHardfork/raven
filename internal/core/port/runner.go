package port

import (
	"context"

	"raven/internal/core/domain"
)

// ScriptRunnerPort 外部脚本调度与执行器接口
type ScriptRunnerPort interface {
	// RunScript 执行指定脚本文件并解析返回规范化漏洞实体列表
	RunScript(ctx context.Context, scriptPath string, args ...string) ([]*domain.Vulnerability, error)

	// ListScripts 发现并列出所有可用的采集脚本文件列表
	ListScripts(ctx context.Context) ([]string, error)
}
