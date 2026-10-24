package port

import (
	"context"

	"raven/internal/core/domain"
)

type ScriptRunnerPort interface {
	RunScript(ctx context.Context, scriptPath string, args ...string) ([]*domain.Vulnerability, error)
	ListScripts(ctx context.Context) ([]string, error)
}
