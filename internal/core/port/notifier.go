package port

import (
	"context"

	"raven/internal/core/domain"
)

type NotifierPort interface {
	SendThreatAlert(ctx context.Context, vuln *domain.Vulnerability) error
	SendBatchAlert(ctx context.Context, vulns []*domain.Vulnerability) error
}
