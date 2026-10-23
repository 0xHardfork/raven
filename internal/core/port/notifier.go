package port

import (
	"context"

	"raven/internal/core/domain"
)

// NotifierPort 告警推送接口
type NotifierPort interface {
	// SendThreatAlert 发送单条高危威胁情报预警卡片
	SendThreatAlert(ctx context.Context, vuln *domain.Vulnerability) error

	// SendBatchAlert 批量发送摘要预警通知
	SendBatchAlert(ctx context.Context, vulns []*domain.Vulnerability) error
}
