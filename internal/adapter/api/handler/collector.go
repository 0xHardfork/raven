package handler

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"raven/internal/core/service"
	"raven/internal/pkg/logger"
)

type TriggerRequest struct {
	Source     string   `json:"source"`
	Categories []string `json:"categories"`
}

type JobStatus struct {
	Status      string                  `json:"status"`
	StartedAt   *time.Time              `json:"started_at,omitempty"`
	FinishedAt  *time.Time              `json:"finished_at,omitempty"`
	LastSummary *service.CollectSummary `json:"last_summary,omitempty"`
	LastError   string                  `json:"last_error,omitempty"`
}

type CollectorHandler struct {
	collectorService *service.CollectorService
	mu               sync.RWMutex
	jobStatus        JobStatus
}

func NewCollectorHandler(collectorService *service.CollectorService) *CollectorHandler {
	return &CollectorHandler{
		collectorService: collectorService,
		jobStatus: JobStatus{
			Status: "idle",
		},
	}
}

func (h *CollectorHandler) Trigger(c *gin.Context) {
	var req TriggerRequest
	if err := c.ShouldBindJSON(&req); err != nil && c.Request.ContentLength > 0 {
		c.JSON(http.StatusBadRequest, Response{
			Code:    http.StatusBadRequest,
			Message: "invalid request body: " + err.Error(),
		})
		return
	}

	h.mu.Lock()
	if h.jobStatus.Status == "running" {
		h.mu.Unlock()
		c.JSON(http.StatusConflict, Response{
			Code:    http.StatusConflict,
			Message: "a collection task is already running",
			Data:    h.jobStatus,
		})
		return
	}

	now := time.Now()
	h.jobStatus = JobStatus{
		Status:    "running",
		StartedAt: &now,
	}
	h.mu.Unlock()

	go func(src string, cats []string) {
		bgCtx := context.Background()
		var summary *service.CollectSummary
		var err error

		if src != "" {
			vulns, sErr := h.collectorService.CollectSource(bgCtx, src, cats)
			if sErr != nil {
				err = sErr
			} else {
				summary = &service.CollectSummary{
					TotalScripts: 1,
					TotalFound:   len(vulns),
					Vulns:        vulns,
				}
			}
		} else {
			summary, err = h.collectorService.CollectAll(bgCtx, cats)
		}

		h.mu.Lock()
		defer h.mu.Unlock()
		finish := time.Now()
		h.jobStatus.FinishedAt = &finish
		if err != nil {
			h.jobStatus.Status = "failed"
			h.jobStatus.LastError = err.Error()
			logger.L().Error("async collection task failed", "error", err)
		} else {
			h.jobStatus.Status = "completed"
			h.jobStatus.LastSummary = summary
			h.jobStatus.LastError = ""
			logger.L().Info("async collection task finished successfully",
				"inserted", summary.Inserted,
				"updated", summary.Updated,
				"total_found", summary.TotalFound,
			)
		}
	}(req.Source, req.Categories)

	c.JSON(http.StatusAccepted, Response{
		Code:    0,
		Message: "collection task triggered successfully",
		Data: gin.H{
			"status":     "running",
			"started_at": now,
		},
	})
}

func (h *CollectorHandler) Status(c *gin.Context) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	c.JSON(http.StatusOK, Response{
		Code: 0,
		Data: h.jobStatus,
	})
}
