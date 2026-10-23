package handler

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"raven/internal/core/domain"
	"raven/internal/core/service"
)

// Response 通用 API 响应结构
type Response struct {
	Code    int    `json:"code"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
}

// ThreatHandler 威胁情报查询 API 处理器
type ThreatHandler struct {
	threatService *service.ThreatQueryService
}

// NewThreatHandler 创建 ThreatHandler
func NewThreatHandler(threatService *service.ThreatQueryService) *ThreatHandler {
	return &ThreatHandler{threatService: threatService}
}

// GetThreats 多维过滤分页检索漏洞列表
// GET /api/v1/threats?category=java&has_poc=true&severity=CRITICAL&page=1&limit=20&keyword=...
func (h *ThreatHandler) GetThreats(c *gin.Context) {
	filter := domain.ThreatFilter{
		CveID:   c.Query("cve_id"),
		Keyword: c.Query("keyword"),
	}

	// category 参数支持逗号分割或多次传递
	if cat := c.Query("category"); cat != "" {
		for _, item := range strings.Split(cat, ",") {
			if item = strings.TrimSpace(item); item != "" {
				filter.Categories = append(filter.Categories, item)
			}
		}
	}
	if cats := c.QueryArray("categories"); len(cats) > 0 {
		filter.Categories = append(filter.Categories, cats...)
	}

	if sev := c.Query("severity"); sev != "" {
		filter.Severity = string(domain.NormalizeSeverity(sev))
	}

	if pocStr := c.Query("has_poc"); pocStr != "" {
		if val, err := strconv.ParseBool(pocStr); err == nil {
			filter.HasPoC = &val
		}
	}

	if expStr := c.Query("is_exploited"); expStr != "" {
		if val, err := strconv.ParseBool(expStr); err == nil {
			filter.IsExploited = &val
		}
	}

	// 分页参数 (兼容 page/page_size 与 limit)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", c.DefaultQuery("limit", "20")))
	filter.Page = page
	filter.PageSize = pageSize

	result, err := h.threatService.SearchThreats(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    http.StatusInternalServerError,
			Message: "search threats failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code: 0,
		Data: result,
	})
}

// GetThreatDetail 查询单条漏洞详情
// GET /api/v1/threats/:cve_id
func (h *ThreatHandler) GetThreatDetail(c *gin.Context) {
	cveID := c.Param("cve_id")
	if strings.TrimSpace(cveID) == "" {
		c.JSON(http.StatusBadRequest, Response{
			Code:    http.StatusBadRequest,
			Message: "cve_id path parameter is required",
		})
		return
	}

	vuln, err := h.threatService.GetThreat(c.Request.Context(), cveID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    http.StatusInternalServerError,
			Message: "get threat detail failed: " + err.Error(),
		})
		return
	}

	if vuln == nil {
		c.JSON(http.StatusNotFound, Response{
			Code:    http.StatusNotFound,
			Message: "threat with cve_id '" + cveID + "' not found",
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code: 0,
		Data: vuln,
	})
}

// GetCategories 获取所有生态标签统计
// GET /api/v1/threats/categories
func (h *ThreatHandler) GetCategories(c *gin.Context) {
	categories, err := h.threatService.GetCategories(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    http.StatusInternalServerError,
			Message: "get categories failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code: 0,
		Data: categories,
	})
}

// GetStats 获取全局威胁大盘指标统计
// GET /api/v1/stats
func (h *ThreatHandler) GetStats(c *gin.Context) {
	stats, err := h.threatService.GetStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{
			Code:    http.StatusInternalServerError,
			Message: "get system stats failed: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, Response{
		Code: 0,
		Data: stats,
	})
}
