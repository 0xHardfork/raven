package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"raven/internal/adapter/api/handler"
	"raven/internal/core/service"
	"raven/internal/pkg/logger"
)

// RouterConfig 路由配置项
type RouterConfig struct {
	ThreatService    *service.ThreatQueryService
	CollectorService *service.CollectorService
	Debug            bool
}

// SetupRouter 初始化 Gin HTTP 路由引擎与中间件
func SetupRouter(cfg RouterConfig) *gin.Engine {
	if !cfg.Debug {
		gin.SetMode(gin.ReleaseMode)
	} else {
		gin.SetMode(gin.DebugMode)
	}

	r := gin.New()

	// 1. 中间件：异常恢复
	r.Use(gin.Recovery())

	// 2. 中间件：结构化日志审计
	r.Use(func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		rawQuery := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method

		if rawQuery != "" {
			path = path + "?" + rawQuery
		}

		logger.L().Info("http request",
			"status", status,
			"method", method,
			"path", path,
			"ip", clientIP,
			"latency_ms", latency.Milliseconds(),
		)
	})

	// 3. 中间件：CORS 跨域支持
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// 4. 基础探针
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"time":   time.Now().Format(time.RFC3339),
			"app":    "raven",
		})
	})

	// 5. 业务 API 分组 /api/v1
	v1 := r.Group("/api/v1")
	{
		// 基础探针
		v1.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok"})
		})

		// 威胁情报接口
		if cfg.ThreatService != nil {
			threatH := handler.NewThreatHandler(cfg.ThreatService)
			threats := v1.Group("/threats")
			{
				threats.GET("", threatH.GetThreats)
				threats.GET("/categories", threatH.GetCategories)
				threats.GET("/:cve_id", threatH.GetThreatDetail)
			}
			v1.GET("/stats", threatH.GetStats)
		}

		// 采集任务触发与状态接口
		if cfg.CollectorService != nil {
			collectH := handler.NewCollectorHandler(cfg.CollectorService)
			collect := v1.Group("/collect")
			{
				collect.POST("/trigger", collectH.Trigger)
				collect.GET("/status", collectH.Status)
			}
		}
	}

	return r
}
