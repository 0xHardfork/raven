---
trigger: always_on
---

# Golang 编码与工程质量规范

## 1. 语言版本与风格
- 目标版本：**Go 1.22+**。
- 遵循官方 Effective Go 与 Go Code Review Comments。
- 代码必须通过 `go vet` 和 `golangci-lint` 检查，零警告通过。

## 2. 错误处理规范
- **禁止静默忽略错误**：绝对不能出现 `_ = err` 或吞掉 error 的情况。
- **错误包装与上下文**：使用 `fmt.Errorf("operation failed: %w", err)` 包装错误保留堆栈链。
- **错误断言**：统一使用 `errors.Is` 和 `errors.As` 进行错误类型判断。
- **禁止无故 Panic**：除程序启动阶段关键配置完全损坏无法初始化外，常规运行时代码严禁调用 `panic()`。

## 3. 并发安全与资源释放
- **Goroutine 生命周期管控**：启动任何 goroutine 必须明确其退出机制（通过 `ctx.Done()` 或 channel 监听），严防 goroutine 泄漏。
- **资源清理**：数据库连接、文件句柄、HTTP Response Body 必须使用 `defer resp.Body.Close()` 或相应 Cleanup 函数确保及时释放。
- **无全局可变状态**：严禁定义全局 map、全局 slice 等未加锁的可变对象。配置与连接对象一律通过依赖注入传递。

## 4. 测试标准
- 单元测试覆盖核心服务层（`internal/core/service`）的计算与合并逻辑。
- 数据库与网络操作支持基于 Interface 的 Mock 验证。

## 5. 禁止对代码添加注释 所有代码要可以自解释