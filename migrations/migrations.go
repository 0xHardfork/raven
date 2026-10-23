package migrations

import "embed"

// FS 内嵌所有版本化 SQL 迁移文件
//
//go:embed *.sql
var FS embed.FS
