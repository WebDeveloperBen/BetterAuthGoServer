// Package migrations provides embedded SQL migration files for core authentication tables.
package migrations

import "embed"

// FS contains all core migration files for all supported dialects.
// Structure:
//
//	postgres/000001_initial_schema.up.sql
//	postgres/000001_initial_schema.down.sql
//	sqlite/000001_initial_schema.up.sql
//	sqlite/000001_initial_schema.down.sql
//	mysql/000001_initial_schema.up.sql
//	mysql/000001_initial_schema.down.sql
//
//go:embed postgres/*.sql sqlite/*.sql mysql/*.sql
var FS embed.FS
