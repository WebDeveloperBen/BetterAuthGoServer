// Package migrations provides embedded SQL migration files for the DeviceAuth plugin.
package migrations

import "embed"

// FS contains all DeviceAuth migration files for all supported dialects.
//
//go:embed postgres/*.sql sqlite/*.sql mysql/*.sql
var FS embed.FS
