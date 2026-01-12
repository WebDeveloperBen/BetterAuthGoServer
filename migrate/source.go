// Package migrate provides database migration functionality for the BetterAuth SDK.
// It allows SDK consumers to run migrations for core tables and enabled plugins
// before initializing the Auth instance.
package migrate

import (
	"io/fs"

	"github.com/webdeveloperben/BetterAuthGoServer/db/migrations"
)

// Source represents a migration source (core or plugin).
// Each source contains embedded SQL migration files and declares its dependencies.
type Source interface {
	// Name returns the source name (e.g., "core", "oauth", "jwt").
	// This is used for logging and as the suffix for the migration tracking table.
	Name() string

	// FS returns the embedded filesystem containing migration files.
	// The filesystem should have dialect subdirectories: postgres/, sqlite/, mysql/
	// containing migration files named like: 000001_description.up.sql
	FS() fs.FS

	// Dependencies returns names of sources this depends on.
	// Return nil or empty slice to depend only on core.
	// Core itself returns nil (no dependencies).
	Dependencies() []string
}

// coreSource is the migration source for core authentication tables.
type coreSource struct {
	fs fs.FS
}

func (s *coreSource) Name() string {
	return "core"
}

func (s *coreSource) FS() fs.FS {
	return s.fs
}

func (s *coreSource) Dependencies() []string {
	return nil // core has no dependencies
}

// CoreMigrations returns the migration source for core authentication tables.
// This includes users, accounts, sessions, and verifications tables.
func CoreMigrations() Source {
	return &coreSource{fs: migrations.FS}
}
