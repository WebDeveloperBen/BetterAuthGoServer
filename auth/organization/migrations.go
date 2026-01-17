package organization

import (
	"io/fs"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization/db/migrations"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// organizationMigrations implements migrate.Source for the Organization plugin.
type organizationMigrations struct{}

func (m *organizationMigrations) Name() string {
	return "organization"
}

func (m *organizationMigrations) FS() fs.FS {
	return migrations.FS
}

func (m *organizationMigrations) Dependencies() []string {
	return nil // depends only on core
}

// Migrations returns the migration source for the Organization plugin.
// Use this with migrate.Run() to include Organization tables in your migrations.
//
// Example:
//
//	err := migrate.Run(ctx, db, migrate.DialectPostgres,
//	    migrate.WithPlugins(organization.Migrations()),
//	)
func Migrations() migrate.Source {
	return &organizationMigrations{}
}
