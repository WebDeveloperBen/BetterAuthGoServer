package apikey

import (
	"io/fs"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey/db/migrations"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// apikeyMigrations implements migrate.Source for the APIKey plugin.
type apikeyMigrations struct{}

func (m *apikeyMigrations) Name() string {
	return "apikey"
}

func (m *apikeyMigrations) FS() fs.FS {
	return migrations.FS
}

func (m *apikeyMigrations) Dependencies() []string {
	return nil // depends only on core
}

// Migrations returns the migration source for the APIKey plugin.
// Use this with migrate.Run() to include APIKey tables in your migrations.
//
// Example:
//
//	err := migrate.Run(ctx, db, migrate.DialectPostgres,
//	    migrate.WithPlugins(apikey.Migrations()),
//	)
func Migrations() migrate.Source {
	return &apikeyMigrations{}
}
