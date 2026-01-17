package oauth

import (
	"io/fs"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db/migrations"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// oauthMigrations implements migrate.Source for the OAuth plugin.
type oauthMigrations struct{}

func (m *oauthMigrations) Name() string {
	return "oauth"
}

func (m *oauthMigrations) FS() fs.FS {
	return migrations.FS
}

func (m *oauthMigrations) Dependencies() []string {
	return nil // depends only on core
}

// Migrations returns the migration source for the OAuth plugin.
// Use this with migrate.Run() to include OAuth tables in your migrations.
//
// Example:
//
//	err := migrate.Run(ctx, db, migrate.DialectPostgres,
//	    migrate.WithPlugins(oauth.Migrations()),
//	)
func Migrations() migrate.Source {
	return &oauthMigrations{}
}
