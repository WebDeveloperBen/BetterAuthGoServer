package webauthn

import (
	"io/fs"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn/db/migrations"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// webauthnMigrations implements migrate.Source for the WebAuthn plugin.
type webauthnMigrations struct{}

func (m *webauthnMigrations) Name() string {
	return "webauthn"
}

func (m *webauthnMigrations) FS() fs.FS {
	return migrations.FS
}

func (m *webauthnMigrations) Dependencies() []string {
	return nil // depends only on core
}

// Migrations returns the migration source for the WebAuthn plugin.
// Use this with migrate.Run() to include WebAuthn tables in your migrations.
//
// Example:
//
//	err := migrate.Run(ctx, db, migrate.DialectPostgres,
//	    migrate.WithPlugins(webauthn.Migrations()),
//	)
func Migrations() migrate.Source {
	return &webauthnMigrations{}
}
