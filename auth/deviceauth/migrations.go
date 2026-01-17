package deviceauth

import (
	"io/fs"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth/db/migrations"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// deviceauthMigrations implements migrate.Source for the DeviceAuth plugin.
type deviceauthMigrations struct{}

func (m *deviceauthMigrations) Name() string {
	return "deviceauth"
}

func (m *deviceauthMigrations) FS() fs.FS {
	return migrations.FS
}

func (m *deviceauthMigrations) Dependencies() []string {
	return nil // depends only on core
}

// Migrations returns the migration source for the DeviceAuth plugin.
// Use this with migrate.Run() to include DeviceAuth tables in your migrations.
//
// Example:
//
//	err := migrate.Run(ctx, db, migrate.DialectPostgres,
//	    migrate.WithPlugins(deviceauth.Migrations()),
//	)
func Migrations() migrate.Source {
	return &deviceauthMigrations{}
}
