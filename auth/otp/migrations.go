package otp

import (
	"io/fs"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp/db/migrations"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// otpMigrations implements migrate.Source for the OTP plugin.
type otpMigrations struct{}

func (m *otpMigrations) Name() string {
	return "otp"
}

func (m *otpMigrations) FS() fs.FS {
	return migrations.FS
}

func (m *otpMigrations) Dependencies() []string {
	return nil // depends only on core
}

// Migrations returns the migration source for the OTP plugin.
// Use this with migrate.Run() to include OTP tables in your migrations.
//
// Example:
//
//	err := migrate.Run(ctx, db, migrate.DialectPostgres,
//	    migrate.WithPlugins(otp.Migrations()),
//	)
func Migrations() migrate.Source {
	return &otpMigrations{}
}
