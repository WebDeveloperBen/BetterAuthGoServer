package jwt

import (
	"io/fs"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt/db/migrations"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// jwtMigrations implements migrate.Source for the JWT plugin.
type jwtMigrations struct{}

func (m *jwtMigrations) Name() string {
	return "jwt"
}

func (m *jwtMigrations) FS() fs.FS {
	return migrations.FS
}

func (m *jwtMigrations) Dependencies() []string {
	return nil // depends only on core
}

// Migrations returns the migration source for the JWT plugin.
// Use this with migrate.Run() to include JWT tables in your migrations.
//
// Example:
//
//	err := migrate.Run(ctx, db, migrate.DialectPostgres,
//	    migrate.WithPlugins(jwt.Migrations()),
//	)
func Migrations() migrate.Source {
	return &jwtMigrations{}
}
