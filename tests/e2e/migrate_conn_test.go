package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// brokenSource is a migration source whose only migration fails.
type brokenSource struct {
	name string
}

func (s brokenSource) Name() string           { return s.name }
func (s brokenSource) Dependencies() []string { return nil }
func (s brokenSource) FS() fs.FS {
	files := fstest.MapFS{}
	for _, dialect := range []db.Dialect{db.DialectPostgres, db.DialectMySQL, db.DialectSQLite} {
		files[string(dialect)+"/000001_broken.up.sql"] = &fstest.MapFile{Data: []byte("THIS IS NOT SQL;")}
		files[string(dialect)+"/000001_broken.down.sql"] = &fstest.MapFile{Data: []byte("SELECT 1;")}
	}
	return files
}

// migrate.Run must return every connection it takes to the caller's pool, also when a
// migration fails, and must leave the caller's *sql.DB open.
func TestMigrateRunReleasesConnections(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping e2e test in short mode")
	}

	for _, dialectEnv := range GetDialects() {
		t.Run(string(dialectEnv.Dialect), func(t *testing.T) {
			ctx := context.Background()
			driver := map[db.Dialect]string{db.DialectPostgres: "postgres", db.DialectMySQL: "mysql", db.DialectSQLite: "sqlite3"}[dialectEnv.Dialect]
			sqlDB, err := sql.Open(driver, dialectEnv.ConnStr)
			require.NoError(t, err)
			defer func() { _ = sqlDB.Close() }()

			require.NoError(t, migrate.Run(ctx, sqlDB, migrate.Dialect(dialectEnv.Dialect),
				migrate.WithPlugins(oauth.Migrations()),
			))
			assert.Zero(t, sqlDB.Stats().InUse, "connections still checked out after migrate.Run")
			require.NoError(t, sqlDB.PingContext(ctx), "migrate.Run must not close the caller's *sql.DB")

			broken := brokenSource{name: fmt.Sprintf("broken_%d", time.Now().UnixNano())}
			err = migrate.Run(ctx, sqlDB, migrate.Dialect(dialectEnv.Dialect), migrate.WithPlugins(broken))
			require.Error(t, err)
			assert.Zero(t, sqlDB.Stats().InUse, "connections still checked out after a failed migrate.Run")
			require.NoError(t, sqlDB.PingContext(ctx))

			_, err = sqlDB.ExecContext(ctx, "DROP TABLE IF EXISTS schema_migrations_"+broken.name)
			require.NoError(t, err)
		})
	}
}
