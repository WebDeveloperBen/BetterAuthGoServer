package apikey_test

import (
	"context"
	"database/sql"
	"log/slog"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// setupTestService creates a new Service with a fresh database connection.
// The database is cleaned up after the test completes.
func setupTestService(t *testing.T) (*apikey.Service, *bun.DB) {
	t.Helper()

	if sharedConnStr == "" {
		t.Fatal("Shared container not initialized - TestMain not called?")
	}

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(sharedConnStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())

	if err := bunDB.PingContext(context.Background()); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	hasher := token.NewHasher("test-secret")
	config := apikey.DefaultConfig()
	service := apikey.NewService(bunDB, hasher, config, slog.Default())

	t.Cleanup(func() {
		// Clean up test data
		_, _ = bunDB.NewDelete().Model((*apikey.APIKey)(nil)).Where("1=1").Exec(context.Background())
		_ = bunDB.Close()
	})

	return service, bunDB
}
