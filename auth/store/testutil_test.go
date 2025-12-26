package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/store"
)

// testDB holds the test database connection
type testDB struct {
	DB    *bun.DB
	Store *store.Store
}

// setupTestDB creates a connection to the shared PostgreSQL container
func setupTestDB(t *testing.T) *testDB {
	t.Helper()

	if sharedConnStr == "" {
		t.Fatal("Shared container not initialized - TestMain not called?")
	}

	// Connect with Bun using shared container
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(sharedConnStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())

	// Verify connection
	if err := bunDB.PingContext(context.Background()); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return &testDB{
		DB:    bunDB,
		Store: store.New(bunDB),
	}
}

// cleanup closes the database connection (container is managed by TestMain)
func (tdb *testDB) cleanup(t *testing.T) {
	t.Helper()
	if tdb.DB != nil {
		tdb.DB.Close()
	}
}

// truncateTables clears all data from tables for test isolation
func (tdb *testDB) truncateTables(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	tables := []string{"verifications", "sessions", "accounts", "users"}
	for _, table := range tables {
		_, err := tdb.DB.ExecContext(ctx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
		if err != nil {
			t.Fatalf("Failed to truncate %s: %v", table, err)
		}
	}
}
