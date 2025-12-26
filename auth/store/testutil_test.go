package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/store"
)

// testDB holds the test database connection and cleanup function
type testDB struct {
	DB        *bun.DB
	Store     *store.Store
	Container testcontainers.Container
}

// setupTestDB creates a PostgreSQL container and returns a connected store
func setupTestDB(t *testing.T) *testDB {
	t.Helper()
	ctx := context.Background()

	// Start PostgreSQL container
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("Failed to get connection string: %v", err)
	}

	// Connect with Bun
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(connStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())

	// Verify connection
	if err := bunDB.PingContext(ctx); err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("Failed to ping database: %v", err)
	}

	// Create store and run migrations
	s := store.New(bunDB)
	if err := s.Migrate(ctx); err != nil {
		bunDB.Close()
		pgContainer.Terminate(ctx)
		t.Fatalf("Failed to run migrations: %v", err)
	}

	return &testDB{
		DB:        bunDB,
		Store:     s,
		Container: pgContainer,
	}
}

// cleanup closes the database and terminates the container
func (tdb *testDB) cleanup(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	if tdb.DB != nil {
		tdb.DB.Close()
	}
	if tdb.Container != nil {
		if err := tdb.Container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
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
