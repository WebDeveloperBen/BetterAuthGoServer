package apikey_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/store"
)

// Shared test infrastructure - initialized once in TestMain
var (
	sharedContainer testcontainers.Container
	sharedConnStr   string
)

// TestMain sets up a shared PostgreSQL container for all apikey tests.
func TestMain(m *testing.M) {
	ctx := context.Background()

	// Start shared PostgreSQL container
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
		fmt.Printf("Failed to start PostgreSQL container: %v\n", err)
		os.Exit(1)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		fmt.Printf("Failed to get connection string: %v\n", err)
		os.Exit(1)
	}

	sharedContainer = pgContainer
	sharedConnStr = connStr

	// Run migrations once on the shared container
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(connStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())

	// Run base store migrations
	s := store.New(bunDB)
	if err := s.Migrate(ctx); err != nil {
		_ = bunDB.Close()
		_ = pgContainer.Terminate(ctx)
		fmt.Printf("Failed to run migrations: %v\n", err)
		os.Exit(1)
	}

	// Run apikey plugin migrations
	_, err = bunDB.NewCreateTable().Model((*apikey.APIKey)(nil)).IfNotExists().Exec(ctx)
	if err != nil {
		_ = bunDB.Close()
		_ = pgContainer.Terminate(ctx)
		fmt.Printf("Failed to create api_keys table: %v\n", err)
		os.Exit(1)
	}

	// Create index for key_prefix lookup
	_, err = bunDB.ExecContext(ctx, `
		CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix) WHERE enabled = true
	`)
	if err != nil {
		fmt.Printf("Warning: Failed to create index: %v\n", err)
	}

	_ = bunDB.Close()

	// Run tests
	code := m.Run()

	// Cleanup
	if sharedContainer != nil {
		_ = sharedContainer.Terminate(ctx)
	}

	os.Exit(code)
}
