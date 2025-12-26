package organization_test

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

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/store"
)

// Shared test infrastructure - initialized once in TestMain
var (
	sharedContainer testcontainers.Container
	sharedConnStr   string
)

// TestMain sets up a shared PostgreSQL container for all organization tests.
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

	// Run organization plugin migrations
	orgModels := []any{
		(*organization.Organization)(nil),
		(*organization.Member)(nil),
		(*organization.Invitation)(nil),
		(*organization.Team)(nil),
		(*organization.TeamMember)(nil),
	}

	for _, model := range orgModels {
		_, err := bunDB.NewCreateTable().Model(model).IfNotExists().Exec(ctx)
		if err != nil {
			_ = bunDB.Close()
			_ = pgContainer.Terminate(ctx)
			fmt.Printf("Failed to create organization tables: %v\n", err)
			os.Exit(1)
		}
	}

	// Add organization extension columns to sessions table
	_, err = bunDB.ExecContext(ctx, `
		ALTER TABLE sessions ADD COLUMN IF NOT EXISTS active_organization_id TEXT;
		ALTER TABLE sessions ADD COLUMN IF NOT EXISTS active_team_id TEXT;
	`)
	if err != nil {
		_ = bunDB.Close()
		_ = pgContainer.Terminate(ctx)
		fmt.Printf("Failed to add session extension columns: %v\n", err)
		os.Exit(1)
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
