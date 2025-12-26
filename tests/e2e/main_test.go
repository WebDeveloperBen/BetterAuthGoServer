package e2e

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestMain sets up a shared PostgreSQL container for all e2e tests.
// This dramatically reduces test time by reusing a single container.
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
		pgContainer.Terminate(ctx)
		fmt.Printf("Failed to get connection string: %v\n", err)
		os.Exit(1)
	}

	sharedContainer = pgContainer
	sharedConnStr = connStr

	// Run tests
	code := m.Run()

	// Cleanup
	if sharedContainer != nil {
		sharedContainer.Terminate(ctx)
	}

	os.Exit(code)
}
