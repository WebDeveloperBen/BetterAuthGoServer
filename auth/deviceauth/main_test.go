package deviceauth_test

import (
	"context"
	"database/sql"
	"log"
	"os"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
)

var (
	sharedContainer testcontainers.Container
	sharedConnStr   string
)

func TestMain(m *testing.M) {
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
		log.Fatalf("Failed to start PostgreSQL container: %v", err)
	}

	sharedContainer = pgContainer

	// Get connection string
	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		log.Fatalf("Failed to get connection string: %v", err)
	}
	sharedConnStr = connStr

	// Run migrations
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(connStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())
	defer func() { _ = bunDB.Close() }()

	// Create device_codes table
	_, err = bunDB.NewCreateTable().
		Model((*deviceauth.DeviceCode)(nil)).
		IfNotExists().
		Exec(ctx)
	if err != nil {
		log.Fatalf("Failed to create device_codes table: %v", err)
	}

	// Create indexes
	_, _ = bunDB.NewCreateIndex().
		Model((*deviceauth.DeviceCode)(nil)).
		Index("idx_device_codes_device_code_hash").
		Column("device_code_hash").
		IfNotExists().
		Exec(ctx)

	_, _ = bunDB.NewCreateIndex().
		Model((*deviceauth.DeviceCode)(nil)).
		Index("idx_device_codes_user_code").
		Column("user_code").
		Unique().
		IfNotExists().
		Exec(ctx)

	_, _ = bunDB.NewCreateIndex().
		Model((*deviceauth.DeviceCode)(nil)).
		Index("idx_device_codes_expires_at").
		Column("expires_at").
		IfNotExists().
		Exec(ctx)

	// Run tests
	code := m.Run()

	// Cleanup
	if err := pgContainer.Terminate(ctx); err != nil {
		log.Printf("Failed to terminate container: %v", err)
	}

	os.Exit(code)
}
