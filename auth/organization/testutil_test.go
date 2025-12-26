package organization_test

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
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
			bunDB.Close()
			pgContainer.Terminate(ctx)
			t.Fatalf("Failed to create organization tables: %v", err)
		}
	}

	// Add organization extension columns to sessions table
	_, err = bunDB.ExecContext(ctx, `
		ALTER TABLE sessions ADD COLUMN IF NOT EXISTS active_organization_id TEXT;
		ALTER TABLE sessions ADD COLUMN IF NOT EXISTS active_team_id TEXT;
	`)
	if err != nil {
		bunDB.Close()
		pgContainer.Terminate(ctx)
		t.Fatalf("Failed to add session extension columns: %v", err)
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

	tables := []string{"team_members", "teams", "invitations", "members", "organizations", "sessions", "accounts", "users"}
	for _, table := range tables {
		_, err := tdb.DB.ExecContext(ctx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
		if err != nil {
			t.Logf("Warning: Failed to truncate %s: %v", table, err)
		}
	}
}

// createTestUser creates a test user in the database
func (tdb *testDB) createTestUser(t *testing.T, id, email, name string) *organization.User {
	t.Helper()
	ctx := context.Background()

	user := &organization.User{
		ID:    id,
		Email: email,
		Name:  name,
	}

	_, err := tdb.DB.NewInsert().Model(user).Exec(ctx)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	return user
}

// createTestSession creates a test session in the database
func (tdb *testDB) createTestSession(t *testing.T, id, userID string) {
	t.Helper()
	ctx := context.Background()

	now := time.Now()
	_, err := tdb.DB.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_used)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, userID, "test-hash-"+id, now, now.Add(24*time.Hour), now)
	if err != nil {
		t.Fatalf("Failed to create test session: %v", err)
	}
}

// mockAuthProvider implements the interfaces needed for testing
type mockAuthProvider struct {
	user        *plugin.User
	sessionInfo *plugin.SessionInfo
}

func newMockAuthProvider(user *plugin.User, session *plugin.SessionInfo) *mockAuthProvider {
	return &mockAuthProvider{
		user:        user,
		sessionInfo: session,
	}
}

func (m *mockAuthProvider) BaseURL() string {
	return "http://localhost:8080"
}

func (m *mockAuthProvider) Secret() string {
	return "test-secret"
}

func (m *mockAuthProvider) GetUserFromRequest(r *http.Request) (*plugin.User, error) {
	if m.user == nil {
		return nil, fmt.Errorf("no user")
	}
	return m.user, nil
}

func (m *mockAuthProvider) GetSessionInfoFromRequest(r *http.Request) *plugin.SessionInfo {
	return m.sessionInfo
}

// createTestService creates a service for testing
func createTestService(t *testing.T, db *bun.DB, opts ...organization.Option) *organization.Service {
	t.Helper()
	config := organization.DefaultConfig()
	for _, opt := range opts {
		opt(&config)
	}
	return organization.NewService(db, slog.Default(), &config)
}
