package organization_test

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
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
