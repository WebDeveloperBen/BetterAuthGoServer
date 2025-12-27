package deviceauth_test

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

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// testDB holds the test database connection
type testDB struct {
	DB *bun.DB
}

// setupTestDB creates a connection to the shared PostgreSQL container
func setupTestDB(t *testing.T) *testDB {
	t.Helper()

	if sharedConnStr == "" {
		t.Fatal("Shared container not initialized - TestMain not called?")
	}

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(sharedConnStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())

	if err := bunDB.PingContext(context.Background()); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return &testDB{DB: bunDB}
}

// cleanup closes the database connection
func (tdb *testDB) cleanup(t *testing.T) {
	t.Helper()
	if tdb.DB != nil {
		_ = tdb.DB.Close()
	}
}

// truncateTables clears all data from tables for test isolation
func (tdb *testDB) truncateTables(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	_, err := tdb.DB.ExecContext(ctx, "TRUNCATE TABLE device_codes CASCADE")
	if err != nil {
		t.Logf("Warning: Failed to truncate device_codes: %v", err)
	}
}

// mockAuthProvider implements AuthProvider and AuthCore for testing
type mockAuthProvider struct {
	users            map[string]*plugin.User
	sessions         map[string]*plugin.Session
	currentUser      *plugin.User
	createSessionErr error
}

func newMockAuthProvider() *mockAuthProvider {
	return &mockAuthProvider{
		users:    make(map[string]*plugin.User),
		sessions: make(map[string]*plugin.Session),
	}
}

// AuthCore interface methods
func (m *mockAuthProvider) BaseURL() string {
	return "https://example.com"
}

func (m *mockAuthProvider) Secret() string {
	return "test-secret-key-32-chars-long!!!"
}

func (m *mockAuthProvider) GetPluginUser(ctx context.Context, userID string) (*plugin.User, error) {
	if user, ok := m.users[userID]; ok {
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockAuthProvider) CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error) {
	if m.createSessionErr != nil {
		return nil, m.createSessionErr
	}

	session := &plugin.Session{
		ID:        fmt.Sprintf("session-%d", len(m.sessions)+1),
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour),
		RawToken:  "test-token",
	}
	m.sessions[session.ID] = session
	return session, nil
}

func (m *mockAuthProvider) GetUserFromRequest(r *http.Request) (*plugin.User, error) {
	if m.currentUser == nil {
		return nil, fmt.Errorf("no user in request")
	}
	return m.currentUser, nil
}

// createTestService creates a service for testing
func createTestService(t *testing.T, db *bun.DB, opts ...deviceauth.Option) *deviceauth.Service {
	t.Helper()

	config := deviceauth.DefaultConfig()
	config.VerificationURI = "https://example.com/device"
	config.CleanupInterval = 0 // Disable cleanup for tests

	for _, opt := range opts {
		opt(&config)
	}

	hasher := token.NewHasher("test-secret-key-32-chars-long!!!")

	return deviceauth.NewService(db, hasher, config, slog.Default())
}

// createTestPlugin creates a plugin for testing
func createTestPlugin(t *testing.T, db *bun.DB, auth *mockAuthProvider, opts ...deviceauth.Option) *deviceauth.Plugin {
	t.Helper()

	p := deviceauth.NewPlugin(opts...)

	hasher := token.NewHasher("test-secret-key-32-chars-long!!!")

	ctx := plugin.Context{
		DB:      db,
		BaseURL: "https://example.com",
		Secret:  "test-secret-key-32-chars-long!!!",
		Auth:    auth,
		Hasher:  hasher,
		Logger:  slog.Default(),
	}

	if err := p.Init(ctx); err != nil {
		t.Fatalf("Failed to initialize plugin: %v", err)
	}

	return p
}
