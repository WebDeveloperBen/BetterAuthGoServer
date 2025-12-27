package anonymous_test

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

	"github.com/webdeveloperben/BetterAuthGoServer/auth/anonymous"
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
		_ = tdb.DB.Close()
	}
}

// truncateTables clears all data from tables for test isolation
func (tdb *testDB) truncateTables(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	tables := []string{"sessions", "accounts", "users"}
	for _, table := range tables {
		_, err := tdb.DB.ExecContext(ctx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
		if err != nil {
			t.Logf("Warning: Failed to truncate %s: %v", table, err)
		}
	}
}

// userRow is a bun model for creating test users with is_anonymous
type userRow struct {
	bun.BaseModel `bun:"table:users"`

	ID            string    `bun:"id,pk"`
	Email         string    `bun:"email,notnull"`
	EmailVerified bool      `bun:"email_verified,notnull,default:false"`
	Name          string    `bun:"name,notnull"`
	Image         *string   `bun:"image"`
	Role          string    `bun:"role,notnull,default:'user'"`
	Banned        bool      `bun:"banned,notnull,default:false"`
	IsAnonymous   bool      `bun:"is_anonymous,notnull,default:false"`
	CreatedAt     time.Time `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt     time.Time `bun:"updated_at,notnull,default:current_timestamp"`
}

// createTestUser creates a test user in the database
func (tdb *testDB) createTestUser(t *testing.T, id, email, name string, isAnonymous bool) *userRow {
	t.Helper()
	ctx := context.Background()

	now := time.Now()
	user := &userRow{
		ID:          id,
		Email:       email,
		Name:        name,
		Role:        "user",
		IsAnonymous: isAnonymous,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	_, err := tdb.DB.NewInsert().Model(user).Exec(ctx)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	return user
}

// createTestSession creates a test session in the database
//
//nolint:unused
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

// mockAuthProvider implements the AuthProvider interface for testing
type mockAuthProvider struct {
	users            map[string]*plugin.User
	sessions         map[string]*plugin.Session
	currentUser      *plugin.User
	createUserFunc   func(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error)
	createSessionErr error
	deleteUserErr    error
	deletedUsers     []string
}

func newMockAuthProvider() *mockAuthProvider {
	return &mockAuthProvider{
		users:        make(map[string]*plugin.User),
		sessions:     make(map[string]*plugin.Session),
		deletedUsers: []string{},
	}
}

func (m *mockAuthProvider) GetPluginUser(ctx context.Context, userID string) (*plugin.User, error) {
	if user, ok := m.users[userID]; ok {
		return user, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockAuthProvider) GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockAuthProvider) CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error) {
	if m.createUserFunc != nil {
		return m.createUserFunc(ctx, req)
	}

	user := &plugin.User{
		ID:            fmt.Sprintf("user-%d", len(m.users)+1),
		Email:         req.Email,
		Name:          req.Name,
		EmailVerified: req.EmailVerified,
		Image:         req.Image,
		Role:          "user",
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	m.users[user.ID] = user
	return user, nil
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

func (m *mockAuthProvider) DeleteUser(ctx context.Context, userID string) error {
	if m.deleteUserErr != nil {
		return m.deleteUserErr
	}
	delete(m.users, userID)
	m.deletedUsers = append(m.deletedUsers, userID)
	return nil
}

func (m *mockAuthProvider) GetUserFromRequest(r *http.Request) (*plugin.User, error) {
	if m.currentUser == nil {
		return nil, fmt.Errorf("no user in request")
	}
	return m.currentUser, nil
}

// createTestService creates a service for testing with a real database
func createTestService(t *testing.T, db *bun.DB, auth anonymous.AuthProvider, opts ...anonymous.Option) *anonymous.Service {
	t.Helper()
	config := anonymous.DefaultConfig()
	for _, opt := range opts {
		opt(&config)
	}
	return anonymous.NewService(db, auth, config, slog.Default())
}
