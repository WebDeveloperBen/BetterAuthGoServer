package organization_test

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"net/http"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// testDB holds the test database connection
type testDB struct {
	DB *sql.DB
}

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *testDB {
	t.Helper()

	sqlDB, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Enable foreign keys
	_, err = sqlDB.Exec("PRAGMA foreign_keys = ON")
	if err != nil {
		t.Fatalf("Failed to enable foreign keys: %v", err)
	}

	// Create necessary tables
	if err := createTestTables(sqlDB); err != nil {
		_ = sqlDB.Close()
		t.Fatalf("Failed to create test tables: %v", err)
	}

	return &testDB{DB: sqlDB}
}

// createTestTables creates the required tables for testing
// These tables match the sqlc schema for SQLite
func createTestTables(db *sql.DB) error {
	ctx := context.Background()

	// Create users table (matches sqlc schema)
	_, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT UNIQUE NOT NULL,
			email_verified INTEGER DEFAULT 0,
			name TEXT NOT NULL,
			image TEXT,
			role TEXT DEFAULT 'user',
			banned INTEGER DEFAULT 0,
			banned_at TEXT,
			ban_reason TEXT,
			is_anonymous INTEGER DEFAULT 0,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create sessions table
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			ip_address TEXT,
			user_agent TEXT,
			active_organization_id TEXT,
			active_team_id TEXT,
			impersonated_by TEXT,
			created_at TEXT NOT NULL,
			expires_at TEXT NOT NULL,
			last_used TEXT NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create sessions table: %w", err)
	}

	// Create organizations table (matches sqlc schema)
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT UNIQUE NOT NULL,
			logo TEXT,
			metadata TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create organizations table: %w", err)
	}

	// Create members table (matches sqlc schema)
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS members (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'member',
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(organization_id, user_id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create members table: %w", err)
	}

	// Create invitations table (matches sqlc schema - uses inviter_id not invited_by)
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS invitations (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			organization_id TEXT NOT NULL,
			inviter_id TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'member',
			status TEXT NOT NULL DEFAULT 'pending',
			expires_at TEXT,
			created_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create invitations table: %w", err)
	}

	// Create teams table (matches sqlc schema)
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS teams (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			organization_id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create teams table: %w", err)
	}

	// Create team_members table (matches sqlc schema - uses user_id not member_id)
	_, err = db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS team_members (
			id TEXT PRIMARY KEY,
			team_id TEXT NOT NULL,
			user_id TEXT NOT NULL,
			created_at TEXT NOT NULL,
			UNIQUE(team_id, user_id)
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create team_members table: %w", err)
	}

	return nil
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

	tables := []string{"team_members", "teams", "invitations", "members", "organizations", "sessions", "users"}
	for _, table := range tables {
		_, err := tdb.DB.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			t.Logf("Warning: Failed to clear %s: %v", table, err)
		}
	}
}

// createTestUser creates a test user in the database
func (tdb *testDB) createTestUser(t *testing.T, id, email, name string) *organization.User {
	t.Helper()
	ctx := context.Background()

	now := time.Now().Format(time.RFC3339)
	_, err := tdb.DB.ExecContext(ctx, `
		INSERT INTO users (id, email, name, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
	`, id, email, name, now, now)
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	return &organization.User{
		ID:    id,
		Email: email,
		Name:  name,
	}
}

// createTestSession creates a test session in the database
func (tdb *testDB) createTestSession(t *testing.T, id, userID string) {
	t.Helper()
	ctx := context.Background()

	now := time.Now()
	_, err := tdb.DB.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token_hash, created_at, expires_at, last_used)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, userID, "test-hash-"+id, now.Format(time.RFC3339), now.Add(24*time.Hour).Format(time.RFC3339), now.Format(time.RFC3339))
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

// createTestService creates a service for testing with SQLite
func createTestService(t *testing.T, sqlDB *sql.DB, opts ...organization.Option) *organization.Service {
	t.Helper()
	config := organization.DefaultConfig()
	for _, opt := range opts {
		opt(&config)
	}

	// Create a store using the SQLite dialect
	store, err := db.New(sqlDB, db.DialectSQLite)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	return organization.NewService(store, sqlDB, db.DialectSQLite, slog.Default(), &config)
}
