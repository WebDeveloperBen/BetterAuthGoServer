// Package e2e provides end-to-end test utilities for the auth package.
package e2e

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Shared test infrastructure - initialized once in TestMain (in main_test.go)
var (
	sharedContainer testcontainers.Container
	sharedConnStr   string
)

// TestEnv holds the test environment
type TestEnv struct {
	Auth      *auth.Auth
	Store     *db.Store
	DB        *sql.DB
	Container testcontainers.Container // nil when using shared container
	Server    *httptest.Server
	useShared bool
}

// Setup creates a test environment using the shared PostgreSQL container.
// Each test gets a fresh auth instance and server, but shares the database.
// Call TruncateTables at the start of each test for isolation.
func Setup(t *testing.T) *TestEnv {
	t.Helper()
	ctx := context.Background()

	if sharedConnStr == "" {
		t.Fatal("Shared container not initialized - TestMain not called?")
	}

	// Connect with database/sql using shared container
	sqlDB, err := sql.Open("postgres", sharedConnStr)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	// Create store using sqlc-based db.Store
	dbStore, err := db.New(sqlDB, db.DialectPostgres)
	if err != nil {
		_ = sqlDB.Close()
		t.Fatalf("Failed to create store: %v", err)
	}

	// Run migrations using the migrator
	if err := runMigrations(ctx, sqlDB); err != nil {
		_ = sqlDB.Close()
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Create auth instance with default plugins (password, OTP, etc.)
	authInstance, err := auth.New(dbStore,
		config.WithDefaults(),
		config.WithSecret("test-secret-key-32-characters!!!"),
		config.WithBaseURL("http://localhost:3000"),
		config.WithSessionDuration(24*time.Hour),
		config.WithAutoSignIn(true),
		config.WithCSRF(false),
		config.WithPasswordComplexity(false),
		config.WithSessionCleanupInterval(0),
		config.WithRateLimit(false, time.Minute, 1000),
	)
	if err != nil {
		_ = sqlDB.Close()
		t.Fatalf("Failed to create auth instance: %v", err)
	}

	// Create test server
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:      authInstance,
		Store:     dbStore,
		DB:        sqlDB,
		Container: nil, // Using shared container
		Server:    server,
		useShared: true,
	}
}

// SetupIsolated creates a fully isolated test environment with its own container.
// Use this for tests that need special configuration (e.g., rate limiting tests).
func SetupIsolated(t *testing.T) *TestEnv {
	t.Helper()
	ctx := context.Background()

	// Start dedicated PostgreSQL container
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

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to get connection string: %v", err)
	}

	sqlDB, err := sql.Open("postgres", connStr)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to open database: %v", err)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to ping database: %v", err)
	}

	dbStore, err := db.New(sqlDB, db.DialectPostgres)
	if err != nil {
		_ = sqlDB.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to create store: %v", err)
	}

	if err := runMigrations(ctx, sqlDB); err != nil {
		_ = sqlDB.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to run migrations: %v", err)
	}

	authInstance, err := auth.New(dbStore,
		config.WithDefaults(),
		config.WithSecret("test-secret-key-32-characters!!!"),
		config.WithBaseURL("http://localhost:3000"),
		config.WithSessionDuration(24*time.Hour),
		config.WithAutoSignIn(true),
		config.WithCSRF(false),
		config.WithPasswordComplexity(false),
		config.WithSessionCleanupInterval(0),
		config.WithRateLimit(false, time.Minute, 1000),
	)
	if err != nil {
		_ = sqlDB.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to create auth instance: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:      authInstance,
		Store:     dbStore,
		DB:        sqlDB,
		Container: pgContainer,
		Server:    server,
		useShared: false,
	}
}

// SetupWithRateLimiting creates a test environment with rate limiting enabled.
// Uses the shared container but creates a fresh auth instance with rate limiting.
func SetupWithRateLimiting(t *testing.T, authRateLimit int) *TestEnv {
	t.Helper()
	ctx := context.Background()

	if sharedConnStr == "" {
		t.Fatal("Shared container not initialized - TestMain not called?")
	}

	sqlDB, err := sql.Open("postgres", sharedConnStr)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}

	if err := sqlDB.PingContext(ctx); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	dbStore, err := db.New(sqlDB, db.DialectPostgres)
	if err != nil {
		_ = sqlDB.Close()
		t.Fatalf("Failed to create store: %v", err)
	}

	if err := runMigrations(ctx, sqlDB); err != nil {
		_ = sqlDB.Close()
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Create auth instance with rate limiting and default plugins
	authInstance, err := auth.New(dbStore,
		config.WithDefaults(),
		config.WithSecret("test-secret-key-32-characters!!!"),
		config.WithBaseURL("http://localhost:3000"),
		config.WithSessionDuration(24*time.Hour),
		config.WithAutoSignIn(true),
		config.WithCSRF(false),
		config.WithPasswordComplexity(false),
		config.WithSessionCleanupInterval(0),
		config.WithAuthRateLimit(authRateLimit),
	)
	if err != nil {
		_ = sqlDB.Close()
		t.Fatalf("Failed to create auth instance: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:      authInstance,
		Store:     dbStore,
		DB:        sqlDB,
		Container: nil,
		Server:    server,
		useShared: true,
	}
}

// Cleanup closes resources. For shared containers, only closes the connection.
// The shared container is terminated in TestMain.
func (env *TestEnv) Cleanup(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	if env.Server != nil {
		env.Server.Close()
	}
	if env.Auth != nil {
		env.Auth.Close()
	}
	if env.DB != nil {
		_ = env.DB.Close()
	}
	// Only terminate container if using isolated mode
	if !env.useShared && env.Container != nil {
		if err := env.Container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}
}

// TruncateTables clears all data from tables for test isolation
func (env *TestEnv) TruncateTables(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	// Core tables that are always created by migrations.
	// Note: oauth_states is created by the OAuth plugin when registered,
	// so it's not included here. If OAuth tests are needed, register the plugin first.
	tables := []string{"verifications", "sessions", "accounts", "users"}
	for _, table := range tables {
		_, err := env.DB.ExecContext(ctx, fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table))
		if err != nil {
			t.Fatalf("Failed to truncate %s: %v", table, err)
		}
	}
}

// runMigrations runs all schema migrations for the test database.
// It reads the SQL schema files and executes them in order.
func runMigrations(ctx context.Context, db *sql.DB) error {
	// SQL statements for PostgreSQL - creates all tables needed for testing
	migrations := []string{
		// Users table
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			name TEXT NOT NULL DEFAULT '',
			image TEXT,
			role TEXT NOT NULL DEFAULT 'user',
			banned BOOLEAN NOT NULL DEFAULT FALSE,
			banned_at TIMESTAMPTZ,
			ban_reason TEXT,
			is_anonymous BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)`,
		`CREATE INDEX IF NOT EXISTS idx_users_banned ON users(banned)`,
		`CREATE INDEX IF NOT EXISTS idx_users_is_anonymous ON users(is_anonymous)`,

		// Accounts table
		`CREATE TABLE IF NOT EXISTS accounts (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			provider TEXT NOT NULL,
			provider_account_id TEXT,
			access_token TEXT,
			refresh_token TEXT,
			access_token_expires_at TIMESTAMPTZ,
			password_hash TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_accounts_provider ON accounts(provider, provider_account_id)`,

		// Sessions table
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL UNIQUE,
			ip_address TEXT,
			user_agent TEXT,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			last_used TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			impersonated_by TEXT
		)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)`,

		// Verifications table
		`CREATE TABLE IF NOT EXISTS verifications (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			type TEXT NOT NULL,
			token_hash TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_verifications_token_hash ON verifications(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_verifications_user_id_type ON verifications(user_id, type)`,

		// OTP tokens table
		`CREATE TABLE IF NOT EXISTS otp_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			type TEXT NOT NULL,
			identifier TEXT,
			token_hash TEXT NOT NULL UNIQUE,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_otp_tokens_user_id_type ON otp_tokens(user_id, type)`,
		`CREATE INDEX IF NOT EXISTS idx_otp_tokens_token_hash ON otp_tokens(token_hash)`,
		`CREATE INDEX IF NOT EXISTS idx_otp_tokens_expires_at ON otp_tokens(expires_at)`,

		// JWT revoked tokens table
		`CREATE TABLE IF NOT EXISTS jwt_revoked_tokens (
			jti TEXT PRIMARY KEY,
			expires_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_jwt_revoked_tokens_expires_at ON jwt_revoked_tokens(expires_at)`,

		// JWT keys table
		`CREATE TABLE IF NOT EXISTS jwt_keys (
			id TEXT PRIMARY KEY,
			algorithm TEXT NOT NULL,
			encrypted_private_key TEXT NOT NULL,
			public_key TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'active',
			activated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_jwt_keys_algorithm_status ON jwt_keys(algorithm, status)`,

		// OAuth states table
		`CREATE TABLE IF NOT EXISTS oauth_states (
			state TEXT PRIMARY KEY,
			provider TEXT NOT NULL,
			verifier TEXT,
			redirect_to TEXT,
			created_at TIMESTAMPTZ NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL
		)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states(expires_at)`,

		// OAuth accounts table
		`CREATE TABLE IF NOT EXISTS oauth_accounts (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			provider_account_id TEXT NOT NULL,
			access_token TEXT,
			refresh_token TEXT,
			access_token_expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_oauth_accounts_provider ON oauth_accounts(provider, provider_account_id)`,

		// WebAuthn credentials table
		`CREATE TABLE IF NOT EXISTS webauthn_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			credential_id BYTEA NOT NULL UNIQUE,
			public_key BYTEA NOT NULL,
			attestation_type TEXT NOT NULL,
			aaguid BYTEA,
			sign_count BIGINT NOT NULL DEFAULT 0,
			transports TEXT,
			backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
			backup_state BOOLEAN NOT NULL DEFAULT FALSE,
			name TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id ON webauthn_credentials(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id ON webauthn_credentials(credential_id)`,

		// WebAuthn sessions table
		`CREATE TABLE IF NOT EXISTS webauthn_sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT,
			challenge TEXT NOT NULL,
			user_verification TEXT NOT NULL,
			operation TEXT NOT NULL,
			expires_at TIMESTAMPTZ NOT NULL,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires_at ON webauthn_sessions(expires_at)`,

		// API keys table
		`CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name TEXT NOT NULL,
			key_prefix TEXT NOT NULL,
			key_hash TEXT NOT NULL UNIQUE,
			scopes TEXT,
			expires_at TIMESTAMPTZ,
			last_used_at TIMESTAMPTZ,
			last_used_ip TEXT,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix)`,

		// Device codes table
		`CREATE TABLE IF NOT EXISTS device_codes (
			id TEXT PRIMARY KEY,
			device_code_hash TEXT NOT NULL UNIQUE,
			device_code_hash_prefix TEXT NOT NULL,
			user_code TEXT NOT NULL UNIQUE,
			client_id TEXT NOT NULL,
			scope TEXT,
			status TEXT NOT NULL DEFAULT 'pending',
			user_id TEXT,
			expires_at TIMESTAMPTZ NOT NULL,
			interval_seconds INTEGER NOT NULL DEFAULT 5,
			last_polled_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_user_code ON device_codes(user_code)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_hash_prefix ON device_codes(device_code_hash_prefix)`,
		`CREATE INDEX IF NOT EXISTS idx_device_codes_expires_at ON device_codes(expires_at)`,

		// Organizations table
		`CREATE TABLE IF NOT EXISTS organizations (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT NOT NULL UNIQUE,
			logo TEXT,
			metadata TEXT,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug)`,

		// Organization members table
		`CREATE TABLE IF NOT EXISTS organization_members (
			id TEXT PRIMARY KEY,
			organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role TEXT NOT NULL DEFAULT 'member',
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(organization_id, user_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_org_members_org_id ON organization_members(organization_id)`,
		`CREATE INDEX IF NOT EXISTS idx_org_members_user_id ON organization_members(user_id)`,

		// Organization invitations table
		`CREATE TABLE IF NOT EXISTS organization_invitations (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			inviter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			role TEXT NOT NULL DEFAULT 'member',
			status TEXT NOT NULL DEFAULT 'pending',
			expires_at TIMESTAMPTZ,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_org_invitations_email ON organization_invitations(email)`,
		`CREATE INDEX IF NOT EXISTS idx_org_invitations_org_id ON organization_invitations(organization_id)`,

		// Teams table
		`CREATE TABLE IF NOT EXISTS teams (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_teams_org_id ON teams(organization_id)`,

		// Team members table
		`CREATE TABLE IF NOT EXISTS team_members (
			id TEXT PRIMARY KEY,
			team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
			UNIQUE(team_id, user_id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_team_members_team_id ON team_members(team_id)`,
		`CREATE INDEX IF NOT EXISTS idx_team_members_user_id ON team_members(user_id)`,
	}

	for _, stmt := range migrations {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migration failed: %w\nStatement: %s", err, stmt)
		}
	}

	return nil
}

// HTTP helper functions

// Post sends a POST request with JSON body
func (env *TestEnv) Post(t *testing.T, path string, body any) *http.Response {
	t.Helper()
	jsonBody, _ := json.Marshal(body)
	resp, err := http.Post(env.Server.URL+path, "application/json", bytes.NewReader(jsonBody))
	if err != nil {
		t.Fatalf("POST %s failed: %v", path, err)
	}
	return resp
}

// PostWithCookies sends a POST request with cookies
func (env *TestEnv) PostWithCookies(t *testing.T, path string, body any, cookies []*http.Cookie) *http.Response {
	t.Helper()
	jsonBody, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", env.Server.URL+path, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s failed: %v", path, err)
	}
	return resp
}

// PostWithHeaders sends a POST request with custom headers
func (env *TestEnv) PostWithHeaders(t *testing.T, path string, body any, headers map[string]string) *http.Response {
	t.Helper()
	jsonBody, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", env.Server.URL+path, bytes.NewReader(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s failed: %v", path, err)
	}
	return resp
}

// Get sends a GET request with optional cookies
func (env *TestEnv) Get(t *testing.T, path string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("GET", env.Server.URL+path, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s failed: %v", path, err)
	}
	return resp
}

// DecodeResponse decodes a JSON response body
func DecodeResponse(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
}

// GetSessionCookie returns the session cookie from a response
func GetSessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == "session" {
			return c
		}
	}
	return nil
}

// CreateUser is a helper to create a user and return cookies
func (env *TestEnv) CreateUser(t *testing.T, email, password, name string) []*http.Cookie {
	t.Helper()
	body := map[string]string{
		"email":    email,
		"password": password,
		"name":     name,
	}
	resp := env.Post(t, "/auth/sign-up", body)
	cookies := resp.Cookies()
	_ = resp.Body.Close()
	return cookies
}
