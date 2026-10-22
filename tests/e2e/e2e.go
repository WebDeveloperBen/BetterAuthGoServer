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
	"sync"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/testcontainers/testcontainers-go"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// dialectEnvs holds all enabled dialect environments (set in TestMain)
var dialectEnvs map[db.Dialect]*DialectEnv

// migrationsRun tracks which dialects have had migrations run
var migrationsRun = make(map[db.Dialect]bool)

// migrationsMu protects migrationsRun for concurrent access
var migrationsMu sync.Mutex

// DialectEnv holds database connection info for a specific dialect
type DialectEnv struct {
	Dialect   db.Dialect
	DB        *sql.DB
	ConnStr   string
	Container testcontainers.Container // nil for SQLite
}

// TestEnv holds the test environment
type TestEnv struct {
	Auth       *auth.Auth
	Store      *db.Store
	DB         *sql.DB
	Dialect    db.Dialect
	Container  testcontainers.Container // nil when using shared container
	Server     *httptest.Server
	useShared  bool
	dialectEnv *DialectEnv
}

// GetDialects returns all enabled dialect environments for testing
func GetDialects() []*DialectEnv {
	var envs []*DialectEnv
	for _, env := range dialectEnvs {
		envs = append(envs, env)
	}
	return envs
}

// SetupWithDialect creates a test environment for a specific dialect.
// Each test gets a fresh auth instance and server.
// Call TruncateTables at the start of each test for isolation.
func SetupWithDialect(t *testing.T, dialectEnv *DialectEnv) *TestEnv {
	t.Helper()
	return SetupWithDialectPlugins(t, dialectEnv)
}

// SetupWithDialectPlugins is SetupWithDialect with additional plugins registered
// (via auth.Use) before the HTTP handler is built.
func SetupWithDialectPlugins(t *testing.T, dialectEnv *DialectEnv, plugins ...plugin.Plugin) *TestEnv {
	t.Helper()
	ctx := context.Background()

	if dialectEnv == nil || dialectEnv.DB == nil {
		t.Fatal("Dialect environment not initialized")
	}

	// Run migrations only once per dialect (protected by mutex for concurrent tests)
	migrationsMu.Lock()
	if !migrationsRun[dialectEnv.Dialect] {
		if err := runMigrations(ctx, dialectEnv.DB, dialectEnv.Dialect); err != nil {
			migrationsMu.Unlock()
			t.Fatalf("Failed to run migrations: %v", err)
		}
		migrationsRun[dialectEnv.Dialect] = true
	}
	migrationsMu.Unlock()

	// Create store using sqlc-based db.Store
	dbStore, err := db.New(dialectEnv.DB, dialectEnv.Dialect)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create auth instance with default plugins
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
		t.Fatalf("Failed to create auth instance: %v", err)
	}
	if len(plugins) > 0 {
		if err := authInstance.Use(plugins...).Err(); err != nil {
			t.Fatalf("Failed to register plugins: %v", err)
		}
	}

	// Create test server
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:       authInstance,
		Store:      dbStore,
		DB:         dialectEnv.DB,
		Dialect:    dialectEnv.Dialect,
		Container:  nil,
		Server:     server,
		useShared:  true,
		dialectEnv: dialectEnv,
	}
}

// Setup creates a test environment using the default dialect (PostgreSQL if available, else first available).
// This is a convenience wrapper for backward compatibility.
func Setup(t *testing.T) *TestEnv {
	t.Helper()

	// Prefer PostgreSQL for backward compatibility, fall back to first available
	var dialectEnv *DialectEnv
	if env, ok := dialectEnvs[db.DialectPostgres]; ok {
		dialectEnv = env
	} else {
		for _, env := range dialectEnvs {
			dialectEnv = env
			break
		}
	}

	if dialectEnv == nil {
		t.Fatal("No dialect environments available - TestMain not called?")
	}

	return SetupWithDialect(t, dialectEnv)
}

// SetupWithRateLimiting creates a test environment with rate limiting enabled.
// Uses the first available dialect.
func SetupWithRateLimiting(t *testing.T, authRateLimit int) *TestEnv {
	t.Helper()
	ctx := context.Background()

	// Get first available dialect
	var dialectEnv *DialectEnv
	if env, ok := dialectEnvs[db.DialectPostgres]; ok {
		dialectEnv = env
	} else {
		for _, env := range dialectEnvs {
			dialectEnv = env
			break
		}
	}

	if dialectEnv == nil {
		t.Fatal("No dialect environments available")
	}

	// Run migrations only once per dialect (protected by mutex for concurrent tests)
	migrationsMu.Lock()
	if !migrationsRun[dialectEnv.Dialect] {
		if err := runMigrations(ctx, dialectEnv.DB, dialectEnv.Dialect); err != nil {
			migrationsMu.Unlock()
			t.Fatalf("Failed to run migrations: %v", err)
		}
		migrationsRun[dialectEnv.Dialect] = true
	}
	migrationsMu.Unlock()

	dbStore, err := db.New(dialectEnv.DB, dialectEnv.Dialect)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create auth instance with rate limiting enabled
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
		t.Fatalf("Failed to create auth instance: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:       authInstance,
		Store:      dbStore,
		DB:         dialectEnv.DB,
		Dialect:    dialectEnv.Dialect,
		Container:  nil,
		Server:     server,
		useShared:  true,
		dialectEnv: dialectEnv,
	}
}

// SetupWithRateLimitingDialect creates a test environment with rate limiting enabled for a specific dialect.
func SetupWithRateLimitingDialect(t *testing.T, dialectEnv *DialectEnv, authRateLimit int) *TestEnv {
	t.Helper()
	ctx := context.Background()

	// Run migrations only once per dialect (protected by mutex for concurrent tests)
	migrationsMu.Lock()
	if !migrationsRun[dialectEnv.Dialect] {
		if err := runMigrations(ctx, dialectEnv.DB, dialectEnv.Dialect); err != nil {
			migrationsMu.Unlock()
			t.Fatalf("Failed to run migrations: %v", err)
		}
		migrationsRun[dialectEnv.Dialect] = true
	}
	migrationsMu.Unlock()

	dbStore, err := db.New(dialectEnv.DB, dialectEnv.Dialect)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	// Create auth instance with rate limiting enabled
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
		t.Fatalf("Failed to create auth instance: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:       authInstance,
		Store:      dbStore,
		DB:         dialectEnv.DB,
		Dialect:    dialectEnv.Dialect,
		Container:  nil,
		Server:     server,
		useShared:  true,
		dialectEnv: dialectEnv,
	}
}

// Cleanup closes resources. For shared containers, only closes the auth instance and server.
// The shared containers are terminated in TestMain.
func (env *TestEnv) Cleanup(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	if env.Server != nil {
		env.Server.Close()
	}
	if env.Auth != nil {
		env.Auth.Close()
	}
	// Note: We don't close env.DB here because it's shared across tests.
	// It will be closed in TestMain cleanup.

	// Only terminate container if using isolated mode
	if !env.useShared && env.Container != nil {
		if err := env.Container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}
}

// TruncateTables clears all data from tables for test isolation.
// Handles dialect-specific truncate syntax.
func (env *TestEnv) TruncateTables(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	// Core tables plus plugin tables exercised by e2e tests; all are created by migrations.
	tables := []string{"oauth_states", "oauth_accounts", "verifications", "sessions", "accounts", "users"}

	for _, table := range tables {
		var query string
		switch env.Dialect {
		case db.DialectPostgres:
			query = fmt.Sprintf("TRUNCATE TABLE %s CASCADE", table)
		case db.DialectMySQL:
			// MySQL requires disabling FK checks for truncate
			query = fmt.Sprintf("DELETE FROM %s", table)
		case db.DialectSQLite:
			query = fmt.Sprintf("DELETE FROM %s", table)
		default:
			query = fmt.Sprintf("DELETE FROM %s", table)
		}
		if _, err := env.DB.ExecContext(ctx, query); err != nil {
			t.Logf("Warning: Failed to truncate %s: %v", table, err)
		}
	}
}

// runMigrations runs all schema migrations using the migrate package.
func runMigrations(ctx context.Context, sqlDB *sql.DB, dialect db.Dialect) error {
	return migrate.Run(ctx, sqlDB, migrate.Dialect(dialect),
		migrate.WithPlugins(
			oauth.Migrations(),
			jwt.Migrations(),
			otp.Migrations(),
			webauthn.Migrations(),
			apikey.Migrations(),
			deviceauth.Migrations(),
			organization.Migrations(),
		),
	)
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
