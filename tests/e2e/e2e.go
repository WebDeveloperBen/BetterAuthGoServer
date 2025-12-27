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

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/store"
)

// Shared test infrastructure - initialized once in TestMain (in main_test.go)
var (
	sharedContainer testcontainers.Container
	sharedConnStr   string
)

// TestEnv holds the test environment
type TestEnv struct {
	Auth      *auth.Auth
	Store     *store.Store
	DB        *bun.DB
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

	// Connect with Bun using shared container
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(sharedConnStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())

	if err := bunDB.PingContext(ctx); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	// Create store and run migrations (idempotent)
	dbStore := store.New(bunDB)
	if err := dbStore.Migrate(ctx); err != nil {
		_ = bunDB.Close()
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
		_ = bunDB.Close()
		t.Fatalf("Failed to create auth instance: %v", err)
	}

	// Create test server
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:      authInstance,
		Store:     dbStore,
		DB:        bunDB,
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

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(connStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())

	if err := bunDB.PingContext(ctx); err != nil {
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to ping database: %v", err)
	}

	dbStore := store.New(bunDB)
	if err := dbStore.Migrate(ctx); err != nil {
		_ = bunDB.Close()
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
		_ = bunDB.Close()
		_ = pgContainer.Terminate(ctx)
		t.Fatalf("Failed to create auth instance: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:      authInstance,
		Store:     dbStore,
		DB:        bunDB,
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

	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(sharedConnStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())

	if err := bunDB.PingContext(ctx); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	dbStore := store.New(bunDB)
	if err := dbStore.Migrate(ctx); err != nil {
		_ = bunDB.Close()
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
		_ = bunDB.Close()
		t.Fatalf("Failed to create auth instance: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:      authInstance,
		Store:     dbStore,
		DB:        bunDB,
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
