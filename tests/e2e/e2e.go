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
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// TestEnv holds the test environment
type TestEnv struct {
	Auth      *auth.Auth
	Store     *db.Store
	DB        *bun.DB
	Container testcontainers.Container
	Server    *httptest.Server
}

// Setup creates a full test environment with PostgreSQL
func Setup(t *testing.T) *TestEnv {
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

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("Failed to get connection string: %v", err)
	}

	// Connect with Bun
	sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(connStr)))
	bunDB := bun.NewDB(sqldb, pgdialect.New())

	if err := bunDB.PingContext(ctx); err != nil {
		pgContainer.Terminate(ctx)
		t.Fatalf("Failed to ping database: %v", err)
	}

	// Create store and run migrations
	store := db.New(bunDB)
	if err := store.Migrate(ctx); err != nil {
		bunDB.Close()
		pgContainer.Terminate(ctx)
		t.Fatalf("Failed to run migrations: %v", err)
	}

	// Create auth instance
	authInstance, err := auth.New(store,
		auth.WithSecret("test-secret-key-32-characters!!!"), // Exactly 32 bytes
		auth.WithBaseURL("http://localhost:3000"),
		auth.WithSessionDuration(24*time.Hour),
		auth.WithAutoSignIn(true),
		auth.WithCSRF(false),               // Disable CSRF for testing
		auth.WithPasswordComplexity(false), // Disable complexity for simpler test passwords
		auth.WithSessionCleanupInterval(0), // Disable background cleanup in tests
	)
	if err != nil {
		bunDB.Close()
		pgContainer.Terminate(ctx)
		t.Fatalf("Failed to create auth instance: %v", err)
	}

	// Create test server - mount auth handler at /auth
	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", authInstance.Handler()))
	server := httptest.NewServer(mux)

	return &TestEnv{
		Auth:      authInstance,
		Store:     store,
		DB:        bunDB,
		Container: pgContainer,
		Server:    server,
	}
}

// Cleanup closes the database and terminates the container
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
		env.DB.Close()
	}
	if env.Container != nil {
		if err := env.Container.Terminate(ctx); err != nil {
			t.Logf("Failed to terminate container: %v", err)
		}
	}
}

// TruncateTables clears all data from tables for test isolation
func (env *TestEnv) TruncateTables(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	tables := []string{"oauth_states", "verifications", "sessions", "accounts", "users"}
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
	defer resp.Body.Close()
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
	resp.Body.Close()
	return cookies
}
