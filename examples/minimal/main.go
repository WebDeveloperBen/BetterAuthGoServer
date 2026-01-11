// Package main demonstrates minimal BetterAuth setup.
// By default, no plugins are registered, providing only core session-based
// authentication. Add plugins as needed using Use().
package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	_ "github.com/lib/pq"           // PostgreSQL driver
	_ "github.com/mattn/go-sqlite3" // SQLite driver

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

func main() {
	// 1. Set up database
	// NOTE: Run migrations first using golang-migrate or your preferred tool:
	//   migrate -path db/migrations/sqlite -database "sqlite3://auth.db" up
	sqldb, err := sql.Open("sqlite3", "file:auth.db?_foreign_keys=on")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = sqldb.Close() }()

	// 2. Create sqlc-based store
	dbStore, err := db.New(sqldb, db.DialectSQLite)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Configuration
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "development-secret-key-at-least-32-characters!"
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	// 4. Create MINIMAL auth instance
	// By default, no plugins are registered. This is ideal when:
	// - You're building an API-only service (no CSRF needed)
	// - You have your own rate limiting (e.g., at load balancer)
	// - You want maximum control over what's enabled
	//
	// Use config.WithDefaults() if you want the standard plugin bundle:
	// - OTP (for password reset/email verification)
	// - Password authentication
	// - Rate limiting
	// - CSRF protection
	authService, err := auth.New(dbStore,
		config.WithSecret(secret),
		config.WithBaseURL(baseURL),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer authService.Close()

	// 5. Add only what you need
	// authService.Use(jwt.NewPlugin()) // Uncomment to add JWT
	// authService.Use(ratelimit.NewPlugin(...)) // Add custom rate limiting

	// 6. Set up HTTP server
	mux := http.NewServeMux()

	// Mount auth endpoints
	mux.Handle("/auth/", http.StripPrefix("/auth", authService.Handler()))

	// Protected endpoint
	mux.Handle("GET /api/profile", authService.AuthMiddleware()(http.HandlerFunc(profileHandler)))

	// Home
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"message": "BetterAuth Minimal Example",
			"note":    "No rate limiting, no CSRF - minimal core auth only",
			"endpoints": map[string]string{
				"sign-up":  "/auth/sign-up",
				"sign-in":  "/auth/sign-in",
				"sign-out": "/auth/sign-out",
				"profile":  "/auth/profile",
			},
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Minimal auth server starting on :%s", port)
	log.Println("Note: No rate limiting or CSRF protection enabled")
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())
	if session == nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"user_id": session.UserID,
		"message": "Hello from minimal auth setup!",
	})
}

// connectDB creates a standard sql.DB connection based on the DATABASE_URL scheme
func connectDB(dbURL string) (*sql.DB, db.Dialect, error) {
	switch {
	case strings.HasPrefix(dbURL, "postgres://"), strings.HasPrefix(dbURL, "postgresql://"):
		sqldb, err := sql.Open("postgres", dbURL)
		if err != nil {
			return nil, "", err
		}
		return sqldb, db.DialectPostgres, nil

	case strings.HasPrefix(dbURL, "sqlite://"):
		path := strings.TrimPrefix(dbURL, "sqlite://")
		sqldb, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
		if err != nil {
			return nil, "", err
		}
		return sqldb, db.DialectSQLite, nil

	default:
		// Assume SQLite file path
		sqldb, err := sql.Open("sqlite3", dbURL+"?_foreign_keys=on")
		if err != nil {
			return nil, "", err
		}
		return sqldb, db.DialectSQLite, nil
	}
}
