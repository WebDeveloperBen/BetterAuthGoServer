// Package main demonstrates minimal BetterAuth setup.
// This example uses WithoutDefaults() to disable rate limiting and CSRF,
// providing only core session-based authentication.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/store"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// 1. Set up database
	sqldb, err := sql.Open("sqlite3", "file:auth.db?_foreign_keys=on")
	if err != nil {
		log.Fatal(err)
	}
	bunDB := bun.NewDB(sqldb, sqlitedialect.New())
	defer bunDB.Close()

	// 2. Create store and run migrations
	dbStore := store.New(bunDB)
	if err := dbStore.Migrate(context.Background()); err != nil {
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
	// WithoutDefaults() disables:
	// - Rate limiting
	// - CSRF protection
	// - Admin plugin
	//
	// Use this when:
	// - You're building an API-only service (no CSRF needed)
	// - You have your own rate limiting (e.g., at load balancer)
	// - You want maximum control over what's enabled
	authService, err := auth.New(dbStore,
		config.WithSecret(secret),
		config.WithBaseURL(baseURL),
		config.WithoutDefaults(), // <-- No default plugins
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
		json.NewEncoder(w).Encode(map[string]interface{}{
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
	json.NewEncoder(w).Encode(map[string]string{
		"user_id": session.UserID,
		"message": "Hello from minimal auth setup!",
	})
}
