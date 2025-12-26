// Package main demonstrates basic usage of the BetterAuth library.
// This example shows the default "batteries included" setup with
// email/password authentication and session management.
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
	// 1. Set up database (using SQLite for this example)
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

	// 3. Get secret from environment (required, must be 32+ characters)
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "development-secret-key-at-least-32-characters!"
		log.Println("WARNING: Using default development secret. Set AUTH_SECRET in production.")
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	// 4. Create auth instance with default plugins (rate limiting, CSRF)
	authService, err := auth.New(dbStore,
		config.WithSecret(secret),
		config.WithBaseURL(baseURL),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer authService.Close()

	// 5. Set up HTTP server
	mux := http.NewServeMux()

	// Mount auth endpoints under /auth/
	mux.Handle("/auth/", http.StripPrefix("/auth", authService.Handler()))

	// Protected endpoint example
	mux.Handle("GET /api/profile", authService.AuthMiddleware()(http.HandlerFunc(profileHandler)))

	// Public endpoint
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "BetterAuth Basic Example",
			"docs":    "/auth/ endpoints available",
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on :%s", port)
	log.Printf("Auth endpoints available at %s/auth/", baseURL)
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
		"user_id":    session.UserID,
		"session_id": session.ID,
		"message":    "Hello from protected endpoint!",
	})
}
