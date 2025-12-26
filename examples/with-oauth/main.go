// Package main demonstrates OAuth integration with BetterAuth.
// This example adds Google, GitHub, and Discord OAuth providers.
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
	"github.com/webdeveloperben/BetterAuthGoServer/auth/handlers"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/providers"
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

	// 3. Configuration from environment
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "development-secret-key-at-least-32-characters!"
		log.Println("WARNING: Using default development secret")
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	// 4. Create auth instance
	authService, err := auth.New(dbStore,
		config.WithSecret(secret),
		config.WithBaseURL(baseURL),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer authService.Close()

	// 5. Add JWT plugin for token-based auth
	authService.Use(jwt.NewPlugin(
		jwt.WithIssuer("myapp"),
	))

	// 6. Add OAuth providers
	var oauthProviders []oauth.Provider

	// Google OAuth (optional)
	if googleID := os.Getenv("GOOGLE_CLIENT_ID"); googleID != "" {
		oauthProviders = append(oauthProviders, providers.NewGoogle(
			googleID,
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			baseURL+"/auth/oauth/google/callback",
		))
		log.Println("Google OAuth enabled")
	}

	// GitHub OAuth (optional)
	if githubID := os.Getenv("GITHUB_CLIENT_ID"); githubID != "" {
		oauthProviders = append(oauthProviders, providers.NewGitHub(
			githubID,
			os.Getenv("GITHUB_CLIENT_SECRET"),
			baseURL+"/auth/oauth/github/callback",
		))
		log.Println("GitHub OAuth enabled")
	}

	// Discord OAuth (optional)
	if discordID := os.Getenv("DISCORD_CLIENT_ID"); discordID != "" {
		oauthProviders = append(oauthProviders, providers.NewDiscord(
			discordID,
			os.Getenv("DISCORD_CLIENT_SECRET"),
			baseURL+"/auth/oauth/discord/callback",
		))
		log.Println("Discord OAuth enabled")
	}

	if len(oauthProviders) > 0 {
		authService.Use(oauth.NewPlugin(oauthProviders...))
	} else {
		log.Println("No OAuth providers configured. Set GOOGLE_CLIENT_ID, GITHUB_CLIENT_ID, or DISCORD_CLIENT_ID")
	}

	// 7. Set up HTTP server
	mux := http.NewServeMux()

	// Mount auth endpoints
	mux.Handle("/auth/", http.StripPrefix("/auth", handlers.NewRouter(authService)))

	// Protected endpoint
	mux.Handle("GET /api/profile", authService.AuthMiddleware()(http.HandlerFunc(profileHandler)))

	// Home page with OAuth links
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "BetterAuth OAuth Example",
			"oauth": map[string]string{
				"google":   "/auth/oauth/google",
				"github":   "/auth/oauth/github",
				"discord":  "/auth/oauth/discord",
				"list":     "/auth/oauth/providers",
			},
			"auth": map[string]string{
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

	log.Printf("Server starting on :%s", port)
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
		"message": "Hello from protected endpoint!",
	})
}
