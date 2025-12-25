package main

import (
	"context"
	"database/sql"
	"log"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"

	_ "github.com/mattn/go-sqlite3"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/handlers"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/providers"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

func main() {
	// Get configuration from environment
	dbURL := getEnv("DATABASE_URL", "sqlite://auth.db")
	secret := getEnv("AUTH_SECRET", "your-secret-key-min-32-chars-long!")
	baseURL := getEnv("BASE_URL", "http://localhost:8080")
	port := getEnv("PORT", "8080")

	// Connect to database (PostgreSQL or SQLite)
	bunDB, err := connectDB(dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer bunDB.Close()

	// Create store and run migrations
	store := db.New(bunDB)
	if err := store.Migrate(context.Background()); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Create auth instance
	authService, err := auth.New(store,
		auth.WithSecret(secret),
		auth.WithBaseURL(baseURL),
		auth.WithTrustedOrigins(baseURL, "http://localhost:3000"),
		auth.WithHooks(hooks.Hooks{
			OnUserCreated: func(ctx context.Context, user *models.User) error {
				slog.Info("New user created", "id", user.ID, "email", user.Email)
				return nil
			},
			OnPasswordResetRequested: func(ctx context.Context, user *models.User, token string) error {
				// In production, send email with reset link
				slog.Info("Password reset requested",
					"user_id", user.ID,
					"reset_url", baseURL+"/auth/password/confirm?token="+token,
				)
				return nil
			},
			OnEmailVerificationRequested: func(ctx context.Context, user *models.User, token string) error {
				// In production, send verification email
				slog.Info("Email verification requested",
					"user_id", user.ID,
					"verify_url", baseURL+"/auth/email/verify?token="+token,
				)
				return nil
			},
		}),
	)
	if err != nil {
		log.Fatal("Failed to create auth service:", err)
	}

	// Register OAuth providers as plugin (optional)
	var oauthProviders []oauth.Provider
	if googleClientID := os.Getenv("GOOGLE_CLIENT_ID"); googleClientID != "" {
		oauthProviders = append(oauthProviders, providers.NewGoogle(
			googleClientID,
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			baseURL+"/auth/oauth/google/callback",
		))
	}

	if githubClientID := os.Getenv("GITHUB_CLIENT_ID"); githubClientID != "" {
		oauthProviders = append(oauthProviders, providers.NewGitHub(
			githubClientID,
			os.Getenv("GITHUB_CLIENT_SECRET"),
			baseURL+"/auth/oauth/github/callback",
		))
	}

	if len(oauthProviders) > 0 {
		if err := authService.Use(oauth.NewPlugin(oauthProviders...)); err != nil {
			log.Fatal("Failed to register OAuth plugin:", err)
		}
	}

	// Set up routes
	mux := http.NewServeMux()

	// Mount auth handler at /auth
	mux.Handle("/auth/", http.StripPrefix("/auth", handlers.NewRouter(authService)))

	// Example protected route
	mux.Handle("GET /api/profile", authService.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		if session == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		user, err := authService.GetUser(r.Context(), session.UserID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"` + user.ID + `","email":"` + user.Email + `","name":"` + user.Name + `"}`))
	})))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Start server
	slog.Info("Starting server", "port", port, "database", maskDSN(dbURL))
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal("Server failed:", err)
	}
}

// connectDB creates a Bun DB connection based on the DATABASE_URL scheme
func connectDB(dbURL string) (*bun.DB, error) {
	switch {
	case strings.HasPrefix(dbURL, "postgres://"), strings.HasPrefix(dbURL, "postgresql://"):
		// PostgreSQL
		sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dbURL)))
		return bun.NewDB(sqldb, pgdialect.New()), nil

	case strings.HasPrefix(dbURL, "sqlite://"):
		// SQLite
		path := strings.TrimPrefix(dbURL, "sqlite://")
		sqldb, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
		if err != nil {
			return nil, err
		}
		return bun.NewDB(sqldb, sqlitedialect.New()), nil

	default:
		// Assume SQLite file path
		sqldb, err := sql.Open("sqlite3", dbURL+"?_foreign_keys=on")
		if err != nil {
			return nil, err
		}
		return bun.NewDB(sqldb, sqlitedialect.New()), nil
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// maskDSN masks sensitive parts of database connection strings for logging
func maskDSN(dsn string) string {
	if strings.Contains(dsn, "@") {
		// Mask password in postgres URLs
		parts := strings.SplitN(dsn, "@", 2)
		if len(parts) == 2 {
			prefix := strings.SplitN(parts[0], "://", 2)
			if len(prefix) == 2 {
				userPass := strings.SplitN(prefix[1], ":", 2)
				if len(userPass) == 2 {
					return prefix[0] + "://" + userPass[0] + ":****@" + parts[1]
				}
			}
		}
	}
	return dsn
}
