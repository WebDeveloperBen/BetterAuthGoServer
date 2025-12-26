// Package main demonstrates using Redis for distributed rate limiting.
//
// This is essential for clustered deployments where multiple instances
// need to share rate limit state. Without a shared backend, each instance
// would track limits independently, allowing users to bypass limits by
// hitting different instances.
//
// To run this example:
//
//	# Start Redis
//	docker run -d -p 6379:6379 redis:alpine
//
//	# Run the example
//	go run ./examples/redis-ratelimit
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	kvredis "github.com/webdeveloperben/BetterAuthGoServer/auth/kv/redis"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/ratelimit"
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

	// 3. Get configuration from environment
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "development-secret-key-at-least-32-characters!"
		log.Println("WARNING: Using default development secret. Set AUTH_SECRET in production.")
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379"
	}

	// 4. Create Redis client for distributed rate limiting
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	// Verify Redis connection
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis at %s: %v", redisAddr, err)
	}
	log.Printf("Connected to Redis at %s", redisAddr)
	defer redisClient.Close()

	// 5. Create Redis-backed rate limiter
	redisStore := kvredis.NewStoreFromClient(redisClient)
	redisRateLimiter := kvredis.NewRateLimiter(redisStore)

	// 6. Create auth instance WITHOUT default plugins (we'll add our own)
	authService, err := auth.New(dbStore,
		config.WithSecret(secret),
		config.WithBaseURL(baseURL),
		config.WithoutDefaults(), // Disable default in-memory rate limiter
	)
	if err != nil {
		log.Fatal(err)
	}
	defer authService.Close()

	// 7. Add rate limiting with Redis backend
	err = authService.Use(ratelimit.NewPlugin(
		ratelimit.WithLimit(100, time.Minute),      // 100 requests per minute
		ratelimit.WithBackend(redisRateLimiter),    // Use Redis for distributed state
		ratelimit.WithTrustedProxies([]string{      // Trust these proxies for X-Forwarded-For
			"127.0.0.1",
			"10.0.0.0/8",
		}),
	))
	if err != nil {
		log.Fatal(err)
	}

	// 8. Set up HTTP server
	mux := http.NewServeMux()

	// Mount auth endpoints under /auth/
	mux.Handle("/auth/", http.StripPrefix("/auth", authService.Handler()))

	// Protected endpoint example
	mux.Handle("GET /api/profile", authService.AuthMiddleware()(http.HandlerFunc(profileHandler)))

	// Health check that also shows rate limit info
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"message":     "BetterAuth Redis Rate Limiting Example",
			"redis":       redisAddr,
			"rate_limit":  "100 requests/minute (shared across all instances)",
			"docs":        "/auth/ endpoints available",
		})
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on :%s", port)
	log.Printf("Auth endpoints available at %s/auth/", baseURL)
	log.Printf("Rate limiting: 100 req/min via Redis at %s", redisAddr)
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
