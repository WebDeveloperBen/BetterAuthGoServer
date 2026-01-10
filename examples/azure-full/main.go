// Package main demonstrates a comprehensive auth setup with Azure Entra ID OAuth,
// JWT tokens, rate limiting, device auth, CORS, API keys, admin, OTP, and password auth.
//
// This example shows a production-ready configuration combining all major plugins.
//
// Environment variables:
//
//	AUTH_SECRET          - Secret key for signing (required, min 32 chars)
//	BASE_URL             - Base URL of the server (default: http://localhost:8080)
//	PORT                 - Server port (default: 8080)
//	ALLOWED_ORIGINS      - Comma-separated list of allowed CORS origins
//
//	Azure OAuth:
//	AZURE_CLIENT_ID      - Azure app registration client ID
//	AZURE_CLIENT_SECRET  - Azure app registration client secret
//	AZURE_TENANT         - Azure tenant (common, organizations, or tenant ID)
//
//	Redis (optional, for distributed rate limiting):
//	REDIS_ADDR           - Redis address (default: localhost:6379)
//	REDIS_PASSWORD       - Redis password (optional)
//
// To run:
//
//	export AUTH_SECRET="your-32-character-or-longer-secret-key"
//	export AZURE_CLIENT_ID="your-azure-client-id"
//	export AZURE_CLIENT_SECRET="your-azure-client-secret"
//	go run ./examples/azure-full
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/admin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/cors"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"
	kvredis "github.com/webdeveloperben/BetterAuthGoServer/auth/kv/redis"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/providers"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/password"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/ratelimit"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/store"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
	// ==========================================================================
	// 1. Database Setup
	// ==========================================================================
	sqldb, err := sql.Open("sqlite3", "file:auth.db?_foreign_keys=on")
	if err != nil {
		log.Fatal(err)
	}
	bunDB := bun.NewDB(sqldb, sqlitedialect.New())
	defer func() { _ = bunDB.Close() }()

	dbStore := store.New(bunDB)
	if err := dbStore.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	// ==========================================================================
	// 2. Configuration from Environment
	// ==========================================================================
	secret := os.Getenv("AUTH_SECRET")
	if secret == "" {
		secret = "development-secret-key-at-least-32-characters!"
		log.Println("WARNING: Using default development secret. Set AUTH_SECRET in production.")
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:8080"
	}

	// ==========================================================================
	// 3. Create Auth Instance
	// ==========================================================================
	authService, err := auth.New(dbStore,
		config.WithSecret(secret),
		config.WithBaseURL(baseURL),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer authService.Close()

	// ==========================================================================
	// 4. CORS Plugin - Must be first for preflight handling
	// ==========================================================================
	allowedOrigins := []string{"http://localhost:3000", "http://localhost:5173"}
	if origins := os.Getenv("ALLOWED_ORIGINS"); origins != "" {
		allowedOrigins = strings.Split(origins, ",")
	}

	authService.Use(cors.NewPlugin(
		cors.WithOrigins(allowedOrigins...),
		cors.WithCredentials(true),
		cors.WithMethods("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"),
		cors.WithHeaders("Content-Type", "Authorization", "X-CSRF-Token", "X-API-Key"),
		cors.WithExposeHeaders("X-Request-Id"),
		cors.WithMaxAge(86400), // 24 hours
	))

	// ==========================================================================
	// 5. Rate Limiting Plugin
	// ==========================================================================
	rateLimitOpts := []ratelimit.Option{
		ratelimit.WithLimit(100, time.Minute), // 100 requests per minute
		ratelimit.WithTrustedProxies([]string{
			"127.0.0.1",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		}),
	}

	// Use Redis for distributed rate limiting if available
	if redisAddr := os.Getenv("REDIS_ADDR"); redisAddr != "" {
		redisClient := redis.NewClient(&redis.Options{
			Addr:     redisAddr,
			Password: os.Getenv("REDIS_PASSWORD"),
			DB:       0,
		})
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			log.Printf("Redis not available at %s, using in-memory rate limiting: %v", redisAddr, err)
		} else {
			log.Printf("Using Redis for distributed rate limiting at %s", redisAddr)
			redisStore := kvredis.NewStoreFromClient(redisClient)
			rateLimitOpts = append(rateLimitOpts, ratelimit.WithBackend(kvredis.NewRateLimiter(redisStore)))
		}
	}

	authService.Use(ratelimit.NewPlugin(rateLimitOpts...))

	// ==========================================================================
	// 6. JWT Plugin - Token-based authentication
	// ==========================================================================
	authService.Use(jwt.NewPlugin(
		jwt.WithIssuer("betterauth-azure-example"),
		jwt.WithAudience("api"),
		jwt.WithAccessTTL(15*time.Minute),  // Short-lived access tokens
		jwt.WithRefreshTTL(7*24*time.Hour), // 7-day refresh tokens
		jwt.WithAlgorithm(jwt.AlgorithmES256),
	))

	// ==========================================================================
	// 7. OTP Plugin - One-time passwords for verification flows
	// ==========================================================================
	authService.Use(otp.NewPlugin(
		otp.WithPasswordResetExpiry(2*time.Hour),
		otp.WithEmailVerificationExpiry(24*time.Hour),
	))

	// ==========================================================================
	// 8. Password Plugin - Email/password authentication
	// ==========================================================================
	authService.Use(password.NewPlugin(
		password.WithMinLength(8),
		password.WithMaxLength(128),
	))

	// ==========================================================================
	// 9. Azure OAuth Plugin
	// ==========================================================================
	if azureClientID := os.Getenv("AZURE_CLIENT_ID"); azureClientID != "" {
		// Determine tenant configuration
		tenant := providers.AzureTenantCommon // Default: supports both personal and business accounts
		if t := os.Getenv("AZURE_TENANT"); t != "" {
			switch t {
			case "common":
				tenant = providers.AzureTenantCommon
			case "organizations":
				tenant = providers.AzureTenantOrganizations
			default:
				// Assume it's a specific tenant ID
				tenant = providers.AzureTenant(t)
			}
		}

		azureProvider := providers.NewAzure(
			azureClientID,
			os.Getenv("AZURE_CLIENT_SECRET"),
			baseURL+"/auth/oauth/azure/callback",
			providers.WithAzureTenant(tenant),
		)

		authService.Use(oauth.NewPlugin(azureProvider))
		log.Printf("Azure OAuth enabled (tenant: %s)", tenant)
	} else {
		log.Println("Azure OAuth not configured. Set AZURE_CLIENT_ID and AZURE_CLIENT_SECRET to enable.")
	}

	// ==========================================================================
	// 10. Device Auth Plugin - OAuth 2.0 Device Authorization Grant (RFC 8628)
	// ==========================================================================
	authService.Use(deviceauth.NewPlugin(
		deviceauth.WithExpiresIn(15*time.Minute),
		deviceauth.WithPollingInterval(5), // seconds
		deviceauth.WithUserCodeLength(8),
	))

	// ==========================================================================
	// 11. API Key Plugin
	// ==========================================================================
	authService.Use(apikey.NewPlugin(
		apikey.WithDefaultPrefix("ba_"),
		apikey.WithDefaultKeyLength(32),
		apikey.WithDefaultExpiresIn(90*24*time.Hour), // 90 days default
		apikey.WithSessionForAPIKeys(true),           // Create synthetic sessions for API key requests
		apikey.WithAPIKeyHeaders("X-API-Key", "Authorization"),
		apikey.WithRateLimitEnabled(true),
		apikey.WithRateLimitMax(1000),
		apikey.WithRateLimitTimeWindow(time.Hour),
		apikey.WithMetadataEnabled(true),
	))

	// ==========================================================================
	// 12. Admin Plugin - User management
	// ==========================================================================
	authService.Use(admin.NewPlugin())

	// ==========================================================================
	// 13. Check for plugin initialization errors
	// ==========================================================================
	if err := authService.Err(); err != nil {
		log.Fatal(err)
	}

	// ==========================================================================
	// 14. Set up HTTP Server
	// ==========================================================================
	mux := http.NewServeMux()

	// Mount auth endpoints under /auth/
	mux.Handle("/auth/", http.StripPrefix("/auth", authService.Handler()))

	// Protected endpoint example - requires valid session or JWT
	mux.Handle("GET /api/profile", authService.AuthMiddleware()(http.HandlerFunc(profileHandler)))

	// Protected endpoint with API key support
	mux.Handle("GET /api/data", authService.AuthMiddleware()(http.HandlerFunc(dataHandler)))

	// Home page with endpoint documentation
	mux.HandleFunc("GET /", homeHandler)

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// ==========================================================================
	// 15. Start Server
	// ==========================================================================
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on :%s", port)
	log.Printf("Auth endpoints: %s/auth/", baseURL)
	log.Printf("API endpoints:  %s/api/", baseURL)
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
		"user_id":    session.UserID,
		"session_id": session.ID,
		"message":    "Hello from protected endpoint!",
	})
}

func dataHandler(w http.ResponseWriter, r *http.Request) {
	// This endpoint can be accessed via session, JWT, or API key
	session := auth.SessionFromContext(r.Context())
	if session == nil {
		// Check for API key session
		apiKeySession := apikey.GetSessionFromContext(r.Context())
		if apiKeySession == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Using API key
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":     apiKeySession.UserID,
			"auth_method": "api_key",
			"data":        []string{"item1", "item2", "item3"},
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"user_id":     session.UserID,
		"auth_method": "session",
		"data":        []string{"item1", "item2", "item3"},
	})
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":    "BetterAuth Azure Full Example",
		"version": "1.0.0",
		"endpoints": map[string]any{
			"auth": map[string]string{
				"sign-up":          "POST /auth/sign-up",
				"sign-in":          "POST /auth/sign-in",
				"sign-out":         "POST /auth/sign-out",
				"profile":          "GET  /auth/profile",
				"password-reset":   "POST /auth/password/reset",
				"password-confirm": "POST /auth/password/confirm",
				"password-change":  "POST /auth/password/change",
			},
			"oauth": map[string]string{
				"azure":     "GET  /auth/oauth/azure",
				"callback":  "GET  /auth/oauth/azure/callback",
				"providers": "GET  /auth/oauth/providers",
			},
			"jwt": map[string]string{
				"token":   "POST /auth/jwt/token",
				"refresh": "POST /auth/jwt/refresh",
				"revoke":  "POST /auth/jwt/revoke",
				"jwks":    "GET  /auth/.well-known/jwks.json",
			},
			"device_auth": map[string]string{
				"code":    "POST /auth/device/code",
				"token":   "POST /auth/device/token",
				"verify":  "GET  /auth/device/verify",
				"approve": "POST /auth/device/approve",
				"deny":    "POST /auth/device/deny",
			},
			"api_keys": map[string]string{
				"create": "POST /auth/api-key",
				"list":   "GET  /auth/api-key",
				"get":    "POST /auth/api-key/get",
				"update": "POST /auth/api-key/update",
				"delete": "POST /auth/api-key/delete",
				"verify": "POST /auth/api-key/verify",
			},
			"admin": map[string]string{
				"list-users":         "GET    /auth/admin/users",
				"get-user":           "GET    /auth/admin/users/{id}",
				"update-user":        "PATCH  /auth/admin/users/{id}",
				"delete-user":        "DELETE /auth/admin/users/{id}",
				"ban-user":           "POST   /auth/admin/users/{id}/ban",
				"unban-user":         "POST   /auth/admin/users/{id}/unban",
				"set-role":           "POST   /auth/admin/users/{id}/role",
				"impersonate":        "POST   /auth/admin/impersonate-user",
				"stop-impersonating": "POST /auth/admin/stop-impersonating",
			},
			"api": map[string]string{
				"profile": "GET /api/profile (requires auth)",
				"data":    "GET /api/data (requires auth or API key)",
			},
		},
		"config": map[string]any{
			"cors_origins": []string{"http://localhost:3000", "http://localhost:5173"},
			"rate_limit":   "100 requests/minute",
			"jwt_issuer":   "betterauth-azure-example",
		},
	})
}
