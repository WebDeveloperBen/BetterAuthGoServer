// Package main demonstrates a fully-featured BetterAuthGoServer configuration
// with all available plugins, options, and extensibility points enabled.
//
// This is a "batteries included" example showing every available feature.
// In production, you would typically only enable the features you need.
package main

import (
	"context"
	"database/sql"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"

	_ "github.com/mattn/go-sqlite3"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/admin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/config"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/providers"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/organization"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/password"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/ratelimit"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/store"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn"
)

func main() {
	// ============================================================================
	// ENVIRONMENT CONFIGURATION
	// ============================================================================
	dbURL := getEnv("DATABASE_URL", "sqlite://auth.db")
	secret := getEnv("AUTH_SECRET", "your-secret-key-min-32-chars-long!")
	baseURL := getEnv("BASE_URL", "http://localhost:8080")
	port := getEnv("PORT", "8080")
	frontendURL := getEnv("FRONTEND_URL", "http://localhost:3000")

	// Parse base URL for WebAuthn configuration
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		log.Fatal("Invalid BASE_URL:", err)
	}

	// ============================================================================
	// LOGGER SETUP
	// ============================================================================
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))
	slog.SetDefault(logger)

	// ============================================================================
	// DATABASE CONNECTION
	// ============================================================================
	bunDB, err := connectDB(dbURL)
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}
	defer func() { _ = bunDB.Close() }()

	// Create store and run migrations
	dbStore := store.New(bunDB)
	if err := dbStore.Migrate(context.Background()); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// ============================================================================
	// AUTH SERVICE - FULL CONFIGURATION
	// ============================================================================
	authService, err := auth.New(dbStore,
		// ----- Core Configuration -----
		config.WithSecret(secret),
		config.WithBaseURL(baseURL),
		config.WithLogger(logger),

		// ----- Session Configuration -----
		config.WithSessionDuration(7*24*time.Hour),     // 7 days
		config.WithSessionCookie("auth_session"),       // Session cookie name
		config.WithSessionCleanupInterval(1*time.Hour), // Auto-cleanup expired sessions
		config.WithMaxSessionsPerUser(10),              // Max concurrent sessions per user

		// ----- Password Configuration -----
		config.WithPasswordAuth(true),               // Enable password auth
		config.WithPasswordPolicy(8, 128),           // Min 8, max 128 characters
		config.WithPasswordComplexity(true),         // Require uppercase, lowercase, digit, special
		config.WithPasswordResetExpiry(1*time.Hour), // Password reset token expiry
		config.WithAutoSignIn(true),                 // Auto sign-in after registration

		// ----- Email Verification -----
		config.WithEmailVerification(true, 24*time.Hour), // Required, 24h token expiry

		// ----- CSRF Protection -----
		config.WithCSRF(true),                 // Enable CSRF protection
		config.WithCSRFCookie("csrf_token"),   // CSRF cookie name
		config.WithCSRFHeader("X-CSRF-Token"), // CSRF header name

		// ----- Rate Limiting -----
		config.WithRateLimit(true, 1*time.Minute, 100), // 100 requests per minute
		config.WithAuthRateLimit(10),                   // 10 auth attempts per minute

		// ----- Trusted Origins/Proxies -----
		config.WithTrustedOrigins(baseURL, frontendURL),
		config.WithTrustedProxies("127.0.0.1", "::1"), // Trust localhost proxies

		// ----- Global Middleware Hooks -----
		config.WithBeforeHook(func(ctx *hooks.Context) error {
			// Log all auth operations
			logger.Debug("auth operation",
				"method", ctx.Request.Method,
				"path", ctx.Request.URL.Path,
				"ip", ctx.Request.RemoteAddr,
			)
			return nil
		}),
		config.WithAfterHook(func(ctx *hooks.Context) error {
			// Post-operation logging
			userID := ""
			if ctx.Session != nil {
				userID = ctx.Session.UserID
			}
			logger.Debug("auth operation completed",
				"path", ctx.Request.URL.Path,
				"user_id", userID,
			)
			return nil
		}),
	)
	if err != nil {
		log.Fatal("Failed to create auth service:", err)
	}

	// ============================================================================
	// REGISTER PLUGINS - Using builder pattern with chained Use() calls
	// Order matters for migrations
	// ============================================================================

	// Build OAuth providers dynamically based on environment
	var oauthProviders []oauth.Provider

	if clientID := os.Getenv("GOOGLE_CLIENT_ID"); clientID != "" {
		oauthProviders = append(oauthProviders, providers.NewGoogle(
			clientID,
			os.Getenv("GOOGLE_CLIENT_SECRET"),
			baseURL+"/auth/oauth/google/callback",
		))
	}

	if clientID := os.Getenv("GITHUB_CLIENT_ID"); clientID != "" {
		oauthProviders = append(oauthProviders, providers.NewGitHub(
			clientID,
			os.Getenv("GITHUB_CLIENT_SECRET"),
			baseURL+"/auth/oauth/github/callback",
		))
	}

	if clientID := os.Getenv("DISCORD_CLIENT_ID"); clientID != "" {
		oauthProviders = append(oauthProviders, providers.NewDiscord(
			clientID,
			os.Getenv("DISCORD_CLIENT_SECRET"),
			baseURL+"/auth/oauth/discord/callback",
		))
	}

	// Chain all plugins using builder pattern
	authService.
		// ----- OTP Plugin (Email/Password Reset Tokens) -----
		Use(otp.NewPlugin(
			otp.WithPasswordResetExpiry(1*time.Hour),
			otp.WithEmailVerificationExpiry(24*time.Hour),
			otp.WithEmailChangeExpiry(1*time.Hour),
		)).
		// ----- Password Plugin (Email/Password Authentication) -----
		Use(password.NewPlugin(
			password.WithMinLength(8),
			password.WithMaxLength(128),
			password.WithComplexity(true),
			password.WithResetExpiry(1*time.Hour),
			password.WithAutoSignIn(true),
			password.WithLockoutThreshold(5),
			password.WithLockoutDuration(15*time.Minute),
		)).
		// ----- Rate Limiting Plugin -----
		Use(ratelimit.NewPlugin(
			ratelimit.WithLimit(100, 1*time.Minute),
			ratelimit.WithKeyFunc(func(r *http.Request) string {
				if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
					return strings.Split(xff, ",")[0]
				}
				return strings.Split(r.RemoteAddr, ":")[0]
			}),
			ratelimit.WithTrustedProxies([]string{"127.0.0.1", "::1"}),
		)).
		// ----- Admin Plugin -----
		Use(admin.NewPlugin(
			admin.WithDefaultRole("user"),
			admin.WithAdminRoles([]string{"admin", "superadmin"}),
			admin.WithAdminUserIDs([]string{}),
			admin.WithImpersonationSessionDuration(1*time.Hour),
			admin.WithDefaultBanReason("Violation of terms of service"),
			admin.WithDefaultBanExpiresIn(0),
			admin.WithBannedUserMessage("Your account has been suspended."),
			admin.WithAllowImpersonatingAdmins(false),
		)).
		// ----- JWT Plugin -----
		Use(jwt.NewPlugin(
			jwt.WithAlgorithm(jwt.AlgorithmHS256),
			jwt.WithAccessTTL(15*time.Minute),
			jwt.WithRefreshTTL(7*24*time.Hour),
			jwt.WithIssuer(baseURL),
			jwt.WithAudience(baseURL),
		)).
		// ----- WebAuthn Plugin (Passwordless/2FA) -----
		Use(webauthn.NewPlugin(
			webauthn.WithRPID(parsedURL.Hostname()),
			webauthn.WithRPDisplayName("BetterAuth Demo"),
			webauthn.WithRPOrigins([]string{baseURL, frontendURL}),
			webauthn.WithTimeout(5*time.Minute),
			webauthn.WithAllowResidentKey(true),
			webauthn.WithAllowPasswordlessAccounts(true),
			webauthn.WithAllowSecondFactor(true),
			webauthn.WithUserVerification("preferred"),
			webauthn.WithAttestationPreference("none"),
		)).
		// ----- Organization Plugin -----
		Use(organization.NewPlugin(
			organization.WithCreatorRole("owner"),
			organization.WithMembershipLimit(100),
			organization.WithInvitationExpiresIn(48*time.Hour),
			organization.WithCancelPendingInvitationsOnReInvite(true),
			organization.WithAllowUserToCreateOrganization(func(userID string) bool {
				return true
			}),
			organization.WithOrganizationLimit(func(userID string) int {
				return 5
			}),
			organization.WithSendInvitationEmail(func(invitation *organization.Invitation, org *organization.Organization) error {
				logger.Info("Send invitation email",
					"to", invitation.Email,
					"org", org.Name,
					"org_id", org.ID,
					"invitation_id", invitation.ID,
					"url", baseURL+"/auth/organization/invitation/accept?id="+invitation.ID,
				)
				return nil
			}),
			organization.WithTeams(organization.TeamsConfig{
				Enabled:               true,
				AllowRemovingAllTeams: false,
				MaximumTeams: func(orgID string) int {
					return 20
				},
				MaximumMembersPerTeam: func(teamID string) int {
					return 50
				},
			}),
			organization.WithOrganizationHooks(organization.OrganizationHooks{
				AfterCreateOrganization: func(org *organization.Organization, member *organization.Member, userID string) error {
					logger.Info("Organization created",
						"org_id", org.ID,
						"org_name", org.Name,
						"creator_id", userID,
					)
					return nil
				},
				AfterAddMember: func(member *organization.Member, userID string) error {
					logger.Info("Member added to organization",
						"member_user_id", member.UserID,
						"role", member.Role,
						"added_by", userID,
					)
					return nil
				},
			}),
		))

	// Add OAuth plugin if any providers are configured
	if len(oauthProviders) > 0 {
		authService.Use(oauth.NewPlugin(oauthProviders...))
	}

	// Check for any plugin registration errors
	if err := authService.Err(); err != nil {
		log.Fatal("Failed to register plugins:", err)
	}

	// ============================================================================
	// EVENT SUBSCRIPTIONS
	// ============================================================================
	eventBus := authService.EventBus()

	// User created - send welcome email
	_, _ = eventBus.Subscribe(models.EventUserCreated, func(ctx context.Context, e models.Event) error {
		var payload models.UserCreatedPayload
		if err := e.UnmarshalPayload(&payload); err != nil {
			return err
		}
		logger.Info("New user registered",
			"user_id", payload.User.ID,
			"email", payload.User.Email,
			"name", payload.User.Name,
		)
		// TODO: Send welcome email
		return nil
	})

	// User signed in - audit log
	_, _ = eventBus.Subscribe(models.EventSignedIn, func(ctx context.Context, e models.Event) error {
		var payload models.SignedInPayload
		if err := e.UnmarshalPayload(&payload); err != nil {
			return err
		}
		logger.Info("User signed in",
			"user_id", payload.User.ID,
			"session_id", payload.Session.ID,
			"ip", payload.Session.IPAddress,
		)
		return nil
	})

	// User signed out
	_, _ = eventBus.Subscribe(models.EventSignedOut, func(ctx context.Context, e models.Event) error {
		var payload models.SignedOutPayload
		if err := e.UnmarshalPayload(&payload); err != nil {
			return err
		}
		logger.Info("User signed out",
			"user_id", payload.User.ID,
			"session_id", payload.Session.ID,
		)
		return nil
	})

	// Email verification sent - send the email
	_, _ = eventBus.Subscribe(models.EventEmailVerificationSent, func(ctx context.Context, e models.Event) error {
		var payload models.EmailVerificationSentPayload
		if err := e.UnmarshalPayload(&payload); err != nil {
			return err
		}
		verifyURL := baseURL + "/auth/email/verify?token=" + payload.Token
		logger.Info("Send email verification",
			"user_id", payload.User.ID,
			"email", payload.User.Email,
			"url", verifyURL,
		)
		// TODO: Send verification email
		return nil
	})

	// Email verified
	_, _ = eventBus.Subscribe(models.EventEmailVerified, func(ctx context.Context, e models.Event) error {
		var payload models.EmailVerifiedPayload
		if err := e.UnmarshalPayload(&payload); err != nil {
			return err
		}
		logger.Info("Email verified",
			"user_id", payload.User.ID,
			"email", payload.User.Email,
		)
		return nil
	})

	// Password reset requested - send reset email
	_, _ = eventBus.Subscribe(models.EventPasswordResetRequested, func(ctx context.Context, e models.Event) error {
		var payload models.PasswordResetRequestedPayload
		if err := e.UnmarshalPayload(&payload); err != nil {
			return err
		}
		resetURL := baseURL + "/auth/password/confirm?token=" + payload.Token
		logger.Info("Send password reset email",
			"user_id", payload.User.ID,
			"email", payload.User.Email,
			"url", resetURL,
		)
		// TODO: Send password reset email
		return nil
	})

	// Password changed - notify user
	_, _ = eventBus.Subscribe(models.EventPasswordChanged, func(ctx context.Context, e models.Event) error {
		var payload models.PasswordChangedPayload
		if err := e.UnmarshalPayload(&payload); err != nil {
			return err
		}
		logger.Info("Password changed",
			"user_id", payload.User.ID,
		)
		// TODO: Send password change notification email
		return nil
	})

	// OAuth account linked
	_, _ = eventBus.Subscribe(models.EventOAuthAccountLinked, func(ctx context.Context, e models.Event) error {
		var payload models.OAuthAccountLinkedPayload
		if err := e.UnmarshalPayload(&payload); err != nil {
			return err
		}
		logger.Info("OAuth account linked",
			"user_id", payload.User.ID,
			"provider", payload.Account.Provider,
		)
		return nil
	})

	// ============================================================================
	// HTTP ROUTES
	// ============================================================================
	mux := http.NewServeMux()

	// Mount auth handler at /auth
	mux.Handle("/auth/", http.StripPrefix("/auth", authService.Handler()))

	// Health check
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Protected API route example
	mux.Handle("GET /api/me", authService.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		if session == nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}

		user, err := authService.GetUser(r.Context(), session.UserID)
		if err != nil {
			http.Error(w, `{"error":"user not found"}`, http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"` + user.ID + `","email":"` + user.Email + `","name":"` + user.Name + `","role":"` + user.Role + `"}`))
	})))

	// Optional auth route example
	mux.Handle("GET /api/status", authService.OptionalAuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		if session != nil {
			_, _ = w.Write([]byte(`{"authenticated":true,"user_id":"` + session.UserID + `"}`))
		} else {
			_, _ = w.Write([]byte(`{"authenticated":false}`))
		}
	})))

	// ============================================================================
	// START SERVER
	// ============================================================================
	logger.Info("Starting BetterAuthGoServer",
		"port", port,
		"base_url", baseURL,
		"database", maskDSN(dbURL),
		"plugins", []string{"otp", "password", "ratelimit", "admin", "jwt", "webauthn", "organization", "oauth"},
	)

	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal("Server failed:", err)
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

// connectDB creates a Bun DB connection based on the DATABASE_URL scheme
func connectDB(dbURL string) (*bun.DB, error) {
	switch {
	case strings.HasPrefix(dbURL, "postgres://"), strings.HasPrefix(dbURL, "postgresql://"):
		sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dbURL)))
		return bun.NewDB(sqldb, pgdialect.New()), nil

	case strings.HasPrefix(dbURL, "sqlite://"):
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
