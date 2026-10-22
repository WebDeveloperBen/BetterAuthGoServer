// Package plugin provides an extensibility framework for the auth library.
// Plugins can add custom functionality like additional authentication methods,
// storage backends, event handlers, and middleware to the authentication system.
package plugin

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Plugin is the core interface that all plugins must implement
type Plugin interface {
	// Name returns a unique identifier for the plugin
	Name() string

	// Init initializes the plugin with the provided context
	Init(ctx Context) error

	// Close cleans up any resources held by the plugin
	Close() error
}

// DBProvider is an interface for stores that can provide database access.
// Implement this interface in your store to allow plugins to access the database.
type DBProvider interface {
	// DB returns the underlying database connection for raw SQL operations.
	DB() db.DBTX
	// Dialect returns the database dialect (postgres, sqlite, mysql).
	Dialect() db.Dialect
}

// PluginStoreProvider is an interface for stores that provide the full plugin store.
// This is the preferred way for plugins to access database operations.
type PluginStoreProvider interface {
	// PluginStore returns the store for plugin database operations.
	PluginStore() db.PluginStore
}

// Context provides plugins access to auth internals during initialization
type Context struct {
	// Store provides access to plugin database operations.
	// This is the preferred way to access database functionality.
	// May be nil if the store doesn't implement PluginStoreProvider.
	Store db.PluginStore

	// RawDB provides the underlying database connection for advanced use cases.
	// Most plugins should use Store instead.
	// May be nil if the store doesn't implement DBProvider.
	RawDB db.DBTX

	// Dialect indicates the database type (postgres, sqlite, mysql).
	Dialect db.Dialect

	// BaseURL is the base URL of the auth service
	BaseURL string

	// Secret is the auth secret (for token generation, etc.)
	Secret string

	// TrustedOrigins contains allowed origins for redirects and CORS.
	TrustedOrigins []string

	// TrustedProxies contains allowed proxy IPs for client IP extraction.
	TrustedProxies []string

	// RequireEmailVerification indicates whether email verification is required
	// before allowing sign-in or session issuance.
	RequireEmailVerification bool

	// Auth provides access to core authentication operations.
	// This allows plugins to perform user lookups, session validation, etc.
	// May be nil during early initialization phases.
	Auth AuthCore

	// Sessions provides session management operations for plugins.
	// Allows plugins to get, create, and delete sessions.
	Sessions SessionManager

	// Token utilities for plugins that need to hash or encrypt tokens
	Hasher    *token.Hasher
	Encryptor *token.Encryptor

	// Logger provides structured logging for plugins
	Logger *slog.Logger

	// EventBus for subscribing to auth events
	EventBus models.EventBus
}

// RoutesProvider is implemented by plugins that add HTTP routes
type RoutesProvider interface {
	// Routes returns the routes to register
	Routes() []Route
}

// Route defines an HTTP route added by a plugin
type Route struct {
	// Method is the HTTP method (GET, POST, etc.)
	Method string

	// Path is the route path (relative to auth mount point)
	Path string

	// Handler is the HTTP handler for this route
	Handler http.HandlerFunc

	// RequireAuth indicates if this route requires authentication
	RequireAuth bool

	// Middleware is optional route-specific middleware
	Middleware []func(http.Handler) http.Handler
}

// MigrationsProvider is implemented by plugins that need database tables
type MigrationsProvider interface {
	// Migrations returns the Bun models to migrate
	Migrations() []any
}

// MiddlewareProvider is implemented by plugins that add middleware
type MiddlewareProvider interface {
	// Middleware returns middleware to apply to auth routes
	Middleware() []Middleware
}

// Middleware represents a middleware handler with ordering priority.
// Lower priority values run first (e.g., rate limiting at 10 runs before auth at 50).
type Middleware struct {
	// Priority determines execution order. Lower values run first.
	// Suggested ranges:
	//   0-20:  Rate limiting, request validation
	//   20-40: Authentication, authorization
	//   40-60: Request transformation
	//   60-80: Logging, metrics
	//   80+:   Cleanup, response transformation
	Priority int

	// Handler is the middleware function
	Handler func(http.Handler) http.Handler
}

// ValidatorProvider is implemented by plugins that add custom validation
type ValidatorProvider interface {
	// ValidateSignUp validates sign up data, return error to reject
	ValidateSignUp(ctx context.Context, email, password, name string) error

	// ValidateSignIn validates sign in, return error to reject
	ValidateSignIn(ctx context.Context, email string) error
}

// EmailVerificationProvider is implemented by plugins that handle email verification tokens.
// This allows the auth package to send/verify emails without importing specific plugin packages.
//
// Implementations should return models.ErrVerificationNotFound for invalid tokens
// and models.ErrVerificationExpired for expired tokens.
type EmailVerificationProvider interface {
	// CreateEmailVerificationToken creates a token and returns the raw token to send via email.
	CreateEmailVerificationToken(ctx context.Context, userID string) (rawToken string, err error)

	// ConsumeEmailVerificationToken validates and consumes a token, returning the user ID.
	ConsumeEmailVerificationToken(ctx context.Context, rawToken string) (userID string, err error)
}

// PasswordResetTokenProvider is implemented by plugins that handle password reset tokens.
// This allows the password plugin to request/verify reset tokens without importing specific plugins.
//
// Implementations should return models.ErrVerificationNotFound for invalid tokens
// and models.ErrVerificationExpired for expired tokens.
type PasswordResetTokenProvider interface {
	// CreatePasswordResetToken creates a token and returns the raw token to send via email.
	CreatePasswordResetToken(ctx context.Context, userID string) (rawToken string, err error)

	// ConsumePasswordResetToken validates and consumes a token, returning the user ID.
	ConsumePasswordResetToken(ctx context.Context, rawToken string) (userID string, err error)
}

// Identity is a sign-in identity a plugin stores for a user outside the core accounts
// table, such as a linked OAuth provider account.
type Identity struct {
	ID                string
	UserID            string
	Provider          string
	ProviderAccountID string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// IdentityProvider is implemented by plugins that store sign-in identities outside the
// core accounts table. Core lists these identities under GET /accounts, lets users
// unlink them, and counts them when protecting the last sign-in method.
//
// tx is the transaction core runs the operation in, or nil when the store has no
// transaction support; implementations must use it when it is non-nil.
type IdentityProvider interface {
	// ListIdentities returns the user's identities.
	ListIdentities(ctx context.Context, tx db.DBTX, userID string) ([]Identity, error)

	// DeleteIdentity deletes the identity with the given ID.
	DeleteIdentity(ctx context.Context, tx db.DBTX, identityID string) error
}
