// Package plugin provides an extensibility framework for the auth library.
// Plugins can add custom functionality like additional authentication methods,
// storage backends, event handlers, and middleware to the authentication system.
package plugin

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
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
	DB() *bun.DB
}

// Context provides plugins access to auth internals during initialization
type Context struct {
	// DB is the database connection (may be nil if store doesn't implement DBProvider)
	DB *bun.DB

	// BaseURL is the base URL of the auth service
	BaseURL string

	// Secret is the auth secret (for token generation, etc.)
	Secret string

	// Auth provides access to core authentication operations.
	// This allows plugins to perform user lookups, session validation, etc.
	// May be nil during early initialization phases.
	Auth AuthCore

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
