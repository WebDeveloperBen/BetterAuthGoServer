// Package plugin provides an extensibility framework for the auth library.
// Plugins can add custom functionality like additional authentication methods,
// storage backends, hooks, and middleware to the authentication system.
package plugin

import (
	"context"
	"net/http"

	"github.com/uptrace/bun"
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
}

// MigrationsProvider is implemented by plugins that need database tables
type MigrationsProvider interface {
	// Migrations returns the Bun models to migrate
	Migrations() []any
}

// HooksProvider is implemented by plugins that want to hook into auth events
type HooksProvider interface {
	// Hooks returns hook functions to merge with existing hooks
	Hooks() Hooks
}

// Hooks contains optional hook functions for auth events
type Hooks struct {
	// OnUserCreated is called after a new user is created
	OnUserCreated func(ctx context.Context, userID string) error

	// OnSignIn is called after successful sign in
	OnSignIn func(ctx context.Context, userID, sessionID string) error

	// OnSignOut is called after sign out
	OnSignOut func(ctx context.Context, userID, sessionID string) error

	// BeforeSignIn is called before sign in validation
	// Return an error to prevent sign in
	BeforeSignIn func(ctx context.Context, email string) error
}

// MiddlewareProvider is implemented by plugins that add middleware
type MiddlewareProvider interface {
	// Middleware returns middleware to apply to auth routes
	Middleware() []func(http.Handler) http.Handler
}

// ValidatorProvider is implemented by plugins that add custom validation
type ValidatorProvider interface {
	// ValidateSignUp validates sign up data, return error to reject
	ValidateSignUp(ctx context.Context, email, password, name string) error

	// ValidateSignIn validates sign in, return error to reject
	ValidateSignIn(ctx context.Context, email string) error
}
