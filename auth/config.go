package auth

import (
	"log/slog"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Config holds all configuration for the Auth system
type Config struct {
	// Required
	Secret  string
	BaseURL string

	// SkipDefaults disables automatic registration of default plugins
	// (rate limiting, CSRF, admin). Use this for minimal setups where
	// you want full control over which features are enabled.
	SkipDefaults bool

	// Session
	SessionDuration time.Duration
	SessionCookie   string

	// Password
	PasswordMinLength         int
	PasswordMaxLength         int
	RequirePasswordComplexity bool // Require uppercase, lowercase, digit, and special char

	// Email verification
	RequireEmailVerification bool
	EmailVerificationExpiry  time.Duration

	// Password reset
	PasswordResetExpiry time.Duration

	// Auto sign-in after sign-up
	AutoSignIn bool

	// CSRF
	CSRFEnabled    bool
	CSRFCookieName string
	CSRFHeaderName string

	// Rate limiting
	RateLimitEnabled bool
	RateLimitWindow  time.Duration
	RateLimitMax     int

	// Auth endpoint rate limiting (stricter)
	AuthRateLimitMax int

	// Custom rate limiter backend (e.g., Redis)
	// If nil, uses in-memory rate limiting
	RateLimiterBackend kv.RateLimiter

	// Session cleanup interval (0 to disable background cleanup)
	SessionCleanupInterval time.Duration

	// Trusted origins (for CORS and redirects)
	TrustedOrigins []string

	// Trusted proxies for X-Forwarded-For
	TrustedProxies []string

	// Hooks (per-event callbacks, backwards compatible)
	Hooks hooks.Hooks

	// MiddlewareHooks (global before/after middleware chains)
	MiddlewareHooks *hooks.MiddlewareHooks

	// Plugins registry for extensibility
	Plugins *plugin.Registry

	// Logger
	Logger *slog.Logger
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		SessionDuration:           7 * 24 * time.Hour, // 7 days
		SessionCookie:             "session",
		PasswordMinLength:         8,
		PasswordMaxLength:         128,
		RequirePasswordComplexity: true,
		RequireEmailVerification:  false,
		EmailVerificationExpiry:   24 * time.Hour,
		PasswordResetExpiry:       1 * time.Hour,
		AutoSignIn:                true,
		CSRFEnabled:               true,
		CSRFCookieName:            "csrf_token",
		CSRFHeaderName:            "X-CSRF-Token",
		RateLimitEnabled:          true,
		RateLimitWindow:           time.Minute,
		RateLimitMax:              100,
		AuthRateLimitMax:          10,
		SessionCleanupInterval:    1 * time.Hour, // Clean up expired sessions every hour
		Logger:                    slog.Default(),
	}
}

// Option is a functional option for configuring Auth
type Option func(*Config)

// WithSecret sets the secret key for token signing and encryption
func WithSecret(secret string) Option {
	return func(c *Config) {
		c.Secret = secret
	}
}

// WithBaseURL sets the base URL for the auth service
func WithBaseURL(url string) Option {
	return func(c *Config) {
		c.BaseURL = url
	}
}

// WithoutDefaults disables automatic registration of default plugins.
// When enabled, you must explicitly Use() any plugins you want.
// This is useful for minimal setups or when you want full control.
//
// Default plugins that are skipped:
//   - Rate limiting
//   - CSRF protection
//   - Admin endpoints
//   - Session cleanup
//
// Example:
//
//	auth := betterauth.New(store,
//	    betterauth.WithSecret(secret),
//	    betterauth.WithoutDefaults(),
//	)
//	auth.Use(jwt.Plugin()) // Only JWT, nothing else
func WithoutDefaults() Option {
	return func(c *Config) {
		c.SkipDefaults = true
	}
}

// WithSessionDuration sets how long sessions last
func WithSessionDuration(d time.Duration) Option {
	return func(c *Config) {
		c.SessionDuration = d
	}
}

// WithSessionCookie sets the session cookie name
func WithSessionCookie(name string) Option {
	return func(c *Config) {
		c.SessionCookie = name
	}
}

// WithPasswordPolicy sets the min and max password lengths
func WithPasswordPolicy(min, max int) Option {
	return func(c *Config) {
		c.PasswordMinLength = min
		c.PasswordMaxLength = max
	}
}

// WithPasswordComplexity enables or disables password complexity requirements
// When enabled, passwords must contain uppercase, lowercase, digit, and special character
func WithPasswordComplexity(required bool) Option {
	return func(c *Config) {
		c.RequirePasswordComplexity = required
	}
}

// WithEmailVerification configures email verification requirements
func WithEmailVerification(required bool, expiry time.Duration) Option {
	return func(c *Config) {
		c.RequireEmailVerification = required
		c.EmailVerificationExpiry = expiry
	}
}

// WithPasswordResetExpiry sets how long password reset tokens last
func WithPasswordResetExpiry(d time.Duration) Option {
	return func(c *Config) {
		c.PasswordResetExpiry = d
	}
}

// WithAutoSignIn enables or disables auto sign-in after sign-up
func WithAutoSignIn(enabled bool) Option {
	return func(c *Config) {
		c.AutoSignIn = enabled
	}
}

// WithCSRF enables or disables CSRF protection
func WithCSRF(enabled bool) Option {
	return func(c *Config) {
		c.CSRFEnabled = enabled
	}
}

// WithCSRFCookie sets the CSRF cookie name
func WithCSRFCookie(name string) Option {
	return func(c *Config) {
		c.CSRFCookieName = name
	}
}

// WithCSRFHeader sets the CSRF header name
func WithCSRFHeader(name string) Option {
	return func(c *Config) {
		c.CSRFHeaderName = name
	}
}

// WithRateLimit configures rate limiting
func WithRateLimit(enabled bool, window time.Duration, max int) Option {
	return func(c *Config) {
		c.RateLimitEnabled = enabled
		c.RateLimitWindow = window
		c.RateLimitMax = max
	}
}

// WithAuthRateLimit sets the stricter rate limit for auth endpoints
func WithAuthRateLimit(max int) Option {
	return func(c *Config) {
		c.AuthRateLimitMax = max
	}
}

// WithRateLimiterBackend sets a custom rate limiter backend (e.g., Redis).
// This allows rate limiting to be shared across multiple instances.
// If not set, an in-memory rate limiter is used.
func WithRateLimiterBackend(limiter kv.RateLimiter) Option {
	return func(c *Config) {
		c.RateLimiterBackend = limiter
	}
}

// WithSessionCleanupInterval sets the interval for automatic session cleanup
// Set to 0 to disable automatic cleanup
func WithSessionCleanupInterval(d time.Duration) Option {
	return func(c *Config) {
		c.SessionCleanupInterval = d
	}
}

// WithTrustedOrigins sets the trusted origins for CORS and redirects
func WithTrustedOrigins(origins ...string) Option {
	return func(c *Config) {
		c.TrustedOrigins = origins
	}
}

// WithTrustedProxies sets the trusted proxies for X-Forwarded-For
func WithTrustedProxies(proxies ...string) Option {
	return func(c *Config) {
		c.TrustedProxies = proxies
	}
}

// WithHooks sets the per-event hooks for auth events.
// These hooks are called after specific events like user creation, sign-in, etc.
// For global middleware-style hooks, use WithMiddlewareHooks instead.
func WithHooks(h hooks.Hooks) Option {
	return func(c *Config) {
		c.Hooks = h
	}
}

// WithMiddlewareHooks sets global before/after middleware hooks.
// These hooks run on every auth operation, similar to HTTP middleware.
// Before hooks can abort requests by returning an error (preferably *hooks.APIError).
// After hooks run after successful operations; errors are logged but don't affect responses.
func WithMiddlewareHooks(h *hooks.MiddlewareHooks) Option {
	return func(c *Config) {
		c.MiddlewareHooks = h
	}
}

// WithBeforeHook adds a single before middleware hook.
// This is a convenience method for adding a single hook without creating a MiddlewareHooks struct.
func WithBeforeHook(fn func(ctx *hooks.Context) error) Option {
	return func(c *Config) {
		if c.MiddlewareHooks == nil {
			c.MiddlewareHooks = &hooks.MiddlewareHooks{}
		}
		c.MiddlewareHooks.Before = append(c.MiddlewareHooks.Before, fn)
	}
}

// WithAfterHook adds a single after middleware hook.
// This is a convenience method for adding a single hook without creating a MiddlewareHooks struct.
func WithAfterHook(fn func(ctx *hooks.Context) error) Option {
	return func(c *Config) {
		if c.MiddlewareHooks == nil {
			c.MiddlewareHooks = &hooks.MiddlewareHooks{}
		}
		c.MiddlewareHooks.After = append(c.MiddlewareHooks.After, fn)
	}
}

// WithPlugins sets the plugin registry.
// Plugins can provide additional routes, middleware, hooks, and validation.
// The registry should be created and plugins registered before calling New.
func WithPlugins(registry *plugin.Registry) Option {
	return func(c *Config) {
		c.Plugins = registry
	}
}

// WithLogger sets the logger
func WithLogger(logger *slog.Logger) Option {
	return func(c *Config) {
		c.Logger = logger
	}
}

// MinSecretLength is the minimum required length for the secret key
const MinSecretLength = 32

// validate checks that required configuration is present
func (c *Config) validate() error {
	if c.Secret == "" {
		return ErrMissingSecret
	}
	if len(c.Secret) < MinSecretLength {
		return ErrSecretTooShort
	}
	if c.BaseURL == "" {
		return ErrMissingBaseURL
	}
	return nil
}
