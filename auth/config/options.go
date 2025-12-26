package config

import (
	"log/slog"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

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
//	auth := auth.New(store,
//	    config.WithSecret(secret),
//	    config.WithoutDefaults(),
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

// WithEventBus sets a custom EventBus for auth events.
// If not set, a default in-memory EventBus is created.
// Use this to provide a custom EventBus implementation (e.g., backed by Redis).
func WithEventBus(bus models.EventBus) Option {
	return func(c *Config) {
		c.EventBus = bus
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
