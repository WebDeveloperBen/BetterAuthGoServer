// Package config provides configuration options and utilities for the authentication system.
package config

import (
	"log/slog"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
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
	PasswordAuthEnabled       bool // Enable password authentication plugin (default: true)
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

	// MaxSessionsPerUser limits concurrent sessions per user.
	// When creating a new session would exceed this limit, the oldest sessions are deleted.
	// Set to 0 for unlimited sessions (default: 10).
	MaxSessionsPerUser int

	// Trusted origins (for CORS and redirects)
	TrustedOrigins []string

	// Trusted proxies for X-Forwarded-For
	TrustedProxies []string

	// EventBus for publishing and subscribing to auth events
	EventBus models.EventBus

	// MiddlewareHooks (global before/after middleware chains)
	MiddlewareHooks *hooks.MiddlewareHooks

	// Plugins registry for extensibility
	Plugins *plugin.Registry

	// Logger
	Logger *slog.Logger
}

// Option is a functional option for configuring Auth
type Option func(*Config)

// NewConfig creates a Config with sensible defaults and applies options.
func NewConfig(opts ...Option) *Config {
	// Define sensible defaults inline
	cfg := &Config{
		// Session
		SessionDuration: 7 * 24 * time.Hour, // 7 days
		SessionCookie:   "session",

		// Password
		PasswordAuthEnabled:       true,
		PasswordMinLength:         8,
		PasswordMaxLength:         128,
		RequirePasswordComplexity: true,

		// Email verification
		RequireEmailVerification: false,
		EmailVerificationExpiry:  24 * time.Hour,

		// Password reset
		PasswordResetExpiry: 1 * time.Hour,

		// Auto sign-in after sign-up
		AutoSignIn: true,

		// CSRF protection
		CSRFEnabled:    true,
		CSRFCookieName: "csrf_token",
		CSRFHeaderName: "X-CSRF-Token",

		// Rate limiting
		RateLimitEnabled: true,
		RateLimitWindow:  time.Minute,
		RateLimitMax:     100,
		AuthRateLimitMax: 10,

		// Session cleanup (background goroutine)
		SessionCleanupInterval: 1 * time.Hour,

		// Max sessions per user
		MaxSessionsPerUser: 10,

		// Logging
		Logger: slog.Default(),
	}

	// Apply the options
	for _, opt := range opts {
		opt(cfg)
	}

	return cfg
}

// DefaultConfig returns a Config with sensible defaults.
// Prefer NewConfig() with options for most use cases.
func DefaultConfig() Config {
	cfg := NewConfig()
	return *cfg
}

// Validate checks that required configuration is present
func (c *Config) Validate() error {
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
