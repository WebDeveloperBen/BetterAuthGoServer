package password

import (
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
)

// Config holds the password plugin configuration.
type Config struct {
	// MinLength is the minimum password length (default: 8)
	MinLength int

	// MaxLength is the maximum password length (default: 128)
	MaxLength int

	// RequireComplexity requires uppercase, lowercase, digit, and special char (default: true)
	RequireComplexity bool

	// ResetTokenExpiry is the password reset token expiry (default: 1 hour)
	ResetTokenExpiry time.Duration

	// AutoSignIn automatically signs in the user after sign-up (default: true)
	AutoSignIn bool

	// RequireEmailVerification blocks sign-in until email is verified.
	RequireEmailVerification bool

	// LockoutThreshold is the number of failed login attempts before account lockout (default: 10)
	// Set to 0 to disable lockout.
	LockoutThreshold int

	// LockoutDuration is how long an account remains locked (default: 15 minutes)
	LockoutDuration time.Duration

	// LockoutStore is the kv.Store used for tracking failed attempts and lockouts.
	// If nil, an in-memory store is used (suitable for single-instance deployments).
	// For clustered deployments, use a Redis-backed store.
	LockoutStore kv.Store
}

// DefaultConfig returns the default password configuration.
func DefaultConfig() Config {
	return Config{
		MinLength:                8,
		MaxLength:                128,
		RequireComplexity:        true,
		ResetTokenExpiry:         time.Hour,
		AutoSignIn:               true,
		RequireEmailVerification: false,
		LockoutThreshold:         10,
		LockoutDuration:          15 * time.Minute,
		// LockoutStore: nil means use in-memory (created in Init)
	}
}

// Option is a functional option for configuring the password plugin.
type Option func(*Config)

// WithMinLength sets the minimum password length.
func WithMinLength(n int) Option {
	return func(c *Config) {
		c.MinLength = n
	}
}

// WithMaxLength sets the maximum password length.
func WithMaxLength(n int) Option {
	return func(c *Config) {
		c.MaxLength = n
	}
}

// WithComplexity enables or disables password complexity requirements.
func WithComplexity(required bool) Option {
	return func(c *Config) {
		c.RequireComplexity = required
	}
}

// WithResetExpiry sets the password reset token expiry duration.
func WithResetExpiry(d time.Duration) Option {
	return func(c *Config) {
		c.ResetTokenExpiry = d
	}
}

// WithAutoSignIn enables or disables automatic sign-in after sign-up.
func WithAutoSignIn(enabled bool) Option {
	return func(c *Config) {
		c.AutoSignIn = enabled
	}
}

// WithRequireEmailVerification enforces email verification before sign-in.
func WithRequireEmailVerification(required bool) Option {
	return func(c *Config) {
		c.RequireEmailVerification = required
	}
}

// WithLockoutThreshold sets the number of failed attempts before account lockout.
// Set to 0 to disable lockout.
func WithLockoutThreshold(n int) Option {
	return func(c *Config) {
		c.LockoutThreshold = n
	}
}

// WithLockoutDuration sets how long an account remains locked after too many failed attempts.
func WithLockoutDuration(d time.Duration) Option {
	return func(c *Config) {
		c.LockoutDuration = d
	}
}

// WithLockoutStore sets a custom kv.Store for tracking failed attempts and lockouts.
// Use this with a Redis-backed store for clustered deployments.
func WithLockoutStore(store kv.Store) Option {
	return func(c *Config) {
		c.LockoutStore = store
	}
}
