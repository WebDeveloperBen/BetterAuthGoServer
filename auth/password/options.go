package password

import "time"

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
}

// DefaultConfig returns the default password configuration.
func DefaultConfig() Config {
	return Config{
		MinLength:         8,
		MaxLength:         128,
		RequireComplexity: true,
		ResetTokenExpiry:  time.Hour,
		AutoSignIn:        true,
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
