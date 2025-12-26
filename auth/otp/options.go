package otp

import "time"

// Config holds OTP plugin configuration
type Config struct {
	// PasswordResetExpiry is how long password reset tokens are valid (default: 1 hour)
	PasswordResetExpiry time.Duration

	// EmailVerificationExpiry is how long email verification tokens are valid (default: 24 hours)
	EmailVerificationExpiry time.Duration

	// EmailChangeExpiry is how long email change tokens are valid (default: 1 hour)
	EmailChangeExpiry time.Duration
}

// DefaultConfig returns the default OTP configuration
func DefaultConfig() Config {
	return Config{
		PasswordResetExpiry:     time.Hour,
		EmailVerificationExpiry: 24 * time.Hour,
		EmailChangeExpiry:       time.Hour,
	}
}

// Option is a function that configures the OTP plugin
type Option func(*Config)

// WithPasswordResetExpiry sets the password reset token expiry duration
func WithPasswordResetExpiry(d time.Duration) Option {
	return func(c *Config) { c.PasswordResetExpiry = d }
}

// WithEmailVerificationExpiry sets the email verification token expiry duration
func WithEmailVerificationExpiry(d time.Duration) Option {
	return func(c *Config) { c.EmailVerificationExpiry = d }
}

// WithEmailChangeExpiry sets the email change token expiry duration
func WithEmailChangeExpiry(d time.Duration) Option {
	return func(c *Config) { c.EmailChangeExpiry = d }
}
