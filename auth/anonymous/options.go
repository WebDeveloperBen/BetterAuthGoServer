package anonymous

import (
	"context"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Config holds the configuration for the anonymous plugin
type Config struct {
	// EmailDomain for generated emails (default: "anonymous.local")
	EmailDomain string

	// GenerateEmail custom function to generate email addresses
	// If nil, uses default: anon-{uuid}@{EmailDomain}
	GenerateEmail func() string

	// GenerateName custom function to generate display names
	// If nil, uses default: "Anonymous User"
	GenerateName func() string

	// OnLinkAccount callback when anonymous user links to real account
	// Receives the anonymous user and the new user
	// Use for data migration (shopping cart, preferences, etc.)
	OnLinkAccount func(ctx context.Context, anonUser, newUser *plugin.User) error

	// DisableDeleteAnonymousUser keeps anonymous user after linking (default: false)
	DisableDeleteAnonymousUser bool

	// AnonymousUserTTL auto-deletes anonymous users who never linked after this duration
	// Set to 0 to disable (default: 0 - disabled)
	AnonymousUserTTL time.Duration

	// CleanupInterval how often to run the cleanup job (default: 1 hour)
	CleanupInterval time.Duration
}

// DefaultConfig returns the default configuration
func DefaultConfig() Config {
	return Config{
		EmailDomain:                "anonymous.local",
		DisableDeleteAnonymousUser: false,
		AnonymousUserTTL:           0, // Disabled by default
		CleanupInterval:            time.Hour,
	}
}

// Option is a functional option for configuring the anonymous plugin
type Option func(*Config)

// WithEmailDomain sets the domain for generated anonymous emails
func WithEmailDomain(domain string) Option {
	return func(c *Config) {
		c.EmailDomain = domain
	}
}

// WithGenerateEmail sets a custom email generation function
func WithGenerateEmail(fn func() string) Option {
	return func(c *Config) {
		c.GenerateEmail = fn
	}
}

// WithGenerateName sets a custom name generation function
func WithGenerateName(fn func() string) Option {
	return func(c *Config) {
		c.GenerateName = fn
	}
}

// WithOnLinkAccount sets the callback for when an anonymous user links to a real account
func WithOnLinkAccount(fn func(ctx context.Context, anonUser, newUser *plugin.User) error) Option {
	return func(c *Config) {
		c.OnLinkAccount = fn
	}
}

// WithDisableDeleteAnonymousUser keeps the anonymous user after linking
func WithDisableDeleteAnonymousUser() Option {
	return func(c *Config) {
		c.DisableDeleteAnonymousUser = true
	}
}

// WithAnonymousUserTTL sets the TTL for automatic cleanup of stale anonymous users
func WithAnonymousUserTTL(ttl time.Duration) Option {
	return func(c *Config) {
		c.AnonymousUserTTL = ttl
	}
}

// WithCleanupInterval sets how often to run the cleanup job
func WithCleanupInterval(interval time.Duration) Option {
	return func(c *Config) {
		c.CleanupInterval = interval
	}
}
