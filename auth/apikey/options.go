package apikey

import (
	"net/http"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
)

// Config holds the configuration for the API key plugin.
type Config struct {
	// Key generation
	DefaultKeyLength  int    // Default: 32 bytes (43 chars base64)
	DefaultPrefix     string // Default prefix for new keys (e.g., "myapp")
	StartLength       int    // Number of chars to store for UI display (default: 6)
	MinPrefixLength   int    // Minimum prefix length (default: 1)
	MaxPrefixLength   int    // Maximum prefix length (default: 32)
	MinNameLength     int    // Minimum name length (default: 1)
	MaxNameLength     int    // Maximum name length (default: 32)
	DisableKeyHashing bool   // If true, store keys in plaintext (NOT RECOMMENDED)

	// Rate limiting defaults
	RateLimitEnabled    bool           // Default: true
	RateLimitTimeWindow time.Duration  // Default: 24h
	RateLimitMax        int            // Default: 10 requests per window
	RateLimiter         kv.RateLimiter // Optional external rate limiter (e.g., Redis)

	// Expiration
	DefaultExpiresIn *time.Duration // Default expiration for new keys (nil = no expiration)
	MinExpiresIn     *time.Duration // Minimum allowed expiration
	MaxExpiresIn     *time.Duration // Maximum allowed expiration

	// Session integration
	EnableSessionForAPIKeys bool                         // If true, valid API keys create synthetic sessions
	APIKeyHeaders           []string                     // Headers to check for API keys (default: ["x-api-key"])
	APIKeyGetter            func(r *http.Request) string // Custom API key extractor

	// Permissions
	DefaultPermissions Permissions // Default permissions for new keys
	EnableMetadata     bool        // If true, allow metadata on keys (default: true)

	// Hooks
	OnAPIKeyCreated  func(key *APIKey)
	OnAPIKeyDeleted  func(key *APIKey)
	OnAPIKeyVerified func(key *APIKey, r *http.Request)
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		DefaultKeyLength:    32,
		StartLength:         6,
		MinPrefixLength:     1,
		MaxPrefixLength:     32,
		MinNameLength:       1,
		MaxNameLength:       32,
		DisableKeyHashing:   false,
		RateLimitEnabled:    true,
		RateLimitTimeWindow: 24 * time.Hour,
		RateLimitMax:        10,
		APIKeyHeaders:       []string{"x-api-key"},
		EnableMetadata:      true,
	}
}

// Option is a functional option for configuring the plugin.
type Option func(*Config)

// WithDefaultKeyLength sets the default key length in bytes.
func WithDefaultKeyLength(length int) Option {
	return func(c *Config) {
		c.DefaultKeyLength = length
	}
}

// WithDefaultPrefix sets the default prefix for new keys.
func WithDefaultPrefix(prefix string) Option {
	return func(c *Config) {
		c.DefaultPrefix = prefix
	}
}

// WithStartLength sets the number of characters to store for UI display.
func WithStartLength(length int) Option {
	return func(c *Config) {
		c.StartLength = length
	}
}

// WithPrefixLimits sets the minimum and maximum prefix length.
func WithPrefixLimits(min, max int) Option {
	return func(c *Config) {
		c.MinPrefixLength = min
		c.MaxPrefixLength = max
	}
}

// WithNameLimits sets the minimum and maximum name length.
func WithNameLimits(min, max int) Option {
	return func(c *Config) {
		c.MinNameLength = min
		c.MaxNameLength = max
	}
}

// WithDisableKeyHashing disables key hashing (NOT RECOMMENDED).
func WithDisableKeyHashing(disable bool) Option {
	return func(c *Config) {
		c.DisableKeyHashing = disable
	}
}

// WithRateLimitEnabled enables or disables rate limiting.
func WithRateLimitEnabled(enabled bool) Option {
	return func(c *Config) {
		c.RateLimitEnabled = enabled
	}
}

// WithRateLimitTimeWindow sets the rate limit time window.
func WithRateLimitTimeWindow(window time.Duration) Option {
	return func(c *Config) {
		c.RateLimitTimeWindow = window
	}
}

// WithRateLimitMax sets the maximum requests per rate limit window.
func WithRateLimitMax(max int) Option {
	return func(c *Config) {
		c.RateLimitMax = max
	}
}

// WithRateLimiter sets an external rate limiter (e.g., Redis).
// If not set, rate limiting state is stored in the database per key.
func WithRateLimiter(limiter kv.RateLimiter) Option {
	return func(c *Config) {
		c.RateLimiter = limiter
	}
}

// WithDefaultExpiresIn sets the default expiration for new keys.
func WithDefaultExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		c.DefaultExpiresIn = &d
	}
}

// WithExpirationLimits sets the minimum and maximum expiration times.
func WithExpirationLimits(min, max time.Duration) Option {
	return func(c *Config) {
		c.MinExpiresIn = &min
		c.MaxExpiresIn = &max
	}
}

// WithSessionForAPIKeys enables session integration for API keys.
// When enabled, valid API keys create synthetic sessions.
func WithSessionForAPIKeys(enable bool) Option {
	return func(c *Config) {
		c.EnableSessionForAPIKeys = enable
	}
}

// WithAPIKeyHeaders sets the headers to check for API keys.
func WithAPIKeyHeaders(headers ...string) Option {
	return func(c *Config) {
		c.APIKeyHeaders = headers
	}
}

// WithAPIKeyGetter sets a custom API key extractor function.
func WithAPIKeyGetter(getter func(r *http.Request) string) Option {
	return func(c *Config) {
		c.APIKeyGetter = getter
	}
}

// WithDefaultPermissions sets the default permissions for new keys.
func WithDefaultPermissions(perms Permissions) Option {
	return func(c *Config) {
		c.DefaultPermissions = perms
	}
}

// WithMetadataEnabled enables or disables metadata on keys.
func WithMetadataEnabled(enabled bool) Option {
	return func(c *Config) {
		c.EnableMetadata = enabled
	}
}

// WithOnAPIKeyCreated sets a hook called when an API key is created.
func WithOnAPIKeyCreated(hook func(key *APIKey)) Option {
	return func(c *Config) {
		c.OnAPIKeyCreated = hook
	}
}

// WithOnAPIKeyDeleted sets a hook called when an API key is deleted.
func WithOnAPIKeyDeleted(hook func(key *APIKey)) Option {
	return func(c *Config) {
		c.OnAPIKeyDeleted = hook
	}
}

// WithOnAPIKeyVerified sets a hook called when an API key is verified.
func WithOnAPIKeyVerified(hook func(key *APIKey, r *http.Request)) Option {
	return func(c *Config) {
		c.OnAPIKeyVerified = hook
	}
}
