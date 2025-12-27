package deviceauth

import (
	"context"
	"time"
)

// Config holds the configuration for the device authorization plugin.
type Config struct {
	// VerificationURI is the URL where users enter device codes.
	// Default: "{BaseURL}/device"
	VerificationURI string

	// ExpiresIn is how long device codes are valid.
	// Default: 30 minutes
	ExpiresIn time.Duration

	// PollingInterval is the minimum seconds between token polls.
	// Default: 5 seconds
	PollingInterval int

	// UserCodeLength is the length of user-facing codes (before hyphen insertion).
	// Default: 8 characters (results in "XXXX-XXXX")
	UserCodeLength int

	// DeviceCodeLength is the length of device codes.
	// Default: 40 characters
	DeviceCodeLength int

	// GenerateDeviceCode is a custom function for device code generation.
	// If nil, uses secure random alphanumeric generation.
	GenerateDeviceCode func() string

	// GenerateUserCode is a custom function for user code generation.
	// If nil, uses secure random with user-friendly charset (no 0/O, 1/I/L).
	GenerateUserCode func() string

	// ValidateClient validates the client_id parameter.
	// If nil, accepts any client_id.
	ValidateClient func(ctx context.Context, clientID string) error

	// OnDeviceAuthRequest is called when a device requests authorization.
	// Can be used for logging, rate limiting, or custom validation.
	OnDeviceAuthRequest func(ctx context.Context, deviceCode *DeviceCode) error

	// CleanupInterval is how often to run expired code cleanup.
	// Default: 5 minutes
	CleanupInterval time.Duration
}

// DefaultConfig returns the default configuration.
func DefaultConfig() Config {
	return Config{
		ExpiresIn:        30 * time.Minute,
		PollingInterval:  5,
		UserCodeLength:   8,
		DeviceCodeLength: 40,
		CleanupInterval:  5 * time.Minute,
	}
}

// Option is a functional option for configuring the plugin.
type Option func(*Config)

// WithVerificationURI sets the URL where users enter device codes.
func WithVerificationURI(uri string) Option {
	return func(c *Config) {
		c.VerificationURI = uri
	}
}

// WithExpiresIn sets how long device codes are valid.
func WithExpiresIn(d time.Duration) Option {
	return func(c *Config) {
		c.ExpiresIn = d
	}
}

// WithPollingInterval sets the minimum seconds between token polls.
func WithPollingInterval(seconds int) Option {
	return func(c *Config) {
		c.PollingInterval = seconds
	}
}

// WithUserCodeLength sets the length of user-facing codes.
func WithUserCodeLength(length int) Option {
	return func(c *Config) {
		c.UserCodeLength = length
	}
}

// WithDeviceCodeLength sets the length of device codes.
func WithDeviceCodeLength(length int) Option {
	return func(c *Config) {
		c.DeviceCodeLength = length
	}
}

// WithGenerateDeviceCode sets a custom device code generation function.
func WithGenerateDeviceCode(fn func() string) Option {
	return func(c *Config) {
		c.GenerateDeviceCode = fn
	}
}

// WithGenerateUserCode sets a custom user code generation function.
func WithGenerateUserCode(fn func() string) Option {
	return func(c *Config) {
		c.GenerateUserCode = fn
	}
}

// WithValidateClient sets a function to validate client_id.
func WithValidateClient(fn func(ctx context.Context, clientID string) error) Option {
	return func(c *Config) {
		c.ValidateClient = fn
	}
}

// WithOnDeviceAuthRequest sets a callback for device authorization requests.
func WithOnDeviceAuthRequest(fn func(ctx context.Context, deviceCode *DeviceCode) error) Option {
	return func(c *Config) {
		c.OnDeviceAuthRequest = fn
	}
}

// WithCleanupInterval sets how often to run expired code cleanup.
func WithCleanupInterval(d time.Duration) Option {
	return func(c *Config) {
		c.CleanupInterval = d
	}
}
