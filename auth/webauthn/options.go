package webauthn

import "time"

// Config holds WebAuthn plugin configuration.
type Config struct {
	RPID                    string
	RPDisplayName           string
	RPOrigins               []string
	AttestationPreference   string
	UserVerification        string
	Timeout                 time.Duration
	AllowResidentKey        bool
	AllowPasswordlessAccounts bool
	AllowSecondFactor       bool
	Debug                   bool
	BaseURL                 string
}

// DefaultConfig returns the default WebAuthn configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:           5 * time.Minute,
		AllowSecondFactor: true,
	}
}

// Option is a functional option for configuring the WebAuthn plugin.
type Option func(*Config)

// WithRPID sets the relying party ID.
func WithRPID(id string) Option {
	return func(c *Config) { c.RPID = id }
}

// WithRPDisplayName sets the relying party display name.
func WithRPDisplayName(name string) Option {
	return func(c *Config) { c.RPDisplayName = name }
}

// WithRPOrigins sets the allowed relying party origins.
func WithRPOrigins(origins []string) Option {
	return func(c *Config) { c.RPOrigins = origins }
}

// WithAttestationPreference sets the attestation preference.
func WithAttestationPreference(preference string) Option {
	return func(c *Config) { c.AttestationPreference = preference }
}

// WithUserVerification sets the user verification requirement.
func WithUserVerification(requirement string) Option {
	return func(c *Config) { c.UserVerification = requirement }
}

// WithTimeout sets the WebAuthn challenge timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Config) { c.Timeout = timeout }
}

// WithAllowResidentKey enables discoverable credentials.
func WithAllowResidentKey(allow bool) Option {
	return func(c *Config) { c.AllowResidentKey = allow }
}

// WithAllowPasswordlessAccounts allows WebAuthn-only account creation.
func WithAllowPasswordlessAccounts(allow bool) Option {
	return func(c *Config) { c.AllowPasswordlessAccounts = allow }
}

// WithAllowSecondFactor allows WebAuthn as an additional login factor.
func WithAllowSecondFactor(allow bool) Option {
	return func(c *Config) { c.AllowSecondFactor = allow }
}

// WithDebug enables debug logging in the WebAuthn library.
func WithDebug(debug bool) Option {
	return func(c *Config) { c.Debug = debug }
}

// WithBaseURL sets the base URL for deriving defaults.
func WithBaseURL(url string) Option {
	return func(c *Config) { c.BaseURL = url }
}
