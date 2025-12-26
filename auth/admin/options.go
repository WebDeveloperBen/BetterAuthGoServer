package admin

import (
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/admin/access"
)

// Config holds the configuration for the admin plugin.
type Config struct {
	// Access control
	AccessControl *access.AccessControl
	Roles         map[string]*access.Role

	// Default role assigned to new users
	DefaultRole string

	// Roles considered admin when not using custom access control
	AdminRoles []string

	// User IDs that are always considered admin
	AdminUserIDs []string

	// Impersonation settings
	ImpersonationSessionDuration time.Duration

	// Ban settings
	DefaultBanReason    string
	DefaultBanExpiresIn time.Duration

	// Messages
	BannedUserMessage string

	// Permissions
	AllowImpersonatingAdmins bool
}

// DefaultConfig returns the default configuration for the admin plugin.
func DefaultConfig() Config {
	return Config{
		DefaultRole:                  "user",
		AdminRoles:                   []string{"admin"},
		AdminUserIDs:                 []string{},
		ImpersonationSessionDuration: 1 * time.Hour,
		DefaultBanReason:             "No reason",
		BannedUserMessage:            "You have been banned from this application. Please contact support if you believe this is an error.",
		AllowImpersonatingAdmins:     false,
	}
}

// Option is a functional option for configuring the admin plugin.
type Option func(*Config)

// WithAccessControl sets the access control system.
func WithAccessControl(ac *access.AccessControl, roles map[string]*access.Role) Option {
	return func(c *Config) {
		c.AccessControl = ac
		c.Roles = roles
	}
}

// WithDefaultRole sets the default role for new users.
func WithDefaultRole(role string) Option {
	return func(c *Config) {
		c.DefaultRole = role
	}
}

// WithAdminRoles sets the roles considered admin.
func WithAdminRoles(roles []string) Option {
	return func(c *Config) {
		c.AdminRoles = roles
	}
}

// WithAdminUserIDs sets user IDs that are always considered admin.
func WithAdminUserIDs(userIDs []string) Option {
	return func(c *Config) {
		c.AdminUserIDs = userIDs
	}
}

// WithImpersonationSessionDuration sets the impersonation session duration.
func WithImpersonationSessionDuration(duration time.Duration) Option {
	return func(c *Config) {
		c.ImpersonationSessionDuration = duration
	}
}

// WithDefaultBanReason sets the default ban reason.
func WithDefaultBanReason(reason string) Option {
	return func(c *Config) {
		c.DefaultBanReason = reason
	}
}

// WithDefaultBanExpiresIn sets the default ban expiration duration.
func WithDefaultBanExpiresIn(duration time.Duration) Option {
	return func(c *Config) {
		c.DefaultBanExpiresIn = duration
	}
}

// WithBannedUserMessage sets the message shown to banned users.
func WithBannedUserMessage(message string) Option {
	return func(c *Config) {
		c.BannedUserMessage = message
	}
}

// WithAllowImpersonatingAdmins sets whether admins can impersonate other admins.
func WithAllowImpersonatingAdmins(allow bool) Option {
	return func(c *Config) {
		c.AllowImpersonatingAdmins = allow
	}
}
