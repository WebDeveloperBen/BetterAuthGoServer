package plugin

import (
	"time"
)

// AuthCore provides plugins access to minimal core auth configuration.
// This interface is intentionally minimal - plugins should define their own
// interfaces for the specific auth operations they need, then type-assert
// to access those operations.
//
// Example:
//
//	type MyAuthProvider interface {
//	    GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)
//	}
//
//	provider, ok := ctx.Auth.(MyAuthProvider)
//	if !ok {
//	    return errors.New("auth doesn't support required operations")
//	}
type AuthCore interface {
	// BaseURL returns the configured base URL of the auth service
	BaseURL() string

	// Secret returns the auth secret key
	Secret() string
}

// CreateUserRequest contains the data needed to create a user from a plugin.
// This is used by OAuth and other plugins that need to create users.
type CreateUserRequest struct {
	Email         string
	Name          string
	EmailVerified bool
	Image         *string
}

// User is a minimal user representation for plugins.
// This avoids plugins depending on the full models package.
type User struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Image         *string
	Role          string
	Banned        bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Session is a minimal session representation for plugins.
type Session struct {
	ID        string
	UserID    string
	IPAddress *string
	UserAgent *string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpired returns true if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
