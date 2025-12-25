package plugin

import (
	"context"
	"net/http"
	"time"
)

// AuthCore provides plugins access to core authentication operations.
// This interface breaks the circular dependency between auth and plugin packages.
// The main Auth struct implements this interface.
//
// Method names are prefixed with "Plugin" or use distinct names to avoid
// conflicts with the main Auth methods that return different types.
type AuthCore interface {
	// User operations (return plugin-specific User type)
	GetPluginUser(ctx context.Context, userID string) (*User, error)
	GetPluginUserByEmail(ctx context.Context, email string) (*User, error)

	// Session operations
	ValidateSessionToken(ctx context.Context, token string) (*Session, error)
	CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*Session, error)

	// Password operations
	VerifyPassword(ctx context.Context, userID string, password string) (bool, error)

	// Config access
	BaseURL() string
	Secret() string
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
