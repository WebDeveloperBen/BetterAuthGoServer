package password

import (
	"context"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// AuthProvider defines the auth operations required by the password plugin.
// The main Auth struct implements this interface.
type AuthProvider interface {
	// GetPluginUserByEmail retrieves a user by email
	GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error)

	// CreatePluginUser creates a new user
	CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error)

	// CreateSessionForUser creates a new session for the given user
	CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error)

	// VerifyPassword verifies a user's password (used for sign-in)
	VerifyPassword(ctx context.Context, userID string, password string) (bool, error)

	// BaseURL returns the base URL configured for the auth service
	BaseURL() string
}

// PasswordResetTokenProvider is an alias for the plugin interface.
// This allows the password plugin to work with any plugin that provides password reset tokens.
type PasswordResetTokenProvider = plugin.PasswordResetTokenProvider

// SessionCookieSetter is an interface for setting session cookies.
// The main Auth struct implements this.
type SessionCookieSetter interface {
	SetPluginSessionCookie(w http.ResponseWriter, session *plugin.Session)
	ClearSessionCookie(w http.ResponseWriter)
}

// SessionGetter is an interface for retrieving the session from request context.
// The main Auth struct implements this via SessionFromContext.
type SessionGetter interface {
	GetSessionFromRequest(r *http.Request) *plugin.SessionInfo
}
