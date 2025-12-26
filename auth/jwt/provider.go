package jwt

import (
	"context"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// AuthProvider defines the auth operations required by the JWT plugin.
// The main Auth struct implements this interface.
type AuthProvider interface {
	// GetPluginUser retrieves a user by ID
	GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)

	// GetPluginUserByEmail retrieves a user by email
	GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error)

	// VerifyPassword verifies a user's password
	VerifyPassword(ctx context.Context, userID string, password string) (bool, error)

	// CreateSessionForUser creates a new session for the given user
	CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error)
}
