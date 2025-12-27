package anonymous

import (
	"context"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// AuthProvider defines the auth operations required by this plugin.
// The main Auth struct implements this interface.
type AuthProvider interface {
	// GetPluginUser retrieves a user by ID
	GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)

	// GetPluginUserByEmail retrieves a user by email
	GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error)

	// CreatePluginUser creates a new user
	CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error)

	// CreateSessionForUser creates a new session for the given user
	CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error)

	// DeleteUser deletes a user by ID
	DeleteUser(ctx context.Context, userID string) error

	// GetUserFromRequest gets the current user from the request context
	GetUserFromRequest(r *http.Request) (*plugin.User, error)
}
