package deviceauth

import (
	"context"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// AuthProvider defines the auth operations required by the device authorization plugin.
// The main Auth struct implements this interface.
type AuthProvider interface {
	// GetPluginUser retrieves a user by ID.
	GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)

	// CreateSessionForUser creates a new session for the given user.
	// Used when a device code is approved and the device polls for a token.
	CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error)

	// GetUserFromRequest gets the current authenticated user from the request.
	// Used to identify who is approving/denying a device authorization.
	GetUserFromRequest(r *http.Request) (*plugin.User, error)
}
