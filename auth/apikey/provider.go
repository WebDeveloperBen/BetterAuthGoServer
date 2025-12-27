package apikey

import (
	"context"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// AuthProvider defines the auth operations required by this plugin.
// The main Auth struct implements this interface.
type AuthProvider interface {
	// GetPluginUser retrieves a user by ID.
	GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)

	// GetUserFromRequest retrieves the current user from a request.
	GetUserFromRequest(r *http.Request) (*plugin.User, error)
}
