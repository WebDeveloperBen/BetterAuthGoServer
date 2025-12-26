// Package admin provides admin functionality as a plugin.
package admin

import (
	"context"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// UserProvider defines the auth operations required by the admin middleware.
// The main Auth struct implements this interface.
type UserProvider interface {
	// GetUserFromRequest retrieves the authenticated user from the request context
	GetUserFromRequest(r *http.Request) (*plugin.User, error)
}

// AdminUserUpdates contains fields that can be updated by an admin.
// Pointer fields allow distinguishing between "not provided" and "set to empty".
type AdminUserUpdates struct {
	Name  *string
	Email *string
	Role  *string
}

// ListUsersOptions contains options for listing users.
// Re-exported from models for convenience.
type ListUsersOptions = models.ListUsersOptions

// ListUsersResult contains the result of listing users.
// Re-exported from models for convenience.
type ListUsersResult = models.ListUsersResult

// AdminOperations defines the interface for admin operations.
// This is implemented by the Service type.
type AdminOperations interface {
	// ListUsers returns a paginated list of users
	ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error)

	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, userID string) (*models.User, error)

	// UpdateUser updates a user's information
	UpdateUser(ctx context.Context, userID string, updates AdminUserUpdates) (*models.User, error)

	// DeleteUser deletes a user and all associated data
	DeleteUser(ctx context.Context, userID string) error

	// BanUser bans a user with an optional reason
	BanUser(ctx context.Context, userID, reason string) error

	// UnbanUser removes a ban from a user
	UnbanUser(ctx context.Context, userID string) error

	// SetUserRole updates a user's role
	SetUserRole(ctx context.Context, userID, role string) error
}

// Ensure Service implements AdminOperations
var _ AdminOperations = (*Service)(nil)
