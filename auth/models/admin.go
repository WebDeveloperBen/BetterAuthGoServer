package models

import "context"

// ListUsersOptions contains options for listing users
type ListUsersOptions struct {
	Offset int
	Limit  int
	Query  string // Optional search query
	Role   string // Filter by role
}

// ListUsersResult contains the result of listing users
type ListUsersResult struct {
	Users []*User
	Total int64
}

// AdminStore defines admin-related database operations.
// This interface is optional - stores can implement it to enable admin features.
type AdminStore interface {
	// ListUsers returns a paginated list of users
	ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error)

	// BanUser bans a user with an optional reason
	BanUser(ctx context.Context, userID string, reason string) error

	// UnbanUser removes a ban from a user
	UnbanUser(ctx context.Context, userID string) error

	// SetUserRole sets the role for a user
	SetUserRole(ctx context.Context, userID string, role string) error

	// CountUsers returns the total number of users
	CountUsers(ctx context.Context) (int64, error)
}
