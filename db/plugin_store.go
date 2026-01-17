package db

import (
	"context"
	"time"
)

// PluginStore defines the interface that plugins use for database operations.
// This provides a clean abstraction that hides the underlying database implementation.
// Note: Plugin-specific stores (OTP, OAuth, JWT, WebAuthn, APIKey, DeviceAuth, Organization)
// have been migrated to their own packages - each plugin now owns its own store.
type PluginStore interface {
	// Password operations (account and session management)
	PasswordPluginStore

	// Admin operations
	AdminPluginStore

	// Anonymous operations
	AnonymousPluginStore
}

// PasswordPluginStore defines account and session operations for the password plugin.
type PasswordPluginStore interface {
	CreatePasswordAccount(ctx context.Context, id, userID, passwordHash string) error
	GetPasswordAccount(ctx context.Context, userID string) (*PasswordAccount, error)
	UpdatePasswordHash(ctx context.Context, userID, passwordHash string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error
}

// PasswordAccount is a simplified account type for the password plugin.
type PasswordAccount struct {
	ID           string
	UserID       string
	Provider     string
	PasswordHash *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AdminPluginStore defines user management operations for the admin plugin.
type AdminPluginStore interface {
	// AdminListUsers returns a paginated list of users with optional filters.
	AdminListUsers(ctx context.Context, opts AdminListUsersOptions) (*AdminListUsersResult, error)
	// AdminGetUser retrieves a user by ID for admin operations.
	AdminGetUser(ctx context.Context, id string) (*AdminUser, error)
	// AdminUpdateUser updates user fields for admin operations.
	AdminUpdateUser(ctx context.Context, user *AdminUser) error
	// AdminDeleteUser deletes a user and all associated sessions/accounts.
	AdminDeleteUser(ctx context.Context, userID string) error
	// AdminBanUser bans a user and revokes all their sessions.
	AdminBanUser(ctx context.Context, userID string, reason *string) error
	// AdminUnbanUser removes a ban from a user.
	AdminUnbanUser(ctx context.Context, userID string) error
	// AdminSetUserRole updates a user's role.
	AdminSetUserRole(ctx context.Context, userID, role string) error
}

// AdminListUsersOptions defines options for listing users.
type AdminListUsersOptions struct {
	Query  string // Search query for name or email
	Role   string // Filter by role
	Offset int    // Pagination offset
	Limit  int    // Pagination limit
}

// AdminListUsersResult contains the paginated list result.
type AdminListUsersResult struct {
	Users []*AdminUser
	Total int64
}

// AdminUser represents a user for admin operations.
type AdminUser struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Image         *string
	Role          string
	Banned        bool
	BanReason     *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AnonymousPluginStore defines operations for the anonymous plugin.
type AnonymousPluginStore interface {
	// SetAnonymousFlag updates the is_anonymous flag for a user.
	SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error
	// DeleteStaleAnonymousUsers deletes anonymous users older than the given cutoff time.
	DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error)
	// EnsureAnonymousColumn ensures the is_anonymous column exists on the users table.
	EnsureAnonymousColumn(ctx context.Context) error
	// GetUserAnonymousStatus retrieves a user with their anonymous status.
	GetUserAnonymousStatus(ctx context.Context, userID string) (*AnonymousUser, error)
}

// AnonymousUser represents a user with anonymous status.
type AnonymousUser struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Image         *string
	Role          string
	Banned        bool
	IsAnonymous   bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Ensure Store implements PluginStore
var _ PluginStore = (*Store)(nil)
