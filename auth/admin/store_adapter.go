package admin

import (
	"context"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// AdminStore defines the database operations required by the admin plugin.
type AdminStore interface {
	// ListUsers returns a paginated list of users with optional filters.
	ListUsers(ctx context.Context, opts models.ListUsersOptions) (*models.ListUsersResult, error)
	// GetUser retrieves a user by ID.
	GetUser(ctx context.Context, userID string) (*models.User, error)
	// UpdateUser updates a user's information.
	UpdateUser(ctx context.Context, user *models.User) error
	// DeleteUser deletes a user and all associated data.
	DeleteUser(ctx context.Context, userID string) error
	// BanUser bans a user and revokes all their sessions.
	BanUser(ctx context.Context, userID string, reason *string) error
	// UnbanUser removes a ban from a user.
	UnbanUser(ctx context.Context, userID string) error
	// SetUserRole updates a user's role.
	SetUserRole(ctx context.Context, userID, role string) error
}

// StoreAdapter adapts db.PluginStore to AdminStore.
type StoreAdapter struct {
	store db.PluginStore
}

// NewStoreAdapter creates a new StoreAdapter.
func NewStoreAdapter(store db.PluginStore) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// ListUsers returns a paginated list of users with optional filters.
func (a *StoreAdapter) ListUsers(ctx context.Context, opts models.ListUsersOptions) (*models.ListUsersResult, error) {
	result, err := a.store.AdminListUsers(ctx, db.AdminListUsersOptions{
		Query:  opts.Query,
		Role:   opts.Role,
		Offset: opts.Offset,
		Limit:  opts.Limit,
	})
	if err != nil {
		return nil, err
	}

	users := make([]*models.User, len(result.Users))
	for i, u := range result.Users {
		users[i] = a.toModelsUser(u)
	}

	return &models.ListUsersResult{
		Users: users,
		Total: result.Total,
	}, nil
}

// GetUser retrieves a user by ID.
func (a *StoreAdapter) GetUser(ctx context.Context, userID string) (*models.User, error) {
	u, err := a.store.AdminGetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	return a.toModelsUser(u), nil
}

// UpdateUser updates a user's information.
func (a *StoreAdapter) UpdateUser(ctx context.Context, user *models.User) error {
	return a.store.AdminUpdateUser(ctx, a.toDBUser(user))
}

// DeleteUser deletes a user and all associated data.
func (a *StoreAdapter) DeleteUser(ctx context.Context, userID string) error {
	return a.store.AdminDeleteUser(ctx, userID)
}

// BanUser bans a user and revokes all their sessions.
func (a *StoreAdapter) BanUser(ctx context.Context, userID string, reason *string) error {
	return a.store.AdminBanUser(ctx, userID, reason)
}

// UnbanUser removes a ban from a user.
func (a *StoreAdapter) UnbanUser(ctx context.Context, userID string) error {
	return a.store.AdminUnbanUser(ctx, userID)
}

// SetUserRole updates a user's role.
func (a *StoreAdapter) SetUserRole(ctx context.Context, userID, role string) error {
	return a.store.AdminSetUserRole(ctx, userID, role)
}

// toModelsUser converts a db.AdminUser to a models.User.
func (a *StoreAdapter) toModelsUser(u *db.AdminUser) *models.User {
	return &models.User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Role:          u.Role,
		Banned:        u.Banned,
		BanReason:     u.BanReason,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

// toDBUser converts a models.User to a db.AdminUser.
func (a *StoreAdapter) toDBUser(user *models.User) *db.AdminUser {
	return &db.AdminUser{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.Name,
		Image:         user.Image,
		Role:          user.Role,
		Banned:        user.Banned,
		BanReason:     user.BanReason,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     time.Now(),
	}
}
