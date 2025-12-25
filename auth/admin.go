package auth

import (
	"context"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// AdminUserUpdates contains fields that can be updated by an admin
type AdminUserUpdates struct {
	Name  *string
	Email *string
	Role  *string
}

// ListUsers returns a paginated list of users (requires AdminStore)
func (a *Auth) ListUsers(ctx context.Context, opts models.ListUsersOptions) (*models.ListUsersResult, error) {
	adminStore, ok := a.store.(models.AdminStore)
	if !ok {
		return nil, ErrAdminNotSupported
	}

	// Apply sensible defaults
	if opts.Limit <= 0 {
		opts.Limit = 20
	}
	if opts.Limit > 100 {
		opts.Limit = 100
	}

	return adminStore.ListUsers(ctx, opts)
}

// AdminGetUser retrieves a user by ID (admin operation)
func (a *Auth) AdminGetUser(ctx context.Context, userID string) (*models.User, error) {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// AdminUpdateUser updates a user's information (admin operation)
func (a *Auth) AdminUpdateUser(ctx context.Context, userID string, updates AdminUserUpdates) (*models.User, error) {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	// Apply updates
	if updates.Name != nil {
		user.Name = *updates.Name
	}
	if updates.Email != nil {
		user.Email = *updates.Email
		user.EmailVerified = false // Reset verification on email change
	}
	if updates.Role != nil {
		user.Role = *updates.Role
	}

	if err := a.store.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// AdminDeleteUser deletes a user and all associated data
func (a *Auth) AdminDeleteUser(ctx context.Context, userID string) error {
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Delete all user sessions
	if err := a.store.DeleteSessionsByUserID(ctx, userID); err != nil {
		return err
	}

	// Delete all user accounts
	if err := a.store.DeleteAccountsByUserID(ctx, userID); err != nil {
		return err
	}

	// Delete the user
	return a.store.DeleteUser(ctx, userID)
}

// BanUser bans a user with an optional reason and revokes all sessions
func (a *Auth) BanUser(ctx context.Context, userID, reason string) error {
	adminStore, ok := a.store.(models.AdminStore)
	if !ok {
		return ErrAdminNotSupported
	}

	// Verify user exists
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	// Ban the user
	if err := adminStore.BanUser(ctx, userID, reason); err != nil {
		return err
	}

	// Revoke all sessions
	return a.store.DeleteSessionsByUserID(ctx, userID)
}

// UnbanUser removes a ban from a user
func (a *Auth) UnbanUser(ctx context.Context, userID string) error {
	adminStore, ok := a.store.(models.AdminStore)
	if !ok {
		return ErrAdminNotSupported
	}

	// Verify user exists
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	return adminStore.UnbanUser(ctx, userID)
}

// SetUserRole updates a user's role
func (a *Auth) SetUserRole(ctx context.Context, userID, role string) error {
	adminStore, ok := a.store.(models.AdminStore)
	if !ok {
		return ErrAdminNotSupported
	}

	if role == "" {
		return ErrInvalidRequest
	}

	// Verify user exists
	user, err := a.store.GetUserByID(ctx, userID)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUserNotFound
	}

	return adminStore.SetUserRole(ctx, userID, role)
}
