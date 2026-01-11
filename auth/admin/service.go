package admin

import (
	"context"
	"log/slog"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// Service provides admin operations using the database directly.
type Service struct {
	store  AdminStore
	logger *slog.Logger
}

// NewService creates a new admin service.
func NewService(store AdminStore, logger *slog.Logger) *Service {
	return &Service{store: store, logger: logger}
}

// ListUsers returns a paginated list of users.
func (s *Service) ListUsers(ctx context.Context, opts models.ListUsersOptions) (*models.ListUsersResult, error) {
	// Apply sensible defaults
	if opts.Limit <= 0 {
		opts.Limit = 20
	}
	if opts.Limit > 100 {
		opts.Limit = 100
	}

	return s.store.ListUsers(ctx, opts)
}

// GetUser retrieves a user by ID.
func (s *Service) GetUser(ctx context.Context, userID string) (*models.User, error) {
	user, err := s.store.GetUser(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// UpdateUser updates a user's information.
func (s *Service) UpdateUser(ctx context.Context, userID string, updates AdminUserUpdates) (*models.User, error) {
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return nil, err
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
	user.UpdatedAt = time.Now()

	if err := s.store.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// DeleteUser deletes a user and all associated data.
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	// Check user exists
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	// Delete user and associated data
	err = s.store.DeleteUser(ctx, userID)

	if err == nil {
		s.logger.Info("user deleted by admin", "user_id", userID, "email", user.Email)
	}

	return err
}

// BanUser bans a user and revokes all their sessions.
func (s *Service) BanUser(ctx context.Context, userID, reason string) error {
	// Check user exists
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	var banReason *string
	if reason != "" {
		banReason = &reason
	}

	err = s.store.BanUser(ctx, userID, banReason)

	if err == nil {
		s.logger.Info("user banned by admin", "user_id", userID, "email", user.Email, "reason", reason)
	}

	return err
}

// UnbanUser removes a ban from a user.
func (s *Service) UnbanUser(ctx context.Context, userID string) error {
	// Check user exists
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	err = s.store.UnbanUser(ctx, userID)

	if err == nil {
		s.logger.Info("user unbanned by admin", "user_id", userID, "email", user.Email)
	}

	return err
}

// SetUserRole updates a user's role.
func (s *Service) SetUserRole(ctx context.Context, userID, role string) error {
	if role == "" {
		return ErrInvalidRequest
	}

	// Check user exists
	user, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	oldRole := user.Role

	err = s.store.SetUserRole(ctx, userID, role)

	if err == nil {
		s.logger.Info("user role changed by admin", "user_id", userID, "email", user.Email, "old_role", oldRole, "new_role", role)
	}

	return err
}
