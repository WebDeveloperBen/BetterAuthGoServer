package admin

import (
	"context"
	"errors"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// Common errors
var (
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidRequest     = errors.New("invalid request")
	ErrAdminNotSupported  = errors.New("admin operations not supported by store")
)

// Service provides admin operations using the database directly.
type Service struct {
	db *bun.DB
}

// NewService creates a new admin service.
func NewService(db *bun.DB) *Service {
	return &Service{db: db}
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

	query := s.db.NewSelect().Model((*models.User)(nil))

	// Apply filters
	if opts.Query != "" {
		query = query.Where("name LIKE ? OR email LIKE ?", "%"+opts.Query+"%", "%"+opts.Query+"%")
	}
	if opts.Role != "" {
		query = query.Where("role = ?", opts.Role)
	}

	// Get total count
	total, err := query.Count(ctx)
	if err != nil {
		return nil, err
	}

	// Get paginated results
	var users []*models.User
	err = query.
		Order("created_at DESC").
		Offset(opts.Offset).
		Limit(opts.Limit).
		Scan(ctx, &users)
	if err != nil {
		return nil, err
	}

	return &models.ListUsersResult{
		Users: users,
		Total: int64(total),
	}, nil
}

// GetUser retrieves a user by ID.
func (s *Service) GetUser(ctx context.Context, userID string) (*models.User, error) {
	user := new(models.User)
	err := s.db.NewSelect().
		Model(user).
		Where("id = ?", userID).
		Scan(ctx)
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

	_, err = s.db.NewUpdate().
		Model(user).
		WherePK().
		Exec(ctx)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// DeleteUser deletes a user and all associated data.
func (s *Service) DeleteUser(ctx context.Context, userID string) error {
	// Check user exists
	_, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	// Delete in transaction
	return s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Delete sessions
		_, err := tx.NewDelete().
			Model((*models.Session)(nil)).
			Where("user_id = ?", userID).
			Exec(ctx)
		if err != nil {
			return err
		}

		// Delete accounts
		_, err = tx.NewDelete().
			Model((*models.Account)(nil)).
			Where("user_id = ?", userID).
			Exec(ctx)
		if err != nil {
			return err
		}

		// Delete user
		_, err = tx.NewDelete().
			Model((*models.User)(nil)).
			Where("id = ?", userID).
			Exec(ctx)
		return err
	})
}

// BanUser bans a user and revokes all their sessions.
func (s *Service) BanUser(ctx context.Context, userID, reason string) error {
	// Check user exists
	_, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	return s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		// Update user ban status
		var banReason *string
		if reason != "" {
			banReason = &reason
		}

		_, err := tx.NewUpdate().
			Model((*models.User)(nil)).
			Set("banned = ?", true).
			Set("ban_reason = ?", banReason).
			Set("updated_at = ?", time.Now()).
			Where("id = ?", userID).
			Exec(ctx)
		if err != nil {
			return err
		}

		// Revoke all sessions
		_, err = tx.NewDelete().
			Model((*models.Session)(nil)).
			Where("user_id = ?", userID).
			Exec(ctx)
		return err
	})
}

// UnbanUser removes a ban from a user.
func (s *Service) UnbanUser(ctx context.Context, userID string) error {
	// Check user exists
	_, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	_, err = s.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("banned = ?", false).
		Set("ban_reason = ?", nil).
		Set("updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)
	return err
}

// SetUserRole updates a user's role.
func (s *Service) SetUserRole(ctx context.Context, userID, role string) error {
	if role == "" {
		return ErrInvalidRequest
	}

	// Check user exists
	_, err := s.GetUser(ctx, userID)
	if err != nil {
		return err
	}

	_, err = s.db.NewUpdate().
		Model((*models.User)(nil)).
		Set("role = ?", role).
		Set("updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)
	return err
}
