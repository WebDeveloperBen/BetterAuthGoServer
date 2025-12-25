package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// User model for Bun
type User struct {
	bun.BaseModel `bun:"table:users,alias:u"`

	ID            string     `bun:"id,pk"`
	Email         string     `bun:"email,notnull,unique"`
	EmailVerified bool       `bun:"email_verified,notnull,default:false"`
	Name          string     `bun:"name,notnull"`
	Image         *string    `bun:"image"`
	Banned        bool       `bun:"banned,notnull,default:false"`
	BannedAt      *time.Time `bun:"banned_at"`
	BanReason     *string    `bun:"ban_reason"`
	Role          string     `bun:"role,notnull,default:'user'"`
	CreatedAt     time.Time  `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt     time.Time  `bun:"updated_at,notnull,default:current_timestamp"`
}

func toAuthUser(u *User) *auth.User {
	if u == nil {
		return nil
	}
	return &auth.User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Banned:        u.Banned,
		BannedAt:      u.BannedAt,
		BanReason:     u.BanReason,
		Role:          u.Role,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

func toBunUser(u *auth.User) *User {
	if u == nil {
		return nil
	}
	return &User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Banned:        u.Banned,
		BannedAt:      u.BannedAt,
		BanReason:     u.BanReason,
		Role:          u.Role,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

func (s *Store) CreateUser(ctx context.Context, user *auth.User) error {
	bunUser := toBunUser(user)
	_, err := s.db.NewInsert().Model(bunUser).Exec(ctx)
	return err
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*auth.User, error) {
	user := new(User)
	err := s.db.NewSelect().Model(user).Where("id = ?", id).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toAuthUser(user), nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	user := new(User)
	err := s.db.NewSelect().Model(user).Where("email = ?", email).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toAuthUser(user), nil
}

func (s *Store) UpdateUser(ctx context.Context, user *auth.User) error {
	bunUser := toBunUser(user)
	_, err := s.db.NewUpdate().Model(bunUser).WherePK().Exec(ctx)
	return err
}

func (s *Store) SetEmailVerified(ctx context.Context, userID string, verified bool) error {
	_, err := s.db.NewUpdate().
		Model((*User)(nil)).
		Set("email_verified = ?", verified).
		Set("updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)
	return err
}

func (s *Store) DeleteUser(ctx context.Context, id string) error {
	_, err := s.db.NewDelete().Model((*User)(nil)).Where("id = ?", id).Exec(ctx)
	return err
}

// AdminStore implementation

// ListUsers returns a paginated list of users
func (s *Store) ListUsers(ctx context.Context, opts auth.ListUsersOptions) (*auth.ListUsersResult, error) {
	var users []User

	query := s.db.NewSelect().Model(&users)

	// Apply search filter
	if opts.Query != "" {
		query = query.Where("email ILIKE ? OR name ILIKE ?", "%"+opts.Query+"%", "%"+opts.Query+"%")
	}

	// Apply role filter
	if opts.Role != "" {
		query = query.Where("role = ?", opts.Role)
	}

	// Get total count
	total, err := query.Count(ctx)
	if err != nil {
		return nil, err
	}

	// Apply pagination
	if opts.Limit > 0 {
		query = query.Limit(opts.Limit)
	} else {
		query = query.Limit(20) // Default limit
	}
	if opts.Offset > 0 {
		query = query.Offset(opts.Offset)
	}

	// Order by created_at desc
	query = query.Order("created_at DESC")

	if err := query.Scan(ctx); err != nil {
		return nil, err
	}

	// Convert to auth users
	authUsers := make([]*auth.User, len(users))
	for i, u := range users {
		authUsers[i] = toAuthUser(&u)
	}

	return &auth.ListUsersResult{
		Users: authUsers,
		Total: int64(total),
	}, nil
}

// BanUser bans a user with an optional reason
func (s *Store) BanUser(ctx context.Context, userID string, reason string) error {
	now := time.Now()
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}

	_, err := s.db.NewUpdate().
		Model((*User)(nil)).
		Set("banned = ?", true).
		Set("banned_at = ?", now).
		Set("ban_reason = ?", reasonPtr).
		Set("updated_at = ?", now).
		Where("id = ?", userID).
		Exec(ctx)
	return err
}

// UnbanUser removes a ban from a user
func (s *Store) UnbanUser(ctx context.Context, userID string) error {
	_, err := s.db.NewUpdate().
		Model((*User)(nil)).
		Set("banned = ?", false).
		Set("banned_at = ?", nil).
		Set("ban_reason = ?", nil).
		Set("updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)
	return err
}

// SetUserRole sets the role for a user
func (s *Store) SetUserRole(ctx context.Context, userID string, role string) error {
	_, err := s.db.NewUpdate().
		Model((*User)(nil)).
		Set("role = ?", role).
		Set("updated_at = ?", time.Now()).
		Where("id = ?", userID).
		Exec(ctx)
	return err
}

// CountUsers returns the total number of users
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	count, err := s.db.NewSelect().Model((*User)(nil)).Count(ctx)
	return int64(count), err
}
