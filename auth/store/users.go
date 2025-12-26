package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
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

func toModelsUser(u *User) *models.User {
	if u == nil {
		return nil
	}
	return &models.User{
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

func toBunUser(u *models.User) *User {
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

func (s *Store) CreateUser(ctx context.Context, user *models.User) error {
	bunUser := toBunUser(user)
	_, err := s.db.NewInsert().Model(bunUser).Exec(ctx)
	return err
}

func (s *Store) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	user := new(User)
	err := s.db.NewSelect().Model(user).Where("id = ?", id).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toModelsUser(user), nil
}

func (s *Store) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	user := new(User)
	err := s.db.NewSelect().Model(user).Where("email = ?", email).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toModelsUser(user), nil
}

func (s *Store) UpdateUser(ctx context.Context, user *models.User) error {
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
