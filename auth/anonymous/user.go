package anonymous

import (
	"context"
	"database/sql"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// User is a local representation that includes the is_anonymous field.
// This allows the anonymous plugin to work with the is_anonymous column
// it owns without requiring it to be part of the core user model.
type User struct {
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

// ToPluginUser converts the local User to a plugin.User
func (u *User) ToPluginUser() *plugin.User {
	return &plugin.User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Role:          u.Role,
		Banned:        u.Banned,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}
}

// userRow is a bun-compatible struct for scanning user rows with is_anonymous
type userRow struct {
	bun.BaseModel `bun:"table:users"`

	ID            string    `bun:"id"`
	Email         string    `bun:"email"`
	EmailVerified bool      `bun:"email_verified"`
	Name          string    `bun:"name"`
	Image         *string   `bun:"image"`
	Role          string    `bun:"role"`
	Banned        bool      `bun:"banned"`
	IsAnonymous   bool      `bun:"is_anonymous"`
	CreatedAt     time.Time `bun:"created_at"`
	UpdatedAt     time.Time `bun:"updated_at"`
}

// toUser converts a userRow to our local User type
func (r *userRow) toUser() *User {
	return &User{
		ID:            r.ID,
		Email:         r.Email,
		EmailVerified: r.EmailVerified,
		Name:          r.Name,
		Image:         r.Image,
		Role:          r.Role,
		Banned:        r.Banned,
		IsAnonymous:   r.IsAnonymous,
		CreatedAt:     r.CreatedAt,
		UpdatedAt:     r.UpdatedAt,
	}
}

// GetUserWithAnonymousStatus retrieves a user by ID and includes the is_anonymous status.
// This queries the is_anonymous column that this plugin owns.
func GetUserWithAnonymousStatus(ctx context.Context, db *bun.DB, userID string) (*User, error) {
	row := new(userRow)
	err := db.NewSelect().
		Model(row).
		Where("id = ?", userID).
		Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return row.toUser(), nil
}

// IsUserAnonymous checks if a user has the is_anonymous flag set.
// Returns false if the user doesn't exist or the column doesn't exist.
func IsUserAnonymous(ctx context.Context, db *bun.DB, userID string) (bool, error) {
	var isAnonymous bool
	err := db.NewSelect().
		Table("users").
		Column("is_anonymous").
		Where("id = ?", userID).
		Scan(ctx, &isAnonymous)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return isAnonymous, nil
}

// FromPluginUser creates a local User from a plugin.User and checks is_anonymous status
func FromPluginUser(ctx context.Context, db *bun.DB, u *plugin.User) (*User, error) {
	if u == nil {
		return nil, nil
	}

	isAnonymous, err := IsUserAnonymous(ctx, db, u.ID)
	if err != nil {
		return nil, err
	}

	return &User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Role:          u.Role,
		Banned:        u.Banned,
		IsAnonymous:   isAnonymous,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}, nil
}
