package anonymous

import (
	"context"
	"time"

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

// GetUserWithAnonymousStatus retrieves a user by ID and includes the is_anonymous status.
// This queries the is_anonymous column that this plugin owns.
func GetUserWithAnonymousStatus(ctx context.Context, store AnonymousStore, userID string) (*User, error) {
	return store.GetUserAnonymousStatus(ctx, userID)
}

// IsUserAnonymous checks if a user has the is_anonymous flag set.
// Returns false if the user doesn't exist or the column doesn't exist.
func IsUserAnonymous(ctx context.Context, store AnonymousStore, userID string) (bool, error) {
	user, err := store.GetUserAnonymousStatus(ctx, userID)
	if err != nil {
		return false, err
	}
	if user == nil {
		return false, nil
	}
	return user.IsAnonymous, nil
}

// FromPluginUser creates a local User from a plugin.User and checks is_anonymous status
func FromPluginUser(ctx context.Context, store AnonymousStore, u *plugin.User) (*User, error) {
	if u == nil {
		return nil, nil
	}

	isAnonymous, err := IsUserAnonymous(ctx, store, u.ID)
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
