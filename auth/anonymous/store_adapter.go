package anonymous

import (
	"context"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// AnonymousStore defines the database operations required by the anonymous plugin.
type AnonymousStore interface {
	// SetAnonymousFlag updates the is_anonymous flag for a user.
	SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error
	// DeleteStaleAnonymousUsers deletes anonymous users older than the given cutoff time.
	DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error)
	// EnsureAnonymousColumn ensures the is_anonymous column exists on the users table.
	EnsureAnonymousColumn(ctx context.Context) error
	// GetUserAnonymousStatus retrieves a user with their anonymous status.
	GetUserAnonymousStatus(ctx context.Context, userID string) (*User, error)
}

// StoreAdapter adapts db.PluginStore to AnonymousStore.
type StoreAdapter struct {
	store db.PluginStore
}

// NewStoreAdapter creates a new StoreAdapter.
func NewStoreAdapter(store db.PluginStore) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// SetAnonymousFlag updates the is_anonymous flag for a user.
func (a *StoreAdapter) SetAnonymousFlag(ctx context.Context, userID string, isAnonymous bool) error {
	return a.store.SetAnonymousFlag(ctx, userID, isAnonymous)
}

// DeleteStaleAnonymousUsers deletes anonymous users older than the given cutoff time.
func (a *StoreAdapter) DeleteStaleAnonymousUsers(ctx context.Context, cutoff time.Time) (int64, error) {
	return a.store.DeleteStaleAnonymousUsers(ctx, cutoff)
}

// EnsureAnonymousColumn ensures the is_anonymous column exists on the users table.
func (a *StoreAdapter) EnsureAnonymousColumn(ctx context.Context) error {
	return a.store.EnsureAnonymousColumn(ctx)
}

// GetUserAnonymousStatus retrieves a user with their anonymous status.
func (a *StoreAdapter) GetUserAnonymousStatus(ctx context.Context, userID string) (*User, error) {
	u, err := a.store.GetUserAnonymousStatus(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, nil
	}
	return &User{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Role:          u.Role,
		Banned:        u.Banned,
		IsAnonymous:   u.IsAnonymous,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
	}, nil
}
