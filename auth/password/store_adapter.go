package password

import (
	"context"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// PasswordStore defines the database operations required by the password plugin.
type PasswordStore interface {
	// CreateEmailAccount creates a new email/password account.
	CreateEmailAccount(ctx context.Context, userID, passwordHash string) error
	// GetEmailAccount retrieves the email account for a user.
	GetEmailAccount(ctx context.Context, userID string) (*Account, error)
	// UpdatePassword updates the password hash for a user's email account.
	UpdatePassword(ctx context.Context, userID, passwordHash string) error
	// DeleteUserSessions deletes all sessions for a user.
	DeleteUserSessions(ctx context.Context, userID string) error
}

// StoreAdapter adapts db.PluginStore to PasswordStore.
type StoreAdapter struct {
	store db.PluginStore
}

// NewStoreAdapter creates a new StoreAdapter.
func NewStoreAdapter(store db.PluginStore) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// CreateEmailAccount creates a new email/password account.
func (a *StoreAdapter) CreateEmailAccount(ctx context.Context, userID, passwordHash string) error {
	id := uuid.New().String()
	return a.store.CreatePasswordAccount(ctx, id, userID, passwordHash)
}

// GetEmailAccount retrieves the email account for a user.
func (a *StoreAdapter) GetEmailAccount(ctx context.Context, userID string) (*Account, error) {
	account, err := a.store.GetPasswordAccount(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &Account{
		ID:           account.ID,
		UserID:       account.UserID,
		Provider:     account.Provider,
		PasswordHash: account.PasswordHash,
		CreatedAt:    account.CreatedAt,
		UpdatedAt:    account.UpdatedAt,
	}, nil
}

// UpdatePassword updates the password hash for a user's email account.
func (a *StoreAdapter) UpdatePassword(ctx context.Context, userID, passwordHash string) error {
	return a.store.UpdatePasswordHash(ctx, userID, passwordHash)
}

// DeleteUserSessions deletes all sessions for a user.
func (a *StoreAdapter) DeleteUserSessions(ctx context.Context, userID string) error {
	return a.store.DeleteSessionsByUserID(ctx, userID)
}
