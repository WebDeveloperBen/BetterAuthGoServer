package models

import (
	"context"
	"time"
)

// Account represents a linked authentication method for a user.
// For email/password auth, PasswordHash is populated.
// For OAuth providers, see the oauth plugin's OAuthAccount type.
type Account struct {
	ID                string
	UserID            string
	Provider          ProviderType
	ProviderAccountID *string
	PasswordHash      *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// AccountStore defines account-related database operations
type AccountStore interface {
	CreateAccount(ctx context.Context, account *Account) error
	GetAccountByID(ctx context.Context, id string) (*Account, error)
	GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider ProviderType) (*Account, error)
	GetAccountByProvider(ctx context.Context, provider ProviderType, providerAccountID string) (*Account, error)
	ListAccountsByUserID(ctx context.Context, userID string) ([]*Account, error)
	UpdateAccount(ctx context.Context, account *Account) error
	DeleteAccount(ctx context.Context, id string) error
	DeleteAccountsByUserID(ctx context.Context, userID string) error
}
