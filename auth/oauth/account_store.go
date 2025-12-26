// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

// AccountStore provides database operations for OAuth accounts.
// User operations are handled through plugin.AuthCore interface.
// This store only manages OAuth-specific account linking and token storage.
type AccountStore struct {
	db *bun.DB
}

// NewAccountStore creates a new account store with database access
func NewAccountStore(db *bun.DB) *AccountStore {
	return &AccountStore{db: db}
}

// ensureTable creates the oauth_accounts table if it doesn't exist
func (s *AccountStore) ensureTable(ctx context.Context) error {
	_, err := s.db.NewCreateTable().
		Model((*OAuthAccount)(nil)).
		IfNotExists().
		Exec(ctx)
	return err
}

// OAuthAccount represents an OAuth account in the database.
// This links a user to an OAuth provider and stores their tokens.
type OAuthAccount struct {
	bun.BaseModel `bun:"table:oauth_accounts,alias:oa"`

	ID                   string     `bun:"id,pk"`
	UserID               string     `bun:"user_id,notnull"`
	Provider             string     `bun:"provider,notnull"`
	ProviderAccountID    string     `bun:"provider_account_id,notnull"`
	AccessToken          string     `bun:"access_token"`
	RefreshToken         string     `bun:"refresh_token"`
	AccessTokenExpiresAt *time.Time `bun:"access_token_expires_at"`
	CreatedAt            time.Time  `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt            time.Time  `bun:"updated_at,notnull,default:current_timestamp"`
}

// TableName returns the table name
func (o *OAuthAccount) TableName() string {
	return "oauth_accounts"
}

// CreateAccount creates a new OAuth account
func (s *AccountStore) CreateAccount(ctx context.Context, account *OAuthAccount) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}

	now := time.Now()
	account.CreatedAt = now
	account.UpdatedAt = now

	_, err := s.db.NewInsert().Model(account).Exec(ctx)
	return err
}

// GetAccountByProvider finds an OAuth account by provider and provider account ID
func (s *AccountStore) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*OAuthAccount, error) {
	if err := s.ensureTable(ctx); err != nil {
		return nil, err
	}

	account := &OAuthAccount{}
	err := s.db.NewSelect().
		Model(account).
		Where("provider = ? AND provider_account_id = ?", provider, providerAccountID).
		Scan(ctx)
	if err != nil {
		return nil, err
	}
	return account, nil
}

// UpdateAccount updates an OAuth account
func (s *AccountStore) UpdateAccount(ctx context.Context, account *OAuthAccount) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}

	account.UpdatedAt = time.Now()

	_, err := s.db.NewUpdate().
		Model(account).
		Where("id = ?", account.ID).
		Exec(ctx)
	return err
}
