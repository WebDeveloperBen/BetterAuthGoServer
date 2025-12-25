package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// Account model for Bun
type Account struct {
	bun.BaseModel `bun:"table:accounts,alias:a"`

	ID                    string     `bun:"id,pk"`
	UserID                string     `bun:"user_id,notnull"`
	Provider              string     `bun:"provider,notnull"`
	ProviderAccountID     *string    `bun:"provider_account_id"`
	PasswordHash          *string    `bun:"password_hash"`
	AccessToken           *string    `bun:"access_token"`
	RefreshToken          *string    `bun:"refresh_token"`
	AccessTokenExpiresAt  *time.Time `bun:"access_token_expires_at"`
	RefreshTokenExpiresAt *time.Time `bun:"refresh_token_expires_at"`
	CreatedAt             time.Time  `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt             time.Time  `bun:"updated_at,notnull,default:current_timestamp"`

	// Relations
	User *User `bun:"rel:belongs-to,join:user_id=id"`
}

func toAuthAccount(a *Account) *auth.Account {
	if a == nil {
		return nil
	}
	return &auth.Account{
		ID:                    a.ID,
		UserID:                a.UserID,
		Provider:              auth.ProviderType(a.Provider),
		ProviderAccountID:     a.ProviderAccountID,
		PasswordHash:          a.PasswordHash,
		AccessToken:           a.AccessToken,
		RefreshToken:          a.RefreshToken,
		AccessTokenExpiresAt:  a.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: a.RefreshTokenExpiresAt,
		CreatedAt:             a.CreatedAt,
		UpdatedAt:             a.UpdatedAt,
	}
}

func toBunAccount(a *auth.Account) *Account {
	if a == nil {
		return nil
	}
	return &Account{
		ID:                    a.ID,
		UserID:                a.UserID,
		Provider:              string(a.Provider),
		ProviderAccountID:     a.ProviderAccountID,
		PasswordHash:          a.PasswordHash,
		AccessToken:           a.AccessToken,
		RefreshToken:          a.RefreshToken,
		AccessTokenExpiresAt:  a.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: a.RefreshTokenExpiresAt,
		CreatedAt:             a.CreatedAt,
		UpdatedAt:             a.UpdatedAt,
	}
}

func (s *Store) CreateAccount(ctx context.Context, account *auth.Account) error {
	bunAccount := toBunAccount(account)
	_, err := s.db.NewInsert().Model(bunAccount).Exec(ctx)
	return err
}

func (s *Store) GetAccountByID(ctx context.Context, id string) (*auth.Account, error) {
	account := new(Account)
	err := s.db.NewSelect().Model(account).Where("id = ?", id).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toAuthAccount(account), nil
}

func (s *Store) GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider auth.ProviderType) (*auth.Account, error) {
	account := new(Account)
	err := s.db.NewSelect().Model(account).
		Where("user_id = ?", userID).
		Where("provider = ?", string(provider)).
		Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toAuthAccount(account), nil
}

func (s *Store) GetAccountByProvider(ctx context.Context, provider auth.ProviderType, providerAccountID string) (*auth.Account, error) {
	account := new(Account)
	err := s.db.NewSelect().Model(account).
		Where("provider = ?", string(provider)).
		Where("provider_account_id = ?", providerAccountID).
		Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toAuthAccount(account), nil
}

func (s *Store) ListAccountsByUserID(ctx context.Context, userID string) ([]*auth.Account, error) {
	var accounts []Account
	err := s.db.NewSelect().Model(&accounts).Where("user_id = ?", userID).Scan(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]*auth.Account, len(accounts))
	for i := range accounts {
		result[i] = toAuthAccount(&accounts[i])
	}
	return result, nil
}

func (s *Store) UpdateAccount(ctx context.Context, account *auth.Account) error {
	bunAccount := toBunAccount(account)
	bunAccount.UpdatedAt = time.Now()
	_, err := s.db.NewUpdate().Model(bunAccount).WherePK().Exec(ctx)
	return err
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	_, err := s.db.NewDelete().Model((*Account)(nil)).Where("id = ?", id).Exec(ctx)
	return err
}

func (s *Store) DeleteAccountsByUserID(ctx context.Context, userID string) error {
	_, err := s.db.NewDelete().Model((*Account)(nil)).Where("user_id = ?", userID).Exec(ctx)
	return err
}
