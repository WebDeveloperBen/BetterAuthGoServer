package store

import (
	"context"
	"database/sql"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// Account model for Bun.
// For email/password auth, PasswordHash is populated.
// For OAuth providers, see the oauth plugin's OAuthAccount type.
type Account struct {
	bun.BaseModel `bun:"table:accounts,alias:a"`

	ID                string    `bun:"id,pk"`
	UserID            string    `bun:"user_id,notnull"`
	Provider          string    `bun:"provider,notnull"`
	ProviderAccountID *string   `bun:"provider_account_id"`
	PasswordHash      *string   `bun:"password_hash"`
	CreatedAt         time.Time `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt         time.Time `bun:"updated_at,notnull,default:current_timestamp"`

	// Relations
	User *User `bun:"rel:belongs-to,join:user_id=id"`
}

func toModelsAccount(a *Account) *models.Account {
	if a == nil {
		return nil
	}
	return &models.Account{
		ID:                a.ID,
		UserID:            a.UserID,
		Provider:          models.ProviderType(a.Provider),
		ProviderAccountID: a.ProviderAccountID,
		PasswordHash:      a.PasswordHash,
		CreatedAt:         a.CreatedAt,
		UpdatedAt:         a.UpdatedAt,
	}
}

func toBunAccount(a *models.Account) *Account {
	if a == nil {
		return nil
	}
	return &Account{
		ID:                a.ID,
		UserID:            a.UserID,
		Provider:          string(a.Provider),
		ProviderAccountID: a.ProviderAccountID,
		PasswordHash:      a.PasswordHash,
		CreatedAt:         a.CreatedAt,
		UpdatedAt:         a.UpdatedAt,
	}
}

func (s *Store) CreateAccount(ctx context.Context, account *models.Account) error {
	bunAccount := toBunAccount(account)
	_, err := s.db.NewInsert().Model(bunAccount).Exec(ctx)
	return err
}

func (s *Store) GetAccountByID(ctx context.Context, id string) (*models.Account, error) {
	account := new(Account)
	err := s.db.NewSelect().Model(account).Where("id = ?", id).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toModelsAccount(account), nil
}

func (s *Store) GetAccountByUserIDAndProvider(ctx context.Context, userID string, provider models.ProviderType) (*models.Account, error) {
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
	return toModelsAccount(account), nil
}

func (s *Store) GetAccountByProvider(ctx context.Context, provider models.ProviderType, providerAccountID string) (*models.Account, error) {
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
	return toModelsAccount(account), nil
}

func (s *Store) ListAccountsByUserID(ctx context.Context, userID string) ([]*models.Account, error) {
	var accounts []Account
	err := s.db.NewSelect().Model(&accounts).Where("user_id = ?", userID).Scan(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]*models.Account, len(accounts))
	for i := range accounts {
		result[i] = toModelsAccount(&accounts[i])
	}
	return result, nil
}

func (s *Store) UpdateAccount(ctx context.Context, account *models.Account) error {
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
