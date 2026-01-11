// Package db provides the OAuth plugin's database operations using sqlc-generated queries.
// This package is owned by the OAuth plugin and handles its own persistence.
package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Store handles OAuth persistence.
// The plugin owns this implementation.
type Store struct {
	dialect coredb.Dialect
	pgQ     *pgstore.Queries
	sqliteQ *sqlitestore.Queries
	mysqlQ  *mysqlstore.Queries
}

// New creates a new OAuth store.
func New(db coredb.DBTX, dialect coredb.Dialect) *Store {
	s := &Store{dialect: dialect}
	switch dialect {
	case coredb.DialectPostgres:
		s.pgQ = pgstore.New(db)
	case coredb.DialectMySQL:
		s.mysqlQ = mysqlstore.New(db)
	default:
		s.sqliteQ = sqlitestore.New(db)
	}
	return s
}

// =============================================================================
// OAuthState domain types
// =============================================================================

// State represents an OAuth state record.
type State struct {
	State      string
	Provider   string
	Verifier   *string
	RedirectTo *string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// Account represents an OAuth account linked to a user.
type Account struct {
	ID                   string
	UserID               string
	Provider             string
	ProviderAccountID    string
	AccessToken          string
	RefreshToken         string
	AccessTokenExpiresAt *time.Time
	CreatedAt            time.Time
	UpdatedAt            time.Time
}

// =============================================================================
// State Store Methods
// =============================================================================

// CreateOAuthState creates a new OAuth state record.
func (s *Store) CreateOAuthState(ctx context.Context, state *State) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateOAuthState(ctx, pgstore.CreateOAuthStateParams{
			State:      state.State,
			Provider:   state.Provider,
			Verifier:   toNullString(state.Verifier),
			RedirectTo: toNullString(state.RedirectTo),
			CreatedAt:  state.CreatedAt,
			ExpiresAt:  state.ExpiresAt,
		})
	}
	if s.dialect == coredb.DialectMySQL {
		return s.mysqlQ.CreateOAuthState(ctx, mysqlstore.CreateOAuthStateParams{
			State:      state.State,
			Provider:   state.Provider,
			Verifier:   toNullString(state.Verifier),
			RedirectTo: toNullString(state.RedirectTo),
			CreatedAt:  state.CreatedAt,
			ExpiresAt:  state.ExpiresAt,
		})
	}
	return s.sqliteQ.CreateOAuthState(ctx, sqlitestore.CreateOAuthStateParams{
		State:      state.State,
		Provider:   state.Provider,
		Verifier:   toNullString(state.Verifier),
		RedirectTo: toNullString(state.RedirectTo),
		CreatedAt:  state.CreatedAt.Format(time.RFC3339),
		ExpiresAt:  state.ExpiresAt.Format(time.RFC3339),
	})
}

// GetOAuthState retrieves an OAuth state record by state value.
func (s *Store) GetOAuthState(ctx context.Context, stateValue string) (*State, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetOAuthState(ctx, stateValue)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return &State{
			State:      row.State,
			Provider:   row.Provider,
			Verifier:   fromNullString(row.Verifier),
			RedirectTo: fromNullString(row.RedirectTo),
			CreatedAt:  row.CreatedAt,
			ExpiresAt:  row.ExpiresAt,
		}, nil
	}
	if s.dialect == coredb.DialectMySQL {
		row, err := s.mysqlQ.GetOAuthState(ctx, stateValue)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return &State{
			State:      row.State,
			Provider:   row.Provider,
			Verifier:   fromNullString(row.Verifier),
			RedirectTo: fromNullString(row.RedirectTo),
			CreatedAt:  row.CreatedAt,
			ExpiresAt:  row.ExpiresAt,
		}, nil
	}

	row, err := s.sqliteQ.GetOAuthState(ctx, stateValue)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, row.CreatedAt)
	expiresAt, _ := time.Parse(time.RFC3339, row.ExpiresAt)

	return &State{
		State:      row.State,
		Provider:   row.Provider,
		Verifier:   fromNullString(row.Verifier),
		RedirectTo: fromNullString(row.RedirectTo),
		CreatedAt:  createdAt,
		ExpiresAt:  expiresAt,
	}, nil
}

// DeleteOAuthState deletes an OAuth state record.
func (s *Store) DeleteOAuthState(ctx context.Context, stateValue string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteOAuthState(ctx, stateValue)
	}
	if s.dialect == coredb.DialectMySQL {
		return s.mysqlQ.DeleteOAuthState(ctx, stateValue)
	}
	return s.sqliteQ.DeleteOAuthState(ctx, stateValue)
}

// DeleteExpiredOAuthStates deletes all expired OAuth state records.
func (s *Store) DeleteExpiredOAuthStates(ctx context.Context) error {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteExpiredOAuthStates(ctx, now)
	}
	if s.dialect == coredb.DialectMySQL {
		return s.mysqlQ.DeleteExpiredOAuthStates(ctx, now)
	}
	return s.sqliteQ.DeleteExpiredOAuthStates(ctx, now.Format(time.RFC3339))
}

// =============================================================================
// Account Store Methods
// =============================================================================

// CreateAccount creates a new OAuth account.
func (s *Store) CreateAccount(ctx context.Context, account *Account) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateOAuthAccount(ctx, pgstore.CreateOAuthAccountParams{
			ID:                   account.ID,
			UserID:               account.UserID,
			Provider:             account.Provider,
			ProviderAccountID:    account.ProviderAccountID,
			AccessToken:          toNullString(&account.AccessToken),
			RefreshToken:         toNullString(&account.RefreshToken),
			AccessTokenExpiresAt: toNullTime(account.AccessTokenExpiresAt),
			CreatedAt:            account.CreatedAt,
			UpdatedAt:            account.UpdatedAt,
		})
	}
	if s.dialect == coredb.DialectMySQL {
		return s.mysqlQ.CreateOAuthAccount(ctx, mysqlstore.CreateOAuthAccountParams{
			ID:                   account.ID,
			UserID:               account.UserID,
			Provider:             account.Provider,
			ProviderAccountID:    account.ProviderAccountID,
			AccessToken:          toNullString(&account.AccessToken),
			RefreshToken:         toNullString(&account.RefreshToken),
			AccessTokenExpiresAt: toNullTime(account.AccessTokenExpiresAt),
			CreatedAt:            account.CreatedAt,
			UpdatedAt:            account.UpdatedAt,
		})
	}
	return s.sqliteQ.CreateOAuthAccount(ctx, sqlitestore.CreateOAuthAccountParams{
		ID:                   account.ID,
		UserID:               account.UserID,
		Provider:             account.Provider,
		ProviderAccountID:    account.ProviderAccountID,
		AccessToken:          toNullString(&account.AccessToken),
		RefreshToken:         toNullString(&account.RefreshToken),
		AccessTokenExpiresAt: toNullStringFromTime(account.AccessTokenExpiresAt),
		CreatedAt:            account.CreatedAt.Format(time.RFC3339),
		UpdatedAt:            account.UpdatedAt.Format(time.RFC3339),
	})
}

// GetAccountByProvider finds an OAuth account by provider and provider account ID.
func (s *Store) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetOAuthAccountByProvider(ctx, pgstore.GetOAuthAccountByProviderParams{
			Provider:          provider,
			ProviderAccountID: providerAccountID,
		})
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgAccountToLocal(&row), nil
	}

	row, err := s.sqliteQ.GetOAuthAccountByProvider(ctx, sqlitestore.GetOAuthAccountByProviderParams{
		Provider:          provider,
		ProviderAccountID: providerAccountID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteAccountToLocal(&row), nil
}

// GetAccountsByUserID finds all OAuth accounts for a user.
func (s *Store) GetAccountsByUserID(ctx context.Context, userID string) ([]*Account, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.GetOAuthAccountsByUserID(ctx, userID)
		if err != nil {
			return nil, err
		}
		accounts := make([]*Account, len(rows))
		for i := range rows {
			accounts[i] = pgAccountToLocal(&rows[i])
		}
		return accounts, nil
	}

	rows, err := s.sqliteQ.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	accounts := make([]*Account, len(rows))
	for i := range rows {
		accounts[i] = sqliteAccountToLocal(&rows[i])
	}
	return accounts, nil
}

// UpdateAccount updates an OAuth account.
func (s *Store) UpdateAccount(ctx context.Context, account *Account) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateOAuthAccount(ctx, pgstore.UpdateOAuthAccountParams{
			ID:                   account.ID,
			AccessToken:          toNullString(&account.AccessToken),
			RefreshToken:         toNullString(&account.RefreshToken),
			AccessTokenExpiresAt: toNullTime(account.AccessTokenExpiresAt),
			UpdatedAt:            account.UpdatedAt,
		})
	}
	return s.sqliteQ.UpdateOAuthAccount(ctx, sqlitestore.UpdateOAuthAccountParams{
		ID:                   account.ID,
		AccessToken:          toNullString(&account.AccessToken),
		RefreshToken:         toNullString(&account.RefreshToken),
		AccessTokenExpiresAt: toNullStringFromTime(account.AccessTokenExpiresAt),
		UpdatedAt:            account.UpdatedAt.Format(time.RFC3339),
	})
}

// DeleteAccount deletes an OAuth account.
func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteOAuthAccount(ctx, id)
	}
	return s.sqliteQ.DeleteOAuthAccount(ctx, id)
}

// =============================================================================
// Conversion helpers
// =============================================================================

func toNullString(s *string) sql.NullString {
	if s == nil || *s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: *s, Valid: true}
}

func fromNullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

func toNullTime(t *time.Time) sql.NullTime {
	if t == nil {
		return sql.NullTime{Valid: false}
	}
	return sql.NullTime{Time: *t, Valid: true}
}

func toNullStringFromTime(t *time.Time) sql.NullString {
	if t == nil {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: t.Format(time.RFC3339), Valid: true}
}

func pgAccountToLocal(a *pgstore.OauthAccount) *Account {
	var accessToken, refreshToken string
	if a.AccessToken.Valid {
		accessToken = a.AccessToken.String
	}
	if a.RefreshToken.Valid {
		refreshToken = a.RefreshToken.String
	}

	var expiresAt *time.Time
	if a.AccessTokenExpiresAt.Valid {
		expiresAt = &a.AccessTokenExpiresAt.Time
	}

	return &Account{
		ID:                   a.ID,
		UserID:               a.UserID,
		Provider:             a.Provider,
		ProviderAccountID:    a.ProviderAccountID,
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		AccessTokenExpiresAt: expiresAt,
		CreatedAt:            a.CreatedAt,
		UpdatedAt:            a.UpdatedAt,
	}
}

func sqliteAccountToLocal(a *sqlitestore.OauthAccount) *Account {
	var accessToken, refreshToken string
	if a.AccessToken.Valid {
		accessToken = a.AccessToken.String
	}
	if a.RefreshToken.Valid {
		refreshToken = a.RefreshToken.String
	}

	var expiresAt *time.Time
	if a.AccessTokenExpiresAt.Valid {
		t, _ := time.Parse(time.RFC3339, a.AccessTokenExpiresAt.String)
		expiresAt = &t
	}

	createdAt, _ := time.Parse(time.RFC3339, a.CreatedAt)
	updatedAt, _ := time.Parse(time.RFC3339, a.UpdatedAt)

	return &Account{
		ID:                   a.ID,
		UserID:               a.UserID,
		Provider:             a.Provider,
		ProviderAccountID:    a.ProviderAccountID,
		AccessToken:          accessToken,
		RefreshToken:         refreshToken,
		AccessTokenExpiresAt: expiresAt,
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
	}
}
