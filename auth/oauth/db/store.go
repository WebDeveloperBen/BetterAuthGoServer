// Package db provides the OAuth plugin's database operations using sqlc-generated queries.
// This package is owned by the OAuth plugin and handles its own persistence.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// =============================================================================
// Domain types
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
// Querier interface - each dialect implements this
// =============================================================================

// Querier defines all OAuth database operations.
// Each dialect implements this interface, handling type conversions internally.
type Querier interface {
	// State operations
	CreateOAuthState(ctx context.Context, state *State) error
	GetOAuthState(ctx context.Context, stateValue string) (*State, error)
	DeleteOAuthState(ctx context.Context, stateValue string) error
	DeleteExpiredOAuthStates(ctx context.Context) error

	// Account operations
	CreateAccount(ctx context.Context, account *Account) error
	GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error)
	GetAccountsByUserID(ctx context.Context, userID string) ([]*Account, error)
	UpdateAccount(ctx context.Context, account *Account) error
	DeleteAccount(ctx context.Context, id string) error
}

// =============================================================================
// Store - delegates to dialect-specific Querier
// =============================================================================

// Store handles OAuth persistence.
type Store struct {
	q Querier
}

// New creates a new OAuth store.
func New(db coredb.DBTX, dialect coredb.Dialect) (*Store, error) {
	var q Querier

	switch dialect {
	case coredb.DialectPostgres:
		q = newPgAdapter(db)
	case coredb.DialectMySQL:
		q = newMysqlAdapter(db)
	case coredb.DialectSQLite:
		q = newSqliteAdapter(db)
	default:
		return nil, fmt.Errorf("unsupported dialect: %s", dialect)
	}

	return &Store{q: q}, nil
}

// State operations - delegate to Querier

func (s *Store) CreateOAuthState(ctx context.Context, state *State) error {
	return s.q.CreateOAuthState(ctx, state)
}

func (s *Store) GetOAuthState(ctx context.Context, stateValue string) (*State, error) {
	return s.q.GetOAuthState(ctx, stateValue)
}

func (s *Store) DeleteOAuthState(ctx context.Context, stateValue string) error {
	return s.q.DeleteOAuthState(ctx, stateValue)
}

func (s *Store) DeleteExpiredOAuthStates(ctx context.Context) error {
	return s.q.DeleteExpiredOAuthStates(ctx)
}

// Account operations - delegate to Querier

func (s *Store) CreateAccount(ctx context.Context, account *Account) error {
	return s.q.CreateAccount(ctx, account)
}

func (s *Store) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error) {
	return s.q.GetAccountByProvider(ctx, provider, providerAccountID)
}

func (s *Store) GetAccountsByUserID(ctx context.Context, userID string) ([]*Account, error) {
	return s.q.GetAccountsByUserID(ctx, userID)
}

func (s *Store) UpdateAccount(ctx context.Context, account *Account) error {
	return s.q.UpdateAccount(ctx, account)
}

func (s *Store) DeleteAccount(ctx context.Context, id string) error {
	return s.q.DeleteAccount(ctx, id)
}

// =============================================================================
// PostgreSQL adapter
// =============================================================================

type pgAdapter struct {
	q *pgstore.Queries
}

func newPgAdapter(db coredb.DBTX) *pgAdapter {
	return &pgAdapter{q: pgstore.New(db)}
}

func (a *pgAdapter) CreateOAuthState(ctx context.Context, state *State) error {
	return a.q.CreateOAuthState(ctx, pgstore.CreateOAuthStateParams{
		State:      state.State,
		Provider:   state.Provider,
		Verifier:   toNullString(state.Verifier),
		RedirectTo: toNullString(state.RedirectTo),
		CreatedAt:  state.CreatedAt,
		ExpiresAt:  state.ExpiresAt,
	})
}

func (a *pgAdapter) GetOAuthState(ctx context.Context, stateValue string) (*State, error) {
	row, err := a.q.GetOAuthState(ctx, stateValue)
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

func (a *pgAdapter) DeleteOAuthState(ctx context.Context, stateValue string) error {
	return a.q.DeleteOAuthState(ctx, stateValue)
}

func (a *pgAdapter) DeleteExpiredOAuthStates(ctx context.Context) error {
	return a.q.DeleteExpiredOAuthStates(ctx, time.Now())
}

func (a *pgAdapter) CreateAccount(ctx context.Context, account *Account) error {
	return a.q.CreateOAuthAccount(ctx, pgstore.CreateOAuthAccountParams{
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

func (a *pgAdapter) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error) {
	row, err := a.q.GetOAuthAccountByProvider(ctx, pgstore.GetOAuthAccountByProviderParams{
		Provider:          provider,
		ProviderAccountID: providerAccountID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgAccountToDomain(&row), nil
}

func (a *pgAdapter) GetAccountsByUserID(ctx context.Context, userID string) ([]*Account, error) {
	rows, err := a.q.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	accounts := make([]*Account, len(rows))
	for i := range rows {
		accounts[i] = pgAccountToDomain(&rows[i])
	}
	return accounts, nil
}

func (a *pgAdapter) UpdateAccount(ctx context.Context, account *Account) error {
	return a.q.UpdateOAuthAccount(ctx, pgstore.UpdateOAuthAccountParams{
		ID:                   account.ID,
		AccessToken:          toNullString(&account.AccessToken),
		RefreshToken:         toNullString(&account.RefreshToken),
		AccessTokenExpiresAt: toNullTime(account.AccessTokenExpiresAt),
		UpdatedAt:            account.UpdatedAt,
	})
}

func (a *pgAdapter) DeleteAccount(ctx context.Context, id string) error {
	return a.q.DeleteOAuthAccount(ctx, id)
}

var _ Querier = (*pgAdapter)(nil)

// =============================================================================
// MySQL adapter
// =============================================================================

type mysqlAdapter struct {
	q *mysqlstore.Queries
}

func newMysqlAdapter(db coredb.DBTX) *mysqlAdapter {
	return &mysqlAdapter{q: mysqlstore.New(db)}
}

func (a *mysqlAdapter) CreateOAuthState(ctx context.Context, state *State) error {
	return a.q.CreateOAuthState(ctx, mysqlstore.CreateOAuthStateParams{
		State:      state.State,
		Provider:   state.Provider,
		Verifier:   toNullString(state.Verifier),
		RedirectTo: toNullString(state.RedirectTo),
		CreatedAt:  state.CreatedAt,
		ExpiresAt:  state.ExpiresAt,
	})
}

func (a *mysqlAdapter) GetOAuthState(ctx context.Context, stateValue string) (*State, error) {
	row, err := a.q.GetOAuthState(ctx, stateValue)
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

func (a *mysqlAdapter) DeleteOAuthState(ctx context.Context, stateValue string) error {
	return a.q.DeleteOAuthState(ctx, stateValue)
}

func (a *mysqlAdapter) DeleteExpiredOAuthStates(ctx context.Context) error {
	return a.q.DeleteExpiredOAuthStates(ctx, time.Now())
}

func (a *mysqlAdapter) CreateAccount(ctx context.Context, account *Account) error {
	return a.q.CreateOAuthAccount(ctx, mysqlstore.CreateOAuthAccountParams{
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

func (a *mysqlAdapter) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error) {
	row, err := a.q.GetOAuthAccountByProvider(ctx, mysqlstore.GetOAuthAccountByProviderParams{
		Provider:          provider,
		ProviderAccountID: providerAccountID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlAccountToDomain(&row), nil
}

func (a *mysqlAdapter) GetAccountsByUserID(ctx context.Context, userID string) ([]*Account, error) {
	rows, err := a.q.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	accounts := make([]*Account, len(rows))
	for i := range rows {
		accounts[i] = mysqlAccountToDomain(&rows[i])
	}
	return accounts, nil
}

func (a *mysqlAdapter) UpdateAccount(ctx context.Context, account *Account) error {
	return a.q.UpdateOAuthAccount(ctx, mysqlstore.UpdateOAuthAccountParams{
		ID:                   account.ID,
		AccessToken:          toNullString(&account.AccessToken),
		RefreshToken:         toNullString(&account.RefreshToken),
		AccessTokenExpiresAt: toNullTime(account.AccessTokenExpiresAt),
		UpdatedAt:            account.UpdatedAt,
	})
}

func (a *mysqlAdapter) DeleteAccount(ctx context.Context, id string) error {
	return a.q.DeleteOAuthAccount(ctx, id)
}

var _ Querier = (*mysqlAdapter)(nil)

// =============================================================================
// SQLite adapter
// =============================================================================

type sqliteAdapter struct {
	q *sqlitestore.Queries
}

func newSqliteAdapter(db coredb.DBTX) *sqliteAdapter {
	return &sqliteAdapter{q: sqlitestore.New(db)}
}

func (a *sqliteAdapter) CreateOAuthState(ctx context.Context, state *State) error {
	return a.q.CreateOAuthState(ctx, sqlitestore.CreateOAuthStateParams{
		State:      state.State,
		Provider:   state.Provider,
		Verifier:   toNullString(state.Verifier),
		RedirectTo: toNullString(state.RedirectTo),
		CreatedAt:  state.CreatedAt.Format(time.RFC3339),
		ExpiresAt:  state.ExpiresAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetOAuthState(ctx context.Context, stateValue string) (*State, error) {
	row, err := a.q.GetOAuthState(ctx, stateValue)
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

func (a *sqliteAdapter) DeleteOAuthState(ctx context.Context, stateValue string) error {
	return a.q.DeleteOAuthState(ctx, stateValue)
}

func (a *sqliteAdapter) DeleteExpiredOAuthStates(ctx context.Context) error {
	return a.q.DeleteExpiredOAuthStates(ctx, time.Now().Format(time.RFC3339))
}

func (a *sqliteAdapter) CreateAccount(ctx context.Context, account *Account) error {
	return a.q.CreateOAuthAccount(ctx, sqlitestore.CreateOAuthAccountParams{
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

func (a *sqliteAdapter) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*Account, error) {
	row, err := a.q.GetOAuthAccountByProvider(ctx, sqlitestore.GetOAuthAccountByProviderParams{
		Provider:          provider,
		ProviderAccountID: providerAccountID,
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteAccountToDomain(&row), nil
}

func (a *sqliteAdapter) GetAccountsByUserID(ctx context.Context, userID string) ([]*Account, error) {
	rows, err := a.q.GetOAuthAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	accounts := make([]*Account, len(rows))
	for i := range rows {
		accounts[i] = sqliteAccountToDomain(&rows[i])
	}
	return accounts, nil
}

func (a *sqliteAdapter) UpdateAccount(ctx context.Context, account *Account) error {
	return a.q.UpdateOAuthAccount(ctx, sqlitestore.UpdateOAuthAccountParams{
		ID:                   account.ID,
		AccessToken:          toNullString(&account.AccessToken),
		RefreshToken:         toNullString(&account.RefreshToken),
		AccessTokenExpiresAt: toNullStringFromTime(account.AccessTokenExpiresAt),
		UpdatedAt:            account.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) DeleteAccount(ctx context.Context, id string) error {
	return a.q.DeleteOAuthAccount(ctx, id)
}

var _ Querier = (*sqliteAdapter)(nil)

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

func pgAccountToDomain(a *pgstore.OauthAccount) *Account {
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

func mysqlAccountToDomain(a *mysqlstore.OauthAccount) *Account {
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

func sqliteAccountToDomain(a *sqlitestore.OauthAccount) *Account {
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
