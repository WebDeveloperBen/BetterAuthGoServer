package oauth

import (
	"context"

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// StoreAdapter adapts db.OAuthStore to the oauth.StateStore interface.
type StoreAdapter struct {
	store db.OAuthStore
}

// NewStoreAdapter creates a new StateStore adapter from a db.OAuthStore.
func NewStoreAdapter(store db.OAuthStore) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// CreateOAuthState creates a new OAuth state record.
func (a *StoreAdapter) CreateOAuthState(ctx context.Context, state *State) error {
	dbState := &db.OAuthState{
		State:      state.State,
		Provider:   state.Provider,
		Verifier:   state.Verifier,
		RedirectTo: state.RedirectTo,
		ExpiresAt:  state.ExpiresAt,
		CreatedAt:  state.CreatedAt,
	}
	return a.store.CreateOAuthState(ctx, dbState)
}

// GetOAuthState retrieves an OAuth state record by state value.
func (a *StoreAdapter) GetOAuthState(ctx context.Context, stateValue string) (*State, error) {
	dbState, err := a.store.GetOAuthState(ctx, stateValue)
	if err != nil {
		return nil, err
	}
	if dbState == nil {
		return nil, nil
	}
	return &State{
		State:      dbState.State,
		Provider:   dbState.Provider,
		Verifier:   dbState.Verifier,
		RedirectTo: dbState.RedirectTo,
		ExpiresAt:  dbState.ExpiresAt,
		CreatedAt:  dbState.CreatedAt,
	}, nil
}

// DeleteOAuthState deletes an OAuth state record.
func (a *StoreAdapter) DeleteOAuthState(ctx context.Context, stateValue string) error {
	return a.store.DeleteOAuthState(ctx, stateValue)
}

// DeleteExpiredOAuthStates deletes all expired OAuth state records.
func (a *StoreAdapter) DeleteExpiredOAuthStates(ctx context.Context) error {
	return a.store.DeleteExpiredOAuthStates(ctx)
}

// Ensure StoreAdapter implements StateStore
var _ StateStore = (*StoreAdapter)(nil)

// AccountStoreAdapter adapts db.OAuthStore to the oauth.AccountStore-like operations.
type AccountStoreAdapter struct {
	store db.OAuthStore
}

// NewAccountStoreAdapter creates a new AccountStore adapter from a db.OAuthStore.
func NewAccountStoreAdapter(store db.OAuthStore) *AccountStoreAdapter {
	return &AccountStoreAdapter{store: store}
}

// CreateAccount creates a new OAuth account.
func (a *AccountStoreAdapter) CreateAccount(ctx context.Context, account *OAuthAccount) error {
	dbAccount := &db.OAuthAccount{
		ID:                   account.ID,
		UserID:               account.UserID,
		Provider:             account.Provider,
		ProviderAccountID:    account.ProviderAccountID,
		AccessToken:          stringPtr(account.AccessToken),
		RefreshToken:         stringPtr(account.RefreshToken),
		AccessTokenExpiresAt: account.AccessTokenExpiresAt,
		CreatedAt:            account.CreatedAt,
		UpdatedAt:            account.UpdatedAt,
	}
	return a.store.CreateOAuthAccount(ctx, dbAccount)
}

// GetAccountByProvider finds an OAuth account by provider and provider account ID.
func (a *AccountStoreAdapter) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*OAuthAccount, error) {
	dbAccount, err := a.store.GetOAuthAccountByProvider(ctx, provider, providerAccountID)
	if err != nil {
		return nil, err
	}
	if dbAccount == nil {
		return nil, nil
	}
	return dbOAuthAccountToLocal(dbAccount), nil
}

// UpdateAccount updates an OAuth account.
func (a *AccountStoreAdapter) UpdateAccount(ctx context.Context, account *OAuthAccount) error {
	dbAccount := &db.OAuthAccount{
		ID:                   account.ID,
		UserID:               account.UserID,
		Provider:             account.Provider,
		ProviderAccountID:    account.ProviderAccountID,
		AccessToken:          stringPtr(account.AccessToken),
		RefreshToken:         stringPtr(account.RefreshToken),
		AccessTokenExpiresAt: account.AccessTokenExpiresAt,
		CreatedAt:            account.CreatedAt,
		UpdatedAt:            account.UpdatedAt,
	}
	return a.store.UpdateOAuthAccount(ctx, dbAccount)
}

// dbOAuthAccountToLocal converts a db.OAuthAccount to the local OAuthAccount type.
func dbOAuthAccountToLocal(a *db.OAuthAccount) *OAuthAccount {
	if a == nil {
		return nil
	}
	return &OAuthAccount{
		ID:                   a.ID,
		UserID:               a.UserID,
		Provider:             a.Provider,
		ProviderAccountID:    a.ProviderAccountID,
		AccessToken:          derefString(a.AccessToken),
		RefreshToken:         derefString(a.RefreshToken),
		AccessTokenExpiresAt: a.AccessTokenExpiresAt,
		CreatedAt:            a.CreatedAt,
		UpdatedAt:            a.UpdatedAt,
	}
}

// stringPtr returns a pointer to the string, or nil if empty.
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// derefString returns the value of a string pointer, or empty string if nil.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
