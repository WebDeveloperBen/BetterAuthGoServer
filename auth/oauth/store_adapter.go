package oauth

import (
	"context"

	oauthdb "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db"
)

// StoreAdapter adapts the oauth plugin's db.Store to the oauth.StateStore interface.
type StoreAdapter struct {
	store *oauthdb.Store
}

// NewStoreAdapter creates a new StateStore adapter from the oauth plugin's store.
func NewStoreAdapter(store *oauthdb.Store) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// CreateOAuthState creates a new OAuth state record.
func (a *StoreAdapter) CreateOAuthState(ctx context.Context, state *State) error {
	dbState := &oauthdb.State{
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

// AccountStoreAdapter adapts the oauth plugin's db.Store to account operations.
type AccountStoreAdapter struct {
	store *oauthdb.Store
}

// NewAccountStoreAdapter creates a new AccountStore adapter from the oauth plugin's store.
func NewAccountStoreAdapter(store *oauthdb.Store) *AccountStoreAdapter {
	return &AccountStoreAdapter{store: store}
}

// CreateAccount creates a new OAuth account.
func (a *AccountStoreAdapter) CreateAccount(ctx context.Context, account *OAuthAccount) error {
	dbAccount := &oauthdb.Account{
		ID:                   account.ID,
		UserID:               account.UserID,
		Provider:             account.Provider,
		ProviderAccountID:    account.ProviderAccountID,
		AccessToken:          account.AccessToken,
		RefreshToken:         account.RefreshToken,
		AccessTokenExpiresAt: account.AccessTokenExpiresAt,
		CreatedAt:            account.CreatedAt,
		UpdatedAt:            account.UpdatedAt,
	}
	return a.store.CreateAccount(ctx, dbAccount)
}

// GetAccountByProvider finds an OAuth account by provider and provider account ID.
func (a *AccountStoreAdapter) GetAccountByProvider(ctx context.Context, provider, providerAccountID string) (*OAuthAccount, error) {
	dbAccount, err := a.store.GetAccountByProvider(ctx, provider, providerAccountID)
	if err != nil {
		return nil, err
	}
	if dbAccount == nil {
		return nil, nil
	}
	return dbAccountToLocal(dbAccount), nil
}

// UpdateAccount updates an OAuth account.
func (a *AccountStoreAdapter) UpdateAccount(ctx context.Context, account *OAuthAccount) error {
	dbAccount := &oauthdb.Account{
		ID:                   account.ID,
		UserID:               account.UserID,
		Provider:             account.Provider,
		ProviderAccountID:    account.ProviderAccountID,
		AccessToken:          account.AccessToken,
		RefreshToken:         account.RefreshToken,
		AccessTokenExpiresAt: account.AccessTokenExpiresAt,
		CreatedAt:            account.CreatedAt,
		UpdatedAt:            account.UpdatedAt,
	}
	return a.store.UpdateAccount(ctx, dbAccount)
}

// dbAccountToLocal converts a db.Account to the local OAuthAccount type.
func dbAccountToLocal(a *oauthdb.Account) *OAuthAccount {
	if a == nil {
		return nil
	}
	return &OAuthAccount{
		ID:                   a.ID,
		UserID:               a.UserID,
		Provider:             a.Provider,
		ProviderAccountID:    a.ProviderAccountID,
		AccessToken:          a.AccessToken,
		RefreshToken:         a.RefreshToken,
		AccessTokenExpiresAt: a.AccessTokenExpiresAt,
		CreatedAt:            a.CreatedAt,
		UpdatedAt:            a.UpdatedAt,
	}
}
