// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"context"
	"time"

	"github.com/uptrace/bun"
)

// StateStore implementations for OAuth state management.
// Users can provide their own implementations by implementing the StateStore interface.
//
// Built-in implementations:
//   - DBStateStore: Database-backed storage (recommended for production)
//
// Example custom implementation:
//   type RedisStateStore struct { /* redis client */ }
//   func (r *RedisStateStore) CreateOAuthState(ctx context.Context, state *State) error { /* ... */ }
//   func (r *RedisStateStore) GetOAuthState(ctx context.Context, stateValue string) (*State, error) { /* ... */ }
//   // ... other StateStore methods
//
// Usage:
//   oauth.Plugin(oauth.WithStateStore(&MyCustomStateStore{}))

// DBStateStore implements StateStore with database persistence.
// Automatically creates the oauth_states table on first use.
type DBStateStore struct {
	db *bun.DB
}

// NewDBStateStore creates a new database-backed OAuth state store
func NewDBStateStore(db *bun.DB) *DBStateStore {
	return &DBStateStore{db: db}
}

// ensureTable creates the oauth_states table if it doesn't exist
func (s *DBStateStore) ensureTable(ctx context.Context) error {
	_, err := s.db.NewCreateTable().
		Model((*OAuthState)(nil)).
		IfNotExists().
		Exec(ctx)
	return err
}

// CreateOAuthState creates a new OAuth state record
func (s *DBStateStore) CreateOAuthState(ctx context.Context, state *State) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}

	oauthState := &OAuthState{
		State:      state.State,
		Provider:   state.Provider,
		Verifier:   state.Verifier,
		RedirectTo: state.RedirectTo,
		CreatedAt:  state.CreatedAt,
		ExpiresAt:  state.ExpiresAt,
	}

	_, err := s.db.NewInsert().
		Model(oauthState).
		Exec(ctx)
	return err
}

// GetOAuthState retrieves an OAuth state record by state value
func (s *DBStateStore) GetOAuthState(ctx context.Context, stateValue string) (*State, error) {
	if err := s.ensureTable(ctx); err != nil {
		return nil, err
	}

	oauthState := new(OAuthState)
	err := s.db.NewSelect().
		Model(oauthState).
		Where("state = ?", stateValue).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return &State{
		State:      oauthState.State,
		Provider:   oauthState.Provider,
		Verifier:   oauthState.Verifier,
		RedirectTo: oauthState.RedirectTo,
		CreatedAt:  oauthState.CreatedAt,
		ExpiresAt:  oauthState.ExpiresAt,
	}, nil
}

// DeleteOAuthState deletes an OAuth state record
func (s *DBStateStore) DeleteOAuthState(ctx context.Context, stateValue string) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewDelete().
		Model((*OAuthState)(nil)).
		Where("state = ?", stateValue).
		Exec(ctx)
	return err
}

// DeleteExpiredOAuthStates deletes all expired OAuth state records
func (s *DBStateStore) DeleteExpiredOAuthStates(ctx context.Context) error {
	if err := s.ensureTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewDelete().
		Model((*OAuthState)(nil)).
		Where("expires_at < ?", time.Now()).
		Exec(ctx)
	return err
}
