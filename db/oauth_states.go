package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/uptrace/bun"
	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// OAuthState model for Bun
type OAuthState struct {
	bun.BaseModel `bun:"table:oauth_states,alias:os"`

	State      string    `bun:"state,pk"`
	Provider   string    `bun:"provider,notnull"`
	Verifier   *string   `bun:"verifier"`
	RedirectTo *string   `bun:"redirect_to"`
	CreatedAt  time.Time `bun:"created_at,notnull,default:current_timestamp"`
	ExpiresAt  time.Time `bun:"expires_at,notnull"`
}

func toAuthOAuthState(o *OAuthState) *auth.OAuthState {
	if o == nil {
		return nil
	}
	return &auth.OAuthState{
		State:      o.State,
		Provider:   o.Provider,
		Verifier:   o.Verifier,
		RedirectTo: o.RedirectTo,
		CreatedAt:  o.CreatedAt,
		ExpiresAt:  o.ExpiresAt,
	}
}

func toBunOAuthState(o *auth.OAuthState) *OAuthState {
	if o == nil {
		return nil
	}
	return &OAuthState{
		State:      o.State,
		Provider:   o.Provider,
		Verifier:   o.Verifier,
		RedirectTo: o.RedirectTo,
		CreatedAt:  o.CreatedAt,
		ExpiresAt:  o.ExpiresAt,
	}
}

func (s *Store) CreateOAuthState(ctx context.Context, state *auth.OAuthState) error {
	bunState := toBunOAuthState(state)
	_, err := s.db.NewInsert().Model(bunState).Exec(ctx)
	return err
}

func (s *Store) GetOAuthState(ctx context.Context, state string) (*auth.OAuthState, error) {
	oauthState := new(OAuthState)
	err := s.db.NewSelect().Model(oauthState).Where("state = ?", state).Scan(ctx)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return toAuthOAuthState(oauthState), nil
}

func (s *Store) DeleteOAuthState(ctx context.Context, state string) error {
	_, err := s.db.NewDelete().Model((*OAuthState)(nil)).Where("state = ?", state).Exec(ctx)
	return err
}

func (s *Store) DeleteExpiredOAuthStates(ctx context.Context) error {
	_, err := s.db.NewDelete().Model((*OAuthState)(nil)).Where("expires_at < ?", time.Now()).Exec(ctx)
	return err
}
