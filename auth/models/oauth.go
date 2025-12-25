package models

import (
	"context"
	"time"
)

// OAuthState represents an OAuth state for CSRF protection
type OAuthState struct {
	State      string
	Provider   string
	Verifier   *string // PKCE verifier
	RedirectTo *string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// OAuthStateStore defines OAuth state-related database operations
type OAuthStateStore interface {
	CreateOAuthState(ctx context.Context, state *OAuthState) error
	GetOAuthState(ctx context.Context, state string) (*OAuthState, error)
	DeleteOAuthState(ctx context.Context, state string) error
	DeleteExpiredOAuthStates(ctx context.Context) error
}
