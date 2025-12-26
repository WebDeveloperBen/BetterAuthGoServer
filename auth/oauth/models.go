// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"time"

	"github.com/uptrace/bun"
)

// OAuthState represents an OAuth state record in the database
type OAuthState struct {
	bun.BaseModel `bun:"table:oauth_states,alias:os"`

	State      string    `bun:"state,pk"`
	Provider   string    `bun:"provider,notnull"`
	Verifier   *string   `bun:"verifier"`
	RedirectTo *string   `bun:"redirect_to"`
	CreatedAt  time.Time `bun:"created_at,notnull"`
	ExpiresAt  time.Time `bun:"expires_at,notnull"`
}

// TableName returns the table name
func (o *OAuthState) TableName() string {
	return "oauth_states"
}
