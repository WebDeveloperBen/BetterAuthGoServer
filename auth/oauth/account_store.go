// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"time"

	"github.com/uptrace/bun"
)

// OAuthAccount represents an OAuth account in the database.
// This links a user to an OAuth provider and stores their tokens.
// Used for bun auto-migrations.
type OAuthAccount struct {
	bun.BaseModel `bun:"table:oauth_accounts,alias:oa"`

	ID                   string     `bun:"id,pk"`
	UserID               string     `bun:"user_id,notnull"`
	Provider             string     `bun:"provider,notnull"`
	ProviderAccountID    string     `bun:"provider_account_id,notnull"`
	AccessToken          string     `bun:"access_token"`
	RefreshToken         string     `bun:"refresh_token"`
	AccessTokenExpiresAt *time.Time `bun:"access_token_expires_at"`
	CreatedAt            time.Time  `bun:"created_at,notnull,default:current_timestamp"`
	UpdatedAt            time.Time  `bun:"updated_at,notnull,default:current_timestamp"`
}

// TableName returns the table name
func (o *OAuthAccount) TableName() string {
	return "oauth_accounts"
}
