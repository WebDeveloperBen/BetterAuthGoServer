package jwt

import (
	"context"
	"time"

	jwtdb "github.com/webdeveloperben/BetterAuthGoServer/auth/jwt/db"
)

// BlocklistAdapter adapts jwtdb.Store to the jwt.TokenBlocklist interface.
type BlocklistAdapter struct {
	store *jwtdb.Store
}

// NewBlocklistAdapter creates a new TokenBlocklist adapter from a jwtdb.Store.
func NewBlocklistAdapter(store *jwtdb.Store) *BlocklistAdapter {
	return &BlocklistAdapter{store: store}
}

// IsRevoked checks if a token ID is revoked.
func (a *BlocklistAdapter) IsRevoked(ctx context.Context, jti string) (bool, error) {
	return a.store.IsJWTTokenRevoked(ctx, jti)
}

// Revoke adds a token ID to the blocklist.
func (a *BlocklistAdapter) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	return a.store.RevokeJWTToken(ctx, jti, expiresAt)
}

// Ensure BlocklistAdapter implements TokenBlocklist
var _ TokenBlocklist = (*BlocklistAdapter)(nil)
