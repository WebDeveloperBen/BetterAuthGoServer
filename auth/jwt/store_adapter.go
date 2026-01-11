package jwt

import (
	"context"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// BlocklistAdapter adapts db.JWTStore to the jwt.TokenBlocklist interface.
type BlocklistAdapter struct {
	store db.JWTStore
}

// NewBlocklistAdapter creates a new TokenBlocklist adapter from a db.JWTStore.
func NewBlocklistAdapter(store db.JWTStore) *BlocklistAdapter {
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
