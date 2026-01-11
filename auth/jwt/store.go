package jwt

import (
	"context"
	"sync"
	"time"

	"github.com/uptrace/bun"
)

// TokenBlocklist implementations for JWT token revocation.
// Users can provide their own implementations by implementing the TokenBlocklist interface.
//
// Built-in implementations:
//   - MemoryTokenBlocklist: In-memory storage (good for single instances)
//   - BlocklistAdapter: Database-backed storage using sqlc (good for multi-instance deployments)
//
// Example custom implementation:
//
//	type RedisTokenBlocklist struct { /* redis client */ }
//	func (r *RedisTokenBlocklist) IsRevoked(ctx context.Context, jti string) (bool, error) { /* ... */ }
//	func (r *RedisTokenBlocklist) Revoke(ctx context.Context, jti string, expiresAt time.Time) error { /* ... */ }
//
// Usage:
//
//	jwt.Plugin(jwt.WithTokenBlocklist(&MyCustomTokenBlocklist{}))

// MemoryTokenBlocklist implements TokenBlocklist with in-memory storage
type MemoryTokenBlocklist struct {
	mu      sync.RWMutex
	revoked map[string]time.Time
}

// NewMemoryTokenBlocklist creates a new in-memory token blocklist
func NewMemoryTokenBlocklist() *MemoryTokenBlocklist {
	return &MemoryTokenBlocklist{
		revoked: make(map[string]time.Time),
	}
}

// IsRevoked checks if a token ID is revoked
func (b *MemoryTokenBlocklist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	expiry, exists := b.revoked[jti]
	if !exists {
		return false, nil
	}
	// Clean up expired entries
	if time.Now().After(expiry) {
		delete(b.revoked, jti)
		return false, nil
	}
	return true, nil
}

// Revoke adds a token ID to the blocklist
func (b *MemoryTokenBlocklist) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.revoked[jti] = expiresAt
	return nil
}

// RevokedToken represents a revoked JWT token in the database.
// Used for bun auto-migration.
type RevokedToken struct {
	bun.BaseModel `bun:"table:jwt_revoked_tokens,alias:rt"`

	ID        string    `bun:"id,pk"`
	ExpiresAt time.Time `bun:"expires_at,notnull"`
	RevokedAt time.Time `bun:"revoked_at,notnull,default:current_timestamp"`
}

// TableName returns the table name
func (r *RevokedToken) TableName() string {
	return "jwt_revoked_tokens"
}
