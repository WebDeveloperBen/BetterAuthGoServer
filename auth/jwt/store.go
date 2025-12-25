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
//   - DBTokenBlocklist: Database-backed storage (good for multi-instance deployments)
//
// Example custom implementation:
//   type RedisTokenBlocklist struct { /* redis client */ }
//   func (r *RedisTokenBlocklist) IsRevoked(ctx context.Context, jti string) (bool, error) { /* ... */ }
//   func (r *RedisTokenBlocklist) Revoke(ctx context.Context, jti string, expiresAt time.Time) error { /* ... */ }
//
// Usage:
//   jwt.Plugin(jwt.WithTokenBlocklist(&MyCustomTokenBlocklist{}))

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

// DBTokenBlocklist implements TokenBlocklist with database persistence.
// Automatically creates the jwt_revoked_tokens table on first use.
type DBTokenBlocklist struct {
	db *bun.DB
}

// NewDBTokenBlocklist creates a new database-backed token blocklist
func NewDBTokenBlocklist(db *bun.DB) *DBTokenBlocklist {
	return &DBTokenBlocklist{db: db}
}

// ensureTable creates the revoked_tokens table if it doesn't exist
func (b *DBTokenBlocklist) ensureTable(ctx context.Context) error {
	_, err := b.db.NewCreateTable().
		Model((*RevokedToken)(nil)).
		IfNotExists().
		Exec(ctx)
	return err
}

// RevokedToken represents a revoked JWT token in the database
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

// IsRevoked checks if a token ID is revoked
func (b *DBTokenBlocklist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	// Ensure table exists
	if err := b.ensureTable(ctx); err != nil {
		return false, err
	}

	exists, err := b.db.NewSelect().
		Model((*RevokedToken)(nil)).
		Where("id = ?", jti).
		Exists(ctx)
	return exists, err
}

// Revoke adds a token ID to the blocklist
func (b *DBTokenBlocklist) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	// Ensure table exists
	if err := b.ensureTable(ctx); err != nil {
		return err
	}

	revokedToken := &RevokedToken{
		ID:        jti,
		ExpiresAt: expiresAt,
	}
	_, err := b.db.NewInsert().
		Model(revokedToken).
		On("CONFLICT (id) DO NOTHING"). // Ignore duplicates
		Exec(ctx)
	return err
}
