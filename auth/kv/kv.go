// Package kv provides a key-value storage interface for auth internals.
// Used for rate limiting, session caching, token blocklists, and plugin state.
package kv

import (
	"context"
	"errors"
	"time"
)

// Common errors
var (
	ErrKeyNotFound = errors.New("key not found")
	ErrStoreClosed = errors.New("store is closed")
)

// Store defines a key-value storage interface.
// Implementations must be safe for concurrent use.
type Store interface {
	// Get retrieves a value by key.
	// Returns ErrKeyNotFound if the key doesn't exist.
	Get(ctx context.Context, key string) ([]byte, error)

	// Set stores a value with optional TTL.
	// TTL of 0 means no expiration.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes a key.
	// Returns nil if the key doesn't exist.
	Delete(ctx context.Context, key string) error

	// Exists checks if a key exists.
	Exists(ctx context.Context, key string) (bool, error)

	// Increment atomically increments a counter, returning the new value.
	// Initializes to 0 if key doesn't exist, then applies the delta.
	// Used for rate limiting counters.
	Increment(ctx context.Context, key string, delta int64) (int64, error)

	// SetNX sets a value only if it doesn't exist (atomic).
	// Returns true if the value was set, false if the key already existed.
	// TTL of 0 means no expiration.
	SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)

	// Expire updates the TTL of an existing key.
	// Returns ErrKeyNotFound if the key doesn't exist.
	Expire(ctx context.Context, key string, ttl time.Duration) error

	// TTL returns the remaining time-to-live for a key.
	// Returns 0 if the key has no expiration.
	// Returns ErrKeyNotFound if the key doesn't exist.
	TTL(ctx context.Context, key string) (time.Duration, error)

	// Close releases any resources held by the store.
	Close() error
}

// RateLimitResult contains the result of a rate limit check.
type RateLimitResult struct {
	Allowed   bool      // Whether the request is allowed
	Remaining int       // Remaining requests in the window
	ResetAt   time.Time // When the rate limit window resets
	Limit     int       // The configured limit
}

// RateLimiter is a specialized interface for rate limiting.
// Implementations may optimize for high-frequency atomic operations.
type RateLimiter interface {
	// Allow checks if n requests are allowed for the key in the given window.
	Allow(ctx context.Context, key string, limit int, window time.Duration, n int) (*RateLimitResult, error)

	// Reset clears the rate limit for a key.
	Reset(ctx context.Context, key string) error

	// Close releases any resources held by the rate limiter.
	Close() error
}

// Prefix helper for namespacing keys
const (
	PrefixRateLimit   = "rl:"
	PrefixSession     = "sess:"
	PrefixBlocklist   = "bl:"
	PrefixOAuthState  = "oauth:"
	PrefixPlugin      = "plugin:"
)

// Key builds a namespaced key
func Key(prefix, key string) string {
	return prefix + key
}
