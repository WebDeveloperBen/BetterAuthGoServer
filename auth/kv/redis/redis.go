// Package redis provides a Redis-backed implementation of the kv.Store interface.
// This is an optional package - import it only if you need Redis support.
//
// Usage:
//
//	import (
//	    "github.com/webdeveloperben/BetterAuthGoServer/auth"
//	    kvredis "github.com/webdeveloperben/BetterAuthGoServer/auth/kv/redis"
//	)
//
//	store := kvredis.NewStore(&redis.Options{Addr: "localhost:6379"})
//	auth.New(db, auth.WithRateLimiterBackend(kvredis.NewRateLimiter(store)))
package redis

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
)

// Store implements kv.Store using Redis
type Store struct {
	client *redis.Client
}

// NewStore creates a new Redis-backed store
func NewStore(opts *redis.Options) *Store {
	return &Store{
		client: redis.NewClient(opts),
	}
}

// NewStoreFromClient creates a store from an existing Redis client
func NewStoreFromClient(client *redis.Client) *Store {
	return &Store{client: client}
}

// Get retrieves a value by key
func (s *Store) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := s.client.Get(ctx, key).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, kv.ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return val, nil
}

// Set stores a value with optional TTL
func (s *Store) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl).Err()
}

// Delete removes a key
func (s *Store) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

// Exists checks if a key exists
func (s *Store) Exists(ctx context.Context, key string) (bool, error) {
	n, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// Increment atomically increments a counter
func (s *Store) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	return s.client.IncrBy(ctx, key, delta).Result()
}

// SetNX sets a value only if it doesn't exist
func (s *Store) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return s.client.SetNX(ctx, key, value, ttl).Result()
}

// Expire updates the TTL of an existing key
func (s *Store) Expire(ctx context.Context, key string, ttl time.Duration) error {
	ok, err := s.client.Expire(ctx, key, ttl).Result()
	if err != nil {
		return err
	}
	if !ok {
		return kv.ErrKeyNotFound
	}
	return nil
}

// TTL returns the remaining time-to-live for a key (millisecond precision)
func (s *Store) TTL(ctx context.Context, key string) (time.Duration, error) {
	// Use PTTL for millisecond precision instead of TTL (seconds)
	ttl, err := s.client.PTTL(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	// PTTL returns -2 if key doesn't exist, -1 if key has no TTL
	if ttl < 0 {
		return 0, kv.ErrKeyNotFound
	}
	return ttl, nil
}

// Close closes the Redis connection
func (s *Store) Close() error {
	return s.client.Close()
}

// Ping checks if the Redis connection is healthy
func (s *Store) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// RateLimiter implements kv.RateLimiter using Redis
type RateLimiter struct {
	store *Store
}

// NewRateLimiter creates a new Redis-backed rate limiter
func NewRateLimiter(store *Store) *RateLimiter {
	return &RateLimiter{store: store}
}

// NewRateLimiterFromOptions creates a rate limiter with a new Redis connection
func NewRateLimiterFromOptions(opts *redis.Options) *RateLimiter {
	return &RateLimiter{store: NewStore(opts)}
}

// Allow checks if n requests are allowed for the key in the given window
func (r *RateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration, n int) (*kv.RateLimitResult, error) {
	fullKey := kv.PrefixRateLimit + key

	// Use a Lua script for atomic increment + expire
	script := redis.NewScript(`
		local current = redis.call('INCRBY', KEYS[1], ARGV[1])
		if current == tonumber(ARGV[1]) then
			redis.call('PEXPIRE', KEYS[1], ARGV[2])
		end
		local ttl = redis.call('PTTL', KEYS[1])
		return {current, ttl}
	`)

	result, err := script.Run(ctx, r.store.client, []string{fullKey}, n, window.Milliseconds()).Slice()
	if err != nil {
		return nil, err
	}

	current := int(result[0].(int64))
	ttlMs := result[1].(int64)

	resetAt := time.Now().Add(time.Duration(ttlMs) * time.Millisecond)

	if current > limit {
		return &kv.RateLimitResult{
			Allowed:   false,
			Remaining: 0,
			ResetAt:   resetAt,
			Limit:     limit,
		}, nil
	}

	return &kv.RateLimitResult{
		Allowed:   true,
		Remaining: limit - current,
		ResetAt:   resetAt,
		Limit:     limit,
	}, nil
}

// Reset clears the rate limit for a key
func (r *RateLimiter) Reset(ctx context.Context, key string) error {
	return r.store.Delete(ctx, kv.PrefixRateLimit+key)
}

// Close releases resources
func (r *RateLimiter) Close() error {
	return r.store.Close()
}

// Int64ToBytes converts an int64 to a byte slice (big-endian)
func Int64ToBytes(n int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(n))
	return buf
}

// BytesToInt64 converts a byte slice to int64 (big-endian)
func BytesToInt64(data []byte) int64 {
	if len(data) < 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(data))
}

// Ensure interface compliance
var (
	_ kv.Store       = (*Store)(nil)
	_ kv.RateLimiter = (*RateLimiter)(nil)
)
