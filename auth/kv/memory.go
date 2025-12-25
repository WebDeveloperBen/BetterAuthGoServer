package kv

import (
	"context"
	"encoding/binary"
	"sync"
	"time"
)

// entry represents a stored value with optional expiration
type entry struct {
	value     []byte
	expiresAt time.Time
	hasExpiry bool
}

// isExpired checks if the entry has expired
func (e *entry) isExpired(now time.Time) bool {
	return e.hasExpiry && now.After(e.expiresAt)
}

// MemoryStore is an in-memory implementation of the Store interface.
// Safe for concurrent use.
type MemoryStore struct {
	data    map[string]*entry
	mu      sync.RWMutex
	stopCh  chan struct{}
	stopped bool
}

// MemoryStoreOption configures a MemoryStore
type MemoryStoreOption func(*MemoryStore)

// WithCleanupInterval sets the interval for expired entry cleanup.
// Default is 1 minute.
func WithCleanupInterval(d time.Duration) MemoryStoreOption {
	return func(s *MemoryStore) {
		go s.runCleanup(d)
	}
}

// NewMemoryStore creates a new in-memory store.
// By default, starts a cleanup goroutine that runs every minute.
func NewMemoryStore(opts ...MemoryStoreOption) *MemoryStore {
	s := &MemoryStore{
		data:   make(map[string]*entry),
		stopCh: make(chan struct{}),
	}

	// Default cleanup interval
	hasCleanup := false
	for _, opt := range opts {
		opt(s)
		hasCleanup = true
	}

	if !hasCleanup {
		go s.runCleanup(time.Minute)
	}

	return s
}

// runCleanup periodically removes expired entries
func (s *MemoryStore) runCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.cleanupExpired()
		case <-s.stopCh:
			return
		}
	}
}

// cleanupExpired removes all expired entries
func (s *MemoryStore) cleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for key, e := range s.data {
		if e.isExpired(now) {
			delete(s.data, key)
		}
	}
}

// Get retrieves a value by key
func (s *MemoryStore) Get(ctx context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, exists := s.data[key]
	if !exists {
		return nil, ErrKeyNotFound
	}

	if e.isExpired(time.Now()) {
		return nil, ErrKeyNotFound
	}

	// Return a copy to prevent mutation
	result := make([]byte, len(e.value))
	copy(result, e.value)
	return result, nil
}

// Set stores a value with optional TTL
func (s *MemoryStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return ErrStoreClosed
	}

	// Copy value to prevent external mutation
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)

	e := &entry{value: valueCopy}
	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
		e.hasExpiry = true
	}

	s.data[key] = e
	return nil
}

// Delete removes a key
func (s *MemoryStore) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
	return nil
}

// Exists checks if a key exists
func (s *MemoryStore) Exists(ctx context.Context, key string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, exists := s.data[key]
	if !exists {
		return false, nil
	}

	if e.isExpired(time.Now()) {
		return false, nil
	}

	return true, nil
}

// Increment atomically increments a counter
func (s *MemoryStore) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return 0, ErrStoreClosed
	}

	var current int64
	e, exists := s.data[key]
	if exists && !e.isExpired(time.Now()) {
		if len(e.value) >= 8 {
			current = int64(binary.BigEndian.Uint64(e.value))
		}
	}

	newValue := current + delta
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(newValue))

	// Preserve existing TTL if key exists
	if exists && !e.isExpired(time.Now()) {
		s.data[key] = &entry{
			value:     buf,
			expiresAt: e.expiresAt,
			hasExpiry: e.hasExpiry,
		}
	} else {
		s.data[key] = &entry{value: buf}
	}

	return newValue, nil
}

// SetNX sets a value only if it doesn't exist
func (s *MemoryStore) SetNX(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
		return false, ErrStoreClosed
	}

	e, exists := s.data[key]
	if exists && !e.isExpired(time.Now()) {
		return false, nil
	}

	// Copy value
	valueCopy := make([]byte, len(value))
	copy(valueCopy, value)

	newEntry := &entry{value: valueCopy}
	if ttl > 0 {
		newEntry.expiresAt = time.Now().Add(ttl)
		newEntry.hasExpiry = true
	}

	s.data[key] = newEntry
	return true, nil
}

// Expire updates the TTL of an existing key
func (s *MemoryStore) Expire(ctx context.Context, key string, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, exists := s.data[key]
	if !exists || e.isExpired(time.Now()) {
		return ErrKeyNotFound
	}

	if ttl > 0 {
		e.expiresAt = time.Now().Add(ttl)
		e.hasExpiry = true
	} else {
		e.hasExpiry = false
	}

	return nil
}

// TTL returns the remaining time-to-live for a key
func (s *MemoryStore) TTL(ctx context.Context, key string) (time.Duration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, exists := s.data[key]
	if !exists || e.isExpired(time.Now()) {
		return 0, ErrKeyNotFound
	}

	if !e.hasExpiry {
		return 0, nil
	}

	remaining := time.Until(e.expiresAt)
	if remaining < 0 {
		return 0, nil
	}
	return remaining, nil
}

// Close stops the cleanup goroutine
func (s *MemoryStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.stopped {
		s.stopped = true
		close(s.stopCh)
	}
	return nil
}

// MemoryRateLimiter implements RateLimiter using the memory store
type MemoryRateLimiter struct {
	store *MemoryStore
}

// NewMemoryRateLimiter creates a new in-memory rate limiter
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return &MemoryRateLimiter{
		store: NewMemoryStore(),
	}
}

// Allow checks if n requests are allowed for the key in the given window
func (r *MemoryRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration, n int) (*RateLimitResult, error) {
	r.store.mu.Lock()
	defer r.store.mu.Unlock()

	now := time.Now()
	fullKey := PrefixRateLimit + key

	e, exists := r.store.data[fullKey]
	if !exists || e.isExpired(now) {
		// Create new entry
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(n))
		r.store.data[fullKey] = &entry{
			value:     buf,
			expiresAt: now.Add(window),
			hasExpiry: true,
		}
		return &RateLimitResult{
			Allowed:   true,
			Remaining: limit - n,
			ResetAt:   now.Add(window),
			Limit:     limit,
		}, nil
	}

	// Get current count
	var count int
	if len(e.value) >= 8 {
		count = int(binary.BigEndian.Uint64(e.value))
	}

	// Check if adding n would exceed limit
	if count+n > limit {
		return &RateLimitResult{
			Allowed:   false,
			Remaining: limit - count,
			ResetAt:   e.expiresAt,
			Limit:     limit,
		}, nil
	}

	// Increment count
	newCount := count + n
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(newCount))
	e.value = buf

	return &RateLimitResult{
		Allowed:   true,
		Remaining: limit - newCount,
		ResetAt:   e.expiresAt,
		Limit:     limit,
	}, nil
}

// Reset clears the rate limit for a key
func (r *MemoryRateLimiter) Reset(ctx context.Context, key string) error {
	return r.store.Delete(ctx, PrefixRateLimit+key)
}

// Close releases resources
func (r *MemoryRateLimiter) Close() error {
	return r.store.Close()
}

// Ensure interface compliance
var (
	_ Store       = (*MemoryStore)(nil)
	_ RateLimiter = (*MemoryRateLimiter)(nil)
)
