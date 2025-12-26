package kv

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// BytesToInt64 converts a byte slice to int64 (used in tests)
func BytesToInt64(data []byte) int64 {
	if len(data) < 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(data))
}

func TestMemoryStore_GetSet(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Test Set and Get
	err := store.Set(ctx, "key1", []byte("value1"), 0)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	value, err := store.Get(ctx, "key1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(value) != "value1" {
		t.Errorf("Expected 'value1', got '%s'", value)
	}

	// Test Get non-existent key
	_, err = store.Get(ctx, "nonexistent")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestMemoryStore_TTL(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Set with TTL
	err := store.Set(ctx, "expiring", []byte("value"), 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Should exist immediately
	value, err := store.Get(ctx, "expiring")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(value) != "value" {
		t.Errorf("Expected 'value', got '%s'", value)
	}

	// Check TTL
	ttl, err := store.TTL(ctx, "expiring")
	if err != nil {
		t.Fatalf("TTL failed: %v", err)
	}
	if ttl <= 0 || ttl > 100*time.Millisecond {
		t.Errorf("Expected TTL between 0 and 100ms, got %v", ttl)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should not exist after expiration
	_, err = store.Get(ctx, "expiring")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after expiration, got %v", err)
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Set a key
	_ = store.Set(ctx, "to_delete", []byte("value"), 0)

	// Delete it
	err := store.Delete(ctx, "to_delete")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Should not exist
	_, err = store.Get(ctx, "to_delete")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after delete, got %v", err)
	}

	// Deleting non-existent key should not error
	err = store.Delete(ctx, "nonexistent")
	if err != nil {
		t.Errorf("Delete of non-existent key should not error, got %v", err)
	}
}

func TestMemoryStore_Exists(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Non-existent key
	exists, err := store.Exists(ctx, "key")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("Expected key to not exist")
	}

	// Set key
	_ = store.Set(ctx, "key", []byte("value"), 0)

	// Should exist now
	exists, err = store.Exists(ctx, "key")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("Expected key to exist")
	}
}

func TestMemoryStore_Increment(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Increment non-existent key (should initialize to 0 then add)
	val, err := store.Increment(ctx, "counter", 1)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val != 1 {
		t.Errorf("Expected 1, got %d", val)
	}

	// Increment again
	val, err = store.Increment(ctx, "counter", 5)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val != 6 {
		t.Errorf("Expected 6, got %d", val)
	}

	// Negative increment
	val, err = store.Increment(ctx, "counter", -2)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val != 4 {
		t.Errorf("Expected 4, got %d", val)
	}
}

func TestMemoryStore_SetNX(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// SetNX on non-existent key should succeed
	set, err := store.SetNX(ctx, "unique", []byte("value1"), 0)
	if err != nil {
		t.Fatalf("SetNX failed: %v", err)
	}
	if !set {
		t.Error("Expected SetNX to return true for new key")
	}

	// SetNX on existing key should fail
	set, err = store.SetNX(ctx, "unique", []byte("value2"), 0)
	if err != nil {
		t.Fatalf("SetNX failed: %v", err)
	}
	if set {
		t.Error("Expected SetNX to return false for existing key")
	}

	// Verify original value is preserved
	value, _ := store.Get(ctx, "unique")
	if string(value) != "value1" {
		t.Errorf("Expected 'value1', got '%s'", value)
	}
}

func TestMemoryStore_Expire(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Set key without expiration
	_ = store.Set(ctx, "key", []byte("value"), 0)

	// Add expiration
	err := store.Expire(ctx, "key", 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Expire failed: %v", err)
	}

	// Check TTL
	ttl, err := store.TTL(ctx, "key")
	if err != nil {
		t.Fatalf("TTL failed: %v", err)
	}
	if ttl <= 0 || ttl > 100*time.Millisecond {
		t.Errorf("Expected TTL between 0 and 100ms, got %v", ttl)
	}

	// Expire on non-existent key
	err = store.Expire(ctx, "nonexistent", time.Hour)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestMemoryStore_Concurrent(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	var wg sync.WaitGroup

	// Concurrent increments
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.Increment(ctx, "concurrent", 1)
		}()
	}

	wg.Wait()

	// Check final value
	data, _ := store.Get(ctx, "concurrent")
	val := BytesToInt64(data)
	if val != 100 {
		t.Errorf("Expected 100, got %d", val)
	}
}

func TestMemoryStore_ValueIsolation(t *testing.T) {
	store := NewMemoryStore()
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Set a value
	original := []byte("original")
	_ = store.Set(ctx, "key", original, 0)

	// Modify the original slice
	original[0] = 'X'

	// Get should return the original value, not the modified one
	value, _ := store.Get(ctx, "key")
	if string(value) != "original" {
		t.Errorf("Expected 'original', got '%s' - value was mutated", value)
	}

	// Modify the returned value
	value[0] = 'Y'

	// Get again should still return original
	value2, _ := store.Get(ctx, "key")
	if string(value2) != "original" {
		t.Errorf("Expected 'original', got '%s' - return value mutation affected store", value2)
	}
}

func TestMemoryRateLimiter_Basic(t *testing.T) {
	limiter := NewMemoryRateLimiter()
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	key := "test_user"
	limit := 3
	window := time.Minute

	// First 3 requests should be allowed
	for i := 0; i < 3; i++ {
		result, err := limiter.Allow(ctx, key, limit, window, 1)
		if err != nil {
			t.Fatalf("Allow failed: %v", err)
		}
		if !result.Allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
		if result.Remaining != limit-i-1 {
			t.Errorf("Expected remaining %d, got %d", limit-i-1, result.Remaining)
		}
	}

	// 4th request should be denied
	result, err := limiter.Allow(ctx, key, limit, window, 1)
	if err != nil {
		t.Fatalf("Allow failed: %v", err)
	}
	if result.Allowed {
		t.Error("4th request should be denied")
	}
	if result.Remaining != 0 {
		t.Errorf("Expected remaining 0, got %d", result.Remaining)
	}
}

func TestMemoryRateLimiter_WindowExpiry(t *testing.T) {
	limiter := NewMemoryRateLimiter()
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	key := "test_expiry"
	limit := 2
	window := 100 * time.Millisecond

	// Use up the limit
	_, _ = limiter.Allow(ctx, key, limit, window, 2)

	// Should be denied
	result, _ := limiter.Allow(ctx, key, limit, window, 1)
	if result.Allowed {
		t.Error("Should be denied after limit exceeded")
	}

	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)

	// Should be allowed again
	result, _ = limiter.Allow(ctx, key, limit, window, 1)
	if !result.Allowed {
		t.Error("Should be allowed after window expires")
	}
}

func TestMemoryRateLimiter_Reset(t *testing.T) {
	limiter := NewMemoryRateLimiter()
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	key := "test_reset"
	limit := 2
	window := time.Minute

	// Use up the limit
	_, _ = limiter.Allow(ctx, key, limit, window, 2)

	// Reset
	err := limiter.Reset(ctx, key)
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// Should be allowed again
	result, _ := limiter.Allow(ctx, key, limit, window, 1)
	if !result.Allowed {
		t.Error("Should be allowed after reset")
	}
	if result.Remaining != limit-1 {
		t.Errorf("Expected remaining %d, got %d", limit-1, result.Remaining)
	}
}

func TestMemoryRateLimiter_AllowN(t *testing.T) {
	limiter := NewMemoryRateLimiter()
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	key := "test_allowN"
	limit := 10
	window := time.Minute

	// Request 5 at once
	result, _ := limiter.Allow(ctx, key, limit, window, 5)
	if !result.Allowed {
		t.Error("Should be allowed")
	}
	if result.Remaining != 5 {
		t.Errorf("Expected remaining 5, got %d", result.Remaining)
	}

	// Request 6 more (should fail)
	result, _ = limiter.Allow(ctx, key, limit, window, 6)
	if result.Allowed {
		t.Error("Should be denied - would exceed limit")
	}

	// Request 5 more (should succeed)
	result, _ = limiter.Allow(ctx, key, limit, window, 5)
	if !result.Allowed {
		t.Error("Should be allowed - exactly at limit")
	}
	if result.Remaining != 0 {
		t.Errorf("Expected remaining 0, got %d", result.Remaining)
	}
}
