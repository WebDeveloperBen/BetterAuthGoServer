package redis

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
)

func getTestStore(t *testing.T) *Store {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "localhost:6379"
	}

	store := NewStore(&redis.Options{Addr: addr})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := store.Ping(ctx); err != nil {
		t.Skipf("Redis not available at %s: %v", addr, err)
	}

	return store
}

func TestStore_GetSet(t *testing.T) {
	store := getTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	key := "test:getset:" + time.Now().Format(time.RFC3339Nano)

	// Cleanup
	defer func() { _ = store.Delete(ctx, key) }()

	// Test Set and Get
	err := store.Set(ctx, key, []byte("value1"), 0)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	value, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(value) != "value1" {
		t.Errorf("Expected 'value1', got '%s'", value)
	}

	// Test Get non-existent key
	_, err = store.Get(ctx, "nonexistent:key:12345")
	if err != kv.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestStore_TTL(t *testing.T) {
	store := getTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	key := "test:ttl:" + time.Now().Format(time.RFC3339Nano)

	// Set with TTL
	err := store.Set(ctx, key, []byte("value"), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Should exist immediately
	value, err := store.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(value) != "value" {
		t.Errorf("Expected 'value', got '%s'", value)
	}

	// Check TTL
	ttl, err := store.TTL(ctx, key)
	if err != nil {
		t.Fatalf("TTL failed: %v", err)
	}
	if ttl <= 0 || ttl > 500*time.Millisecond {
		t.Errorf("Expected TTL between 0 and 500ms, got %v", ttl)
	}

	// Wait for expiration
	time.Sleep(600 * time.Millisecond)

	// Should not exist after expiration
	_, err = store.Get(ctx, key)
	if err != kv.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after expiration, got %v", err)
	}
}

func TestStore_Delete(t *testing.T) {
	store := getTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	key := "test:delete:" + time.Now().Format(time.RFC3339Nano)

	// Set a key
	_ = store.Set(ctx, key, []byte("value"), 0)

	// Delete it
	err := store.Delete(ctx, key)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Should not exist
	_, err = store.Get(ctx, key)
	if err != kv.ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after delete, got %v", err)
	}
}

func TestStore_Exists(t *testing.T) {
	store := getTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	key := "test:exists:" + time.Now().Format(time.RFC3339Nano)

	// Cleanup
	defer func() { _ = store.Delete(ctx, key) }()

	// Non-existent key
	exists, err := store.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if exists {
		t.Error("Expected key to not exist")
	}

	// Set key
	_ = store.Set(ctx, key, []byte("value"), 0)

	// Should exist now
	exists, err = store.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !exists {
		t.Error("Expected key to exist")
	}
}

func TestStore_Increment(t *testing.T) {
	store := getTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	key := "test:increment:" + time.Now().Format(time.RFC3339Nano)

	// Cleanup
	defer func() { _ = store.Delete(ctx, key) }()

	// Increment non-existent key
	val, err := store.Increment(ctx, key, 1)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val != 1 {
		t.Errorf("Expected 1, got %d", val)
	}

	// Increment again
	val, err = store.Increment(ctx, key, 5)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val != 6 {
		t.Errorf("Expected 6, got %d", val)
	}

	// Negative increment
	val, err = store.Increment(ctx, key, -2)
	if err != nil {
		t.Fatalf("Increment failed: %v", err)
	}
	if val != 4 {
		t.Errorf("Expected 4, got %d", val)
	}
}

func TestStore_SetNX(t *testing.T) {
	store := getTestStore(t)
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	key := "test:setnx:" + time.Now().Format(time.RFC3339Nano)

	// Cleanup
	defer func() { _ = store.Delete(ctx, key) }()

	// SetNX on non-existent key should succeed
	set, err := store.SetNX(ctx, key, []byte("value1"), 0)
	if err != nil {
		t.Fatalf("SetNX failed: %v", err)
	}
	if !set {
		t.Error("Expected SetNX to return true for new key")
	}

	// SetNX on existing key should fail
	set, err = store.SetNX(ctx, key, []byte("value2"), 0)
	if err != nil {
		t.Fatalf("SetNX failed: %v", err)
	}
	if set {
		t.Error("Expected SetNX to return false for existing key")
	}

	// Verify original value is preserved
	value, _ := store.Get(ctx, key)
	if string(value) != "value1" {
		t.Errorf("Expected 'value1', got '%s'", value)
	}
}

func TestRateLimiter_Basic(t *testing.T) {
	store := getTestStore(t)
	limiter := NewRateLimiter(store)
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	key := "test:ratelimit:" + time.Now().Format(time.RFC3339Nano)

	// Cleanup
	defer func() { _ = limiter.Reset(ctx, key) }()

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
	}

	// 4th request should be denied
	result, err := limiter.Allow(ctx, key, limit, window, 1)
	if err != nil {
		t.Fatalf("Allow failed: %v", err)
	}
	if result.Allowed {
		t.Error("4th request should be denied")
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	store := getTestStore(t)
	limiter := NewRateLimiter(store)
	defer func() { _ = limiter.Close() }()

	ctx := context.Background()
	key := "test:ratelimit:reset:" + time.Now().Format(time.RFC3339Nano)

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
}

func TestByteConversions(t *testing.T) {
	tests := []int64{0, 1, -1, 100, -100, 9223372036854775807, -9223372036854775808}

	for _, val := range tests {
		bytes := Int64ToBytes(val)
		result := BytesToInt64(bytes)
		if result != val {
			t.Errorf("Round-trip failed for %d: got %d", val, result)
		}
	}

	// Test short slice
	if BytesToInt64([]byte{1, 2, 3}) != 0 {
		t.Error("Expected 0 for short slice")
	}
}
