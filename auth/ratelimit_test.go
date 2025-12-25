package auth

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestNewRateLimiter(t *testing.T) {
	config := RateLimitConfig{
		Window:      time.Minute,
		MaxRequests: 10,
	}

	limiter := NewRateLimiter(config)
	defer limiter.Close()

	if limiter == nil {
		t.Fatal("NewRateLimiter returned nil")
	}
	if limiter.config.Window != time.Minute {
		t.Errorf("Window = %v, want %v", limiter.config.Window, time.Minute)
	}
	if limiter.config.MaxRequests != 10 {
		t.Errorf("MaxRequests = %d, want 10", limiter.config.MaxRequests)
	}
}

func TestDefaultRateLimitConfig(t *testing.T) {
	config := DefaultRateLimitConfig()

	if config.Window != time.Minute {
		t.Errorf("Window = %v, want %v", config.Window, time.Minute)
	}
	if config.MaxRequests != 100 {
		t.Errorf("MaxRequests = %d, want 100", config.MaxRequests)
	}
}

func TestRateLimiter_Allow(t *testing.T) {
	config := RateLimitConfig{
		Window:      time.Minute,
		MaxRequests: 5,
	}

	limiter := NewRateLimiter(config)
	defer limiter.Close()

	key := "test-key"

	// First 5 requests should be allowed
	for i := 0; i < 5; i++ {
		if !limiter.Allow(key) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	if limiter.Allow(key) {
		t.Error("6th request should be denied")
	}

	// Different key should be allowed
	if !limiter.Allow("different-key") {
		t.Error("Different key should be allowed")
	}
}

func TestRateLimiter_AllowN(t *testing.T) {
	config := RateLimitConfig{
		Window:      time.Minute,
		MaxRequests: 10,
	}

	limiter := NewRateLimiter(config)
	defer limiter.Close()

	key := "test-key"

	// Allow 5 requests at once
	if !limiter.AllowN(key, 5) {
		t.Error("AllowN(5) should succeed")
	}

	// Allow 5 more - should work (total = 10)
	if !limiter.AllowN(key, 5) {
		t.Error("AllowN(5) should succeed (total = 10)")
	}

	// Allow 1 more - should fail (would exceed 10)
	if limiter.AllowN(key, 1) {
		t.Error("AllowN(1) should fail (would exceed 10)")
	}
}

func TestRateLimiter_Remaining(t *testing.T) {
	config := RateLimitConfig{
		Window:      time.Minute,
		MaxRequests: 10,
	}

	limiter := NewRateLimiter(config)
	defer limiter.Close()

	key := "test-key"

	// Initial remaining should be max
	if got := limiter.Remaining(key); got != 10 {
		t.Errorf("Initial Remaining = %d, want 10", got)
	}

	// Use 3 requests
	for i := 0; i < 3; i++ {
		limiter.Allow(key)
	}

	// Remaining should be 7
	if got := limiter.Remaining(key); got != 7 {
		t.Errorf("Remaining after 3 requests = %d, want 7", got)
	}

	// Use all remaining
	for i := 0; i < 7; i++ {
		limiter.Allow(key)
	}

	// Remaining should be 0
	if got := limiter.Remaining(key); got != 0 {
		t.Errorf("Remaining after exhausted = %d, want 0", got)
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	config := RateLimitConfig{
		Window:      time.Minute,
		MaxRequests: 10,
	}

	limiter := NewRateLimiter(config)
	defer limiter.Close()

	key := "test-key"

	// For non-existent key, reset should be ~1 minute from now
	before := time.Now()
	reset := limiter.Reset(key)
	after := time.Now()

	if reset.Before(before.Add(time.Minute)) || reset.After(after.Add(time.Minute+time.Second)) {
		t.Errorf("Reset for new key should be ~1 minute from now, got %v", reset)
	}

	// Make a request to create entry
	limiter.Allow(key)

	// Reset should be when the entry expires
	reset = limiter.Reset(key)
	if reset.Before(before) || reset.After(after.Add(time.Minute+time.Second)) {
		t.Errorf("Reset for existing key unexpected: %v", reset)
	}
}

func TestRateLimiter_WindowExpiry(t *testing.T) {
	config := RateLimitConfig{
		Window:      50 * time.Millisecond, // Short window for testing
		MaxRequests: 2,
	}

	limiter := NewRateLimiter(config)
	defer limiter.Close()

	key := "test-key"

	// Use up the limit
	limiter.Allow(key)
	limiter.Allow(key)
	if limiter.Allow(key) {
		t.Error("3rd request should be denied")
	}

	// Wait for window to expire
	time.Sleep(60 * time.Millisecond)

	// Should be allowed again
	if !limiter.Allow(key) {
		t.Error("Request after window expiry should be allowed")
	}
}

func TestRateLimiter_Concurrent(t *testing.T) {
	config := RateLimitConfig{
		Window:      time.Minute,
		MaxRequests: 100,
	}

	limiter := NewRateLimiter(config)
	defer limiter.Close()

	key := "concurrent-key"

	var wg sync.WaitGroup
	allowed := make(chan bool, 150)

	// Start 150 concurrent requests
	for i := 0; i < 150; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			allowed <- limiter.Allow(key)
		}()
	}

	wg.Wait()
	close(allowed)

	// Count allowed and denied
	allowedCount := 0
	deniedCount := 0
	for a := range allowed {
		if a {
			allowedCount++
		} else {
			deniedCount++
		}
	}

	// Exactly 100 should be allowed
	if allowedCount != 100 {
		t.Errorf("Allowed = %d, want 100", allowedCount)
	}
	if deniedCount != 50 {
		t.Errorf("Denied = %d, want 50", deniedCount)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	config := RateLimitConfig{
		Window:      time.Minute,
		MaxRequests: 3,
	}

	limiter := NewRateLimiter(config)
	defer limiter.Close()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	middleware := limiter.RateLimitMiddleware(func(r *http.Request) string {
		return "test-key"
	})

	wrapped := middleware(handler)

	// First 3 requests should succeed
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: status = %d, want %d", i+1, rec.Code, http.StatusOK)
		}

		// Check rate limit headers
		if rec.Header().Get("X-RateLimit-Limit") != "3" {
			t.Errorf("X-RateLimit-Limit = %s, want 3", rec.Header().Get("X-RateLimit-Limit"))
		}
	}

	// 4th request should be rate limited
	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("4th request: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}

	// Should have Retry-After header
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Rate limited response should have Retry-After header")
	}
}

func TestIPKeyFunc(t *testing.T) {
	tests := []struct {
		name        string
		remoteAddr  string
		xff         string
		xRealIP     string
		expectedKey string
	}{
		{
			name:        "RemoteAddr only",
			remoteAddr:  "192.168.1.1:12345",
			expectedKey: "192.168.1.1:12345",
		},
		{
			name:        "X-Forwarded-For single",
			remoteAddr:  "127.0.0.1:80",
			xff:         "203.0.113.50",
			expectedKey: "203.0.113.50",
		},
		{
			name:        "X-Forwarded-For multiple",
			remoteAddr:  "127.0.0.1:80",
			xff:         "203.0.113.50, 70.41.3.18, 150.172.238.178",
			expectedKey: "203.0.113.50",
		},
		{
			name:        "X-Real-IP",
			remoteAddr:  "127.0.0.1:80",
			xRealIP:     "198.51.100.178",
			expectedKey: "198.51.100.178",
		},
		{
			name:        "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr:  "127.0.0.1:80",
			xff:         "203.0.113.50",
			xRealIP:     "198.51.100.178",
			expectedKey: "203.0.113.50",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := IPKeyFunc(req)
			if got != tt.expectedKey {
				t.Errorf("IPKeyFunc() = %s, want %s", got, tt.expectedKey)
			}
		})
	}
}

func TestPathIPKeyFunc(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/users", nil)
	req.RemoteAddr = "192.168.1.1:12345"

	got := PathIPKeyFunc(req)
	want := "/api/users:192.168.1.1:12345"

	if got != want {
		t.Errorf("PathIPKeyFunc() = %s, want %s", got, want)
	}
}

func TestRateLimiter_Close(t *testing.T) {
	config := RateLimitConfig{
		Window:      time.Minute,
		MaxRequests: 10,
	}

	limiter := NewRateLimiter(config)

	// Close should not panic
	limiter.Close()
}
