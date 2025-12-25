package auth

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// RateLimitConfig holds rate limiter configuration
type RateLimitConfig struct {
	Window          time.Duration // Time window for rate limiting
	MaxRequests     int           // Maximum requests per window
	CleanupInterval time.Duration // How often to clean up expired entries
}

// DefaultRateLimitConfig returns default rate limit configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Window:          time.Minute,
		MaxRequests:     100,
		CleanupInterval: 5 * time.Minute,
	}
}

// rateLimitEntry represents a rate limit entry for a single key
type rateLimitEntry struct {
	count     int
	expiresAt time.Time
}

// RateLimiter is an in-memory rate limiter
type RateLimiter struct {
	config  RateLimitConfig
	entries map[string]*rateLimitEntry
	mu      sync.RWMutex
	stopCh  chan struct{}
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	l := &RateLimiter{
		config:  config,
		entries: make(map[string]*rateLimitEntry),
		stopCh:  make(chan struct{}),
	}

	// Start cleanup goroutine
	go l.cleanup()

	return l
}

// Allow checks if a request is allowed for the given key
// Returns true if allowed, false if rate limit exceeded
func (l *RateLimiter) Allow(key string) bool {
	return l.AllowN(key, 1)
}

// AllowN checks if n requests are allowed for the given key
func (l *RateLimiter) AllowN(key string, n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	e, exists := l.entries[key]
	if !exists || now.After(e.expiresAt) {
		// Create new entry
		l.entries[key] = &rateLimitEntry{
			count:     n,
			expiresAt: now.Add(l.config.Window),
		}
		return true
	}

	// Check if adding n would exceed limit
	if e.count+n > l.config.MaxRequests {
		return false
	}

	e.count += n
	return true
}

// Remaining returns the number of requests remaining for the given key
func (l *RateLimiter) Remaining(key string) int {
	l.mu.RLock()
	defer l.mu.RUnlock()

	now := time.Now()

	e, exists := l.entries[key]
	if !exists || now.After(e.expiresAt) {
		return l.config.MaxRequests
	}

	remaining := l.config.MaxRequests - e.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Reset returns when the rate limit resets for the given key
func (l *RateLimiter) Reset(key string) time.Time {
	l.mu.RLock()
	defer l.mu.RUnlock()

	e, exists := l.entries[key]
	if !exists {
		return time.Now().Add(l.config.Window)
	}
	return e.expiresAt
}

// cleanup periodically removes expired entries
func (l *RateLimiter) cleanup() {
	ticker := time.NewTicker(l.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			l.cleanupExpired()
		case <-l.stopCh:
			return
		}
	}
}

// cleanupExpired removes all expired entries
func (l *RateLimiter) cleanupExpired() {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	for key, e := range l.entries {
		if now.After(e.expiresAt) {
			delete(l.entries, key)
		}
	}
}

// Close stops the cleanup goroutine
func (l *RateLimiter) Close() {
	close(l.stopCh)
}

// RateLimitMiddleware returns HTTP middleware that applies rate limiting
func (l *RateLimiter) RateLimitMiddleware(keyFunc func(r *http.Request) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := keyFunc(r)

			if !l.Allow(key) {
				w.Header().Set("Retry-After", l.Reset(key).Format(time.RFC1123))
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			// Set rate limit headers
			remaining := l.Remaining(key)
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(l.config.MaxRequests))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))

			next.ServeHTTP(w, r)
		})
	}
}

// IPKeyFunc returns the client IP address as the rate limit key
func IPKeyFunc(r *http.Request) string {
	// Check X-Forwarded-For first
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}

// PathIPKeyFunc returns a composite key of path and IP
func PathIPKeyFunc(r *http.Request) string {
	return r.URL.Path + ":" + IPKeyFunc(r)
}
