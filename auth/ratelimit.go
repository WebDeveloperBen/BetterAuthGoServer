package auth

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
)

// RateLimitConfig holds rate limiter configuration
type RateLimitConfig struct {
	Window      time.Duration // Time window for rate limiting
	MaxRequests int           // Maximum requests per window
}

// DefaultRateLimitConfig returns default rate limit configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		Window:      time.Minute,
		MaxRequests: 100,
	}
}

// RateLimiter wraps a kv.RateLimiter with HTTP middleware support
type RateLimiter struct {
	config  RateLimitConfig
	limiter kv.RateLimiter
}

// NewRateLimiter creates a new rate limiter using in-memory storage
func NewRateLimiter(config RateLimitConfig) *RateLimiter {
	return &RateLimiter{
		config:  config,
		limiter: kv.NewMemoryRateLimiter(),
	}
}

// NewRateLimiterWithBackend creates a rate limiter with a custom backend
func NewRateLimiterWithBackend(config RateLimitConfig, limiter kv.RateLimiter) *RateLimiter {
	return &RateLimiter{
		config:  config,
		limiter: limiter,
	}
}

// Allow checks if a request is allowed for the given key
// Returns true if allowed, false if rate limit exceeded
func (l *RateLimiter) Allow(key string) bool {
	return l.AllowN(key, 1)
}

// AllowN checks if n requests are allowed for the given key
func (l *RateLimiter) AllowN(key string, n int) bool {
	ctx := context.Background()
	result, err := l.limiter.Allow(ctx, key, l.config.MaxRequests, l.config.Window, n)
	if err != nil {
		// On error, allow the request (fail open)
		return true
	}
	return result.Allowed
}

// Remaining returns the number of requests remaining for the given key
func (l *RateLimiter) Remaining(key string) int {
	ctx := context.Background()
	result, err := l.limiter.Allow(ctx, key, l.config.MaxRequests, l.config.Window, 0)
	if err != nil {
		return l.config.MaxRequests
	}
	return result.Remaining
}

// Reset returns when the rate limit resets for the given key
func (l *RateLimiter) Reset(key string) time.Time {
	ctx := context.Background()
	result, err := l.limiter.Allow(ctx, key, l.config.MaxRequests, l.config.Window, 0)
	if err != nil {
		return time.Now().Add(l.config.Window)
	}
	return result.ResetAt
}

// Close stops the rate limiter
func (l *RateLimiter) Close() {
	if l.limiter != nil {
		l.limiter.Close()
	}
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
