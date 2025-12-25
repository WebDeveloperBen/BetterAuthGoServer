// Package ratelimit provides rate limiting functionality as a plugin.
package ratelimit

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
)

// Config holds rate limiter configuration
type Config struct {
	// Window is the time window for rate limiting
	Window time.Duration

	// MaxRequests is the maximum requests allowed per window
	MaxRequests int

	// KeyFunc extracts the rate limit key from a request.
	// If nil, defaults to IPKeyFunc (or TrustedIPKeyFunc if TrustedProxies is set).
	KeyFunc func(r *http.Request) string

	// Backend is the rate limiter backend (e.g., Redis).
	// If nil, uses in-memory storage.
	Backend kv.RateLimiter

	// TrustedProxies is a list of IP addresses that are trusted to set
	// X-Forwarded-For and X-Real-IP headers. If empty, these headers are
	// always trusted (legacy behavior). If set, headers from untrusted
	// sources are ignored to prevent IP spoofing.
	TrustedProxies []string
}

// DefaultConfig returns default rate limit configuration
func DefaultConfig() Config {
	return Config{
		Window:      time.Minute,
		MaxRequests: 100,
		// KeyFunc is nil by default; New() will set RemoteAddrKeyFunc
		// unless TrustedProxies is configured
	}
}

// Limiter wraps a kv.RateLimiter with HTTP middleware support
type Limiter struct {
	config  Config
	limiter kv.RateLimiter
}

// New creates a new rate limiter
func New(opts ...Option) *Limiter {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	var backend kv.RateLimiter
	if cfg.Backend != nil {
		backend = cfg.Backend
	} else {
		backend = kv.NewMemoryRateLimiter()
	}

	// If no custom KeyFunc, use secure default that doesn't trust proxy headers
	// unless TrustedProxies is explicitly configured
	if cfg.KeyFunc == nil {
		if len(cfg.TrustedProxies) > 0 {
			cfg.KeyFunc = MakeTrustedIPKeyFunc(cfg.TrustedProxies)
		} else {
			// Secure by default: don't trust any proxy headers
			cfg.KeyFunc = RemoteAddrKeyFunc
		}
	}

	return &Limiter{
		config:  cfg,
		limiter: backend,
	}
}

// Option is a functional option for configuring the rate limiter
type Option func(*Config)

// WithWindow sets the time window for rate limiting
func WithWindow(d time.Duration) Option {
	return func(c *Config) {
		c.Window = d
	}
}

// WithMaxRequests sets the maximum requests per window
func WithMaxRequests(max int) Option {
	return func(c *Config) {
		c.MaxRequests = max
	}
}

// WithLimit sets both window and max requests
func WithLimit(max int, window time.Duration) Option {
	return func(c *Config) {
		c.MaxRequests = max
		c.Window = window
	}
}

// WithKeyFunc sets the key extraction function
func WithKeyFunc(fn func(r *http.Request) string) Option {
	return func(c *Config) {
		c.KeyFunc = fn
	}
}

// WithBackend sets a custom rate limiter backend (e.g., Redis)
func WithBackend(backend kv.RateLimiter) Option {
	return func(c *Config) {
		c.Backend = backend
	}
}

// WithTrustedProxies sets the trusted proxies for X-Forwarded-For/X-Real-IP.
// When set, only requests from these IPs will have their proxy headers trusted.
// This prevents IP spoofing attacks where clients send fake X-Forwarded-For.
func WithTrustedProxies(proxies []string) Option {
	return func(c *Config) {
		c.TrustedProxies = proxies
	}
}

// Allow checks if a request is allowed for the given key
// Returns true if allowed, false if rate limit exceeded
func (l *Limiter) Allow(key string) bool {
	return l.AllowN(key, 1)
}

// AllowN checks if n requests are allowed for the given key
func (l *Limiter) AllowN(key string, n int) bool {
	ctx := context.Background()
	result, err := l.limiter.Allow(ctx, key, l.config.MaxRequests, l.config.Window, n)
	if err != nil {
		// On error, allow the request (fail open)
		return true
	}
	return result.Allowed
}

// Remaining returns the number of requests remaining for the given key
func (l *Limiter) Remaining(key string) int {
	ctx := context.Background()
	result, err := l.limiter.Allow(ctx, key, l.config.MaxRequests, l.config.Window, 0)
	if err != nil {
		return l.config.MaxRequests
	}
	return result.Remaining
}

// Reset returns when the rate limit resets for the given key
func (l *Limiter) Reset(key string) time.Time {
	ctx := context.Background()
	result, err := l.limiter.Allow(ctx, key, l.config.MaxRequests, l.config.Window, 0)
	if err != nil {
		return time.Now().Add(l.config.Window)
	}
	return result.ResetAt
}

// Close stops the rate limiter and releases resources
func (l *Limiter) Close() error {
	if l.limiter != nil {
		l.limiter.Close()
	}
	return nil
}

// Config returns the limiter configuration
func (l *Limiter) Config() Config {
	return l.config
}

// Middleware returns HTTP middleware that applies rate limiting
func (l *Limiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := l.config.KeyFunc(r)

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

// RemoteAddrKeyFunc returns the remote address as the rate limit key.
// This is the secure default that doesn't trust any proxy headers.
func RemoteAddrKeyFunc(r *http.Request) string {
	// Extract IP without port from RemoteAddr
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}
	return remoteIP
}

// IPKeyFunc returns the client IP address as the rate limit key.
// WARNING: This trusts X-Forwarded-For and X-Real-IP headers unconditionally.
// Only use this if you trust all incoming requests (e.g., behind a reverse proxy
// that strips client-provided headers). For most cases, use MakeTrustedIPKeyFunc
// or RemoteAddrKeyFunc instead.
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

// MakeTrustedIPKeyFunc creates a key function that only trusts proxy headers
// from the specified trusted proxy IPs. This prevents IP spoofing attacks.
func MakeTrustedIPKeyFunc(trustedProxies []string) func(r *http.Request) string {
	// Build a set for O(1) lookup
	trusted := make(map[string]bool, len(trustedProxies))
	for _, ip := range trustedProxies {
		trusted[ip] = true
	}

	return func(r *http.Request) string {
		return getClientIP(r, trusted)
	}
}

// MakePathTrustedIPKeyFunc creates a composite key function using path and trusted IP
func MakePathTrustedIPKeyFunc(trustedProxies []string) func(r *http.Request) string {
	ipKeyFunc := MakeTrustedIPKeyFunc(trustedProxies)
	return func(r *http.Request) string {
		return r.URL.Path + ":" + ipKeyFunc(r)
	}
}

// getClientIP extracts the client IP, only trusting proxy headers from trusted sources
func getClientIP(r *http.Request, trusted map[string]bool) string {
	// Extract IP without port from RemoteAddr
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	// Only trust X-Forwarded-For if the request came from a trusted proxy
	if trusted[remoteIP] {
		// Request is from trusted proxy, check X-Forwarded-For
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			// Take the first IP (client IP)
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		// Check X-Real-IP
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return strings.TrimSpace(xri)
		}
	}

	// Return IP without port (don't trust headers from untrusted sources)
	return remoteIP
}
