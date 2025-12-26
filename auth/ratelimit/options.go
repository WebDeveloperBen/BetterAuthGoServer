package ratelimit

import (
	"net/http"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
)

// Config holds rate limiter configuration.
type Config struct {
	// Window is the time window for rate limiting.
	Window time.Duration

	// MaxRequests is the maximum requests allowed per window.
	MaxRequests int

	// KeyFunc extracts the rate limit key from a request.
	// If nil, defaults to RemoteAddrKeyFunc (or TrustedIPKeyFunc if TrustedProxies is set).
	KeyFunc func(r *http.Request) string

	// Backend is the rate limiter backend (e.g., Redis).
	// If nil, uses in-memory storage.
	//
	// For clustered deployments, use a shared backend like Redis:
	//
	//   import kvredis "github.com/webdeveloperben/BetterAuthGoServer/auth/kv/redis"
	//
	//   redisStore := kvredis.NewStore(&redis.Options{Addr: "localhost:6379"})
	//   ratelimit.NewPlugin(
	//       ratelimit.WithBackend(kvredis.NewRateLimiter(redisStore)),
	//   )
	Backend kv.RateLimiter

	// TrustedProxies is a list of IP addresses that are trusted to set
	// X-Forwarded-For and X-Real-IP headers. If empty, these headers are
	// ignored and only RemoteAddr is used (secure by default).
	// If set, headers from trusted proxies are used to determine client IP.
	TrustedProxies []string
}

// DefaultConfig returns default rate limit configuration.
func DefaultConfig() Config {
	return Config{
		Window:      time.Minute,
		MaxRequests: 100,
		// KeyFunc is nil by default; Limiter.init() will set RemoteAddrKeyFunc
		// unless TrustedProxies is configured
	}
}

// Option is a functional option for configuring the rate limiter.
type Option func(*Config)

// WithWindow sets the time window for rate limiting.
func WithWindow(d time.Duration) Option {
	return func(c *Config) {
		c.Window = d
	}
}

// WithMaxRequests sets the maximum requests per window.
func WithMaxRequests(max int) Option {
	return func(c *Config) {
		c.MaxRequests = max
	}
}

// WithLimit sets both window and max requests.
func WithLimit(max int, window time.Duration) Option {
	return func(c *Config) {
		c.MaxRequests = max
		c.Window = window
	}
}

// WithKeyFunc sets the key extraction function.
func WithKeyFunc(fn func(r *http.Request) string) Option {
	return func(c *Config) {
		c.KeyFunc = fn
	}
}

// WithBackend sets a custom rate limiter backend.
//
// For single-instance deployments, the default in-memory backend is sufficient.
// For clustered deployments, use a shared backend like Redis:
//
//	import kvredis "github.com/webdeveloperben/BetterAuthGoServer/auth/kv/redis"
//
//	redisStore := kvredis.NewStore(&redis.Options{Addr: "localhost:6379"})
//	ratelimit.NewPlugin(
//	    ratelimit.WithBackend(kvredis.NewRateLimiter(redisStore)),
//	)
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
