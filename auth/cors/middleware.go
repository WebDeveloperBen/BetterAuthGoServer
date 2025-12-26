// Package cors provides CORS middleware as a plugin.
package cors

import (
	"net/http"
	"strings"
)

// Config holds CORS middleware configuration
type Config struct {
	// TrustedOrigins is the list of allowed origins.
	// Requests from these origins will receive CORS headers.
	TrustedOrigins []string

	// AllowMethods is the list of allowed HTTP methods.
	// Default: GET, POST, PUT, PATCH, DELETE, OPTIONS
	AllowMethods []string

	// AllowHeaders is the list of allowed request headers.
	// Default: Content-Type, Authorization
	AllowHeaders []string

	// ExposeHeaders is the list of headers that browsers can access.
	// Default: Set-Cookie
	ExposeHeaders []string

	// AllowCredentials indicates whether credentials (cookies, auth) are allowed.
	// Default: true
	AllowCredentials bool

	// MaxAge is the max age (in seconds) for preflight request caching.
	// Default: 86400 (24 hours)
	MaxAge int

	// BaseURL is the auth service base URL.
	// Requests from this origin are automatically trusted.
	BaseURL string
}

// DefaultConfig returns default CORS configuration
func DefaultConfig() Config {
	return Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type", "Authorization", "X-CSRF-Token"},
		ExposeHeaders:    []string{"Set-Cookie"},
		AllowCredentials: true,
		MaxAge:           86400,
	}
}

// CORS provides CORS middleware
type CORS struct {
	config Config
}

// New creates a new CORS middleware with the given options
func New(opts ...Option) *CORS {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	return &CORS{
		config: cfg,
	}
}

// Option is a functional option for configuring the CORS middleware
type Option func(*Config)

// WithOrigins sets the trusted origins
func WithOrigins(origins ...string) Option {
	return func(c *Config) {
		c.TrustedOrigins = origins
	}
}

// WithMethods sets the allowed HTTP methods
func WithMethods(methods ...string) Option {
	return func(c *Config) {
		c.AllowMethods = methods
	}
}

// WithHeaders sets the allowed request headers
func WithHeaders(headers ...string) Option {
	return func(c *Config) {
		c.AllowHeaders = headers
	}
}

// WithExposeHeaders sets the headers that browsers can access
func WithExposeHeaders(headers ...string) Option {
	return func(c *Config) {
		c.ExposeHeaders = headers
	}
}

// WithCredentials sets whether credentials are allowed
func WithCredentials(allow bool) Option {
	return func(c *Config) {
		c.AllowCredentials = allow
	}
}

// WithMaxAge sets the preflight cache max age in seconds
func WithMaxAge(seconds int) Option {
	return func(c *Config) {
		c.MaxAge = seconds
	}
}

// WithBaseURL sets the base URL (its origin is auto-trusted)
func WithBaseURL(url string) Option {
	return func(c *Config) {
		c.BaseURL = url
	}
}

// Config returns the CORS configuration
func (c *CORS) Config() Config {
	return c.config
}

// Middleware returns the CORS middleware handler
func (c *CORS) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is trusted
			if c.isOriginTrusted(origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)

				if c.config.AllowCredentials {
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}

				w.Header().Set("Access-Control-Allow-Methods", strings.Join(c.config.AllowMethods, ", "))
				w.Header().Set("Access-Control-Allow-Headers", strings.Join(c.config.AllowHeaders, ", "))

				if len(c.config.ExposeHeaders) > 0 {
					w.Header().Set("Access-Control-Expose-Headers", strings.Join(c.config.ExposeHeaders, ", "))
				}

				if c.config.MaxAge > 0 {
					w.Header().Set("Access-Control-Max-Age", formatInt(c.config.MaxAge))
				}
			}

			// Handle preflight
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isOriginTrusted checks if an origin is in the trusted origins list
func (c *CORS) isOriginTrusted(origin string) bool {
	if origin == "" {
		return false
	}

	for _, trusted := range c.config.TrustedOrigins {
		if origin == trusted {
			return true
		}
	}

	// Also check if it matches the base URL
	if c.config.BaseURL != "" && strings.HasPrefix(c.config.BaseURL, origin) {
		return true
	}

	return false
}

// formatInt converts an int to string without importing strconv
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}

	var result []byte
	for n > 0 {
		result = append([]byte{byte('0' + n%10)}, result...)
		n /= 10
	}
	return string(result)
}
