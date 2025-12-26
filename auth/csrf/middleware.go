// Package csrf provides CSRF protection as a plugin.
package csrf

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// Config holds CSRF middleware configuration
type Config struct {
	// CookieName is the name of the CSRF cookie.
	// Default: "csrf_token"
	CookieName string

	// HeaderName is the name of the CSRF header.
	// Default: "X-CSRF-Token"
	HeaderName string

	// Secure sets the Secure flag on the CSRF cookie.
	// If not set, it's automatically determined from BaseURL.
	Secure *bool

	// BaseURL is used to determine if cookies should be secure.
	// If it starts with "https://", Secure will be true.
	BaseURL string

	// SameSite sets the SameSite attribute on the CSRF cookie.
	// Default: http.SameSiteStrictMode
	SameSite http.SameSite

	// ErrorHandler is called when CSRF validation fails.
	// If nil, a default error response is written.
	ErrorHandler func(w http.ResponseWriter, r *http.Request, err error)
}

// DefaultConfig returns default CSRF configuration
func DefaultConfig() Config {
	return Config{
		CookieName: "csrf_token",
		HeaderName: "X-CSRF-Token",
		SameSite:   http.SameSiteStrictMode,
	}
}

// CSRF provides CSRF protection middleware
type CSRF struct {
	config Config
}

// New creates a new CSRF middleware
func New(opts ...Option) *CSRF {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	return &CSRF{
		config: cfg,
	}
}

// Option is a functional option for configuring the CSRF middleware
type Option func(*Config)

// WithCookieName sets the CSRF cookie name
func WithCookieName(name string) Option {
	return func(c *Config) {
		c.CookieName = name
	}
}

// WithHeaderName sets the CSRF header name
func WithHeaderName(name string) Option {
	return func(c *Config) {
		c.HeaderName = name
	}
}

// WithSecure sets whether the cookie should have the Secure flag
func WithSecure(secure bool) Option {
	return func(c *Config) {
		c.Secure = &secure
	}
}

// WithBaseURL sets the base URL for determining secure cookies
func WithBaseURL(url string) Option {
	return func(c *Config) {
		c.BaseURL = url
	}
}

// WithSameSite sets the SameSite attribute for the cookie
func WithSameSite(sameSite http.SameSite) Option {
	return func(c *Config) {
		c.SameSite = sameSite
	}
}

// WithErrorHandler sets a custom error handler for CSRF failures
func WithErrorHandler(handler func(w http.ResponseWriter, r *http.Request, err error)) Option {
	return func(c *Config) {
		c.ErrorHandler = handler
	}
}

// Config returns the CSRF configuration
func (c *CSRF) Config() Config {
	return c.config
}

// Middleware returns the CSRF protection middleware
func (c *CSRF) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip CSRF for safe methods
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				// Set CSRF token cookie if not present
				c.ensureCookie(w, r)
				next.ServeHTTP(w, r)
				return
			}

			// Validate CSRF token for state-changing methods
			cookieToken := c.getCookie(r)
			headerToken := r.Header.Get(c.config.HeaderName)

			if cookieToken == "" {
				c.handleError(w, r, ErrTokenMissing)
				return
			}

			if headerToken == "" {
				c.handleError(w, r, ErrTokenMissing)
				return
			}

			// Constant-time comparison
			if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
				c.handleError(w, r, ErrTokenMismatch)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ensureCookie sets a CSRF cookie if not present
func (c *CSRF) ensureCookie(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(c.config.CookieName); err == nil {
		return // Cookie already exists
	}

	csrfToken, err := token.Generate()
	if err != nil {
		return
	}

	secure := c.isSecure()

	http.SetCookie(w, &http.Cookie{
		Name:     c.config.CookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false, // Must be readable by JavaScript
		Secure:   secure,
		SameSite: c.config.SameSite,
	})
}

// getCookie retrieves the CSRF token from the cookie
func (c *CSRF) getCookie(r *http.Request) string {
	cookie, err := r.Cookie(c.config.CookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// isSecure determines if the cookie should have the Secure flag
func (c *CSRF) isSecure() bool {
	if c.config.Secure != nil {
		return *c.config.Secure
	}
	return strings.HasPrefix(c.config.BaseURL, "https://")
}

// handleError handles CSRF validation errors
func (c *CSRF) handleError(w http.ResponseWriter, r *http.Request, err error) {
	if c.config.ErrorHandler != nil {
		c.config.ErrorHandler(w, r, err)
		return
	}

	// Default error response
	http.Error(w, err.Error(), http.StatusForbidden)
}

// HeaderName returns the CSRF header name for use in CORS configuration
func (c *CSRF) HeaderName() string {
	return c.config.HeaderName
}
