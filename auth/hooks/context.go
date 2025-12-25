package hooks

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// Context provides request/response context to hooks.
// It allows hooks to inspect and modify requests and responses.
type Context struct {
	// Request info
	Path    string         // e.g., "/sign-up", "/sign-in", "/oauth/google"
	Method  string         // HTTP method
	Body    map[string]any // Parsed request body (JSON)
	Headers http.Header    // Request headers
	Query   url.Values     // Query parameters
	Request *http.Request  // Raw request (for advanced use)

	// Auth context (populated if authenticated)
	Session *models.Session // Current session (if authenticated)
	User    *models.User    // Current user (if authenticated)

	// Utilities
	Context context.Context // Go context with values
	Store   models.Store    // Database access
	Secret  string          // Auth secret for token operations

	// Response control (for after hooks)
	Response any // The response that will be sent
	Returned any // Value returned from previous hook in chain

	// Internal
	writer    http.ResponseWriter
	bodyRead  bool
	rawBody   []byte
	responded bool
}

// NewContext creates a new Context from an HTTP request
func NewContext(w http.ResponseWriter, r *http.Request, path string) *Context {
	return &Context{
		Path:    path,
		Method:  r.Method,
		Headers: r.Header,
		Query:   r.URL.Query(),
		Request: r,
		Context: r.Context(),
		writer:  w,
	}
}

// ParseBody reads and parses the request body as JSON
func (c *Context) ParseBody() error {
	if c.bodyRead {
		return nil
	}
	c.bodyRead = true

	if c.Request.Body == nil {
		c.Body = make(map[string]any)
		return nil
	}

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.Body = make(map[string]any)
		return err
	}
	c.rawBody = body

	if len(body) == 0 {
		c.Body = make(map[string]any)
		return nil
	}

	c.Body = make(map[string]any)
	if err := json.Unmarshal(body, &c.Body); err != nil {
		// Not JSON, store empty map
		return nil
	}

	return nil
}

// RawBody returns the raw request body bytes
func (c *Context) RawBody() []byte {
	return c.rawBody
}

// JSON sends a JSON response with the given status code.
// This aborts the normal handler execution.
func (c *Context) JSON(status int, data any) error {
	c.responded = true
	c.writer.Header().Set("Content-Type", "application/json")
	c.writer.WriteHeader(status)
	return json.NewEncoder(c.writer).Encode(data)
}

// Redirect sends an HTTP redirect response.
// This aborts the normal handler execution.
func (c *Context) Redirect(url string, status int) {
	c.responded = true
	http.Redirect(c.writer, c.Request, url, status)
}

// SetHeader sets a response header
func (c *Context) SetHeader(key, value string) {
	c.writer.Header().Set(key, value)
}

// AddHeader adds a response header (doesn't replace existing)
func (c *Context) AddHeader(key, value string) {
	c.writer.Header().Add(key, value)
}

// GetCookie returns the value of a cookie, or empty string if not found
func (c *Context) GetCookie(name string) string {
	cookie, err := c.Request.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// SetCookie sets a cookie on the response
func (c *Context) SetCookie(cookie *http.Cookie) {
	http.SetCookie(c.writer, cookie)
}

// GetBodyString returns a string value from the parsed body
func (c *Context) GetBodyString(key string) string {
	if c.Body == nil {
		return ""
	}
	if v, ok := c.Body[key].(string); ok {
		return v
	}
	return ""
}

// GetBodyBool returns a bool value from the parsed body
func (c *Context) GetBodyBool(key string) bool {
	if c.Body == nil {
		return false
	}
	if v, ok := c.Body[key].(bool); ok {
		return v
	}
	return false
}

// GetQueryString returns a query parameter value
func (c *Context) GetQueryString(key string) string {
	return c.Query.Get(key)
}

// GetHeader returns a header value
func (c *Context) GetHeader(key string) string {
	return c.Headers.Get(key)
}

// HasResponded returns true if a response has been sent
func (c *Context) HasResponded() bool {
	return c.responded
}

// ClientIP returns the client's IP address
func (c *Context) ClientIP() string {
	// Check X-Forwarded-For first
	if xff := c.Headers.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP
	if xri := c.Headers.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return c.Request.RemoteAddr
}

// WithValue returns a new context with the given key-value pair
func (c *Context) WithValue(key, value any) {
	c.Context = context.WithValue(c.Context, key, value)
}

// Value returns the value for a key from the context
func (c *Context) Value(key any) any {
	return c.Context.Value(key)
}

// ResponseWriter returns the underlying http.ResponseWriter for advanced use cases
func (c *Context) ResponseWriter() http.ResponseWriter {
	return c.writer
}
