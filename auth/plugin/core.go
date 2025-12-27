package plugin

import (
	"context"
	"net/http"
	"time"
)

// AuthCore provides plugins access to minimal core auth configuration.
// This interface is intentionally minimal - plugins should define their own
// interfaces for the specific auth operations they need, then type-assert
// to access those operations.
//
// Example:
//
//	type MyAuthProvider interface {
//	    GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)
//	}
//
//	provider, ok := ctx.Auth.(MyAuthProvider)
//	if !ok {
//	    return errors.New("auth doesn't support required operations")
//	}
type AuthCore interface {
	// BaseURL returns the configured base URL of the auth service
	BaseURL() string

	// Secret returns the auth secret key
	Secret() string
}

// CreateUserRequest contains the data needed to create a user from a plugin.
// This is used by OAuth and other plugins that need to create users.
type CreateUserRequest struct {
	Email         string
	Name          string
	EmailVerified bool
	Image         *string
}

// User is a minimal user representation for plugins.
// This avoids plugins depending on the full models package.
type User struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Image         *string
	Role          string
	Banned        bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Session is a minimal session representation for plugins.
type Session struct {
	ID        string
	UserID    string
	IPAddress *string
	UserAgent *string
	CreatedAt time.Time
	ExpiresAt time.Time
	// ImpersonatedBy is the user ID of the admin who started this impersonation session.
	// If nil, this is a regular session (not impersonation).
	ImpersonatedBy *string
	// RawToken is the unhashed session token, needed for setting cookies.
	// Only populated when a new session is created.
	RawToken string
}

// SessionInfo is a minimal session info for plugins that only need ID and UserID.
// This is used by password plugin's SessionGetter interface.
type SessionInfo struct {
	ID     string
	UserID string
}

// IsExpired returns true if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsImpersonation returns true if this session is an impersonation session
func (s *Session) IsImpersonation() bool {
	return s.ImpersonatedBy != nil
}

// SessionManager provides session operations for plugins.
// This allows plugins to create, retrieve, and manage sessions without
// directly depending on the auth package internals.
type SessionManager interface {
	// GetFromRequest extracts the current session from an HTTP request context.
	// Returns nil if no session is present.
	GetFromRequest(r *http.Request) *Session

	// Create creates a new session for a user.
	// The request is used to extract IP address and user agent.
	Create(ctx context.Context, userID string, r *http.Request) (*Session, error)

	// CreateWithImpersonation creates an impersonation session where an admin
	// is acting as another user. The impersonatedBy parameter is the admin's user ID.
	CreateWithImpersonation(ctx context.Context, targetUserID, impersonatedBy string, r *http.Request, duration time.Duration) (*Session, error)

	// Get retrieves a session by ID.
	// Returns nil if the session doesn't exist.
	Get(ctx context.Context, sessionID string) (*Session, error)

	// Delete removes a session by ID.
	Delete(ctx context.Context, sessionID string) error

	// WriteAuthResponse writes authentication credentials to the response.
	// If JWT plugin is registered, returns JWT tokens in response body.
	// Otherwise, sets a session cookie.
	// Context is required for database-backed JWT key operations.
	WriteAuthResponse(ctx context.Context, w http.ResponseWriter, session *Session, user *User) error

	// ClearAuthResponse clears authentication credentials.
	// Clears the session cookie. For JWT, clients discard tokens themselves.
	ClearAuthResponse(w http.ResponseWriter)

	// GetSessionToken returns the raw session token from the request cookie.
	// Used for impersonation to store the admin's token for later restoration.
	GetSessionToken(r *http.Request) string

	// SetSessionCookie sets the session cookie directly.
	// Used for impersonation restoration where we already have the token.
	SetSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time)
}

// TokenPair represents JWT access and refresh tokens.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// JWTTokenGenerator is implemented by plugins that can generate JWT tokens.
// The JWT plugin implements this interface.
type JWTTokenGenerator interface {
	// GenerateTokensForSession generates JWT tokens for a session.
	// Context is required for database-backed key operations.
	GenerateTokensForSession(ctx context.Context, session *Session, user *User) (*TokenPair, error)
}
