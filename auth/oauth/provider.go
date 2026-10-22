// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"context"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
	"golang.org/x/oauth2"
)

// AuthProvider defines the auth operations required by the OAuth plugin.
// The main Auth struct implements this interface.
type AuthProvider interface {
	// GetPluginUser retrieves a user by ID
	GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)

	// GetPluginUserByEmail retrieves a user by email.
	// Must return an error matching models.ErrUserNotFound when no user has the email.
	GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error)

	// CreatePluginUserTx creates a new user and runs fn in the same unit of work.
	// fn receives the database transaction (nil when the store has no transaction
	// support); if fn fails, no user is left behind.
	CreatePluginUserTx(ctx context.Context, req plugin.CreateUserRequest, fn func(ctx context.Context, tx db.DBTX, user *plugin.User) error) (*plugin.User, error)

	// GetPluginSessionFromRequest validates the session carried by the request.
	// Returns nil, nil when the request carries no valid session.
	GetPluginSessionFromRequest(r *http.Request) (*plugin.Session, error)

	// CreateSessionForUser creates a new session for the given user
	CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error)

	// FireOAuthAccountLinked fires the hook when an OAuth account is linked
	FireOAuthAccountLinked(ctx context.Context, userID, provider, providerAccountID string) error

	// BaseURL returns the configured base URL (used for secure cookie check)
	BaseURL() string
}

// Provider defines the interface for OAuth2 providers
type Provider interface {
	// Name returns the provider name (e.g., "google", "github")
	Name() string

	// Config returns the OAuth2 configuration
	Config() *oauth2.Config

	// GetUserInfo fetches user information from the provider
	GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error)

	// RequiresPKCE returns whether this provider requires PKCE
	RequiresPKCE() bool
}

// UserInfo contains user information from an OAuth provider
type UserInfo struct {
	ID            string
	Email         string
	EmailVerified bool
	Name          string
	Picture       string
}

// AuthStart contains the data needed to begin an OAuth flow
type AuthStart struct {
	URL      string
	State    string
	Verifier string // PKCE code verifier, if applicable
}

// AuthResult contains the result of completing an OAuth flow
type AuthResult struct {
	UserInfo   *UserInfo
	OAuthToken *oauth2.Token
	IsNewUser  bool
}
