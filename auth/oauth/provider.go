package oauth

import (
	"context"

	"golang.org/x/oauth2"
)

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
