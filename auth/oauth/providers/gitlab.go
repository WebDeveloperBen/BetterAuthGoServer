// Package providers implements OAuth2 provider integrations for GitLab.
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"golang.org/x/oauth2"
)

const (
	// DefaultGitLabBaseURL is the base URL of GitLab.com.
	DefaultGitLabBaseURL = "https://gitlab.com"
	gitlabTimeout        = 10 * time.Second
)

// GitLabProvider implements the Provider interface for GitLab (GitLab.com or self-managed)
// using GitLab's OpenID Connect userinfo endpoint.
type GitLabProvider struct {
	config  *oauth2.Config
	baseURL string
}

// GitLabOption is a functional option for configuring the GitLab provider.
type GitLabOption func(*GitLabProvider)

// WithGitLabBaseURL sets the base URL of a self-managed GitLab instance,
// e.g. "https://gitlab.example.com". Defaults to DefaultGitLabBaseURL.
func WithGitLabBaseURL(baseURL string) GitLabOption {
	return func(p *GitLabProvider) {
		p.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// NewGitLab creates a new GitLab OAuth provider.
// The GitLab application needs the "openid", "profile" and "email" scopes.
func NewGitLab(clientID, clientSecret, redirectURL string, opts ...GitLabOption) *GitLabProvider {
	p := &GitLabProvider{baseURL: DefaultGitLabBaseURL}
	for _, opt := range opts {
		opt(p)
	}
	if p.baseURL == "" {
		p.baseURL = DefaultGitLabBaseURL
	}

	p.config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes: []string{
			"openid",
			"profile",
			"email",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.baseURL + "/oauth/authorize",
			TokenURL: p.baseURL + "/oauth/token",
		},
	}
	return p
}

// Name returns the provider name
func (p *GitLabProvider) Name() string {
	return "gitlab"
}

// Config returns the OAuth2 configuration
func (p *GitLabProvider) Config() *oauth2.Config {
	return p.config
}

// RequiresPKCE returns whether this provider requires PKCE.
// GitLab supports PKCE (S256) for all applications.
func (p *GitLabProvider) RequiresPKCE() bool {
	return true
}

// BaseURL returns the configured GitLab base URL.
func (p *GitLabProvider) BaseURL() string {
	return p.baseURL
}

// gitlabUserInfo represents the response from GitLab's OIDC userinfo endpoint.
type gitlabUserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	Nickname      string `json:"nickname"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Picture       string `json:"picture"`
}

// GetUserInfo fetches user information from GitLab's OIDC userinfo endpoint.
// EmailVerified mirrors GitLab's email_verified claim.
func (p *GitLabProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*oauth.UserInfo, error) {
	client := p.config.Client(ctx, token)
	if client.Timeout == 0 {
		client.Timeout = gitlabTimeout
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.baseURL+"/oauth/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build user info request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gitlab api error (status %d): %s", resp.StatusCode, string(body))
	}

	var info gitlabUserInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}
	if info.Sub == "" {
		return nil, fmt.Errorf("gitlab user info missing sub claim")
	}

	name := info.Name
	if name == "" {
		name = info.Nickname
	}

	return &oauth.UserInfo{
		ID:            info.Sub,
		Email:         info.Email,
		EmailVerified: info.Email != "" && info.EmailVerified,
		Name:          name,
		Picture:       info.Picture,
	}, nil
}
