package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

const (
	githubUserURL   = "https://api.github.com/user"
	githubEmailsURL = "https://api.github.com/user/emails"
)

// GitHubProvider implements the Provider interface for GitHub OAuth
type GitHubProvider struct {
	config *oauth2.Config
}

// NewGitHub creates a new GitHub OAuth provider
func NewGitHub(clientID, clientSecret, redirectURL string) *GitHubProvider {
	return &GitHubProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"user:email",
				"read:user",
			},
			Endpoint: github.Endpoint,
		},
	}
}

// Name returns the provider name
func (p *GitHubProvider) Name() string {
	return "github"
}

// Config returns the OAuth2 configuration
func (p *GitHubProvider) Config() *oauth2.Config {
	return p.config
}

// RequiresPKCE returns whether this provider requires PKCE
func (p *GitHubProvider) RequiresPKCE() bool {
	return false
}

// githubUser represents the response from GitHub's user endpoint
type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// githubEmail represents an email from GitHub's emails endpoint
type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// GetUserInfo fetches user information from GitHub
func (p *GitHubProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := p.config.Client(ctx, token)

	// Get user info
	userResp, err := client.Get(githubUserURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userResp.Body)
		return nil, fmt.Errorf("github api error: %s", string(body))
	}

	var user githubUser
	if err := json.NewDecoder(userResp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Get primary verified email
	email, emailVerified, err := p.getPrimaryEmail(ctx, client)
	if err != nil {
		// Fall back to user email if available
		email = user.Email
		emailVerified = false
	}

	name := user.Name
	if name == "" {
		name = user.Login
	}

	return &UserInfo{
		ID:            strconv.FormatInt(user.ID, 10),
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		Picture:       user.AvatarURL,
	}, nil
}

// getPrimaryEmail fetches the primary verified email from GitHub
func (p *GitHubProvider) getPrimaryEmail(ctx context.Context, client *http.Client) (string, bool, error) {
	resp, err := client.Get(githubEmailsURL)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("failed to get emails")
	}

	var emails []githubEmail
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, err
	}

	// Find primary verified email
	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, true, nil
		}
	}

	// Fall back to any verified email
	for _, e := range emails {
		if e.Verified {
			return e.Email, true, nil
		}
	}

	// Fall back to primary email (unverified)
	for _, e := range emails {
		if e.Primary {
			return e.Email, false, nil
		}
	}

	// Fall back to first email
	if len(emails) > 0 {
		return emails[0].Email, emails[0].Verified, nil
	}

	return "", false, fmt.Errorf("no email found")
}
