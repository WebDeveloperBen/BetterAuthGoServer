package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

var discordEndpoint = oauth2.Endpoint{
	AuthURL:  "https://discord.com/api/oauth2/authorize",
	TokenURL: "https://discord.com/api/oauth2/token",
}

const discordUserURL = "https://discord.com/api/users/@me"

// DiscordProvider implements the Provider interface for Discord OAuth
type DiscordProvider struct {
	config *oauth2.Config
}

// NewDiscord creates a new Discord OAuth provider
func NewDiscord(clientID, clientSecret, redirectURL string) *DiscordProvider {
	return &DiscordProvider{
		config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes: []string{
				"identify",
				"email",
			},
			Endpoint: discordEndpoint,
		},
	}
}

// Name returns the provider name
func (p *DiscordProvider) Name() string {
	return "discord"
}

// Config returns the OAuth2 configuration
func (p *DiscordProvider) Config() *oauth2.Config {
	return p.config
}

// RequiresPKCE returns whether this provider requires PKCE
func (p *DiscordProvider) RequiresPKCE() bool {
	return false
}

// discordUser represents the response from Discord's user endpoint
type discordUser struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Discriminator string `json:"discriminator"`
	GlobalName    string `json:"global_name"`
	Email         string `json:"email"`
	Verified      bool   `json:"verified"`
	Avatar        string `json:"avatar"`
}

// GetUserInfo fetches user information from Discord
func (p *DiscordProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*UserInfo, error) {
	client := p.config.Client(ctx, token)

	resp, err := client.Get(discordUserURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("discord api error: %s", string(body))
	}

	var user discordUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Use global name if available, otherwise username
	name := user.GlobalName
	if name == "" {
		name = user.Username
	}

	// Build avatar URL if available
	var picture string
	if user.Avatar != "" {
		picture = fmt.Sprintf("https://cdn.discordapp.com/avatars/%s/%s.png", user.ID, user.Avatar)
	}

	return &UserInfo{
		ID:            user.ID,
		Email:         user.Email,
		EmailVerified: user.Verified,
		Name:          name,
		Picture:       picture,
	}, nil
}
