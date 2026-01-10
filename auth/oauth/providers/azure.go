// Package providers implements OAuth2 provider integrations for Azure Entra ID.
package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
	"golang.org/x/oauth2"
)

// AzureTenant represents the Azure tenant configuration.
// Use predefined constants or a specific tenant ID/domain.
type AzureTenant string

const (
	// AzureTenantCommon allows both personal Microsoft accounts and work/school accounts
	// from any Azure AD tenant. Use this for multi-tenant apps supporting all account types.
	// Requires app registration with "Accounts in any organizational directory and personal Microsoft accounts".
	AzureTenantCommon AzureTenant = "common"

	// AzureTenantOrganizations allows work/school accounts from any Azure AD tenant.
	// Use this for multi-tenant business apps that don't need personal account support.
	// Requires app registration with "Accounts in any organizational directory".
	AzureTenantOrganizations AzureTenant = "organizations"
)

// azureEndpoint returns the OAuth2 endpoint for the specified tenant.
// Uses v2.0 endpoints which support both personal and organizational accounts.
func azureEndpoint(tenant AzureTenant) oauth2.Endpoint {
	tenantStr := string(tenant)
	if tenantStr == "" {
		tenantStr = "common"
	}
	return oauth2.Endpoint{
		AuthURL:  fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/authorize", tenantStr),
		TokenURL: fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantStr),
	}
}

// Microsoft Graph API endpoint for user info
const azureGraphMeURL = "https://graph.microsoft.com/v1.0/me"

// AzureProvider implements the Provider interface for Azure Entra ID (formerly Azure AD)
type AzureProvider struct {
	config *oauth2.Config
	tenant AzureTenant
}

// AzureOption is a functional option for configuring the Azure provider
type AzureOption func(*AzureProvider)

// WithAzureTenant sets the Azure tenant for authentication.
// Defaults to AzureTenantCommon if not specified.
func WithAzureTenant(tenant AzureTenant) AzureOption {
	return func(p *AzureProvider) {
		p.tenant = tenant
	}
}

// NewAzure creates a new Azure Entra ID OAuth provider.
// By default, it uses the "common" tenant which accepts both personal Microsoft accounts
// and work/school accounts from any Azure AD tenant.
//
// For specific tenant configurations:
//   - Use WithAzureTenant(AzureTenantCommon) for both personal and work/school accounts (default)
//   - Use WithAzureTenant(AzureTenantOrganizations) for work/school accounts only
//   - Use WithAzureTenant(AzureTenant("your-tenant-id")) for a specific tenant/organization
func NewAzure(clientID, clientSecret, redirectURL string, opts ...AzureOption) *AzureProvider {
	p := &AzureProvider{
		tenant: AzureTenantCommon, // Default to common for maximum compatibility
	}

	// Apply options
	for _, opt := range opts {
		opt(p)
	}

	p.config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		// Scopes for v2.0 endpoint:
		// - openid: Required for OIDC, provides the 'sub' claim
		// - profile: Provides name, preferred_username
		// - email: Provides email address
		// - User.Read: Required to access Microsoft Graph /me endpoint
		Scopes: []string{
			"openid",
			"profile",
			"email",
			"User.Read",
		},
		Endpoint: azureEndpoint(p.tenant),
	}

	return p
}

// Name returns the provider name
func (p *AzureProvider) Name() string {
	return "azure"
}

// Config returns the OAuth2 configuration
func (p *AzureProvider) Config() *oauth2.Config {
	return p.config
}

// RequiresPKCE returns whether this provider requires PKCE.
// Azure recommends PKCE but doesn't strictly require it for confidential clients.
func (p *AzureProvider) RequiresPKCE() bool {
	return false
}

// Tenant returns the configured tenant
func (p *AzureProvider) Tenant() AzureTenant {
	return p.tenant
}

// azureUser represents the response from Microsoft Graph /me endpoint.
// Field availability depends on the user's account type and tenant configuration.
type azureUser struct {
	// ID is the unique identifier for the user in the directory (oid claim equivalent)
	ID string `json:"id"`

	// DisplayName is the user's display name
	DisplayName string `json:"displayName"`

	// GivenName is the user's first name
	GivenName string `json:"givenName"`

	// Surname is the user's last name
	Surname string `json:"surname"`

	// Mail is the user's email address.
	// Note: This may be empty for personal accounts; use userPrincipalName as fallback.
	Mail string `json:"mail"`

	// UserPrincipalName is the user's principal name.
	// For personal accounts, this is typically the email address.
	// For work/school accounts, this is the UPN (e.g., user@contoso.com).
	UserPrincipalName string `json:"userPrincipalName"`
}

// GetUserInfo fetches user information from Microsoft Graph API.
// Uses the /me endpoint which works for both personal and organizational accounts.
func (p *AzureProvider) GetUserInfo(ctx context.Context, token *oauth2.Token) (*oauth.UserInfo, error) {
	client := p.config.Client(ctx, token)

	resp, err := client.Get(azureGraphMeURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("azure graph api error (status %d): %s", resp.StatusCode, string(body))
	}

	var user azureUser
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	// Determine the best email to use
	// Priority: mail > userPrincipalName (if it looks like an email)
	email := user.Mail
	if email == "" && isValidEmailFormat(user.UserPrincipalName) {
		email = user.UserPrincipalName
	}

	// Build the display name
	name := user.DisplayName
	if name == "" {
		// Fall back to constructing from given/surname
		if user.GivenName != "" && user.Surname != "" {
			name = user.GivenName + " " + user.Surname
		} else if user.GivenName != "" {
			name = user.GivenName
		} else if user.Surname != "" {
			name = user.Surname
		}
	}

	// Azure doesn't return email verification status via Graph API.
	// For organizational accounts, emails are typically verified by the org.
	// For personal accounts with Microsoft, the email is verified by Microsoft.
	// We set this to true as Microsoft requires email verification for all accounts.
	emailVerified := email != ""

	return &oauth.UserInfo{
		ID:            user.ID,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          name,
		// Note: Profile photo requires a separate call to /me/photo/$value
		// which returns binary data, not a URL. Leaving empty for now.
		Picture: "",
	}, nil
}

// isValidEmailFormat performs a basic check if the string looks like an email.
// This is used to determine if userPrincipalName can be used as an email fallback.
func isValidEmailFormat(s string) bool {
	if s == "" {
		return false
	}
	// Simple check: contains @ and has content before and after it
	atIndex := -1
	for i, c := range s {
		if c == '@' {
			atIndex = i
			break
		}
	}
	return atIndex > 0 && atIndex < len(s)-1
}
