// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	oauthdb "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	PluginName = "oauth"
)

// Plugin wraps OAuth functionality as an auth plugin
type Plugin struct {
	service                  *Service
	providers                []Provider
	ctx                      plugin.Context
	auth                     AuthProvider
	store                    *oauthdb.Store
	accountStore             *AccountStoreAdapter
	trustedRedirectOrigins   []string
	allowRelativeRedirects   bool
	requireEmailVerification bool
	// callbackErrorRedirect is the parsed WithCallbackErrorRedirect target (nil when unset).
	callbackErrorRedirect *url.URL
	// configErr records an invalid option; Init returns it.
	configErr error
}

// Ensure Plugin implements required interfaces
var (
	_ plugin.Plugin         = (*Plugin)(nil)
	_ plugin.RoutesProvider = (*Plugin)(nil)
)

// NewPlugin creates a new OAuth plugin with the given providers.
// At least one provider must be provided.
func NewPlugin(providers ...Provider) (*Plugin, error) {
	if len(providers) == 0 {
		return nil, ErrNoProviders
	}
	return &Plugin{
		providers:              providers,
		allowRelativeRedirects: true,
	}, nil
}

// WithTrustedRedirectOrigins configures allowed redirect origins for OAuth flows.
// Origins should be full origins like "https://example.com".
func (p *Plugin) WithTrustedRedirectOrigins(origins ...string) *Plugin {
	p.trustedRedirectOrigins = origins
	return p
}

// WithAllowRelativeRedirects enables or disables relative redirect targets.
func (p *Plugin) WithAllowRelativeRedirects(allow bool) *Plugin {
	p.allowRelativeRedirects = allow
	return p
}

// WithRequireEmailVerification enforces verified emails before session issuance.
func (p *Plugin) WithRequireEmailVerification(required bool) *Plugin {
	p.requireEmailVerification = required
	return p
}

// WithCallbackErrorRedirect makes browser-facing failures of the sign-in begin
// (GET /oauth/{provider}) and callback (GET /oauth/{provider}/callback) endpoints respond
// 302 to target instead of JSON. The redirect carries the stable error code in "error",
// the provider path name in "provider" (omitted when empty) and "flow=link" when the
// failed callback belonged to a link flow; any query already on target is preserved.
// POST /oauth/{provider}/link keeps responding JSON.
//
// target must be an absolute http(s) URL or a path starting with a single "/"; otherwise
// Init fails with ErrInvalidCallbackErrorRedirect.
func (p *Plugin) WithCallbackErrorRedirect(target string) *Plugin {
	u, err := parseCallbackErrorRedirect(target)
	if err != nil {
		p.callbackErrorRedirect = nil
		p.configErr = err
		return p
	}
	p.callbackErrorRedirect = u
	p.configErr = nil
	return p
}

func parseCallbackErrorRedirect(target string) (*url.URL, error) {
	invalid := fmt.Errorf("%w: %q", ErrInvalidCallbackErrorRedirect, target)
	// Browsers treat "\" like "/", so "/\host" would be protocol-relative.
	if strings.ContainsAny(target, "\\\r\n\t") {
		return nil, invalid
	}
	u, err := url.Parse(target)
	if err != nil {
		return nil, invalid
	}
	if strings.HasPrefix(target, "/") {
		if strings.HasPrefix(target, "//") {
			return nil, invalid
		}
		return u, nil
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, invalid
	}
	return u, nil
}

// Name returns the plugin identifier
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the OAuth plugin
func (p *Plugin) Init(ctx plugin.Context) error {
	if p.configErr != nil {
		return p.configErr
	}
	p.ctx = ctx
	if p.trustedRedirectOrigins == nil {
		p.trustedRedirectOrigins = ctx.TrustedOrigins
	}
	if !p.requireEmailVerification {
		p.requireEmailVerification = ctx.RequireEmailVerification
	}

	// Type-assert to get AuthProvider
	auth, ok := ctx.Auth.(AuthProvider)
	if !ok {
		return nil // Auth doesn't support OAuth operations
	}
	p.auth = auth

	// Create the plugin's own store using raw DB access
	if ctx.RawDB == nil {
		if ctx.Logger != nil {
			ctx.Logger.Warn("oauth plugin: no database available, plugin disabled")
		}
		return nil
	}

	// Create the oauth store using the plugin's own sqlc-generated code
	store, err := oauthdb.New(ctx.RawDB, ctx.Dialect)
	if err != nil {
		return fmt.Errorf("oauth plugin: failed to create store: %w", err)
	}
	p.store = store

	// Create adapters for the service
	stateStore := NewStoreAdapter(p.store)
	p.accountStore = NewAccountStoreAdapter(p.store)

	// Create OAuth service with token utilities from context
	service := NewService(stateStore, ctx.Hasher, ctx.Encryptor)

	// Register user-provided providers
	for _, provider := range p.providers {
		service.RegisterProvider(provider)
	}

	p.service = service
	return nil
}

// Close cleans up plugin resources
func (p *Plugin) Close() error {
	return nil
}

// Routes returns the OAuth routes
func (p *Plugin) Routes() []plugin.Route {
	// If plugin is disabled (no database), don't register routes
	if p.service == nil {
		return nil
	}
	return []plugin.Route{
		{
			Method:  "GET",
			Path:    "/oauth/providers",
			Handler: p.ListOAuthProvidersHandler(),
		},
		{
			Method:  "GET",
			Path:    "/oauth/",
			Handler: p.OAuthDynamicHandler(),
		},
		{
			Method:      "POST",
			Path:        "/oauth/{provider}/link",
			Handler:     p.OAuthLinkBeginHandler(),
			RequireAuth: true,
		},
	}
}

// ConfiguredProviders returns the configured provider names in stable order.
func (p *Plugin) ConfiguredProviders() []string {
	if p.service == nil {
		return []string{}
	}
	providers := p.service.ListProviders()
	slices.Sort(providers)
	return providers
}

// ListLinkedAccounts returns safe provider identity metadata for a user.
// OAuth access and refresh tokens are never exposed.
func (p *Plugin) ListLinkedAccounts(ctx context.Context, userID string) ([]plugin.LinkedAccount, error) {
	if p.store == nil {
		return nil, ErrStoreRequired
	}
	accounts, err := p.store.GetAccountsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]plugin.LinkedAccount, 0, len(accounts))
	for _, account := range accounts {
		result = append(result, plugin.LinkedAccount{
			ID: account.ID, Provider: account.Provider, CreatedAt: account.CreatedAt,
		})
	}
	slices.SortFunc(result, compareLinkedAccounts)
	return result, nil
}

// ListLinkedAccountsByUserIDs loads provider metadata for multiple users in one
// database query. OAuth secrets and provider account identifiers are omitted.
func (p *Plugin) ListLinkedAccountsByUserIDs(
	ctx context.Context,
	userIDs []string,
) (map[string][]plugin.LinkedAccount, error) {
	result := make(map[string][]plugin.LinkedAccount, len(userIDs))
	if len(userIDs) == 0 {
		return result, nil
	}
	if p.store == nil {
		return nil, ErrStoreRequired
	}
	accounts, err := p.store.GetAccountsByUserIDs(ctx, userIDs)
	if err != nil {
		return nil, err
	}
	for _, account := range accounts {
		result[account.UserID] = append(result[account.UserID], plugin.LinkedAccount{
			ID: account.ID, Provider: account.Provider, CreatedAt: account.CreatedAt,
		})
	}
	for userID := range result {
		slices.SortFunc(result[userID], compareLinkedAccounts)
	}
	return result, nil
}

func compareLinkedAccounts(left, right plugin.LinkedAccount) int {
	if order := left.CreatedAt.Compare(right.CreatedAt); order != 0 {
		return order
	}
	if left.Provider < right.Provider {
		return -1
	}
	if left.Provider > right.Provider {
		return 1
	}
	if left.ID < right.ID {
		return -1
	}
	if left.ID > right.ID {
		return 1
	}
	return 0
}

// UnlinkLinkedAccount removes an OAuth identity only when it belongs to the
// specified user.
func (p *Plugin) UnlinkLinkedAccount(ctx context.Context, userID, accountID string) error {
	if p.store == nil {
		return ErrStoreRequired
	}
	accounts, err := p.store.GetAccountsByUserID(ctx, userID)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		if account.ID == accountID {
			return p.store.DeleteAccount(ctx, account.ID)
		}
	}
	return models.ErrAccountNotFound
}
