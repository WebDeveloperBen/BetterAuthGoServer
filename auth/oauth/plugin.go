// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	"fmt"

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

// Name returns the plugin identifier
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the OAuth plugin
func (p *Plugin) Init(ctx plugin.Context) error {
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
