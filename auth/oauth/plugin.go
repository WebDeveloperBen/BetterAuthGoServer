// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import (
	oauthdb "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/db"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	PluginName = "oauth"
)

// Plugin wraps OAuth functionality as an auth plugin
type Plugin struct {
	service      *Service
	providers    []Provider
	ctx          plugin.Context
	auth         AuthProvider
	store        *oauthdb.Store
	accountStore *AccountStoreAdapter
}

// Ensure Plugin implements required interfaces
var (
	_ plugin.Plugin         = (*Plugin)(nil)
	_ plugin.RoutesProvider = (*Plugin)(nil)
)

// NewPlugin creates a new OAuth plugin with the given providers.
// At least one provider must be provided.
func NewPlugin(providers ...Provider) *Plugin {
	if len(providers) == 0 {
		panic("OAuth plugin requires at least one provider")
	}
	return &Plugin{
		providers: providers,
	}
}

// Name returns the plugin identifier
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the OAuth plugin
func (p *Plugin) Init(ctx plugin.Context) error {
	p.ctx = ctx

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
	p.store = oauthdb.New(ctx.RawDB, ctx.Dialect)

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
	}
}
