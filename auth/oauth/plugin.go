package oauth

import (
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	PluginName = "oauth"
)

// Plugin wraps OAuth functionality as an auth plugin
type Plugin struct {
	service   *Service
	providers []Provider
	ctx       plugin.Context
	auth      AuthProvider
}

// Ensure Plugin implements required interfaces
var (
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.RoutesProvider     = (*Plugin)(nil)
	_ plugin.MigrationsProvider = (*Plugin)(nil)
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

	// Create state store with auto-table creation
	stateStore := NewDBStateStore(ctx.DB)

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

// Migrations returns database models that need migration
func (p *Plugin) Migrations() []any {
	return []any{
		&OAuthState{},
		&OAuthAccount{},
	}
}

// Routes returns the OAuth routes
func (p *Plugin) Routes() []plugin.Route {
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
