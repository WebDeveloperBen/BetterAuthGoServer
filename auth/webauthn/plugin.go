package webauthn

import (
	"fmt"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	webauthndb "github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn/db"
)

const (
	// PluginName is the unique identifier for this plugin.
	PluginName = "webauthn"
)

// Plugin implements WebAuthn authentication as a plugin.
type Plugin struct {
	ctx     plugin.Context
	auth    AuthProvider
	service *Service
	dbStore *webauthndb.Store
	config  Config
	opts    []Option
}

// Compile-time interface checks.
var (
	_ plugin.Plugin         = (*Plugin)(nil)
	_ plugin.RoutesProvider = (*Plugin)(nil)
)

// NewPlugin creates a new WebAuthn plugin with the given options.
func NewPlugin(opts ...Option) *Plugin {
	return &Plugin{opts: opts}
}

// Name returns the plugin identifier.
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the plugin with the auth context.
func (p *Plugin) Init(ctx plugin.Context) error {
	p.ctx = ctx

	// Require database access.
	if ctx.RawDB == nil {
		ctx.Logger.Warn("webauthn plugin: no database available, plugin disabled")
		return nil
	}

	// Type-assert to get AuthProvider.
	auth, ok := ctx.Auth.(AuthProvider)
	if !ok {
		ctx.Logger.Warn("webauthn plugin: auth doesn't support required interface, plugin disabled")
		return nil
	}
	p.auth = auth

	// Build config from options, defaulting from context BaseURL.
	config := DefaultConfig()
	opts := append([]Option{WithBaseURL(ctx.BaseURL)}, p.opts...)
	for _, opt := range opts {
		opt(&config)
	}
	applyBaseURLDefaults(&config)

	// Validate required config.
	if config.RPID == "" || len(config.RPOrigins) == 0 {
		ctx.Logger.Warn("webauthn plugin: missing RPID or RPOrigins, plugin disabled")
		return nil
	}

	// Create plugin's own store using ctx.RawDB
	dbStore, err := webauthndb.New(ctx.RawDB, ctx.Dialect)
	if err != nil {
		return fmt.Errorf("webauthn plugin: failed to create store: %w", err)
	}
	p.dbStore = dbStore
	store := NewStoreAdapter(p.dbStore)
	service, err := NewService(store, ctx.Encryptor, config, ctx.Logger)
	if err != nil {
		return err
	}

	p.service = service
	p.config = config
	ctx.Logger.Info("webauthn plugin initialized")
	return nil
}

// Close cleans up plugin resources.
func (p *Plugin) Close() error {
	return nil
}

// Routes returns the WebAuthn routes.
func (p *Plugin) Routes() []plugin.Route {
	if p.service == nil {
		return nil
	}

	requireAuth := !p.config.AllowPasswordlessAccounts

	return []plugin.Route{
		{
			Method:      "POST",
			Path:        "/webauthn/register/begin",
			Handler:     p.handleRegisterBegin(),
			RequireAuth: requireAuth,
		},
		{
			Method:      "POST",
			Path:        "/webauthn/register/finish",
			Handler:     p.handleRegisterFinish(),
			RequireAuth: requireAuth,
		},
		{
			Method:  "POST",
			Path:    "/webauthn/login/begin",
			Handler: p.handleLoginBegin(),
		},
		{
			Method:  "POST",
			Path:    "/webauthn/login/finish",
			Handler: p.handleLoginFinish(),
		},
	}
}

// Service returns the WebAuthn service.
func (p *Plugin) Service() *Service {
	return p.service
}

// IsEnabled returns true if the plugin is properly initialized.
func (p *Plugin) IsEnabled() bool {
	return p.service != nil
}
