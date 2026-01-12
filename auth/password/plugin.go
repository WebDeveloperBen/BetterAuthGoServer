// Package password provides email/password authentication as a plugin.
//
// This plugin handles:
//   - User sign-up with email/password
//   - User sign-in with email/password
//   - Password change (authenticated)
//   - Password reset flow (via OTP tokens)
//
// Usage:
//
//	authService.Use(password.NewPlugin(
//	    password.WithMinLength(10),
//	    password.WithComplexity(true),
//	))
package password

import (
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	// PluginName is the unique identifier for this plugin.
	PluginName = "password"
)

// Plugin implements password authentication as a plugin.
type Plugin struct {
	ctx           plugin.Context
	service       *Service
	auth          AuthProvider
	sessionGetter SessionGetter
	opts          []Option
}

// Compile-time interface checks.
var (
	_ plugin.Plugin         = (*Plugin)(nil)
	_ plugin.RoutesProvider = (*Plugin)(nil)
)

// NewPlugin creates a new password authentication plugin with the given options.
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

	// Require database access
	if ctx.Store == nil {
		ctx.Logger.Warn("password plugin: no database available, plugin disabled")
		return nil
	}

	// Type-assert to get AuthProvider
	auth, ok := ctx.Auth.(AuthProvider)
	if !ok {
		ctx.Logger.Warn("password plugin: auth doesn't support required interface, plugin disabled")
		return nil
	}
	p.auth = auth

	// Try to get SessionGetter (optional, required for password change)
	if getter, ok := ctx.Auth.(SessionGetter); ok {
		p.sessionGetter = getter
	}

	// Build config from options
	config := DefaultConfig()
	for _, opt := range p.opts {
		opt(&config)
	}
	if !config.RequireEmailVerification {
		config.RequireEmailVerification = ctx.RequireEmailVerification
	}

	// Try to find a PasswordResetTokenProvider (e.g., OTP plugin)
	var tokenProvider PasswordResetTokenProvider
	if registry, ok := ctx.Auth.(pluginRegistryGetter); ok {
		for _, p := range registry.GetPlugins() {
			if provider, ok := p.(plugin.PasswordResetTokenProvider); ok {
				tokenProvider = provider
				break
			}
		}
	}

	// Create the service
	p.service = NewService(
		NewStoreAdapter(ctx.Store),
		auth,
		tokenProvider,
		ctx.EventBus,
		config,
		ctx.Logger,
	)

	ctx.Logger.Info("password plugin initialized")
	return nil
}

// Close cleans up plugin resources.
func (p *Plugin) Close() error {
	if p.service != nil {
		return p.service.Close()
	}
	return nil
}

// Routes returns the password authentication routes.
func (p *Plugin) Routes() []plugin.Route {
	if p.service == nil {
		return nil
	}

	return []plugin.Route{
		{
			Method:  "POST",
			Path:    "/sign-up",
			Handler: p.handleSignUp(),
		},
		{
			Method:  "POST",
			Path:    "/sign-in",
			Handler: p.handleSignIn(),
		},
		{
			Method:  "POST",
			Path:    "/password/reset",
			Handler: p.handlePasswordReset(),
		},
		{
			Method:  "POST",
			Path:    "/password/confirm",
			Handler: p.handlePasswordConfirm(),
		},
		{
			Method:      "POST",
			Path:        "/password/change",
			Handler:     p.handlePasswordChange(),
			RequireAuth: true,
		},
	}
}

// IsEnabled returns true if the plugin is properly initialized.
func (p *Plugin) IsEnabled() bool {
	return p.service != nil
}

// pluginRegistryGetter is an interface for getting plugins from the registry.
type pluginRegistryGetter interface {
	GetPlugins() []plugin.Plugin
}
