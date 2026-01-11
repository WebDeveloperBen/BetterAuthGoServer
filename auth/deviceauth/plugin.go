package deviceauth

import (
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	// PluginName is the unique identifier for this plugin.
	PluginName = "device-authorization"
)

// Plugin implements OAuth 2.0 Device Authorization Grant (RFC 8628).
type Plugin struct {
	ctx      plugin.Context
	auth     AuthProvider
	service  *Service
	handlers *handlers
	config   Config
	opts     []Option
}

// Compile-time interface checks
var (
	_ plugin.Plugin         = (*Plugin)(nil)
	_ plugin.RoutesProvider = (*Plugin)(nil)
)

// NewPlugin creates a new device authorization plugin with the given options.
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

	// Type-assert to get AuthProvider
	auth, ok := ctx.Auth.(AuthProvider)
	if !ok {
		ctx.Logger.Warn("deviceauth: Auth doesn't implement required interface, plugin disabled")
		return nil
	}
	p.auth = auth

	// Check for required context
	if ctx.Store == nil {
		ctx.Logger.Warn("deviceauth: Store not available, plugin disabled")
		return nil
	}

	if ctx.Hasher == nil {
		ctx.Logger.Warn("deviceauth: Hasher not available, plugin disabled")
		return nil
	}

	// Build config from options
	p.config = DefaultConfig()
	for _, opt := range p.opts {
		opt(&p.config)
	}

	// Set default verification URI from base URL if not configured
	if p.config.VerificationURI == "" {
		p.config.VerificationURI = ctx.BaseURL + "/device"
	}

	// Create store adapter
	storeAdapter := NewStoreAdapter(ctx.Store)

	// Create service and handlers
	p.service = NewService(storeAdapter, ctx.Hasher, p.config, ctx.Logger)
	p.handlers = newHandlers(p.service, p.auth)

	ctx.Logger.Info("deviceauth: plugin initialized",
		"verification_uri", p.config.VerificationURI,
		"expires_in", p.config.ExpiresIn,
		"polling_interval", p.config.PollingInterval,
	)

	return nil
}

// Close shuts down the plugin and its background goroutines.
func (p *Plugin) Close() error {
	if p.service != nil {
		return p.service.Close()
	}
	return nil
}

// Routes returns the HTTP routes for device authorization.
func (p *Plugin) Routes() []plugin.Route {
	if p.service == nil || p.handlers == nil {
		return nil
	}

	return []plugin.Route{
		{
			Method:      "POST",
			Path:        "/device/code",
			Handler:     p.handlers.handleDeviceCode,
			RequireAuth: false,
		},
		{
			Method:      "POST",
			Path:        "/device/token",
			Handler:     p.handlers.handleDeviceToken,
			RequireAuth: false,
		},
		{
			Method:      "GET",
			Path:        "/device/verify",
			Handler:     p.handlers.handleVerify,
			RequireAuth: false,
		},
		{
			Method:      "POST",
			Path:        "/device/approve",
			Handler:     p.handlers.handleApprove,
			RequireAuth: true,
		},
		{
			Method:      "POST",
			Path:        "/device/deny",
			Handler:     p.handlers.handleDeny,
			RequireAuth: false,
		},
	}
}
