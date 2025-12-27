package deviceauth

import (
	"context"

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
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.RoutesProvider     = (*Plugin)(nil)
	_ plugin.MigrationsProvider = (*Plugin)(nil)
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
	if ctx.DB == nil {
		ctx.Logger.Warn("deviceauth: DB not available, plugin disabled")
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

	// Create table if not exists
	if err := p.ensureTable(ctx); err != nil {
		return err
	}

	// Create service and handlers
	p.service = NewService(ctx.DB, ctx.Hasher, p.config, ctx.Logger)
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

// Migrations returns the database models for auto-migration.
func (p *Plugin) Migrations() []any {
	return []any{&DeviceCode{}}
}

// ensureTable creates the device_codes table if it doesn't exist.
func (p *Plugin) ensureTable(ctx plugin.Context) error {
	_, err := ctx.DB.NewCreateTable().
		Model((*DeviceCode)(nil)).
		IfNotExists().
		Exec(context.Background())

	if err != nil {
		ctx.Logger.Error("deviceauth: failed to create table", "error", err)
		return err
	}

	// Create indexes
	indexes := []struct {
		name   string
		column string
		unique bool
	}{
		{"idx_device_codes_device_code_hash", "device_code_hash", false},
		{"idx_device_codes_user_code", "user_code", true},
		{"idx_device_codes_expires_at", "expires_at", false},
	}

	for _, idx := range indexes {
		query := ctx.DB.NewCreateIndex().
			Model((*DeviceCode)(nil)).
			Index(idx.name).
			Column(idx.column).
			IfNotExists()

		if idx.unique {
			query = query.Unique()
		}

		if _, err := query.Exec(context.Background()); err != nil {
			// Index might already exist, log but don't fail
			ctx.Logger.Debug("deviceauth: index creation", "index", idx.name, "error", err)
		}
	}

	return nil
}
