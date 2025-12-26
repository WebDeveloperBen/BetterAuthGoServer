package cors

import (
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	// PluginName is the unique identifier for the CORS plugin
	PluginName = "cors"

	// MiddlewarePriority determines when CORS runs in the middleware chain.
	// Lower values run first. CORS should run very early to handle preflight
	// requests before any other processing.
	MiddlewarePriority = 5
)

// Plugin wraps CORS middleware as an auth plugin.
// It implements plugin.Plugin and plugin.MiddlewareProvider.
type Plugin struct {
	cors *CORS
	opts []Option
}

// Ensure Plugin implements the required interfaces
var (
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.MiddlewareProvider = (*Plugin)(nil)
)

// NewPlugin creates a new CORS plugin with the given options.
//
// Example:
//
//	auth.Use(cors.NewPlugin(
//	    cors.WithOrigins("http://localhost:3000", "https://myapp.com"),
//	    cors.WithCredentials(true),
//	))
func NewPlugin(opts ...Option) *Plugin {
	return &Plugin{
		opts: opts,
	}
}

// Name returns the plugin identifier
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the CORS middleware
func (p *Plugin) Init(ctx plugin.Context) error {
	// Add BaseURL from context if not explicitly set
	opts := append([]Option{WithBaseURL(ctx.BaseURL)}, p.opts...)
	p.cors = New(opts...)
	return nil
}

// Close is a no-op for CORS (no resources to release)
func (p *Plugin) Close() error {
	return nil
}

// Middleware returns the CORS middleware
func (p *Plugin) Middleware() []plugin.Middleware {
	if p.cors == nil {
		return nil
	}

	return []plugin.Middleware{
		{
			Priority: MiddlewarePriority,
			Handler:  p.cors.Middleware(),
		},
	}
}

// CORS returns the underlying CORS instance.
// This can be used to access CORS configuration directly.
func (p *Plugin) CORS() *CORS {
	return p.cors
}
