package csrf

import (
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	// PluginName is the unique identifier for the CSRF plugin
	PluginName = "csrf"

	// MiddlewarePriority determines when CSRF runs in the middleware chain.
	// Lower values run first. CSRF should run after rate limiting but before
	// business logic to protect state-changing requests.
	MiddlewarePriority = 20
)

// Plugin wraps CSRF middleware as an auth plugin.
// It implements plugin.Plugin and plugin.MiddlewareProvider.
type Plugin struct {
	csrf *CSRF
	opts []Option
}

// Ensure Plugin implements the required interfaces
var (
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.MiddlewareProvider = (*Plugin)(nil)
)

// NewPlugin creates a new CSRF plugin with the given options.
//
// Example:
//
//	auth.Use(csrf.NewPlugin(
//	    csrf.WithCookieName("my_csrf"),
//	    csrf.WithHeaderName("X-My-CSRF"),
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

// Init initializes the CSRF middleware
func (p *Plugin) Init(ctx plugin.Context) error {
	// Add BaseURL from context if not explicitly set
	opts := append([]Option{WithBaseURL(ctx.BaseURL)}, p.opts...)
	p.csrf = New(opts...)
	return nil
}

// Close is a no-op for CSRF (no resources to release)
func (p *Plugin) Close() error {
	return nil
}

// Middleware returns the CSRF middleware
func (p *Plugin) Middleware() []plugin.Middleware {
	if p.csrf == nil {
		return nil
	}

	return []plugin.Middleware{
		{
			Priority: MiddlewarePriority,
			Handler:  p.csrf.Middleware(),
		},
	}
}

// CSRF returns the underlying CSRF instance.
// This can be used to access CSRF configuration directly.
func (p *Plugin) CSRF() *CSRF {
	return p.csrf
}

// HeaderName returns the CSRF header name.
// This is useful for CORS configuration.
func (p *Plugin) HeaderName() string {
	if p.csrf == nil {
		return DefaultConfig().HeaderName
	}
	return p.csrf.HeaderName()
}
