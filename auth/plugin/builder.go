package plugin

// BasePlugin provides a generic plugin implementation using functional options.
// Use NewPlugin() for simple plugins that don't need custom struct fields.
//
// Example:
//
//	myPlugin := plugin.NewPlugin(
//	    plugin.WithPluginName("my-plugin"),
//	    plugin.WithPluginInit(func(ctx plugin.Context) error {
//	        // initialization logic
//	        return nil
//	    }),
//	    plugin.WithPluginRoutes([]plugin.Route{
//	        {Method: "GET", Path: "/my-endpoint", Handler: myHandler},
//	    }),
//	)
type BasePlugin struct {
	name       string
	initFn     func(ctx Context) error
	closeFn    func() error
	routes     []Route
	middleware []Middleware
	migrations []any
}

// PluginOption configures a BasePlugin
type PluginOption func(*BasePlugin)

// NewPlugin creates a new plugin with the provided options.
// Useful for simple plugins that don't need custom struct fields.
func NewPlugin(opts ...PluginOption) *BasePlugin {
	p := &BasePlugin{
		name:    "unnamed",
		initFn:  func(ctx Context) error { return nil },
		closeFn: func() error { return nil },
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Compile-time interface checks
var (
	_ Plugin             = (*BasePlugin)(nil)
	_ RoutesProvider     = (*BasePlugin)(nil)
	_ MiddlewareProvider = (*BasePlugin)(nil)
	_ MigrationsProvider = (*BasePlugin)(nil)
)

// Plugin interface implementation
func (p *BasePlugin) Name() string           { return p.name }
func (p *BasePlugin) Init(ctx Context) error { return p.initFn(ctx) }
func (p *BasePlugin) Close() error           { return p.closeFn() }

// RoutesProvider implementation
func (p *BasePlugin) Routes() []Route { return p.routes }

// MiddlewareProvider implementation
func (p *BasePlugin) Middleware() []Middleware { return p.middleware }

// MigrationsProvider implementation
func (p *BasePlugin) Migrations() []any { return p.migrations }

// WithPluginName sets the plugin name
func WithPluginName(name string) PluginOption {
	return func(p *BasePlugin) {
		p.name = name
	}
}

// WithPluginInit sets the initialization function
func WithPluginInit(fn func(ctx Context) error) PluginOption {
	return func(p *BasePlugin) {
		p.initFn = fn
	}
}

// WithPluginClose sets the cleanup function
func WithPluginClose(fn func() error) PluginOption {
	return func(p *BasePlugin) {
		p.closeFn = fn
	}
}

// WithPluginRoutes sets the routes provided by this plugin
func WithPluginRoutes(routes []Route) PluginOption {
	return func(p *BasePlugin) {
		p.routes = routes
	}
}

// WithPluginMiddleware sets the middleware provided by this plugin
func WithPluginMiddleware(middleware []Middleware) PluginOption {
	return func(p *BasePlugin) {
		p.middleware = middleware
	}
}

// WithPluginMigrations sets the database models for migration
func WithPluginMigrations(migrations []any) PluginOption {
	return func(p *BasePlugin) {
		p.migrations = migrations
	}
}
