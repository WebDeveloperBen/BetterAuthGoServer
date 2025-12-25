package plugin

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
)

// Registry manages plugin lifecycle and aggregates plugin capabilities
type Registry struct {
	plugins    []Plugin
	routes     []Route
	middleware []func(http.Handler) http.Handler
	hooks      Hooks
	ctx        Context
	logger     *slog.Logger
}

// NewRegistry creates a new plugin registry
func NewRegistry(logger *slog.Logger) *Registry {
	if logger == nil {
		logger = slog.Default()
	}
	return &Registry{
		plugins: make([]Plugin, 0),
		routes:  make([]Route, 0),
		logger:  logger,
	}
}

// Register adds a plugin to the registry
// The plugin is not initialized until Init is called
func (r *Registry) Register(p Plugin) {
	r.plugins = append(r.plugins, p)
}

// Init initializes all registered plugins with the provided context
func (r *Registry) Init(ctx Context) error {
	r.ctx = ctx

	for _, p := range r.plugins {
		r.logger.Info("initializing plugin", "name", p.Name())

		if err := p.Init(ctx); err != nil {
			return fmt.Errorf("failed to initialize plugin %s: %w", p.Name(), err)
		}

		// Collect routes from plugins
		if rp, ok := p.(RoutesProvider); ok {
			r.routes = append(r.routes, rp.Routes()...)
		}

		// Collect middleware from plugins
		if mp, ok := p.(MiddlewareProvider); ok {
			r.middleware = append(r.middleware, mp.Middleware()...)
		}

		// Merge hooks from plugins
		if hp, ok := p.(HooksProvider); ok {
			r.mergeHooks(hp.Hooks())
		}

		r.logger.Info("plugin initialized", "name", p.Name())
	}

	return nil
}

// Close shuts down all plugins in reverse order
func (r *Registry) Close() error {
	var lastErr error
	for i := len(r.plugins) - 1; i >= 0; i-- {
		p := r.plugins[i]
		r.logger.Info("closing plugin", "name", p.Name())
		if err := p.Close(); err != nil {
			r.logger.Error("failed to close plugin", "name", p.Name(), "error", err)
			lastErr = err
		}
	}
	return lastErr
}

// Routes returns all routes from registered plugins
func (r *Registry) Routes() []Route {
	return r.routes
}

// Middleware returns all middleware from registered plugins
func (r *Registry) Middleware() []func(http.Handler) http.Handler {
	return r.middleware
}

// Hooks returns the merged hooks from all plugins
func (r *Registry) Hooks() Hooks {
	return r.hooks
}

// Migrations returns all models requiring migration from plugins
func (r *Registry) Migrations() []any {
	var models []any
	for _, p := range r.plugins {
		if mp, ok := p.(MigrationsProvider); ok {
			models = append(models, mp.Migrations()...)
		}
	}
	return models
}

// Plugins returns all registered plugins
func (r *Registry) Plugins() []Plugin {
	return r.plugins
}

// Get returns a plugin by name, or nil if not found
func (r *Registry) Get(name string) Plugin {
	for _, p := range r.plugins {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// mergeHooks combines hooks from a plugin with existing hooks
func (r *Registry) mergeHooks(h Hooks) {
	if h.OnUserCreated != nil {
		prev := r.hooks.OnUserCreated
		r.hooks.OnUserCreated = func(ctx context.Context, userID string) error {
			if prev != nil {
				if err := prev(ctx, userID); err != nil {
					return err
				}
			}
			return h.OnUserCreated(ctx, userID)
		}
	}

	if h.OnSignIn != nil {
		prev := r.hooks.OnSignIn
		r.hooks.OnSignIn = func(ctx context.Context, userID, sessionID string) error {
			if prev != nil {
				if err := prev(ctx, userID, sessionID); err != nil {
					return err
				}
			}
			return h.OnSignIn(ctx, userID, sessionID)
		}
	}

	if h.OnSignOut != nil {
		prev := r.hooks.OnSignOut
		r.hooks.OnSignOut = func(ctx context.Context, userID, sessionID string) error {
			if prev != nil {
				if err := prev(ctx, userID, sessionID); err != nil {
					return err
				}
			}
			return h.OnSignOut(ctx, userID, sessionID)
		}
	}

	if h.BeforeSignIn != nil {
		prev := r.hooks.BeforeSignIn
		r.hooks.BeforeSignIn = func(ctx context.Context, email string) error {
			if prev != nil {
				if err := prev(ctx, email); err != nil {
					return err
				}
			}
			return h.BeforeSignIn(ctx, email)
		}
	}
}

// ValidateSignUp runs all plugin validators for sign up
func (r *Registry) ValidateSignUp(ctx context.Context, email, password, name string) error {
	for _, p := range r.plugins {
		if vp, ok := p.(ValidatorProvider); ok {
			if err := vp.ValidateSignUp(ctx, email, password, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// ValidateSignIn runs all plugin validators for sign in
func (r *Registry) ValidateSignIn(ctx context.Context, email string) error {
	for _, p := range r.plugins {
		if vp, ok := p.(ValidatorProvider); ok {
			if err := vp.ValidateSignIn(ctx, email); err != nil {
				return err
			}
		}
	}
	return nil
}
