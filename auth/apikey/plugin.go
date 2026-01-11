package apikey

import (
	"context"
	"net/http"
	"strings"
	"time"

	apikeydb "github.com/webdeveloperben/BetterAuthGoServer/auth/apikey/db"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// PluginName is the unique identifier for this plugin.
const PluginName = "apikey"

// Middleware priorities
const (
	// MiddlewarePriority runs before auth middleware to inject synthetic sessions
	MiddlewarePriority = 15
)

// Context keys for synthetic sessions
type contextKey string

const (
	sessionContextKey contextKey = "apikey:session"
	userContextKey    contextKey = "apikey:user"
	apiKeyContextKey  contextKey = "apikey:key"
)

// Plugin implements the API key plugin.
type Plugin struct {
	ctx      plugin.Context
	auth     AuthProvider
	dbStore  *apikeydb.Store
	service  *Service
	handlers *handlers
	config   Config
	opts     []Option
}

// Compile-time interface checks
var (
	_ plugin.Plugin             = (*Plugin)(nil)
	_ plugin.RoutesProvider     = (*Plugin)(nil)
	_ plugin.MiddlewareProvider = (*Plugin)(nil)
)

// NewPlugin creates a new API key plugin with options.
func NewPlugin(opts ...Option) *Plugin {
	return &Plugin{opts: opts}
}

// Name returns the plugin name.
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the plugin with the provided context.
func (p *Plugin) Init(ctx plugin.Context) error {
	p.ctx = ctx

	// Database is required
	if ctx.RawDB == nil {
		ctx.Logger.Warn("apikey plugin: no database available, plugin disabled")
		return nil
	}

	// Type-assert for required capabilities
	auth, ok := ctx.Auth.(AuthProvider)
	if !ok {
		ctx.Logger.Warn("apikey plugin: auth doesn't support required interface")
		return nil
	}
	p.auth = auth

	// Apply options
	config := DefaultConfig()
	for _, opt := range p.opts {
		opt(&config)
	}
	p.config = config

	// Create plugin's own store
	p.dbStore = apikeydb.New(ctx.RawDB, ctx.Dialect)

	// Create store adapter using sqlc-based store
	store := NewStoreAdapter(p.dbStore)

	// Create service
	p.service = NewService(store, ctx.Hasher, config, ctx.Logger)

	// Create handlers
	p.handlers = newHandlers(p.service, auth, &config)

	return nil
}

// Close cleans up any resources held by the plugin.
func (p *Plugin) Close() error {
	if p.service != nil {
		return p.service.Close()
	}
	return nil
}

// IsEnabled returns true if the plugin is enabled.
func (p *Plugin) IsEnabled() bool {
	return p.service != nil
}

// Routes returns the HTTP routes provided by this plugin.
func (p *Plugin) Routes() []plugin.Route {
	if p.service == nil || p.handlers == nil {
		return nil
	}

	return []plugin.Route{
		{
			Method:      "POST",
			Path:        "/api-key",
			Handler:     p.handlers.handleCreate,
			RequireAuth: true,
		},
		{
			Method:      "GET",
			Path:        "/api-key",
			Handler:     p.handlers.handleList,
			RequireAuth: true,
		},
		{
			Method:      "POST",
			Path:        "/api-key/get",
			Handler:     p.handlers.handleGet,
			RequireAuth: true,
		},
		{
			Method:      "POST",
			Path:        "/api-key/update",
			Handler:     p.handlers.handleUpdate,
			RequireAuth: true,
		},
		{
			Method:      "POST",
			Path:        "/api-key/delete",
			Handler:     p.handlers.handleDelete,
			RequireAuth: true,
		},
		{
			Method:      "POST",
			Path:        "/api-key/verify",
			Handler:     p.handlers.handleVerify,
			RequireAuth: false, // Verification doesn't require session auth
		},
		{
			Method:      "POST",
			Path:        "/api-key/delete-all-expired",
			Handler:     p.handlers.handleDeleteAllExpired,
			RequireAuth: true,
		},
		// Dynamic route for /api-key/{id}
		{
			Method:      "GET",
			Path:        "/api-key/",
			Handler:     p.handlers.handleDynamicRoute,
			RequireAuth: true,
		},
	}
}

// Middleware returns the middleware provided by this plugin.
func (p *Plugin) Middleware() []plugin.Middleware {
	if p.service == nil || !p.config.EnableSessionForAPIKeys {
		return nil
	}

	return []plugin.Middleware{
		{
			Priority: MiddlewarePriority,
			Handler:  p.apiKeySessionMiddleware(),
		},
	}
}

// apiKeySessionMiddleware creates synthetic sessions from valid API keys.
func (p *Plugin) apiKeySessionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip if already has a session
			if p.ctx.Sessions != nil && p.ctx.Sessions.GetFromRequest(r) != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Extract API key from headers
			apiKeyValue := p.extractAPIKey(r)
			if apiKeyValue == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Verify key (no permissions check in middleware)
			key, err := p.service.VerifyKey(r.Context(), apiKeyValue, nil)
			if err != nil {
				// Let request proceed without session
				next.ServeHTTP(w, r)
				return
			}

			// Get user
			user, err := p.auth.GetPluginUser(r.Context(), key.UserID)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Inject synthetic session into context
			syntheticSession := &plugin.Session{
				ID:        "apikey:" + key.ID,
				UserID:    key.UserID,
				ExpiresAt: time.Now().Add(time.Minute), // Short-lived
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, sessionContextKey, syntheticSession)
			ctx = context.WithValue(ctx, userContextKey, user)
			ctx = context.WithValue(ctx, apiKeyContextKey, key)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractAPIKey extracts the API key from request headers.
func (p *Plugin) extractAPIKey(r *http.Request) string {
	// Use custom getter if provided
	if p.config.APIKeyGetter != nil {
		return p.config.APIKeyGetter(r)
	}

	// Check configured headers
	for _, header := range p.config.APIKeyHeaders {
		value := r.Header.Get(header)
		if value != "" {
			// Handle "Bearer <token>" format
			if strings.HasPrefix(strings.ToLower(header), "authorization") {
				if after, ok := strings.CutPrefix(value, "Bearer "); ok {
					return after
				}
			}
			return value
		}
	}

	return ""
}

// GetSessionFromContext retrieves the synthetic session from context.
func GetSessionFromContext(ctx context.Context) *plugin.Session {
	if sess, ok := ctx.Value(sessionContextKey).(*plugin.Session); ok {
		return sess
	}
	return nil
}

// GetUserFromContext retrieves the user from context (set by API key middleware).
func GetUserFromContext(ctx context.Context) *plugin.User {
	if user, ok := ctx.Value(userContextKey).(*plugin.User); ok {
		return user
	}
	return nil
}

// GetAPIKeyFromContext retrieves the API key from context.
func GetAPIKeyFromContext(ctx context.Context) *APIKey {
	if key, ok := ctx.Value(apiKeyContextKey).(*APIKey); ok {
		return key
	}
	return nil
}

// Service returns the API key service for direct access.
func (p *Plugin) Service() *Service {
	return p.service
}
