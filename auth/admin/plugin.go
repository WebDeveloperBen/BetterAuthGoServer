package admin

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
	// PluginName is the identifier for the admin plugin.
	PluginName = "admin"
)

// Plugin provides admin functionality as an auth plugin.
// It adds routes for user management operations and admin middleware.
type Plugin struct {
	ctx          plugin.Context
	logger       *slog.Logger
	service      *Service
	handlers     *handlers
	userProvider UserProvider
}

// Ensure Plugin implements required interfaces
var (
	_ plugin.Plugin         = (*Plugin)(nil)
	_ plugin.RoutesProvider = (*Plugin)(nil)
)

// NewPlugin creates a new admin plugin.
func NewPlugin() *Plugin {
	return &Plugin{}
}

// Name returns the plugin identifier
func (p *Plugin) Name() string {
	return PluginName
}

// Init initializes the admin plugin.
// It creates the admin service using the database from the plugin context.
func (p *Plugin) Init(ctx plugin.Context) error {
	p.ctx = ctx

	// Use provided logger or default
	if ctx.Logger != nil {
		p.logger = ctx.Logger
	} else {
		p.logger = slog.Default()
	}

	if ctx.DB == nil {
		p.logger.Warn("admin plugin: no database available, plugin disabled")
		return nil
	}

	// Type-assert to get UserProvider for middleware
	userProvider, ok := ctx.Auth.(UserProvider)
	if !ok {
		p.logger.Warn("admin plugin: auth doesn't support UserProvider, plugin disabled")
		return nil
	}
	p.userProvider = userProvider

	p.service = NewService(ctx.DB, p.logger)
	p.handlers = newHandlers(p.service, ctx.Auth)

	p.logger.Info("admin plugin initialized")
	return nil
}

// Close cleans up plugin resources
func (p *Plugin) Close() error {
	return nil
}

// Routes returns the admin routes.
// Admin routes use a dynamic handler pattern for /admin/users paths.
func (p *Plugin) Routes() []plugin.Route {
	if p.service == nil || p.userProvider == nil {
		// No routes if service or userProvider not initialized
		return nil
	}

	adminMw := requireAdmin(p.userProvider, p.logger)

	return []plugin.Route{
		{
			Method:      "GET",
			Path:        "/admin/users",
			Handler:     p.handlers.listUsers,
			RequireAuth: true,
			Middleware:  []func(http.Handler) http.Handler{adminMw},
		},
		{
			Method:      "GET",
			Path:        "/admin/users/",
			Handler:     p.handleUserRoutes,
			RequireAuth: true,
			Middleware:  []func(http.Handler) http.Handler{adminMw},
		},
	}
}

// handleUserRoutes is a dynamic handler for /admin/users/{id} paths
func (p *Plugin) handleUserRoutes(w http.ResponseWriter, r *http.Request) {
	userID, action := parseUserPath(r.URL.Path)
	if userID == "" {
		http.Error(w, "user ID required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		if action == "" {
			p.handlers.getUser(w, r, userID)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case http.MethodPatch:
		if action == "" {
			p.handlers.updateUser(w, r, userID)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case http.MethodDelete:
		if action == "" {
			p.handlers.deleteUser(w, r, userID)
		} else {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case http.MethodPost:
		switch action {
		case "ban":
			p.handlers.banUser(w, r, userID)
		case "unban":
			p.handlers.unbanUser(w, r, userID)
		case "role":
			p.handlers.setRole(w, r, userID)
		default:
			http.Error(w, "unknown action", http.StatusNotFound)
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// RequireAdmin returns middleware that requires admin role.
// This can be used by other packages to protect routes.
func RequireAdmin(auth UserProvider, logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return requireAdmin(auth, logger)
}

// parseUserPath extracts the user ID and optional action from the path
func parseUserPath(path string) (userID string, action string) {
	path = strings.TrimPrefix(path, "/admin/users/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "", ""
	}
	userID = parts[0]
	if len(parts) > 1 {
		action = parts[1]
	}
	return userID, action
}
