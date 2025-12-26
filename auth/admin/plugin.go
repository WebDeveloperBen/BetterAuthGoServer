package admin

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/admin/access"
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
	config       Config
}

// Ensure Plugin implements required interfaces
var (
	_ plugin.Plugin         = (*Plugin)(nil)
	_ plugin.RoutesProvider = (*Plugin)(nil)
)

// NewPlugin creates a new admin plugin with optional configuration.
func NewPlugin(opts ...Option) *Plugin {
	config := DefaultConfig()
	for _, opt := range opts {
		opt(&config)
	}
	return &Plugin{
		config: config,
	}
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
	p.handlers = newHandlers(p.service, ctx.Auth, ctx.Sessions, userProvider, &p.config)

	// Initialize access control
	if p.config.AccessControl == nil {
		ac, err := access.CreateDefaultAccessControl()
		if err != nil {
			return fmt.Errorf("failed to create default access control: %w", err)
		}
		p.config.AccessControl = ac
		if p.config.Roles == nil {
			adminRole, err := ac.GetRole("admin")
			if err != nil {
				return fmt.Errorf("failed to get admin role: %w", err)
			}
			userRole, err := ac.GetRole("user")
			if err != nil {
				return fmt.Errorf("failed to get user role: %w", err)
			}
			p.config.Roles = map[string]*access.Role{
				"admin": adminRole,
				"user":  userRole,
			}
		}

	}

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

	adminMw := requireAdmin(p.userProvider, p.logger, p.config.AccessControl)

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
		{
			Method:      "POST",
			Path:        "/admin/permissions/has-permission",
			Handler:     p.handlers.hasPermission,
			RequireAuth: true,
			Middleware:  []func(http.Handler) http.Handler{adminMw},
		},
		{
			Method:      "POST",
			Path:        "/admin/permissions/check-role",
			Handler:     p.handlers.checkRolePermission,
			RequireAuth: true,
			Middleware:  []func(http.Handler) http.Handler{adminMw},
		},
		{
			Method:      "POST",
			Path:        "/admin/impersonate-user",
			Handler:     p.handlers.impersonateUser,
			RequireAuth: true,
			Middleware:  []func(http.Handler) http.Handler{adminMw},
		},
		{
			Method:      "POST",
			Path:        "/admin/stop-impersonating",
			Handler:     p.handlers.stopImpersonating,
			RequireAuth: true,
			// Note: No admin middleware - any authenticated user with an impersonation session can stop
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

// RequireAdmin returns middleware that requires admin-level permissions.
// This can be used by other packages to protect routes.
// The accessControl parameter should be the AccessControl instance from the admin plugin.
func RequireAdmin(auth UserProvider, logger *slog.Logger, accessControl *access.AccessControl) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return requireAdmin(auth, logger, accessControl)
}

// RequirePermissions returns middleware that requires specific permissions.
// This can be used by other packages to protect routes with fine-grained access control.
// The permissions parameter is a map of resource names to required actions.
// The accessControl parameter should be the AccessControl instance from the admin plugin.
func RequirePermissions(auth UserProvider, logger *slog.Logger, accessControl *access.AccessControl, permissions map[string][]string) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return requirePermissions(auth, logger, accessControl, permissions)
}

// parseUserPath extracts the user ID and optional action from the path
func parseUserPath(path string) (userID string, action string) {
	path = strings.TrimPrefix(path, "/admin/users")
	if path == "" {
		return "", ""
	}
	// Remove leading slash if present
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		return "", ""
	}
	userID = parts[0]
	if len(parts) > 1 {
		action = parts[1]
	}
	return userID, action
}
