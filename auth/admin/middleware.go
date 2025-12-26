package admin

import (
	"log/slog"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/admin/access"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// requireAdmin is middleware that requires admin-level permissions.
// It checks for user:list permission which is granted to admin roles by default.
func requireAdmin(auth UserProvider, logger *slog.Logger, ac *access.AccessControl) func(http.Handler) http.Handler {
	return requirePermissions(auth, logger, ac, map[string][]string{"user": {"list"}})
}

// requirePermissions is middleware that requires the user to have specific permissions.
// It uses the UserProvider interface to get the current user and checks permissions
// against the configured access control system.
func requirePermissions(auth UserProvider, logger *slog.Logger, ac *access.AccessControl, permissions map[string][]string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := auth.GetUserFromRequest(r)
			if err != nil {
				logger.Debug("access denied: not authenticated",
					"path", r.URL.Path,
					"method", r.Method,
				)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user has required permissions
			if !userHasPermissions(user, ac, permissions, logger) {
				logger.Debug("access denied: insufficient permissions",
					"path", r.URL.Path,
					"method", r.Method,
					"user_id", user.ID,
					"role", user.Role,
					"required_permissions", permissions,
				)
				http.Error(w, "forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// userHasPermissions checks if a user has the required permissions.
// It uses the access control system if configured, otherwise falls back to role-based checking.
func userHasPermissions(user *plugin.User, ac *access.AccessControl, permissions map[string][]string, logger *slog.Logger) bool {
	// If access control is not configured, fall back to simple admin role check
	if ac == nil {
		return user.Role == "admin"
	}

	// Use access control system
	return ac.UserHasPermission(user.Role, permissions)
}
