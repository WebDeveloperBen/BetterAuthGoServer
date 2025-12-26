package admin

import (
	"log/slog"
	"net/http"
)

// requireAdmin is middleware that requires the user to have admin role.
// It uses the UserProvider interface to get the current user from the request.
func requireAdmin(auth UserProvider, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := auth.GetUserFromRequest(r)
			if err != nil {
				logger.Debug("admin access denied: not authenticated",
					"path", r.URL.Path,
					"method", r.Method,
				)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if user.Role != "admin" {
				logger.Debug("admin access denied: insufficient role",
					"path", r.URL.Path,
					"method", r.Method,
					"user_id", user.ID,
					"role", user.Role,
				)
				http.Error(w, "forbidden: admin access required", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
