package admin

import (
	"net/http"
)

// requireAdmin is middleware that requires the user to have admin role.
// It uses the UserProvider interface to get the current user from the request.
func requireAdmin(auth UserProvider) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, err := auth.GetUserFromRequest(r)
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			if user.Role != "admin" {
				http.Error(w, "forbidden: admin access required", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
