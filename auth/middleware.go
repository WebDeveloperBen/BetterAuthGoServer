package auth

import (
	"net/http"
)

// RequireAuth is middleware that requires a valid session
func (a *Auth) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawToken := a.GetSessionToken(r)
		if rawToken == "" {
			writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
			return
		}

		session, err := a.ValidateSession(r.Context(), rawToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err)
			return
		}

		// Get user from session
		user, err := a.store.GetUserByID(r.Context(), session.UserID)
		if err != nil || user == nil {
			writeError(w, http.StatusUnauthorized, ErrUserNotFound)
			return
		}

		// Check if user is banned
		if user.Banned {
			writeError(w, http.StatusForbidden, ErrUserBanned)
			return
		}

		// Add session and user to context
		ctx := contextWithSession(r.Context(), session)
		ctx = contextWithUser(ctx, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// OptionalAuth is middleware that loads the session if present but doesn't require it
func (a *Auth) OptionalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawToken := a.GetSessionToken(r)
		if rawToken != "" {
			session, err := a.ValidateSession(r.Context(), rawToken)
			if err == nil && session != nil {
				ctx := contextWithSession(r.Context(), session)
				// Also load user
				user, err := a.store.GetUserByID(r.Context(), session.UserID)
				if err == nil && user != nil && !user.Banned {
					ctx = contextWithUser(ctx, user)
				}
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RequireAdmin returns middleware that requires the user to have admin role
func (a *Auth) RequireAdmin(next http.Handler) http.Handler {
	return a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := GetUserFromContext(r.Context())
		if user == nil {
			writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
			return
		}

		// Check if user has admin role
		if user.Role != "admin" {
			writeError(w, http.StatusForbidden, ErrForbidden)
			return
		}

		next.ServeHTTP(w, r)
	}))
}

// AuthMiddleware returns middleware that can be used to protect routes
// outside the auth handler
func (a *Auth) AuthMiddleware() func(http.Handler) http.Handler {
	return a.RequireAuth
}

// OptionalAuthMiddleware returns middleware that loads the session if present
func (a *Auth) OptionalAuthMiddleware() func(http.Handler) http.Handler {
	return a.OptionalAuth
}
