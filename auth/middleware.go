package auth

import (
	"net/http"
	"strings"
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

// CORS is middleware that handles CORS headers
func (a *Auth) CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Check if origin is trusted
		if a.isOriginTrusted(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, "+a.config.CSRFHeaderName)
			w.Header().Set("Access-Control-Expose-Headers", "Set-Cookie")
		}

		// Handle preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
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

// isOriginTrusted checks if an origin is in the trusted origins list
func (a *Auth) isOriginTrusted(origin string) bool {
	if origin == "" {
		return false
	}

	for _, trusted := range a.config.TrustedOrigins {
		if origin == trusted {
			return true
		}
	}

	// Also check if it matches the base URL
	if strings.HasPrefix(a.config.BaseURL, origin) {
		return true
	}

	return false
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
