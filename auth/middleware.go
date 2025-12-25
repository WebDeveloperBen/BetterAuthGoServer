package auth

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
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

		// Add session to context
		ctx := contextWithSession(r.Context(), session)
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
				r = r.WithContext(ctx)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// CSRF is middleware that provides CSRF protection
func (a *Auth) CSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.config.CSRFEnabled {
			next.ServeHTTP(w, r)
			return
		}

		// Skip CSRF for safe methods
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			// Set CSRF token cookie if not present
			a.ensureCSRFCookie(w, r)
			next.ServeHTTP(w, r)
			return
		}

		// Validate CSRF token for state-changing methods
		cookieToken := a.getCSRFCookie(r)
		headerToken := r.Header.Get(a.config.CSRFHeaderName)

		if cookieToken == "" {
			writeError(w, http.StatusForbidden, ErrCSRFTokenMissing)
			return
		}

		if headerToken == "" {
			writeError(w, http.StatusForbidden, ErrCSRFTokenMissing)
			return
		}

		// Constant-time comparison
		if subtle.ConstantTimeCompare([]byte(cookieToken), []byte(headerToken)) != 1 {
			writeError(w, http.StatusForbidden, ErrCSRFTokenMismatch)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ensureCSRFCookie sets a CSRF cookie if not present
func (a *Auth) ensureCSRFCookie(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(a.config.CSRFCookieName); err == nil {
		return // Cookie already exists
	}

	csrfToken, err := token.Generate()
	if err != nil {
		return
	}

	secure := strings.HasPrefix(a.config.BaseURL, "https://")

	http.SetCookie(w, &http.Cookie{
		Name:     a.config.CSRFCookieName,
		Value:    csrfToken,
		Path:     "/",
		HttpOnly: false, // Must be readable by JavaScript
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// getCSRFCookie retrieves the CSRF token from the cookie
func (a *Auth) getCSRFCookie(r *http.Request) string {
	cookie, err := r.Cookie(a.config.CSRFCookieName)
	if err != nil {
		return ""
	}
	return cookie.Value
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
