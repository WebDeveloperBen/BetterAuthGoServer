package auth

import (
	"net/http"
	"strings"
)

// Handler returns an http.Handler for the auth routes
// Mount this at your desired path, e.g., http.Handle("/auth/", auth.Handler())
func (a *Auth) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints (no auth required)
	mux.HandleFunc("POST /sign-up", a.handleSignUp)
	mux.HandleFunc("POST /sign-in", a.handleSignIn)
	mux.HandleFunc("POST /password/reset", a.handlePasswordResetRequest)
	mux.HandleFunc("POST /password/confirm", a.handlePasswordResetConfirm)
	mux.HandleFunc("GET /email/verify", a.handleVerifyEmail)

	// Protected endpoints (require auth)
	mux.Handle("POST /sign-out", a.RequireAuth(http.HandlerFunc(a.handleSignOut)))
	mux.Handle("GET /me", a.RequireAuth(http.HandlerFunc(a.handleGetMe)))
	mux.Handle("POST /password/change", a.RequireAuth(http.HandlerFunc(a.handlePasswordChange)))
	mux.Handle("POST /email/verify/send", a.RequireAuth(http.HandlerFunc(a.handleSendVerificationEmail)))
	mux.Handle("GET /sessions", a.RequireAuth(http.HandlerFunc(a.handleListSessions)))
	mux.Handle("DELETE /sessions", a.RequireAuth(http.HandlerFunc(a.handleRevokeAllSessions)))

	// Session revocation with ID - need custom handling for path params
	mux.Handle("DELETE /sessions/", a.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract session ID from path
		path := strings.TrimPrefix(r.URL.Path, "/sessions/")
		if path == "" || strings.Contains(path, "/") {
			writeError(w, http.StatusNotFound, ErrSessionNotFound)
			return
		}
		a.handleRevokeSession(w, r, path)
	})))

	// OAuth routes
	mux.HandleFunc("GET /oauth/providers", a.handleListOAuthProviders)

	// OAuth provider routes with path parameter extraction
	mux.HandleFunc("GET /oauth/", func(w http.ResponseWriter, r *http.Request) {
		// Parse path: /oauth/:provider or /oauth/:provider/callback
		path := strings.TrimPrefix(r.URL.Path, "/oauth/")
		parts := strings.Split(path, "/")

		if len(parts) == 0 || parts[0] == "" {
			writeError(w, http.StatusNotFound, ErrOAuthProviderNotFound)
			return
		}

		provider := parts[0]

		if len(parts) == 1 {
			// GET /oauth/:provider - begin OAuth flow
			a.handleOAuthBegin(w, r, provider)
			return
		}

		if len(parts) == 2 && parts[1] == "callback" {
			// GET /oauth/:provider/callback - OAuth callback
			a.handleOAuthCallback(w, r, provider)
			return
		}

		writeError(w, http.StatusNotFound, ErrOAuthProviderNotFound)
	})

	// Apply middleware stack
	var handler http.Handler = mux

	// Apply CORS
	handler = a.CORS(handler)

	// Apply CSRF protection
	handler = a.CSRF(handler)

	// Apply security headers
	handler = securityHeaders(handler)

	// Apply rate limiting
	if a.rateLimiter != nil {
		handler = a.rateLimiter.RateLimitMiddleware(a.rateLimitKeyFunc)(handler)
	}

	return handler
}

// securityHeaders adds security headers to responses
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")
		// Enable XSS filter in older browsers
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		// Referrer policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		next.ServeHTTP(w, r)
	})
}

// rateLimitKeyFunc returns the key for rate limiting based on client IP
func (a *Auth) rateLimitKeyFunc(r *http.Request) string {
	return r.URL.Path + ":" + a.getClientIP(r)
}

// getClientIP extracts the client IP, only trusting proxy headers from configured proxies
func (a *Auth) getClientIP(r *http.Request) string {
	// Extract IP without port from RemoteAddr
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	// Only trust X-Forwarded-For if the request came from a trusted proxy
	if len(a.config.TrustedProxies) > 0 {
		for _, trusted := range a.config.TrustedProxies {
			if remoteIP == trusted {
				// Request is from trusted proxy, check X-Forwarded-For
				xff := r.Header.Get("X-Forwarded-For")
				if xff != "" {
					// Take the first IP (client IP)
					if idx := strings.Index(xff, ","); idx != -1 {
						return strings.TrimSpace(xff[:idx])
					}
					return strings.TrimSpace(xff)
				}
				// Check X-Real-IP
				if xri := r.Header.Get("X-Real-IP"); xri != "" {
					return strings.TrimSpace(xri)
				}
				break
			}
		}
	}

	// Return IP without port (don't trust headers from untrusted sources)
	return remoteIP
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
