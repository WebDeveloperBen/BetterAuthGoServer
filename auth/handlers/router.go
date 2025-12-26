package handlers

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// NewRouter creates an HTTP handler with all auth routes
func NewRouter(a *auth.Auth) http.Handler {
	mux := http.NewServeMux()

	// Public endpoints (no auth required)
	// Note: /sign-up, /sign-in, /password/* are now provided by the password plugin
	mux.HandleFunc("GET /email/verify", wrapHandler(a, "/email/verify", VerifyEmail(a)))

	// Protected endpoints (require auth)
	mux.Handle("POST /sign-out", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/sign-out", SignOut(a)))))
	mux.Handle("GET /me", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/me", GetMe(a)))))
	mux.Handle("POST /email/verify/send", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/email/verify/send", SendVerificationEmail(a)))))
	mux.Handle("GET /sessions", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/sessions", ListSessions(a)))))
	mux.Handle("DELETE /sessions", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/sessions", RevokeAllSessions(a)))))

	// Session revocation with ID
	revokeSession := RevokeSession(a)
	mux.Handle("DELETE /sessions/", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/sessions/:id", func(w http.ResponseWriter, r *http.Request) {
		sessionID := parseSessionID(r.URL.Path)
		if sessionID == "" || strings.Contains(sessionID, "/") {
			WriteError(w, http.StatusNotFound, auth.ErrSessionNotFound)
			return
		}
		revokeSession(w, r, sessionID)
	}))))

	// Admin endpoints are now provided by the admin plugin

	// Self-service profile endpoints
	unlinkAccount := UnlinkAccount(a)
	mux.Handle("GET /profile", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/profile", GetProfile(a)))))
	mux.Handle("PATCH /profile", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/profile", UpdateProfile(a)))))
	mux.Handle("DELETE /account", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/account", DeleteAccount(a)))))
	mux.Handle("GET /accounts", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/accounts", ListLinkedAccounts(a)))))
	mux.Handle("DELETE /accounts/", a.RequireAuth(http.HandlerFunc(wrapHandler(a, "/accounts/:provider", func(w http.ResponseWriter, r *http.Request) {
		provider := parseAccountProvider(r.URL.Path)
		if provider == "" {
			WriteError(w, http.StatusNotFound, auth.ErrAccountNotFound)
			return
		}
		unlinkAccount(w, r, provider)
	}))))

	// Mount plugin routes
	mountPluginRoutes(mux, a)

	// Apply middleware stack
	return applyMiddleware(mux, a)
}

// mountPluginRoutes registers all routes provided by plugins
func mountPluginRoutes(mux *http.ServeMux, a *auth.Auth) {
	routes := a.PluginRoutes()
	if len(routes) == 0 {
		return
	}

	for _, route := range routes {
		handler := http.HandlerFunc(wrapHandler(a, route.Path, route.Handler))

		// Apply route-specific middleware if any
		var h http.Handler = handler
		for i := len(route.Middleware) - 1; i >= 0; i-- {
			h = route.Middleware[i](h)
		}

		// Apply auth requirement if specified
		if route.RequireAuth {
			h = a.RequireAuth(h)
		}

		// Register the route
		pattern := route.Method + " " + route.Path
		mux.Handle(pattern, h)
	}
}

// applyMiddleware applies the standard middleware stack
func applyMiddleware(h http.Handler, a *auth.Auth) http.Handler {
	// Apply plugin middleware (sorted by priority)
	// This includes rate limiting, CSRF, CORS (if enabled), and any other registered plugins
	h = a.ChainPluginMiddleware(h)

	// Apply security headers
	h = securityHeaders(h)

	return h
}

// securityHeaders adds security headers to responses
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

// wrapHandler wraps an HTTP handler with middleware hooks
func wrapHandler(a *auth.Auth, path string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := a.Config()

		// Skip if no middleware hooks configured
		if cfg.MiddlewareHooks == nil {
			handler(w, r)
			return
		}

		// Create hook context
		ctx := hooks.NewContext(w, r, path)
		ctx.Store = a.Store()
		ctx.Secret = cfg.Secret

		// Read and buffer the body so hooks can access it and handler can re-read
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err == nil {
				ctx.ParseBody()
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		// Try to load session/user for context (optional auth)
		if session, user := getOptionalSession(a, r); session != nil {
			ctx.Session = session
			ctx.User = user
		}

		// Run before hooks
		if err := cfg.MiddlewareHooks.RunBefore(ctx, cfg.Logger); err != nil {
			if ctx.HasResponded() {
				return
			}
			if apiErr, ok := err.(*hooks.APIError); ok {
				hooks.WriteAPIError(w, apiErr)
			} else {
				hooks.WriteAPIError(w, hooks.AsAPIError(err))
			}
			return
		}

		if ctx.HasResponded() {
			return
		}

		// Run the actual handler
		handler(w, r)

		// Run after hooks
		cfg.MiddlewareHooks.RunAfter(ctx, cfg.Logger)
	}
}

// getOptionalSession tries to get the current session without requiring auth
func getOptionalSession(a *auth.Auth, r *http.Request) (*models.Session, *models.User) {
	rawToken := a.GetSessionToken(r)
	if rawToken == "" {
		return nil, nil
	}

	session, err := a.ValidateSession(r.Context(), rawToken)
	if err != nil || session == nil {
		return nil, nil
	}

	user, err := a.GetUser(r.Context(), session.UserID)
	if err != nil || user == nil {
		return nil, nil
	}

	return session, user
}
