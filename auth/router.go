package auth

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// Handler returns an HTTP handler with all auth routes.
// This is the main entry point for mounting auth endpoints.
//
// Usage:
//
//	authService, _ := auth.New(store, config.WithSecret("..."))
//	mux.Handle("/auth/", http.StripPrefix("/auth", authService.Handler()))
func (a *Auth) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints (no auth required)
	// Note: /sign-up, /sign-in, /password/* are provided by the password plugin
	mux.HandleFunc("GET /email/verify", a.wrapHandler("/email/verify", a.handleVerifyEmail))

	// Protected endpoints (require auth)
	mux.Handle("POST /sign-out", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/sign-out", a.handleSignOut))))
	mux.Handle("GET /me", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/me", a.handleGetMe))))
	mux.Handle("POST /email/verify/send", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/email/verify/send", a.handleSendVerificationEmail))))
	mux.Handle("GET /sessions", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/sessions", a.handleListSessions))))
	mux.Handle("DELETE /sessions", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/sessions", a.handleRevokeAllSessions))))

	// Session revocation with ID
	mux.Handle("DELETE /sessions/", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/sessions/:id", func(w http.ResponseWriter, r *http.Request) {
		sessionID := parseSessionID(r.URL.Path)
		if sessionID == "" || strings.Contains(sessionID, "/") {
			WriteError(w, http.StatusNotFound, models.ErrSessionNotFound)
			return
		}
		a.handleRevokeSession(w, r, sessionID)
	}))))

	// Self-service profile endpoints
	mux.Handle("GET /profile", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/profile", a.handleGetProfile))))
	mux.Handle("PATCH /profile", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/profile", a.handleUpdateProfile))))
	mux.Handle("DELETE /account", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/account", a.handleDeleteAccount))))
	mux.Handle("GET /accounts", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/accounts", a.handleListLinkedAccounts))))
	mux.Handle("DELETE /accounts/", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/accounts/:provider", func(w http.ResponseWriter, r *http.Request) {
		provider := parseAccountProvider(r.URL.Path)
		if provider == "" {
			WriteError(w, http.StatusNotFound, models.ErrAccountNotFound)
			return
		}
		a.handleUnlinkAccount(w, r, provider)
	}))))

	// Mount plugin routes
	a.mountPluginRoutes(mux)

	// Apply middleware stack
	return a.applyMiddleware(mux)
}

// mountPluginRoutes registers all routes provided by plugins
func (a *Auth) mountPluginRoutes(mux *http.ServeMux) {
	routes := a.PluginRoutes()
	if len(routes) == 0 {
		return
	}

	for _, route := range routes {
		handler := http.HandlerFunc(a.wrapHandler(route.Path, route.Handler))

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
func (a *Auth) applyMiddleware(h http.Handler) http.Handler {
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
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// wrapHandler wraps an HTTP handler with middleware hooks
func (a *Auth) wrapHandler(path string, handler http.HandlerFunc) http.HandlerFunc {
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
				_ = ctx.ParseBody()
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		// Try to load session/user for context (optional auth)
		if session, user := a.getOptionalSession(r); session != nil {
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
func (a *Auth) getOptionalSession(r *http.Request) (*models.Session, *models.User) {
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

// parseSessionID extracts the session ID from the path
func parseSessionID(path string) string {
	return strings.TrimPrefix(path, "/sessions/")
}

// parseAccountProvider extracts the provider from the path
func parseAccountProvider(path string) string {
	return strings.TrimPrefix(path, "/accounts/")
}
