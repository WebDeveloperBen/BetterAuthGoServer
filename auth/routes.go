package auth

import (
	"bytes"
	"io"
	"net/http"
	"strings"
)

// Handler returns an http.Handler for the auth routes
// Mount this at your desired path, e.g., http.Handle("/auth/", auth.Handler())
func (a *Auth) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints (no auth required) - wrapped with middleware hooks
	mux.HandleFunc("POST /sign-up", a.wrapHandler("/sign-up", a.handleSignUp))
	mux.HandleFunc("POST /sign-in", a.wrapHandler("/sign-in", a.handleSignIn))
	mux.HandleFunc("POST /password/reset", a.wrapHandler("/password/reset", a.handlePasswordResetRequest))
	mux.HandleFunc("POST /password/confirm", a.wrapHandler("/password/confirm", a.handlePasswordResetConfirm))
	mux.HandleFunc("GET /email/verify", a.wrapHandler("/email/verify", a.handleVerifyEmail))

	// Protected endpoints (require auth) - wrapped with middleware hooks
	mux.Handle("POST /sign-out", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/sign-out", a.handleSignOut))))
	mux.Handle("GET /me", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/me", a.handleGetMe))))
	mux.Handle("POST /password/change", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/password/change", a.handlePasswordChange))))
	mux.Handle("POST /email/verify/send", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/email/verify/send", a.handleSendVerificationEmail))))
	mux.Handle("GET /sessions", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/sessions", a.handleListSessions))))
	mux.Handle("DELETE /sessions", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/sessions", a.handleRevokeAllSessions))))

	// Session revocation with ID - need custom handling for path params
	mux.Handle("DELETE /sessions/", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/sessions/:id", func(w http.ResponseWriter, r *http.Request) {
		// Extract session ID from path
		path := strings.TrimPrefix(r.URL.Path, "/sessions/")
		if path == "" || strings.Contains(path, "/") {
			writeError(w, http.StatusNotFound, ErrSessionNotFound)
			return
		}
		a.handleRevokeSession(w, r, path)
	}))))

	// OAuth routes - wrapped with middleware hooks
	mux.HandleFunc("GET /oauth/providers", a.wrapHandler("/oauth/providers", a.handleListOAuthProviders))

	// OAuth provider routes with path parameter extraction
	mux.HandleFunc("GET /oauth/", a.wrapHandler("/oauth/:provider", func(w http.ResponseWriter, r *http.Request) {
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
	}))

	// Register plugin routes
	if a.plugins != nil {
		for _, route := range a.plugins.Routes() {
			handler := a.wrapHandler(route.Path, route.Handler)
			if route.RequireAuth {
				mux.Handle(route.Method+" "+route.Path, a.RequireAuth(http.HandlerFunc(handler)))
			} else {
				mux.HandleFunc(route.Method+" "+route.Path, handler)
			}
		}
	}

	// JWT endpoints (if enabled)
	if a.jwt != nil {
		mux.HandleFunc("POST /token", a.wrapHandler("/token", a.handleToken))
		mux.HandleFunc("POST /token/refresh", a.wrapHandler("/token/refresh", a.handleTokenRefresh))
		mux.HandleFunc("POST /token/revoke", a.wrapHandler("/token/revoke", a.handleTokenRevoke))
		mux.HandleFunc("POST /token/introspect", a.wrapHandler("/token/introspect", a.handleTokenIntrospect))
	}

	// Admin endpoints (require admin role)
	mux.Handle("GET /admin/users", a.RequireAdmin(http.HandlerFunc(a.wrapHandler("/admin/users", a.handleAdminListUsers))))
	mux.Handle("GET /admin/users/", a.RequireAdmin(http.HandlerFunc(a.wrapHandler("/admin/users/:id", func(w http.ResponseWriter, r *http.Request) {
		userID, action := parseAdminUserPath(r.URL.Path)
		if userID == "" {
			writeError(w, http.StatusNotFound, ErrUserNotFound)
			return
		}
		if action == "" {
			a.handleAdminGetUser(w, r, userID)
		} else {
			writeError(w, http.StatusNotFound, ErrUserNotFound)
		}
	}))))
	mux.Handle("PATCH /admin/users/", a.RequireAdmin(http.HandlerFunc(a.wrapHandler("/admin/users/:id", func(w http.ResponseWriter, r *http.Request) {
		userID, _ := parseAdminUserPath(r.URL.Path)
		if userID == "" {
			writeError(w, http.StatusNotFound, ErrUserNotFound)
			return
		}
		a.handleAdminUpdateUser(w, r, userID)
	}))))
	mux.Handle("DELETE /admin/users/", a.RequireAdmin(http.HandlerFunc(a.wrapHandler("/admin/users/:id", func(w http.ResponseWriter, r *http.Request) {
		userID, _ := parseAdminUserPath(r.URL.Path)
		if userID == "" {
			writeError(w, http.StatusNotFound, ErrUserNotFound)
			return
		}
		a.handleAdminDeleteUser(w, r, userID)
	}))))
	mux.Handle("POST /admin/users/", a.RequireAdmin(http.HandlerFunc(a.wrapHandler("/admin/users/:id/:action", func(w http.ResponseWriter, r *http.Request) {
		userID, action := parseAdminUserPath(r.URL.Path)
		if userID == "" {
			writeError(w, http.StatusNotFound, ErrUserNotFound)
			return
		}
		switch action {
		case "ban":
			a.handleAdminBanUser(w, r, userID)
		case "unban":
			a.handleAdminUnbanUser(w, r, userID)
		case "role":
			a.handleAdminSetRole(w, r, userID)
		default:
			writeError(w, http.StatusNotFound, ErrUserNotFound)
		}
	}))))

	// Self-service profile endpoints
	mux.Handle("GET /profile", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/profile", a.handleGetProfile))))
	mux.Handle("PATCH /profile", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/profile", a.handleUpdateProfile))))
	mux.Handle("DELETE /account", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/account", a.handleDeleteAccount))))
	mux.Handle("GET /accounts", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/accounts", a.handleListAccounts))))
	mux.Handle("DELETE /accounts/", a.RequireAuth(http.HandlerFunc(a.wrapHandler("/accounts/:provider", func(w http.ResponseWriter, r *http.Request) {
		provider := strings.TrimPrefix(r.URL.Path, "/accounts/")
		if provider == "" {
			writeError(w, http.StatusNotFound, ErrAccountNotFound)
			return
		}
		a.handleUnlinkAccount(w, r, provider)
	}))))

	// Apply middleware stack
	var handler http.Handler = mux

	// Apply plugin middleware (innermost, runs first)
	if a.plugins != nil {
		for _, mw := range a.plugins.Middleware() {
			handler = mw(handler)
		}
	}

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

// wrapHandler wraps an HTTP handler with middleware hooks.
// Before hooks run before the handler and can abort the request.
// After hooks run after a successful response.
func (a *Auth) wrapHandler(path string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip if no middleware hooks configured
		if a.config.MiddlewareHooks == nil {
			handler(w, r)
			return
		}

		// Create hook context
		ctx := newHookContext(w, r, path)
		ctx.Store = a.store
		ctx.Secret = a.config.Secret

		// Read and buffer the body so hooks can access it and handler can re-read
		if r.Body != nil {
			body, err := io.ReadAll(r.Body)
			if err == nil {
				ctx.rawBody = body
				ctx.bodyRead = true
				// Parse as JSON if possible
				ctx.parseBody()
				// Restore body for handler
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
		}

		// Try to load session/user for context (optional auth)
		if session, user := a.getOptionalSession(r); session != nil {
			ctx.Session = session
			ctx.User = user
		}

		// Run before hooks
		if err := a.config.MiddlewareHooks.RunBefore(ctx, a.config.Logger); err != nil {
			if ctx.HasResponded() {
				return // Hook already sent response
			}
			// Write error response
			if apiErr, ok := err.(*APIError); ok {
				WriteAPIError(w, apiErr)
			} else {
				WriteAPIError(w, AsAPIError(err))
			}
			return
		}

		// Check if hook already responded
		if ctx.HasResponded() {
			return
		}

		// Run the actual handler
		handler(w, r)

		// Run after hooks (errors logged, don't affect response)
		a.config.MiddlewareHooks.RunAfter(ctx, a.config.Logger)
	}
}

// getOptionalSession tries to get the current session without requiring auth
func (a *Auth) getOptionalSession(r *http.Request) (*Session, *User) {
	rawToken := a.GetSessionToken(r)
	if rawToken == "" {
		return nil, nil
	}

	tokenHash := a.tokenHasher.Hash(rawToken)
	session, err := a.store.GetSessionByTokenHash(r.Context(), tokenHash)
	if err != nil || session == nil || session.IsExpired() {
		return nil, nil
	}

	user, err := a.store.GetUserByID(r.Context(), session.UserID)
	if err != nil || user == nil {
		return nil, nil
	}

	return session, user
}
