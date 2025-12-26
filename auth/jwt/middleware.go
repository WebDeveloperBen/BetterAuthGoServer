package jwt

import (
	"context"
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Context keys for JWT middleware
type contextKey string

const (
	jwtClaimsKey contextKey = "jwt_claims"
	jwtUserKey   contextKey = "jwt_user"
)

// GetJWTClaims retrieves JWT claims from the request context
func GetJWTClaims(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(jwtClaimsKey).(*Claims)
	return claims, ok
}

// GetJWTUser retrieves the JWT-authenticated user from the request context
func GetJWTUser(ctx context.Context) (*plugin.User, bool) {
	user, ok := ctx.Value(jwtUserKey).(*plugin.User)
	return user, ok
}

// jwtAuthMiddleware provides JWT authentication middleware
func (p *Plugin) jwtAuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract JWT token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check for Bearer token
			const bearerPrefix = "Bearer "
			if !strings.HasPrefix(authHeader, bearerPrefix) {
				next.ServeHTTP(w, r)
				return
			}

			tokenString := strings.TrimPrefix(authHeader, bearerPrefix)
			if tokenString == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Validate the JWT token
			claims, err := p.service.ValidateAccessToken(r.Context(), tokenString)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Get user information
			user, err := p.auth.GetPluginUser(r.Context(), claims.UserID)
			if err != nil || user == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Add JWT claims to request context
			ctx := context.WithValue(r.Context(), jwtClaimsKey, claims)
			ctx = context.WithValue(ctx, jwtUserKey, user)

			// Continue with authenticated request
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
