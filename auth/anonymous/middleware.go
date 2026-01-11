// Package anonymous provides middleware for anonymous authentication.
package anonymous

import (
	"context"
	"net/http"
)

// Context keys for storing previous session info
type contextKey string

const (
	previousUserKey contextKey = "anonymous_previous_user"
)

// capturePreviousSessionMiddleware captures the current user before auth handlers run.
// This allows the EventSignedIn handler to detect if the previous user was anonymous.
// We query the is_anonymous status here so it's available in the event handler.
func (p *Plugin) capturePreviousSessionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Get current user from request (if any)
			pluginUser, _ := p.auth.GetUserFromRequest(r)
			if pluginUser != nil {
				// Convert to local User type with is_anonymous status from DB
				user, err := FromPluginUser(ctx, p.store, pluginUser)
				if err != nil {
					p.ctx.Logger.Error("failed to get user with anonymous status", "error", err)
					// Still continue, just without the previous user context
					next.ServeHTTP(w, r)
					return
				}

				// Store in context for later retrieval
				ctx = context.WithValue(ctx, previousUserKey, user)
				r = r.WithContext(ctx)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// GetPreviousUser retrieves the previous user from context (set by middleware).
// Returns the local User type which includes the IsAnonymous field.
func GetPreviousUser(ctx context.Context) *User {
	user, _ := ctx.Value(previousUserKey).(*User)
	return user
}
