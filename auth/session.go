package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// Context keys for session management
type contextKey string

const (
	sessionContextKey contextKey = "auth_session"
	userContextKey    contextKey = "auth_user"
)

// SessionFromContext extracts the session from the request context
func SessionFromContext(ctx context.Context) *Session {
	if session, ok := ctx.Value(sessionContextKey).(*Session); ok {
		return session
	}
	return nil
}

// GetUserFromContext extracts the user from the request context
func GetUserFromContext(ctx context.Context) *User {
	if user, ok := ctx.Value(userContextKey).(*User); ok {
		return user
	}
	return nil
}

// contextWithSession adds a session to the context
func contextWithSession(ctx context.Context, session *Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, session)
}

// contextWithUser adds a user to the context
func contextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// ValidateSession validates a session token and returns the session if valid
func (a *Auth) ValidateSession(ctx context.Context, rawToken string) (*Session, error) {
	tokenHash := a.tokenHasher.Hash(rawToken)

	session, err := a.store.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Check expiration
	if session.IsExpired() {
		_ = a.store.DeleteSession(ctx, session.ID)
		return nil, ErrSessionExpired
	}

	// Update last used timestamp
	_ = a.store.UpdateSessionLastUsed(ctx, session.ID)

	return session, nil
}

// ListSessions returns all active sessions for a user
func (a *Auth) ListSessions(ctx context.Context, userID string) ([]*Session, error) {
	sessions, err := a.store.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Filter out expired sessions
	var activeSessions []*Session
	for _, s := range sessions {
		if !s.IsExpired() {
			activeSessions = append(activeSessions, s)
		} else {
			// Clean up expired sessions
			_ = a.store.DeleteSession(ctx, s.ID)
		}
	}

	return activeSessions, nil
}

// RevokeSession revokes a specific session by ID
func (a *Auth) RevokeSession(ctx context.Context, sessionID string) error {
	return a.store.DeleteSession(ctx, sessionID)
}

// RevokeAllSessions revokes all sessions for a user
func (a *Auth) RevokeAllSessions(ctx context.Context, userID string) error {
	return a.store.DeleteSessionsByUserID(ctx, userID)
}

// RefreshSession extends the expiration of a session
func (a *Auth) RefreshSession(ctx context.Context, sessionID string) (*Session, error) {
	session, err := a.store.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrSessionNotFound
	}

	// Update last used (which effectively refreshes the session)
	if err := a.store.UpdateSessionLastUsed(ctx, sessionID); err != nil {
		return nil, err
	}

	session.LastUsed = time.Now()
	return session, nil
}

// CleanupExpiredSessions removes all expired sessions from the database
func (a *Auth) CleanupExpiredSessions(ctx context.Context) error {
	return a.store.DeleteExpiredSessions(ctx)
}

// createSession creates a new session for a user
func (a *Auth) createSession(ctx context.Context, userID string, r *http.Request) (*Session, error) {
	rawToken, err := token.Generate()
	if err != nil {
		return nil, err
	}

	tokenHash := a.tokenHasher.Hash(rawToken)
	now := time.Now()

	var ipAddress, userAgent *string
	if r != nil {
		ip := getIPAddress(r)
		ipAddress = &ip

		ua := r.UserAgent()
		if len(ua) > 500 {
			ua = ua[:500]
		}
		userAgent = &ua
	}

	session := &Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		TokenHash: tokenHash,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: now,
		ExpiresAt: now.Add(a.config.SessionDuration),
		LastUsed:  now,
		RawToken:  rawToken,
	}

	if err := a.store.CreateSession(ctx, session); err != nil {
		return nil, err
	}

	return session, nil
}

// getIPAddress extracts the client IP from the request
func getIPAddress(r *http.Request) string {
	// Check X-Forwarded-For first (may be set by proxy)
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		// Take the first IP in the list
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP
	xri := r.Header.Get("X-Real-IP")
	if xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return r.RemoteAddr
}
