package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/token"
)

// Context keys for session management
type contextKey string

const (
	sessionContextKey contextKey = "auth_session"
	userContextKey    contextKey = "auth_user"
)

// SessionFromContext extracts the session from the request context
func SessionFromContext(ctx context.Context) *models.Session {
	if session, ok := ctx.Value(sessionContextKey).(*models.Session); ok {
		return session
	}
	return nil
}

// GetUserFromContext extracts the user from the request context
func GetUserFromContext(ctx context.Context) *models.User {
	if user, ok := ctx.Value(userContextKey).(*models.User); ok {
		return user
	}
	return nil
}

// contextWithSession adds a session to the context
func contextWithSession(ctx context.Context, session *models.Session) context.Context {
	return context.WithValue(ctx, sessionContextKey, session)
}

// contextWithUser adds a user to the context
func contextWithUser(ctx context.Context, user *models.User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

// GetSessionInfoFromRequest gets the session ID and user ID from the request context.
// Returns nil if no session is present. This method is used by plugins that need
// to access session information without depending on the full models package.
func (a *Auth) GetSessionInfoFromRequest(r *http.Request) *plugin.SessionInfo {
	session := SessionFromContext(r.Context())
	if session == nil {
		return nil
	}
	return &plugin.SessionInfo{
		ID:     session.ID,
		UserID: session.UserID,
	}
}

// ValidateSession validates a session token and returns the session if valid
func (a *Auth) ValidateSession(ctx context.Context, rawToken string) (*models.Session, error) {
	tokenHash := a.tokenHasher.Hash(rawToken)

	session, err := a.store.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, models.ErrSessionNotFound
	}

	// Check expiration
	if session.IsExpired() {
		_ = a.store.DeleteSession(ctx, session.ID)
		return nil, models.ErrSessionExpired
	}

	// Update last used timestamp
	_ = a.store.UpdateSessionLastUsed(ctx, session.ID)

	return session, nil
}

// ListSessions returns all active sessions for a user
func (a *Auth) ListSessions(ctx context.Context, userID string) ([]*models.Session, error) {
	sessions, err := a.store.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Filter out expired sessions
	var activeSessions []*models.Session
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

// GetSessionByID retrieves a session by its ID
func (a *Auth) GetSessionByID(ctx context.Context, sessionID string) (*models.Session, error) {
	return a.store.GetSessionByID(ctx, sessionID)
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
func (a *Auth) RefreshSession(ctx context.Context, sessionID string) (*models.Session, error) {
	session, err := a.store.GetSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, models.ErrSessionNotFound
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
func (a *Auth) createSession(ctx context.Context, userID string, r *http.Request) (*models.Session, error) {
	// Enforce max sessions per user limit
	if a.config.MaxSessionsPerUser > 0 {
		if err := a.enforceMaxSessions(ctx, userID); err != nil {
			a.config.Logger.Error("failed to enforce max sessions", "user_id", userID, "error", err)
			// Continue anyway - don't block session creation due to cleanup issues
		}
	}

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

	session := &models.Session{
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

// enforceMaxSessions deletes the oldest sessions if the user has too many.
// This ensures we have room for one new session.
func (a *Auth) enforceMaxSessions(ctx context.Context, userID string) error {
	sessions, err := a.store.ListSessionsByUserID(ctx, userID)
	if err != nil {
		return err
	}

	// Filter out expired sessions and get count
	var activeSessions []*models.Session
	for _, s := range sessions {
		if s.IsExpired() {
			// Clean up expired sessions
			_ = a.store.DeleteSession(ctx, s.ID)
		} else {
			activeSessions = append(activeSessions, s)
		}
	}

	// Need to leave room for the new session, so max allowed is MaxSessionsPerUser - 1
	maxAllowed := a.config.MaxSessionsPerUser - 1
	if len(activeSessions) <= maxAllowed {
		return nil
	}

	// Sort by LastUsed (oldest first) - sessions are typically returned in creation order,
	// but we want to delete the least recently used ones
	sortSessionsByLastUsed(activeSessions)

	// Delete oldest sessions to make room
	toDelete := len(activeSessions) - maxAllowed
	for i := 0; i < toDelete; i++ {
		if err := a.store.DeleteSession(ctx, activeSessions[i].ID); err != nil {
			a.config.Logger.Error("failed to delete old session",
				"session_id", activeSessions[i].ID,
				"error", err,
			)
		}
	}

	return nil
}

// sortSessionsByLastUsed sorts sessions by LastUsed time (oldest first)
func sortSessionsByLastUsed(sessions []*models.Session) {
	// Simple insertion sort - typically small number of sessions
	for i := 1; i < len(sessions); i++ {
		j := i
		for j > 0 && sessions[j].LastUsed.Before(sessions[j-1].LastUsed) {
			sessions[j], sessions[j-1] = sessions[j-1], sessions[j]
			j--
		}
	}
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
