package models

import (
	"context"
	"time"
)

// Session represents an authenticated user session
type Session struct {
	ID        string
	UserID    string
	TokenHash string
	IPAddress *string
	UserAgent *string
	CreatedAt time.Time
	ExpiresAt time.Time
	LastUsed  time.Time

	// ImpersonatedBy is the user ID of the admin who started this impersonation session.
	// If nil, this is a regular session (not impersonation).
	ImpersonatedBy *string

	// RawToken is not persisted - only set on creation
	RawToken string
}

// IsExpired returns true if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// IsImpersonation returns true if this is an impersonation session
func (s *Session) IsImpersonation() bool {
	return s.ImpersonatedBy != nil
}

// SessionStore defines session-related database operations
type SessionStore interface {
	CreateSession(ctx context.Context, session *Session) error
	GetSessionByID(ctx context.Context, id string) (*Session, error)
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	ListSessionsByUserID(ctx context.Context, userID string) ([]*Session, error)
	UpdateSessionLastUsed(ctx context.Context, id string) error
	DeleteSession(ctx context.Context, id string) error
	DeleteSessionsByUserID(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context) error
}
