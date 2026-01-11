package webauthn

import (
	"time"
)

// WebAuthnCredential represents a stored WebAuthn credential.
type WebAuthnCredential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	Transports   []string
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

// WebAuthnSession stores registration/login session data between requests.
type WebAuthnSession struct {
	ID        string
	UserID    *string
	Type      string
	Data      []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired returns true if the session has expired.
func (s *WebAuthnSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
