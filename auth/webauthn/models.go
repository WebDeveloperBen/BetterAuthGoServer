package webauthn

import (
	"time"

	"github.com/uptrace/bun"
)

// WebAuthnCredential represents a stored WebAuthn credential.
type WebAuthnCredential struct {
	bun.BaseModel `bun:"table:webauthn_credentials"`

	ID           string    `bun:"id,pk"`
	UserID       string    `bun:"user_id,notnull"`
	CredentialID []byte    `bun:"credential_id,notnull"`
	PublicKey    []byte    `bun:"public_key,notnull"`
	SignCount    uint32    `bun:"sign_count,notnull"`
	Transports   []string  `bun:"transports,array"`
	CreatedAt    time.Time `bun:"created_at,notnull,default:current_timestamp"`
	LastUsedAt   time.Time `bun:"last_used_at,nullzero"`
}

// WebAuthnSession stores registration/login session data between requests.
type WebAuthnSession struct {
	bun.BaseModel `bun:"table:webauthn_sessions"`

	ID        string    `bun:"id,pk"`
	UserID    *string   `bun:"user_id"`
	Type      string    `bun:"type,notnull"`
	Data      []byte    `bun:"data,notnull"`
	ExpiresAt time.Time `bun:"expires_at,notnull"`
	CreatedAt time.Time `bun:"created_at,notnull"`
}

// IsExpired returns true if the session has expired.
func (s *WebAuthnSession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
