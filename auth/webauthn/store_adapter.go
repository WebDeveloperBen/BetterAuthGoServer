package webauthn

import (
	"context"
	"strings"
	"time"

	webauthndb "github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn/db"
)

// StoreAdapter adapts webauthndb.Store to the WebAuthn package's Store interface.
type StoreAdapter struct {
	store *webauthndb.Store
}

// NewStoreAdapter creates a new WebAuthn store adapter from a webauthndb.Store.
func NewStoreAdapter(store *webauthndb.Store) *StoreAdapter {
	return &StoreAdapter{store: store}
}

// CreateCredential stores a new WebAuthn credential.
func (a *StoreAdapter) CreateCredential(ctx context.Context, credential *WebAuthnCredential) error {
	dbCred := &webauthndb.Credential{
		ID:           credential.ID,
		UserID:       credential.UserID,
		CredentialID: credential.CredentialID,
		PublicKey:    credential.PublicKey,
		SignCount:    int64(credential.SignCount),
		Transports:   a.transportsToString(credential.Transports),
		CreatedAt:    credential.CreatedAt,
		LastUsedAt:   a.timeToPtr(credential.LastUsedAt),
	}
	return a.store.CreateCredential(ctx, dbCred)
}

// GetCredentialByID retrieves a credential by its credential ID.
func (a *StoreAdapter) GetCredentialByID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error) {
	dbCred, err := a.store.GetCredentialByID(ctx, credentialID)
	if err != nil {
		return nil, err
	}
	if dbCred == nil {
		return nil, nil
	}
	return a.toWebAuthnCredential(dbCred), nil
}

// ListCredentialsByUser returns all credentials for a user.
func (a *StoreAdapter) ListCredentialsByUser(ctx context.Context, userID string) ([]*WebAuthnCredential, error) {
	dbCreds, err := a.store.ListCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	result := make([]*WebAuthnCredential, len(dbCreds))
	for i, dbCred := range dbCreds {
		result[i] = a.toWebAuthnCredential(dbCred)
	}
	return result, nil
}

// UpdateCredentialSignCount updates the sign count and last used time.
func (a *StoreAdapter) UpdateCredentialSignCount(ctx context.Context, id string, signCount uint32, lastUsedAt time.Time) error {
	return a.store.UpdateCredentialSignCount(ctx, id, int64(signCount), lastUsedAt)
}

// DeleteCredential deletes a credential by record ID.
func (a *StoreAdapter) DeleteCredential(ctx context.Context, id string) error {
	return a.store.DeleteCredential(ctx, id)
}

// CreateSession stores a new WebAuthn session.
func (a *StoreAdapter) CreateSession(ctx context.Context, session *WebAuthnSession) error {
	dbSession := &webauthndb.Session{
		ID:        session.ID,
		UserID:    session.UserID,
		Type:      session.Type,
		Data:      session.Data,
		ExpiresAt: session.ExpiresAt,
		CreatedAt: session.CreatedAt,
	}
	return a.store.CreateSession(ctx, dbSession)
}

// GetSession retrieves a WebAuthn session by ID.
func (a *StoreAdapter) GetSession(ctx context.Context, id string) (*WebAuthnSession, error) {
	dbSession, err := a.store.GetSession(ctx, id)
	if err != nil {
		return nil, err
	}
	if dbSession == nil {
		return nil, nil
	}
	return a.toWebAuthnSession(dbSession), nil
}

// DeleteSession deletes a WebAuthn session by ID.
func (a *StoreAdapter) DeleteSession(ctx context.Context, id string) error {
	return a.store.DeleteSession(ctx, id)
}

// DeleteExpiredSessions removes all expired sessions.
func (a *StoreAdapter) DeleteExpiredSessions(ctx context.Context) error {
	return a.store.DeleteExpiredSessions(ctx)
}

// toWebAuthnCredential converts a webauthndb.Credential to a WebAuthnCredential.
func (a *StoreAdapter) toWebAuthnCredential(c *webauthndb.Credential) *WebAuthnCredential {
	var lastUsedAt time.Time
	if c.LastUsedAt != nil {
		lastUsedAt = *c.LastUsedAt
	}
	return &WebAuthnCredential{
		ID:           c.ID,
		UserID:       c.UserID,
		CredentialID: c.CredentialID,
		PublicKey:    c.PublicKey,
		SignCount:    uint32(c.SignCount),
		Transports:   a.stringToTransports(c.Transports),
		CreatedAt:    c.CreatedAt,
		LastUsedAt:   lastUsedAt,
	}
}

// toWebAuthnSession converts a webauthndb.Session to a WebAuthnSession.
func (a *StoreAdapter) toWebAuthnSession(s *webauthndb.Session) *WebAuthnSession {
	return &WebAuthnSession{
		ID:        s.ID,
		UserID:    s.UserID,
		Type:      s.Type,
		Data:      s.Data,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
	}
}

// transportsToString converts a slice of transport strings to a comma-separated string.
func (a *StoreAdapter) transportsToString(transports []string) *string {
	if len(transports) == 0 {
		return nil
	}
	s := strings.Join(transports, ",")
	return &s
}

// stringToTransports converts a comma-separated string to a slice of transport strings.
func (a *StoreAdapter) stringToTransports(s *string) []string {
	if s == nil || *s == "" {
		return nil
	}
	return strings.Split(*s, ",")
}

// timeToPtr converts a time.Time to a pointer, returning nil for zero time.
func (a *StoreAdapter) timeToPtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
