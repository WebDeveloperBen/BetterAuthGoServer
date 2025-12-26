package webauthn

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uptrace/bun"
)

// Store handles WebAuthn credential and session persistence.
type Store struct {
	db                      *bun.DB
	credentialsTableCreated bool
	sessionsTableCreated    bool
}

// NewStore creates a new WebAuthn store.
func NewStore(db *bun.DB) *Store {
	return &Store{db: db}
}

func (s *Store) ensureCredentialsTable(ctx context.Context) error {
	if s.credentialsTableCreated {
		return nil
	}

	_, err := s.db.NewCreateTable().
		Model((*WebAuthnCredential)(nil)).
		IfNotExists().
		Exec(ctx)
	if err != nil {
		return err
	}

	_, _ = s.db.NewCreateIndex().
		Model((*WebAuthnCredential)(nil)).
		Index("idx_webauthn_credentials_credential_id").
		Column("credential_id").
		IfNotExists().
		Exec(ctx)

	_, _ = s.db.NewCreateIndex().
		Model((*WebAuthnCredential)(nil)).
		Index("idx_webauthn_credentials_user_id").
		Column("user_id").
		IfNotExists().
		Exec(ctx)

	s.credentialsTableCreated = true
	return nil
}

func (s *Store) ensureSessionsTable(ctx context.Context) error {
	if s.sessionsTableCreated {
		return nil
	}

	_, err := s.db.NewCreateTable().
		Model((*WebAuthnSession)(nil)).
		IfNotExists().
		Exec(ctx)
	if err != nil {
		return err
	}

	_, _ = s.db.NewCreateIndex().
		Model((*WebAuthnSession)(nil)).
		Index("idx_webauthn_sessions_expires_at").
		Column("expires_at").
		IfNotExists().
		Exec(ctx)

	_, _ = s.db.NewCreateIndex().
		Model((*WebAuthnSession)(nil)).
		Index("idx_webauthn_sessions_user_id").
		Column("user_id").
		IfNotExists().
		Exec(ctx)

	s.sessionsTableCreated = true
	return nil
}

// CreateCredential stores a new WebAuthn credential.
func (s *Store) CreateCredential(ctx context.Context, credential *WebAuthnCredential) error {
	if err := s.ensureCredentialsTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewInsert().
		Model(credential).
		Exec(ctx)
	return err
}

// GetCredentialByID retrieves a credential by its credential ID.
func (s *Store) GetCredentialByID(ctx context.Context, credentialID []byte) (*WebAuthnCredential, error) {
	if err := s.ensureCredentialsTable(ctx); err != nil {
		return nil, err
	}

	credential := new(WebAuthnCredential)
	err := s.db.NewSelect().
		Model(credential).
		Where("credential_id = ?", credentialID).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return credential, nil
}

// ListCredentialsByUser returns all credentials for a user.
func (s *Store) ListCredentialsByUser(ctx context.Context, userID string) ([]*WebAuthnCredential, error) {
	if err := s.ensureCredentialsTable(ctx); err != nil {
		return nil, err
	}

	var credentials []*WebAuthnCredential
	err := s.db.NewSelect().
		Model(&credentials).
		Where("user_id = ?", userID).
		Order("created_at ASC").
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// UpdateCredentialSignCount updates the sign count and last used time.
func (s *Store) UpdateCredentialSignCount(ctx context.Context, id string, signCount uint32, lastUsedAt time.Time) error {
	if err := s.ensureCredentialsTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewUpdate().
		Model((*WebAuthnCredential)(nil)).
		Set("sign_count = ?", signCount).
		Set("last_used_at = ?", lastUsedAt).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// DeleteCredential deletes a credential by record ID.
func (s *Store) DeleteCredential(ctx context.Context, id string) error {
	if err := s.ensureCredentialsTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewDelete().
		Model((*WebAuthnCredential)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// CreateSession stores a new WebAuthn session.
func (s *Store) CreateSession(ctx context.Context, session *WebAuthnSession) error {
	if err := s.ensureSessionsTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewInsert().
		Model(session).
		Exec(ctx)
	return err
}

// GetSession retrieves a WebAuthn session by ID.
func (s *Store) GetSession(ctx context.Context, id string) (*WebAuthnSession, error) {
	if err := s.ensureSessionsTable(ctx); err != nil {
		return nil, err
	}

	session := new(WebAuthnSession)
	err := s.db.NewSelect().
		Model(session).
		Where("id = ?", id).
		Scan(ctx)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	return session, nil
}

// DeleteSession deletes a WebAuthn session by ID.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	if err := s.ensureSessionsTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewDelete().
		Model((*WebAuthnSession)(nil)).
		Where("id = ?", id).
		Exec(ctx)
	return err
}

// DeleteExpiredSessions removes all expired sessions.
func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	if err := s.ensureSessionsTable(ctx); err != nil {
		return err
	}

	_, err := s.db.NewDelete().
		Model((*WebAuthnSession)(nil)).
		Where("expires_at < ?", time.Now()).
		Exec(ctx)
	return err
}
