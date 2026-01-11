// Package db provides database storage implementations for WebAuthn authentication.
package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Credential represents a WebAuthn credential.
type Credential struct {
	ID           string
	UserID       string
	CredentialID []byte
	PublicKey    []byte
	SignCount    int64
	Transports   *string
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// Session represents a WebAuthn session (registration/login ceremony state).
type Session struct {
	ID        string
	UserID    *string
	Type      string
	Data      []byte
	ExpiresAt time.Time
	CreatedAt time.Time
}

// IsExpired returns true if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// Store wraps the sqlc-generated queries for WebAuthn operations.
type Store struct {
	dialect coredb.Dialect
	pgQ     *pgstore.Queries
	sqliteQ *sqlitestore.Queries
}

// New creates a new Store for WebAuthn operations.
func New(db coredb.DBTX, dialect coredb.Dialect) *Store {
	s := &Store{dialect: dialect}
	if dialect == coredb.DialectPostgres {
		s.pgQ = pgstore.New(db)
	} else {
		s.sqliteQ = sqlitestore.New(db)
	}
	return s
}

// ---- Credential operations ----

// CreateCredential stores a new WebAuthn credential.
func (s *Store) CreateCredential(ctx context.Context, cred *Credential) error {
	if s.dialect == coredb.DialectPostgres {
		var lastUsedAt sql.NullTime
		if cred.LastUsedAt != nil {
			lastUsedAt = sql.NullTime{Time: *cred.LastUsedAt, Valid: true}
		}
		return s.pgQ.CreateWebAuthnCredential(ctx, pgstore.CreateWebAuthnCredentialParams{
			ID:           cred.ID,
			UserID:       cred.UserID,
			CredentialID: cred.CredentialID,
			PublicKey:    cred.PublicKey,
			SignCount:    int32(cred.SignCount),
			Transports:   toNullString(cred.Transports),
			CreatedAt:    cred.CreatedAt,
			LastUsedAt:   lastUsedAt,
		})
	}
	var lastUsedAt sql.NullString
	if cred.LastUsedAt != nil {
		lastUsedAt = sql.NullString{String: cred.LastUsedAt.Format(time.RFC3339), Valid: true}
	}
	return s.sqliteQ.CreateWebAuthnCredential(ctx, sqlitestore.CreateWebAuthnCredentialParams{
		ID:           cred.ID,
		UserID:       cred.UserID,
		CredentialID: cred.CredentialID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.SignCount,
		Transports:   toNullString(cred.Transports),
		CreatedAt:    cred.CreatedAt.Format(time.RFC3339),
		LastUsedAt:   lastUsedAt,
	})
}

// GetCredentialByID retrieves a credential by its credential ID.
func (s *Store) GetCredentialByID(ctx context.Context, credentialID []byte) (*Credential, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetWebAuthnCredentialByID(ctx, credentialID)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgCredentialToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetWebAuthnCredentialByID(ctx, credentialID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteCredentialToDomain(&row), nil
}

// ListCredentialsByUserID returns all credentials for a user.
func (s *Store) ListCredentialsByUserID(ctx context.Context, userID string) ([]*Credential, error) {
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.ListWebAuthnCredentialsByUserID(ctx, userID)
		if err != nil {
			return nil, err
		}
		creds := make([]*Credential, len(rows))
		for i, row := range rows {
			r := row
			creds[i] = pgCredentialToDomain(&r)
		}
		return creds, nil
	}
	rows, err := s.sqliteQ.ListWebAuthnCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds := make([]*Credential, len(rows))
	for i, row := range rows {
		r := row
		creds[i] = sqliteCredentialToDomain(&r)
	}
	return creds, nil
}

// UpdateCredentialSignCount updates the sign count and last used time.
func (s *Store) UpdateCredentialSignCount(ctx context.Context, id string, signCount int64, lastUsedAt time.Time) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.UpdateWebAuthnCredentialSignCount(ctx, pgstore.UpdateWebAuthnCredentialSignCountParams{
			ID:         id,
			SignCount:  int32(signCount),
			LastUsedAt: sql.NullTime{Time: lastUsedAt, Valid: true},
		})
	}
	return s.sqliteQ.UpdateWebAuthnCredentialSignCount(ctx, sqlitestore.UpdateWebAuthnCredentialSignCountParams{
		ID:         id,
		SignCount:  signCount,
		LastUsedAt: sql.NullString{String: lastUsedAt.Format(time.RFC3339), Valid: true},
	})
}

// DeleteCredential deletes a credential by record ID.
func (s *Store) DeleteCredential(ctx context.Context, id string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteWebAuthnCredential(ctx, id)
	}
	return s.sqliteQ.DeleteWebAuthnCredential(ctx, id)
}

// ---- Session operations ----

// CreateSession stores a new WebAuthn session.
func (s *Store) CreateSession(ctx context.Context, session *Session) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateWebAuthnSession(ctx, pgstore.CreateWebAuthnSessionParams{
			ID:        session.ID,
			UserID:    toNullString(session.UserID),
			Type:      session.Type,
			Data:      session.Data,
			ExpiresAt: session.ExpiresAt,
			CreatedAt: session.CreatedAt,
		})
	}
	return s.sqliteQ.CreateWebAuthnSession(ctx, sqlitestore.CreateWebAuthnSessionParams{
		ID:        session.ID,
		UserID:    toNullString(session.UserID),
		Type:      session.Type,
		Data:      session.Data,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		CreatedAt: session.CreatedAt.Format(time.RFC3339),
	})
}

// GetSession retrieves a WebAuthn session by ID.
func (s *Store) GetSession(ctx context.Context, id string) (*Session, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetWebAuthnSession(ctx, id)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgSessionToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetWebAuthnSession(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteSessionToDomain(&row), nil
}

// DeleteSession deletes a WebAuthn session by ID.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteWebAuthnSession(ctx, id)
	}
	return s.sqliteQ.DeleteWebAuthnSession(ctx, id)
}

// DeleteExpiredSessions removes all expired sessions.
func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteExpiredWebAuthnSessions(ctx, now)
	}
	return s.sqliteQ.DeleteExpiredWebAuthnSessions(ctx, now.Format(time.RFC3339))
}

// ---- Conversion helpers ----

func toNullString(s *string) sql.NullString {
	if s == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *s, Valid: true}
}

func fromNullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}

func pgCredentialToDomain(row *pgstore.WebauthnCredential) *Credential {
	cred := &Credential{
		ID:           row.ID,
		UserID:       row.UserID,
		CredentialID: row.CredentialID,
		PublicKey:    row.PublicKey,
		SignCount:    int64(row.SignCount),
		Transports:   fromNullString(row.Transports),
		CreatedAt:    row.CreatedAt,
	}
	if row.LastUsedAt.Valid {
		cred.LastUsedAt = &row.LastUsedAt.Time
	}
	return cred
}

func sqliteCredentialToDomain(row *sqlitestore.WebauthnCredential) *Credential {
	cred := &Credential{
		ID:           row.ID,
		UserID:       row.UserID,
		CredentialID: row.CredentialID,
		PublicKey:    row.PublicKey,
		SignCount:    row.SignCount,
		Transports:   fromNullString(row.Transports),
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		cred.CreatedAt = t
	}
	if row.LastUsedAt.Valid {
		if t, err := time.Parse(time.RFC3339, row.LastUsedAt.String); err == nil {
			cred.LastUsedAt = &t
		}
	}
	return cred
}

func pgSessionToDomain(row *pgstore.WebauthnSession) *Session {
	return &Session{
		ID:        row.ID,
		UserID:    fromNullString(row.UserID),
		Type:      row.Type,
		Data:      row.Data,
		ExpiresAt: row.ExpiresAt,
		CreatedAt: row.CreatedAt,
	}
}

func sqliteSessionToDomain(row *sqlitestore.WebauthnSession) *Session {
	session := &Session{
		ID:     row.ID,
		UserID: fromNullString(row.UserID),
		Type:   row.Type,
		Data:   row.Data,
	}
	if t, err := time.Parse(time.RFC3339, row.ExpiresAt); err == nil {
		session.ExpiresAt = t
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		session.CreatedAt = t
	}
	return session
}
