// Package db provides database storage implementations for WebAuthn authentication.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/webauthn/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// =============================================================================
// Domain types
// =============================================================================

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

// =============================================================================
// Querier interface - each dialect implements this
// =============================================================================

// Querier defines all WebAuthn database operations.
// Each dialect implements this interface, handling type conversions internally.
type Querier interface {
	// Credential operations
	CreateCredential(ctx context.Context, cred *Credential) error
	GetCredentialByID(ctx context.Context, credentialID []byte) (*Credential, error)
	ListCredentialsByUserID(ctx context.Context, userID string) ([]*Credential, error)
	UpdateCredentialSignCount(ctx context.Context, id string, signCount int64, lastUsedAt time.Time) error
	DeleteCredential(ctx context.Context, id string) error

	// Session operations
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	DeleteExpiredSessions(ctx context.Context) error
}

// =============================================================================
// Store - delegates to dialect-specific Querier
// =============================================================================

// Store wraps the sqlc-generated queries for WebAuthn operations.
type Store struct {
	q Querier
}

// New creates a new Store for WebAuthn operations.
func New(db coredb.DBTX, dialect coredb.Dialect) (*Store, error) {
	var q Querier

	switch dialect {
	case coredb.DialectPostgres:
		q = newPgAdapter(db)
	case coredb.DialectMySQL:
		q = newMysqlAdapter(db)
	case coredb.DialectSQLite:
		q = newSqliteAdapter(db)
	default:
		return nil, fmt.Errorf("unsupported dialect: %s", dialect)
	}

	return &Store{q: q}, nil
}

// Delegate to Querier

func (s *Store) CreateCredential(ctx context.Context, cred *Credential) error {
	return s.q.CreateCredential(ctx, cred)
}

func (s *Store) GetCredentialByID(ctx context.Context, credentialID []byte) (*Credential, error) {
	return s.q.GetCredentialByID(ctx, credentialID)
}

func (s *Store) ListCredentialsByUserID(ctx context.Context, userID string) ([]*Credential, error) {
	return s.q.ListCredentialsByUserID(ctx, userID)
}

func (s *Store) UpdateCredentialSignCount(ctx context.Context, id string, signCount int64, lastUsedAt time.Time) error {
	return s.q.UpdateCredentialSignCount(ctx, id, signCount, lastUsedAt)
}

func (s *Store) DeleteCredential(ctx context.Context, id string) error {
	return s.q.DeleteCredential(ctx, id)
}

func (s *Store) CreateSession(ctx context.Context, session *Session) error {
	return s.q.CreateSession(ctx, session)
}

func (s *Store) GetSession(ctx context.Context, id string) (*Session, error) {
	return s.q.GetSession(ctx, id)
}

func (s *Store) DeleteSession(ctx context.Context, id string) error {
	return s.q.DeleteSession(ctx, id)
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	return s.q.DeleteExpiredSessions(ctx)
}

// =============================================================================
// PostgreSQL adapter
// =============================================================================

type pgAdapter struct {
	q *pgstore.Queries
}

func newPgAdapter(db coredb.DBTX) *pgAdapter {
	return &pgAdapter{q: pgstore.New(db)}
}

func (a *pgAdapter) CreateCredential(ctx context.Context, cred *Credential) error {
	var lastUsedAt sql.NullTime
	if cred.LastUsedAt != nil {
		lastUsedAt = sql.NullTime{Time: *cred.LastUsedAt, Valid: true}
	}
	return a.q.CreateWebAuthnCredential(ctx, pgstore.CreateWebAuthnCredentialParams{
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

func (a *pgAdapter) GetCredentialByID(ctx context.Context, credentialID []byte) (*Credential, error) {
	row, err := a.q.GetWebAuthnCredentialByID(ctx, credentialID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgCredentialToDomain(&row), nil
}

func (a *pgAdapter) ListCredentialsByUserID(ctx context.Context, userID string) ([]*Credential, error) {
	rows, err := a.q.ListWebAuthnCredentialsByUserID(ctx, userID)
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

func (a *pgAdapter) UpdateCredentialSignCount(ctx context.Context, id string, signCount int64, lastUsedAt time.Time) error {
	return a.q.UpdateWebAuthnCredentialSignCount(ctx, pgstore.UpdateWebAuthnCredentialSignCountParams{
		ID:         id,
		SignCount:  int32(signCount),
		LastUsedAt: sql.NullTime{Time: lastUsedAt, Valid: true},
	})
}

func (a *pgAdapter) DeleteCredential(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnCredential(ctx, id)
}

func (a *pgAdapter) CreateSession(ctx context.Context, session *Session) error {
	return a.q.CreateWebAuthnSession(ctx, pgstore.CreateWebAuthnSessionParams{
		ID:        session.ID,
		UserID:    toNullString(session.UserID),
		Type:      session.Type,
		Data:      session.Data,
		ExpiresAt: session.ExpiresAt,
		CreatedAt: session.CreatedAt,
	})
}

func (a *pgAdapter) GetSession(ctx context.Context, id string) (*Session, error) {
	row, err := a.q.GetWebAuthnSession(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgSessionToDomain(&row), nil
}

func (a *pgAdapter) DeleteSession(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnSession(ctx, id)
}

func (a *pgAdapter) DeleteExpiredSessions(ctx context.Context) error {
	return a.q.DeleteExpiredWebAuthnSessions(ctx, time.Now())
}

var _ Querier = (*pgAdapter)(nil)

// =============================================================================
// MySQL adapter
// =============================================================================

type mysqlAdapter struct {
	q *mysqlstore.Queries
}

func newMysqlAdapter(db coredb.DBTX) *mysqlAdapter {
	return &mysqlAdapter{q: mysqlstore.New(db)}
}

func (a *mysqlAdapter) CreateCredential(ctx context.Context, cred *Credential) error {
	var lastUsedAt sql.NullTime
	if cred.LastUsedAt != nil {
		lastUsedAt = sql.NullTime{Time: *cred.LastUsedAt, Valid: true}
	}
	return a.q.CreateWebAuthnCredential(ctx, mysqlstore.CreateWebAuthnCredentialParams{
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

func (a *mysqlAdapter) GetCredentialByID(ctx context.Context, credentialID []byte) (*Credential, error) {
	row, err := a.q.GetWebAuthnCredentialByID(ctx, credentialID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlCredentialToDomain(&row), nil
}

func (a *mysqlAdapter) ListCredentialsByUserID(ctx context.Context, userID string) ([]*Credential, error) {
	rows, err := a.q.ListWebAuthnCredentialsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	creds := make([]*Credential, len(rows))
	for i, row := range rows {
		r := row
		creds[i] = mysqlCredentialToDomain(&r)
	}
	return creds, nil
}

func (a *mysqlAdapter) UpdateCredentialSignCount(ctx context.Context, id string, signCount int64, lastUsedAt time.Time) error {
	return a.q.UpdateWebAuthnCredentialSignCount(ctx, mysqlstore.UpdateWebAuthnCredentialSignCountParams{
		ID:         id,
		SignCount:  int32(signCount),
		LastUsedAt: sql.NullTime{Time: lastUsedAt, Valid: true},
	})
}

func (a *mysqlAdapter) DeleteCredential(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnCredential(ctx, id)
}

func (a *mysqlAdapter) CreateSession(ctx context.Context, session *Session) error {
	return a.q.CreateWebAuthnSession(ctx, mysqlstore.CreateWebAuthnSessionParams{
		ID:        session.ID,
		UserID:    toNullString(session.UserID),
		Type:      session.Type,
		Data:      session.Data,
		ExpiresAt: session.ExpiresAt,
		CreatedAt: session.CreatedAt,
	})
}

func (a *mysqlAdapter) GetSession(ctx context.Context, id string) (*Session, error) {
	row, err := a.q.GetWebAuthnSession(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlSessionToDomain(&row), nil
}

func (a *mysqlAdapter) DeleteSession(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnSession(ctx, id)
}

func (a *mysqlAdapter) DeleteExpiredSessions(ctx context.Context) error {
	return a.q.DeleteExpiredWebAuthnSessions(ctx, time.Now())
}

var _ Querier = (*mysqlAdapter)(nil)

// =============================================================================
// SQLite adapter
// =============================================================================

type sqliteAdapter struct {
	q *sqlitestore.Queries
}

func newSqliteAdapter(db coredb.DBTX) *sqliteAdapter {
	return &sqliteAdapter{q: sqlitestore.New(db)}
}

func (a *sqliteAdapter) CreateCredential(ctx context.Context, cred *Credential) error {
	var lastUsedAt sql.NullString
	if cred.LastUsedAt != nil {
		lastUsedAt = sql.NullString{String: cred.LastUsedAt.Format(time.RFC3339), Valid: true}
	}
	return a.q.CreateWebAuthnCredential(ctx, sqlitestore.CreateWebAuthnCredentialParams{
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

func (a *sqliteAdapter) GetCredentialByID(ctx context.Context, credentialID []byte) (*Credential, error) {
	row, err := a.q.GetWebAuthnCredentialByID(ctx, credentialID)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteCredentialToDomain(&row), nil
}

func (a *sqliteAdapter) ListCredentialsByUserID(ctx context.Context, userID string) ([]*Credential, error) {
	rows, err := a.q.ListWebAuthnCredentialsByUserID(ctx, userID)
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

func (a *sqliteAdapter) UpdateCredentialSignCount(ctx context.Context, id string, signCount int64, lastUsedAt time.Time) error {
	return a.q.UpdateWebAuthnCredentialSignCount(ctx, sqlitestore.UpdateWebAuthnCredentialSignCountParams{
		ID:         id,
		SignCount:  signCount,
		LastUsedAt: sql.NullString{String: lastUsedAt.Format(time.RFC3339), Valid: true},
	})
}

func (a *sqliteAdapter) DeleteCredential(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnCredential(ctx, id)
}

func (a *sqliteAdapter) CreateSession(ctx context.Context, session *Session) error {
	return a.q.CreateWebAuthnSession(ctx, sqlitestore.CreateWebAuthnSessionParams{
		ID:        session.ID,
		UserID:    toNullString(session.UserID),
		Type:      session.Type,
		Data:      session.Data,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
		CreatedAt: session.CreatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetSession(ctx context.Context, id string) (*Session, error) {
	row, err := a.q.GetWebAuthnSession(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteSessionToDomain(&row), nil
}

func (a *sqliteAdapter) DeleteSession(ctx context.Context, id string) error {
	return a.q.DeleteWebAuthnSession(ctx, id)
}

func (a *sqliteAdapter) DeleteExpiredSessions(ctx context.Context) error {
	return a.q.DeleteExpiredWebAuthnSessions(ctx, time.Now().Format(time.RFC3339))
}

var _ Querier = (*sqliteAdapter)(nil)

// =============================================================================
// Conversion helpers
// =============================================================================

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

func mysqlCredentialToDomain(row *mysqlstore.WebauthnCredential) *Credential {
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

func mysqlSessionToDomain(row *mysqlstore.WebauthnSession) *Session {
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
