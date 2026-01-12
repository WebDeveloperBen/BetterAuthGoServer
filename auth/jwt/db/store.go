// Package db provides database storage implementations for JWT token management.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// =============================================================================
// Domain types
// =============================================================================

// JWTKey represents a JWT signing/verification key.
type JWTKey struct {
	ID            string
	Algorithm     string
	Use           string
	KeyType       string
	Status        string
	PrivateKeyEnc string
	PublicKeyJWK  string
	ActivatedAt   time.Time
	RotatedAt     *time.Time
	ExpiresAt     *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// RevokedToken represents a revoked JWT token in the blocklist.
type RevokedToken struct {
	ID        string
	ExpiresAt time.Time
	RevokedAt time.Time
}

// =============================================================================
// Querier interface - each dialect implements this
// =============================================================================

// Querier defines all JWT database operations.
// Each dialect implements this interface, handling type conversions internally.
type Querier interface {
	// Blocklist operations
	RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error
	IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error)
	DeleteExpiredRevokedTokens(ctx context.Context) error

	// Key management operations
	CreateJWTKey(ctx context.Context, key *JWTKey) error
	GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error)
	GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error)
	GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error)
	GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error)
	RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error
	RetireExpiredJWTKeys(ctx context.Context) (int64, error)
	DeleteJWTKey(ctx context.Context, id string) error
}

// =============================================================================
// Store - delegates to dialect-specific Querier
// =============================================================================

// Store wraps the sqlc-generated queries for JWT operations.
type Store struct {
	q Querier
}

// New creates a new Store for JWT operations.
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

// Blocklist operations - delegate to Querier

func (s *Store) RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return s.q.RevokeJWTToken(ctx, jti, expiresAt)
}

func (s *Store) IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return s.q.IsJWTTokenRevoked(ctx, jti)
}

func (s *Store) DeleteExpiredRevokedTokens(ctx context.Context) error {
	return s.q.DeleteExpiredRevokedTokens(ctx)
}

// Key management operations - delegate to Querier

func (s *Store) CreateJWTKey(ctx context.Context, key *JWTKey) error {
	return s.q.CreateJWTKey(ctx, key)
}

func (s *Store) GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error) {
	return s.q.GetJWTKeyByID(ctx, id)
}

func (s *Store) GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error) {
	return s.q.GetActiveJWTKey(ctx, algorithm)
}

func (s *Store) GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error) {
	return s.q.GetJWTKeysForVerification(ctx, algorithm)
}

func (s *Store) GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error) {
	return s.q.GetJWTKeyForVerification(ctx, id)
}

func (s *Store) RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error {
	return s.q.RotateActiveJWTKeys(ctx, algorithm, expiresAt)
}

func (s *Store) RetireExpiredJWTKeys(ctx context.Context) (int64, error) {
	return s.q.RetireExpiredJWTKeys(ctx)
}

func (s *Store) DeleteJWTKey(ctx context.Context, id string) error {
	return s.q.DeleteJWTKey(ctx, id)
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

func (a *pgAdapter) RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return a.q.RevokeJWTToken(ctx, pgstore.RevokeJWTTokenParams{
		ID:        jti,
		ExpiresAt: expiresAt,
		RevokedAt: time.Now(),
	})
}

func (a *pgAdapter) IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return a.q.IsJWTTokenRevoked(ctx, jti)
}

func (a *pgAdapter) DeleteExpiredRevokedTokens(ctx context.Context) error {
	return a.q.DeleteExpiredRevokedTokens(ctx, time.Now())
}

func (a *pgAdapter) CreateJWTKey(ctx context.Context, key *JWTKey) error {
	return a.q.CreateJWTKey(ctx, pgstore.CreateJWTKeyParams{
		ID:            key.ID,
		Algorithm:     key.Algorithm,
		Use:           key.Use,
		Kty:           key.KeyType,
		Status:        key.Status,
		PrivateKeyEnc: key.PrivateKeyEnc,
		PublicKeyJwk:  key.PublicKeyJWK,
		ActivatedAt:   key.ActivatedAt,
		CreatedAt:     key.CreatedAt,
		UpdatedAt:     key.UpdatedAt,
	})
}

func (a *pgAdapter) GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error) {
	row, err := a.q.GetJWTKeyByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgKeyToDomain(&row), nil
}

func (a *pgAdapter) GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error) {
	row, err := a.q.GetActiveJWTKey(ctx, algorithm)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgKeyToDomain(&row), nil
}

func (a *pgAdapter) GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error) {
	now := time.Now()
	rows, err := a.q.GetJWTKeysForVerification(ctx, pgstore.GetJWTKeysForVerificationParams{
		Algorithm: algorithm,
		ExpiresAt: sql.NullTime{Time: now, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	keys := make([]*JWTKey, len(rows))
	for i, row := range rows {
		r := row
		keys[i] = pgKeyToDomain(&r)
	}
	return keys, nil
}

func (a *pgAdapter) GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error) {
	now := time.Now()
	row, err := a.q.GetJWTKeyForVerification(ctx, pgstore.GetJWTKeyForVerificationParams{
		ID:        id,
		ExpiresAt: sql.NullTime{Time: now, Valid: true},
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return pgKeyToDomain(&row), nil
}

func (a *pgAdapter) RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error {
	now := time.Now()
	return a.q.RotateActiveJWTKeys(ctx, pgstore.RotateActiveJWTKeysParams{
		RotatedAt: sql.NullTime{Time: now, Valid: true},
		ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
		UpdatedAt: now,
		Algorithm: algorithm,
	})
}

func (a *pgAdapter) RetireExpiredJWTKeys(ctx context.Context) (int64, error) {
	now := time.Now()
	return a.q.RetireExpiredJWTKeys(ctx, pgstore.RetireExpiredJWTKeysParams{
		UpdatedAt: now,
		ExpiresAt: sql.NullTime{Time: now, Valid: true},
	})
}

func (a *pgAdapter) DeleteJWTKey(ctx context.Context, id string) error {
	return a.q.DeleteJWTKey(ctx, id)
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

func (a *mysqlAdapter) RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return a.q.RevokeJWTToken(ctx, mysqlstore.RevokeJWTTokenParams{
		ID:        jti,
		ExpiresAt: expiresAt,
		RevokedAt: time.Now(),
	})
}

func (a *mysqlAdapter) IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error) {
	return a.q.IsJWTTokenRevoked(ctx, jti)
}

func (a *mysqlAdapter) DeleteExpiredRevokedTokens(ctx context.Context) error {
	return a.q.DeleteExpiredRevokedTokens(ctx, time.Now())
}

func (a *mysqlAdapter) CreateJWTKey(ctx context.Context, key *JWTKey) error {
	return a.q.CreateJWTKey(ctx, mysqlstore.CreateJWTKeyParams{
		ID:            key.ID,
		Algorithm:     key.Algorithm,
		Use:           key.Use,
		Kty:           key.KeyType,
		Status:        key.Status,
		PrivateKeyEnc: key.PrivateKeyEnc,
		PublicKeyJwk:  key.PublicKeyJWK,
		ActivatedAt:   key.ActivatedAt,
		CreatedAt:     key.CreatedAt,
		UpdatedAt:     key.UpdatedAt,
	})
}

func (a *mysqlAdapter) GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error) {
	row, err := a.q.GetJWTKeyByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlKeyToDomain(&row), nil
}

func (a *mysqlAdapter) GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error) {
	row, err := a.q.GetActiveJWTKey(ctx, algorithm)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlKeyToDomain(&row), nil
}

func (a *mysqlAdapter) GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error) {
	now := time.Now()
	rows, err := a.q.GetJWTKeysForVerification(ctx, mysqlstore.GetJWTKeysForVerificationParams{
		Algorithm: algorithm,
		ExpiresAt: sql.NullTime{Time: now, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	keys := make([]*JWTKey, len(rows))
	for i, row := range rows {
		r := row
		keys[i] = mysqlKeyToDomain(&r)
	}
	return keys, nil
}

func (a *mysqlAdapter) GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error) {
	now := time.Now()
	row, err := a.q.GetJWTKeyForVerification(ctx, mysqlstore.GetJWTKeyForVerificationParams{
		ID:        id,
		ExpiresAt: sql.NullTime{Time: now, Valid: true},
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return mysqlKeyToDomain(&row), nil
}

func (a *mysqlAdapter) RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error {
	now := time.Now()
	return a.q.RotateActiveJWTKeys(ctx, mysqlstore.RotateActiveJWTKeysParams{
		RotatedAt: sql.NullTime{Time: now, Valid: true},
		ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
		UpdatedAt: now,
		Algorithm: algorithm,
	})
}

func (a *mysqlAdapter) RetireExpiredJWTKeys(ctx context.Context) (int64, error) {
	now := time.Now()
	return a.q.RetireExpiredJWTKeys(ctx, mysqlstore.RetireExpiredJWTKeysParams{
		UpdatedAt: now,
		ExpiresAt: sql.NullTime{Time: now, Valid: true},
	})
}

func (a *mysqlAdapter) DeleteJWTKey(ctx context.Context, id string) error {
	return a.q.DeleteJWTKey(ctx, id)
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

func (a *sqliteAdapter) RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return a.q.RevokeJWTToken(ctx, sqlitestore.RevokeJWTTokenParams{
		ID:        jti,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		RevokedAt: time.Now().Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error) {
	count, err := a.q.IsJWTTokenRevoked(ctx, jti)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (a *sqliteAdapter) DeleteExpiredRevokedTokens(ctx context.Context) error {
	return a.q.DeleteExpiredRevokedTokens(ctx, time.Now().Format(time.RFC3339))
}

func (a *sqliteAdapter) CreateJWTKey(ctx context.Context, key *JWTKey) error {
	return a.q.CreateJWTKey(ctx, sqlitestore.CreateJWTKeyParams{
		ID:            key.ID,
		Algorithm:     key.Algorithm,
		Use:           key.Use,
		Kty:           key.KeyType,
		Status:        key.Status,
		PrivateKeyEnc: key.PrivateKeyEnc,
		PublicKeyJwk:  key.PublicKeyJWK,
		ActivatedAt:   key.ActivatedAt.Format(time.RFC3339),
		CreatedAt:     key.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     key.UpdatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error) {
	row, err := a.q.GetJWTKeyByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteKeyToDomain(&row), nil
}

func (a *sqliteAdapter) GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error) {
	row, err := a.q.GetActiveJWTKey(ctx, algorithm)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteKeyToDomain(&row), nil
}

func (a *sqliteAdapter) GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error) {
	now := time.Now()
	rows, err := a.q.GetJWTKeysForVerification(ctx, sqlitestore.GetJWTKeysForVerificationParams{
		Algorithm: algorithm,
		ExpiresAt: sql.NullString{String: now.Format(time.RFC3339), Valid: true},
	})
	if err != nil {
		return nil, err
	}
	keys := make([]*JWTKey, len(rows))
	for i, row := range rows {
		r := row
		keys[i] = sqliteKeyToDomain(&r)
	}
	return keys, nil
}

func (a *sqliteAdapter) GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error) {
	now := time.Now()
	row, err := a.q.GetJWTKeyForVerification(ctx, sqlitestore.GetJWTKeyForVerificationParams{
		ID:        id,
		ExpiresAt: sql.NullString{String: now.Format(time.RFC3339), Valid: true},
	})
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteKeyToDomain(&row), nil
}

func (a *sqliteAdapter) RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error {
	now := time.Now()
	return a.q.RotateActiveJWTKeys(ctx, sqlitestore.RotateActiveJWTKeysParams{
		RotatedAt: sql.NullString{String: now.Format(time.RFC3339), Valid: true},
		ExpiresAt: sql.NullString{String: expiresAt.Format(time.RFC3339), Valid: true},
		UpdatedAt: now.Format(time.RFC3339),
		Algorithm: algorithm,
	})
}

func (a *sqliteAdapter) RetireExpiredJWTKeys(ctx context.Context) (int64, error) {
	now := time.Now()
	return a.q.RetireExpiredJWTKeys(ctx, sqlitestore.RetireExpiredJWTKeysParams{
		UpdatedAt: now.Format(time.RFC3339),
		ExpiresAt: sql.NullString{String: now.Format(time.RFC3339), Valid: true},
	})
}

func (a *sqliteAdapter) DeleteJWTKey(ctx context.Context, id string) error {
	return a.q.DeleteJWTKey(ctx, id)
}

var _ Querier = (*sqliteAdapter)(nil)

// =============================================================================
// Conversion helpers
// =============================================================================

func pgKeyToDomain(row *pgstore.JwtKey) *JWTKey {
	key := &JWTKey{
		ID:            row.ID,
		Algorithm:     row.Algorithm,
		Use:           row.Use,
		KeyType:       row.Kty,
		Status:        row.Status,
		PrivateKeyEnc: row.PrivateKeyEnc,
		PublicKeyJWK:  row.PublicKeyJwk,
		ActivatedAt:   row.ActivatedAt,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
	if row.RotatedAt.Valid {
		key.RotatedAt = &row.RotatedAt.Time
	}
	if row.ExpiresAt.Valid {
		key.ExpiresAt = &row.ExpiresAt.Time
	}
	return key
}

func mysqlKeyToDomain(row *mysqlstore.JwtKey) *JWTKey {
	key := &JWTKey{
		ID:            row.ID,
		Algorithm:     row.Algorithm,
		Use:           row.Use,
		KeyType:       row.Kty,
		Status:        row.Status,
		PrivateKeyEnc: row.PrivateKeyEnc,
		PublicKeyJWK:  row.PublicKeyJwk,
		ActivatedAt:   row.ActivatedAt,
		CreatedAt:     row.CreatedAt,
		UpdatedAt:     row.UpdatedAt,
	}
	if row.RotatedAt.Valid {
		key.RotatedAt = &row.RotatedAt.Time
	}
	if row.ExpiresAt.Valid {
		key.ExpiresAt = &row.ExpiresAt.Time
	}
	return key
}

func sqliteKeyToDomain(row *sqlitestore.JwtKey) *JWTKey {
	key := &JWTKey{
		ID:            row.ID,
		Algorithm:     row.Algorithm,
		Use:           row.Use,
		KeyType:       row.Kty,
		Status:        row.Status,
		PrivateKeyEnc: row.PrivateKeyEnc,
		PublicKeyJWK:  row.PublicKeyJwk,
	}
	if t, err := time.Parse(time.RFC3339, row.ActivatedAt); err == nil {
		key.ActivatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, row.CreatedAt); err == nil {
		key.CreatedAt = t
	}
	if t, err := time.Parse(time.RFC3339, row.UpdatedAt); err == nil {
		key.UpdatedAt = t
	}
	if row.RotatedAt.Valid {
		if t, err := time.Parse(time.RFC3339, row.RotatedAt.String); err == nil {
			key.RotatedAt = &t
		}
	}
	if row.ExpiresAt.Valid {
		if t, err := time.Parse(time.RFC3339, row.ExpiresAt.String); err == nil {
			key.ExpiresAt = &t
		}
	}
	return key
}
