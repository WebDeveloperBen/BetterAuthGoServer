// Package db provides database storage implementations for JWT token management.
package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/jwt/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

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

// Store wraps the sqlc-generated queries for JWT operations.
type Store struct {
	dialect coredb.Dialect
	pgQ     *pgstore.Queries
	sqliteQ *sqlitestore.Queries
}

// New creates a new Store for JWT operations.
func New(db coredb.DBTX, dialect coredb.Dialect) *Store {
	s := &Store{dialect: dialect}
	if dialect == coredb.DialectPostgres {
		s.pgQ = pgstore.New(db)
	} else {
		s.sqliteQ = sqlitestore.New(db)
	}
	return s
}

// ---- Blocklist operations ----

// RevokeJWTToken adds a token to the blocklist.
func (s *Store) RevokeJWTToken(ctx context.Context, jti string, expiresAt time.Time) error {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.RevokeJWTToken(ctx, pgstore.RevokeJWTTokenParams{
			ID:        jti,
			ExpiresAt: expiresAt,
			RevokedAt: now,
		})
	}
	return s.sqliteQ.RevokeJWTToken(ctx, sqlitestore.RevokeJWTTokenParams{
		ID:        jti,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		RevokedAt: now.Format(time.RFC3339),
	})
}

// IsJWTTokenRevoked checks if a token is in the blocklist.
func (s *Store) IsJWTTokenRevoked(ctx context.Context, jti string) (bool, error) {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.IsJWTTokenRevoked(ctx, jti)
	}
	revoked, err := s.sqliteQ.IsJWTTokenRevoked(ctx, jti)
	if err != nil {
		return false, err
	}
	return revoked > 0, nil
}

// DeleteExpiredRevokedTokens removes expired tokens from the blocklist.
func (s *Store) DeleteExpiredRevokedTokens(ctx context.Context) error {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteExpiredRevokedTokens(ctx, now)
	}
	return s.sqliteQ.DeleteExpiredRevokedTokens(ctx, now.Format(time.RFC3339))
}

// ---- Key management operations ----

// CreateJWTKey creates a new JWT key.
func (s *Store) CreateJWTKey(ctx context.Context, key *JWTKey) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateJWTKey(ctx, pgstore.CreateJWTKeyParams{
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
	return s.sqliteQ.CreateJWTKey(ctx, sqlitestore.CreateJWTKeyParams{
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

// GetJWTKeyByID retrieves a JWT key by ID.
func (s *Store) GetJWTKeyByID(ctx context.Context, id string) (*JWTKey, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetJWTKeyByID(ctx, id)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgKeyToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetJWTKeyByID(ctx, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteKeyToDomain(&row), nil
}

// GetActiveJWTKey retrieves the active key for the given algorithm.
func (s *Store) GetActiveJWTKey(ctx context.Context, algorithm string) (*JWTKey, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetActiveJWTKey(ctx, algorithm)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return pgKeyToDomain(&row), nil
	}
	row, err := s.sqliteQ.GetActiveJWTKey(ctx, algorithm)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return sqliteKeyToDomain(&row), nil
}

// GetJWTKeysForVerification retrieves all keys valid for verification.
func (s *Store) GetJWTKeysForVerification(ctx context.Context, algorithm string) ([]*JWTKey, error) {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		rows, err := s.pgQ.GetJWTKeysForVerification(ctx, pgstore.GetJWTKeysForVerificationParams{
			Algorithm: algorithm,
			ExpiresAt: sql.NullTime{Time: now, Valid: true},
		})
		if err != nil {
			return nil, err
		}
		keys := make([]*JWTKey, len(rows))
		for i, row := range rows {
			r := row // avoid aliasing
			keys[i] = pgKeyToDomain(&r)
		}
		return keys, nil
	}
	rows, err := s.sqliteQ.GetJWTKeysForVerification(ctx, sqlitestore.GetJWTKeysForVerificationParams{
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

// GetJWTKeyForVerification retrieves a specific key for verification.
func (s *Store) GetJWTKeyForVerification(ctx context.Context, id string) (*JWTKey, error) {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetJWTKeyForVerification(ctx, pgstore.GetJWTKeyForVerificationParams{
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
	row, err := s.sqliteQ.GetJWTKeyForVerification(ctx, sqlitestore.GetJWTKeyForVerificationParams{
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

// RotateActiveJWTKeys moves active keys to rotating status.
func (s *Store) RotateActiveJWTKeys(ctx context.Context, algorithm string, expiresAt time.Time) error {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.RotateActiveJWTKeys(ctx, pgstore.RotateActiveJWTKeysParams{
			RotatedAt: sql.NullTime{Time: now, Valid: true},
			ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
			UpdatedAt: now,
			Algorithm: algorithm,
		})
	}
	return s.sqliteQ.RotateActiveJWTKeys(ctx, sqlitestore.RotateActiveJWTKeysParams{
		RotatedAt: sql.NullString{String: now.Format(time.RFC3339), Valid: true},
		ExpiresAt: sql.NullString{String: expiresAt.Format(time.RFC3339), Valid: true},
		UpdatedAt: now.Format(time.RFC3339),
		Algorithm: algorithm,
	})
}

// RetireExpiredJWTKeys marks expired rotating keys as retired.
func (s *Store) RetireExpiredJWTKeys(ctx context.Context) (int64, error) {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.RetireExpiredJWTKeys(ctx, pgstore.RetireExpiredJWTKeysParams{
			UpdatedAt: now,
			ExpiresAt: sql.NullTime{Time: now, Valid: true},
		})
	}
	return s.sqliteQ.RetireExpiredJWTKeys(ctx, sqlitestore.RetireExpiredJWTKeysParams{
		UpdatedAt: now.Format(time.RFC3339),
		ExpiresAt: sql.NullString{String: now.Format(time.RFC3339), Valid: true},
	})
}

// DeleteJWTKey deletes a JWT key by ID.
func (s *Store) DeleteJWTKey(ctx context.Context, id string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteJWTKey(ctx, id)
	}
	return s.sqliteQ.DeleteJWTKey(ctx, id)
}

// ---- Conversion helpers ----

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
