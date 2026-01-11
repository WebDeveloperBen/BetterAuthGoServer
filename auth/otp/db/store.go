// Package db provides the OTP plugin's database operations using sqlc-generated queries.
// This package is owned by the OTP plugin and handles its own persistence.
package db

import (
	"context"
	"database/sql"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Store handles OTP token persistence.
// The plugin owns this implementation.
type Store struct {
	dialect coredb.Dialect
	pgQ     *pgstore.Queries
	sqliteQ *sqlitestore.Queries
	mysqlQ  *mysqlstore.Queries
}

// New creates a new OTP store.
func New(db coredb.DBTX, dialect coredb.Dialect) *Store {
	s := &Store{dialect: dialect}
	switch dialect {
	case coredb.DialectPostgres:
		s.pgQ = pgstore.New(db)
	case coredb.DialectMySQL:
		s.mysqlQ = mysqlstore.New(db)
	default:
		s.sqliteQ = sqlitestore.New(db)
	}
	return s
}

// =============================================================================
// Token domain type
// =============================================================================

// Token represents an OTP token record.
type Token struct {
	ID         string
	UserID     string
	TokenHash  string
	Type       string
	Identifier *string
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

// IsExpired returns true if the token has expired.
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// =============================================================================
// Store Methods
// =============================================================================

// CreateToken creates a new OTP token.
func (s *Store) CreateToken(ctx context.Context, token *Token) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.CreateOTPToken(ctx, pgstore.CreateOTPTokenParams{
			ID:         token.ID,
			UserID:     token.UserID,
			TokenHash:  token.TokenHash,
			Type:       token.Type,
			Identifier: toNullString(token.Identifier),
			ExpiresAt:  token.ExpiresAt,
			CreatedAt:  token.CreatedAt,
		})
	}
	if s.dialect == coredb.DialectMySQL {
		return s.mysqlQ.CreateOTPToken(ctx, mysqlstore.CreateOTPTokenParams{
			ID:         token.ID,
			UserID:     token.UserID,
			TokenHash:  token.TokenHash,
			Type:       token.Type,
			Identifier: toNullString(token.Identifier),
			ExpiresAt:  token.ExpiresAt,
			CreatedAt:  token.CreatedAt,
		})
	}
	return s.sqliteQ.CreateOTPToken(ctx, sqlitestore.CreateOTPTokenParams{
		ID:         token.ID,
		UserID:     token.UserID,
		TokenHash:  token.TokenHash,
		Type:       token.Type,
		Identifier: toNullString(token.Identifier),
		ExpiresAt:  token.ExpiresAt.Format(time.RFC3339),
		CreatedAt:  token.CreatedAt.Format(time.RFC3339),
	})
}

// GetTokenByHash retrieves an OTP token by its hash.
func (s *Store) GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error) {
	if s.dialect == coredb.DialectPostgres {
		row, err := s.pgQ.GetOTPTokenByTokenHash(ctx, tokenHash)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, nil
			}
			return nil, err
		}
		return &Token{
			ID:         row.ID,
			UserID:     row.UserID,
			TokenHash:  row.TokenHash,
			Type:       row.Type,
			Identifier: fromNullString(row.Identifier),
			ExpiresAt:  row.ExpiresAt,
			CreatedAt:  row.CreatedAt,
		}, nil
	}

	row, err := s.sqliteQ.GetOTPTokenByTokenHash(ctx, tokenHash)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	expiresAt, _ := time.Parse(time.RFC3339, row.ExpiresAt)
	createdAt, _ := time.Parse(time.RFC3339, row.CreatedAt)

	return &Token{
		ID:         row.ID,
		UserID:     row.UserID,
		TokenHash:  row.TokenHash,
		Type:       row.Type,
		Identifier: fromNullString(row.Identifier),
		ExpiresAt:  expiresAt,
		CreatedAt:  createdAt,
	}, nil
}

// DeleteToken deletes an OTP token by ID.
func (s *Store) DeleteToken(ctx context.Context, id string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteOTPToken(ctx, id)
	}
	return s.sqliteQ.DeleteOTPToken(ctx, id)
}

// DeleteTokensByUserAndType deletes all OTP tokens for a user of a specific type.
func (s *Store) DeleteTokensByUserAndType(ctx context.Context, userID, tokenType string) error {
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteOTPTokensByUserAndType(ctx, pgstore.DeleteOTPTokensByUserAndTypeParams{
			UserID: userID,
			Type:   tokenType,
		})
	}
	return s.sqliteQ.DeleteOTPTokensByUserAndType(ctx, sqlitestore.DeleteOTPTokensByUserAndTypeParams{
		UserID: userID,
		Type:   tokenType,
	})
}

// DeleteExpiredTokens deletes all expired OTP tokens.
func (s *Store) DeleteExpiredTokens(ctx context.Context) error {
	now := time.Now()
	if s.dialect == coredb.DialectPostgres {
		return s.pgQ.DeleteExpiredOTPTokens(ctx, now)
	}
	return s.sqliteQ.DeleteExpiredOTPTokens(ctx, now.Format(time.RFC3339))
}

// =============================================================================
// Conversion helpers
// =============================================================================

func toNullString(s *string) sql.NullString {
	if s == nil || *s == "" {
		return sql.NullString{Valid: false}
	}
	return sql.NullString{String: *s, Valid: true}
}

func fromNullString(ns sql.NullString) *string {
	if !ns.Valid {
		return nil
	}
	return &ns.String
}
