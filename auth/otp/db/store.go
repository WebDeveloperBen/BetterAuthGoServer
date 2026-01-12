// Package db provides the OTP plugin's database operations using sqlc-generated queries.
// This package is owned by the OTP plugin and handles its own persistence.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp/db/mysqlstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp/db/pgstore"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp/db/sqlitestore"
	coredb "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// =============================================================================
// Domain types
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
// Querier interface - each dialect implements this
// =============================================================================

// Querier defines all OTP database operations.
// Each dialect implements this interface, handling type conversions internally.
type Querier interface {
	CreateToken(ctx context.Context, token *Token) error
	GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error)
	DeleteToken(ctx context.Context, id string) error
	DeleteTokensByUserAndType(ctx context.Context, userID, tokenType string) error
	DeleteExpiredTokens(ctx context.Context) error
}

// =============================================================================
// Store - delegates to dialect-specific Querier
// =============================================================================

// Store handles OTP token persistence.
type Store struct {
	q Querier
}

// New creates a new OTP store.
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

func (s *Store) CreateToken(ctx context.Context, token *Token) error {
	return s.q.CreateToken(ctx, token)
}

func (s *Store) GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error) {
	return s.q.GetTokenByHash(ctx, tokenHash)
}

func (s *Store) DeleteToken(ctx context.Context, id string) error {
	return s.q.DeleteToken(ctx, id)
}

func (s *Store) DeleteTokensByUserAndType(ctx context.Context, userID, tokenType string) error {
	return s.q.DeleteTokensByUserAndType(ctx, userID, tokenType)
}

func (s *Store) DeleteExpiredTokens(ctx context.Context) error {
	return s.q.DeleteExpiredTokens(ctx)
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

func (a *pgAdapter) CreateToken(ctx context.Context, token *Token) error {
	return a.q.CreateOTPToken(ctx, pgstore.CreateOTPTokenParams{
		ID:         token.ID,
		UserID:     token.UserID,
		TokenHash:  token.TokenHash,
		Type:       token.Type,
		Identifier: toNullString(token.Identifier),
		ExpiresAt:  token.ExpiresAt,
		CreatedAt:  token.CreatedAt,
	})
}

func (a *pgAdapter) GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error) {
	row, err := a.q.GetOTPTokenByTokenHash(ctx, tokenHash)
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

func (a *pgAdapter) DeleteToken(ctx context.Context, id string) error {
	return a.q.DeleteOTPToken(ctx, id)
}

func (a *pgAdapter) DeleteTokensByUserAndType(ctx context.Context, userID, tokenType string) error {
	return a.q.DeleteOTPTokensByUserAndType(ctx, pgstore.DeleteOTPTokensByUserAndTypeParams{
		UserID: userID,
		Type:   tokenType,
	})
}

func (a *pgAdapter) DeleteExpiredTokens(ctx context.Context) error {
	return a.q.DeleteExpiredOTPTokens(ctx, time.Now())
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

func (a *mysqlAdapter) CreateToken(ctx context.Context, token *Token) error {
	return a.q.CreateOTPToken(ctx, mysqlstore.CreateOTPTokenParams{
		ID:         token.ID,
		UserID:     token.UserID,
		TokenHash:  token.TokenHash,
		Type:       token.Type,
		Identifier: toNullString(token.Identifier),
		ExpiresAt:  token.ExpiresAt,
		CreatedAt:  token.CreatedAt,
	})
}

func (a *mysqlAdapter) GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error) {
	row, err := a.q.GetOTPTokenByTokenHash(ctx, tokenHash)
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

func (a *mysqlAdapter) DeleteToken(ctx context.Context, id string) error {
	return a.q.DeleteOTPToken(ctx, id)
}

func (a *mysqlAdapter) DeleteTokensByUserAndType(ctx context.Context, userID, tokenType string) error {
	return a.q.DeleteOTPTokensByUserAndType(ctx, mysqlstore.DeleteOTPTokensByUserAndTypeParams{
		UserID: userID,
		Type:   tokenType,
	})
}

func (a *mysqlAdapter) DeleteExpiredTokens(ctx context.Context) error {
	return a.q.DeleteExpiredOTPTokens(ctx, time.Now())
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

func (a *sqliteAdapter) CreateToken(ctx context.Context, token *Token) error {
	return a.q.CreateOTPToken(ctx, sqlitestore.CreateOTPTokenParams{
		ID:         token.ID,
		UserID:     token.UserID,
		TokenHash:  token.TokenHash,
		Type:       token.Type,
		Identifier: toNullString(token.Identifier),
		ExpiresAt:  token.ExpiresAt.Format(time.RFC3339),
		CreatedAt:  token.CreatedAt.Format(time.RFC3339),
	})
}

func (a *sqliteAdapter) GetTokenByHash(ctx context.Context, tokenHash string) (*Token, error) {
	row, err := a.q.GetOTPTokenByTokenHash(ctx, tokenHash)
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

func (a *sqliteAdapter) DeleteToken(ctx context.Context, id string) error {
	return a.q.DeleteOTPToken(ctx, id)
}

func (a *sqliteAdapter) DeleteTokensByUserAndType(ctx context.Context, userID, tokenType string) error {
	return a.q.DeleteOTPTokensByUserAndType(ctx, sqlitestore.DeleteOTPTokensByUserAndTypeParams{
		UserID: userID,
		Type:   tokenType,
	})
}

func (a *sqliteAdapter) DeleteExpiredTokens(ctx context.Context) error {
	return a.q.DeleteExpiredOTPTokens(ctx, time.Now().Format(time.RFC3339))
}

var _ Querier = (*sqliteAdapter)(nil)

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
