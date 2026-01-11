// Package store provides database implementations for the auth package using Bun ORM.
// It supports PostgreSQL and SQLite with model-based migrations.
package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/uptrace/bun"

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// Store implements auth.Store using Bun (supports PostgreSQL, SQLite, MySQL)
type Store struct {
	db *bun.DB
}

// Compile-time check that Store implements plugin.DBProvider
var _ interface {
	DB() db.DBTX
	Dialect() db.Dialect
} = (*Store)(nil)

// New creates a new database store with Bun
func New(db *bun.DB) *Store {
	return &Store{
		db: db,
	}
}

// Migrations returns the Bun models for creating database tables.
// This follows the same pattern as plugin.MigrationsProvider.
func (s *Store) Migrations() []any {
	return []any{
		&User{},
		&Account{},
		&Session{},
		&Verification{},
	}
}

// Migrate creates all required database tables if they don't exist.
// This uses Bun's model-based table creation with IfNotExists().
func (s *Store) Migrate(ctx context.Context) error {
	models := s.Migrations()

	for _, model := range models {
		_, err := s.db.NewCreateTable().
			Model(model).
			IfNotExists().
			Exec(ctx)
		if err != nil {
			return fmt.Errorf("failed to create table for %T: %w", model, err)
		}
	}

	// Create indexes
	if err := s.createIndexes(ctx); err != nil {
		return fmt.Errorf("failed to create indexes: %w", err)
	}

	return nil
}

// createIndexes creates database indexes for better query performance.
// Uses raw SQL with IF NOT EXISTS for idempotency.
func (s *Store) createIndexes(ctx context.Context) error {
	indexes := []string{
		// Users indexes
		"CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
		"CREATE INDEX IF NOT EXISTS idx_users_banned ON users(banned)",
		"CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)",

		// Accounts indexes
		"CREATE INDEX IF NOT EXISTS idx_accounts_user_id ON accounts(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_accounts_provider ON accounts(provider, provider_account_id)",

		// Sessions indexes
		"CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_token_hash ON sessions(token_hash)",
		"CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at)",

		// Verifications indexes
		"CREATE INDEX IF NOT EXISTS idx_verifications_token_hash ON verifications(token_hash)",
		"CREATE INDEX IF NOT EXISTS idx_verifications_user_id_type ON verifications(user_id, type)",
	}

	for _, idx := range indexes {
		if _, err := s.db.ExecContext(ctx, idx); err != nil {
			return err
		}
	}

	return nil
}

// BunDB returns the underlying bun.DB connection.
// This is used by the plugin system for plugin migrations.
func (s *Store) BunDB() *bun.DB {
	return s.db
}

// =============================================================================
// plugin.DBProvider implementation
// =============================================================================

// DB returns the underlying database connection for raw SQL operations.
// This implements plugin.DBProvider and allows plugins to access the raw *sql.DB.
func (s *Store) DB() db.DBTX {
	return s.db.DB
}

// Dialect returns the database dialect detected from the bun.DB connection.
// This implements plugin.DBProvider.
func (s *Store) Dialect() db.Dialect {
	dialectName := s.db.Dialect().Name().String()
	switch {
	case strings.Contains(dialectName, "pg"):
		return db.DialectPostgres
	case strings.Contains(dialectName, "sqlite"):
		return db.DialectSQLite
	case strings.Contains(dialectName, "mysql"):
		return db.DialectMySQL
	default:
		// Default to postgres for unknown dialects
		return db.DialectPostgres
	}
}
