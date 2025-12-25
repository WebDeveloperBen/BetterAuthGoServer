// Package db provides database implementations for the auth package using Bun ORM.
// It supports PostgreSQL and SQLite with SQL-based migrations.
package db

import (
	"context"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/migrate"

	"github.com/webdeveloperben/BetterAuthGoServer/db/migrations"
)

// Store implements auth.Store using Bun (supports PostgreSQL, SQLite, MySQL)
type Store struct {
	db       *bun.DB
	migrator *migrate.Migrator
}

// New creates a new database store with Bun
func New(db *bun.DB) *Store {
	return &Store{
		db:       db,
		migrator: migrate.NewMigrator(db, migrations.Migrations),
	}
}

// Migrate runs all pending database migrations
func (s *Store) Migrate(ctx context.Context) error {
	// Initialize migration tables (bun_migrations, bun_migration_locks)
	if err := s.migrator.Init(ctx); err != nil {
		return err
	}

	// Run pending migrations
	if _, err := s.migrator.Migrate(ctx); err != nil {
		return err
	}

	return nil
}

// Rollback rolls back the last migration group
func (s *Store) Rollback(ctx context.Context) error {
	_, err := s.migrator.Rollback(ctx)
	return err
}

// MigrationStatus returns the status of all migrations
func (s *Store) MigrationStatus(ctx context.Context) (migrate.MigrationSlice, error) {
	return s.migrator.MigrationsWithStatus(ctx)
}

// DB returns the underlying bun.DB connection.
// This is used by the plugin system for plugin migrations.
func (s *Store) DB() *bun.DB {
	return s.db
}
