package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// Run executes database migrations for core tables and any provided plugins.
// Migrations are run in dependency order: core first, then plugins sorted
// topologically based on their declared dependencies.
//
// Example:
//
//	err := migrate.Run(ctx, db, migrate.DialectPostgres,
//	    migrate.WithPlugins(
//	        oauth.Migrations(),
//	        jwt.Migrations(),
//	    ),
//	)
func Run(ctx context.Context, db *sql.DB, dialect Dialect, opts ...Option) error {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	// Collect all sources: core + plugins
	sources := []Source{CoreMigrations()}
	sources = append(sources, cfg.plugins...)

	// Topologically sort by dependencies
	sorted, err := topoSort(sources)
	if err != nil {
		return fmt.Errorf("failed to resolve migration dependencies: %w", err)
	}

	cfg.logger.Info("running migrations",
		"dialect", dialect,
		"sources", sourceNames(sorted),
		"dry_run", cfg.dryRun,
	)

	// Run each source in order
	for _, src := range sorted {
		if err := runSource(ctx, db, dialect, src, cfg); err != nil {
			return err
		}
	}

	cfg.logger.Info("all migrations completed successfully")
	return nil
}

// Up runs all pending migrations for the given source.
// This is a lower-level function; most users should use Run instead.
func Up(ctx context.Context, db *sql.DB, dialect Dialect, src Source, opts ...Option) error {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return runSource(ctx, db, dialect, src, cfg)
}

// Down rolls back the last migration for the given source.
func Down(ctx context.Context, db *sql.DB, dialect Dialect, src Source, opts ...Option) error {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	m, err := createMigrator(db, dialect, src)
	if err != nil {
		return err
	}
	// Note: We don't call m.Close() - see comment in runSource()

	if cfg.dryRun {
		version, dirty, err := m.Version()
		if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
			return err
		}
		cfg.logger.Info("dry run: would rollback",
			"source", src.Name(),
			"current_version", version,
			"dirty", dirty,
		)
		return nil
	}

	if err := m.Steps(-1); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return &MigrationError{
			Source:    src.Name(),
			Direction: "down",
			Err:       err,
		}
	}

	return nil
}

// Status returns the current migration version for a source.
func Status(ctx context.Context, db *sql.DB, dialect Dialect, src Source) (version uint, dirty bool, err error) {
	m, err := createMigrator(db, dialect, src)
	if err != nil {
		return 0, false, err
	}
	// Note: We don't call m.Close() - see comment in runSource()

	version, dirty, err = m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return version, dirty, err
}

// runSource runs all pending migrations for a single source.
func runSource(ctx context.Context, db *sql.DB, dialect Dialect, src Source, cfg Config) error {
	cfg.logger.Info("running migrations for source",
		"source", src.Name(),
		"dependencies", src.Dependencies(),
	)

	m, err := createMigrator(db, dialect, src)
	if err != nil {
		return fmt.Errorf("failed to create migrator for %s: %w", src.Name(), err)
	}
	// Note: We intentionally don't call m.Close() here because golang-migrate's
	// database drivers close the underlying DB connection, which prevents us from
	// running subsequent migrations on the same connection. The source driver
	// will be garbage collected, and the DB connection is managed by the caller.

	if cfg.dryRun {
		version, dirty, err := m.Version()
		if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
			return err
		}
		cfg.logger.Info("dry run: current state",
			"source", src.Name(),
			"version", version,
			"dirty", dirty,
		)
		return nil
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			cfg.logger.Info("no pending migrations",
				"source", src.Name(),
			)
			return nil
		}
		return &MigrationError{
			Source:    src.Name(),
			Direction: "up",
			Err:       err,
		}
	}

	version, _, _ := m.Version()
	cfg.logger.Info("migrations completed",
		"source", src.Name(),
		"version", version,
	)

	return nil
}

// createMigrator creates a golang-migrate instance for the given source.
func createMigrator(db *sql.DB, dialect Dialect, src Source) (*migrate.Migrate, error) {
	// Get subdirectory for dialect
	subFS, err := fs.Sub(src.FS(), string(dialect))
	if err != nil {
		return nil, fmt.Errorf("dialect %s not found in source %s: %w", dialect, src.Name(), err)
	}

	// Create iofs source driver
	sourceDriver, err := iofs.New(subFS, ".")
	if err != nil {
		return nil, fmt.Errorf("failed to create iofs source for %s: %w", src.Name(), err)
	}

	// Create database driver with source-specific table name
	tableName := "schema_migrations_" + src.Name()
	dbDriver, err := createDBDriver(db, dialect, tableName)
	if err != nil {
		return nil, fmt.Errorf("failed to create database driver for %s: %w", src.Name(), err)
	}

	return migrate.NewWithInstance("iofs", sourceDriver, string(dialect), dbDriver)
}

// createDBDriver creates a database-specific migrate driver.
func createDBDriver(db *sql.DB, dialect Dialect, tableName string) (database.Driver, error) {
	switch dialect {
	case DialectPostgres:
		return postgres.WithInstance(db, &postgres.Config{
			MigrationsTable: tableName,
		})
	case DialectSQLite:
		return sqlite3.WithInstance(db, &sqlite3.Config{
			MigrationsTable: tableName,
		})
	case DialectMySQL:
		return mysql.WithInstance(db, &mysql.Config{
			MigrationsTable: tableName,
		})
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedDialect, dialect)
	}
}

// sourceNames extracts names from a slice of sources.
func sourceNames(sources []Source) []string {
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.Name()
	}
	return names
}
