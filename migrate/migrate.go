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
	"github.com/golang-migrate/migrate/v4/source"
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
func Down(ctx context.Context, db *sql.DB, dialect Dialect, src Source, opts ...Option) (err error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	m, err := createMigrator(ctx, db, dialect, src)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, m.close()) }()

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
	m, err := createMigrator(ctx, db, dialect, src)
	if err != nil {
		return 0, false, err
	}
	defer func() { err = errors.Join(err, m.close()) }()

	version, dirty, err = m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return version, dirty, err
}

// runSource runs all pending migrations for a single source.
func runSource(ctx context.Context, db *sql.DB, dialect Dialect, src Source, cfg Config) (err error) {
	cfg.logger.Info("running migrations for source",
		"source", src.Name(),
		"dependencies", src.Dependencies(),
	)

	m, err := createMigrator(ctx, db, dialect, src)
	if err != nil {
		return fmt.Errorf("failed to create migrator for %s: %w", src.Name(), err)
	}
	defer func() { err = errors.Join(err, m.close()) }()

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

// migrator is a golang-migrate instance plus the resources opened for it.
type migrator struct {
	*migrate.Migrate
	source source.Driver
	conn   *sql.Conn // dedicated connection (postgres, mysql); nil for sqlite
}

// close releases the source driver and the dedicated connection. It deliberately does
// not call migrate.Migrate.Close: golang-migrate drivers created with WithInstance close
// the caller's *sql.DB, which must stay open for the application.
func (m *migrator) close() error {
	err := m.source.Close()
	if m.conn != nil {
		err = errors.Join(err, m.conn.Close())
	}
	return err
}

// createMigrator creates a golang-migrate instance for the given source. The caller must
// call close on the result; on error everything opened here is already released.
func createMigrator(ctx context.Context, db *sql.DB, dialect Dialect, src Source) (*migrator, error) {
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
	m := &migrator{source: sourceDriver}

	// Create database driver with source-specific table name
	tableName := "schema_migrations_" + src.Name()
	dbDriver, err := m.createDBDriver(ctx, db, dialect, tableName)
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("failed to create database driver for %s: %w", src.Name(), err),
			m.close(),
		)
	}

	m.Migrate, err = migrate.NewWithInstance("iofs", sourceDriver, string(dialect), dbDriver)
	if err != nil {
		return nil, errors.Join(err, m.close())
	}
	return m, nil
}

// createDBDriver creates a database-specific migrate driver. PostgreSQL and MySQL drivers
// are bound to a dedicated connection taken from db (recorded in m.conn) instead of db
// itself, so closing them never closes db. The SQLite driver holds no connection.
func (m *migrator) createDBDriver(ctx context.Context, db *sql.DB, dialect Dialect, tableName string) (database.Driver, error) {
	switch dialect {
	case DialectPostgres, DialectMySQL:
	case DialectSQLite:
		return sqlite3.WithInstance(db, &sqlite3.Config{
			MigrationsTable: tableName,
		})
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedDialect, dialect)
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, err
	}
	m.conn = conn

	if dialect == DialectPostgres {
		return postgres.WithConnection(ctx, conn, &postgres.Config{
			MigrationsTable: tableName,
		})
	}
	return mysql.WithConnection(ctx, conn, &mysql.Config{
		MigrationsTable: tableName,
	})
}

// sourceNames extracts names from a slice of sources.
func sourceNames(sources []Source) []string {
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.Name()
	}
	return names
}
