package e2e

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/webdeveloperben/BetterAuthGoServer/db"
)

// TestMain sets up database containers for all e2e tests.
// Supports PostgreSQL, MySQL, and SQLite based on environment variables:
//   - TEST_POSTGRES: "true" (default) or "false"
//   - TEST_MYSQL: "true" (default) or "false"
//   - TEST_SQLITE: "true" (default) or "false"
//
// All dialects are enabled by default. Set to "false" to disable.
func TestMain(m *testing.M) {
	ctx := context.Background()
	dialectEnvs = make(map[db.Dialect]*DialectEnv)

	// PostgreSQL (enabled by default)
	if os.Getenv("TEST_POSTGRES") != "false" {
		fmt.Println("Setting up PostgreSQL container...")
		pgEnv, err := setupPostgresContainer(ctx)
		if err != nil {
			fmt.Printf("Failed to setup PostgreSQL: %v\n", err)
			os.Exit(1)
		}
		dialectEnvs[db.DialectPostgres] = pgEnv
		fmt.Println("PostgreSQL container ready")
	}

	// MySQL (enabled by default)
	if os.Getenv("TEST_MYSQL") != "false" {
		fmt.Println("Setting up MySQL container...")
		mysqlEnv, err := setupMySQLContainer(ctx)
		if err != nil {
			fmt.Printf("Failed to setup MySQL: %v\n", err)
			// Cleanup already started containers
			cleanupDialectEnvs(ctx)
			os.Exit(1)
		}
		dialectEnvs[db.DialectMySQL] = mysqlEnv
		fmt.Println("MySQL container ready")
	}

	// SQLite (enabled by default, no container needed)
	if os.Getenv("TEST_SQLITE") != "false" {
		fmt.Println("Setting up SQLite...")
		sqliteEnv, err := setupSQLiteEnv()
		if err != nil {
			fmt.Printf("Failed to setup SQLite: %v\n", err)
			cleanupDialectEnvs(ctx)
			os.Exit(1)
		}
		dialectEnvs[db.DialectSQLite] = sqliteEnv
		fmt.Println("SQLite ready")
	}

	if len(dialectEnvs) == 0 {
		fmt.Println("No dialects enabled - at least one of TEST_POSTGRES, TEST_MYSQL, or TEST_SQLITE must be enabled")
		os.Exit(1)
	}

	fmt.Printf("Running tests with %d dialect(s)\n", len(dialectEnvs))

	// Run tests
	code := m.Run()

	// Cleanup
	cleanupDialectEnvs(ctx)

	os.Exit(code)
}

// setupPostgresContainer creates a PostgreSQL container
func setupPostgresContainer(ctx context.Context) (*DialectEnv, error) {
	pgContainer, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("testuser"),
		postgres.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
		// Reuse container across test packages
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: "betterauth-test-postgres",
			},
			Reuse: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start PostgreSQL container: %w", err)
	}

	connStr, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get connection string: %w", err)
	}

	sqlDB, err := sql.Open("postgres", connStr)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool to prevent exhaustion. Each migration source's
	// golang-migrate driver keeps one connection checked out (migrate.Run does not close
	// them), so leave room above the number of sources for concurrent tests.
	sqlDB.SetMaxOpenConns(32)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DialectEnv{
		Dialect:   db.DialectPostgres,
		DB:        sqlDB,
		ConnStr:   connStr,
		Container: pgContainer,
	}, nil
}

// setupMySQLContainer creates a MySQL container
func setupMySQLContainer(ctx context.Context) (*DialectEnv, error) {
	mysqlContainer, err := mysql.Run(ctx,
		"mysql:8",
		mysql.WithDatabase("testdb"),
		mysql.WithUsername("testuser"),
		mysql.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("ready for connections").
				WithOccurrence(2).
				WithStartupTimeout(120*time.Second),
		),
		// Reuse container across test packages
		testcontainers.CustomizeRequest(testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Name: "betterauth-test-mysql",
			},
			Reuse: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to start MySQL container: %w", err)
	}

	// Get base connection string
	baseConnStr, err := mysqlContainer.ConnectionString(ctx, "parseTime=true&multiStatements=true")
	if err != nil {
		_ = mysqlContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get connection string: %w", err)
	}

	// Build root connection string for admin operations (creating databases)
	host, err := mysqlContainer.Host(ctx)
	if err != nil {
		_ = mysqlContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get MySQL host: %w", err)
	}
	port, err := mysqlContainer.MappedPort(ctx, "3306")
	if err != nil {
		_ = mysqlContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get MySQL port: %w", err)
	}
	rootConnStr := fmt.Sprintf("root:testpass@tcp(%s:%s)/mysql?parseTime=true&multiStatements=true", host, port.Port())

	// MySQL needs additional time after reporting ready - retry with backoff
	var rootDB *sql.DB
	var pingErr error
	for attempt := 0; attempt < 10; attempt++ {
		rootDB, err = sql.Open("mysql", rootConnStr)
		if err != nil {
			_ = mysqlContainer.Terminate(ctx)
			return nil, fmt.Errorf("failed to open root database: %w", err)
		}

		pingErr = rootDB.PingContext(ctx)
		if pingErr == nil {
			break
		}

		// Close the failed connection and retry
		_ = rootDB.Close()
		time.Sleep(time.Duration(500*(attempt+1)) * time.Millisecond)
	}

	if pingErr != nil {
		_ = mysqlContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to ping database after retries: %w", pingErr)
	}

	// Create a package-specific database for isolation from other test packages
	// This prevents conflicts when db/migrate tests also run against the same container
	dbName := "testdb_e2e"
	_, err = rootDB.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS %s", dbName))
	if err != nil {
		_ = rootDB.Close()
		return nil, fmt.Errorf("failed to create database %s: %w", dbName, err)
	}

	// Grant privileges to testuser on the new database
	_, err = rootDB.ExecContext(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO 'testuser'@'%%'", dbName))
	if err != nil {
		_ = rootDB.Close()
		return nil, fmt.Errorf("failed to grant privileges: %w", err)
	}
	_, _ = rootDB.ExecContext(ctx, "FLUSH PRIVILEGES")
	_ = rootDB.Close()

	// Build connection string for our isolated database
	connStr := replaceDBName(baseConnStr, dbName)

	// Open connection to the isolated database
	sqlDB, err := sql.Open("mysql", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open isolated database: %w", err)
	}

	// Configure connection pool (see the PostgreSQL pool comment for the size).
	sqlDB.SetMaxOpenConns(32)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to ping isolated database: %w", err)
	}

	return &DialectEnv{
		Dialect:   db.DialectMySQL,
		DB:        sqlDB,
		ConnStr:   connStr,
		Container: mysqlContainer,
	}, nil
}

// replaceDBName replaces the database name in a MySQL connection string
func replaceDBName(connStr, newDBName string) string {
	// MySQL DSN format: user:password@tcp(host:port)/dbname?params
	// Find the position after / and before ?
	start := 0
	for i := 0; i < len(connStr); i++ {
		if connStr[i] == '/' {
			start = i + 1
			break
		}
	}
	end := len(connStr)
	for i := start; i < len(connStr); i++ {
		if connStr[i] == '?' {
			end = i
			break
		}
	}
	return connStr[:start] + newDBName + connStr[end:]
}

// setupSQLiteEnv creates an in-memory SQLite environment
// Note: Uses a temp file (not :memory:) because golang-migrate requires it
func setupSQLiteEnv() (*DialectEnv, error) {
	// Create temp directory for SQLite file
	tmpDir, err := os.MkdirTemp("", "e2e-sqlite-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	connStr := dbPath + "?_foreign_keys=on"

	sqlDB, err := sql.Open("sqlite3", connStr)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if err := sqlDB.Ping(); err != nil {
		_ = sqlDB.Close()
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DialectEnv{
		Dialect:   db.DialectSQLite,
		DB:        sqlDB,
		ConnStr:   connStr,
		Container: nil, // No container for SQLite
	}, nil
}

// cleanupDialectEnvs closes all database connections
// Note: Reusable containers are NOT terminated - they're shared across test packages
func cleanupDialectEnvs(ctx context.Context) {
	for dialect, env := range dialectEnvs {
		if env.DB != nil {
			_ = env.DB.Close()
		}
		// Don't terminate reusable containers - they're shared across test packages
		// Containers will be cleaned up by Ryuk or manual `docker rm`
		// Clean up SQLite temp files only
		if dialect == db.DialectSQLite && env.ConnStr != "" {
			// Extract path before query params
			dbPath := env.ConnStr
			if idx := len(dbPath) - len("?_foreign_keys=on"); idx > 0 {
				dbPath = dbPath[:idx]
			}
			if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
				_ = os.RemoveAll(dir)
			}
		}
	}
}
