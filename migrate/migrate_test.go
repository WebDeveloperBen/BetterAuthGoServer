package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Shared test environments (initialized in TestMain)
var sharedDialectEnvs map[Dialect]*dialectTestEnv

// testMigrationFS creates a mock filesystem with migration files for a specific dialect.
func testMigrationFS(dialect Dialect, upSQL, downSQL string) fs.FS {
	dir := string(dialect)
	return fstest.MapFS{
		dir + "/000001_test.up.sql":   &fstest.MapFile{Data: []byte(upSQL)},
		dir + "/000001_test.down.sql": &fstest.MapFile{Data: []byte(downSQL)},
	}
}

// testTableSQL returns dialect-appropriate SQL for creating a test table.
// MySQL requires VARCHAR for primary keys, not TEXT.
func testTableSQL(dialect Dialect, tableName string) (upSQL, downSQL string) {
	switch dialect {
	case DialectMySQL:
		upSQL = fmt.Sprintf("CREATE TABLE %s (id VARCHAR(255) PRIMARY KEY, data TEXT);", tableName)
	default:
		upSQL = fmt.Sprintf("CREATE TABLE %s (id TEXT PRIMARY KEY, data TEXT);", tableName)
	}
	downSQL = fmt.Sprintf("DROP TABLE IF EXISTS %s;", tableName)
	return upSQL, downSQL
}

// testSource is a mock migration source for testing.
type testSource struct {
	name string
	fs   fs.FS
	deps []string
}

func (s *testSource) Name() string           { return s.name }
func (s *testSource) FS() fs.FS              { return s.fs }
func (s *testSource) Dependencies() []string { return s.deps }

// dialectTestEnv holds database connection info for a specific dialect.
type dialectTestEnv struct {
	dialect   Dialect
	db        *sql.DB
	connStr   string
	container testcontainers.Container
}

// TestMain sets up shared database containers for all migrate tests.
func TestMain(m *testing.M) {
	ctx := context.Background()
	sharedDialectEnvs = make(map[Dialect]*dialectTestEnv)

	// SQLite (enabled by default, fast, no container needed)
	if os.Getenv("TEST_SQLITE") != "false" {
		fmt.Println("Setting up SQLite for migrate tests...")
		env, err := setupSharedSQLite()
		if err != nil {
			fmt.Printf("Failed to setup SQLite: %v\n", err)
			os.Exit(1)
		}
		sharedDialectEnvs[DialectSQLite] = env
		fmt.Println("SQLite ready")
	}

	// PostgreSQL (enabled by default)
	if os.Getenv("TEST_POSTGRES") != "false" {
		fmt.Println("Setting up PostgreSQL container for migrate tests...")
		env, err := setupSharedPostgres(ctx)
		if err != nil {
			fmt.Printf("Failed to setup PostgreSQL: %v\n", err)
			cleanupSharedEnvs(ctx)
			os.Exit(1)
		}
		sharedDialectEnvs[DialectPostgres] = env
		fmt.Println("PostgreSQL container ready")
	}

	// MySQL (enabled by default)
	if os.Getenv("TEST_MYSQL") != "false" {
		fmt.Println("Setting up MySQL container for migrate tests...")
		env, err := setupSharedMySQL(ctx)
		if err != nil {
			fmt.Printf("Failed to setup MySQL: %v\n", err)
			cleanupSharedEnvs(ctx)
			os.Exit(1)
		}
		sharedDialectEnvs[DialectMySQL] = env
		fmt.Println("MySQL container ready")
	}

	if len(sharedDialectEnvs) == 0 {
		fmt.Println("No dialects enabled for migrate tests")
		os.Exit(1)
	}

	fmt.Printf("Running migrate tests with %d dialect(s)\n", len(sharedDialectEnvs))

	code := m.Run()

	// Cleanup
	cleanupSharedEnvs(ctx)

	os.Exit(code)
}

func setupSharedSQLite() (*dialectTestEnv, error) {
	tmpDir, err := os.MkdirTemp("", "migrate-test-sqlite-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}

	dbPath := filepath.Join(tmpDir, "test.db")
	connStr := dbPath + "?_foreign_keys=on"

	db, err := sql.Open("sqlite3", connStr)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	return &dialectTestEnv{
		dialect: DialectSQLite,
		db:      db,
		connStr: connStr,
	}, nil
}

func setupSharedPostgres(ctx context.Context) (*dialectTestEnv, error) {
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

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool to prevent stale connections
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Verify connection is working
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &dialectTestEnv{
		dialect:   DialectPostgres,
		db:        db,
		connStr:   connStr,
		container: pgContainer,
	}, nil
}

func setupSharedMySQL(ctx context.Context) (*dialectTestEnv, error) {
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
	// This prevents conflicts when db tests also run against the same container
	dbName := "testdb_migrate"
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
	db, err := sql.Open("mysql", connStr)
	if err != nil {
		return nil, fmt.Errorf("failed to open isolated database: %w", err)
	}

	// Configure connection pool to prevent stale connections
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("failed to ping isolated database: %w", err)
	}

	return &dialectTestEnv{
		dialect:   DialectMySQL,
		db:        db,
		connStr:   connStr,
		container: mysqlContainer,
	}, nil
}

func cleanupSharedEnvs(ctx context.Context) {
	for dialect, env := range sharedDialectEnvs {
		if env.db != nil {
			_ = env.db.Close()
		}
		// Don't terminate reusable containers - they're shared across test packages
		// Containers will be cleaned up by Ryuk or manual `docker rm`
		// Clean up SQLite temp files only
		if dialect == DialectSQLite && env.connStr != "" {
			dbPath := env.connStr
			if idx := len(dbPath) - len("?_foreign_keys=on"); idx > 0 {
				dbPath = dbPath[:idx]
			}
			if dir := filepath.Dir(dbPath); dir != "" && dir != "." {
				_ = os.RemoveAll(dir)
			}
		}
	}
}

// getTestDialects returns all enabled dialect environments for testing.
// Each test gets a fresh database connection to the shared container.
func getTestDialects(t *testing.T) []*dialectTestEnv {
	t.Helper()
	var envs []*dialectTestEnv

	for dialect, sharedEnv := range sharedDialectEnvs {
		// Create a fresh database for each test to avoid state leakage
		freshEnv := createFreshTestDB(t, sharedEnv)
		envs = append(envs, freshEnv)
		_ = dialect // suppress unused warning
	}

	if len(envs) == 0 {
		t.Skip("No test dialects enabled")
	}

	return envs
}

// createFreshTestDB creates a fresh database/schema for a test
func createFreshTestDB(t *testing.T, sharedEnv *dialectTestEnv) *dialectTestEnv {
	t.Helper()
	ctx := context.Background()

	switch sharedEnv.dialect {
	case DialectSQLite:
		// For SQLite, create a new temp file
		tmpDir := t.TempDir()
		dbPath := filepath.Join(tmpDir, "test.db")
		db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
		if err != nil {
			t.Fatalf("failed to open SQLite test db: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return &dialectTestEnv{
			dialect: DialectSQLite,
			db:      db,
			connStr: dbPath,
		}

	case DialectPostgres:
		// For PostgreSQL, create a new schema
		schemaName := fmt.Sprintf("test_%d", time.Now().UnixNano())
		_, err := sharedEnv.db.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA %s", schemaName))
		if err != nil {
			t.Fatalf("failed to create schema: %v", err)
		}
		_, err = sharedEnv.db.ExecContext(ctx, fmt.Sprintf("SET search_path TO %s", schemaName))
		if err != nil {
			t.Fatalf("failed to set search_path: %v", err)
		}

		// Create a new connection with the schema set
		connStr := sharedEnv.connStr + "&search_path=" + schemaName
		db, err := sql.Open("postgres", connStr)
		if err != nil {
			t.Fatalf("failed to open postgres connection: %v", err)
		}
		t.Cleanup(func() {
			_ = db.Close()
			_, _ = sharedEnv.db.ExecContext(ctx, fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE", schemaName))
		})
		return &dialectTestEnv{
			dialect: DialectPostgres,
			db:      db,
			connStr: connStr,
		}

	case DialectMySQL:
		// For MySQL, use the shared database and truncate tables between tests
		// (testuser doesn't have CREATE DATABASE privilege)
		if err := sharedEnv.db.PingContext(ctx); err != nil {
			t.Fatalf("shared MySQL connection is invalid: %v", err)
		}

		// Drop all migration tracking tables and data tables to start fresh
		// This allows each test to run migrations from scratch
		tables := []string{
			"schema_migrations_core",
			"schema_migrations_testplugin",
			"schema_migrations_multiplemigrations",
			"verifications",
			"sessions",
			"accounts",
			"users",
			"test_plugin_table",
			"test_table_1",
			"test_table_2",
		}
		_, _ = sharedEnv.db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0")
		for _, table := range tables {
			_, _ = sharedEnv.db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", table))
		}
		_, _ = sharedEnv.db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")

		t.Cleanup(func() {
			// Clean up after test
			_, _ = sharedEnv.db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0")
			for _, table := range tables {
				_, _ = sharedEnv.db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS %s", table))
			}
			_, _ = sharedEnv.db.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
		})

		return &dialectTestEnv{
			dialect: DialectMySQL,
			db:      sharedEnv.db,
			connStr: sharedEnv.connStr,
		}

	default:
		t.Fatalf("unsupported dialect: %s", sharedEnv.dialect)
		return nil
	}
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

// newTestDB creates a SQLite test database (legacy helper for SQLite-only tests).
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// tableExistsQuery returns the query to check if a table exists for the given dialect.
func tableExistsQuery(dialect Dialect, tableName string) (string, []any) {
	switch dialect {
	case DialectPostgres:
		return "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = $1", []any{tableName}
	case DialectMySQL:
		return "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?", []any{tableName}
	case DialectSQLite:
		return "SELECT name FROM sqlite_master WHERE type='table' AND name=?", []any{tableName}
	default:
		return "", nil
	}
}

// assertTableExists checks that a table exists in the database.
func assertTableExists(t *testing.T, db *sql.DB, dialect Dialect, tableName string) {
	t.Helper()
	query, args := tableExistsQuery(dialect, tableName)
	var name string
	err := db.QueryRow(query, args...).Scan(&name)
	if err != nil {
		t.Errorf("table %s not found in %s: %v", tableName, dialect, err)
	}
}

// TestRun_CoreOnly_AllDialects tests core migrations across all enabled dialects.
func TestRun_CoreOnly_AllDialects(t *testing.T) {
	for _, env := range getTestDialects(t) {
		t.Run(string(env.dialect), func(t *testing.T) {
			ctx := context.Background()

			// Run core migrations only (no plugins)
			err := Run(ctx, env.db, env.dialect, WithLogger(testLogger()))
			if err != nil {
				t.Fatalf("Run failed: %v", err)
			}

			// Verify core tables exist
			tables := []string{"users", "accounts", "sessions", "verifications"}
			for _, table := range tables {
				assertTableExists(t, env.db, env.dialect, table)
			}

			// Verify migration tracking table exists
			assertTableExists(t, env.db, env.dialect, "schema_migrations_core")
		})
	}
}

// TestRun_WithPlugins_AllDialects tests plugin migrations across all enabled dialects.
func TestRun_WithPlugins_AllDialects(t *testing.T) {
	for _, env := range getTestDialects(t) {
		t.Run(string(env.dialect), func(t *testing.T) {
			ctx := context.Background()

			// Create a test plugin migration with dialect-appropriate SQL
			upSQL, downSQL := testTableSQL(env.dialect, "test_plugin_table")
			pluginFS := testMigrationFS(env.dialect, upSQL, downSQL)
			testPlugin := &testSource{name: "testplugin", fs: pluginFS, deps: nil}

			err := Run(ctx, env.db, env.dialect,
				WithLogger(testLogger()),
				WithPlugins(testPlugin),
			)
			if err != nil {
				t.Fatalf("Run failed: %v", err)
			}

			// Verify core tables exist
			assertTableExists(t, env.db, env.dialect, "users")

			// Verify plugin table exists
			assertTableExists(t, env.db, env.dialect, "test_plugin_table")

			// Verify both migration tracking tables exist
			assertTableExists(t, env.db, env.dialect, "schema_migrations_core")
			assertTableExists(t, env.db, env.dialect, "schema_migrations_testplugin")
		})
	}
}

// TestRun_Idempotent_AllDialects tests that migrations are idempotent across all dialects.
func TestRun_Idempotent_AllDialects(t *testing.T) {
	for _, env := range getTestDialects(t) {
		t.Run(string(env.dialect), func(t *testing.T) {
			ctx := context.Background()

			// Run migrations twice - should be idempotent
			err := Run(ctx, env.db, env.dialect, WithLogger(testLogger()))
			if err != nil {
				t.Fatalf("first Run failed: %v", err)
			}

			err = Run(ctx, env.db, env.dialect, WithLogger(testLogger()))
			if err != nil {
				t.Fatalf("second Run failed: %v", err)
			}

			// Should still have exactly one version in tracking table
			var count int
			err = env.db.QueryRow("SELECT COUNT(*) FROM schema_migrations_core").Scan(&count)
			if err != nil {
				t.Fatalf("failed to count migrations: %v", err)
			}
			if count != 1 {
				t.Errorf("expected 1 migration record, got %d", count)
			}
		})
	}
}

// ============================================================================
// SQLite-only tests (for features that don't need multi-dialect testing)
// ============================================================================

func TestRun_CoreOnly(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	err := Run(ctx, db, DialectSQLite, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	tables := []string{"users", "accounts", "sessions", "verifications"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}
}

func TestRun_WithPlugins(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pluginFS := testMigrationFS(DialectSQLite,
		"CREATE TABLE test_plugin_table (id TEXT PRIMARY KEY, data TEXT);",
		"DROP TABLE IF EXISTS test_plugin_table;",
	)
	testPlugin := &testSource{name: "testplugin", fs: pluginFS, deps: nil}

	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithPlugins(testPlugin),
	)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	var usersTable string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&usersTable)
	if err != nil {
		t.Errorf("users table not found: %v", err)
	}

	var pluginTable string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='test_plugin_table'").Scan(&pluginTable)
	if err != nil {
		t.Errorf("test_plugin_table not found: %v", err)
	}
}

func TestRun_Idempotent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	err := Run(ctx, db, DialectSQLite, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	err = Run(ctx, db, DialectSQLite, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("second Run failed: %v", err)
	}

	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM schema_migrations_core").Scan(&count)
	if err != nil {
		t.Fatalf("failed to count migrations: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 migration record, got %d", count)
	}
}

func TestRun_DryRun(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithDryRun(true),
	)
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&name)
	if err == nil {
		t.Error("users table should not exist in dry-run mode")
	}
}

func TestRun_DependencyOrder(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	plugin1FS := testMigrationFS(DialectSQLite,
		"CREATE TABLE plugin1_table (id TEXT PRIMARY KEY);",
		"DROP TABLE IF EXISTS plugin1_table;",
	)
	plugin2FS := testMigrationFS(DialectSQLite,
		"CREATE TABLE plugin2_table (id TEXT PRIMARY KEY, plugin1_ref TEXT REFERENCES plugin1_table(id));",
		"DROP TABLE IF EXISTS plugin2_table;",
	)

	plugin1 := &testSource{name: "plugin1", fs: plugin1FS, deps: nil}
	plugin2 := &testSource{name: "plugin2", fs: plugin2FS, deps: []string{"plugin1"}}

	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithPlugins(plugin2, plugin1),
	)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	tables := []string{"plugin1_table", "plugin2_table"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}
}

func TestUp_SingleSource(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pluginFS := testMigrationFS(DialectSQLite,
		"CREATE TABLE single_source_test (id TEXT PRIMARY KEY);",
		"DROP TABLE IF EXISTS single_source_test;",
	)
	src := &testSource{name: "singlesource", fs: pluginFS, deps: nil}

	err := Up(ctx, db, DialectSQLite, src, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("Up failed: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='single_source_test'").Scan(&name)
	if err != nil {
		t.Errorf("table not found: %v", err)
	}
}

func TestDown_Rollback(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pluginFS := testMigrationFS(DialectSQLite,
		"CREATE TABLE rollback_test (id TEXT PRIMARY KEY);",
		"DROP TABLE IF EXISTS rollback_test;",
	)
	src := &testSource{name: "rollbacktest", fs: pluginFS, deps: nil}

	err := Up(ctx, db, DialectSQLite, src, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("Up failed: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='rollback_test'").Scan(&name)
	if err != nil {
		t.Fatalf("table not found after Up: %v", err)
	}

	err = Down(ctx, db, DialectSQLite, src, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("Down failed: %v", err)
	}

	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='rollback_test'").Scan(&name)
	if err == nil {
		t.Error("table should not exist after Down")
	}
}

func TestStatus_ReturnsVersion(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pluginFS := testMigrationFS(DialectSQLite,
		"CREATE TABLE status_test (id TEXT PRIMARY KEY);",
		"DROP TABLE IF EXISTS status_test;",
	)
	src := &testSource{name: "statustest", fs: pluginFS, deps: nil}

	version, dirty, err := Status(ctx, db, DialectSQLite, src)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if version != 0 {
		t.Errorf("expected version 0 before migration, got %d", version)
	}
	if dirty {
		t.Error("expected clean state before migration")
	}

	err = Up(ctx, db, DialectSQLite, src, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("Up failed: %v", err)
	}

	version, dirty, err = Status(ctx, db, DialectSQLite, src)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if version != 1 {
		t.Errorf("expected version 1 after migration, got %d", version)
	}
	if dirty {
		t.Error("expected clean state after successful migration")
	}
}

func TestRun_UnsupportedDialect(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	err := Run(ctx, db, Dialect("unsupported"))
	if err == nil {
		t.Error("expected error for unsupported dialect")
	}
}

func TestRun_MissingDependency(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pluginFS := testMigrationFS(DialectSQLite,
		"CREATE TABLE dep_test (id TEXT PRIMARY KEY);",
		"DROP TABLE IF EXISTS dep_test;",
	)
	plugin := &testSource{name: "deptest", fs: pluginFS, deps: []string{"nonexistent"}}

	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithPlugins(plugin),
	)
	if err == nil {
		t.Error("expected error for missing dependency")
	}
}

func TestRun_CyclicDependency(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pluginAFS := testMigrationFS(DialectSQLite, "SELECT 1;", "SELECT 1;")
	pluginBFS := testMigrationFS(DialectSQLite, "SELECT 1;", "SELECT 1;")

	pluginA := &testSource{name: "cycleA", fs: pluginAFS, deps: []string{"cycleB"}}
	pluginB := &testSource{name: "cycleB", fs: pluginBFS, deps: []string{"cycleA"}}

	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithPlugins(pluginA, pluginB),
	)
	if err == nil {
		t.Error("expected error for cyclic dependency")
	}
}

func TestRun_InvalidMigrationSQL(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pluginFS := testMigrationFS(DialectSQLite,
		"THIS IS NOT VALID SQL;",
		"DROP TABLE IF EXISTS invalid_test;",
	)
	plugin := &testSource{name: "invalidsql", fs: pluginFS, deps: nil}

	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithPlugins(plugin),
	)
	if err == nil {
		t.Error("expected error for invalid SQL")
	}
}

func TestRun_EmptyPluginsList(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithPlugins(),
	)
	if err != nil {
		t.Fatalf("Run with empty plugins failed: %v", err)
	}

	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&name)
	if err != nil {
		t.Errorf("users table not found: %v", err)
	}
}

func TestRun_MultipleMigrationsInOrder(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	multiFS := fstest.MapFS{
		"sqlite/000001_first.up.sql":    &fstest.MapFile{Data: []byte("CREATE TABLE multi_first (id TEXT PRIMARY KEY);")},
		"sqlite/000001_first.down.sql":  &fstest.MapFile{Data: []byte("DROP TABLE IF EXISTS multi_first;")},
		"sqlite/000002_second.up.sql":   &fstest.MapFile{Data: []byte("CREATE TABLE multi_second (id TEXT PRIMARY KEY, first_ref TEXT REFERENCES multi_first(id));")},
		"sqlite/000002_second.down.sql": &fstest.MapFile{Data: []byte("DROP TABLE IF EXISTS multi_second;")},
	}
	plugin := &testSource{name: "multiplemigrations", fs: multiFS, deps: nil}

	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithPlugins(plugin),
	)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	tables := []string{"multi_first", "multi_second"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}

	version, _, err := Status(ctx, db, DialectSQLite, plugin)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if version != 2 {
		t.Errorf("expected version 2, got %d", version)
	}
}
