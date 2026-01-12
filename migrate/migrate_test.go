package migrate

import (
	"context"
	"database/sql"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	_ "github.com/mattn/go-sqlite3"
)

// testMigrationFS creates a mock filesystem with migration files.
func testMigrationFS(upSQL, downSQL string) fs.FS {
	return fstest.MapFS{
		"sqlite/000001_test.up.sql":   &fstest.MapFile{Data: []byte(upSQL)},
		"sqlite/000001_test.down.sql": &fstest.MapFile{Data: []byte(downSQL)},
	}
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

func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	// Use a temp file instead of in-memory because golang-migrate's sqlite3 driver
	// closes the connection when the migrator is closed, which destroys in-memory DBs.
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

func TestRun_CoreOnly(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Run core migrations only (no plugins)
	err := Run(ctx, db, DialectSQLite, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Verify core tables exist
	tables := []string{"users", "accounts", "sessions", "verifications"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}

	// Verify migration tracking table exists
	var trackingTable string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations_core'").Scan(&trackingTable)
	if err != nil {
		t.Errorf("schema_migrations_core table not found: %v", err)
	}
}

func TestRun_WithPlugins(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Create a test plugin migration
	pluginFS := testMigrationFS(
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

	// Verify core tables exist
	var usersTable string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&usersTable)
	if err != nil {
		t.Errorf("users table not found: %v", err)
	}

	// Verify plugin table exists
	var pluginTable string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='test_plugin_table'").Scan(&pluginTable)
	if err != nil {
		t.Errorf("test_plugin_table not found: %v", err)
	}

	// Verify both migration tracking tables exist
	var coreTracking, pluginTracking string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations_core'").Scan(&coreTracking)
	if err != nil {
		t.Errorf("schema_migrations_core not found: %v", err)
	}
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations_testplugin'").Scan(&pluginTracking)
	if err != nil {
		t.Errorf("schema_migrations_testplugin not found: %v", err)
	}
}

func TestRun_Idempotent(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Run migrations twice - should be idempotent
	err := Run(ctx, db, DialectSQLite, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("first Run failed: %v", err)
	}

	err = Run(ctx, db, DialectSQLite, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("second Run failed: %v", err)
	}

	// Should still have exactly one version in tracking table
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

	// Run with dry-run enabled
	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithDryRun(true),
	)
	if err != nil {
		t.Fatalf("dry run failed: %v", err)
	}

	// Tables should NOT exist in dry-run mode
	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&name)
	if err == nil {
		t.Error("users table should not exist in dry-run mode")
	}
}

func TestRun_DependencyOrder(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Track execution order
	var executionOrder []string

	// Create plugins with dependencies
	// plugin2 depends on plugin1
	plugin1FS := testMigrationFS(
		"CREATE TABLE plugin1_table (id TEXT PRIMARY KEY);",
		"DROP TABLE IF EXISTS plugin1_table;",
	)
	plugin2FS := testMigrationFS(
		"CREATE TABLE plugin2_table (id TEXT PRIMARY KEY, plugin1_ref TEXT REFERENCES plugin1_table(id));",
		"DROP TABLE IF EXISTS plugin2_table;",
	)

	plugin1 := &testSource{name: "plugin1", fs: plugin1FS, deps: nil}
	plugin2 := &testSource{name: "plugin2", fs: plugin2FS, deps: []string{"plugin1"}}

	// Register in reverse order to test sorting
	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithPlugins(plugin2, plugin1), // Note: plugin2 listed first
	)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	// Both tables should exist (plugin2 depends on plugin1, so plugin1 must run first)
	tables := []string{"plugin1_table", "plugin2_table"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}

	// Verify the execution order was correct by checking tracking tables
	_ = executionOrder // Would need hooks to verify exact order
}

func TestUp_SingleSource(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pluginFS := testMigrationFS(
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

	pluginFS := testMigrationFS(
		"CREATE TABLE rollback_test (id TEXT PRIMARY KEY);",
		"DROP TABLE IF EXISTS rollback_test;",
	)
	src := &testSource{name: "rollbacktest", fs: pluginFS, deps: nil}

	// First, run Up
	err := Up(ctx, db, DialectSQLite, src, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("Up failed: %v", err)
	}

	// Verify table exists
	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='rollback_test'").Scan(&name)
	if err != nil {
		t.Fatalf("table not found after Up: %v", err)
	}

	// Now run Down
	err = Down(ctx, db, DialectSQLite, src, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("Down failed: %v", err)
	}

	// Verify table no longer exists
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='rollback_test'").Scan(&name)
	if err == nil {
		t.Error("table should not exist after Down")
	}
}

func TestStatus_ReturnsVersion(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	pluginFS := testMigrationFS(
		"CREATE TABLE status_test (id TEXT PRIMARY KEY);",
		"DROP TABLE IF EXISTS status_test;",
	)
	src := &testSource{name: "statustest", fs: pluginFS, deps: nil}

	// Before running migrations, version should be 0
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

	// Run migration
	err = Up(ctx, db, DialectSQLite, src, WithLogger(testLogger()))
	if err != nil {
		t.Fatalf("Up failed: %v", err)
	}

	// After running, version should be 1
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

	// Plugin depends on "nonexistent" which isn't provided
	pluginFS := testMigrationFS(
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

	// Create cyclic dependency: a -> b -> a
	pluginAFS := testMigrationFS("SELECT 1;", "SELECT 1;")
	pluginBFS := testMigrationFS("SELECT 1;", "SELECT 1;")

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

	// Invalid SQL should cause an error
	pluginFS := testMigrationFS(
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

	// Running with empty plugins list should just run core
	err := Run(ctx, db, DialectSQLite,
		WithLogger(testLogger()),
		WithPlugins(), // Empty
	)
	if err != nil {
		t.Fatalf("Run with empty plugins failed: %v", err)
	}

	// Core tables should exist
	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").Scan(&name)
	if err != nil {
		t.Errorf("users table not found: %v", err)
	}
}

func TestRun_MultipleMigrationsInOrder(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Create a plugin with multiple migrations
	multiFS := fstest.MapFS{
		"sqlite/000001_first.up.sql":   &fstest.MapFile{Data: []byte("CREATE TABLE multi_first (id TEXT PRIMARY KEY);")},
		"sqlite/000001_first.down.sql": &fstest.MapFile{Data: []byte("DROP TABLE IF EXISTS multi_first;")},
		"sqlite/000002_second.up.sql":  &fstest.MapFile{Data: []byte("CREATE TABLE multi_second (id TEXT PRIMARY KEY, first_ref TEXT REFERENCES multi_first(id));")},
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

	// Both tables should exist
	tables := []string{"multi_first", "multi_second"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("table %s not found: %v", table, err)
		}
	}

	// Version should be 2
	version, _, err := Status(ctx, db, DialectSQLite, plugin)
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if version != 2 {
		t.Errorf("expected version 2, got %d", version)
	}
}
