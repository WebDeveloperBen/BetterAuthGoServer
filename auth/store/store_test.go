package store_test

import (
	"context"
	"database/sql"
	"testing"
)

func TestNew(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	if tdb.Store == nil {
		t.Fatal("New() returned nil store")
	}
}

func TestDB(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	dbtx := tdb.Store.DB()
	if dbtx == nil {
		t.Fatal("DB() returned nil")
	}

	// Type assert to *sql.DB to use PingContext
	db, ok := dbtx.(*sql.DB)
	if !ok {
		t.Fatal("DB() did not return *sql.DB")
	}

	// Verify the DB connection is valid by pinging
	ctx := context.Background()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("DB().Ping() error = %v", err)
	}
}

func TestMigrations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	migrations := tdb.Store.Migrations()

	// Should have 4 models: User, Account, Session, Verification
	if len(migrations) != 4 {
		t.Errorf("Migrations() returned %d models, want 4", len(migrations))
	}
}

func TestMigrate(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()

	// Migration should already have run in setupTestDB, but verify tables exist
	tables := []string{"users", "accounts", "sessions", "verifications"}
	for _, table := range tables {
		var exists bool
		err := tdb.DB.NewSelect().
			ColumnExpr("EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name = ?)", table).
			Scan(ctx, &exists)
		if err != nil {
			t.Fatalf("Failed to check table %s existence: %v", table, err)
		}
		if !exists {
			t.Errorf("Table %s does not exist after migration", table)
		}
	}
}

func TestMigrate_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()

	// Run migration again - should not error
	err := tdb.Store.Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate() second run error = %v", err)
	}

	// Run a third time to be sure
	err = tdb.Store.Migrate(ctx)
	if err != nil {
		t.Fatalf("Migrate() third run error = %v", err)
	}
}

func TestMigrate_CreatesIndexes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tdb := setupTestDB(t)
	defer tdb.cleanup(t)

	ctx := context.Background()

	// Check some expected indexes exist
	expectedIndexes := []struct {
		table string
		index string
	}{
		{"users", "idx_users_email"},
		{"users", "idx_users_banned"},
		{"users", "idx_users_role"},
		{"accounts", "idx_accounts_user_id"},
		{"accounts", "idx_accounts_provider"},
		{"sessions", "idx_sessions_user_id"},
		{"sessions", "idx_sessions_token_hash"},
		{"sessions", "idx_sessions_expires_at"},
		{"verifications", "idx_verifications_token_hash"},
		{"verifications", "idx_verifications_user_id_type"},
	}

	for _, expected := range expectedIndexes {
		var exists bool
		err := tdb.DB.NewSelect().
			ColumnExpr("EXISTS(SELECT 1 FROM pg_indexes WHERE tablename = ? AND indexname = ?)",
				expected.table, expected.index).
			Scan(ctx, &exists)
		if err != nil {
			t.Fatalf("Failed to check index %s existence: %v", expected.index, err)
		}
		if !exists {
			t.Errorf("Index %s on table %s does not exist after migration", expected.index, expected.table)
		}
	}
}
