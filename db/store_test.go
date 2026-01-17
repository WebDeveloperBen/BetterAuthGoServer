package db_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/db"
	"github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

// Shared test environments (initialized in TestMain)
var sharedDialectEnvs map[db.Dialect]*dialectTestEnv

// dialectTestEnv holds database connection info for a specific dialect.
type dialectTestEnv struct {
	dialect   db.Dialect
	db        *sql.DB
	connStr   string
	container testcontainers.Container
}

// TestMain sets up shared database containers for all store tests.
func TestMain(m *testing.M) {
	ctx := context.Background()
	sharedDialectEnvs = make(map[db.Dialect]*dialectTestEnv)

	// SQLite (enabled by default)
	if os.Getenv("TEST_SQLITE") != "false" {
		fmt.Println("Setting up SQLite for db store tests...")
		env, err := setupSharedSQLite()
		if err != nil {
			fmt.Printf("Failed to setup SQLite: %v\n", err)
			os.Exit(1)
		}
		sharedDialectEnvs[db.DialectSQLite] = env
		fmt.Println("SQLite ready")
	}

	// PostgreSQL (enabled by default)
	if os.Getenv("TEST_POSTGRES") != "false" {
		fmt.Println("Setting up PostgreSQL container for db store tests...")
		env, err := setupSharedPostgres(ctx)
		if err != nil {
			fmt.Printf("Failed to setup PostgreSQL: %v\n", err)
			cleanupSharedEnvs(ctx)
			os.Exit(1)
		}
		sharedDialectEnvs[db.DialectPostgres] = env
		fmt.Println("PostgreSQL container ready")
	}

	// MySQL (enabled by default)
	if os.Getenv("TEST_MYSQL") != "false" {
		fmt.Println("Setting up MySQL container for db store tests...")
		env, err := setupSharedMySQL(ctx)
		if err != nil {
			fmt.Printf("Failed to setup MySQL: %v\n", err)
			cleanupSharedEnvs(ctx)
			os.Exit(1)
		}
		sharedDialectEnvs[db.DialectMySQL] = env
		fmt.Println("MySQL container ready")
	}

	if len(sharedDialectEnvs) == 0 {
		fmt.Println("No dialects enabled for db store tests")
		os.Exit(1)
	}

	fmt.Printf("Running db store tests with %d dialect(s)\n", len(sharedDialectEnvs))

	code := m.Run()

	// Cleanup
	cleanupSharedEnvs(ctx)

	os.Exit(code)
}

func setupSharedSQLite() (*dialectTestEnv, error) {
	tmpDir, err := os.MkdirTemp("", "db-store-test-sqlite-*")
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

	return &dialectTestEnv{
		dialect: db.DialectSQLite,
		db:      sqlDB,
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

	sqlDB, err := sql.Open("postgres", connStr)
	if err != nil {
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool to prevent stale connections
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	// Verify connection is working
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		_ = pgContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &dialectTestEnv{
		dialect:   db.DialectPostgres,
		db:        sqlDB,
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

	// Get base connection string (without database specified)
	baseConnStr, err := mysqlContainer.ConnectionString(ctx, "parseTime=true&multiStatements=true")
	if err != nil {
		_ = mysqlContainer.Terminate(ctx)
		return nil, fmt.Errorf("failed to get connection string: %w", err)
	}

	// Get root connection string for admin operations (creating databases)
	// Root password is 'testpass' when using mysql.WithPassword
	rootConnStr := replaceDBName(baseConnStr, "mysql")
	rootConnStr = rootConnStr[:len("root:testpass@tcp")] + rootConnStr[len("testuser:testpass@tcp"):]

	// Build proper root connection string
	// Format: user:password@tcp(host:port)/dbname?params
	// We need to replace testuser with root
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
	rootConnStr = fmt.Sprintf("root:testpass@tcp(%s:%s)/mysql?parseTime=true&multiStatements=true", host, port.Port())

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
	// This prevents conflicts when migrate tests drop/recreate tables
	dbName := "testdb_dbpkg"
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

	// Configure connection pool to prevent stale connections
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to ping isolated database: %w", err)
	}

	// Run migrations once during setup for MySQL
	// (we reuse the same database and truncate tables between tests)
	if err := migrate.Run(ctx, sqlDB, migrate.Dialect(db.DialectMySQL)); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return &dialectTestEnv{
		dialect:   db.DialectMySQL,
		db:        sqlDB,
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
		if dialect == db.DialectSQLite && env.connStr != "" {
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

// testCounter is used to create unique schema/database names per test
var testCounter int

// setupTestStore creates a fresh store for a test with migrations applied.
func setupTestStore(t *testing.T, sharedEnv *dialectTestEnv) *db.Store {
	t.Helper()
	ctx := context.Background()

	testCounter++
	testName := fmt.Sprintf("test_%d", testCounter)

	var testDB *sql.DB
	var err error

	switch sharedEnv.dialect {
	case db.DialectPostgres:
		// Create a fresh schema for this test
		schemaName := testName
		_, err = sharedEnv.db.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA %s", schemaName))
		if err != nil {
			t.Fatalf("failed to create schema: %v", err)
		}

		// Open a new connection with search_path set in the connection string
		// This ensures migrations also use this schema
		connStrWithSchema := sharedEnv.connStr + fmt.Sprintf("&search_path=%s", schemaName)
		testDB, err = sql.Open("postgres", connStrWithSchema)
		if err != nil {
			t.Fatalf("failed to open database with schema: %v", err)
		}

		// Configure connection pool
		testDB.SetMaxOpenConns(5)
		testDB.SetMaxIdleConns(2)
		testDB.SetConnMaxLifetime(5 * time.Minute)

		t.Cleanup(func() {
			_ = testDB.Close()
			_, _ = sharedEnv.db.ExecContext(ctx, fmt.Sprintf("DROP SCHEMA %s CASCADE", schemaName))
		})

	case db.DialectMySQL:
		// For MySQL, use the shared database and clean tables before/after each test
		// (migrations are already run during container setup)
		testDB = sharedEnv.db

		// Clean all tables before the test
		tables := []string{"verifications", "sessions", "accounts", "users"}
		// Disable foreign key checks temporarily for truncation
		_, _ = testDB.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0")
		for _, table := range tables {
			_, _ = testDB.ExecContext(ctx, fmt.Sprintf("TRUNCATE TABLE %s", table))
		}
		_, _ = testDB.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")

		t.Cleanup(func() {
			// Clean tables after test
			_, _ = testDB.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 0")
			for _, table := range tables {
				_, _ = testDB.ExecContext(ctx, fmt.Sprintf("TRUNCATE TABLE %s", table))
			}
			_, _ = testDB.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS = 1")
		})

		// Create store and return early (migrations already run during setup)
		store, err := db.New(testDB, sharedEnv.dialect)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}
		return store

	case db.DialectSQLite:
		// For SQLite, just use the shared database and clean tables after
		testDB = sharedEnv.db
		t.Cleanup(func() {
			tables := []string{"verifications", "sessions", "accounts", "users"}
			for _, table := range tables {
				_, _ = sharedEnv.db.ExecContext(ctx, fmt.Sprintf("DELETE FROM %s", table))
			}
		})
	}

	// Run migrations
	err = migrate.Run(ctx, testDB, migrate.Dialect(sharedEnv.dialect))
	if err != nil {
		t.Fatalf("failed to run migrations: %v", err)
	}

	// Create store
	store, err := db.New(testDB, sharedEnv.dialect)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	return store
}

// getDialects returns all enabled dialect environments for testing.
func getDialects() []*dialectTestEnv {
	var envs []*dialectTestEnv
	for _, env := range sharedDialectEnvs {
		envs = append(envs, env)
	}
	return envs
}

// =============================================================================
// User Store Tests
// =============================================================================

func TestUserStore_CreateAndGet(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)
			user := &models.User{
				ID:            "user-123",
				Email:         "test@example.com",
				EmailVerified: false,
				Name:          "Test User",
				Role:          "user",
				CreatedAt:     now,
				UpdatedAt:     now,
			}

			// Create
			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			// Get by ID
			got, err := store.GetUserByID(ctx, user.ID)
			if err != nil {
				t.Fatalf("GetUserByID failed: %v", err)
			}

			if got.ID != user.ID {
				t.Errorf("expected ID %s, got %s", user.ID, got.ID)
			}
			if got.Email != user.Email {
				t.Errorf("expected Email %s, got %s", user.Email, got.Email)
			}
			if got.Name != user.Name {
				t.Errorf("expected Name %s, got %s", user.Name, got.Name)
			}

			// Get by Email
			got, err = store.GetUserByEmail(ctx, user.Email)
			if err != nil {
				t.Fatalf("GetUserByEmail failed: %v", err)
			}

			if got.ID != user.ID {
				t.Errorf("expected ID %s, got %s", user.ID, got.ID)
			}
		})
	}
}

func TestUserStore_Update(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)
			user := &models.User{
				ID:            "user-123",
				Email:         "test@example.com",
				EmailVerified: false,
				Name:          "Original Name",
				Role:          "user",
				CreatedAt:     now,
				UpdatedAt:     now,
			}

			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			// Update
			user.Name = "Updated Name"
			user.EmailVerified = true
			user.UpdatedAt = time.Now().Truncate(time.Second)

			err = store.UpdateUser(ctx, user)
			if err != nil {
				t.Fatalf("UpdateUser failed: %v", err)
			}

			// Verify
			got, err := store.GetUserByID(ctx, user.ID)
			if err != nil {
				t.Fatalf("GetUserByID failed: %v", err)
			}

			if got.Name != "Updated Name" {
				t.Errorf("expected Name 'Updated Name', got %s", got.Name)
			}
			if !got.EmailVerified {
				t.Error("expected EmailVerified to be true")
			}
		})
	}
}

func TestUserStore_SetEmailVerified(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)
			user := &models.User{
				ID:            "user-123",
				Email:         "test@example.com",
				EmailVerified: false,
				Name:          "Test User",
				Role:          "user",
				CreatedAt:     now,
				UpdatedAt:     now,
			}

			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			// Set verified
			err = store.SetEmailVerified(ctx, user.ID, true)
			if err != nil {
				t.Fatalf("SetEmailVerified failed: %v", err)
			}

			got, err := store.GetUserByID(ctx, user.ID)
			if err != nil {
				t.Fatalf("GetUserByID failed: %v", err)
			}

			if !got.EmailVerified {
				t.Error("expected EmailVerified to be true")
			}
		})
	}
}

func TestUserStore_Delete(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)
			user := &models.User{
				ID:            "user-123",
				Email:         "test@example.com",
				EmailVerified: false,
				Name:          "Test User",
				Role:          "user",
				CreatedAt:     now,
				UpdatedAt:     now,
			}

			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			// Delete
			err = store.DeleteUser(ctx, user.ID)
			if err != nil {
				t.Fatalf("DeleteUser failed: %v", err)
			}

			// Verify deleted - store returns (nil, nil) for not found
			got, err := store.GetUserByID(ctx, user.ID)
			if err != nil {
				t.Errorf("expected nil error for deleted user, got: %v", err)
			}
			if got != nil {
				t.Errorf("expected nil user for deleted user, got: %+v", got)
			}
		})
	}
}

// =============================================================================
// Session Store Tests
// =============================================================================

func TestSessionStore_CreateAndGet(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)

			// First create a user (required for foreign key)
			user := &models.User{
				ID:        "user-123",
				Email:     "test@example.com",
				Name:      "Test User",
				Role:      "user",
				CreatedAt: now,
				UpdatedAt: now,
			}
			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			ip := "127.0.0.1"
			ua := "TestBrowser/1.0"
			session := &models.Session{
				ID:        "session-123",
				UserID:    user.ID,
				TokenHash: "hash123",
				IPAddress: &ip,
				UserAgent: &ua,
				CreatedAt: now,
				ExpiresAt: now.Add(24 * time.Hour),
				LastUsed:  now,
			}

			// Create
			err = store.CreateSession(ctx, session)
			if err != nil {
				t.Fatalf("CreateSession failed: %v", err)
			}

			// Get by ID
			got, err := store.GetSessionByID(ctx, session.ID)
			if err != nil {
				t.Fatalf("GetSessionByID failed: %v", err)
			}

			if got.ID != session.ID {
				t.Errorf("expected ID %s, got %s", session.ID, got.ID)
			}
			if got.UserID != session.UserID {
				t.Errorf("expected UserID %s, got %s", session.UserID, got.UserID)
			}

			// Get by Token Hash
			got, err = store.GetSessionByTokenHash(ctx, session.TokenHash)
			if err != nil {
				t.Fatalf("GetSessionByTokenHash failed: %v", err)
			}

			if got.ID != session.ID {
				t.Errorf("expected ID %s, got %s", session.ID, got.ID)
			}
		})
	}
}

func TestSessionStore_ListByUserID(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)

			user := &models.User{
				ID:        "user-123",
				Email:     "test@example.com",
				Name:      "Test User",
				Role:      "user",
				CreatedAt: now,
				UpdatedAt: now,
			}
			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			// Create multiple sessions
			for i := 0; i < 3; i++ {
				session := &models.Session{
					ID:        fmt.Sprintf("session-%d", i),
					UserID:    user.ID,
					TokenHash: fmt.Sprintf("hash%d", i),
					CreatedAt: now,
					ExpiresAt: now.Add(24 * time.Hour),
					LastUsed:  now,
				}
				err = store.CreateSession(ctx, session)
				if err != nil {
					t.Fatalf("CreateSession %d failed: %v", i, err)
				}
			}

			// List
			sessions, err := store.ListSessionsByUserID(ctx, user.ID)
			if err != nil {
				t.Fatalf("ListSessionsByUserID failed: %v", err)
			}

			if len(sessions) != 3 {
				t.Errorf("expected 3 sessions, got %d", len(sessions))
			}
		})
	}
}

func TestSessionStore_Delete(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)

			user := &models.User{
				ID:        "user-123",
				Email:     "test@example.com",
				Name:      "Test User",
				Role:      "user",
				CreatedAt: now,
				UpdatedAt: now,
			}
			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			session := &models.Session{
				ID:        "session-123",
				UserID:    user.ID,
				TokenHash: "hash123",
				CreatedAt: now,
				ExpiresAt: now.Add(24 * time.Hour),
				LastUsed:  now,
			}
			err = store.CreateSession(ctx, session)
			if err != nil {
				t.Fatalf("CreateSession failed: %v", err)
			}

			// Delete
			err = store.DeleteSession(ctx, session.ID)
			if err != nil {
				t.Fatalf("DeleteSession failed: %v", err)
			}

			// Verify deleted - store returns (nil, nil) for not found
			got, err := store.GetSessionByID(ctx, session.ID)
			if err != nil {
				t.Errorf("expected nil error for deleted session, got: %v", err)
			}
			if got != nil {
				t.Errorf("expected nil session for deleted session, got: %+v", got)
			}
		})
	}
}

func TestSessionStore_DeleteByUserID(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)

			user := &models.User{
				ID:        "user-123",
				Email:     "test@example.com",
				Name:      "Test User",
				Role:      "user",
				CreatedAt: now,
				UpdatedAt: now,
			}
			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			// Create multiple sessions
			for i := 0; i < 3; i++ {
				session := &models.Session{
					ID:        fmt.Sprintf("session-%d", i),
					UserID:    user.ID,
					TokenHash: fmt.Sprintf("hash%d", i),
					CreatedAt: now,
					ExpiresAt: now.Add(24 * time.Hour),
					LastUsed:  now,
				}
				err = store.CreateSession(ctx, session)
				if err != nil {
					t.Fatalf("CreateSession %d failed: %v", i, err)
				}
			}

			// Delete all by user
			err = store.DeleteSessionsByUserID(ctx, user.ID)
			if err != nil {
				t.Fatalf("DeleteSessionsByUserID failed: %v", err)
			}

			// Verify all deleted
			sessions, err := store.ListSessionsByUserID(ctx, user.ID)
			if err != nil {
				t.Fatalf("ListSessionsByUserID failed: %v", err)
			}

			if len(sessions) != 0 {
				t.Errorf("expected 0 sessions, got %d", len(sessions))
			}
		})
	}
}

// =============================================================================
// Account Store Tests
// =============================================================================

func TestAccountStore_CreateAndGet(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)

			user := &models.User{
				ID:        "user-123",
				Email:     "test@example.com",
				Name:      "Test User",
				Role:      "user",
				CreatedAt: now,
				UpdatedAt: now,
			}
			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			passwordHash := "hashed-password"
			account := &models.Account{
				ID:           "account-123",
				UserID:       user.ID,
				Provider:     models.ProviderType("email"),
				PasswordHash: &passwordHash,
				CreatedAt:    now,
				UpdatedAt:    now,
			}

			// Create
			err = store.CreateAccount(ctx, account)
			if err != nil {
				t.Fatalf("CreateAccount failed: %v", err)
			}

			// Get by ID
			got, err := store.GetAccountByID(ctx, account.ID)
			if err != nil {
				t.Fatalf("GetAccountByID failed: %v", err)
			}

			if got.ID != account.ID {
				t.Errorf("expected ID %s, got %s", account.ID, got.ID)
			}
			if got.UserID != account.UserID {
				t.Errorf("expected UserID %s, got %s", account.UserID, got.UserID)
			}
			if *got.PasswordHash != *account.PasswordHash {
				t.Errorf("expected PasswordHash %s, got %s", *account.PasswordHash, *got.PasswordHash)
			}

			// Get by User and Provider
			got, err = store.GetAccountByUserIDAndProvider(ctx, user.ID, models.ProviderType("email"))
			if err != nil {
				t.Fatalf("GetAccountByUserIDAndProvider failed: %v", err)
			}

			if got.ID != account.ID {
				t.Errorf("expected ID %s, got %s", account.ID, got.ID)
			}
		})
	}
}

func TestAccountStore_ListByUserID(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)

			user := &models.User{
				ID:        "user-123",
				Email:     "test@example.com",
				Name:      "Test User",
				Role:      "user",
				CreatedAt: now,
				UpdatedAt: now,
			}
			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			// Create email account
			passwordHash := "hashed-password"
			emailAccount := &models.Account{
				ID:           "account-email",
				UserID:       user.ID,
				Provider:     models.ProviderType("email"),
				PasswordHash: &passwordHash,
				CreatedAt:    now,
				UpdatedAt:    now,
			}
			err = store.CreateAccount(ctx, emailAccount)
			if err != nil {
				t.Fatalf("CreateAccount (email) failed: %v", err)
			}

			// Create oauth account
			providerID := "github-123"
			oauthAccount := &models.Account{
				ID:                "account-github",
				UserID:            user.ID,
				Provider:          models.ProviderType("github"),
				ProviderAccountID: &providerID,
				CreatedAt:         now,
				UpdatedAt:         now,
			}
			err = store.CreateAccount(ctx, oauthAccount)
			if err != nil {
				t.Fatalf("CreateAccount (github) failed: %v", err)
			}

			// List
			accounts, err := store.ListAccountsByUserID(ctx, user.ID)
			if err != nil {
				t.Fatalf("ListAccountsByUserID failed: %v", err)
			}

			if len(accounts) != 2 {
				t.Errorf("expected 2 accounts, got %d", len(accounts))
			}
		})
	}
}

func TestAccountStore_Delete(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)

			user := &models.User{
				ID:        "user-123",
				Email:     "test@example.com",
				Name:      "Test User",
				Role:      "user",
				CreatedAt: now,
				UpdatedAt: now,
			}
			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			passwordHash := "hashed-password"
			account := &models.Account{
				ID:           "account-123",
				UserID:       user.ID,
				Provider:     models.ProviderType("email"),
				PasswordHash: &passwordHash,
				CreatedAt:    now,
				UpdatedAt:    now,
			}
			err = store.CreateAccount(ctx, account)
			if err != nil {
				t.Fatalf("CreateAccount failed: %v", err)
			}

			// Delete
			err = store.DeleteAccount(ctx, account.ID)
			if err != nil {
				t.Fatalf("DeleteAccount failed: %v", err)
			}

			// Verify deleted - store returns (nil, nil) for not found
			got, err := store.GetAccountByID(ctx, account.ID)
			if err != nil {
				t.Errorf("expected nil error for deleted account, got: %v", err)
			}
			if got != nil {
				t.Errorf("expected nil account for deleted account, got: %+v", got)
			}
		})
	}
}

// =============================================================================
// Password Plugin Store Tests
// =============================================================================

func TestPasswordPluginStore(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)
			ctx := context.Background()

			now := time.Now().Truncate(time.Second)

			user := &models.User{
				ID:        "user-123",
				Email:     "test@example.com",
				Name:      "Test User",
				Role:      "user",
				CreatedAt: now,
				UpdatedAt: now,
			}
			err := store.CreateUser(ctx, user)
			if err != nil {
				t.Fatalf("CreateUser failed: %v", err)
			}

			// Create password account
			err = store.CreatePasswordAccount(ctx, "account-123", user.ID, "initial-hash")
			if err != nil {
				t.Fatalf("CreatePasswordAccount failed: %v", err)
			}

			// Get password account
			got, err := store.GetPasswordAccount(ctx, user.ID)
			if err != nil {
				t.Fatalf("GetPasswordAccount failed: %v", err)
			}

			if got.UserID != user.ID {
				t.Errorf("expected UserID %s, got %s", user.ID, got.UserID)
			}
			if *got.PasswordHash != "initial-hash" {
				t.Errorf("expected PasswordHash 'initial-hash', got %s", *got.PasswordHash)
			}

			// Update password hash
			err = store.UpdatePasswordHash(ctx, user.ID, "updated-hash")
			if err != nil {
				t.Fatalf("UpdatePasswordHash failed: %v", err)
			}

			got, err = store.GetPasswordAccount(ctx, user.ID)
			if err != nil {
				t.Fatalf("GetPasswordAccount after update failed: %v", err)
			}

			if *got.PasswordHash != "updated-hash" {
				t.Errorf("expected PasswordHash 'updated-hash', got %s", *got.PasswordHash)
			}
		})
	}
}

// =============================================================================
// Dialect-Specific Tests
// =============================================================================

func TestStore_NewWithInvalidDialect(t *testing.T) {
	_, err := db.New(nil, "invalid")
	if err == nil {
		t.Error("expected error for invalid dialect")
	}
}

func TestStore_DialectReturnsCorrectValue(t *testing.T) {
	for _, dialectEnv := range getDialects() {
		t.Run(string(dialectEnv.dialect), func(t *testing.T) {
			store := setupTestStore(t, dialectEnv)

			if store.Dialect() != dialectEnv.dialect {
				t.Errorf("expected dialect %s, got %s", dialectEnv.dialect, store.Dialect())
			}
		})
	}
}
