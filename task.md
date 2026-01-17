# TODO

## Migration System

- [x] Define migration UX for SDK consumers (CLI and/or library API, default migration dir, env var support)
- [x] Decide migration packaging strategy (ship migrations inside SDK, embed via `embed.FS`, expose versioned paths)
- [x] Implement migration runner for consumers (up/down/step/status, locking, dry-run, timeout)
- [ ] Add stable migration versioning and compatibility notes in docs
- [ ] Update tests to use the migration runner as the single source of truth
- [ ] Remove hardcoded SQL fixtures once tests use migrations
- [ ] Document upgrade flow for SDK users (examples for local dev and CI)

## Multi-Dialect Integration Testing

- [ ] Create shared test infrastructure for all three dialects
- [ ] Update E2E tests to run against PostgreSQL, MySQL, and SQLite
- [ ] Add plugin store integration tests for each dialect
- [ ] Add migration integration tests for each dialect

---

# Integration Testing Plan

## Current State

- **E2E tests** (`tests/e2e/`): Only run against PostgreSQL via testcontainers
- **Unit tests**: Mock-based, don't test actual database interactions
- **Migration tests** (`migrate/migrate_test.go`): Only test SQLite (in-memory)

## Goal

Run the full test suite against all three database dialects (PostgreSQL, MySQL, SQLite) to ensure:
1. All sqlc-generated code works correctly per dialect
2. Adapter pattern conversions are correct
3. Migrations run successfully on each database
4. E2E auth flows work identically across databases

## Implementation Plan

### Phase 1: Test Infrastructure

#### 1.1 Create `tests/testutil/` package

```go
// tests/testutil/dialects.go
package testutil

type DialectTestEnv struct {
    DB      *sql.DB
    Dialect db.Dialect
    Cleanup func()
}

// GetTestDialects returns test environments for all enabled dialects
// Controlled by environment variables: TEST_POSTGRES, TEST_MYSQL, TEST_SQLITE
func GetTestDialects(t *testing.T) []DialectTestEnv

// SetupPostgres creates a PostgreSQL container
func SetupPostgres(t *testing.T) DialectTestEnv

// SetupMySQL creates a MySQL container
func SetupMySQL(t *testing.T) DialectTestEnv

// SetupSQLite creates an in-memory SQLite database
func SetupSQLite(t *testing.T) DialectTestEnv
```

#### 1.2 Update testcontainers setup

```go
// tests/e2e/main_test.go
// Add MySQL container alongside PostgreSQL

var (
    pgContainer    testcontainers.Container
    mysqlContainer testcontainers.Container
    pgConnStr      string
    mysqlConnStr   string
)
```

### Phase 2: Store Integration Tests

#### 2.1 Create `db/store_test.go` (multi-dialect)

```go
func TestStore_AllDialects(t *testing.T) {
    for _, env := range testutil.GetTestDialects(t) {
        t.Run(string(env.Dialect), func(t *testing.T) {
            defer env.Cleanup()

            // Run migrations
            migrate.Run(ctx, env.DB, env.Dialect)

            // Create store
            store, _ := db.New(env.DB, env.Dialect)

            // Test user CRUD
            t.Run("CreateUser", func(t *testing.T) { ... })
            t.Run("GetUser", func(t *testing.T) { ... })
            t.Run("UpdateUser", func(t *testing.T) { ... })
            t.Run("DeleteUser", func(t *testing.T) { ... })

            // Test session CRUD
            // Test account CRUD
            // Test verification CRUD
        })
    }
}
```

#### 2.2 Create plugin store tests

For each plugin with a db store:
- `auth/oauth/db/store_test.go`
- `auth/jwt/db/store_test.go`
- `auth/otp/db/store_test.go`
- `auth/webauthn/db/store_test.go`
- `auth/apikey/db/store_test.go`
- `auth/deviceauth/db/store_test.go`
- `auth/organization/db/store_test.go`

### Phase 3: E2E Tests Update

#### 3.1 Parameterize E2E tests

```go
// tests/e2e/main_test.go
func TestMain(m *testing.M) {
    // Start containers for enabled dialects
    if os.Getenv("TEST_POSTGRES") != "false" {
        pgContainer, pgConnStr = startPostgres()
    }
    if os.Getenv("TEST_MYSQL") == "true" {
        mysqlContainer, mysqlConnStr = startMySQL()
    }
    // SQLite doesn't need a container

    code := m.Run()

    // Cleanup
    if pgContainer != nil { pgContainer.Terminate(ctx) }
    if mysqlContainer != nil { mysqlContainer.Terminate(ctx) }

    os.Exit(code)
}

// Each test runs against all enabled dialects
func TestSignUp(t *testing.T) {
    for _, env := range getE2EDialects() {
        t.Run(string(env.Dialect), func(t *testing.T) {
            server := setupTestServer(t, env)
            defer server.Close()

            // ... existing test logic
        })
    }
}
```

### Phase 4: Migration Tests

#### 4.1 Update `migrate/migrate_test.go`

```go
func TestMigrate_AllDialects(t *testing.T) {
    for _, env := range testutil.GetTestDialects(t) {
        t.Run(string(env.Dialect), func(t *testing.T) {
            defer env.Cleanup()

            // Test core migrations
            err := migrate.Run(ctx, env.DB, env.Dialect)
            require.NoError(t, err)

            // Verify tables exist
            assertTableExists(t, env.DB, "users")
            assertTableExists(t, env.DB, "accounts")
            assertTableExists(t, env.DB, "sessions")
            assertTableExists(t, env.DB, "verifications")
        })
    }
}

func TestMigrate_WithPlugins_AllDialects(t *testing.T) {
    for _, env := range testutil.GetTestDialects(t) {
        t.Run(string(env.Dialect), func(t *testing.T) {
            defer env.Cleanup()

            // Test with all plugins
            err := migrate.Run(ctx, env.DB, env.Dialect,
                migrate.WithPlugins(
                    oauth.Migrations(),
                    jwt.Migrations(),
                    otp.Migrations(),
                    webauthn.Migrations(),
                    apikey.Migrations(),
                    deviceauth.Migrations(),
                    organization.Migrations(),
                ),
            )
            require.NoError(t, err)

            // Verify plugin tables exist
            assertTableExists(t, env.DB, "oauth_states")
            assertTableExists(t, env.DB, "jwt_keys")
            // ... etc
        })
    }
}
```

### Phase 5: CI/CD Integration

#### 5.1 GitHub Actions workflow

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:16-alpine
        env:
          POSTGRES_DB: testdb
          POSTGRES_USER: testuser
          POSTGRES_PASSWORD: testpass
        ports:
          - 5432:5432
      mysql:
        image: mysql:8
        env:
          MYSQL_DATABASE: testdb
          MYSQL_USER: testuser
          MYSQL_PASSWORD: testpass
          MYSQL_ROOT_PASSWORD: rootpass
        ports:
          - 3306:3306

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.22'

      - name: Run tests (all dialects)
        env:
          TEST_POSTGRES: true
          TEST_MYSQL: true
          TEST_SQLITE: true
          POSTGRES_URL: postgres://testuser:testpass@localhost:5432/testdb?sslmode=disable
          MYSQL_URL: testuser:testpass@tcp(localhost:3306)/testdb?parseTime=true
        run: go test -v ./...
```

## Test Categories

| Category | Files | Dialects | Method |
|----------|-------|----------|--------|
| Unit tests | `*_test.go` (non-integration) | None (mocks) | `go test ./...` |
| Store integration | `db/store_test.go`, `auth/*/db/store_test.go` | All three | testcontainers |
| Migration integration | `migrate/migrate_test.go` | All three | testcontainers |
| E2E integration | `tests/e2e/*_test.go` | All three | testcontainers |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TEST_POSTGRES` | `true` | Run PostgreSQL tests |
| `TEST_MYSQL` | `false` | Run MySQL tests |
| `TEST_SQLITE` | `true` | Run SQLite tests |
| `POSTGRES_URL` | - | PostgreSQL connection string |
| `MYSQL_URL` | - | MySQL connection string |

## Implementation Order

1. Create `tests/testutil/` package with dialect helpers
2. Add MySQL testcontainer support
3. Create core store integration tests (`db/store_test.go`)
4. Update migration tests to use all dialects
5. Create plugin store integration tests (one per plugin)
6. Update E2E tests to run against all dialects
7. Update CI workflow

---

## Implemented

### Migration API

The `migrate` package provides a simple Go API for running migrations:

```go
import (
    "github.com/webdeveloperben/BetterAuthGoServer/migrate"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"
)

// Run migrations before creating Auth
err := migrate.Run(ctx, db, migrate.DialectPostgres,
    migrate.WithPlugins(
        oauth.Migrations(),
        jwt.Migrations(),
    ),
)
```

### Features

- **Standalone API**: `migrate.Run()` runs before Auth creation (no chicken-egg problem)
- **golang-migrate**: Uses battle-tested golang-migrate library under the hood
- **Embedded migrations**: All SQL files embedded via `embed.FS` - no file copying needed
- **Separate tracking tables**: Each source has its own `schema_migrations_<name>` table
- **Topological sorting**: Plugins declare dependencies, sorted automatically
- **Multi-dialect support**: PostgreSQL, SQLite, MySQL
- **Dry-run mode**: `migrate.WithDryRun(true)` to preview changes

### Plugin Migrations

Each plugin exposes a `Migrations()` function:
- `oauth.Migrations()`
- `otp.Migrations()`
- `jwt.Migrations()`
- `webauthn.Migrations()`
- `apikey.Migrations()`
- `deviceauth.Migrations()`
- `organization.Migrations()`

### Files Created

- `migrate/migrate.go` - Core runner
- `migrate/source.go` - Source interface
- `migrate/options.go` - Functional options
- `migrate/errors.go` - Error types
- `migrate/dialect.go` - Dialect re-exports
- `migrate/topo.go` - Topological sort
- `db/migrations/embed.go` - Core migrations embed
- `auth/*/migrations.go` - Plugin migration sources
- `auth/*/db/migrations/embed.go` - Plugin migration embeds
