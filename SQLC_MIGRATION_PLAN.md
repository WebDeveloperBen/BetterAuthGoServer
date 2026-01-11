# SQLC Migration Plan

## Overview

This codebase is migrating from **bun ORM** to **sqlc** with **Atlas HCL** for schema management. The goal is to completely remove the bun dependency while maintaining the **plugin drop-in/drop-out architecture**.

**Target Stack:**
- **sqlc** - Type-safe SQL code generation
- **Atlas** - Schema management with HCL (declarative migrations)
- **database/sql** - Standard library for database access

---

## Architecture Decision: Hybrid Approach

### The Problem

The initial sqlc migration centralized all storage in `db/`:
- Plugins lost ownership of their persistence layer
- Adding/removing a plugin required modifying the central `db/` package
- Plugins were no longer self-contained

### The Solution: Hybrid Architecture

**Core entities** (shared across all plugins) stay in `db/`:
- `users` - User records
- `sessions` - Authentication sessions
- `accounts` - Generic account linking
- `verifications` - Email verification tokens

**Plugin-specific entities** are owned by each plugin:
- Each plugin has its own `db/` subdirectory
- Each plugin has its own `sqlc.yaml`
- Each plugin generates its own store code
- Plugins can be dropped in/out independently

---

## Target File Structure

### Core (`db/`)

```
db/
├── atlas.hcl                     # Atlas config for core tables
├── sqlc.yaml                     # sqlc config for core only
├── schema/
│   ├── sqlite/
│   │   ├── 001_users.sql
│   │   ├── 002_sessions.sql
│   │   ├── 003_accounts.sql
│   │   └── 004_verifications.sql
│   └── postgres/
│       └── ... (same structure)
├── queries/
│   ├── sqlite/
│   │   ├── users.sql
│   │   ├── sessions.sql
│   │   ├── accounts.sql
│   │   └── verifications.sql
│   └── postgres/
│       └── ...
├── pgstore/                      # sqlc generated (core only)
├── sqlitestore/                  # sqlc generated (core only)
├── store.go                      # Core Store struct
├── pg_adapter.go                 # PostgreSQL adapter (core only)
└── sqlite_adapter.go             # SQLite adapter (core only)
```

### Plugin Example (`auth/oauth/`)

```
auth/oauth/
├── db/
│   ├── sqlc.yaml                 # Plugin's own sqlc config
│   ├── schema/
│   │   ├── sqlite/oauth.sql      # Plugin's schema
│   │   └── postgres/oauth.sql
│   ├── queries/
│   │   ├── sqlite/oauth.sql      # Plugin's queries
│   │   └── postgres/oauth.sql
│   ├── pgstore/                  # sqlc generated (plugin-specific)
│   │   ├── db.go
│   │   ├── models.go
│   │   └── oauth.sql.go
│   └── sqlitestore/              # sqlc generated (plugin-specific)
│       ├── db.go
│       ├── models.go
│       └── oauth.sql.go
├── store.go                      # Plugin's store implementation
├── service.go                    # Business logic
├── plugin.go                     # Plugin initialization
├── handlers.go                   # HTTP handlers
└── ... (other plugin files)
```

---

## Plugin Store Pattern

### sqlc.yaml (per plugin)

```yaml
# auth/oauth/db/sqlc.yaml
version: "2"
sql:
  - engine: "postgresql"
    queries: "queries/postgres/"
    schema: "schema/postgres/"
    gen:
      go:
        package: "pgstore"
        out: "pgstore"
        emit_json_tags: true
        emit_empty_slices: true
  - engine: "sqlite"
    queries: "queries/sqlite/"
    schema: "schema/sqlite/"
    gen:
      go:
        package: "sqlitestore"
        out: "sqlitestore"
        emit_json_tags: true
        emit_empty_slices: true
```

### Store Implementation (per plugin)

```go
// auth/oauth/store.go
package oauth

import (
    "context"
    "database/sql"
    "time"

    "github.com/yourproject/auth/oauth/db/pgstore"
    "github.com/yourproject/auth/oauth/db/sqlitestore"
)

// Dialect constants
const (
    DialectPostgres = "postgres"
    DialectSQLite   = "sqlite"
)

// Store handles OAuth persistence.
// The plugin owns this implementation.
type Store struct {
    dialect string
    pgQ     *pgstore.Queries
    sqliteQ *sqlitestore.Queries
}

// NewStore creates a new OAuth store.
func NewStore(db *sql.DB, dialect string) *Store {
    s := &Store{dialect: dialect}
    if dialect == DialectPostgres {
        s.pgQ = pgstore.New(db)
    } else {
        s.sqliteQ = sqlitestore.New(db)
    }
    return s
}

// CreateOAuthState creates a new OAuth state record.
func (s *Store) CreateOAuthState(ctx context.Context, state *State) error {
    if s.dialect == DialectPostgres {
        return s.pgQ.CreateOAuthState(ctx, pgstore.CreateOAuthStateParams{
            State:      state.State,
            Provider:   state.Provider,
            Verifier:   toNullString(state.Verifier),
            RedirectTo: toNullString(state.RedirectTo),
            CreatedAt:  state.CreatedAt,
            ExpiresAt:  state.ExpiresAt,
        })
    }
    return s.sqliteQ.CreateOAuthState(ctx, sqlitestore.CreateOAuthStateParams{
        State:      state.State,
        Provider:   state.Provider,
        Verifier:   toNullString(state.Verifier),
        RedirectTo: toNullString(state.RedirectTo),
        CreatedAt:  state.CreatedAt.Format(time.RFC3339),
        ExpiresAt:  state.ExpiresAt.Format(time.RFC3339),
    })
}

// ... other methods
```

### Plugin Initialization

```go
// auth/oauth/plugin.go
func (p *Plugin) Init(ctx plugin.Context) error {
    // Plugin creates its own store from raw DB connection
    if ctx.DB == nil {
        p.logger.Warn("oauth plugin: no database available, plugin disabled")
        return nil
    }

    p.store = NewStore(ctx.DB, ctx.Dialect)
    p.service = NewService(p.store, p.config)

    return nil
}
```

### Updated plugin.Context

```go
// auth/plugin/context.go
type Context struct {
    // Database access
    DB      *sql.DB  // Raw database connection
    Dialect string   // "postgres" or "sqlite"

    // Core store (for plugins that need user/session access)
    CoreStore CoreStore

    // Other context fields...
    Auth      interface{}
    Logger    *slog.Logger
    BaseURL   string
    Secret    string
    Hasher    *token.Hasher
    Encryptor *token.Encryptor
}

// CoreStore provides access to core entities (users, sessions, accounts)
type CoreStore interface {
    // User operations
    GetUserByID(ctx context.Context, id string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)
    CreateUser(ctx context.Context, user *User) error
    UpdateUser(ctx context.Context, user *User) error

    // Session operations
    CreateSession(ctx context.Context, session *Session) error
    GetSessionByToken(ctx context.Context, tokenHash string) (*Session, error)
    DeleteSession(ctx context.Context, id string) error

    // Account operations
    CreateAccount(ctx context.Context, account *Account) error
    GetAccountsByUserID(ctx context.Context, userID string) ([]*Account, error)
}
```

---

## What Each Plugin Owns

| Plugin | Tables | Notes |
|--------|--------|-------|
| `auth/oauth` | `oauth_states`, `oauth_accounts` | OAuth flow state, linked accounts |
| `auth/otp` | `otp_tokens` | One-time password tokens |
| `auth/jwt` | `jwt_keys`, `jwt_revoked_tokens` | JWT signing keys, revocation |
| `auth/webauthn` | `webauthn_credentials`, `webauthn_sessions` | Passkey storage |
| `auth/apikey` | `api_keys` | API key storage |
| `auth/deviceauth` | `device_codes` | Device authorization flow |
| `auth/organization` | `organizations`, `members`, `invitations`, `teams`, `team_members` | Multi-tenancy |

## What Core Owns

| Table | Purpose |
|-------|---------|
| `users` | User identity |
| `sessions` | Auth sessions |
| `accounts` | Generic provider account linking |
| `verifications` | Email verification tokens |

---

## Migration Phases

### Phase 1: Update plugin.Context ✅

**Goal:** Change plugin.Context to provide raw DB access instead of centralized store.

**Status:** Complete. plugin.Context now has RawDB and Dialect fields.

#### Tasks

- [x] Update `auth/plugin/context.go`:
  - [x] Add `RawDB db.DBTX` field (raw database connection)
  - [x] Add `Dialect db.Dialect` field
  - [x] Keep `Store` for backwards compatibility
- [x] Update `auth/auth.go` to populate new context fields
- [x] Plugins now use `ctx.RawDB` and `ctx.Dialect` to create their own stores

### Phase 2: Migrate OAuth Plugin (Prototype) ✅

**Goal:** Convert oauth to plugin-owned storage as the template for other plugins.

**Status:** Complete. OAuth plugin now uses its own sqlc-generated store.

#### Tasks

- [x] Create `auth/oauth/db/` directory structure
- [x] Create `auth/oauth/db/sqlc.yaml`
- [x] Move schema files to `auth/oauth/db/schema/{sqlite,postgres}/`
- [x] Move query files to `auth/oauth/db/queries/{sqlite,postgres}/`
- [x] Run `sqlc generate` in `auth/oauth/db/`
- [x] Create `auth/oauth/db/store.go` using generated code
- [x] Update `auth/oauth/plugin.go` to use new store via `ctx.RawDB`
- [x] Update `auth/oauth/store_adapter.go` to wrap plugin's own db.Store
- [x] Delete `auth/oauth/models.go` (bun models removed)
- [x] Delete `auth/oauth/account_store.go` (bun models removed)
- [x] Move `OAuthAccount` domain model to `core.go` (no bun dependency)
- [x] Remove `Migrations()` method from plugin.go
- [x] Test oauth plugin works independently
- [ ] Remove oauth queries/schema from central `db/` (deferred to Phase 4)

### Phase 3: Migrate Remaining Plugins

**Goal:** Apply the same pattern to all other plugins.

#### OTP Plugin ✅

- [x] Create `auth/otp/db/` directory structure
- [x] Create `auth/otp/db/sqlc.yaml`
- [x] Create schema and query files
- [x] Run `sqlc generate`
- [x] Create `auth/otp/db/store.go`
- [x] Update `auth/otp/plugin.go` to use `ctx.RawDB`
- [x] Update `auth/otp/store_adapter.go` to wrap plugin's own db.Store
- [x] Move domain types to `service.go` (remove bun)
- [x] Delete `auth/otp/models.go`
- [x] Remove `Migrations()` method
- [x] Test plugin works (all e2e tests pass)

#### JWT Plugin ✅

- [x] Create `auth/jwt/db/` directory structure
- [x] Create `auth/jwt/db/sqlc.yaml`
- [x] Create schema and query files (postgres and sqlite)
- [x] Run `sqlc generate`
- [x] Create `auth/jwt/db/store.go` with domain types (JWTKey, RevokedToken)
- [x] Update `auth/jwt/keymanager_adapter.go` to use plugin's own `jwtdb.JWTKey`
- [x] Update `auth/jwt/store_adapter.go` to wrap plugin's own `jwtdb.Store`
- [x] Update `auth/jwt/plugin.go` to use `ctx.RawDB`
- [x] Remove bun tags from `auth/jwt/keys.go` (JWK struct)
- [x] Remove bun model from `auth/jwt/store.go` (RevokedToken)
- [x] Remove `MigrationsProvider` interface and `Migrations()` method
- [x] Update tests (remove `TestRevokedToken_TableName`)
- [x] Test plugin works (all unit tests and e2e tests pass)

#### WebAuthn Plugin ✅

- [x] Create `auth/webauthn/db/` directory structure
- [x] Create `auth/webauthn/db/sqlc.yaml`
- [x] Create schema and query files (postgres and sqlite)
- [x] Run `sqlc generate`
- [x] Create `auth/webauthn/db/store.go` with domain types (Credential, Session)
- [x] Update `auth/webauthn/store_adapter.go` to use plugin's own `webauthndb.Store`
- [x] Update `auth/webauthn/plugin.go` to use `ctx.RawDB`
- [x] Remove bun tags from `auth/webauthn/models.go`
- [x] Remove `MigrationsProvider` interface and `Migrations()` method
- [x] Update tests (remove `TestPlugin_Migrations`)
- [x] Test plugin works (all unit tests and e2e tests pass)

#### APIKey Plugin ✅

- [x] Create `auth/apikey/db/` directory structure
- [x] Create `auth/apikey/db/sqlc.yaml`
- [x] Create schema and query files (postgres and sqlite)
- [x] Run `sqlc generate`
- [x] Create `auth/apikey/db/store.go` with domain type (APIKey)
- [x] Update `auth/apikey/store_adapter.go` to use plugin's own `apikeydb.Store`
- [x] Update `auth/apikey/plugin.go` to use `ctx.RawDB`
- [x] Remove bun tags from `auth/apikey/models.go`
- [x] Remove `MigrationsProvider` interface and `Migrations()` method
- [x] Test plugin works (all unit tests and e2e tests pass)

#### DeviceAuth Plugin ✅

- [x] Create `auth/deviceauth/db/` directory structure
- [x] Create `auth/deviceauth/db/sqlc.yaml`
- [x] Create schema and query files (postgres and sqlite)
- [x] Run `sqlc generate`
- [x] Create `auth/deviceauth/db/store.go` with domain type (DeviceCode)
- [x] Update `auth/deviceauth/store_adapter.go` to use plugin's own `deviceauthdb.Store`
- [x] Update `auth/deviceauth/plugin.go` to use `ctx.RawDB`
- [x] Test plugin works (all unit tests and e2e tests pass)

#### Organization Plugin ✅

- [x] Create `auth/organization/db/` directory structure
- [x] Create `auth/organization/db/sqlc.yaml`
- [x] Create schema and query files (postgres and sqlite - 5 tables)
- [x] Run `sqlc generate`
- [x] Create `auth/organization/db/store.go` with domain types (Organization, Member, Invitation, Team, TeamMember)
- [x] Update `auth/organization/store_adapter.go` to use plugin's own `orgdb.Store`
- [x] Update `auth/organization/service.go` to use plugin's own `orgdb.Store`
- [x] Update `auth/organization/plugin.go` to use `ctx.RawDB`
- [x] Remove `MigrationsProvider` interface and `Migrations()` method
- [x] Update tests (remove `TestPlugin_Migrations`, update test helper)
- [x] Test plugin works (all unit tests pass)

### Phase 4: Clean Up Central db/ ✅

**Goal:** Central db/ only contains core entities.

**Status:** Complete. Central db/ now only contains core entities (users, sessions, accounts, verifications).

#### Tasks

- [x] Remove plugin-specific interfaces from `db/plugin_store.go`
- [x] Remove plugin-specific methods from `db/pg_adapter.go`
- [x] Remove plugin-specific methods from `db/sqlite_adapter.go`
- [x] Remove plugin schema/query files from `db/schema/` and `db/queries/`
- [x] Keep only: users, sessions, accounts, verifications
- [x] Update `db/sqlc.yaml` to only generate core stores
- [x] Run `sqlc generate`
- [x] Remove plugin types from `db/querier.go` and `db/convert.go`
- [x] Remove plugin methods from `db/store.go`
- [x] All tests pass

### ~~Phase 5: Atlas HCL Setup~~ - SKIPPED

**Decision:** Skip Atlas. Plain SQL schemas work fine and provide more flexibility for SDK consumers.

**Migration Philosophy:**
- **No auto-migrations** - SDK never modifies database schema automatically
- **Schema as contract** - SDK expects tables/columns to exist, runs queries against them
- **Migrations as optional** - Provide migration SQL for version transitions

**For SDK Consumers:**
```
Option A: "I'll manage my own schema"
- Copy schema from SDK's schema/ directories or documentation
- Integrate into your own migration system (goose, golang-migrate, etc.)
- SDK works if schema matches expected structure

Option B: "Give me the migrations"
- Use SDK-provided migration files from migrations/ directories
- Run with your preferred migration tool
- Get easy version upgrades when SDK schema changes
```

**File Structure:**
```
db/
├── schema/           # Reference schemas (current table definitions)
│   ├── postgres/
│   └── sqlite/
└── migrations/       # golang-migrate format migrations
    ├── postgres/
    │   ├── 000001_initial_schema.up.sql
    │   └── 000001_initial_schema.down.sql
    └── sqlite/
        ├── 000001_initial_schema.up.sql
        └── 000001_initial_schema.down.sql

auth/{plugin}/db/
├── schema/           # Plugin's reference schema
└── migrations/       # Plugin's migrations (golang-migrate format)
    ├── postgres/
    │   ├── 000001_{plugin}_tables.up.sql
    │   └── 000001_{plugin}_tables.down.sql
    └── sqlite/
        ├── 000001_{plugin}_tables.up.sql
        └── 000001_{plugin}_tables.down.sql
```

**Migrations Created:** ✅
- Core: `db/migrations/{postgres,sqlite}/000001_initial_schema.{up,down}.sql`
- OAuth: `auth/oauth/db/migrations/{postgres,sqlite}/000001_oauth_tables.{up,down}.sql`
- OTP: `auth/otp/db/migrations/{postgres,sqlite}/000001_otp_tables.{up,down}.sql`
- JWT: `auth/jwt/db/migrations/{postgres,sqlite}/000001_jwt_tables.{up,down}.sql`
- WebAuthn: `auth/webauthn/db/migrations/{postgres,sqlite}/000001_webauthn_tables.{up,down}.sql`
- APIKey: `auth/apikey/db/migrations/{postgres,sqlite}/000001_apikey_tables.{up,down}.sql`
- DeviceAuth: `auth/deviceauth/db/migrations/{postgres,sqlite}/000001_deviceauth_tables.{up,down}.sql`
- Organization: `auth/organization/db/migrations/{postgres,sqlite}/000001_organization_tables.{up,down}.sql`

### Phase 5: Update Application Code ✅

**Goal:** Update main.go and examples to use sqlc-based db.Store.

**Status:** Complete. All application code now uses database/sql with db.Store.

#### Tasks

- [x] Update `main.go`:
  - [x] Replace bun.DB with *sql.DB
  - [x] Create core db.Store
  - [x] Pass DB and dialect to auth.New()
- [x] Update all examples (basic, minimal, with-oauth, redis-ratelimit, azure-full)
- [x] Remove `cmd/migrate/main.go` (bun-based migration tool no longer needed)
- [x] Update `cmd/sqlc-example/main.go` to use database/sql pattern
- [x] Tests verified passing

### Phase 6: Final Cleanup ✅

**Goal:** Remove bun dependency entirely.

**Status:** Complete. Bun has been completely removed from the project.

#### Tasks

- [x] Delete `auth/store/` directory
- [x] Remove bun from `go.mod`
- [x] Run `go mod tidy`
- [x] Verify build passes (`go build ./...`)
- [x] Verify all tests pass (`go test ./...`)
- [ ] Update documentation (README.md, plugin-development.md)

---

## Testing

### Running Tests During Migration

As you work through the migration phases, run tests frequently to ensure everything is working. The e2e tests have been updated to use the sqlc-based `db.Store`.

```bash
# Run all unit tests (fast)
go test ./... -short

# Run e2e tests (requires Docker for PostgreSQL testcontainers)
go test -v ./tests/e2e/... -timeout 300s

# Run specific e2e test
go test -v ./tests/e2e/... -run "TestSignUpFlow" -timeout 120s

# Build all packages to check for compilation errors
go build ./...
```

### Test Environment

The e2e tests use **testcontainers** to spin up a PostgreSQL container:
- Tests share a single container to improve performance
- Each test truncates tables for isolation
- The container is automatically cleaned up after tests

### Key Test Files

| File | Purpose |
|------|---------|
| `tests/e2e/e2e.go` | Test setup, shared container, migrations |
| `tests/e2e/main_test.go` | TestMain, container lifecycle |
| `tests/e2e/*_test.go` | Individual test files |

### Database Schema for Tests

The `runMigrations()` function in `tests/e2e/e2e.go` contains all PostgreSQL schema definitions. When adding new columns or tables:

1. Update the migrations in `tests/e2e/e2e.go`
2. Ensure column names match sqlc query files in `db/queries/postgres/*.sql`
3. Run e2e tests to verify

### Expected Test Results

All 14 e2e tests should pass:
- `TestConcurrentSignUps`
- `TestConcurrentSignIns`
- `TestEmailVerificationFlow`
- `TestPasswordResetFlow`
- `TestPasswordChangeFlow`
- `TestRateLimitingApplied`
- `TestMaxSessionsPerUser`
- `TestSecurityHeaders`
- `TestConcurrentRateLimiting`
- `TestSessionFlow`
- `TestSignInFlow`
- `TestSignOutFlow`
- `TestSignUpFlow`

### Troubleshooting

**"column X does not exist"**: The test migrations don't match the sqlc queries. Compare:
- `tests/e2e/e2e.go` (CREATE TABLE statements)
- `db/queries/postgres/*.sql` (column names in queries)

**"no database available, plugin disabled"**: The store passed to `auth.New()` doesn't implement `plugin.PluginStoreProvider`. Use `db.Store` which implements both interfaces.

**"pq: relation X does not exist"**: Missing table in migrations. Add the CREATE TABLE statement to `runMigrations()`.

---

## Commands Reference

```bash
# Generate sqlc for a specific plugin
cd auth/oauth/db && sqlc generate

# Generate sqlc for core
cd db && sqlc generate

# Generate all (script)
for dir in db auth/*/db; do
  if [ -f "$dir/sqlc.yaml" ]; then
    echo "Generating $dir..."
    (cd "$dir" && sqlc generate)
  fi
done

# Atlas commands
atlas schema apply -u "sqlite://auth.db" --to file://db/schema/atlas
atlas schema apply -u "sqlite://auth.db" --to file://auth/oauth/db/schema/atlas

# Go commands
go build ./...
go test ./...
```

---

## Benefits of Hybrid Approach

1. **Plugins are self-contained** - Can be dropped in/out independently
2. **Clear ownership** - Each plugin owns its schema, queries, and store
3. **Independent versioning** - Plugins can evolve their schemas independently
4. **Easier extraction** - A plugin could be extracted to its own repo
5. **Simpler core** - Central db/ only handles shared entities
6. **No interface explosion** - No need for massive PluginStore interface

## Tradeoffs

1. **Multiple sqlc.yaml files** - Each plugin has its own config
2. **More directories** - Each plugin has a db/ subdirectory
3. **Generate script needed** - Need to run sqlc generate per plugin
4. **Some code duplication** - Dialect switching logic in each store

---

## Notes

- PostgreSQL uses `$1, $2, $3` placeholders; SQLite uses `?`
- PostgreSQL uses `TIMESTAMPTZ`; SQLite uses `TEXT` for timestamps
- Each plugin handles its own time conversion in store.go
- Core entities are accessed via `ctx.CoreStore` interface
- Raw DB access via `ctx.DB` and `ctx.Dialect`
