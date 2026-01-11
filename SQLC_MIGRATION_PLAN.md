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

### Phase 1: Update plugin.Context

**Goal:** Change plugin.Context to provide raw DB access instead of centralized store.

#### Tasks

- [ ] Update `auth/plugin/context.go`:
  - [ ] Add `DB *sql.DB` field
  - [ ] Add `Dialect string` field
  - [ ] Add `CoreStore` interface for core entity access
  - [ ] Deprecate `Store db.PluginStore` field
- [ ] Update `auth/auth.go` to populate new context fields
- [ ] Ensure backwards compatibility during migration

### Phase 2: Migrate OAuth Plugin (Prototype)

**Goal:** Convert oauth to plugin-owned storage as the template for other plugins.

#### Tasks

- [ ] Create `auth/oauth/db/` directory structure
- [ ] Create `auth/oauth/db/sqlc.yaml`
- [ ] Move schema files to `auth/oauth/db/schema/{sqlite,postgres}/`
- [ ] Move query files to `auth/oauth/db/queries/{sqlite,postgres}/`
- [ ] Run `sqlc generate` in `auth/oauth/db/`
- [ ] Create `auth/oauth/store.go` using generated code
- [ ] Update `auth/oauth/plugin.go` to use new store
- [ ] Delete `auth/oauth/store_adapter.go` (no longer needed)
- [ ] Delete `auth/oauth/models.go` (bun models no longer needed)
- [ ] Delete `auth/oauth/account_store.go` (bun models no longer needed)
- [ ] Test oauth plugin works independently
- [ ] Remove oauth queries/schema from central `db/`

### Phase 3: Migrate Remaining Plugins

**Goal:** Apply the same pattern to all other plugins.

#### Tasks

For each plugin (otp, jwt, webauthn, apikey, deviceauth, organization):

- [ ] Create `auth/{plugin}/db/` directory structure
- [ ] Create `auth/{plugin}/db/sqlc.yaml`
- [ ] Move schema and query files
- [ ] Run `sqlc generate`
- [ ] Create `auth/{plugin}/store.go`
- [ ] Update `auth/{plugin}/plugin.go`
- [ ] Delete old `store_adapter.go` and bun model files
- [ ] Remove from central `db/`
- [ ] Test plugin independently

### Phase 4: Clean Up Central db/

**Goal:** Central db/ only contains core entities.

#### Tasks

- [ ] Remove plugin-specific interfaces from `db/plugin_store.go`
- [ ] Remove plugin-specific methods from `db/pg_adapter.go`
- [ ] Remove plugin-specific methods from `db/sqlite_adapter.go`
- [ ] Remove plugin schema/query files from `db/schema/` and `db/queries/`
- [ ] Keep only: users, sessions, accounts, verifications
- [ ] Update `db/sqlc.yaml` to only generate core stores
- [ ] Run `sqlc generate`
- [ ] Rename `PluginStore` to `CoreStore`

### Phase 5: Atlas HCL Setup

**Goal:** Replace bun auto-migrations with Atlas HCL.

#### Tasks

- [ ] Create `atlas.hcl` in project root (for core tables)
- [ ] Create `auth/{plugin}/db/atlas.hcl` for each plugin
- [ ] Convert SQL schemas to HCL format
- [ ] Test `atlas schema apply` for each
- [ ] Remove `Migrations()` method from all plugins
- [ ] Delete remaining bun model files

### Phase 6: Update Application Code

**Goal:** Update main.go and examples.

#### Tasks

- [ ] Update `main.go`:
  - [ ] Replace bun.DB with *sql.DB
  - [ ] Create core db.Store
  - [ ] Pass DB and dialect to auth.New()
- [ ] Update all examples
- [ ] Update `cmd/migrate/main.go` to use Atlas
- [ ] Update tests

### Phase 7: Final Cleanup

**Goal:** Remove bun dependency entirely.

#### Tasks

- [ ] Delete `auth/store/` directory
- [ ] Remove bun from `go.mod`
- [ ] Verify build and tests pass
- [ ] Update documentation

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
