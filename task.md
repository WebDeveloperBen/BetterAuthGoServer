# TODO

- [x] Define migration UX for SDK consumers (CLI and/or library API, default migration dir, env var support)
- [x] Decide migration packaging strategy (ship migrations inside SDK, embed via `embed.FS`, expose versioned paths)
- [x] Implement migration runner for consumers (up/down/step/status, locking, dry-run, timeout)
- [ ] Add stable migration versioning and compatibility notes in docs
- [ ] Update tests to use the migration runner as the single source of truth
- [ ] Remove hardcoded SQL fixtures once tests use migrations
- [ ] Document upgrade flow for SDK users (examples for local dev and CI)

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
