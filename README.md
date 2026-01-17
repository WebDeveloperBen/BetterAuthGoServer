# BetterAuth Go Server

A complete, embeddable authentication library for Go applications. Handles email/password authentication, OAuth2 providers, session management, and email verification flows with security best practices built-in.

## Features

- **Email/Password Authentication** - Sign up, sign in, password reset, password change
- **OAuth2 Providers** - Google, GitHub, Discord (extensible for more)
- **Session Management** - Cookie-based sessions with optional Bearer token support
- **Email Verification** - Token-based email verification flow
- **Plugin Architecture** - Extend with JWT, OAuth, Admin, and custom plugins
- **Security Built-in**
  - Argon2id password hashing
  - HMAC-SHA256 token hashing
  - AES-256-GCM OAuth token encryption
  - CSRF protection (plugin)
  - Rate limiting (plugin)
  - Secure cookie settings (HttpOnly, Secure, SameSite)
  - No user enumeration on login/reset endpoints
- **Extensible Hooks** - React to auth events (user created, sign in, password changed, etc.)
- **Database Agnostic** - Ships with PostgreSQL, MySQL, and SQLite support
- **Schema as Contract** - You control your database schema; SDK provides reference SQL files

## Database Setup

The SDK provides an embedded migration system powered by golang-migrate. Migrations are embedded in the SDK and run programmatically.

### Running Migrations

```go
import (
    "github.com/webdeveloperben/BetterAuthGoServer/migrate"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"
)

func main() {
    db, _ := sql.Open("postgres", dsn)

    // Run migrations before creating Auth
    err := migrate.Run(ctx, db, migrate.DialectPostgres,
        migrate.WithPlugins(
            oauth.Migrations(),
            jwt.Migrations(),
        ),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Now create Auth
    // ...
}
```

### Migration Features

- **Standalone API**: `migrate.Run()` runs before Auth creation
- **Embedded migrations**: All SQL files embedded via `embed.FS` - no file copying needed
- **Separate tracking tables**: Each source has its own `schema_migrations_<name>` table
- **Topological sorting**: Plugins declare dependencies, sorted automatically
- **Multi-dialect support**: PostgreSQL, SQLite, MySQL
- **Dry-run mode**: `migrate.WithDryRun(true)` to preview changes

### Manual Schema Setup

Alternatively, you can manage your own schema. See [SCHEMA.md](./SCHEMA.md) for:
- Core and plugin table schemas
- Adding custom columns
- PostgreSQL vs MySQL vs SQLite differences

## Installation

```bash
go get github.com/webdeveloperben/BetterAuthGoServer
```

## Quick Start

```go
package main

import (
    "context"
    "database/sql"
    "log"
    "net/http"

    _ "github.com/lib/pq"           // PostgreSQL driver
    _ "github.com/go-sql-driver/mysql" // MySQL driver
    _ "github.com/mattn/go-sqlite3" // SQLite driver

    "github.com/webdeveloperben/BetterAuthGoServer/auth"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/config"
    "github.com/webdeveloperben/BetterAuthGoServer/db"
    "github.com/webdeveloperben/BetterAuthGoServer/migrate"
)

func main() {
    ctx := context.Background()

    // 1. Connect to database (PostgreSQL, MySQL, or SQLite)
    sqlDB, err := sql.Open("postgres", "postgres://user:pass@localhost:5432/authdb?sslmode=disable")
    // Or MySQL: sql.Open("mysql", "user:pass@tcp(localhost:3306)/authdb?parseTime=true")
    // Or SQLite: sql.Open("sqlite3", "file:auth.db?_foreign_keys=on")
    if err != nil {
        log.Fatal(err)
    }
    defer sqlDB.Close()

    // 2. Run migrations (embedded in SDK)
    if err := migrate.Run(ctx, sqlDB, migrate.DialectPostgres); err != nil {
        log.Fatal(err)
    }

    // 3. Create sqlc-based store
    dbStore, err := db.New(sqlDB, db.DialectPostgres)
    if err != nil {
        log.Fatal(err)
    }

    // 4. Create auth instance with config options
    authService, err := auth.New(dbStore,
        config.WithSecret("your-secret-key-minimum-32-characters!"),
        config.WithBaseURL("http://localhost:8080"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer authService.Close()

    // 5. Mount auth handler
    mux := http.NewServeMux()
    mux.Handle("/auth/", http.StripPrefix("/auth", authService.Handler()))

    // 6. Protect your routes
    mux.Handle("GET /api/profile", authService.AuthMiddleware()(profileHandler()))

    log.Println("Server starting on :8080")
    http.ListenAndServe(":8080", mux)
}

func profileHandler() http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session := auth.SessionFromContext(r.Context())
        // session.UserID contains the authenticated user's ID
        w.Write([]byte("Hello, " + session.UserID))
    })
}
```

## Configuration

Use functional options from the `config` package to configure the auth instance:

```go
import (
    "github.com/webdeveloperben/BetterAuthGoServer/auth"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/config"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
)

authService, err := auth.New(store,
    // Required
    config.WithSecret("your-secret-key-minimum-32-characters!"),
    config.WithBaseURL("http://localhost:8080"),

    // Session settings
    config.WithSessionDuration(7 * 24 * time.Hour),  // Default: 7 days
    config.WithSessionCookie("session"),              // Default: "session"
    config.WithSessionCookieSameSite(http.SameSiteLaxMode),

    // Password policy
    config.WithPasswordPolicy(8, 128),                // Min/max length (default: 8, 128)
    config.WithPasswordComplexity(true),              // Require upper, lower, digit, special

    // Email verification
    config.WithEmailVerification(true, 24*time.Hour), // Require verification, token expiry

    // Password reset
    config.WithPasswordResetExpiry(1 * time.Hour),    // Default: 1 hour

    // Auto sign-in after sign-up
    config.WithAutoSignIn(true),                      // Default: true

    // Security (enabled by default via plugins)
    config.WithCSRF(true),                            // Default: true
    config.WithRateLimit(true, time.Minute, 100),     // Enabled, window, max requests
    config.WithAuthRateLimit(10),                     // Stricter limit for auth endpoints
    config.WithTrustedOrigins("http://localhost:3000"),
    config.WithTrustedProxies("127.0.0.1"),
    config.WithEmitRawTokensInEvents(false),

    // Cleanup
    config.WithSessionCleanupInterval(1 * time.Hour), // Auto-cleanup expired sessions

    // Logging
    config.WithLogger(slog.Default()),

    // Hooks (see Hooks section)
    config.WithHooks(hooks.Hooks{...}),

    // Disable default plugins for minimal setup
    // config.WithoutDefaults(),
)
```

## Plugin Architecture

BetterAuth uses a plugin system for extensibility. Default plugins (CSRF, rate limiting) are enabled automatically unless you use `config.WithoutDefaults()`.

### Adding Plugins

Plugins use a builder pattern with method chaining. Register plugins with `Use()` and check for errors with `Err()`:

```go
import (
    "github.com/webdeveloperben/BetterAuthGoServer/auth"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/config"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/providers"
)

// Create auth with defaults (includes CSRF + rate limiting)
authService, _ := auth.New(store,
    config.WithSecret(secret),
    config.WithBaseURL(baseURL),
)

oauthPlugin, err := oauth.NewPlugin(
    providers.NewGoogle(clientID, clientSecret, callbackURL),
    providers.NewGitHub(clientID, clientSecret, callbackURL),
)
if err != nil {
    log.Fatal("Failed to create OAuth plugin:", err)
}

// Register plugins
authService.
    Use(jwt.NewPlugin(jwt.WithIssuer("myapp"))).
    Use(oauthPlugin)

// Check for any plugin registration errors
if err := authService.Err(); err != nil {
    log.Fatal("Failed to register plugins:", err)
}
```

You can also register multiple plugins in a single `Use()` call:

```go
authService.Use(plugin1, plugin2, plugin3)
```

### Rate Limiting Plugin

```go
authService.Use(ratelimit.NewPlugin(
    ratelimit.WithLimit(100, time.Minute),
    ratelimit.WithFailClosed(true),
    ratelimit.WithBackendTimeout(2*time.Second),
))
```

### Minimal Setup (No Defaults)

```go
authService, _ := auth.New(store,
    config.WithSecret(secret),
    config.WithBaseURL(baseURL),
    config.WithoutDefaults(), // No CSRF, no rate limiting
)

// Add only what you need
authService.Use(myCustomPlugin)
if err := authService.Err(); err != nil {
    log.Fatal(err)
}
```

### Creating Custom Plugins

```go
import "github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"

// Using the plugin builder for simple plugins
myPlugin := plugin.NewPlugin(
    plugin.WithPluginName("my-plugin"),
    plugin.WithPluginInit(func(ctx plugin.Context) error {
        // Access auth internals via ctx
        return nil
    }),
    plugin.WithPluginRoutes([]plugin.Route{
        {Method: "GET", Path: "/my-endpoint", Handler: myHandler},
    }),
)

authService.Use(myPlugin)
```

## API Endpoints

All endpoints are mounted under your chosen path (e.g., `/auth`).

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/sign-up` | No | Create new user |
| POST | `/sign-in` | No | Sign in with email/password |
| POST | `/sign-out` | Yes | Sign out current session |
| GET | `/profile` | Yes | Get current user |
| POST | `/password/reset` | No | Request password reset |
| POST | `/password/confirm` | No | Confirm password reset |
| POST | `/password/change` | Yes | Change password |
| GET | `/email/verify` | No | Verify email with token |
| POST | `/email/verify/send` | Yes | Send verification email |
| GET | `/sessions` | Yes | List all sessions |
| DELETE | `/sessions` | Yes | Revoke all sessions |
| DELETE | `/sessions/{id}` | Yes | Revoke specific session |
| GET | `/oauth/providers` | No | List OAuth providers (with OAuth plugin) |
| GET | `/oauth/{provider}` | No | Begin OAuth flow |
| GET | `/oauth/{provider}/callback` | No | OAuth callback |

## Hooks

React to authentication events by providing hook functions:

```go
import (
    "github.com/webdeveloperben/BetterAuthGoServer/auth/config"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

config.WithHooks(hooks.Hooks{
    OnUserCreated: func(ctx context.Context, user *models.User) error {
        log.Printf("New user: %s", user.Email)
        return nil
    },

    OnSignIn: func(ctx context.Context, user *models.User, session *models.Session) error {
        log.Printf("User signed in: %s", user.Email)
        return nil
    },

    OnSignOut: func(ctx context.Context, user *models.User, session *models.Session) error {
        log.Printf("User signed out: %s", user.Email)
        return nil
    },

    OnPasswordChanged: func(ctx context.Context, user *models.User) error {
        // Send notification email
        return nil
    },

    OnPasswordResetRequested: func(ctx context.Context, user *models.User, token string) error {
        // Send password reset email with token
        resetURL := fmt.Sprintf("https://yourapp.com/reset?token=%s", token)
        return sendEmail(user.Email, "Password Reset", resetURL)
    },

    OnEmailVerificationRequested: func(ctx context.Context, user *models.User, token string) error {
        // Send verification email with token
        verifyURL := fmt.Sprintf("https://yourapp.com/verify?token=%s", token)
        return sendEmail(user.Email, "Verify Email", verifyURL)
    },

    OnEmailVerified: func(ctx context.Context, user *models.User) error {
        log.Printf("Email verified: %s", user.Email)
        return nil
    },

    OnOAuthAccountLinked: func(ctx context.Context, user *models.User, account *models.Account) error {
        log.Printf("OAuth account linked: %s -> %s", user.Email, account.Provider)
        return nil
    },
})
```

## OAuth Providers

### Setup

```go
import (
    "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth/providers"
)

// Register OAuth as a plugin after creating auth instance
oauthPlugin, err := oauth.NewPlugin(
    providers.NewGoogle(
        os.Getenv("GOOGLE_CLIENT_ID"),
        os.Getenv("GOOGLE_CLIENT_SECRET"),
        "http://localhost:8080/auth/oauth/google/callback",
    ),
    providers.NewGitHub(
        os.Getenv("GITHUB_CLIENT_ID"),
        os.Getenv("GITHUB_CLIENT_SECRET"),
        "http://localhost:8080/auth/oauth/github/callback",
    ),
    providers.NewDiscord(
        os.Getenv("DISCORD_CLIENT_ID"),
        os.Getenv("DISCORD_CLIENT_SECRET"),
        "http://localhost:8080/auth/oauth/discord/callback",
    ),
)
if err != nil {
    log.Fatal("Failed to create OAuth plugin:", err)
}
authService.Use(oauthPlugin)

// Check for errors after registering plugins
if err := authService.Err(); err != nil {
    log.Fatal(err)
}
```

### Frontend Integration

```javascript
// Redirect to OAuth provider
window.location.href = '/auth/oauth/google?redirect_to=/dashboard';

// Or open in popup
const popup = window.open('/auth/oauth/google', 'oauth', 'width=500,height=600');
```

## Middleware

### Require Authentication

```go
// Require auth - returns 401 if not authenticated
mux.Handle("GET /api/private", authService.AuthMiddleware()(handler))

// Inside handler, get the session
session := auth.SessionFromContext(r.Context())
userID := session.UserID
```

### Optional Authentication

```go
// Load session if present, but don't require it
mux.Handle("GET /api/public", authService.OptionalAuth(handler))

// Inside handler, session may be nil
session := auth.SessionFromContext(r.Context())
if session != nil {
    // User is authenticated
}
```

### Require Admin

```go
// Require admin role - returns 403 if not admin
mux.Handle("GET /admin/users", authService.RequireAdmin(handler))
```

## Database Connections

### PostgreSQL

```go
import (
    "database/sql"
    _ "github.com/lib/pq"
    "github.com/webdeveloperben/BetterAuthGoServer/db"
)

sqlDB, _ := sql.Open("postgres", "postgres://user:pass@localhost:5432/dbname?sslmode=disable")
store, _ := db.New(sqlDB, db.DialectPostgres)
```

### MySQL

```go
import (
    "database/sql"
    _ "github.com/go-sql-driver/mysql"
    "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// parseTime=true is required for proper timestamp handling
sqlDB, _ := sql.Open("mysql", "user:pass@tcp(localhost:3306)/dbname?parseTime=true")
store, _ := db.New(sqlDB, db.DialectMySQL)
```

### SQLite

```go
import (
    "database/sql"
    _ "github.com/mattn/go-sqlite3"
    "github.com/webdeveloperben/BetterAuthGoServer/db"
)

// _foreign_keys=on enables foreign key constraints
sqlDB, _ := sql.Open("sqlite3", "auth.db?_foreign_keys=on")
store, _ := db.New(sqlDB, db.DialectSQLite)
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite://auth.db` |
| `AUTH_SECRET` | Secret key for tokens (min 32 chars) | Required |
| `BASE_URL` | Base URL for the auth service | Required |
| `PORT` | Server port | `8080` |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | - |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | - |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID | - |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret | - |
| `DISCORD_CLIENT_ID` | Discord OAuth client ID | - |
| `DISCORD_CLIENT_SECRET` | Discord OAuth client secret | - |

## Development

This project uses [Task](https://taskfile.dev) for development commands and [mise](https://mise.jdx.dev) for tool version management.

### First-time Setup

```bash
# Install mise (if not already installed)
# See: https://mise.jdx.dev/getting-started.html

# Install Go (version managed by mise.toml)
mise install

# Set up development environment (install tools and git hooks)
task setup
```

The `task setup` command installs:
- **air** - Hot reload for development
- **lefthook** - Git hooks for pre-commit formatting and pre-push linting
- **golangci-lint** - Go linter

### Git Hooks

This project uses [lefthook](https://github.com/evilmartians/lefthook) to run automated checks:

**Pre-commit:**
- Format Go files with `gofmt -s`
- Run `go vet`
- Run `go mod tidy`

**Pre-push:**
- Run `golangci-lint`

### Common Commands

```bash
# Run the application
task run

# Run with hot reload (requires air)
task dev

# Run tests
task test              # All tests
task test:unit         # Unit tests only (fast)
task test:e2e          # E2E tests (requires Docker)
task test:coverage     # Generate coverage report

# Code quality
task fmt               # Format code
task vet               # Run go vet
task lint              # Run linter
task check             # Run all checks

# Docker
task up                # Start postgres + auth
task down              # Stop all services

# Test Nuxt integration
cd nuxt-playground && npm install && npm run dev  # Requires auth server + database
```

## Security Considerations

- **Secret Key**: Use a cryptographically random string of at least 32 characters
- **HTTPS**: Always use HTTPS in production (cookies are marked Secure automatically)
- **Rate Limiting**: Enabled by default via plugin, configure limits based on your needs
- **CSRF**: Enabled by default via plugin for state-changing operations
- **Password Policy**: Complexity requirements enabled by default
- **Session Cleanup**: Expired sessions are automatically cleaned up hourly

## Architecture

```
auth/                  # Main package - public API
├── config/            # Configuration options
├── handlers/          # HTTP handlers
├── hooks/             # Event hooks system
├── models/            # Data models and store interface
├── plugin/            # Plugin system
├── defaults/          # Default plugin bundle
├── csrf/              # CSRF protection plugin
├── ratelimit/         # Rate limiting plugin
├── jwt/               # JWT authentication plugin
│   └── db/            # Plugin's own database schema & queries
├── oauth/             # OAuth2 plugin
│   ├── providers/     # OAuth provider implementations
│   └── db/            # Plugin's own database schema & queries
├── organization/      # Multi-tenancy plugin
│   └── db/            # Plugin's own database schema & queries
├── admin/             # Admin functionality plugin
├── token/             # Token generation and verification
├── kv/                # Key-value stores (memory, Redis)
└── otel/              # OpenTelemetry observability
db/                    # Core database (sqlc-generated)
├── schema/            # SQL schema definitions
├── queries/           # SQL query definitions
├── pgstore/           # PostgreSQL generated code
├── mysqlstore/        # MySQL generated code
└── sqlitestore/       # SQLite generated code
migrate/               # Migration runner
tests/e2e/             # End-to-end tests
```

Each plugin owns its own database schema and queries. Core tables (users, sessions, accounts, verifications) are in the central `db/` package. All database code uses sqlc with dialect-specific adapters for PostgreSQL, MySQL, and SQLite.

## License

MIT License - see [LICENSE](./LICENSE) for details.
