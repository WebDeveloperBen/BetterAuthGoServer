# BetterAuth Go Server

A complete, embeddable authentication library for Go applications. Handles email/password authentication, OAuth2 providers, session management, and email verification flows with security best practices built-in.

## Features

- **Email/Password Authentication** - Sign up, sign in, password reset, password change
- **OAuth2 Providers** - Google, GitHub, Discord (extensible for more)
- **Session Management** - Cookie-based sessions with optional Bearer token support
- **Email Verification** - Token-based email verification flow
- **Security Built-in**
  - Argon2id password hashing
  - HMAC-SHA256 token hashing
  - AES-256-GCM OAuth token encryption
  - CSRF protection
  - Rate limiting
  - Secure cookie settings (HttpOnly, Secure, SameSite)
  - No user enumeration on login/reset endpoints
- **Extensible Hooks** - React to auth events (user created, sign in, password changed, etc.)
- **Database Agnostic** - Ships with PostgreSQL and SQLite support via Bun ORM

## Installation

```bash
go get github.com/webdeveloperben/BetterAuthGoServer
```

## Quick Start

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/uptrace/bun"
    "github.com/webdeveloperben/BetterAuthGoServer/auth"
    "github.com/webdeveloperben/BetterAuthGoServer/db"
)

func main() {
    // 1. Connect to database (PostgreSQL or SQLite)
    bunDB := connectToDatabase() // your database connection

    // 2. Create store and run migrations
    store := db.New(bunDB)
    store.Migrate(context.Background())

    // 3. Create auth instance
    authService, err := auth.New(store,
        auth.WithSecret("your-secret-key-minimum-32-characters!"),
        auth.WithBaseURL("http://localhost:8080"),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer authService.Close()

    // 4. Mount auth handler
    mux := http.NewServeMux()
    mux.Handle("/auth/", http.StripPrefix("/auth", authService.Handler()))

    // 5. Protect your routes
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

Use functional options to configure the auth instance:

```go
authService, err := auth.New(store,
    // Required
    auth.WithSecret("your-secret-key-minimum-32-characters!"),
    auth.WithBaseURL("http://localhost:8080"),

    // Session settings
    auth.WithSessionDuration(7 * 24 * time.Hour),  // Default: 7 days
    auth.WithSessionCookie("session"),              // Default: "session"

    // Password policy
    auth.WithPasswordPolicy(8, 128),                // Min/max length (default: 8, 128)
    auth.WithPasswordComplexity(true),              // Require upper, lower, digit, special

    // Email verification
    auth.WithEmailVerification(true, 24*time.Hour), // Require verification, token expiry

    // Password reset
    auth.WithPasswordResetExpiry(1 * time.Hour),    // Default: 1 hour

    // Auto sign-in after sign-up
    auth.WithAutoSignIn(true),                      // Default: true

    // Security
    auth.WithCSRF(true),                            // Default: true
    auth.WithRateLimit(true, time.Minute, 100),     // Enabled, window, max requests
    auth.WithAuthRateLimit(10),                     // Stricter limit for auth endpoints
    auth.WithTrustedOrigins("http://localhost:3000"),
    auth.WithTrustedProxies("127.0.0.1"),

    // Cleanup
    auth.WithSessionCleanupInterval(1 * time.Hour), // Auto-cleanup expired sessions

    // Logging
    auth.WithLogger(slog.Default()),

    // Hooks (see Hooks section)
    auth.WithHooks(auth.Hooks{...}),
)
```

## API Endpoints

All endpoints are mounted under your chosen path (e.g., `/auth`).

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/sign-up` | No | Create new user |
| POST | `/sign-in` | No | Sign in with email/password |
| POST | `/sign-out` | Yes | Sign out current session |
| GET | `/me` | Yes | Get current user |
| POST | `/password/reset` | No | Request password reset |
| POST | `/password/confirm` | No | Confirm password reset |
| POST | `/password/change` | Yes | Change password |
| GET | `/email/verify` | No | Verify email with token |
| POST | `/email/verify/send` | Yes | Send verification email |
| GET | `/sessions` | Yes | List all sessions |
| DELETE | `/sessions` | Yes | Revoke all sessions |
| DELETE | `/sessions/{id}` | Yes | Revoke specific session |
| GET | `/oauth/providers` | No | List OAuth providers |
| GET | `/oauth/{provider}` | No | Begin OAuth flow |
| GET | `/oauth/{provider}/callback` | No | OAuth callback |

See [`openapi.yaml`](./openapi.yaml) for complete API documentation.

## Hooks

React to authentication events by providing hook functions:

```go
auth.WithHooks(auth.Hooks{
    OnUserCreated: func(ctx context.Context, user *auth.User) error {
        log.Printf("New user: %s", user.Email)
        return nil
    },

    OnSignIn: func(ctx context.Context, user *auth.User, session *auth.Session) error {
        log.Printf("User signed in: %s", user.Email)
        return nil
    },

    OnSignOut: func(ctx context.Context, user *auth.User, session *auth.Session) error {
        log.Printf("User signed out: %s", user.Email)
        return nil
    },

    OnPasswordChanged: func(ctx context.Context, user *auth.User) error {
        // Send notification email
        return nil
    },

    OnPasswordResetRequested: func(ctx context.Context, user *auth.User, token string) error {
        // Send password reset email with token
        resetURL := fmt.Sprintf("https://yourapp.com/reset?token=%s", token)
        return sendEmail(user.Email, "Password Reset", resetURL)
    },

    OnEmailVerificationRequested: func(ctx context.Context, user *auth.User, token string) error {
        // Send verification email with token
        verifyURL := fmt.Sprintf("https://yourapp.com/verify?token=%s", token)
        return sendEmail(user.Email, "Verify Email", verifyURL)
    },

    OnEmailVerified: func(ctx context.Context, user *auth.User) error {
        log.Printf("Email verified: %s", user.Email)
        return nil
    },

    OnOAuthAccountLinked: func(ctx context.Context, user *auth.User, account *auth.Account) error {
        log.Printf("OAuth account linked: %s -> %s", user.Email, account.Provider)
        return nil
    },
})
```

## OAuth Providers

### Setup

```go
import "github.com/webdeveloperben/BetterAuthGoServer/auth/oauth"

// Register providers after creating auth instance
authService.RegisterOAuthProvider(oauth.NewGoogle(
    os.Getenv("GOOGLE_CLIENT_ID"),
    os.Getenv("GOOGLE_CLIENT_SECRET"),
    "http://localhost:8080/auth/oauth/google/callback",
))

authService.RegisterOAuthProvider(oauth.NewGitHub(
    os.Getenv("GITHUB_CLIENT_ID"),
    os.Getenv("GITHUB_CLIENT_SECRET"),
    "http://localhost:8080/auth/oauth/github/callback",
))

authService.RegisterOAuthProvider(oauth.NewDiscord(
    os.Getenv("DISCORD_CLIENT_ID"),
    os.Getenv("DISCORD_CLIENT_SECRET"),
    "http://localhost:8080/auth/oauth/discord/callback",
))
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
mux.Handle("GET /api/public", authService.OptionalAuthMiddleware()(handler))

// Inside handler, session may be nil
session := auth.SessionFromContext(r.Context())
if session != nil {
    // User is authenticated
}
```

## Database Setup

### PostgreSQL

```go
import (
    "database/sql"
    "github.com/uptrace/bun"
    "github.com/uptrace/bun/dialect/pgdialect"
    "github.com/uptrace/bun/driver/pgdriver"
)

dsn := "postgres://user:pass@localhost:5432/dbname?sslmode=disable"
sqldb := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(dsn)))
bunDB := bun.NewDB(sqldb, pgdialect.New())
```

### SQLite

```go
import (
    "database/sql"
    "github.com/uptrace/bun"
    "github.com/uptrace/bun/dialect/sqlitedialect"
    _ "github.com/mattn/go-sqlite3"
)

sqldb, _ := sql.Open("sqlite3", "auth.db?_foreign_keys=on")
bunDB := bun.NewDB(sqldb, sqlitedialect.New())
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

This project uses [Task](https://taskfile.dev) for development commands.

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

# Database migrations
task db:migrate        # Run pending migrations
task db:rollback       # Rollback last migration
task db:status         # Show migration status
task db:create -- name # Create new migration

# Code quality
task fmt               # Format code
task vet               # Run go vet
task lint              # Run linter
task check             # Run all checks

# Docker
task up                # Start postgres + auth
task up:dev            # Start with hot reload
task down              # Stop all services
task logs              # View logs
task db:shell          # Open PostgreSQL shell
```

## Security Considerations

- **Secret Key**: Use a cryptographically random string of at least 32 characters
- **HTTPS**: Always use HTTPS in production (cookies are marked Secure automatically)
- **Rate Limiting**: Enabled by default, configure limits based on your needs
- **CSRF**: Enabled by default for state-changing operations
- **Password Policy**: Complexity requirements enabled by default
- **Session Cleanup**: Expired sessions are automatically cleaned up hourly

## Architecture

```
auth/                  # Main package - public API and handlers
├── oauth/             # OAuth2 provider implementations
├── token/             # Token generation and verification
├── plugin/            # Plugin system for extensions
db/                    # Database store implementation (Bun ORM)
├── migrations/        # SQL migrations
cmd/migrate/           # Migration CLI tool
tests/e2e/             # End-to-end tests
```

## License

MIT License - see [LICENSE](./LICENSE) for details.
