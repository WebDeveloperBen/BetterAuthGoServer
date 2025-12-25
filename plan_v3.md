# Plan v3: Full Plugin Architecture

## Goal

Transform the auth library to follow the **"flexible foundation, convenient defaults"** pattern:

- **Batteries included** by default (one import, works out of the box)
- **Fully composable** for power users (disable defaults, pick what you need)
- **Each feature is a plugin** (isolated, testable, optional)

---

## Current State

```
auth/
├── auth.go              # Main Auth struct - orchestrates everything
├── config.go            # Functional options, all config in one place
├── plugin/              # Extension system (for TOTP, magic links, etc.)
│   ├── plugin.go        # Plugin interface
│   └── registry.go      # Lifecycle management
├── jwt/                 # JWT service (standalone, but wired as field)
├── oauth/               # OAuth (wired directly into Auth)
├── handlers/            # HTTP handlers
├── ratelimit.go         # Rate limiting (embedded in Auth)
├── admin.go             # Admin functionality (embedded in Auth)
└── ...
```

**Problems:**
1. Core features (JWT, OAuth, Admin, RateLimit) are hardcoded fields on `Auth`
2. Can't opt-out of features without config flags
3. `Auth` struct is a god object
4. Features can't be used independently

---

## Target State

```
betterauth/
├── auth.go              # Minimal core: User, Session, SignIn, SignUp
├── config.go            # Core config only
├── store.go             # Store interface
├── middleware.go        # RequireSession only
├── errors.go            # Core errors
│
├── plugin/              # Plugin system (existing, enhanced)
│   ├── plugin.go        # Plugin interface
│   ├── registry.go      # Lifecycle management
│   └── context.go       # Plugin context (access to core)
│
├── jwt/                 # JWT as plugin
│   ├── service.go       # JWT logic (existing)
│   ├── claims.go        # Claims types (existing)
│   ├── plugin.go        # NEW: Plugin wrapper
│   ├── middleware.go    # JWT middleware
│   └── handlers.go      # /token endpoints
│
├── oauth/               # OAuth as plugin
│   ├── service.go       # OAuth logic
│   ├── plugin.go        # NEW: Plugin wrapper
│   ├── handlers.go      # OAuth endpoints
│   └── providers/
│       ├── google.go
│       ├── github.go
│       └── discord.go
│
├── admin/               # Admin as plugin
│   ├── plugin.go        # Plugin wrapper
│   ├── handlers.go      # Admin endpoints
│   └── middleware.go    # Admin auth
│
├── ratelimit/           # Rate limiting as plugin
│   ├── plugin.go        # Plugin wrapper
│   ├── limiter.go       # Rate limit logic
│   └── middleware.go    # Rate limit middleware
│
├── csrf/                # CSRF as plugin
│   ├── plugin.go
│   └── middleware.go
│
├── hooks/               # Hooks (existing, unchanged)
│   └── hooks.go
│
├── defaults/            # Default plugin bundle
│   └── defaults.go      # Wires up standard plugins
│
└── token/               # Token utilities (existing, internal)
    ├── hasher.go
    └── encryptor.go
```

---

## Usage Examples (Target)

### 1. Batteries Included (Most Users)

```go
import "github.com/webdeveloperben/betterauth"

auth := betterauth.New(store,
    betterauth.WithSecret(secret),
    betterauth.WithBaseURL(baseURL),
)

// Includes by default:
// - Session-based auth
// - Rate limiting
// - CSRF protection
// - Admin endpoints
// - Session cleanup

mux.Handle("/auth/", auth.Handler())
```

### 2. Add Optional Features

```go
import (
    "github.com/webdeveloperben/betterauth"
    "github.com/webdeveloperben/betterauth/jwt"
    "github.com/webdeveloperben/betterauth/oauth"
    "github.com/webdeveloperben/betterauth/oauth/providers"
)

auth := betterauth.New(store,
    betterauth.WithSecret(secret),
    betterauth.WithBaseURL(baseURL),
)

// Add JWT support
auth.Use(jwt.Plugin(
    jwt.WithAccessTTL(15 * time.Minute),
    jwt.WithRefreshTTL(7 * 24 * time.Hour),
))

// Add OAuth providers
auth.Use(oauth.Plugin(
    providers.Google(clientID, clientSecret),
    providers.GitHub(clientID, clientSecret),
))

mux.Handle("/auth/", auth.Handler())
```

### 3. Minimal (Power Users)

```go
import (
    "github.com/webdeveloperben/betterauth"
    "github.com/webdeveloperben/betterauth/jwt"
)

auth := betterauth.New(store,
    betterauth.WithSecret(secret),
    betterauth.WithBaseURL(baseURL),
    betterauth.WithoutDefaults(), // No rate limit, no CSRF, no admin
)

// Only JWT, nothing else
auth.Use(jwt.Plugin())

mux.Handle("/auth/", auth.Handler())
```

### 4. Direct Package Usage (Maximum Control)

```go
import (
    "github.com/webdeveloperben/betterauth/jwt"
    "github.com/webdeveloperben/betterauth/ratelimit"
)

// Use packages directly without the Auth orchestrator
jwtService := jwt.NewService(jwt.Config{
    Secret:         secret,
    AccessTokenTTL: 15 * time.Minute,
})

limiter := ratelimit.New(100, time.Minute)

// Wire up yourself
mux.Handle("/api/", limiter.Middleware(jwtService.Middleware(apiHandler)))
```

---

## Implementation Phases

### Phase 1: Foundation (WithoutDefaults + Plugin Context)

**Goal:** Add escape hatch, enhance plugin context for core feature access

**Changes:**

1. Add `WithoutDefaults()` option to config
2. Enhance `plugin.Context` to provide access to core Auth methods
3. Add `Auth.Use()` method for registering plugins after creation
4. Refactor route mounting to be plugin-aware

**Files to modify:**
- `auth/config.go` - Add `WithoutDefaults`, `SkipDefaults` field
- `auth/auth.go` - Add `Use()` method, conditional default loading
- `auth/plugin/plugin.go` - Enhance Context with Auth interface

**Deliverable:** Users can `WithoutDefaults()` and manually `Use()` plugins

---

### Phase 2: Rate Limiting as Plugin

**Goal:** Extract rate limiting into a standalone plugin

**Changes:**

1. Create `auth/ratelimit/plugin.go`
2. Move rate limit logic to `auth/ratelimit/limiter.go`
3. Implement `Plugin`, `MiddlewareProvider` interfaces
4. Remove rate limit fields from `Auth` struct
5. Auto-register as default plugin (unless `WithoutDefaults`)

**Files to create:**
- `auth/ratelimit/plugin.go`
- `auth/ratelimit/limiter.go` (move from `auth/ratelimit.go`)
- `auth/ratelimit/middleware.go`

**Files to modify:**
- `auth/auth.go` - Remove rate limiter field, add to defaults
- `auth/config.go` - Remove rate limit config (move to plugin)

**Deliverable:** Rate limiting works as plugin, can be disabled/replaced

---

### Phase 3: CSRF as Plugin

**Goal:** Extract CSRF into a standalone plugin

**Changes:**

1. Create `auth/csrf/plugin.go`
2. Implement `Plugin`, `MiddlewareProvider` interfaces
3. Remove CSRF logic from handlers
4. Auto-register as default plugin

**Files to create:**
- `auth/csrf/plugin.go`
- `auth/csrf/middleware.go`

**Files to modify:**
- `auth/config.go` - Remove CSRF config
- `auth/handlers/*.go` - Remove inline CSRF checks

**Deliverable:** CSRF works as plugin, can be disabled for API-only usage

---

### Phase 4: JWT as Plugin

**Goal:** Convert JWT from field on Auth to plugin

**Changes:**

1. Create `auth/jwt/plugin.go`
2. Move handlers from `auth/handlers/jwt.go` to `auth/jwt/handlers.go`
3. Implement `Plugin`, `RoutesProvider`, `MiddlewareProvider`
4. Remove JWT field from `Auth` struct
5. JWT is opt-in (not in defaults, requires explicit `Use()`)

**Files to create:**
- `auth/jwt/plugin.go`
- `auth/jwt/handlers.go` (move from handlers/)
- `auth/jwt/middleware.go`

**Files to modify:**
- `auth/auth.go` - Remove `jwt` field
- `auth/auth_jwt.go` - Remove (methods move to plugin)
- `auth/config.go` - Remove JWT config
- `auth/handlers/router.go` - Remove JWT routes

**Deliverable:** JWT is fully optional, imported and used explicitly

---

### Phase 5: OAuth as Plugin

**Goal:** Convert OAuth from field on Auth to plugin

**Changes:**

1. Create `auth/oauth/plugin.go`
2. Move handlers from `auth/handlers/oauth.go` to `auth/oauth/handlers.go`
3. Implement `Plugin`, `RoutesProvider`
4. Remove OAuth field from `Auth` struct
5. OAuth is opt-in (not in defaults)

**Files to create:**
- `auth/oauth/plugin.go`
- `auth/oauth/handlers.go`

**Files to modify:**
- `auth/auth.go` - Remove `oauth` field
- `auth/auth_oauth.go` - Remove (methods move to plugin)
- `auth/handlers/router.go` - Remove OAuth routes

**Deliverable:** OAuth is fully optional, providers registered via plugin

---

### Phase 6: Admin as Plugin

**Goal:** Convert Admin functionality to plugin

**Changes:**

1. Create `auth/admin/plugin.go`
2. Move handlers from `auth/handlers/admin.go` to `auth/admin/handlers.go`
3. Implement `Plugin`, `RoutesProvider`, `MiddlewareProvider`
4. Auto-register as default plugin (unless `WithoutDefaults`)

**Files to create:**
- `auth/admin/plugin.go`
- `auth/admin/handlers.go`
- `auth/admin/middleware.go`

**Files to modify:**
- `auth/admin.go` - Keep core logic, remove handler coupling
- `auth/handlers/router.go` - Remove admin routes

**Deliverable:** Admin is a default plugin, can be disabled for embedded use

---

### Phase 7: Defaults Bundle

**Goal:** Create the defaults bundle that wires everything together

**Changes:**

1. Create `auth/defaults/defaults.go`
2. Define which plugins are included by default
3. Provide `Plugins()` function returning default plugin set
4. Update `Auth.New()` to use defaults unless `WithoutDefaults()`

**Files to create:**
- `auth/defaults/defaults.go`

**Code:**
```go
package defaults

import (
    "github.com/webdeveloperben/betterauth/admin"
    "github.com/webdeveloperben/betterauth/csrf"
    "github.com/webdeveloperben/betterauth/ratelimit"
    "github.com/webdeveloperben/betterauth/plugin"
)

// Plugins returns the default plugin set
func Plugins(cfg Config) []plugin.Plugin {
    return []plugin.Plugin{
        ratelimit.Plugin(
            ratelimit.WithLimit(cfg.RateLimitMax, cfg.RateLimitWindow),
        ),
        csrf.Plugin(),
        admin.Plugin(),
    }
}
```

**Deliverable:** Clean separation between core and defaults

---

### Phase 8: Cleanup & Documentation

**Goal:** Polish, test, document

**Changes:**

1. Remove dead code from previous phases
2. Update all tests
3. Update README with new usage patterns
4. Add migration guide from v2 to v3
5. Add examples/ directory

---

## Plugin Interface (Enhanced)

```go
package plugin

import (
    "context"
    "net/http"

    "github.com/uptrace/bun"
)

// Plugin is the core interface
type Plugin interface {
    Name() string
    Init(ctx Context) error
    Close() error
}

// Context provides plugins access to auth internals
type Context struct {
    // Database access
    DB *bun.DB

    // Configuration
    BaseURL string
    Secret  string

    // Core auth operations (interface to avoid circular imports)
    Auth AuthCore
}

// AuthCore exposes core auth methods to plugins
type AuthCore interface {
    // User operations
    GetUser(ctx context.Context, userID string) (*User, error)
    GetUserByEmail(ctx context.Context, email string) (*User, error)

    // Session operations
    ValidateSession(ctx context.Context, token string) (*Session, error)
    CreateSession(ctx context.Context, userID string, r *http.Request) (*Session, error)

    // Store access
    Store() Store
}

// RoutesProvider - plugins that add HTTP routes
type RoutesProvider interface {
    Routes() []Route
}

// MiddlewareProvider - plugins that add middleware
type MiddlewareProvider interface {
    Middleware() []Middleware
}

// Middleware with priority for ordering
type Middleware struct {
    Priority int // Lower = runs first
    Handler  func(http.Handler) http.Handler
}

// Route definition
type Route struct {
    Method      string
    Path        string
    Handler     http.HandlerFunc
    RequireAuth bool
    Middleware  []func(http.Handler) http.Handler
}
```

---

## Migration Guide (v2 → v3)

### Before (v2)
```go
auth, err := auth.New(store,
    auth.WithSecret(secret),
    auth.WithBaseURL(baseURL),
    auth.WithJWT(true),
    auth.WithRateLimit(true, time.Minute, 100),
)

auth.RegisterOAuthProvider(oauth.NewGoogle(...))
```

### After (v3)
```go
auth, err := betterauth.New(store,
    betterauth.WithSecret(secret),
    betterauth.WithBaseURL(baseURL),
)

auth.Use(jwt.Plugin())
auth.Use(oauth.Plugin(
    providers.Google(clientID, clientSecret),
))
```

### Minimal (v3)
```go
auth, err := betterauth.New(store,
    betterauth.WithSecret(secret),
    betterauth.WithBaseURL(baseURL),
    betterauth.WithoutDefaults(),
)
// Only core session auth, nothing else
```

---

## Success Criteria

1. **Batteries included still works** - Default usage requires no changes
2. **Each feature is optional** - Can disable any feature via `WithoutDefaults()` + selective `Use()`
3. **Plugins are isolated** - Each plugin package can be tested independently
4. **No god object** - `Auth` struct only contains core session logic
5. **Backwards compatible** - v2 patterns still work (with deprecation warnings)
6. **Clear boundaries** - Each plugin owns its routes, middleware, and config

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Breaking changes | Provide v2 compatibility shim, deprecation warnings |
| Plugin ordering issues | Add priority to middleware, document ordering |
| Circular imports | Use interfaces (`AuthCore`) to break cycles |
| Performance overhead | Plugin init happens once at startup, not per-request |
| Testing complexity | Each plugin has its own test suite |

---

## Timeline Estimate

| Phase | Scope |
|-------|-------|
| Phase 1 | Foundation - `WithoutDefaults`, enhanced context |
| Phase 2 | Rate limiting plugin |
| Phase 3 | CSRF plugin |
| Phase 4 | JWT plugin |
| Phase 5 | OAuth plugin |
| Phase 6 | Admin plugin |
| Phase 7 | Defaults bundle |
| Phase 8 | Cleanup & docs |

Each phase is independently shippable and testable.
