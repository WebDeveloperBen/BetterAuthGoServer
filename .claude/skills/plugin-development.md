# BetterAuth Go Plugin Development Guide

This skill provides conventions and patterns for building plugins in the BetterAuthGoServer authentication library.

## Plugin Architecture Overview

Plugins are self-contained packages that extend the auth library without modifying core code. Each plugin:
- Lives in its own package under `auth/`
- Is completely independent (no cross-plugin imports)
- Uses the `plugin.Context` for accessing auth internals
- Gets registered via `authService.Use(pluginName.NewPlugin())`

## Required Plugin Interfaces

Every plugin MUST implement `plugin.Plugin`:

```go
type Plugin interface {
    Name() string           // Unique identifier
    Init(ctx Context) error // Initialize with auth context
    Close() error           // Cleanup resources
}
```

## Optional Plugin Interfaces

Implement these based on what your plugin provides:

| Interface | Purpose | Methods |
|-----------|---------|---------|
| `RoutesProvider` | Add HTTP endpoints | `Routes() []Route` |
| `MiddlewareProvider` | Add middleware | `Middleware() []Middleware` |
| `MigrationsProvider` | Add database tables | `Migrations() []any` |
| `ValidatorProvider` | Custom validation | `ValidateSignUp()`, `ValidateSignIn()` |

## Plugin Context

The `plugin.Context` provides access to:
```go
type Context struct {
    DB        *bun.DB          // Database connection (may be nil)
    BaseURL   string           // Auth service base URL
    Secret    string           // Auth secret key
    Auth      AuthCore         // Minimal interface for type assertion
    Hasher    *token.Hasher    // For hashing tokens
    Encryptor *token.Encryptor // For encrypting tokens
    Logger    *slog.Logger     // Structured logger
    EventBus  models.EventBus  // For subscribing to auth events
}
```

**Important**: `AuthCore` is intentionally minimal (just `BaseURL()` and `Secret()`). For auth operations, define your own interface and type-assert (see "Provider Interface Pattern" below).

## EventBus - Subscribing to Auth Events

Plugins can subscribe to auth events via the `EventBus` in the plugin context. This is the recommended way to react to authentication events.

### Available Events

| Event Type | Payload Type | When Fired |
|------------|--------------|------------|
| `models.EventUserCreated` | `UserCreatedPayload` | After user signup |
| `models.EventUserUpdated` | `UserCreatedPayload` | After user profile update |
| `models.EventSignedIn` | `SignedInPayload` | After successful sign in |
| `models.EventSignedOut` | `SignedOutPayload` | After sign out |
| `models.EventPasswordChanged` | `PasswordChangedPayload` | After password change/reset |
| `models.EventPasswordResetRequested` | `PasswordResetRequestedPayload` | When reset token generated |
| `models.EventEmailVerified` | `EmailVerifiedPayload` | After email verification |
| `models.EventEmailVerificationSent` | `EmailVerificationSentPayload` | When verification email sent |
| `models.EventOAuthAccountLinked` | `OAuthAccountLinkedPayload` | After OAuth account linked |

### Subscribing to Events in Init()

```go
func (p *Plugin) Init(ctx plugin.Context) error {
    p.ctx = ctx

    // Subscribe to user creation events
    if ctx.EventBus != nil {
        ctx.EventBus.Subscribe(models.EventUserCreated, func(c context.Context, e models.Event) error {
            var payload models.UserCreatedPayload
            if err := e.UnmarshalPayload(&payload); err != nil {
                return err
            }
            // payload.User contains full *models.User
            return p.onUserCreated(c, payload.User)
        })

        ctx.EventBus.Subscribe(models.EventSignedIn, func(c context.Context, e models.Event) error {
            var payload models.SignedInPayload
            if err := e.UnmarshalPayload(&payload); err != nil {
                return err
            }
            // payload.User and payload.Session available
            return p.onSignIn(c, payload.User, payload.Session)
        })
    }

    return nil
}
```

### Event Payload Types

All payloads use full model types for rich data access:

```go
type UserCreatedPayload struct {
    User *User `json:"user"`
}

type SignedInPayload struct {
    User    *User    `json:"user"`
    Session *Session `json:"session"`
}

type SignedOutPayload struct {
    User    *User    `json:"user"`
    Session *Session `json:"session"`
}

type PasswordChangedPayload struct {
    User *User `json:"user"`
}

type PasswordResetRequestedPayload struct {
    User  *User  `json:"user"`
    Token string `json:"token"`  // Raw token for email
}

type EmailVerifiedPayload struct {
    User *User `json:"user"`
}

type EmailVerificationSentPayload struct {
    User  *User  `json:"user"`
    Token string `json:"token"`  // Raw token for email
}

type OAuthAccountLinkedPayload struct {
    User    *User    `json:"user"`
    Account *Account `json:"account"`
}
```

### Event Handler Best Practices

1. **Fire-and-forget**: Events are asynchronous; handler errors are logged but don't affect the caller
2. **Panic-safe**: Panics in handlers are recovered and logged
3. **Keep handlers fast**: Long-running work should be queued for background processing
4. **Idempotent**: Handlers may be called multiple times; design for idempotency

## File Structure Convention

For a plugin named `myplugin`:
```
auth/myplugin/
├── plugin.go      # Plugin struct, Init, Close, interface implementations
├── provider.go    # AuthProvider interface for auth operations (REQUIRED)
├── service.go     # Business logic (uses DB directly)
├── handlers.go    # HTTP handlers (if providing routes)
├── middleware.go  # Middleware functions (if providing middleware)
├── models.go      # Database models (if needing tables)
├── options.go     # Functional options for configuration
└── *_test.go      # Tests
```

## Plugin Template

### provider.go (REQUIRED)
```go
package myplugin

import (
    "context"
    "net/http"

    "github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// AuthProvider defines the auth operations required by this plugin.
// The main Auth struct implements this interface.
type AuthProvider interface {
    // GetPluginUser retrieves a user by ID
    GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)

    // CreateSessionForUser creates a new session for the given user
    CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error)

    // Add other methods your plugin needs from Auth...
}
```

### plugin.go
```go
package myplugin

import (
    "context"

    "github.com/webdeveloperben/BetterAuthGoServer/auth/models"
    "github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

const (
    PluginName = "myplugin"

    // Middleware priority (if applicable)
    // 0-20: Rate limiting, validation
    // 20-40: Auth, authorization
    // 40-60: Request transformation
    // 60-80: Logging, metrics
    MiddlewarePriority = 30
)

type Plugin struct {
    ctx     plugin.Context
    auth    AuthProvider  // Type-asserted auth provider
    service *Service
    opts    []Option
}

// Compile-time interface checks
var (
    _ plugin.Plugin         = (*Plugin)(nil)
    _ plugin.RoutesProvider = (*Plugin)(nil)  // if providing routes
    // _ plugin.MiddlewareProvider = (*Plugin)(nil)  // if providing middleware
    // _ plugin.MigrationsProvider = (*Plugin)(nil)  // if needing DB tables
)

// NewPlugin creates a new plugin with options
func NewPlugin(opts ...Option) *Plugin {
    return &Plugin{opts: opts}
}

func (p *Plugin) Name() string {
    return PluginName
}

func (p *Plugin) Init(ctx plugin.Context) error {
    p.ctx = ctx

    // Type-assert to get AuthProvider (REQUIRED PATTERN)
    auth, ok := ctx.Auth.(AuthProvider)
    if !ok {
        return nil // Auth doesn't support required operations
    }
    p.auth = auth

    // Check for required context (e.g., DB)
    if ctx.DB == nil {
        return nil // Gracefully disable if DB not available
    }

    // Subscribe to auth events
    if ctx.EventBus != nil {
        ctx.EventBus.Subscribe(models.EventUserCreated, p.handleUserCreated)
    }

    // Create service with config from options
    config := DefaultConfig()
    for _, opt := range p.opts {
        opt(&config)
    }

    // Use context values as defaults
    if config.SomeValue == "" {
        config.SomeValue = ctx.BaseURL
    }

    p.service = NewService(ctx.DB, config)
    return nil
}

func (p *Plugin) handleUserCreated(ctx context.Context, e models.Event) error {
    var payload models.UserCreatedPayload
    if err := e.UnmarshalPayload(&payload); err != nil {
        return err
    }
    // React to user creation
    p.ctx.Logger.Info("user created", "user_id", payload.User.ID)
    return nil
}

func (p *Plugin) Close() error {
    if p.service != nil {
        return p.service.Close()
    }
    return nil
}

// Routes returns HTTP endpoints (if RoutesProvider)
func (p *Plugin) Routes() []plugin.Route {
    if p.service == nil || p.auth == nil {
        return nil
    }
    return []plugin.Route{
        {
            Method:      "GET",
            Path:        "/myplugin/resource",
            Handler:     p.handleGetResource,
            RequireAuth: true,
            Middleware:  []func(http.Handler) http.Handler{p.customMiddleware},
        },
    }
}

// Middleware returns global middleware (if MiddlewareProvider)
func (p *Plugin) Middleware() []plugin.Middleware {
    return []plugin.Middleware{
        {Priority: MiddlewarePriority, Handler: p.service.Middleware()},
    }
}

// Migrations returns DB models (if MigrationsProvider)
func (p *Plugin) Migrations() []any {
    return []any{&MyModel{}}
}
```

### service.go
```go
package myplugin

import (
    "context"
    "github.com/uptrace/bun"
)

// Service contains business logic using DB directly
type Service struct {
    db     *bun.DB
    config Config
}

func NewService(db *bun.DB, config Config) *Service {
    return &Service{db: db, config: config}
}

func (s *Service) Close() error {
    return nil
}

func (s *Service) DoSomething(ctx context.Context, id string) (*Result, error) {
    var result Result
    err := s.db.NewSelect().
        Model(&result).
        Where("id = ?", id).
        Scan(ctx)
    return &result, err
}
```

### handlers.go
```go
package myplugin

import (
    "encoding/json"
    "errors"
    "net/http"
)

// Response/request types (keep private to package)
type resourceResponse struct {
    ID   string `json:"id"`
    Name string `json:"name"`
}

// Helper functions
func writeJSON(w http.ResponseWriter, status int, data any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, err error) {
    writeJSON(w, status, map[string]string{
        "error":   http.StatusText(status),
        "message": err.Error(),
    })
}

// Handler methods on Plugin
func (p *Plugin) handleGetResource(w http.ResponseWriter, r *http.Request) {
    result, err := p.service.DoSomething(r.Context(), "123")
    if err != nil {
        if errors.Is(err, ErrNotFound) {
            writeError(w, http.StatusNotFound, err)
        } else {
            writeError(w, http.StatusInternalServerError, err)
        }
        return
    }
    writeJSON(w, http.StatusOK, result)
}
```

### options.go
```go
package myplugin

import "time"

type Config struct {
    SomeValue string
    TTL       time.Duration
}

func DefaultConfig() Config {
    return Config{
        TTL: 24 * time.Hour,
    }
}

type Option func(*Config)

func WithSomeValue(v string) Option {
    return func(c *Config) { c.SomeValue = v }
}

func WithTTL(ttl time.Duration) Option {
    return func(c *Config) { c.TTL = ttl }
}
```

## Provider Interface Pattern (IMPORTANT)

Plugins do NOT use `plugin.AuthCore` directly for auth operations. Instead:

1. **Define your own interface** in `provider.go` with exactly the methods you need
2. **Type-assert in Init()** to get your interface from `ctx.Auth`
3. **Use your interface** in handlers and middleware

### Why This Pattern?

- **Minimal coupling**: Plugins only depend on what they actually use
- **Clear contracts**: Each plugin declares its auth requirements explicitly
- **Type safety**: Compile-time checks ensure Auth implements your interface
- **Flexibility**: Different plugins can have different interfaces

### Available Methods on `*Auth`

When defining your AuthProvider interface, you can include any of these methods (add only what you need):

```go
// User operations
GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)
GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error)
CreatePluginUser(ctx context.Context, req plugin.CreateUserRequest) (*plugin.User, error)
// Creates the user and runs fn in the same DB transaction (tx is nil without transaction support;
// the user is then deleted again if fn fails)
CreatePluginUserTx(ctx context.Context, req plugin.CreateUserRequest, fn func(ctx context.Context, tx db.DBTX, user *plugin.User) error) (*plugin.User, error)

// Session operations
CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error)
// Validates the session token on a route without RequireAuth; nil, nil when absent/invalid
GetPluginSessionFromRequest(r *http.Request) (*plugin.Session, error)

// Password operations
VerifyPassword(ctx context.Context, userID string, password string) (bool, error)

// Request operations
GetUserFromRequest(r *http.Request) (*plugin.User, error)

// Configuration
BaseURL() string
Secret() string

// Event publishing (for OAuth plugins)
FireOAuthAccountLinked(ctx context.Context, userID, provider, accountID string) error
```

### Example: JWT Plugin Interface

```go
// auth/jwt/provider.go
type AuthProvider interface {
    GetPluginUser(ctx context.Context, userID string) (*plugin.User, error)
    GetPluginUserByEmail(ctx context.Context, email string) (*plugin.User, error)
    VerifyPassword(ctx context.Context, userID string, password string) (bool, error)
    CreateSessionForUser(ctx context.Context, userID string, r *http.Request) (*plugin.Session, error)
}
```

### Example: Admin Plugin Interface

```go
// auth/admin/provider.go
type UserProvider interface {
    GetUserFromRequest(r *http.Request) (*plugin.User, error)
}
```

## Error Handling

Define package-level errors:
```go
var (
    ErrNotFound      = errors.New("not found")
    ErrInvalidInput  = errors.New("invalid input")
    ErrNotConfigured = errors.New("plugin not configured")
)
```

In handlers, use `errors.Is()` for matching:
```go
if errors.Is(err, ErrNotFound) {
    writeError(w, http.StatusNotFound, err)
}
```

## Database Models

Use bun tags for table definitions:
```go
type MyModel struct {
    bun.BaseModel `bun:"table:my_plugin_items"`

    ID        string    `bun:"id,pk"`
    Name      string    `bun:"name,notnull"`
    CreatedAt time.Time `bun:"created_at,notnull,default:current_timestamp"`
}
```

For auto-table creation in Init:
```go
_, err := ctx.DB.NewCreateTable().
    Model((*MyModel)(nil)).
    IfNotExists().
    Exec(context.Background())
```

## Testing

Create mocks for dependencies:
```go
type mockService struct {
    items map[string]*Item
}

func (m *mockService) GetItem(ctx context.Context, id string) (*Item, error) {
    if item, ok := m.items[id]; ok {
        return item, nil
    }
    return nil, ErrNotFound
}
```

## Registration Pattern

Users register plugins after creating auth:
```go
authService, _ := auth.New(store, auth.WithSecret(secret))

// Register plugins
authService.Use(ratelimit.NewPlugin(
    ratelimit.WithLimit(100, time.Minute),
))
authService.Use(myplugin.NewPlugin(
    myplugin.WithSomeValue("custom"),
))

// Subscribe to events from user code
authService.EventBus().Subscribe(models.EventUserCreated, func(ctx context.Context, e models.Event) error {
    var payload models.UserCreatedPayload
    e.UnmarshalPayload(&payload)
    return sendWelcomeEmail(payload.User)
})
```

## Key Conventions

1. **Independence**: Never import other plugin packages
2. **Provider pattern**: Define your own interface, type-assert in Init()
3. **Graceful degradation**: Handle missing DB/Auth gracefully in Init()
4. **Functional options**: Use `WithXxx()` pattern for configuration
5. **Private helpers**: Keep response types and helpers private
6. **Compile-time checks**: Use `var _ Interface = (*Type)(nil)` pattern
7. **Context-based**: Use context.Context for cancellation/timeouts
8. **No auth package import**: Use provider.go interface, never import auth directly
9. **Minimal interfaces**: Only include methods your plugin actually uses
10. **Event subscriptions**: Use EventBus for reacting to auth events (not hooks)
