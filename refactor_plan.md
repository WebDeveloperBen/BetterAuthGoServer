# Refactor Plan: Separate Business Logic from HTTP Handlers

## Goal

Separate the `auth` package into two distinct layers:
1. **`auth/`** - Pure business/service logic (no HTTP knowledge)
2. **`handlers/`** - HTTP adapter layer (thin wrappers that call business methods)

This enables better testability, reusability (gRPC, CLI), and clearer architectural boundaries.

---

## Current State

```
auth/
  auth.go              # Auth struct + some business methods (SignUp, SignIn, etc.)
  admin_handlers.go    # Mixed: HTTP handlers + business logic inline
  handlers.go          # HTTP handlers (call auth methods)
  routes.go            # Route registration + middleware
  middleware.go        # Auth middleware
  session.go           # Session management
  config.go            # Configuration
  helpers.go           # Mixed utilities
  errors.go            # Error definitions
  ...
```

**Problems:**
- `admin_handlers.go` contains business logic (accesses `a.store` directly)
- `routes.go` mixes HTTP concerns with business package
- Handlers are methods on `*Auth`, coupling HTTP to business logic
- Can't test business logic without HTTP
- Can't reuse business logic for other transports (gRPC, CLI)

---

## Target Architecture

```
auth/                      # Business/service layer (NO HTTP imports)
  auth.go                  # Auth struct, New(), Close()
  auth_signup.go           # SignUp, SignIn, SignOut
  auth_password.go         # Password reset, change
  auth_email.go            # Email verification
  auth_oauth.go            # OAuth business logic
  admin.go                 # Admin operations (ListUsers, BanUser, etc.)
  profile.go               # Profile operations (UpdateProfile, DeleteAccount)
  session.go               # Session management
  config.go                # Configuration
  errors.go                # Business errors

handlers/                  # HTTP adapter layer
  router.go                # NewRouter(), route registration
  middleware.go            # HTTP middleware (CORS, CSRF, auth, admin)
  auth.go                  # Sign up/in/out handlers
  password.go              # Password handlers
  email.go                 # Email verification handlers
  oauth.go                 # OAuth handlers
  admin.go                 # Admin handlers
  profile.go               # Profile handlers
  session.go               # Session list/revoke handlers
  helpers.go               # writeJSON, writeError, response types
  request.go               # Request parsing utilities
  response.go              # Response types (UserResponse, etc.)

main.go                    # Wires everything together
```

---

## Dependency Graph (No Cycles)

```
         models/
            ↑
     ┌──────┴──────┐
     │             │
   auth/        hooks/
     ↑             ↑
     │             │
     └──────┬──────┘
            │
        handlers/
            ↑
            │
         main.go
```

---

## Phase 1: Add Missing Business Methods to `auth/`

Currently, admin handlers access `a.store` directly. We need to expose these as proper business methods.

### New file: `auth/admin.go`

```go
package auth

// ListUsersOptions for filtering user lists
type ListUsersOptions struct {
    Offset int
    Limit  int
    Query  string
    Role   string
}

// ListUsersResult contains paginated user results
type ListUsersResult struct {
    Users []*models.User
    Total int64
}

// ListUsers returns a paginated list of users (admin only)
func (a *Auth) ListUsers(ctx context.Context, opts ListUsersOptions) (*ListUsersResult, error)

// GetUserByID retrieves a user by ID
func (a *Auth) GetUserByID(ctx context.Context, userID string) (*models.User, error)

// UpdateUser updates a user's information (admin)
func (a *Auth) UpdateUser(ctx context.Context, userID string, updates UserUpdates) (*models.User, error)

// DeleteUser deletes a user and all associated data
func (a *Auth) DeleteUser(ctx context.Context, userID string) error

// BanUser bans a user with optional reason
func (a *Auth) BanUser(ctx context.Context, userID, reason string) error

// UnbanUser removes a ban from a user
func (a *Auth) UnbanUser(ctx context.Context, userID string) error

// SetUserRole updates a user's role
func (a *Auth) SetUserRole(ctx context.Context, userID, role string) error
```

### New file: `auth/profile.go`

```go
package auth

// UpdateProfile updates the current user's profile
func (a *Auth) UpdateProfile(ctx context.Context, userID string, updates ProfileUpdates) (*models.User, error)

// DeleteOwnAccount deletes the current user's account
func (a *Auth) DeleteOwnAccount(ctx context.Context, userID string) error

// ListLinkedAccounts returns OAuth accounts linked to a user
func (a *Auth) ListLinkedAccounts(ctx context.Context, userID string) ([]*models.Account, error)

// UnlinkAccount removes an OAuth account from a user
func (a *Auth) UnlinkAccount(ctx context.Context, userID, provider string) error
```

---

## Phase 2: Create `handlers/` Package

### `handlers/router.go`

```go
package handlers

import (
    "net/http"
    "github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// NewRouter creates the HTTP router with all auth routes
func NewRouter(a *auth.Auth) http.Handler {
    mux := http.NewServeMux()

    // Public endpoints
    mux.HandleFunc("POST /sign-up", SignUp(a))
    mux.HandleFunc("POST /sign-in", SignIn(a))
    mux.HandleFunc("POST /password/reset", RequestPasswordReset(a))
    mux.HandleFunc("POST /password/confirm", ConfirmPasswordReset(a))
    mux.HandleFunc("GET /email/verify", VerifyEmail(a))

    // Protected endpoints
    mux.Handle("POST /sign-out", RequireAuth(a, SignOut(a)))
    mux.Handle("GET /me", RequireAuth(a, GetMe(a)))
    mux.Handle("POST /password/change", RequireAuth(a, ChangePassword(a)))
    // ... etc

    // Admin endpoints
    mux.Handle("GET /admin/users", RequireAdmin(a, AdminListUsers(a)))
    mux.Handle("POST /admin/users/{id}/ban", RequireAdmin(a, AdminBanUser(a)))
    // ... etc

    // Apply middleware stack
    return applyMiddleware(mux, a)
}

func applyMiddleware(h http.Handler, a *auth.Auth) http.Handler {
    h = corsMiddleware(h, a.Config())
    h = csrfMiddleware(h, a.Config())
    h = securityHeaders(h)
    h = rateLimitMiddleware(h, a)
    return h
}
```

### `handlers/auth.go`

```go
package handlers

// SignUp handles POST /sign-up
func SignUp(a *auth.Auth) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req SignUpRequest
        if err := parseJSON(r, &req); err != nil {
            writeError(w, http.StatusBadRequest, err)
            return
        }

        user, session, err := a.SignUp(r.Context(), auth.SignUpRequest{
            Email:    req.Email,
            Password: req.Password,
            Name:     req.Name,
        }, r)

        if err != nil {
            writeAuthError(w, err)
            return
        }

        if session != nil {
            setSessionCookie(w, a, session)
        }

        writeJSON(w, http.StatusCreated, toUserResponse(user))
    }
}

// SignIn handles POST /sign-in
func SignIn(a *auth.Auth) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        var req SignInRequest
        if err := parseJSON(r, &req); err != nil {
            writeError(w, http.StatusBadRequest, err)
            return
        }

        user, session, err := a.SignIn(r.Context(), req.Email, req.Password, r)
        if err != nil {
            writeAuthError(w, err)
            return
        }

        setSessionCookie(w, a, session)
        writeJSON(w, http.StatusOK, toUserResponse(user))
    }
}
```

### `handlers/middleware.go`

```go
package handlers

// RequireAuth middleware ensures the request has a valid session
func RequireAuth(a *auth.Auth, next http.HandlerFunc) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        session, user, err := getSessionFromRequest(a, r)
        if err != nil {
            writeError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
            return
        }

        if user.Banned {
            writeError(w, http.StatusForbidden, auth.ErrUserBanned)
            return
        }

        // Add to context
        ctx := context.WithValue(r.Context(), sessionKey, session)
        ctx = context.WithValue(ctx, userKey, user)

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

// RequireAdmin middleware ensures the user has admin role
func RequireAdmin(a *auth.Auth, next http.HandlerFunc) http.Handler {
    return RequireAuth(a, func(w http.ResponseWriter, r *http.Request) {
        user := UserFromContext(r.Context())
        if user.Role != "admin" {
            writeError(w, http.StatusForbidden, auth.ErrForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

### `handlers/helpers.go`

```go
package handlers

func writeJSON(w http.ResponseWriter, status int, v any) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
    writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeAuthError(w http.ResponseWriter, err error) {
    status := mapErrorToStatus(err)
    writeError(w, status, err)
}

func parseJSON(r *http.Request, v any) error {
    return json.NewDecoder(r.Body).Decode(v)
}

func setSessionCookie(w http.ResponseWriter, a *auth.Auth, session *models.Session) {
    // Use auth config for cookie settings
    cfg := a.Config()
    http.SetCookie(w, &http.Cookie{
        Name:     cfg.SessionCookie,
        Value:    session.Token, // raw token
        Path:     "/",
        HttpOnly: true,
        Secure:   cfg.SecureCookies,
        SameSite: http.SameSiteLaxMode,
        MaxAge:   int(cfg.SessionDuration.Seconds()),
    })
}
```

### `handlers/response.go`

```go
package handlers

// Request types
type SignUpRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
    Name     string `json:"name"`
}

type SignInRequest struct {
    Email    string `json:"email"`
    Password string `json:"password"`
}

// Response types
type UserResponse struct {
    ID            string  `json:"id"`
    Email         string  `json:"email"`
    Name          string  `json:"name"`
    EmailVerified bool    `json:"emailVerified"`
    Image         *string `json:"image,omitempty"`
    Role          string  `json:"role,omitempty"`
    CreatedAt     string  `json:"createdAt"`
}

func toUserResponse(u *models.User) *UserResponse {
    return &UserResponse{
        ID:            u.ID,
        Email:         u.Email,
        Name:          u.Name,
        EmailVerified: u.EmailVerified,
        Image:         u.Image,
        Role:          u.Role,
        CreatedAt:     u.CreatedAt.Format(time.RFC3339),
    }
}
```

---

## Phase 3: Update `main.go`

```go
package main

import (
    "github.com/webdeveloperben/BetterAuthGoServer/auth"
    "github.com/webdeveloperben/BetterAuthGoServer/handlers"
    "github.com/webdeveloperben/BetterAuthGoServer/db"
)

func main() {
    // Database
    store := db.New(connectDB())

    // Auth service (business logic)
    authService, err := auth.New(store,
        auth.WithSecret(secret),
        auth.WithBaseURL(baseURL),
        // ... other options
    )
    if err != nil {
        log.Fatal(err)
    }
    defer authService.Close()

    // HTTP router (handlers)
    router := handlers.NewRouter(authService)

    // Mount at /auth
    mux := http.NewServeMux()
    mux.Handle("/auth/", http.StripPrefix("/auth", router))
    mux.Handle("/api/", apiRoutes(authService))

    log.Println("Starting server on :8080")
    http.ListenAndServe(":8080", mux)
}
```

---

## Phase 4: Clean Up `auth/` Package

### Files to DELETE from `auth/`:
- `handlers.go` → moved to `handlers/auth.go`
- `admin_handlers.go` → split between `auth/admin.go` (business) and `handlers/admin.go` (HTTP)
- `routes.go` → moved to `handlers/router.go`
- `jwt_handlers.go` → moved to `handlers/jwt.go`

### Files to MODIFY in `auth/`:
- `auth.go` - Remove HTTP-specific code, keep business methods
- `middleware.go` - Keep session loading logic, move HTTP middleware to handlers
- `helpers.go` - Move HTTP helpers to handlers, keep business helpers

### Files that STAY in `auth/`:
- `auth.go` - Core business logic
- `auth_oauth.go` - OAuth business logic
- `session.go` - Session management
- `config.go` - Configuration
- `errors.go` - Business errors
- `password.go` - Password hashing

---

## Migration Checklist

### Phase 1: Add Business Methods
- [ ] Create `auth/admin.go` with admin business methods
- [ ] Create `auth/profile.go` with profile business methods
- [ ] Ensure all business logic is exposed as methods on `*Auth`
- [ ] Add any missing methods that handlers currently do inline
- [ ] Run tests

### Phase 2: Create Handlers Package
- [ ] Create `handlers/` directory
- [ ] Create `handlers/helpers.go` with HTTP utilities
- [ ] Create `handlers/response.go` with request/response types
- [ ] Create `handlers/middleware.go` with HTTP middleware
- [ ] Create `handlers/auth.go` with auth handlers
- [ ] Create `handlers/admin.go` with admin handlers
- [ ] Create `handlers/profile.go` with profile handlers
- [ ] Create `handlers/oauth.go` with OAuth handlers
- [ ] Create `handlers/session.go` with session handlers
- [ ] Create `handlers/jwt.go` with JWT handlers (if enabled)
- [ ] Create `handlers/router.go` with route registration
- [ ] Run tests

### Phase 3: Update Main
- [ ] Update `main.go` to use `handlers.NewRouter()`
- [ ] Verify application works end-to-end

### Phase 4: Clean Up
- [ ] Delete old handler files from `auth/`
- [ ] Delete `auth/routes.go`
- [ ] Remove unused exports from `auth/`
- [ ] Run full test suite
- [ ] Update any documentation

---

## Benefits After Refactor

| Benefit | Description |
|---------|-------------|
| **Testability** | Test business logic with mock store, no HTTP |
| **Reusability** | Same auth logic for REST, gRPC, CLI, WebSocket |
| **Clarity** | Clear boundary: business vs HTTP concerns |
| **Maintainability** | Change HTTP layer without touching business logic |
| **Single Responsibility** | Each package has one job |

---

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Breaking changes | Keep existing method signatures where possible |
| Missing functionality | Comprehensive test coverage before/after |
| Circular imports | Strict dependency direction: handlers → auth → models |

---

## Estimated Effort

| Phase | Effort |
|-------|--------|
| Phase 1: Business methods | 2-3 hours |
| Phase 2: Handlers package | 3-4 hours |
| Phase 3: Update main | 30 mins |
| Phase 4: Cleanup | 1-2 hours |
| **Total** | **7-10 hours** |
