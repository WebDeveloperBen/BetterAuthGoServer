# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Go authentication library designed to be embeddable in applications or run as a standalone microservice. Handles email/password authentication, OAuth2 (Google, GitHub, Discord), session management, and email verification flows.

## Development Commands

```bash
# Run the application
go run .

# Build
go build -o auth-server .

# Run tests
go test ./...

# Run a single test
go test -run TestName ./path/to/package

# Run tests with verbose output
go test -v ./...

# Run tests with coverage
go test -cover ./...

# Format code
go fmt ./...

# Vet code for issues
go vet ./...

# Tidy dependencies
go mod tidy
```

## Architecture

The project follows a **Root Orchestration + Capability Sub-packages** pattern:

- **Root package (`auth/`)**: Contains the main `Auth` struct, public API (SignIn, SignUp, etc.), HTTP handlers, and orchestrates sub-packages
- **Sub-packages are capabilities**: Each provides focused functionality with no cross-imports between siblings

### Package Structure

| Package | Responsibility |
|---------|---------------|
| `identity/` | User and Account models, password hashing (Argon2id) |
| `session/` | Session lifecycle, token storage (HMAC-SHA256 hashed), middleware |
| `token/` | Token generation, verification flows (email, password reset) |
| `oauth/` | OAuth2 providers and flow management |
| `ratelimit/` | Rate limiting with configurable stores |
| `plugin/` | Plugin system for extensions (TOTP, magic links, etc.) |

### Key Patterns

1. **Handlers are thin**: Parse request → call Auth method → write response
2. **Each sub-package owns its models**: User in identity/, Session in session/
3. **Hooks over event bus**: Synchronous hooks for extensibility
4. **Functional options for configuration**: `auth.New(db, auth.WithSecret(...), ...)`

## Security Requirements

- Passwords: Argon2id, 8-128 character length
- Tokens: 32-byte crypto/rand, stored as HMAC-SHA256 hashes
- Sessions: HttpOnly, Secure, SameSite=Lax cookies
- OAuth tokens: AES-256-GCM encrypted before storage
- CSRF: Synchronizer token pattern with constant-time comparison
- No user enumeration: Same response for "user not found" and "wrong password"

## Dependencies

Uses stdlib `net/http` (no web framework). Key dependencies:
- `gorm.io/gorm` - ORM
- `github.com/alexedwards/argon2id` - Password hashing
- `golang.org/x/oauth2` - OAuth2 client
