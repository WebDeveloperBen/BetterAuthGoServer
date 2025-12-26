# BetterAuth Examples

This directory contains runnable examples demonstrating different usage patterns.

## Examples

### basic/

The simplest setup with default plugins (rate limiting, CSRF). Good for most applications.

```bash
cd basic
go run main.go
```

### with-oauth/

Adds OAuth providers (Google, GitHub, Discord) and JWT support.

```bash
# Set OAuth credentials
export GOOGLE_CLIENT_ID=your-client-id
export GOOGLE_CLIENT_SECRET=your-client-secret
# (similar for GitHub, Discord)

cd with-oauth
go run main.go
```

### minimal/

Uses `WithoutDefaults()` for maximum control. No rate limiting or CSRF - suitable for API-only services or when you provide your own middleware.

```bash
cd minimal
go run main.go
```

### redis-ratelimit/

Demonstrates distributed rate limiting with Redis. Essential for clustered deployments where multiple instances need to share rate limit state.

```bash
# Start Redis
docker run -d -p 6379:6379 redis:alpine

# Run the example
cd redis-ratelimit
go run main.go
```

Without a shared backend like Redis, each instance tracks limits independently, allowing users to bypass limits by hitting different instances.

## Running Examples

Each example:
1. Uses SQLite for simplicity (creates `auth.db` in the example directory)
2. Listens on `:8080` by default (set `PORT` env var to change)
3. Uses a development secret (set `AUTH_SECRET` in production)

## Testing Endpoints

```bash
# Sign up
curl -X POST http://localhost:8080/auth/sign-up \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!", "name": "Test User"}'

# Sign in
curl -X POST http://localhost:8080/auth/sign-in \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "SecurePass123!"}' \
  -c cookies.txt

# Get profile (requires session cookie)
curl http://localhost:8080/auth/profile -b cookies.txt

# Sign out
curl -X POST http://localhost:8080/auth/sign-out -b cookies.txt
```
