# Database Schema Guide

## Overview

BetterAuth uses a **"schema as contract"** approach:

- **You own the schema** - The SDK never creates or modifies tables automatically
- **SDK expects tables to exist** - It runs queries against your database assuming the schema is correct
- **Migrations are optional** - Use the SDK-provided SQL files or manage schema yourself

This gives you full control over your database while ensuring the SDK works correctly.

## Quick Start

### Option A: Use SDK Schema Files

Copy the SQL schema files from the SDK and run them with your preferred migration tool:

```bash
# Core tables (required)
db/schema/postgres/001_users.sql
db/schema/postgres/002_accounts.sql
db/schema/postgres/003_sessions.sql
db/schema/postgres/004_verifications.sql

# Plugin tables (only for plugins you use)
auth/oauth/db/schema/postgres/001_oauth.sql
auth/jwt/db/schema/postgres/001_jwt.sql
auth/organization/db/schema/postgres/001_organizations.sql
# ... etc
```

### Option B: Create Schema Manually

Create tables that match the expected structure. As long as the required columns exist with correct types, the SDK will work.

## Core Tables

These tables are required for basic authentication:

### users

```sql
-- PostgreSQL
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    name TEXT NOT NULL,
    image TEXT,
    role TEXT DEFAULT 'user',
    banned BOOLEAN DEFAULT FALSE,
    banned_at TIMESTAMPTZ,
    ban_reason TEXT,
    is_anonymous BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- MySQL
CREATE TABLE users (
    id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    name VARCHAR(255) NOT NULL,
    image TEXT,
    role VARCHAR(50) DEFAULT 'user',
    banned BOOLEAN DEFAULT FALSE,
    banned_at TIMESTAMP NULL,
    ban_reason TEXT,
    is_anonymous BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL
);

-- SQLite
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    email_verified INTEGER DEFAULT 0,
    name TEXT NOT NULL,
    image TEXT,
    role TEXT DEFAULT 'user',
    banned INTEGER DEFAULT 0,
    banned_at TEXT,
    ban_reason TEXT,
    is_anonymous INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
```

### accounts

```sql
-- PostgreSQL
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_account_id TEXT,
    password_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE(user_id, provider)
);

-- MySQL
CREATE TABLE accounts (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    provider VARCHAR(100) NOT NULL,
    provider_account_id VARCHAR(255),
    password_hash TEXT,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    UNIQUE(user_id, provider),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- SQLite
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    provider_account_id TEXT,
    password_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(user_id, provider),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### sessions

```sql
-- PostgreSQL
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    impersonated_by TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    last_used TIMESTAMPTZ NOT NULL
);

-- MySQL
CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    impersonated_by VARCHAR(255),
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    last_used TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- SQLite
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    impersonated_by TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
```

### verifications

```sql
-- PostgreSQL
CREATE TABLE verifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    type TEXT NOT NULL,
    identifier TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

-- MySQL
CREATE TABLE verifications (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    type VARCHAR(50) NOT NULL,
    identifier VARCHAR(255),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL
);

-- SQLite
CREATE TABLE verifications (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    type TEXT NOT NULL,
    identifier TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
```

## Plugin Tables

Each plugin has its own schema. Only create tables for plugins you use.

| Plugin | Schema Location | Tables |
|--------|-----------------|--------|
| OAuth | `auth/oauth/db/schema/` | `oauth_states`, `oauth_accounts` |
| OTP | `auth/otp/db/schema/` | `otp_tokens` |
| JWT | `auth/jwt/db/schema/` | `jwt_keys`, `jwt_revoked_tokens` |
| WebAuthn | `auth/webauthn/db/schema/` | `webauthn_credentials`, `webauthn_sessions` |
| API Keys | `auth/apikey/db/schema/` | `api_keys` |
| Device Auth | `auth/deviceauth/db/schema/` | `device_codes` |
| Organization | `auth/organization/db/schema/` | `organizations`, `members`, `invitations`, `teams`, `team_members` |

## Custom Columns

**Need custom columns? Just add them to your schema.**

The SDK only reads/writes its own columns and ignores any additional columns you add.

### Example: Adding Custom User Fields

```sql
-- Add your own columns to the users table
ALTER TABLE users ADD COLUMN company_id TEXT;
ALTER TABLE users ADD COLUMN department TEXT;
ALTER TABLE users ADD COLUMN employee_number TEXT;
ALTER TABLE users ADD COLUMN preferences JSONB;
```

### Rules for Custom Columns

1. **Must be nullable or have defaults** - The SDK's INSERT statements won't include your columns
2. **Use any valid SQL type** - TEXT, INTEGER, JSONB, etc.
3. **Add indexes as needed** - The SDK won't manage indexes for your columns
4. **Query with RawDB** - Use the raw database connection to read/write your columns

### Querying Custom Columns

```go
// Get raw DB connection
rawDB := authService.DB()

// Query your custom columns
var companyID, department string
err := rawDB.QueryRowContext(ctx,
    "SELECT company_id, department FROM users WHERE id = $1",
    userID,
).Scan(&companyID, &department)

// Update your custom columns
_, err = rawDB.ExecContext(ctx,
    "UPDATE users SET company_id = $1, department = $2 WHERE id = $3",
    "acme-corp", "engineering", userID,
)
```

## Version Upgrades

When a new SDK version changes the schema, we provide migration files:

```
db/migrations/
├── postgres/
│   ├── v1.0.0_to_v1.1.0.sql
│   └── v1.1.0_to_v1.2.0.sql
└── sqlite/
    └── ...
```

### Upgrade Process

1. Check the release notes for schema changes
2. Review the migration SQL
3. Run with your migration tool (goose, golang-migrate, etc.)
4. Or apply manually if you prefer

### Example Migration

```sql
-- v1.1.0_to_v1.2.0.sql
-- Adds new column for feature X

ALTER TABLE users ADD COLUMN IF NOT EXISTS new_feature_flag BOOLEAN DEFAULT FALSE;
```

## Type Differences: PostgreSQL vs MySQL vs SQLite

| Concept | PostgreSQL | MySQL | SQLite |
|---------|------------|-------|--------|
| Boolean | `BOOLEAN` | `BOOLEAN` | `INTEGER` (0/1) |
| Timestamp | `TIMESTAMPTZ` | `TIMESTAMP` | `TEXT` (RFC3339) |
| Timestamp with timezone | `TIMESTAMPTZ` | `TIMESTAMP` (UTC) | `TEXT` (RFC3339) |
| Variable text | `TEXT` | `VARCHAR(n)` | `TEXT` |
| JSON | `JSONB` | `JSON` | `TEXT` |
| Auto-increment | `SERIAL` | `INT AUTO_INCREMENT` | `INTEGER PRIMARY KEY` |

**Important MySQL notes:**
- Use `parseTime=true` in connection string for proper timestamp handling
- `VARCHAR` lengths must be specified (e.g., `VARCHAR(255)`)
- `TEXT` columns cannot have default values in some MySQL versions

The SDK handles these differences internally - just use the correct types for your database.

## Indexes

The SDK schema files include recommended indexes. Add more based on your query patterns:

```sql
-- Example: If you frequently query by company_id
CREATE INDEX idx_users_company_id ON users(company_id);

-- Example: If you query sessions by user frequently
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
```

## Foreign Keys

- **PostgreSQL**: Foreign keys are enforced by default
- **SQLite**: Enable with `PRAGMA foreign_keys = ON`

```go
// For SQLite, enable foreign keys after connecting
db.Exec("PRAGMA foreign_keys = ON")
```

## Troubleshooting

### "column X does not exist"

Your schema is missing a column the SDK expects. Check the schema files and add the missing column.

### "relation X does not exist"

The table doesn't exist. Run the schema creation SQL for the missing table.

### "duplicate key value violates unique constraint"

You're trying to insert a duplicate. This is application logic, not a schema issue.

## Summary

| Aspect | Approach |
|--------|----------|
| Schema creation | You run the SQL (SDK provides files) |
| Schema modifications | You control it |
| Custom columns | Just add them |
| Version upgrades | SDK provides migration SQL |
| Runtime behavior | SDK queries existing tables |
