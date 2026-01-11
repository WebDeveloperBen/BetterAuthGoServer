# Future Extensibility Plan

## Overview

This document outlines a future enhancement to allow SDK users to extend database tables with custom columns, similar to [better-auth.com](https://better-auth.com).

## Goal

Allow users to add custom columns to SDK-managed tables without forking the SDK:

```go
auth.New(db,
    auth.WithUserFields(map[string]string{
        "company_id":  "TEXT",
        "department":  "TEXT NOT NULL DEFAULT ''",
        "employee_id": "TEXT",
    }),
    auth.WithOrganizationFields(map[string]string{
        "billing_plan":    "TEXT",
        "stripe_customer": "TEXT",
    }),
    auth.WithSessionFields(map[string]string{
        "device_fingerprint": "TEXT",
    }),
)
```

## Design Principles

1. **SDK ignores custom columns** - The SDK never reads or writes to user-defined columns
2. **Nullable or with defaults** - Custom columns must be nullable or have defaults (SDK INSERT statements won't include them)
3. **User manages their data** - Users query/update custom columns with their own code
4. **Migration-safe** - Custom columns survive SDK upgrades

## Implementation Approach

### Phase 1: Schema Extension

Store custom field definitions and apply them during migrations:

```go
type SchemaExtension struct {
    Table   string            // "users", "organizations", etc.
    Columns map[string]string // column_name -> SQL type definition
}

type Config struct {
    // ... existing fields
    SchemaExtensions []SchemaExtension
}

func WithUserFields(fields map[string]string) Option {
    return func(c *Config) {
        c.SchemaExtensions = append(c.SchemaExtensions, SchemaExtension{
            Table:   "users",
            Columns: fields,
        })
    }
}
```

### Phase 2: Dynamic Migration

During `Migrate()`, after creating base tables, add custom columns:

```go
func (s *Store) Migrate(ctx context.Context) error {
    // 1. Run base migrations (sqlc schemas)
    if err := s.runBaseMigrations(ctx); err != nil {
        return err
    }

    // 2. Apply schema extensions
    for _, ext := range s.config.SchemaExtensions {
        for colName, colType := range ext.Columns {
            // ALTER TABLE ADD COLUMN IF NOT EXISTS
            sql := fmt.Sprintf(
                "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s",
                ext.Table, colName, colType,
            )
            if _, err := s.db.ExecContext(ctx, sql); err != nil {
                // Ignore "column already exists" errors
                if !isColumnExistsError(err) {
                    return err
                }
            }
        }
    }

    return nil
}
```

### Phase 3: Query Helpers (Optional)

Provide helpers for users to work with their custom fields:

```go
// Generic update for custom fields
func (s *Store) UpdateUserFields(ctx context.Context, userID string, fields map[string]any) error {
    // Build dynamic UPDATE statement
    // Only allows updating columns defined in SchemaExtensions
}

// Get user with custom fields as map
func (s *Store) GetUserWithFields(ctx context.Context, userID string) (*User, map[string]any, error) {
    // SELECT * including custom columns
    // Return base User + map of custom field values
}
```

## Supported Tables

Tables that should support extension:

| Table | Option Function | Use Cases |
|-------|-----------------|-----------|
| `users` | `WithUserFields()` | company_id, department, employee_id, preferences |
| `organizations` | `WithOrganizationFields()` | billing_plan, stripe_id, settings |
| `sessions` | `WithSessionFields()` | device_fingerprint, geo_location |
| `accounts` | `WithAccountFields()` | provider-specific metadata |
| `members` | `WithMemberFields()` | org-specific member data |

## Constraints

1. **Column names** - Must not conflict with existing SDK columns
2. **Types** - Must be valid SQL types for both PostgreSQL and SQLite
3. **Nullability** - Must be `NULL` or have `DEFAULT` value
4. **No foreign keys** - SDK won't manage FK relationships for custom columns
5. **No indexes** - Users must create their own indexes if needed

## Example Usage

```go
// Initialize with custom fields
a, err := auth.New(db,
    auth.WithSecret("..."),
    auth.WithUserFields(map[string]string{
        "company_id": "TEXT",
        "role_level": "INTEGER DEFAULT 0",
    }),
)

// SDK operations work normally
user, err := a.CreateUser(ctx, auth.CreateUserInput{
    Email: "user@example.com",
    Name:  "John Doe",
})

// User updates custom fields directly
_, err = db.ExecContext(ctx,
    "UPDATE users SET company_id = ?, role_level = ? WHERE id = ?",
    "company-123", 5, user.ID,
)

// User queries with custom fields
row := db.QueryRowContext(ctx,
    "SELECT id, email, name, company_id, role_level FROM users WHERE id = ?",
    user.ID,
)
```

## Alternative: Type-Safe Extension (Advanced)

For users who want compile-time type safety, they could generate their own types:

```go
// User defines their extended type
type MyUser struct {
    auth.User
    CompanyID  *string `db:"company_id"`
    RoleLevel  int     `db:"role_level"`
}

// User creates a typed store wrapper
type MyStore struct {
    *auth.Store
}

func (s *MyStore) GetMyUser(ctx context.Context, id string) (*MyUser, error) {
    // Custom query that includes extended fields
}
```

## Migration Path

1. **v1.x** - Current: No extension support, use metadata columns or separate tables
2. **v2.0** - Add `WithXxxFields()` options and dynamic ALTER TABLE
3. **v2.1** - Add query helpers for custom fields
4. **v3.0** - Consider code generation for type-safe extended models

## SQLite vs PostgreSQL Considerations

```sql
-- PostgreSQL: ADD COLUMN IF NOT EXISTS (native)
ALTER TABLE users ADD COLUMN IF NOT EXISTS company_id TEXT;

-- SQLite: No IF NOT EXISTS, need to check schema first
-- Check if column exists:
SELECT COUNT(*) FROM pragma_table_info('users') WHERE name = 'company_id';
-- Then conditionally add
```

## References

- [better-auth.com](https://better-auth.com) - JavaScript auth library with similar extensibility
- [Lucia Auth](https://lucia-auth.com) - Another approach to extensible auth

## Status

**NOT IMPLEMENTED** - This is a future enhancement proposal.

Current workarounds:
1. Use `metadata` JSON columns where available
2. Create separate extension tables with foreign keys
3. Use `RawDB` for custom migrations and queries
