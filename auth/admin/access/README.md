# Access Control Package

A flexible access control system for the BetterAuthGoServer admin plugin, providing fine-grained permission management.

## Overview

The access control system allows you to define resources, actions, and roles with granular permissions. It's designed to be highly flexible and extensible, similar to the Better Auth TypeScript implementation.

## Core Concepts

### Statement
A statement defines all available resources and their permitted actions:

```go
statement := access.Statement{
    "user":    {"create", "list", "set-role", "ban", "impersonate", "delete", "set-password"},
    "session": {"list", "revoke", "delete"},
    "project": {"create", "share", "update", "delete"},
}
```

### Roles
Roles define what permissions a user has for each resource:

```go
adminRole, _ := ac.NewRole(access.Permissions{
    "user":    {"create", "list", "set-role", "ban", "impersonate", "delete", "set-password"},
    "session": {"list", "revoke", "delete"},
    "project": {"create", "share", "update", "delete"},
})

userRole, _ := ac.NewRole(access.Permissions{
    "user":    {"list"},
    "project": {"create", "update"},
})
```

## Usage

### Basic Setup

```go
// Create access control with default Better Auth statements
ac, err := access.CreateDefaultAccessControl()
if err != nil {
    log.Fatal(err)
}

// Use with admin plugin
adminPlugin := admin.NewPlugin(
    admin.WithAccessControl(ac, map[string]*access.Role{
        "admin": adminRole,
        "user":  userRole,
    }),
)
```

### Custom Access Control

```go
// Define custom statement
statement := access.Statement{
    "project": {"create", "share", "update", "delete"},
    "invoice": {"create", "read", "update", "delete"},
    "user":    {"list", "ban"},
}

ac := access.NewAccessControl(statement)

// Create roles
adminRole, _ := ac.NewRole(access.Permissions{
    "project": {"create", "share", "update", "delete"},
    "invoice": {"create", "read", "update", "delete"},
    "user":    {"list", "ban"},
})

userRole, _ := ac.NewRole(access.Permissions{
    "project": {"create", "update"},
    "invoice": {"read"},
})
```

### Permission Checking

```go
// Check if a role has specific permissions
hasPermission, err := ac.HasPermission("admin", "project", []string{"create", "update"})

// Check user permissions (handles multiple comma-separated roles)
userHasPermission := ac.UserHasPermission("admin,user", access.PermissionChecks{
    "project": {"create"},
})

// Check role permissions directly
canCreate := adminRole.CheckRolePermission(access.PermissionChecks{
    "project": {"create"},
})
```

### Middleware

```go
// Require specific permissions
projectMw := admin.RequirePermissions(authProvider, logger, accessControl, map[string][]string{
    "project": {"create"},
})

// Require admin permissions (convenience wrapper)
adminMw := admin.RequireAdmin(authProvider, logger, accessControl)
```

## API Endpoints

The admin plugin provides API endpoints for permission checking:

### Check User Permissions
```http
POST /admin/permissions/has-permission
Content-Type: application/json

{
  "userId": "user-123",
  "permissions": {
    "project": ["create", "update"]
  }
}
```

### Check Role Permissions
```http
POST /admin/permissions/check-role
Content-Type: application/json

{
  "role": "admin",
  "permissions": {
    "project": ["create"]
  }
}
```

## Default Better Auth Resources

The default access control includes these resources matching Better Auth:

- **user**: create, list, set-role, ban, impersonate, delete, set-password
- **session**: list, revoke, delete

## Best Practices

1. **Define statements first**: Always define your complete statement before creating roles
2. **Validate permissions**: The system validates that role permissions are subsets of the statement
3. **Use descriptive names**: Use clear, descriptive resource and action names
4. **Test thoroughly**: Permission systems are security-critical - test all combinations
5. **Start restrictive**: Grant minimal permissions and expand as needed

## Error Handling

The system provides clear error messages for common issues:

- Undefined resources in roles
- Undefined actions for resources
- Non-existent roles during permission checks

## Security Considerations

- Permission checks should be performed server-side only
- Client-side permission checks should be considered hints, not authoritative
- Always validate permissions before performing sensitive operations
- Log permission check failures for security monitoring
