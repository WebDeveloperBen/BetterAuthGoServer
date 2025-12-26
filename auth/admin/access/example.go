// Package access provides an example of how to configure custom access control.
//
// This example demonstrates:
// 1. Creating custom statements with additional resources
// 2. Defining roles with specific permissions
// 3. Using the access control system in the admin plugin
//
// Example usage:
//
//	import (
//		"github.com/webdeveloperben/BetterAuthGoServer/auth/admin"
//		"github.com/webdeveloperben/BetterAuthGoServer/auth/admin/access"
//	)
//
//	// Create custom statement with project permissions
//	statement := access.Statement{
//		"user":    {"create", "list", "set-role", "ban", "impersonate", "delete", "set-password"},
//		"session": {"list", "revoke", "delete"},
//		"project": {"create", "share", "update", "delete"},
//	}
//
//	// Create access control
//	ac := access.NewAccessControl(statement)
//
//	// Create roles
//	adminRole, _ := ac.NewRole(access.Permissions{
//		"user":    {"create", "list", "set-role", "ban", "impersonate", "delete", "set-password"},
//		"session": {"list", "revoke", "delete"},
//		"project": {"create", "share", "update", "delete"},
//	})
//
//	userRole, _ := ac.NewRole(access.Permissions{
//		"user":    {"list"},
//		"project": {"create", "update"},
//	})
//
//	moderatorRole, _ := ac.NewRole(access.Permissions{
//		"user":    {"list", "ban"},
//		"session": {"list", "revoke"},
//		"project": {"create", "update"},
//	})
//
//	// Register roles
//	ac.RegisterRole("admin", adminRole)
//	ac.RegisterRole("user", userRole)
//	ac.RegisterRole("moderator", moderatorRole)
//
//	// Configure admin plugin with custom access control
//	adminPlugin := admin.NewPlugin(
//		admin.WithAccessControl(ac, map[string]*access.Role{
//			"admin":     adminRole,
//			"user":      userRole,
//			"moderator": moderatorRole,
//		}),
//	)
//
//	// Use in auth service
//	authService.Use(adminPlugin)
//
// Permission Checking:
//
//	// Check if user has permissions
//	hasPermission := ac.UserHasPermission("admin", access.PermissionChecks{
//		"project": {"create", "update"},
//	})
//
//	// Check role permissions
//	canCreateProject := adminRole.CheckRolePermission(access.PermissionChecks{
//		"project": {"create"},
//	})
//
// Middleware Usage:
//
//	// Require admin role (backwards compatible)
//	adminMw := admin.RequireAdmin(authProvider, logger)
//
//	// Require specific permissions
//	projectCreateMw := admin.RequirePermissions(authProvider, logger, map[string][]string{
//		"project": {"create"},
//	})
//
//	// Use in routes
//	route := plugin.Route{
//		Method:     "POST",
//		Path:       "/api/projects",
//		Handler:    createProjectHandler,
//		Middleware: []func(http.Handler) http.Handler{projectCreateMw},
//	}
package access
