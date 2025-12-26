// Package access provides access control for organization operations.
package access

// Statement defines the available resources and their actions for organizations.
type Statement map[string][]string

// Permissions defines the permissions for a specific role.
type Permissions map[string][]string

// Role represents a role with its assigned permissions.
type Role struct {
	Name        string
	Permissions Permissions
}

// AccessControl manages roles and permissions for organizations.
type AccessControl struct {
	statement Statement
	roles     map[string]*Role
}

// PermissionChecks represents multiple permission checks.
type PermissionChecks map[string][]string
