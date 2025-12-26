// Package access provides a flexible access control system for the admin plugin.
// It allows defining resources, actions, and roles with granular permissions.
package access

// Statement defines the available resources and their actions.
// It maps resource names to slices of allowed actions.
type Statement map[string][]string

// Permissions defines the permissions for a specific role.
// It maps resource names to slices of allowed actions for that role.
type Permissions map[string][]string

// Role represents a role with its assigned permissions.
// It contains the role name and the permissions it grants.
type Role struct {
	Name        string
	Permissions Permissions
}

// AccessControl manages roles and permissions.
// It provides methods to create roles and check permissions.
type AccessControl struct {
	statement Statement
	roles     map[string]*Role
}

// PermissionChecks represents multiple permission checks.
// It maps resources to their required actions.
type PermissionChecks map[string][]string
