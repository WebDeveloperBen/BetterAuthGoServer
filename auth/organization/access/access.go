package access

import (
	"fmt"
	"slices"
	"strings"
)

// NewAccessControl creates a new AccessControl instance with the given statement.
func NewAccessControl(statement Statement) *AccessControl {
	return &AccessControl{
		statement: statement,
		roles:     make(map[string]*Role),
	}
}

// NewRole creates a new role with the specified permissions.
func (ac *AccessControl) NewRole(permissions Permissions) (*Role, error) {
	// Validate permissions against the statement
	for resource, actions := range permissions {
		availableActions, exists := ac.statement[resource]
		if !exists {
			return nil, fmt.Errorf("resource '%s' not defined in statement", resource)
		}

		for _, action := range actions {
			if !contains(availableActions, action) {
				return nil, fmt.Errorf("action '%s' not allowed for resource '%s'", action, resource)
			}
		}
	}

	role := &Role{
		Permissions: permissions,
	}

	return role, nil
}

// RegisterRole registers a role with a name.
func (ac *AccessControl) RegisterRole(name string, role *Role) {
	role.Name = name
	ac.roles[name] = role
}

// GetRole returns a registered role by name.
func (ac *AccessControl) GetRole(name string) (*Role, error) {
	role, exists := ac.roles[name]
	if !exists {
		return nil, fmt.Errorf("role '%s' not found", name)
	}
	return role, nil
}

// HasPermission checks if a role has the specified permission.
func (ac *AccessControl) HasPermission(roleName string, resource string, actions []string) (bool, error) {
	role, err := ac.GetRole(roleName)
	if err != nil {
		return false, err
	}

	roleActions, hasResource := role.Permissions[resource]
	if !hasResource {
		return false, nil
	}

	for _, action := range actions {
		if !contains(roleActions, action) {
			return false, nil
		}
	}

	return true, nil
}

// HasPermissions checks if a role has all the specified permissions.
func (ac *AccessControl) HasPermissions(roleName string, checks PermissionChecks) (bool, error) {
	for resource, actions := range checks {
		hasPerm, err := ac.HasPermission(roleName, resource, actions)
		if err != nil {
			return false, err
		}
		if !hasPerm {
			return false, nil
		}
	}
	return true, nil
}

// UserHasPermission checks if a user has the specified permissions based on their role.
// The user's role is passed as a string (can be comma-separated for multiple roles).
func (ac *AccessControl) UserHasPermission(userRole string, checks PermissionChecks) bool {
	// Handle multiple roles (comma-separated)
	roles := strings.SplitSeq(userRole, ",")
	for role := range roles {
		role = strings.TrimSpace(role)
		if role == "" {
			continue
		}

		hasPerm, err := ac.HasPermissions(role, checks)
		if err == nil && hasPerm {
			return true
		}
	}
	return false
}

// CheckRolePermission checks if a role has specific permissions.
func (r *Role) CheckRolePermission(checks PermissionChecks) bool {
	for resource, requiredActions := range checks {
		roleActions, hasResource := r.Permissions[resource]
		if !hasResource {
			return false
		}

		for _, action := range requiredActions {
			if !contains(roleActions, action) {
				return false
			}
		}
	}
	return true
}

// GetStatement returns the access control statement.
func (ac *AccessControl) GetStatement() Statement {
	return ac.statement
}

// contains checks if a slice contains a string.
func contains(slice []string, item string) bool {
	return slices.Contains(slice, item)
}
