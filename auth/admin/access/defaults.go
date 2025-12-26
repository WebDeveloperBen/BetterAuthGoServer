package access

// DefaultStatements defines the default resources and actions.
// These match the Better Auth admin plugin defaults.
var DefaultStatements = Statement{
	"user": {
		"create",
		"list", 
		"set-role",
		"ban",
		"impersonate",
		"delete",
		"set-password",
	},
	"session": {
		"list",
		"revoke",
		"delete",
	},
}

// CreateDefaultRoles creates the default admin and user roles.
func CreateDefaultRoles(ac *AccessControl) (admin, user *Role, err error) {
	// Admin role has all permissions
	admin, err = ac.NewRole(Permissions{
		"user":    {"create", "list", "set-role", "ban", "impersonate", "delete", "set-password"},
		"session": {"list", "revoke", "delete"},
	})
	if err != nil {
		return nil, nil, err
	}

	// User role has no admin permissions
	user, err = ac.NewRole(Permissions{})
	if err != nil {
		return nil, nil, err
	}

	return admin, user, nil
}

// CreateDefaultAccessControl creates an AccessControl with default statements and roles.
func CreateDefaultAccessControl() (*AccessControl, error) {
	ac := NewAccessControl(DefaultStatements)
	
	admin, user, err := CreateDefaultRoles(ac)
	if err != nil {
		return nil, err
	}

	ac.RegisterRole("admin", admin)
	ac.RegisterRole("user", user)

	return ac, nil
}
