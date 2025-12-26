package access

// DefaultStatements defines the default resources and actions for organizations.
// These match the Better Auth organization plugin defaults.
var DefaultStatements = Statement{
	"organization": {"update", "delete"},
	"member":       {"create", "update", "delete"},
	"invitation":   {"create", "cancel"},
	"team":         {"create", "update", "delete"},
}

// CreateDefaultRoles creates the default organization roles.
func CreateDefaultRoles(ac *AccessControl) (owner, admin, member *Role, err error) {
	// Owner has all permissions
	owner, err = ac.NewRole(Permissions{
		"organization": {"update", "delete"},
		"member":       {"create", "update", "delete"},
		"invitation":   {"create", "cancel"},
		"team":         {"create", "update", "delete"},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// Admin has most permissions except deleting organization
	admin, err = ac.NewRole(Permissions{
		"organization": {"update"},
		"member":       {"create", "update", "delete"},
		"invitation":   {"create", "cancel"},
		"team":         {"create", "update", "delete"},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// Member has no permissions
	member, err = ac.NewRole(Permissions{})
	if err != nil {
		return nil, nil, nil, err
	}

	return owner, admin, member, nil
}

// CreateDefaultAccessControl creates an AccessControl with default statements and roles.
func CreateDefaultAccessControl() (*AccessControl, error) {
	ac := NewAccessControl(DefaultStatements)

	owner, admin, member, err := CreateDefaultRoles(ac)
	if err != nil {
		return nil, err
	}

	ac.RegisterRole("owner", owner)
	ac.RegisterRole("admin", admin)
	ac.RegisterRole("member", member)

	return ac, nil
}
