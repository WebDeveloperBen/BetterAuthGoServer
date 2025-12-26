package access

import (
	"testing"
)

func TestNewAccessControl(t *testing.T) {
	statement := Statement{
		"user":    {"create", "read", "update"},
		"project": {"create", "delete"},
	}

	ac := NewAccessControl(statement)
	if ac == nil {
		t.Fatal("NewAccessControl returned nil")
	}

	if len(ac.statement) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(ac.statement))
	}
}

func TestNewRole(t *testing.T) {
	statement := Statement{
		"user":    {"create", "read", "update"},
		"project": {"create", "delete"},
	}

	ac := NewAccessControl(statement)

	// Valid role
	role, err := ac.NewRole(Permissions{
		"user":    {"create", "read"},
		"project": {"create"},
	})
	if err != nil {
		t.Fatalf("NewRole failed: %v", err)
	}
	if role == nil {
		t.Fatal("NewRole returned nil role")
	}

	// Invalid role - undefined resource
	_, err = ac.NewRole(Permissions{
		"invalid": {"action"},
	})
	if err == nil {
		t.Fatal("NewRole should have failed for undefined resource")
	}

	// Invalid role - undefined action
	_, err = ac.NewRole(Permissions{
		"user": {"invalid"},
	})
	if err == nil {
		t.Fatal("NewRole should have failed for undefined action")
	}
}

func TestRegisterRole(t *testing.T) {
	ac := NewAccessControl(Statement{"user": {"read"}})
	role, _ := ac.NewRole(Permissions{"user": {"read"}})

	ac.RegisterRole("test", role)

	retrieved, err := ac.GetRole("test")
	if err != nil {
		t.Fatalf("GetRole failed: %v", err)
	}
	if retrieved != role {
		t.Fatal("Retrieved role doesn't match registered role")
	}
}

func TestHasPermission(t *testing.T) {
	ac := NewAccessControl(Statement{
		"user": {"create", "read", "update"},
	})

	role, _ := ac.NewRole(Permissions{
		"user": {"create", "read"},
	})
	ac.RegisterRole("test", role)

	// Test positive case
	hasPerm, err := ac.HasPermission("test", "user", []string{"create"})
	if err != nil {
		t.Fatalf("HasPermission failed: %v", err)
	}
	if !hasPerm {
		t.Fatal("Expected permission to be granted")
	}

	// Test negative case - missing permission
	hasPerm, err = ac.HasPermission("test", "user", []string{"update"})
	if err != nil {
		t.Fatalf("HasPermission failed: %v", err)
	}
	if hasPerm {
		t.Fatal("Expected permission to be denied")
	}

	// Test negative case - missing resource
	hasPerm, err = ac.HasPermission("test", "project", []string{"create"})
	if err != nil {
		t.Fatalf("HasPermission failed: %v", err)
	}
	if hasPerm {
		t.Fatal("Expected permission to be denied for missing resource")
	}
}

func TestUserHasPermission(t *testing.T) {
	ac := NewAccessControl(Statement{
		"user": {"create", "read"},
	})

	role, _ := ac.NewRole(Permissions{
		"user": {"create", "read"},
	})
	ac.RegisterRole("admin", role)

	// Test single role
	hasPerm := ac.UserHasPermission("admin", PermissionChecks{
		"user": {"create"},
	})
	if !hasPerm {
		t.Fatal("Expected permission for admin role")
	}

	// Test multiple roles (comma-separated)
	hasPerm = ac.UserHasPermission("user,admin", PermissionChecks{
		"user": {"create"},
	})
	if !hasPerm {
		t.Fatal("Expected permission with multiple roles")
	}

	// Test no permission
	hasPerm = ac.UserHasPermission("user", PermissionChecks{
		"user": {"create"},
	})
	if hasPerm {
		t.Fatal("Expected no permission for user role")
	}
}

func TestRoleCheckRolePermission(t *testing.T) {
	ac := NewAccessControl(Statement{
		"user": {"create", "read", "update"},
	})

	role, _ := ac.NewRole(Permissions{
		"user": {"create", "read"},
	})

	// Test positive case
	hasPerm := role.CheckRolePermission(PermissionChecks{
		"user": {"create"},
	})
	if !hasPerm {
		t.Fatal("Expected permission to be granted")
	}

	// Test multiple permissions
	hasPerm = role.CheckRolePermission(PermissionChecks{
		"user": {"create", "read"},
	})
	if !hasPerm {
		t.Fatal("Expected multiple permissions to be granted")
	}

	// Test negative case
	hasPerm = role.CheckRolePermission(PermissionChecks{
		"user": {"update"},
	})
	if hasPerm {
		t.Fatal("Expected permission to be denied")
	}
}

func TestCreateDefaultAccessControl(t *testing.T) {
	ac, err := CreateDefaultAccessControl()
	if err != nil {
		t.Fatalf("CreateDefaultAccessControl failed: %v", err)
	}
	if ac == nil {
		t.Fatal("CreateDefaultAccessControl returned nil")
	}

	// Check default roles exist
	adminRole, err := ac.GetRole("admin")
	if err != nil {
		t.Fatalf("Default admin role not found: %v", err)
	}
	if adminRole == nil {
		t.Fatal("Admin role is nil")
	}

	userRole, err := ac.GetRole("user")
	if err != nil {
		t.Fatalf("Default user role not found: %v", err)
	}
	if userRole == nil {
		t.Fatal("User role is nil")
	}
}
