package admin

import (
	"reflect"
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func TestAdminUserUpdates_Type(t *testing.T) {
	// Test that AdminUserUpdates has pointer fields
	var updates AdminUserUpdates

	// Should be able to set pointers
	name := "test"
	email := "test@example.com"
	role := "admin"

	updates.Name = &name
	updates.Email = &email
	updates.Role = &role

	if updates.Name == nil || *updates.Name != "test" {
		t.Error("Name field not set correctly")
	}
	if updates.Email == nil || *updates.Email != "test@example.com" {
		t.Error("Email field not set correctly")
	}
	if updates.Role == nil || *updates.Role != "admin" {
		t.Error("Role field not set correctly")
	}
}

func TestTypeAliases(t *testing.T) {
	// Test that type aliases work correctly
	var opts ListUsersOptions
	var result ListUsersResult

	// These should be the same as the models types
	if reflect.TypeOf(opts) != reflect.TypeOf(models.ListUsersOptions{}) {
		t.Error("ListUsersOptions type alias not working")
	}

	if reflect.TypeOf(result) != reflect.TypeOf(models.ListUsersResult{}) {
		t.Error("ListUsersResult type alias not working")
	}
}

// Interface compliance is checked at compile time with:
// var _ AdminOperations = (*Service)(nil)
