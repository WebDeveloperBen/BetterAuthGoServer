package admin

import (
	"reflect"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/admin/access"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Check default values
	if config.DefaultRole != "user" {
		t.Errorf("DefaultRole = %q, want %q", config.DefaultRole, "user")
	}

	if len(config.AdminRoles) != 1 || config.AdminRoles[0] != "admin" {
		t.Errorf("AdminRoles = %v, want [admin]", config.AdminRoles)
	}

	if len(config.AdminUserIDs) != 0 {
		t.Errorf("AdminUserIDs should be empty, got %v", config.AdminUserIDs)
	}

	if config.ImpersonationSessionDuration != 1*time.Hour {
		t.Errorf("ImpersonationSessionDuration = %v, want 1h", config.ImpersonationSessionDuration)
	}

	if config.DefaultBanReason != "No reason" {
		t.Errorf("DefaultBanReason = %q, want %q", config.DefaultBanReason, "No reason")
	}

	expectedMessage := "You have been banned from this application. Please contact support if you believe this is an error."
	if config.BannedUserMessage != expectedMessage {
		t.Errorf("BannedUserMessage = %q, want %q", config.BannedUserMessage, expectedMessage)
	}

	if config.AllowImpersonatingAdmins != false {
		t.Error("AllowImpersonatingAdmins should be false")
	}

	// Access control should be nil by default
	if config.AccessControl != nil {
		t.Error("AccessControl should be nil by default")
	}

	if config.Roles != nil {
		t.Error("Roles should be nil by default")
	}
}

func TestWithAccessControl(t *testing.T) {
	ac := &access.AccessControl{}
	roles := map[string]*access.Role{"admin": {}}

	opt := WithAccessControl(ac, roles)

	config := DefaultConfig()
	opt(&config)

	if config.AccessControl != ac {
		t.Error("AccessControl not set correctly")
	}

	if !reflect.DeepEqual(config.Roles, roles) {
		t.Errorf("Roles not set correctly: got %v, want %v", config.Roles, roles)
	}
}

func TestWithDefaultRole(t *testing.T) {
	opt := WithDefaultRole("moderator")

	config := DefaultConfig()
	opt(&config)

	if config.DefaultRole != "moderator" {
		t.Errorf("DefaultRole = %q, want %q", config.DefaultRole, "moderator")
	}
}

func TestWithAdminRoles(t *testing.T) {
	roles := []string{"admin", "superadmin"}
	opt := WithAdminRoles(roles)

	config := DefaultConfig()
	opt(&config)

	if !reflect.DeepEqual(config.AdminRoles, roles) {
		t.Errorf("AdminRoles = %v, want %v", config.AdminRoles, roles)
	}
}

func TestWithAdminUserIDs(t *testing.T) {
	userIDs := []string{"user1", "user2"}
	opt := WithAdminUserIDs(userIDs)

	config := DefaultConfig()
	opt(&config)

	if !reflect.DeepEqual(config.AdminUserIDs, userIDs) {
		t.Errorf("AdminUserIDs = %v, want %v", config.AdminUserIDs, userIDs)
	}
}

func TestWithImpersonationSessionDuration(t *testing.T) {
	duration := 2 * time.Hour
	opt := WithImpersonationSessionDuration(duration)

	config := DefaultConfig()
	opt(&config)

	if config.ImpersonationSessionDuration != duration {
		t.Errorf("ImpersonationSessionDuration = %v, want %v", config.ImpersonationSessionDuration, duration)
	}
}

func TestWithDefaultBanReason(t *testing.T) {
	reason := "Violation of terms"
	opt := WithDefaultBanReason(reason)

	config := DefaultConfig()
	opt(&config)

	if config.DefaultBanReason != reason {
		t.Errorf("DefaultBanReason = %q, want %q", config.DefaultBanReason, reason)
	}
}

func TestWithDefaultBanExpiresIn(t *testing.T) {
	duration := 24 * time.Hour
	opt := WithDefaultBanExpiresIn(duration)

	config := DefaultConfig()
	opt(&config)

	if config.DefaultBanExpiresIn != duration {
		t.Errorf("DefaultBanExpiresIn = %v, want %v", config.DefaultBanExpiresIn, duration)
	}
}

func TestWithBannedUserMessage(t *testing.T) {
	message := "Custom ban message"
	opt := WithBannedUserMessage(message)

	config := DefaultConfig()
	opt(&config)

	if config.BannedUserMessage != message {
		t.Errorf("BannedUserMessage = %q, want %q", config.BannedUserMessage, message)
	}
}

func TestWithAllowImpersonatingAdmins(t *testing.T) {
	opt := WithAllowImpersonatingAdmins(true)

	config := DefaultConfig()
	opt(&config)

	if !config.AllowImpersonatingAdmins {
		t.Error("AllowImpersonatingAdmins should be true")
	}
}

func TestOptionsComposition(t *testing.T) {
	// Test that multiple options can be applied
	config := DefaultConfig()

	WithDefaultRole("moderator")(&config)
	WithAdminUserIDs([]string{"special"})(&config)
	WithAllowImpersonatingAdmins(true)(&config)

	if config.DefaultRole != "moderator" {
		t.Errorf("DefaultRole = %q, want %q", config.DefaultRole, "moderator")
	}

	if len(config.AdminUserIDs) != 1 || config.AdminUserIDs[0] != "special" {
		t.Errorf("AdminUserIDs = %v, want [special]", config.AdminUserIDs)
	}

	if !config.AllowImpersonatingAdmins {
		t.Error("AllowImpersonatingAdmins should be true")
	}
}
