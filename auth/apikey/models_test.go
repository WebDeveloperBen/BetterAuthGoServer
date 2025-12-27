package apikey_test

import (
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey"
)

func TestPermissions_HasPermission(t *testing.T) {
	perms := apikey.Permissions{
		"files": {"read", "write"},
		"users": {"read"},
		"admin": {"*"},
	}

	tests := []struct {
		name     string
		resource string
		action   string
		expected bool
	}{
		{"files read allowed", "files", "read", true},
		{"files write allowed", "files", "write", true},
		{"files delete not allowed", "files", "delete", false},
		{"users read allowed", "users", "read", true},
		{"users write not allowed", "users", "write", false},
		{"admin wildcard allows anything", "admin", "anything", true},
		{"admin wildcard allows delete", "admin", "delete", true},
		{"unknown resource not allowed", "projects", "read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := perms.HasPermission(tt.resource, tt.action)
			if got != tt.expected {
				t.Errorf("HasPermission(%q, %q) = %v, want %v", tt.resource, tt.action, got, tt.expected)
			}
		})
	}
}

func TestPermissions_HasAllPermissions(t *testing.T) {
	perms := apikey.Permissions{
		"files": {"read", "write"},
		"users": {"read"},
	}

	tests := []struct {
		name     string
		required apikey.Permissions
		expected bool
	}{
		{
			name:     "single permission granted",
			required: apikey.Permissions{"files": {"read"}},
			expected: true,
		},
		{
			name:     "multiple permissions same resource granted",
			required: apikey.Permissions{"files": {"read", "write"}},
			expected: true,
		},
		{
			name:     "multiple resources granted",
			required: apikey.Permissions{"files": {"read"}, "users": {"read"}},
			expected: true,
		},
		{
			name:     "missing action not granted",
			required: apikey.Permissions{"files": {"read", "delete"}},
			expected: false,
		},
		{
			name:     "missing resource not granted",
			required: apikey.Permissions{"projects": {"read"}},
			expected: false,
		},
		{
			name:     "nil required returns true",
			required: nil,
			expected: true,
		},
		{
			name:     "empty required returns true",
			required: apikey.Permissions{},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := perms.HasAllPermissions(tt.required)
			if got != tt.expected {
				t.Errorf("HasAllPermissions() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPermissions_NilPermissions(t *testing.T) {
	var perms apikey.Permissions

	t.Run("nil permissions HasPermission returns false", func(t *testing.T) {
		if perms.HasPermission("files", "read") {
			t.Error("nil Permissions.HasPermission() should return false")
		}
	})

	t.Run("nil permissions HasAllPermissions with nil returns true", func(t *testing.T) {
		if !perms.HasAllPermissions(nil) {
			t.Error("nil Permissions.HasAllPermissions(nil) should return true")
		}
	})

	t.Run("nil permissions HasAllPermissions with required returns false", func(t *testing.T) {
		if perms.HasAllPermissions(apikey.Permissions{"files": {"read"}}) {
			t.Error("nil Permissions.HasAllPermissions(required) should return false")
		}
	})
}

func TestAPIKey_Fields(t *testing.T) {
	key := &apikey.APIKey{
		ID:               "key-123",
		UserID:           "user-456",
		Start:            "abc123",
		RateLimitEnabled: true,
		RateLimitMax:     100,
		Enabled:          true,
	}

	if key.ID != "key-123" {
		t.Errorf("ID = %q, want 'key-123'", key.ID)
	}
	if key.UserID != "user-456" {
		t.Errorf("UserID = %q, want 'user-456'", key.UserID)
	}
	if key.Start != "abc123" {
		t.Errorf("Start = %q, want 'abc123'", key.Start)
	}
	if !key.RateLimitEnabled {
		t.Error("RateLimitEnabled should be true")
	}
	if key.RateLimitMax != 100 {
		t.Errorf("RateLimitMax = %d, want 100", key.RateLimitMax)
	}
	if !key.Enabled {
		t.Error("Enabled should be true")
	}
}
