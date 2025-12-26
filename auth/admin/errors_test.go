package admin

import (
	"errors"
	"testing"
)

func TestErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrUserNotFound", ErrUserNotFound, "admin: user not found"},
		{"ErrInvalidRequest", ErrInvalidRequest, "admin: invalid request"},
		{"ErrAdminNotSupported", ErrAdminNotSupported, "admin: operations not supported by store"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error should not be nil")
			}
			if tt.err.Error() != tt.want {
				t.Errorf("got %q, want %q", tt.err.Error(), tt.want)
			}
		})
	}
}

func TestErrorComparisons(t *testing.T) {
	// Test that errors.Is works correctly
	testErr := errors.New("test error")

	if errors.Is(ErrUserNotFound, testErr) {
		t.Error("ErrUserNotFound should not be testErr")
	}

	if !errors.Is(ErrUserNotFound, ErrUserNotFound) {
		t.Error("ErrUserNotFound should be ErrUserNotFound")
	}
}
