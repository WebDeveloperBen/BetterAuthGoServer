package webauthn

import (
	"errors"
	"strings"
	"testing"
)

func TestErrors_NotEmpty(t *testing.T) {
	testCases := []struct {
		err      error
		contains string
	}{
		{ErrNotConfigured, "not configured"},
		{ErrInvalidRequest, "invalid request"},
		{ErrInvalidResponse, "invalid response"},
		{ErrCredentialNotFound, "credential not found"},
		{ErrSessionNotFound, "session not found"},
		{ErrSessionExpired, "session expired"},
		{ErrUserNotAllowed, "user not allowed"},
		{ErrUserAlreadyExists, "user already exists"},
	}

	for _, tc := range testCases {
		t.Run(tc.err.Error(), func(t *testing.T) {
			if tc.err.Error() == "" {
				t.Error("error message should not be empty")
			}
			if !strings.Contains(tc.err.Error(), tc.contains) {
				t.Errorf("error %q should contain %q", tc.err.Error(), tc.contains)
			}
		})
	}
}

func TestErrors_HavePrefix(t *testing.T) {
	allErrors := []error{
		ErrNotConfigured,
		ErrInvalidRequest,
		ErrInvalidResponse,
		ErrCredentialNotFound,
		ErrSessionNotFound,
		ErrSessionExpired,
		ErrUserNotAllowed,
		ErrUserAlreadyExists,
	}

	for _, err := range allErrors {
		t.Run(err.Error(), func(t *testing.T) {
			if !strings.HasPrefix(err.Error(), "webauthn:") {
				t.Errorf("error %q should have 'webauthn:' prefix", err.Error())
			}
		})
	}
}

func TestErrors_AreDistinct(t *testing.T) {
	allErrors := []error{
		ErrNotConfigured,
		ErrInvalidRequest,
		ErrInvalidResponse,
		ErrCredentialNotFound,
		ErrSessionNotFound,
		ErrSessionExpired,
		ErrUserNotAllowed,
		ErrUserAlreadyExists,
	}

	seen := make(map[string]bool)
	for _, err := range allErrors {
		msg := err.Error()
		if seen[msg] {
			t.Errorf("duplicate error message: %q", msg)
		}
		seen[msg] = true
	}
}

func TestErrors_Is(t *testing.T) {
	// Verify errors.Is works correctly with wrapped errors
	wrapped := errors.New("wrapped: " + ErrNotConfigured.Error())

	// Should not match when not properly wrapped
	if errors.Is(wrapped, ErrNotConfigured) {
		t.Error("should not match unwrapped error")
	}
}
