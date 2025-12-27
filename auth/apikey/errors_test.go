package apikey_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/apikey"
)

func TestErrors_NotEmpty(t *testing.T) {
	testCases := []struct {
		err      error
		contains string
	}{
		{apikey.ErrInvalidAPIKey, "invalid api key"},
		{apikey.ErrExpiredAPIKey, "api key expired"},
		{apikey.ErrDisabledAPIKey, "api key disabled"},
		{apikey.ErrRateLimited, "rate limited"},
		{apikey.ErrNoRemainingUses, "no remaining uses"},
		{apikey.ErrInsufficientPerms, "insufficient permissions"},
		{apikey.ErrKeyNotFound, "key not found"},
		{apikey.ErrInvalidPrefix, "invalid prefix"},
		{apikey.ErrInvalidName, "invalid name"},
		{apikey.ErrUnauthorized, "unauthorized"},
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
		apikey.ErrInvalidAPIKey,
		apikey.ErrExpiredAPIKey,
		apikey.ErrDisabledAPIKey,
		apikey.ErrRateLimited,
		apikey.ErrNoRemainingUses,
		apikey.ErrInsufficientPerms,
		apikey.ErrKeyNotFound,
		apikey.ErrInvalidPrefix,
		apikey.ErrInvalidName,
		apikey.ErrUnauthorized,
	}

	for _, err := range allErrors {
		t.Run(err.Error(), func(t *testing.T) {
			if !strings.HasPrefix(err.Error(), "apikey:") {
				t.Errorf("error %q should have 'apikey:' prefix", err.Error())
			}
		})
	}
}

func TestErrors_AreDistinct(t *testing.T) {
	allErrors := []error{
		apikey.ErrInvalidAPIKey,
		apikey.ErrExpiredAPIKey,
		apikey.ErrDisabledAPIKey,
		apikey.ErrRateLimited,
		apikey.ErrNoRemainingUses,
		apikey.ErrInsufficientPerms,
		apikey.ErrKeyNotFound,
		apikey.ErrInvalidPrefix,
		apikey.ErrInvalidName,
		apikey.ErrUnauthorized,
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

func TestRateLimitError(t *testing.T) {
	err := &apikey.RateLimitError{RetryAfter: 5 * time.Second}

	if !strings.Contains(err.Error(), "rate limited") {
		t.Errorf("error message should contain 'rate limited': %q", err.Error())
	}
	if !strings.Contains(err.Error(), "5s") {
		t.Errorf("error message should contain retry duration: %q", err.Error())
	}
	if !errors.Is(err, apikey.ErrRateLimited) {
		t.Error("RateLimitError should unwrap to ErrRateLimited")
	}
}

func TestVerifyError(t *testing.T) {
	err := &apikey.VerifyError{
		Code:    "TEST_CODE",
		Message: "test message",
		Err:     apikey.ErrInvalidAPIKey,
	}

	if err.Error() != "test message" {
		t.Errorf("Error() should return message: got %q", err.Error())
	}
	if !errors.Is(err, apikey.ErrInvalidAPIKey) {
		t.Error("VerifyError should unwrap to wrapped error")
	}
}
