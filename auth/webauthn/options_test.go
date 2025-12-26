package webauthn

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.Timeout != 5*time.Minute {
		t.Errorf("expected timeout 5m, got %v", config.Timeout)
	}
	if !config.AllowSecondFactor {
		t.Error("expected AllowSecondFactor to be true")
	}
	if config.AllowPasswordlessAccounts {
		t.Error("expected AllowPasswordlessAccounts to be false")
	}
	if config.Debug {
		t.Error("expected Debug to be false")
	}
}

func TestWithRPID(t *testing.T) {
	config := DefaultConfig()
	WithRPID("example.com")(&config)

	if config.RPID != "example.com" {
		t.Errorf("expected RPID 'example.com', got %q", config.RPID)
	}
}

func TestWithRPDisplayName(t *testing.T) {
	config := DefaultConfig()
	WithRPDisplayName("My App")(&config)

	if config.RPDisplayName != "My App" {
		t.Errorf("expected RPDisplayName 'My App', got %q", config.RPDisplayName)
	}
}

func TestWithRPOrigins(t *testing.T) {
	config := DefaultConfig()
	origins := []string{"https://example.com", "https://app.example.com"}
	WithRPOrigins(origins)(&config)

	if len(config.RPOrigins) != 2 {
		t.Errorf("expected 2 origins, got %d", len(config.RPOrigins))
	}
	if config.RPOrigins[0] != "https://example.com" {
		t.Errorf("expected first origin 'https://example.com', got %q", config.RPOrigins[0])
	}
}

func TestWithAttestationPreference(t *testing.T) {
	config := DefaultConfig()
	WithAttestationPreference("direct")(&config)

	if config.AttestationPreference != "direct" {
		t.Errorf("expected AttestationPreference 'direct', got %q", config.AttestationPreference)
	}
}

func TestWithUserVerification(t *testing.T) {
	config := DefaultConfig()
	WithUserVerification("required")(&config)

	if config.UserVerification != "required" {
		t.Errorf("expected UserVerification 'required', got %q", config.UserVerification)
	}
}

func TestWithTimeout(t *testing.T) {
	config := DefaultConfig()
	WithTimeout(10 * time.Minute)(&config)

	if config.Timeout != 10*time.Minute {
		t.Errorf("expected timeout 10m, got %v", config.Timeout)
	}
}

func TestWithAllowResidentKey(t *testing.T) {
	config := DefaultConfig()
	WithAllowResidentKey(true)(&config)

	if !config.AllowResidentKey {
		t.Error("expected AllowResidentKey to be true")
	}
}

func TestWithAllowPasswordlessAccounts(t *testing.T) {
	config := DefaultConfig()
	WithAllowPasswordlessAccounts(true)(&config)

	if !config.AllowPasswordlessAccounts {
		t.Error("expected AllowPasswordlessAccounts to be true")
	}
}

func TestWithAllowSecondFactor(t *testing.T) {
	config := DefaultConfig()
	WithAllowSecondFactor(false)(&config)

	if config.AllowSecondFactor {
		t.Error("expected AllowSecondFactor to be false")
	}
}

func TestWithDebug(t *testing.T) {
	config := DefaultConfig()
	WithDebug(true)(&config)

	if !config.Debug {
		t.Error("expected Debug to be true")
	}
}

func TestWithBaseURL(t *testing.T) {
	config := DefaultConfig()
	WithBaseURL("https://example.com")(&config)

	if config.BaseURL != "https://example.com" {
		t.Errorf("expected BaseURL 'https://example.com', got %q", config.BaseURL)
	}
}
