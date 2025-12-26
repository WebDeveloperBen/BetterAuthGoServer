package webauthn

import (
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestWebauthnUser_Interface(t *testing.T) {
	user := &plugin.User{
		ID:    "user-123",
		Email: "test@example.com",
		Name:  "Test User",
	}

	webUser := &webauthnUser{
		user:        user,
		credentials: nil,
	}

	if string(webUser.WebAuthnID()) != "user-123" {
		t.Errorf("WebAuthnID() = %q, want 'user-123'", string(webUser.WebAuthnID()))
	}
	if webUser.WebAuthnName() != "test@example.com" {
		t.Errorf("WebAuthnName() = %q, want 'test@example.com'", webUser.WebAuthnName())
	}
	if webUser.WebAuthnDisplayName() != "Test User" {
		t.Errorf("WebAuthnDisplayName() = %q, want 'Test User'", webUser.WebAuthnDisplayName())
	}
	if webUser.WebAuthnIcon() != "" {
		t.Errorf("WebAuthnIcon() = %q, want empty string", webUser.WebAuthnIcon())
	}
	if len(webUser.WebAuthnCredentials()) != 0 {
		t.Errorf("WebAuthnCredentials() len = %d, want 0", len(webUser.WebAuthnCredentials()))
	}
}

func TestWebauthnUser_NilUser(t *testing.T) {
	webUser := &webauthnUser{user: nil}

	if webUser.WebAuthnID() != nil {
		t.Error("expected nil WebAuthnID for nil user")
	}
	if webUser.WebAuthnName() != "" {
		t.Error("expected empty WebAuthnName for nil user")
	}
	if webUser.WebAuthnDisplayName() != "" {
		t.Error("expected empty WebAuthnDisplayName for nil user")
	}
}

func TestSessionTimeout(t *testing.T) {
	tests := []struct {
		name     string
		timeout  time.Duration
		expected time.Duration
	}{
		{"custom timeout", 10 * time.Minute, 10 * time.Minute},
		{"zero timeout uses default", 0, 5 * time.Minute},
		{"negative timeout uses default", -1 * time.Minute, 5 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Service{config: Config{Timeout: tt.timeout}}
			if got := s.sessionTimeout(); got != tt.expected {
				t.Errorf("sessionTimeout() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestApplyBaseURLDefaults(t *testing.T) {
	tests := []struct {
		name            string
		baseURL         string
		existingRPID    string
		expectedRPID    string
		expectedDisplay string
		expectedOrigins []string
	}{
		{
			name:            "derives all from base URL",
			baseURL:         "https://example.com",
			existingRPID:    "",
			expectedRPID:    "example.com",
			expectedDisplay: "example.com",
			expectedOrigins: []string{"https://example.com"},
		},
		{
			name:            "preserves existing RPID",
			baseURL:         "https://example.com",
			existingRPID:    "custom.com",
			expectedRPID:    "custom.com",
			expectedDisplay: "example.com",
			expectedOrigins: []string{"https://example.com"},
		},
		{
			name:            "handles base URL with port",
			baseURL:         "https://localhost:3000",
			existingRPID:    "",
			expectedRPID:    "localhost",
			expectedDisplay: "localhost",
			expectedOrigins: []string{"https://localhost:3000"},
		},
		{
			name:            "handles http URL",
			baseURL:         "http://localhost:8080",
			existingRPID:    "",
			expectedRPID:    "localhost",
			expectedDisplay: "localhost",
			expectedOrigins: []string{"http://localhost:8080"},
		},
		{
			name:            "empty base URL does nothing",
			baseURL:         "",
			existingRPID:    "",
			expectedRPID:    "",
			expectedDisplay: "",
			expectedOrigins: nil,
		},
		{
			name:            "nil config handled",
			baseURL:         "",
			existingRPID:    "",
			expectedRPID:    "",
			expectedDisplay: "",
			expectedOrigins: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				BaseURL: tt.baseURL,
				RPID:    tt.existingRPID,
			}
			applyBaseURLDefaults(config)

			if config.RPID != tt.expectedRPID {
				t.Errorf("RPID = %q, want %q", config.RPID, tt.expectedRPID)
			}
			if config.RPDisplayName != tt.expectedDisplay {
				t.Errorf("RPDisplayName = %q, want %q", config.RPDisplayName, tt.expectedDisplay)
			}
			if len(config.RPOrigins) != len(tt.expectedOrigins) {
				t.Errorf("RPOrigins len = %d, want %d", len(config.RPOrigins), len(tt.expectedOrigins))
			}
			for i, origin := range tt.expectedOrigins {
				if i < len(config.RPOrigins) && config.RPOrigins[i] != origin {
					t.Errorf("RPOrigins[%d] = %q, want %q", i, config.RPOrigins[i], origin)
				}
			}
		})
	}
}

func TestApplyBaseURLDefaults_NilConfig(t *testing.T) {
	// Should not panic
	applyBaseURLDefaults(nil)
}

func TestFormatTransport(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
	}{
		{"nil value", nil, ""},
		{"string value", "usb", "usb"},
		{"int value", 123, "123"},
		{"bool value", true, "true"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTransport(tt.input); got != tt.expected {
				t.Errorf("formatTransport(%v) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}
