package webauthn

import (
	"testing"
	"time"
)

func TestWebAuthnSession_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{
			name:      "not expired",
			expiresAt: time.Now().Add(5 * time.Minute),
			expected:  false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-5 * time.Minute),
			expected:  true,
		},
		{
			name:      "just expired",
			expiresAt: time.Now().Add(-1 * time.Second),
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &WebAuthnSession{ExpiresAt: tt.expiresAt}
			if got := session.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWebAuthnCredential_Fields(t *testing.T) {
	now := time.Now()
	cred := &WebAuthnCredential{
		ID:           "cred-123",
		UserID:       "user-456",
		CredentialID: []byte("credential-id"),
		PublicKey:    []byte("public-key"),
		SignCount:    5,
		Transports:   []string{"usb", "nfc"},
		CreatedAt:    now,
	}

	if cred.ID != "cred-123" {
		t.Errorf("ID = %q, want 'cred-123'", cred.ID)
	}
	if cred.UserID != "user-456" {
		t.Errorf("UserID = %q, want 'user-456'", cred.UserID)
	}
	if string(cred.CredentialID) != "credential-id" {
		t.Errorf("CredentialID = %q, want 'credential-id'", string(cred.CredentialID))
	}
	if cred.SignCount != 5 {
		t.Errorf("SignCount = %d, want 5", cred.SignCount)
	}
	if len(cred.Transports) != 2 {
		t.Errorf("Transports len = %d, want 2", len(cred.Transports))
	}
}
