package jwt

import (
	"testing"
	"time"
)

func TestNewAccessClaims(t *testing.T) {
	userID := "user-123"
	sessionID := "session-456"
	email := "test@example.com"
	name := "Test User"
	emailVerified := true
	issuer := "test-issuer"
	audience := "test-audience"
	ttl := 15 * time.Minute

	claims := NewAccessClaims(userID, sessionID, email, name, emailVerified, issuer, audience, ttl, nil)

	// Check registered claims
	if claims.Subject != userID {
		t.Errorf("Subject = %s, want %s", claims.Subject, userID)
	}
	if claims.Issuer != issuer {
		t.Errorf("Issuer = %s, want %s", claims.Issuer, issuer)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != audience {
		t.Errorf("Audience = %v, want [%s]", claims.Audience, audience)
	}

	// Check custom claims
	if claims.UserID != userID {
		t.Errorf("UserID = %s, want %s", claims.UserID, userID)
	}
	if claims.SessionID != sessionID {
		t.Errorf("SessionID = %s, want %s", claims.SessionID, sessionID)
	}
	if claims.Email != email {
		t.Errorf("Email = %s, want %s", claims.Email, email)
	}
	if claims.Name != name {
		t.Errorf("Name = %s, want %s", claims.Name, name)
	}
	if claims.EmailVerified != emailVerified {
		t.Errorf("EmailVerified = %v, want %v", claims.EmailVerified, emailVerified)
	}
	if claims.TokenType != TokenTypeAccess {
		t.Errorf("TokenType = %s, want %s", claims.TokenType, TokenTypeAccess)
	}

	// Check expiry is set correctly
	expectedExpiry := time.Now().Add(ttl)
	if claims.ExpiresAt == nil || claims.ExpiresAt.Time.After(expectedExpiry.Add(time.Minute)) {
		t.Error("ExpiresAt not set correctly")
	}
}

func TestNewRefreshClaims(t *testing.T) {
	userID := "user-123"
	sessionID := "session-456"
	issuer := "test-issuer"
	audience := "test-audience"
	ttl := 7 * 24 * time.Hour

	claims := NewRefreshClaims(userID, sessionID, issuer, audience, ttl, nil)

	// Check registered claims
	if claims.Subject != userID {
		t.Errorf("Subject = %s, want %s", claims.Subject, userID)
	}
	if claims.Issuer != issuer {
		t.Errorf("Issuer = %s, want %s", claims.Issuer, issuer)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != audience {
		t.Errorf("Audience = %v, want [%s]", claims.Audience, audience)
	}

	// Check custom claims
	if claims.UserID != userID {
		t.Errorf("UserID = %s, want %s", claims.UserID, userID)
	}
	if claims.SessionID != sessionID {
		t.Errorf("SessionID = %s, want %s", claims.SessionID, sessionID)
	}
	if claims.TokenType != TokenTypeRefresh {
		t.Errorf("TokenType = %s, want %s", claims.TokenType, TokenTypeRefresh)
	}

	// Check that access token fields are empty for refresh tokens
	if claims.Email != "" {
		t.Errorf("Email should be empty for refresh tokens, got %s", claims.Email)
	}
	if claims.Name != "" {
		t.Errorf("Name should be empty for refresh tokens, got %s", claims.Name)
	}
	if claims.EmailVerified != false {
		t.Errorf("EmailVerified should be false for refresh tokens, got %v", claims.EmailVerified)
	}
}

func TestActorClaim(t *testing.T) {
	t.Run("access token with actor", func(t *testing.T) {
		actorID := "admin-123"
		claims := NewAccessClaims("user-456", "session", "email", "name", true, "issuer", "audience", time.Hour, &actorID)

		if claims.Act == nil {
			t.Fatal("Act claim should be set")
		}
		if claims.Act.Sub != actorID {
			t.Errorf("Act.Sub = %s, want %s", claims.Act.Sub, actorID)
		}
	})

	t.Run("access token without actor", func(t *testing.T) {
		claims := NewAccessClaims("user-456", "session", "email", "name", true, "issuer", "audience", time.Hour, nil)

		if claims.Act != nil {
			t.Error("Act claim should be nil when no actor provided")
		}
	})

	t.Run("access token with empty actor", func(t *testing.T) {
		empty := ""
		claims := NewAccessClaims("user-456", "session", "email", "name", true, "issuer", "audience", time.Hour, &empty)

		if claims.Act != nil {
			t.Error("Act claim should be nil when empty actor provided")
		}
	})

	t.Run("refresh token with actor", func(t *testing.T) {
		actorID := "admin-123"
		claims := NewRefreshClaims("user-456", "session", "issuer", "audience", time.Hour, &actorID)

		if claims.Act == nil {
			t.Fatal("Act claim should be set")
		}
		if claims.Act.Sub != actorID {
			t.Errorf("Act.Sub = %s, want %s", claims.Act.Sub, actorID)
		}
	})
}

func TestGenerateJTI(t *testing.T) {
	jti1 := generateJTI()
	jti2 := generateJTI()

	// JTIs should be unique
	if jti1 == jti2 {
		t.Error("Generated JTIs should be unique")
	}

	// JTI should be 32 characters (16 bytes * 2 hex chars per byte)
	if len(jti1) != 32 {
		t.Errorf("JTI length = %d, want 32", len(jti1))
	}

	// Should only contain hex characters
	for _, char := range jti1 {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			t.Errorf("JTI contains non-hex character: %c", char)
		}
	}
}

func TestEncodeHex(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected string
	}{
		{[]byte{0}, "00"},
		{[]byte{255}, "ff"},
		{[]byte{0, 1, 15, 255}, "00010fff"},
		{[]byte{}, ""},
	}

	for _, tc := range testCases {
		result := encodeHex(tc.input)
		if result != tc.expected {
			t.Errorf("encodeHex(%v) = %s, want %s", tc.input, result, tc.expected)
		}
	}
}
