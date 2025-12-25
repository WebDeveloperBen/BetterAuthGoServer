package jwt

import (
	"context"
	"testing"
	"time"
)

func TestNewService(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid HS256 config",
			config: Config{
				Algorithm: AlgorithmHS256,
				Secret:    "super-secret-key-that-is-long-enough",
			},
			wantErr: false,
		},
		{
			name: "valid HS384 config",
			config: Config{
				Algorithm: AlgorithmHS384,
				Secret:    "super-secret-key-that-is-long-enough",
			},
			wantErr: false,
		},
		{
			name: "valid HS512 config",
			config: Config{
				Algorithm: AlgorithmHS512,
				Secret:    "super-secret-key-that-is-long-enough",
			},
			wantErr: false,
		},
		{
			name: "missing secret for HMAC",
			config: Config{
				Algorithm: AlgorithmHS256,
				Secret:    "",
			},
			wantErr: true,
		},
		{
			name: "unsupported algorithm",
			config: Config{
				Algorithm: "invalid",
				Secret:    "secret",
			},
			wantErr: true,
		},
		{
			name: "default algorithm",
			config: Config{
				Secret: "super-secret-key-that-is-long-enough",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewService(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewService() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestService_GenerateTokenPair(t *testing.T) {
	svc, err := NewService(Config{
		Algorithm:       AlgorithmHS256,
		Secret:          "super-secret-key-that-is-long-enough",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
		Audience:        "test-audience",
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	user := UserInfo{
		ID:            "user-123",
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}

	pair, err := svc.GenerateTokenPair(user, "session-456")
	if err != nil {
		t.Fatalf("GenerateTokenPair() error: %v", err)
	}

	if pair.AccessToken == "" {
		t.Error("AccessToken is empty")
	}
	if pair.RefreshToken == "" {
		t.Error("RefreshToken is empty")
	}
	if pair.TokenType != "Bearer" {
		t.Errorf("TokenType = %s, want Bearer", pair.TokenType)
	}
	if pair.ExpiresIn != int64(15*time.Minute.Seconds()) {
		t.Errorf("ExpiresIn = %d, want %d", pair.ExpiresIn, int64(15*time.Minute.Seconds()))
	}
}

func TestService_ValidateAccessToken(t *testing.T) {
	svc, err := NewService(Config{
		Algorithm:       AlgorithmHS256,
		Secret:          "super-secret-key-that-is-long-enough",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
		Audience:        "test-audience",
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	user := UserInfo{
		ID:            "user-123",
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}

	pair, err := svc.GenerateTokenPair(user, "session-456")
	if err != nil {
		t.Fatalf("GenerateTokenPair() error: %v", err)
	}

	ctx := context.Background()

	t.Run("valid access token", func(t *testing.T) {
		claims, err := svc.ValidateAccessToken(ctx, pair.AccessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken() error: %v", err)
		}
		if claims.UserID != "user-123" {
			t.Errorf("UserID = %s, want user-123", claims.UserID)
		}
		if claims.Email != "test@example.com" {
			t.Errorf("Email = %s, want test@example.com", claims.Email)
		}
		if claims.SessionID != "session-456" {
			t.Errorf("SessionID = %s, want session-456", claims.SessionID)
		}
		if claims.TokenType != TokenTypeAccess {
			t.Errorf("TokenType = %s, want access", claims.TokenType)
		}
	})

	t.Run("refresh token as access token fails", func(t *testing.T) {
		_, err := svc.ValidateAccessToken(ctx, pair.RefreshToken)
		if err != ErrInvalidTokenType {
			t.Errorf("Expected ErrInvalidTokenType, got: %v", err)
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := svc.ValidateAccessToken(ctx, "invalid-token")
		if err != ErrInvalidToken {
			t.Errorf("Expected ErrInvalidToken, got: %v", err)
		}
	})
}

func TestService_ValidateRefreshToken(t *testing.T) {
	svc, err := NewService(Config{
		Algorithm:       AlgorithmHS256,
		Secret:          "super-secret-key-that-is-long-enough",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
		Audience:        "test-audience",
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	user := UserInfo{
		ID:            "user-123",
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}

	pair, err := svc.GenerateTokenPair(user, "session-456")
	if err != nil {
		t.Fatalf("GenerateTokenPair() error: %v", err)
	}

	ctx := context.Background()

	t.Run("valid refresh token", func(t *testing.T) {
		claims, err := svc.ValidateRefreshToken(ctx, pair.RefreshToken)
		if err != nil {
			t.Fatalf("ValidateRefreshToken() error: %v", err)
		}
		if claims.UserID != "user-123" {
			t.Errorf("UserID = %s, want user-123", claims.UserID)
		}
		if claims.TokenType != TokenTypeRefresh {
			t.Errorf("TokenType = %s, want refresh", claims.TokenType)
		}
	})

	t.Run("access token as refresh token fails", func(t *testing.T) {
		_, err := svc.ValidateRefreshToken(ctx, pair.AccessToken)
		if err != ErrInvalidTokenType {
			t.Errorf("Expected ErrInvalidTokenType, got: %v", err)
		}
	})
}

func TestService_RefreshTokens(t *testing.T) {
	svc, err := NewService(Config{
		Algorithm:       AlgorithmHS256,
		Secret:          "super-secret-key-that-is-long-enough",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
		Audience:        "test-audience",
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	user := UserInfo{
		ID:            "user-123",
		Email:         "test@example.com",
		Name:          "Test User",
		EmailVerified: true,
	}

	pair, err := svc.GenerateTokenPair(user, "session-456")
	if err != nil {
		t.Fatalf("GenerateTokenPair() error: %v", err)
	}

	ctx := context.Background()

	newPair, err := svc.RefreshTokens(ctx, pair.RefreshToken, user)
	if err != nil {
		t.Fatalf("RefreshTokens() error: %v", err)
	}

	if newPair.AccessToken == "" {
		t.Error("New AccessToken is empty")
	}
	if newPair.RefreshToken == "" {
		t.Error("New RefreshToken is empty")
	}

	// Old and new tokens should be different
	if newPair.AccessToken == pair.AccessToken {
		t.Error("New access token should be different from old")
	}
	if newPair.RefreshToken == pair.RefreshToken {
		t.Error("New refresh token should be different from old")
	}
}

func TestService_ExpiredToken(t *testing.T) {
	svc, err := NewService(Config{
		Algorithm:       AlgorithmHS256,
		Secret:          "super-secret-key-that-is-long-enough",
		AccessTokenTTL:  -1 * time.Hour, // Expired
		RefreshTokenTTL: 7 * 24 * time.Hour,
		Issuer:          "test-issuer",
		Audience:        "test-audience",
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	user := UserInfo{
		ID:    "user-123",
		Email: "test@example.com",
	}

	pair, err := svc.GenerateTokenPair(user, "session-456")
	if err != nil {
		t.Fatalf("GenerateTokenPair() error: %v", err)
	}

	ctx := context.Background()
	_, err = svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != ErrExpiredToken {
		t.Errorf("Expected ErrExpiredToken, got: %v", err)
	}
}

// mockBlocklist is a simple in-memory blocklist for testing
type mockBlocklist struct {
	revoked map[string]bool
}

func (m *mockBlocklist) IsRevoked(ctx context.Context, jti string) (bool, error) {
	return m.revoked[jti], nil
}

func (m *mockBlocklist) Revoke(ctx context.Context, jti string, expiresAt time.Time) error {
	if m.revoked == nil {
		m.revoked = make(map[string]bool)
	}
	m.revoked[jti] = true
	return nil
}

func TestService_TokenBlocklist(t *testing.T) {
	blocklist := &mockBlocklist{revoked: make(map[string]bool)}

	svc, err := NewService(Config{
		Algorithm:       AlgorithmHS256,
		Secret:          "super-secret-key-that-is-long-enough",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		TokenBlocklist:  blocklist,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	user := UserInfo{
		ID:    "user-123",
		Email: "test@example.com",
	}

	pair, err := svc.GenerateTokenPair(user, "session-456")
	if err != nil {
		t.Fatalf("GenerateTokenPair() error: %v", err)
	}

	ctx := context.Background()

	// Token should be valid initially
	_, err = svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("Token should be valid: %v", err)
	}

	// Revoke the token
	err = svc.RevokeToken(ctx, pair.AccessToken)
	if err != nil {
		t.Fatalf("RevokeToken() error: %v", err)
	}

	// Token should now be revoked
	_, err = svc.ValidateAccessToken(ctx, pair.AccessToken)
	if err != ErrTokenRevoked {
		t.Errorf("Expected ErrTokenRevoked, got: %v", err)
	}
}

func TestClaims_IsExpired(t *testing.T) {
	t.Run("not expired", func(t *testing.T) {
		claims := NewAccessClaims("user", "session", "email", "name", true, "issuer", "audience", time.Hour)
		if claims.IsExpired() {
			t.Error("Token should not be expired")
		}
	})

	t.Run("expired", func(t *testing.T) {
		claims := NewAccessClaims("user", "session", "email", "name", true, "issuer", "audience", -time.Hour)
		if !claims.IsExpired() {
			t.Error("Token should be expired")
		}
	})

	t.Run("nil expiry", func(t *testing.T) {
		claims := &Claims{}
		if claims.IsExpired() {
			t.Error("Token with nil expiry should not be expired")
		}
	})
}
