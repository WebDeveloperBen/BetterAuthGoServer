package otp_test

import (
	"context"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/otp"
)

func TestService_CreateToken(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	userID := "user-123"

	t.Run("creates password reset token", func(t *testing.T) {
		rawToken, err := service.CreateToken(ctx, userID, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("CreateToken failed: %v", err)
		}

		if rawToken == "" {
			t.Error("expected non-empty raw token")
		}

		// Verify token was stored
		if store.count() != 1 {
			t.Errorf("expected 1 token in store, got %d", store.count())
		}
	})

	t.Run("creates email verification token", func(t *testing.T) {
		rawToken, err := service.CreateToken(ctx, userID, otp.TokenTypeEmailVerification)
		if err != nil {
			t.Fatalf("CreateToken failed: %v", err)
		}

		if rawToken == "" {
			t.Error("expected non-empty raw token")
		}
	})

	t.Run("replaces existing token of same type", func(t *testing.T) {
		// Create initial token
		_, err := service.CreateToken(ctx, userID, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("first CreateToken failed: %v", err)
		}

		initialCount := store.count()

		// Create another token of same type - should replace
		_, err = service.CreateToken(ctx, userID, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("second CreateToken failed: %v", err)
		}

		// Count should remain the same (old token deleted, new one added)
		if store.count() != initialCount {
			t.Errorf("expected %d tokens, got %d (old token should be replaced)", initialCount, store.count())
		}
	})
}

func TestService_CreateTokenWithIdentifier(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	userID := "user-123"
	newEmail := "new@example.com"

	t.Run("creates token with identifier", func(t *testing.T) {
		rawToken, err := service.CreateTokenWithIdentifier(ctx, userID, otp.TokenTypeEmailChange, newEmail)
		if err != nil {
			t.Fatalf("CreateTokenWithIdentifier failed: %v", err)
		}

		if rawToken == "" {
			t.Error("expected non-empty raw token")
		}

		// Verify identifier was stored
		tokens := store.getAll()
		found := false
		for _, tok := range tokens {
			if tok.Identifier != nil && *tok.Identifier == newEmail {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected token with identifier to be stored")
		}
	})
}

func TestService_ValidateToken(t *testing.T) {
	service, _ := setupTestService(t)
	ctx := context.Background()
	userID := "user-123"

	t.Run("validates valid token", func(t *testing.T) {
		rawToken, err := service.CreateToken(ctx, userID, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("CreateToken failed: %v", err)
		}

		tok, err := service.ValidateToken(ctx, rawToken, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("ValidateToken failed: %v", err)
		}

		if tok.UserID != userID {
			t.Errorf("expected userID %s, got %s", userID, tok.UserID)
		}
		if tok.Type != otp.TokenTypePasswordReset {
			t.Errorf("expected type %s, got %s", otp.TokenTypePasswordReset, tok.Type)
		}
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		_, err := service.ValidateToken(ctx, "invalid-token", otp.TokenTypePasswordReset)
		if err != otp.ErrTokenNotFound {
			t.Errorf("expected ErrTokenNotFound, got %v", err)
		}
	})

	t.Run("rejects wrong token type", func(t *testing.T) {
		rawToken, err := service.CreateToken(ctx, userID, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("CreateToken failed: %v", err)
		}

		_, err = service.ValidateToken(ctx, rawToken, otp.TokenTypeEmailVerification)
		if err != otp.ErrTokenNotFound {
			t.Errorf("expected ErrTokenNotFound for wrong type, got %v", err)
		}
	})

	t.Run("rejects expired token", func(t *testing.T) {
		// Create service with very short expiry
		shortConfig := otp.Config{
			PasswordResetExpiry:     1 * time.Millisecond,
			EmailVerificationExpiry: 1 * time.Millisecond,
			EmailChangeExpiry:       1 * time.Millisecond,
		}
		shortService, _ := setupTestServiceWithConfig(t, shortConfig)

		rawToken, err := shortService.CreateToken(ctx, userID, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("CreateToken failed: %v", err)
		}

		// Wait for expiry
		time.Sleep(10 * time.Millisecond)

		_, err = shortService.ValidateToken(ctx, rawToken, otp.TokenTypePasswordReset)
		if err != otp.ErrTokenExpired {
			t.Errorf("expected ErrTokenExpired, got %v", err)
		}
	})
}

func TestService_ConsumeToken(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	userID := "user-123"

	t.Run("consumes and deletes token", func(t *testing.T) {
		rawToken, err := service.CreateToken(ctx, userID, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("CreateToken failed: %v", err)
		}

		initialCount := store.count()

		tok, err := service.ConsumeToken(ctx, rawToken, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("ConsumeToken failed: %v", err)
		}

		if tok.UserID != userID {
			t.Errorf("expected userID %s, got %s", userID, tok.UserID)
		}

		// Token should be deleted
		if store.count() != initialCount-1 {
			t.Errorf("token should be deleted after consumption")
		}

		// Second consume should fail
		_, err = service.ConsumeToken(ctx, rawToken, otp.TokenTypePasswordReset)
		if err != otp.ErrTokenNotFound {
			t.Errorf("expected ErrTokenNotFound on second consume, got %v", err)
		}
	})
}

func TestService_DeleteTokensForUser(t *testing.T) {
	service, store := setupTestService(t)
	ctx := context.Background()
	userID := "user-123"

	t.Run("deletes tokens for user", func(t *testing.T) {
		// Create multiple tokens
		_, _ = service.CreateToken(ctx, userID, otp.TokenTypePasswordReset)
		_, _ = service.CreateToken(ctx, userID, otp.TokenTypeEmailVerification)

		// Delete password reset tokens
		err := service.DeleteTokensForUser(ctx, userID, otp.TokenTypePasswordReset)
		if err != nil {
			t.Fatalf("DeleteTokensForUser failed: %v", err)
		}

		// Should still have the email verification token
		tokens := store.getAll()
		for _, tok := range tokens {
			if tok.UserID == userID && tok.Type == otp.TokenTypePasswordReset {
				t.Error("password reset token should be deleted")
			}
		}
	})
}

func TestService_CleanupExpired(t *testing.T) {
	// Create service with very short expiry
	shortConfig := otp.Config{
		PasswordResetExpiry:     1 * time.Millisecond,
		EmailVerificationExpiry: 1 * time.Millisecond,
		EmailChangeExpiry:       1 * time.Millisecond,
	}
	service, store := setupTestServiceWithConfig(t, shortConfig)
	ctx := context.Background()

	t.Run("removes expired tokens", func(t *testing.T) {
		// Create tokens
		_, _ = service.CreateToken(ctx, "user-1", otp.TokenTypePasswordReset)
		_, _ = service.CreateToken(ctx, "user-2", otp.TokenTypeEmailVerification)

		// Wait for expiry
		time.Sleep(10 * time.Millisecond)

		// Cleanup
		err := service.CleanupExpired(ctx)
		if err != nil {
			t.Fatalf("CleanupExpired failed: %v", err)
		}

		// All tokens should be deleted
		if store.count() != 0 {
			t.Errorf("expected 0 tokens after cleanup, got %d", store.count())
		}
	})
}

func TestOTPToken_IsExpired(t *testing.T) {
	t.Run("returns false for future expiry", func(t *testing.T) {
		tok := &otp.OTPToken{
			ExpiresAt: time.Now().Add(time.Hour),
		}
		if tok.IsExpired() {
			t.Error("token should not be expired")
		}
	})

	t.Run("returns true for past expiry", func(t *testing.T) {
		tok := &otp.OTPToken{
			ExpiresAt: time.Now().Add(-time.Hour),
		}
		if !tok.IsExpired() {
			t.Error("token should be expired")
		}
	})
}
