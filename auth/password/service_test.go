package password_test

import (
	"context"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/password"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestService_SignUp(t *testing.T) {
	ctx := context.Background()

	t.Run("successful signup", func(t *testing.T) {
		service, _ := setupTestService(t)

		user, session, err := service.SignUp(ctx, "test@example.com", "SecureP@ss1", "Test User", nil)
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}

		if user == nil {
			t.Fatal("expected user to be returned")
		}
		if user.Email != "test@example.com" {
			t.Errorf("expected email %q, got %q", "test@example.com", user.Email)
		}
		if user.Name != "Test User" {
			t.Errorf("expected name %q, got %q", "Test User", user.Name)
		}

		// Session should be created due to AutoSignIn
		if session == nil {
			t.Error("expected session to be created with AutoSignIn enabled")
		}
	})

	t.Run("signup with auto signin disabled", func(t *testing.T) {
		config := password.DefaultConfig()
		config.AutoSignIn = false
		service, _ := setupTestServiceWithConfig(t, config)

		user, session, err := service.SignUp(ctx, "test@example.com", "SecureP@ss1", "Test User", nil)
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}

		if user == nil {
			t.Fatal("expected user to be returned")
		}
		if session != nil {
			t.Error("expected no session when AutoSignIn is disabled")
		}
	})

	t.Run("signup with email verification required", func(t *testing.T) {
		config := password.DefaultConfig()
		config.RequireEmailVerification = true
		service, _ := setupTestServiceWithConfig(t, config)

		user, session, err := service.SignUp(ctx, "test@example.com", "SecureP@ss1", "Test User", nil)
		if err != nil {
			t.Fatalf("SignUp failed: %v", err)
		}

		if user == nil {
			t.Fatal("expected user to be returned")
		}
		// Session should NOT be created when email verification is required
		if session != nil {
			t.Error("expected no session when email verification is required")
		}
	})

	t.Run("rejects invalid password", func(t *testing.T) {
		service, _ := setupTestService(t)

		_, _, err := service.SignUp(ctx, "test@example.com", "weak", "Test User", nil)
		if err != password.ErrPasswordTooShort {
			t.Errorf("expected ErrPasswordTooShort, got: %v", err)
		}
	})

	t.Run("rejects duplicate email", func(t *testing.T) {
		service, _ := setupTestService(t)

		// First signup
		_, _, err := service.SignUp(ctx, "test@example.com", "SecureP@ss1", "Test User", nil)
		if err != nil {
			t.Fatalf("first SignUp failed: %v", err)
		}

		// Second signup with same email
		_, _, err = service.SignUp(ctx, "test@example.com", "SecureP@ss2", "Another User", nil)
		if err != password.ErrUserAlreadyExists {
			t.Errorf("expected ErrUserAlreadyExists, got: %v", err)
		}
	})
}

func TestService_SignIn(t *testing.T) {
	ctx := context.Background()

	t.Run("successful signin", func(t *testing.T) {
		service, deps := setupTestService(t)

		// Create a user
		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
			Name:          "Test User",
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "SecureP@ss1"))

		// Sign in
		returnedUser, session, err := service.SignIn(ctx, "test@example.com", "SecureP@ss1", nil)
		if err != nil {
			t.Fatalf("SignIn failed: %v", err)
		}

		if returnedUser == nil {
			t.Fatal("expected user to be returned")
		}
		if returnedUser.ID != user.ID {
			t.Errorf("expected user ID %q, got %q", user.ID, returnedUser.ID)
		}
		if session == nil {
			t.Fatal("expected session to be created")
		}
	})

	t.Run("rejects invalid password", func(t *testing.T) {
		service, deps := setupTestService(t)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "CorrectP@ss1"))

		_, _, err := service.SignIn(ctx, "test@example.com", "WrongP@ss1", nil)
		if err != password.ErrInvalidCredentials {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("rejects non-existent user", func(t *testing.T) {
		service, _ := setupTestService(t)

		_, _, err := service.SignIn(ctx, "nonexistent@example.com", "SomeP@ss1", nil)
		if err != password.ErrInvalidCredentials {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("rejects unverified email when verification required", func(t *testing.T) {
		config := password.DefaultConfig()
		config.RequireEmailVerification = true
		service, deps := setupTestServiceWithConfig(t, config)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: false, // Not verified
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "SecureP@ss1"))

		_, _, err := service.SignIn(ctx, "test@example.com", "SecureP@ss1", nil)
		if err != models.ErrEmailNotVerified {
			t.Errorf("expected ErrEmailNotVerified, got: %v", err)
		}
	})

	t.Run("allows unverified email when verification not required", func(t *testing.T) {
		config := password.DefaultConfig()
		config.RequireEmailVerification = false
		service, deps := setupTestServiceWithConfig(t, config)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: false,
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "SecureP@ss1"))

		_, _, err := service.SignIn(ctx, "test@example.com", "SecureP@ss1", nil)
		if err != nil {
			t.Errorf("expected successful signin when verification not required, got: %v", err)
		}
	})

	t.Run("rejects user without email account", func(t *testing.T) {
		service, deps := setupTestService(t)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
		}
		deps.authProvider.addUser(user)
		// No email account created

		_, _, err := service.SignIn(ctx, "test@example.com", "SomeP@ss1", nil)
		if err != password.ErrInvalidCredentials {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})
}

func TestService_ChangePassword(t *testing.T) {
	ctx := context.Background()

	t.Run("successful password change", func(t *testing.T) {
		service, deps := setupTestService(t)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "correct-password"))

		err := service.ChangePassword(ctx, user.ID, "correct-password", "NewSecureP@ss1")
		if err != nil {
			t.Fatalf("ChangePassword failed: %v", err)
		}
	})

	t.Run("rejects invalid old password", func(t *testing.T) {
		service, deps := setupTestService(t)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "correct-password"))

		err := service.ChangePassword(ctx, user.ID, "wrong-password", "NewSecureP@ss1")
		if err != password.ErrInvalidCredentials {
			t.Errorf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("rejects weak new password", func(t *testing.T) {
		service, deps := setupTestService(t)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "correct-password"))

		err := service.ChangePassword(ctx, user.ID, "correct-password", "weak")
		if err != password.ErrPasswordTooShort {
			t.Errorf("expected ErrPasswordTooShort, got: %v", err)
		}
	})
}

func TestService_RequestPasswordReset(t *testing.T) {
	ctx := context.Background()

	t.Run("successful password reset request", func(t *testing.T) {
		service, deps := setupTestService(t)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "OldP@ss1"))

		err := service.RequestPasswordReset(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("RequestPasswordReset failed: %v", err)
		}
	})

	t.Run("does not reveal non-existent user", func(t *testing.T) {
		service, _ := setupTestService(t)

		// Should not return error for non-existent user (security)
		err := service.RequestPasswordReset(ctx, "nonexistent@example.com")
		if err != nil {
			t.Errorf("expected nil error for non-existent user, got: %v", err)
		}
	})

	t.Run("fails when token provider is nil", func(t *testing.T) {
		config := password.DefaultConfig()
		deps := &testDependencies{
			store:         newMockPasswordStore(),
			authProvider:  newMockAuthProvider(),
			tokenProvider: nil, // No token provider
			eventBus:      newMockEventBus(),
		}

		service := password.NewService(
			deps.store,
			deps.authProvider,
			nil, // No token provider
			deps.eventBus,
			config,
			nil,
		)
		defer service.Close()

		err := service.RequestPasswordReset(ctx, "test@example.com")
		if err != password.ErrPasswordResetNotAvailable {
			t.Errorf("expected ErrPasswordResetNotAvailable, got: %v", err)
		}
	})
}

func TestService_ConfirmPasswordReset(t *testing.T) {
	ctx := context.Background()

	t.Run("successful password reset confirmation", func(t *testing.T) {
		service, deps := setupTestService(t)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "OldP@ss1"))

		// Create a token directly
		token, _ := deps.tokenProvider.CreatePasswordResetToken(ctx, user.ID)

		// Confirm password reset
		err := service.ConfirmPasswordReset(ctx, token, "NewSecureP@ss1")
		if err != nil {
			t.Fatalf("ConfirmPasswordReset failed: %v", err)
		}
	})

	t.Run("rejects invalid token", func(t *testing.T) {
		service, _ := setupTestService(t)

		err := service.ConfirmPasswordReset(ctx, "invalid-token", "NewSecureP@ss1")
		if err != models.ErrVerificationNotFound {
			t.Errorf("expected ErrVerificationNotFound, got: %v", err)
		}
	})

	t.Run("rejects weak new password", func(t *testing.T) {
		service, deps := setupTestService(t)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "OldP@ss1"))

		token, _ := deps.tokenProvider.CreatePasswordResetToken(ctx, user.ID)

		err := service.ConfirmPasswordReset(ctx, token, "weak")
		if err != password.ErrPasswordTooShort {
			t.Errorf("expected ErrPasswordTooShort, got: %v", err)
		}
	})

	t.Run("token cannot be reused", func(t *testing.T) {
		service, deps := setupTestService(t)

		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
		}
		deps.authProvider.addUser(user)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "OldP@ss1"))

		token, _ := deps.tokenProvider.CreatePasswordResetToken(ctx, user.ID)

		// First use
		err := service.ConfirmPasswordReset(ctx, token, "NewSecureP@ss1")
		if err != nil {
			t.Fatalf("first ConfirmPasswordReset failed: %v", err)
		}

		// Second use should fail
		err = service.ConfirmPasswordReset(ctx, token, "AnotherP@ss1")
		if err != models.ErrVerificationNotFound {
			t.Errorf("expected ErrVerificationNotFound on reuse, got: %v", err)
		}
	})

	t.Run("fails when token provider is nil", func(t *testing.T) {
		config := password.DefaultConfig()
		deps := &testDependencies{
			store:        newMockPasswordStore(),
			authProvider: newMockAuthProvider(),
			eventBus:     newMockEventBus(),
		}

		service := password.NewService(
			deps.store,
			deps.authProvider,
			nil, // No token provider
			deps.eventBus,
			config,
			nil,
		)
		defer service.Close()

		err := service.ConfirmPasswordReset(ctx, "some-token", "NewSecureP@ss1")
		if err != password.ErrPasswordResetNotAvailable {
			t.Errorf("expected ErrPasswordResetNotAvailable, got: %v", err)
		}
	})
}

func TestService_Close(t *testing.T) {
	t.Run("closes without error", func(t *testing.T) {
		service, _ := setupTestService(t)

		err := service.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})

	t.Run("closes with custom lockout store", func(t *testing.T) {
		config := password.DefaultConfig()
		// Don't set LockoutStore - it will create its own
		config.LockoutStore = nil

		service, _ := setupTestServiceWithConfig(t, config)

		err := service.Close()
		if err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})
}

func TestConfig(t *testing.T) {
	t.Run("default config has sensible values", func(t *testing.T) {
		config := password.DefaultConfig()

		if config.MinLength != 8 {
			t.Errorf("expected MinLength 8, got %d", config.MinLength)
		}
		if config.MaxLength != 128 {
			t.Errorf("expected MaxLength 128, got %d", config.MaxLength)
		}
		if !config.RequireComplexity {
			t.Error("expected RequireComplexity to be true")
		}
		if config.ResetTokenExpiry != time.Hour {
			t.Errorf("expected ResetTokenExpiry 1h, got %v", config.ResetTokenExpiry)
		}
		if !config.AutoSignIn {
			t.Error("expected AutoSignIn to be true")
		}
		if config.RequireEmailVerification {
			t.Error("expected RequireEmailVerification to be false")
		}
		if config.LockoutThreshold != 10 {
			t.Errorf("expected LockoutThreshold 10, got %d", config.LockoutThreshold)
		}
		if config.LockoutDuration != 15*time.Minute {
			t.Errorf("expected LockoutDuration 15m, got %v", config.LockoutDuration)
		}
	})

	t.Run("options modify config", func(t *testing.T) {
		config := password.DefaultConfig()

		password.WithMinLength(12)(&config)
		if config.MinLength != 12 {
			t.Errorf("expected MinLength 12, got %d", config.MinLength)
		}

		password.WithMaxLength(64)(&config)
		if config.MaxLength != 64 {
			t.Errorf("expected MaxLength 64, got %d", config.MaxLength)
		}

		password.WithComplexity(false)(&config)
		if config.RequireComplexity {
			t.Error("expected RequireComplexity to be false")
		}

		password.WithAutoSignIn(false)(&config)
		if config.AutoSignIn {
			t.Error("expected AutoSignIn to be false")
		}

		password.WithRequireEmailVerification(true)(&config)
		if !config.RequireEmailVerification {
			t.Error("expected RequireEmailVerification to be true")
		}

		password.WithLockoutThreshold(5)(&config)
		if config.LockoutThreshold != 5 {
			t.Errorf("expected LockoutThreshold 5, got %d", config.LockoutThreshold)
		}

		password.WithLockoutDuration(10 * time.Minute)(&config)
		if config.LockoutDuration != 10*time.Minute {
			t.Errorf("expected LockoutDuration 10m, got %v", config.LockoutDuration)
		}

		password.WithResetExpiry(2 * time.Hour)(&config)
		if config.ResetTokenExpiry != 2*time.Hour {
			t.Errorf("expected ResetTokenExpiry 2h, got %v", config.ResetTokenExpiry)
		}
	})
}
