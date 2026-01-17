package password_test

import (
	"context"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/kv"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/password"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestLockoutService(t *testing.T) {
	ctx := context.Background()

	t.Run("locks account after threshold failures", func(t *testing.T) {
		config := password.Config{
			MinLength:         8,
			MaxLength:         128,
			RequireComplexity: false,
			LockoutThreshold:  3,
			LockoutDuration:   5 * time.Minute,
			LockoutStore:      kv.NewMemoryStore(),
		}
		service, deps := setupTestServiceWithConfig(t, config)

		// Add a test user
		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
			Name:          "Test User",
		}
		deps.authProvider.addUser(user)

		// Create email account with password (we test with wrong password attempts, so any hash works)
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "SomePassword1!"))

		// Attempt failed logins
		for i := 0; i < 3; i++ {
			_, _, err := service.SignIn(ctx, "test@example.com", "WrongPass1!", nil)
			if err != password.ErrInvalidCredentials && err != password.ErrAccountLocked {
				t.Errorf("expected ErrInvalidCredentials or ErrAccountLocked on attempt %d, got: %v", i+1, err)
			}
		}

		// Next attempt should be blocked due to lockout
		_, _, err := service.SignIn(ctx, "test@example.com", "WrongPass1!", nil)
		if err != password.ErrAccountLocked {
			t.Errorf("expected ErrAccountLocked after threshold, got: %v", err)
		}
	})

	t.Run("lockout disabled when threshold is 0", func(t *testing.T) {
		config := password.Config{
			MinLength:         8,
			MaxLength:         128,
			RequireComplexity: false,
			LockoutThreshold:  0, // Disabled
			LockoutDuration:   5 * time.Minute,
			LockoutStore:      kv.NewMemoryStore(),
		}
		service, deps := setupTestServiceWithConfig(t, config)

		// Add a test user
		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
			Name:          "Test User",
		}
		deps.authProvider.addUser(user)

		// Create email account
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "SomePassword1!"))

		// Multiple failed attempts should not lock
		for i := 0; i < 10; i++ {
			_, _, err := service.SignIn(ctx, "test@example.com", "WrongPass1!", nil)
			if err == password.ErrAccountLocked {
				t.Errorf("expected no lockout when disabled, but got ErrAccountLocked on attempt %d", i+1)
			}
		}
	})

	t.Run("successful login clears failure count", func(t *testing.T) {
		config := password.Config{
			MinLength:         8,
			MaxLength:         128,
			RequireComplexity: false,
			LockoutThreshold:  5,
			LockoutDuration:   5 * time.Minute,
			LockoutStore:      kv.NewMemoryStore(),
		}
		service, deps := setupTestServiceWithConfig(t, config)

		// Add a test user
		user := &plugin.User{
			ID:            "user-123",
			Email:         "test@example.com",
			EmailVerified: true,
			Name:          "Test User",
		}
		deps.authProvider.addUser(user)

		// Create email account with known password
		_ = deps.store.CreateEmailAccount(ctx, user.ID, hashPassword(t, "CorrectPass1!"))

		// Make 4 failed attempts (one less than threshold)
		for i := 0; i < 4; i++ {
			_, _, _ = service.SignIn(ctx, "test@example.com", "WrongPass1!", nil)
		}

		// Successful login
		_, _, err := service.SignIn(ctx, "test@example.com", "CorrectPass1!", nil)
		if err != nil {
			t.Fatalf("expected successful login, got: %v", err)
		}

		// Now 4 more failed attempts should not lock (counter was reset)
		for i := 0; i < 4; i++ {
			_, _, err := service.SignIn(ctx, "test@example.com", "WrongPass1!", nil)
			if err == password.ErrAccountLocked {
				t.Errorf("expected counter to be reset after success, but got locked on attempt %d", i+1)
			}
		}
	})

	t.Run("tracks failures for non-existent users", func(t *testing.T) {
		config := password.Config{
			MinLength:         8,
			MaxLength:         128,
			RequireComplexity: false,
			LockoutThreshold:  3,
			LockoutDuration:   5 * time.Minute,
			LockoutStore:      kv.NewMemoryStore(),
		}
		service, _ := setupTestServiceWithConfig(t, config)

		// Attempt logins for non-existent user
		for i := 0; i < 3; i++ {
			_, _, _ = service.SignIn(ctx, "nonexistent@example.com", "SomePass1!", nil)
		}

		// Next attempt should be blocked due to lockout
		_, _, err := service.SignIn(ctx, "nonexistent@example.com", "SomePass1!", nil)
		if err != password.ErrAccountLocked {
			t.Errorf("expected ErrAccountLocked for non-existent user after threshold, got: %v", err)
		}
	})

	t.Run("different emails tracked separately", func(t *testing.T) {
		config := password.Config{
			MinLength:         8,
			MaxLength:         128,
			RequireComplexity: false,
			LockoutThreshold:  3,
			LockoutDuration:   5 * time.Minute,
			LockoutStore:      kv.NewMemoryStore(),
		}
		service, deps := setupTestServiceWithConfig(t, config)

		// Add test users
		user1 := &plugin.User{ID: "user-1", Email: "user1@example.com", EmailVerified: true}
		user2 := &plugin.User{ID: "user-2", Email: "user2@example.com", EmailVerified: true}
		deps.authProvider.addUser(user1)
		deps.authProvider.addUser(user2)

		_ = deps.store.CreateEmailAccount(ctx, user1.ID, hashPassword(t, "Password1!"))
		_ = deps.store.CreateEmailAccount(ctx, user2.ID, hashPassword(t, "Password2!"))

		// 2 failed attempts for user1
		for i := 0; i < 2; i++ {
			_, _, _ = service.SignIn(ctx, "user1@example.com", "WrongPass1!", nil)
		}

		// User2 should still be able to attempt login
		_, _, err := service.SignIn(ctx, "user2@example.com", "Password2!", nil)
		if err != nil {
			t.Errorf("user2 should not be affected by user1's failures, got: %v", err)
		}
	})
}
