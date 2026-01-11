package anonymous_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/anonymous"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestService_CreateAnonymousUser(t *testing.T) {
	t.Run("creates anonymous user successfully", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		service := createTestService(t, store, auth)
		defer func() { _ = service.Close() }()

		req := httptest.NewRequest("POST", "/anonymous", nil)
		user, session, err := service.CreateAnonymousUser(context.Background(), req)

		if err != nil {
			t.Fatalf("CreateAnonymousUser failed: %v", err)
		}

		if user == nil {
			t.Fatal("User should not be nil")
		}

		if session == nil {
			t.Fatal("Session should not be nil")
		}

		if user.ID == "" {
			t.Error("User ID should not be empty")
		}

		if !user.IsAnonymous {
			t.Error("User should be anonymous")
		}

		// Check email domain
		if user.Email == "" {
			t.Error("User email should not be empty")
		}

		if user.Name != "Anonymous User" {
			t.Errorf("Name = %q, want %q", user.Name, "Anonymous User")
		}
	})

	t.Run("uses custom email domain", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		service := createTestService(t, store, auth, anonymous.WithEmailDomain("custom.local"))
		defer func() { _ = service.Close() }()

		req := httptest.NewRequest("POST", "/anonymous", nil)
		user, _, err := service.CreateAnonymousUser(context.Background(), req)

		if err != nil {
			t.Fatalf("CreateAnonymousUser failed: %v", err)
		}

		if user.Email == "" {
			t.Error("Email should not be empty")
		}

		// Email should end with @custom.local
		if len(user.Email) < 13 || user.Email[len(user.Email)-13:] != "@custom.local" {
			t.Errorf("Email = %q, should end with @custom.local", user.Email)
		}
	})

	t.Run("uses custom email generator", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		customEmail := "custom-user@test.local"
		service := createTestService(t, store, auth, anonymous.WithGenerateEmail(func() string {
			return customEmail
		}))
		defer func() { _ = service.Close() }()

		req := httptest.NewRequest("POST", "/anonymous", nil)
		user, _, err := service.CreateAnonymousUser(context.Background(), req)

		if err != nil {
			t.Fatalf("CreateAnonymousUser failed: %v", err)
		}

		if user.Email != customEmail {
			t.Errorf("Email = %q, want %q", user.Email, customEmail)
		}
	})

	t.Run("uses custom name generator", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		customName := "Guest User"
		service := createTestService(t, store, auth, anonymous.WithGenerateName(func() string {
			return customName
		}))
		defer func() { _ = service.Close() }()

		req := httptest.NewRequest("POST", "/anonymous", nil)
		user, _, err := service.CreateAnonymousUser(context.Background(), req)

		if err != nil {
			t.Fatalf("CreateAnonymousUser failed: %v", err)
		}

		if user.Name != customName {
			t.Errorf("Name = %q, want %q", user.Name, customName)
		}
	})

	t.Run("fails when session creation fails", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		auth.createSessionErr = errors.New("session error")
		service := createTestService(t, store, auth)
		defer func() { _ = service.Close() }()

		req := httptest.NewRequest("POST", "/anonymous", nil)
		_, _, err := service.CreateAnonymousUser(context.Background(), req)

		if err == nil {
			t.Error("Should fail when session creation fails")
		}

		// User should be cleaned up
		if len(auth.deletedUsers) != 1 {
			t.Errorf("len(deletedUsers) = %d, want %d", len(auth.deletedUsers), 1)
		}
	})
}

func TestService_HandleAccountLink(t *testing.T) {
	t.Run("links account successfully", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		service := createTestService(t, store, auth)
		defer func() { _ = service.Close() }()

		anonUser := &plugin.User{
			ID:    "anon-user-1",
			Email: "anon@anonymous.local",
			Name:  "Anonymous User",
		}
		auth.users[anonUser.ID] = anonUser

		newUser := &plugin.User{
			ID:    "real-user-1",
			Email: "real@example.com",
			Name:  "Real User",
		}

		err := service.HandleAccountLink(context.Background(), anonUser, newUser)

		if err != nil {
			t.Fatalf("HandleAccountLink failed: %v", err)
		}

		// Anonymous user should be deleted by default
		if len(auth.deletedUsers) != 1 || auth.deletedUsers[0] != anonUser.ID {
			t.Error("Anonymous user should be deleted")
		}
	})

	t.Run("calls OnLinkAccount callback", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		callbackCalled := false
		var callbackAnonUser, callbackNewUser *plugin.User

		service := createTestService(t, store, auth, anonymous.WithOnLinkAccount(
			func(ctx context.Context, anonUser, newUser *plugin.User) error {
				callbackCalled = true
				callbackAnonUser = anonUser
				callbackNewUser = newUser
				return nil
			},
		))
		defer func() { _ = service.Close() }()

		anonUser := &plugin.User{ID: "anon-1", Email: "anon@test.local"}
		newUser := &plugin.User{ID: "real-1", Email: "real@test.com"}
		auth.users[anonUser.ID] = anonUser

		err := service.HandleAccountLink(context.Background(), anonUser, newUser)

		if err != nil {
			t.Fatalf("HandleAccountLink failed: %v", err)
		}

		if !callbackCalled {
			t.Error("OnLinkAccount callback was not called")
		}

		if callbackAnonUser.ID != anonUser.ID {
			t.Errorf("Callback anonUser.ID = %q, want %q", callbackAnonUser.ID, anonUser.ID)
		}

		if callbackNewUser.ID != newUser.ID {
			t.Errorf("Callback newUser.ID = %q, want %q", callbackNewUser.ID, newUser.ID)
		}
	})

	t.Run("returns callback error", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		callbackErr := errors.New("callback error")

		service := createTestService(t, store, auth, anonymous.WithOnLinkAccount(
			func(ctx context.Context, anonUser, newUser *plugin.User) error {
				return callbackErr
			},
		))
		defer func() { _ = service.Close() }()

		anonUser := &plugin.User{ID: "anon-1"}
		newUser := &plugin.User{ID: "real-1"}

		err := service.HandleAccountLink(context.Background(), anonUser, newUser)

		if err != callbackErr {
			t.Errorf("err = %v, want %v", err, callbackErr)
		}
	})

	t.Run("does not delete when DisableDeleteAnonymousUser is set", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		service := createTestService(t, store, auth, anonymous.WithDisableDeleteAnonymousUser())
		defer func() { _ = service.Close() }()

		anonUser := &plugin.User{ID: "anon-1"}
		newUser := &plugin.User{ID: "real-1"}
		auth.users[anonUser.ID] = anonUser

		err := service.HandleAccountLink(context.Background(), anonUser, newUser)

		if err != nil {
			t.Fatalf("HandleAccountLink failed: %v", err)
		}

		// Anonymous user should NOT be deleted
		if len(auth.deletedUsers) != 0 {
			t.Error("Anonymous user should not be deleted when DisableDeleteAnonymousUser is set")
		}
	})
}

func TestService_Close(t *testing.T) {
	t.Run("closes without error", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		service := createTestService(t, store, auth)

		err := service.Close()
		if err != nil {
			t.Errorf("Close() should not error, got: %v", err)
		}
	})

	t.Run("closes with TTL cleanup running", func(t *testing.T) {
		store := newMockAnonymousStore()
		auth := newMockAuthProvider()
		service := createTestService(t, store, auth,
			anonymous.WithAnonymousUserTTL(24*time.Hour),
			anonymous.WithCleanupInterval(100*time.Millisecond),
		)

		// Give cleanup loop time to start
		time.Sleep(50 * time.Millisecond)

		err := service.Close()
		if err != nil {
			t.Errorf("Close() should not error, got: %v", err)
		}
	})
}

func TestService_CleanupStaleUsers(t *testing.T) {
	t.Run("deletes stale anonymous users", func(t *testing.T) {
		store := newMockAnonymousStore()

		// Create old anonymous user (older than 1 second TTL)
		oldTime := time.Now().Add(-2 * time.Second)
		store.addUser("old-anon-1", "old@anonymous.local", "Old Anonymous", true, oldTime)

		// Create fresh anonymous user
		store.addUser("new-anon-1", "new@anonymous.local", "New Anonymous", true, time.Now())

		// Create regular user (should not be deleted)
		store.addUser("regular-1", "regular@example.com", "Regular User", false, time.Now())

		auth := newMockAuthProvider()
		service := createTestService(t, store, auth,
			anonymous.WithAnonymousUserTTL(1*time.Second),
			anonymous.WithCleanupInterval(50*time.Millisecond),
		)

		// Wait for cleanup to run
		time.Sleep(150 * time.Millisecond)

		_ = service.Close()

		// Check that old anonymous user was deleted
		if store.getUser("old-anon-1") != nil {
			t.Error("Old anonymous user should be deleted")
		}

		// Check that new anonymous user still exists
		if store.getUser("new-anon-1") == nil {
			t.Error("New anonymous user should still exist")
		}

		// Check that regular user still exists
		if store.getUser("regular-1") == nil {
			t.Error("Regular user should still exist")
		}
	})
}
