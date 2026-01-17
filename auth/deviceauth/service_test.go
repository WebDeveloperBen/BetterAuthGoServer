package deviceauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
)

func TestService_CreateDeviceCode(t *testing.T) {
	t.Run("creates device code successfully", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, err := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "test-client",
			Scope:    "openid profile",
		})

		if err != nil {
			t.Fatalf("CreateDeviceCode failed: %v", err)
		}

		if result.DeviceCode == "" {
			t.Error("DeviceCode should not be empty")
		}

		if result.UserCode == "" {
			t.Error("UserCode should not be empty")
		}

		// User code should have hyphen in middle
		if len(result.UserCode) != 9 { // 8 chars + 1 hyphen
			t.Errorf("UserCode length = %d, want 9", len(result.UserCode))
		}

		if result.VerificationURI != "https://example.com/device" {
			t.Errorf("VerificationURI = %q, want %q", result.VerificationURI, "https://example.com/device")
		}

		if result.ExpiresIn != 1800 { // 30 minutes
			t.Errorf("ExpiresIn = %d, want 1800", result.ExpiresIn)
		}

		if result.Interval != 5 {
			t.Errorf("Interval = %d, want 5", result.Interval)
		}
	})

	t.Run("creates device code without client_id", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, err := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{})

		if err != nil {
			t.Fatalf("CreateDeviceCode failed: %v", err)
		}

		if result.DeviceCode == "" {
			t.Error("DeviceCode should not be empty")
		}
	})

	t.Run("calls ValidateClient hook", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		validateCalled := false
		service := createTestService(t, store, deviceauth.WithValidateClient(func(ctx context.Context, clientID string) error {
			validateCalled = true
			if clientID != "my-client" {
				t.Errorf("clientID = %q, want %q", clientID, "my-client")
			}
			return nil
		}))
		defer func() { _ = service.Close() }()

		_, err := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "my-client",
		})

		if err != nil {
			t.Fatalf("CreateDeviceCode failed: %v", err)
		}

		if !validateCalled {
			t.Error("ValidateClient hook was not called")
		}
	})

	t.Run("rejects invalid client", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store, deviceauth.WithValidateClient(func(ctx context.Context, clientID string) error {
			return deviceauth.ErrInvalidClient
		}))
		defer func() { _ = service.Close() }()

		_, err := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "invalid-client",
		})

		if err != deviceauth.ErrInvalidClient {
			t.Errorf("err = %v, want ErrInvalidClient", err)
		}
	})

	t.Run("calls OnDeviceAuthRequest hook", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		hookCalled := false
		service := createTestService(t, store, deviceauth.WithOnDeviceAuthRequest(func(ctx context.Context, dc *deviceauth.DeviceCode) error {
			hookCalled = true
			if dc.UserCode == "" {
				t.Error("DeviceCode.UserCode should not be empty in hook")
			}
			return nil
		}))
		defer func() { _ = service.Close() }()

		_, err := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{})

		if err != nil {
			t.Fatalf("CreateDeviceCode failed: %v", err)
		}

		if !hookCalled {
			t.Error("OnDeviceAuthRequest hook was not called")
		}
	})
}

func TestService_GetByUserCode(t *testing.T) {
	t.Run("retrieves device code by user code", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "test-client",
		})

		dc, err := service.GetByUserCode(context.Background(), result.UserCode)

		if err != nil {
			t.Fatalf("GetByUserCode failed: %v", err)
		}

		if dc == nil {
			t.Fatal("DeviceCode should not be nil")
		}

		if dc.UserCode != result.UserCode {
			t.Errorf("UserCode = %q, want %q", dc.UserCode, result.UserCode)
		}
	})

	t.Run("normalizes user code (removes hyphens)", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{})

		// Try without hyphen
		codeWithoutHyphen := result.UserCode[:4] + result.UserCode[5:]
		dc, err := service.GetByUserCode(context.Background(), codeWithoutHyphen)

		if err != nil {
			t.Fatalf("GetByUserCode failed: %v", err)
		}

		if dc == nil {
			t.Error("Should find device code without hyphen")
		}
	})

	t.Run("returns error for invalid user code", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		_, err := service.GetByUserCode(context.Background(), "INVALID-CODE")

		if err != deviceauth.ErrInvalidUserCode {
			t.Errorf("err = %v, want ErrInvalidUserCode", err)
		}
	})

	t.Run("returns error for expired user code", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store, deviceauth.WithExpiresIn(1*time.Millisecond))
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{})

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		_, err := service.GetByUserCode(context.Background(), result.UserCode)

		if err != deviceauth.ErrExpiredUserCode {
			t.Errorf("err = %v, want ErrExpiredUserCode", err)
		}
	})
}

func TestService_Approve(t *testing.T) {
	t.Run("approves device code successfully", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{})

		err := service.Approve(context.Background(), result.UserCode, "user-123")

		if err != nil {
			t.Fatalf("Approve failed: %v", err)
		}

		// Verify status changed
		dc, _ := service.GetByUserCode(context.Background(), result.UserCode)
		if !dc.IsApproved() {
			t.Error("DeviceCode should be approved")
		}
		if dc.UserID == nil || *dc.UserID != "user-123" {
			t.Error("UserID should be set to user-123")
		}
	})

	t.Run("returns error for already processed code", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{})

		// Approve first time
		_ = service.Approve(context.Background(), result.UserCode, "user-123")

		// Try to approve again
		err := service.Approve(context.Background(), result.UserCode, "user-456")

		if err != deviceauth.ErrAlreadyProcessed {
			t.Errorf("err = %v, want ErrAlreadyProcessed", err)
		}
	})
}

func TestService_Deny(t *testing.T) {
	t.Run("denies device code successfully", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{})

		err := service.Deny(context.Background(), result.UserCode)

		if err != nil {
			t.Fatalf("Deny failed: %v", err)
		}

		// Verify status changed
		dc, _ := service.GetByUserCode(context.Background(), result.UserCode)
		if !dc.IsDenied() {
			t.Error("DeviceCode should be denied")
		}
	})
}

func TestService_CheckToken(t *testing.T) {
	t.Run("returns authorization pending for pending code", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "test-client",
		})

		_, err := service.CheckToken(context.Background(), result.DeviceCode, "test-client")

		if err != deviceauth.ErrAuthorizationPending {
			t.Errorf("err = %v, want ErrAuthorizationPending", err)
		}
	})

	t.Run("returns access denied for denied code", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "test-client",
		})

		_ = service.Deny(context.Background(), result.UserCode)

		_, err := service.CheckToken(context.Background(), result.DeviceCode, "test-client")

		if err != deviceauth.ErrAccessDenied {
			t.Errorf("err = %v, want ErrAccessDenied", err)
		}
	})

	t.Run("returns user ID for approved code", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "test-client",
		})

		_ = service.Approve(context.Background(), result.UserCode, "user-123")

		checkResult, err := service.CheckToken(context.Background(), result.DeviceCode, "test-client")

		if err != nil {
			t.Fatalf("CheckToken failed: %v", err)
		}

		if !checkResult.Approved {
			t.Error("Result should indicate approved")
		}

		if checkResult.UserID != "user-123" {
			t.Errorf("UserID = %q, want %q", checkResult.UserID, "user-123")
		}
	})

	t.Run("returns slow down for rapid polling", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store, deviceauth.WithPollingInterval(5))
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "test-client",
		})

		// First poll should succeed (pending)
		_, _ = service.CheckToken(context.Background(), result.DeviceCode, "test-client")

		// Second poll immediately should fail with slow_down
		_, err := service.CheckToken(context.Background(), result.DeviceCode, "test-client")

		if err != deviceauth.ErrSlowDown {
			t.Errorf("err = %v, want ErrSlowDown", err)
		}
	})

	t.Run("returns expired for expired code", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store, deviceauth.WithExpiresIn(1*time.Millisecond))
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "test-client",
		})

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		_, err := service.CheckToken(context.Background(), result.DeviceCode, "test-client")

		if err != deviceauth.ErrExpiredDeviceCode {
			t.Errorf("err = %v, want ErrExpiredDeviceCode", err)
		}
	})

	t.Run("returns invalid client for mismatched client_id", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)
		defer func() { _ = service.Close() }()

		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{
			ClientID: "client-a",
		})

		_, err := service.CheckToken(context.Background(), result.DeviceCode, "client-b")

		if err != deviceauth.ErrInvalidClient {
			t.Errorf("err = %v, want ErrInvalidClient", err)
		}
	})
}

func TestService_CleanupExpired(t *testing.T) {
	t.Run("removes expired device codes", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store, deviceauth.WithExpiresIn(1*time.Millisecond))
		defer func() { _ = service.Close() }()

		// Create a device code that will expire
		result, _ := service.CreateDeviceCode(context.Background(), deviceauth.CreateDeviceCodeRequest{})

		// Wait for expiration
		time.Sleep(10 * time.Millisecond)

		count, err := service.CleanupExpired(context.Background())

		if err != nil {
			t.Fatalf("CleanupExpired failed: %v", err)
		}

		if count != 1 {
			t.Errorf("count = %d, want 1", count)
		}

		// Verify code is gone
		_, err = service.GetByUserCode(context.Background(), result.UserCode)
		if err != deviceauth.ErrInvalidUserCode {
			t.Error("Code should be deleted")
		}
	})
}

func TestService_Close(t *testing.T) {
	t.Run("closes without error", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store)

		err := service.Close()
		if err != nil {
			t.Errorf("Close() should not error, got: %v", err)
		}
	})

	t.Run("closes with cleanup running", func(t *testing.T) {
		store := newMockDeviceCodeStore()
		service := createTestService(t, store,
			deviceauth.WithCleanupInterval(100*time.Millisecond),
		)

		// Give cleanup loop time to start
		time.Sleep(50 * time.Millisecond)

		err := service.Close()
		if err != nil {
			t.Errorf("Close() should not error, got: %v", err)
		}
	})
}
