package deviceauth_test

import (
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
)

func TestDeviceCodeStatus_Constants(t *testing.T) {
	if deviceauth.StatusPending != "pending" {
		t.Errorf("StatusPending = %q, want %q", deviceauth.StatusPending, "pending")
	}

	if deviceauth.StatusApproved != "approved" {
		t.Errorf("StatusApproved = %q, want %q", deviceauth.StatusApproved, "approved")
	}

	if deviceauth.StatusDenied != "denied" {
		t.Errorf("StatusDenied = %q, want %q", deviceauth.StatusDenied, "denied")
	}
}

func TestDeviceCode_IsExpired(t *testing.T) {
	t.Run("returns false for future expiration", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}

		if dc.IsExpired() {
			t.Error("IsExpired() should return false for future expiration")
		}
	})

	t.Run("returns true for past expiration", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		if !dc.IsExpired() {
			t.Error("IsExpired() should return true for past expiration")
		}
	})
}

func TestDeviceCode_IsPending(t *testing.T) {
	t.Run("returns true for pending status", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			Status: deviceauth.StatusPending,
		}

		if !dc.IsPending() {
			t.Error("IsPending() should return true for pending status")
		}
	})

	t.Run("returns false for approved status", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			Status: deviceauth.StatusApproved,
		}

		if dc.IsPending() {
			t.Error("IsPending() should return false for approved status")
		}
	})

	t.Run("returns false for denied status", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			Status: deviceauth.StatusDenied,
		}

		if dc.IsPending() {
			t.Error("IsPending() should return false for denied status")
		}
	})
}

func TestDeviceCode_IsApproved(t *testing.T) {
	t.Run("returns true for approved status", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			Status: deviceauth.StatusApproved,
		}

		if !dc.IsApproved() {
			t.Error("IsApproved() should return true for approved status")
		}
	})

	t.Run("returns false for pending status", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			Status: deviceauth.StatusPending,
		}

		if dc.IsApproved() {
			t.Error("IsApproved() should return false for pending status")
		}
	})
}

func TestDeviceCode_IsDenied(t *testing.T) {
	t.Run("returns true for denied status", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			Status: deviceauth.StatusDenied,
		}

		if !dc.IsDenied() {
			t.Error("IsDenied() should return true for denied status")
		}
	})

	t.Run("returns false for pending status", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			Status: deviceauth.StatusPending,
		}

		if dc.IsDenied() {
			t.Error("IsDenied() should return false for pending status")
		}
	})
}

func TestDeviceCode_CanPoll(t *testing.T) {
	t.Run("returns true for first poll (nil LastPolledAt)", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			PollingInterval: 5,
			LastPolledAt:    nil,
		}

		if !dc.CanPoll() {
			t.Error("CanPoll() should return true for first poll")
		}
	})

	t.Run("returns true after interval has passed", func(t *testing.T) {
		lastPolled := time.Now().Add(-10 * time.Second)
		dc := &deviceauth.DeviceCode{
			PollingInterval: 5,
			LastPolledAt:    &lastPolled,
		}

		if !dc.CanPoll() {
			t.Error("CanPoll() should return true after interval has passed")
		}
	})

	t.Run("returns false before interval has passed", func(t *testing.T) {
		lastPolled := time.Now().Add(-2 * time.Second)
		dc := &deviceauth.DeviceCode{
			PollingInterval: 5,
			LastPolledAt:    &lastPolled,
		}

		if dc.CanPoll() {
			t.Error("CanPoll() should return false before interval has passed")
		}
	})
}

func TestDeviceCode_ExpiresInSeconds(t *testing.T) {
	t.Run("returns positive seconds for future expiration", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			ExpiresAt: time.Now().Add(30 * time.Second),
		}

		seconds := dc.ExpiresInSeconds()
		if seconds < 28 || seconds > 31 {
			t.Errorf("ExpiresInSeconds() = %d, want ~30", seconds)
		}
	})

	t.Run("returns 0 for past expiration", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			ExpiresAt: time.Now().Add(-1 * time.Hour),
		}

		if dc.ExpiresInSeconds() != 0 {
			t.Errorf("ExpiresInSeconds() = %d, want 0", dc.ExpiresInSeconds())
		}
	})

	t.Run("returns large value for far future expiration", func(t *testing.T) {
		dc := &deviceauth.DeviceCode{
			ExpiresAt: time.Now().Add(30 * time.Minute),
		}

		seconds := dc.ExpiresInSeconds()
		// 30 minutes = 1800 seconds, allow some margin
		if seconds < 1795 || seconds > 1805 {
			t.Errorf("ExpiresInSeconds() = %d, want ~1800", seconds)
		}
	})
}
