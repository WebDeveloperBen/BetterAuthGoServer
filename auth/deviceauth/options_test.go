package deviceauth_test

import (
	"context"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/deviceauth"
)

func TestDefaultConfig(t *testing.T) {
	config := deviceauth.DefaultConfig()

	if config.ExpiresIn != 30*time.Minute {
		t.Errorf("ExpiresIn = %v, want 30m", config.ExpiresIn)
	}

	if config.PollingInterval != 5 {
		t.Errorf("PollingInterval = %d, want 5", config.PollingInterval)
	}

	if config.UserCodeLength != 8 {
		t.Errorf("UserCodeLength = %d, want 8", config.UserCodeLength)
	}

	if config.DeviceCodeLength != 40 {
		t.Errorf("DeviceCodeLength = %d, want 40", config.DeviceCodeLength)
	}

	if config.CleanupInterval != 5*time.Minute {
		t.Errorf("CleanupInterval = %v, want 5m", config.CleanupInterval)
	}

	if config.VerificationURI != "" {
		t.Errorf("VerificationURI = %q, want empty (set during init)", config.VerificationURI)
	}

	if config.GenerateDeviceCode != nil {
		t.Error("GenerateDeviceCode should be nil by default")
	}

	if config.GenerateUserCode != nil {
		t.Error("GenerateUserCode should be nil by default")
	}

	if config.ValidateClient != nil {
		t.Error("ValidateClient should be nil by default")
	}

	if config.OnDeviceAuthRequest != nil {
		t.Error("OnDeviceAuthRequest should be nil by default")
	}
}

func TestWithVerificationURI(t *testing.T) {
	config := deviceauth.DefaultConfig()
	deviceauth.WithVerificationURI("https://example.com/activate")(&config)

	if config.VerificationURI != "https://example.com/activate" {
		t.Errorf("VerificationURI = %q, want %q", config.VerificationURI, "https://example.com/activate")
	}
}

func TestWithExpiresIn(t *testing.T) {
	config := deviceauth.DefaultConfig()
	deviceauth.WithExpiresIn(15 * time.Minute)(&config)

	if config.ExpiresIn != 15*time.Minute {
		t.Errorf("ExpiresIn = %v, want 15m", config.ExpiresIn)
	}
}

func TestWithPollingInterval(t *testing.T) {
	config := deviceauth.DefaultConfig()
	deviceauth.WithPollingInterval(10)(&config)

	if config.PollingInterval != 10 {
		t.Errorf("PollingInterval = %d, want 10", config.PollingInterval)
	}
}

func TestWithUserCodeLength(t *testing.T) {
	config := deviceauth.DefaultConfig()
	deviceauth.WithUserCodeLength(6)(&config)

	if config.UserCodeLength != 6 {
		t.Errorf("UserCodeLength = %d, want 6", config.UserCodeLength)
	}
}

func TestWithDeviceCodeLength(t *testing.T) {
	config := deviceauth.DefaultConfig()
	deviceauth.WithDeviceCodeLength(32)(&config)

	if config.DeviceCodeLength != 32 {
		t.Errorf("DeviceCodeLength = %d, want 32", config.DeviceCodeLength)
	}
}

func TestWithGenerateDeviceCode(t *testing.T) {
	customCode := "custom-device-code"
	config := deviceauth.DefaultConfig()
	deviceauth.WithGenerateDeviceCode(func() string {
		return customCode
	})(&config)

	if config.GenerateDeviceCode == nil {
		t.Fatal("GenerateDeviceCode should not be nil")
	}

	if config.GenerateDeviceCode() != customCode {
		t.Errorf("GenerateDeviceCode() = %q, want %q", config.GenerateDeviceCode(), customCode)
	}
}

func TestWithGenerateUserCode(t *testing.T) {
	customCode := "ABCD-1234"
	config := deviceauth.DefaultConfig()
	deviceauth.WithGenerateUserCode(func() string {
		return customCode
	})(&config)

	if config.GenerateUserCode == nil {
		t.Fatal("GenerateUserCode should not be nil")
	}

	if config.GenerateUserCode() != customCode {
		t.Errorf("GenerateUserCode() = %q, want %q", config.GenerateUserCode(), customCode)
	}
}

func TestWithValidateClient(t *testing.T) {
	called := false
	config := deviceauth.DefaultConfig()
	deviceauth.WithValidateClient(func(ctx context.Context, clientID string) error {
		called = true
		return nil
	})(&config)

	if config.ValidateClient == nil {
		t.Fatal("ValidateClient should not be nil")
	}

	_ = config.ValidateClient(context.Background(), "test-client")
	if !called {
		t.Error("ValidateClient was not called")
	}
}

func TestWithOnDeviceAuthRequest(t *testing.T) {
	called := false
	config := deviceauth.DefaultConfig()
	deviceauth.WithOnDeviceAuthRequest(func(ctx context.Context, dc *deviceauth.DeviceCode) error {
		called = true
		return nil
	})(&config)

	if config.OnDeviceAuthRequest == nil {
		t.Fatal("OnDeviceAuthRequest should not be nil")
	}

	_ = config.OnDeviceAuthRequest(context.Background(), &deviceauth.DeviceCode{})
	if !called {
		t.Error("OnDeviceAuthRequest was not called")
	}
}

func TestWithCleanupInterval(t *testing.T) {
	config := deviceauth.DefaultConfig()
	deviceauth.WithCleanupInterval(10 * time.Minute)(&config)

	if config.CleanupInterval != 10*time.Minute {
		t.Errorf("CleanupInterval = %v, want 10m", config.CleanupInterval)
	}
}

func TestOptionsChaining(t *testing.T) {
	config := deviceauth.DefaultConfig()

	opts := []deviceauth.Option{
		deviceauth.WithVerificationURI("https://example.com/device"),
		deviceauth.WithExpiresIn(20 * time.Minute),
		deviceauth.WithPollingInterval(10),
		deviceauth.WithUserCodeLength(6),
		deviceauth.WithDeviceCodeLength(32),
		deviceauth.WithCleanupInterval(15 * time.Minute),
	}

	for _, opt := range opts {
		opt(&config)
	}

	if config.VerificationURI != "https://example.com/device" {
		t.Errorf("VerificationURI = %q, want %q", config.VerificationURI, "https://example.com/device")
	}

	if config.ExpiresIn != 20*time.Minute {
		t.Errorf("ExpiresIn = %v, want 20m", config.ExpiresIn)
	}

	if config.PollingInterval != 10 {
		t.Errorf("PollingInterval = %d, want 10", config.PollingInterval)
	}

	if config.UserCodeLength != 6 {
		t.Errorf("UserCodeLength = %d, want 6", config.UserCodeLength)
	}

	if config.DeviceCodeLength != 32 {
		t.Errorf("DeviceCodeLength = %d, want 32", config.DeviceCodeLength)
	}

	if config.CleanupInterval != 15*time.Minute {
		t.Errorf("CleanupInterval = %v, want 15m", config.CleanupInterval)
	}
}
