package anonymous

import (
	"context"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	if config.EmailDomain != "anonymous.local" {
		t.Errorf("EmailDomain = %q, want %q", config.EmailDomain, "anonymous.local")
	}

	if config.DisableDeleteAnonymousUser != false {
		t.Error("DisableDeleteAnonymousUser should be false by default")
	}

	if config.AnonymousUserTTL != 0 {
		t.Errorf("AnonymousUserTTL = %v, want %v", config.AnonymousUserTTL, time.Duration(0))
	}

	if config.CleanupInterval != time.Hour {
		t.Errorf("CleanupInterval = %v, want %v", config.CleanupInterval, time.Hour)
	}

	if config.GenerateEmail != nil {
		t.Error("GenerateEmail should be nil by default")
	}

	if config.GenerateName != nil {
		t.Error("GenerateName should be nil by default")
	}

	if config.OnLinkAccount != nil {
		t.Error("OnLinkAccount should be nil by default")
	}
}

func TestWithEmailDomain(t *testing.T) {
	config := DefaultConfig()
	opt := WithEmailDomain("custom.local")
	opt(&config)

	if config.EmailDomain != "custom.local" {
		t.Errorf("EmailDomain = %q, want %q", config.EmailDomain, "custom.local")
	}
}

func TestWithGenerateEmail(t *testing.T) {
	config := DefaultConfig()
	customEmail := "custom@test.com"
	opt := WithGenerateEmail(func() string { return customEmail })
	opt(&config)

	if config.GenerateEmail == nil {
		t.Fatal("GenerateEmail should not be nil")
	}

	if config.GenerateEmail() != customEmail {
		t.Errorf("GenerateEmail() = %q, want %q", config.GenerateEmail(), customEmail)
	}
}

func TestWithGenerateName(t *testing.T) {
	config := DefaultConfig()
	customName := "Guest User"
	opt := WithGenerateName(func() string { return customName })
	opt(&config)

	if config.GenerateName == nil {
		t.Fatal("GenerateName should not be nil")
	}

	if config.GenerateName() != customName {
		t.Errorf("GenerateName() = %q, want %q", config.GenerateName(), customName)
	}
}

func TestWithOnLinkAccount(t *testing.T) {
	config := DefaultConfig()
	called := false
	opt := WithOnLinkAccount(func(ctx context.Context, anonUser, newUser *plugin.User) error {
		called = true
		return nil
	})
	opt(&config)

	if config.OnLinkAccount == nil {
		t.Fatal("OnLinkAccount should not be nil")
	}

	// Call the function to verify it works
	_ = config.OnLinkAccount(context.Background(), nil, nil)
	if !called {
		t.Error("OnLinkAccount callback was not called")
	}
}

func TestWithDisableDeleteAnonymousUser(t *testing.T) {
	config := DefaultConfig()

	if config.DisableDeleteAnonymousUser {
		t.Error("DisableDeleteAnonymousUser should be false initially")
	}

	opt := WithDisableDeleteAnonymousUser()
	opt(&config)

	if !config.DisableDeleteAnonymousUser {
		t.Error("DisableDeleteAnonymousUser should be true after option applied")
	}
}

func TestWithAnonymousUserTTL(t *testing.T) {
	config := DefaultConfig()
	ttl := 30 * 24 * time.Hour
	opt := WithAnonymousUserTTL(ttl)
	opt(&config)

	if config.AnonymousUserTTL != ttl {
		t.Errorf("AnonymousUserTTL = %v, want %v", config.AnonymousUserTTL, ttl)
	}
}

func TestWithCleanupInterval(t *testing.T) {
	config := DefaultConfig()
	interval := 30 * time.Minute
	opt := WithCleanupInterval(interval)
	opt(&config)

	if config.CleanupInterval != interval {
		t.Errorf("CleanupInterval = %v, want %v", config.CleanupInterval, interval)
	}
}

func TestMultipleOptions(t *testing.T) {
	config := DefaultConfig()

	opts := []Option{
		WithEmailDomain("myapp.local"),
		WithAnonymousUserTTL(7 * 24 * time.Hour),
		WithCleanupInterval(15 * time.Minute),
		WithDisableDeleteAnonymousUser(),
	}

	for _, opt := range opts {
		opt(&config)
	}

	if config.EmailDomain != "myapp.local" {
		t.Errorf("EmailDomain = %q, want %q", config.EmailDomain, "myapp.local")
	}

	if config.AnonymousUserTTL != 7*24*time.Hour {
		t.Errorf("AnonymousUserTTL = %v, want %v", config.AnonymousUserTTL, 7*24*time.Hour)
	}

	if config.CleanupInterval != 15*time.Minute {
		t.Errorf("CleanupInterval = %v, want %v", config.CleanupInterval, 15*time.Minute)
	}

	if !config.DisableDeleteAnonymousUser {
		t.Error("DisableDeleteAnonymousUser should be true")
	}
}
