package auth

import (
	"context"
	"testing"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/hooks"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Session defaults
	if cfg.SessionDuration != 7*24*time.Hour {
		t.Errorf("SessionDuration = %v, want %v", cfg.SessionDuration, 7*24*time.Hour)
	}
	if cfg.SessionCookie != "session" {
		t.Errorf("SessionCookie = %s, want session", cfg.SessionCookie)
	}

	// Password defaults
	if cfg.PasswordMinLength != 8 {
		t.Errorf("PasswordMinLength = %d, want 8", cfg.PasswordMinLength)
	}
	if cfg.PasswordMaxLength != 128 {
		t.Errorf("PasswordMaxLength = %d, want 128", cfg.PasswordMaxLength)
	}
	if !cfg.RequirePasswordComplexity {
		t.Error("RequirePasswordComplexity should default to true")
	}

	// Email verification defaults
	if cfg.RequireEmailVerification {
		t.Error("RequireEmailVerification should default to false")
	}
	if cfg.EmailVerificationExpiry != 24*time.Hour {
		t.Errorf("EmailVerificationExpiry = %v, want %v", cfg.EmailVerificationExpiry, 24*time.Hour)
	}

	// Password reset defaults
	if cfg.PasswordResetExpiry != 1*time.Hour {
		t.Errorf("PasswordResetExpiry = %v, want %v", cfg.PasswordResetExpiry, 1*time.Hour)
	}

	// Auto sign-in defaults
	if !cfg.AutoSignIn {
		t.Error("AutoSignIn should default to true")
	}

	// CSRF defaults
	if !cfg.CSRFEnabled {
		t.Error("CSRFEnabled should default to true")
	}
	if cfg.CSRFCookieName != "csrf_token" {
		t.Errorf("CSRFCookieName = %s, want csrf_token", cfg.CSRFCookieName)
	}
	if cfg.CSRFHeaderName != "X-CSRF-Token" {
		t.Errorf("CSRFHeaderName = %s, want X-CSRF-Token", cfg.CSRFHeaderName)
	}

	// Rate limiting defaults
	if !cfg.RateLimitEnabled {
		t.Error("RateLimitEnabled should default to true")
	}
	if cfg.RateLimitWindow != time.Minute {
		t.Errorf("RateLimitWindow = %v, want %v", cfg.RateLimitWindow, time.Minute)
	}
	if cfg.RateLimitMax != 100 {
		t.Errorf("RateLimitMax = %d, want 100", cfg.RateLimitMax)
	}
	if cfg.AuthRateLimitMax != 10 {
		t.Errorf("AuthRateLimitMax = %d, want 10", cfg.AuthRateLimitMax)
	}

	// Session cleanup defaults
	if cfg.SessionCleanupInterval != 1*time.Hour {
		t.Errorf("SessionCleanupInterval = %v, want %v", cfg.SessionCleanupInterval, 1*time.Hour)
	}
}

func TestConfig_Validate(t *testing.T) {
	// 32-byte secret for valid tests
	validSecret := "this-is-a-valid-32-byte-secret!!" // exactly 32 bytes

	tests := []struct {
		name      string
		config    Config
		wantError error
	}{
		{
			name: "valid config",
			config: Config{
				Secret:  validSecret,
				BaseURL: "http://localhost:3000",
			},
			wantError: nil,
		},
		{
			name: "missing secret",
			config: Config{
				Secret:  "",
				BaseURL: "http://localhost:3000",
			},
			wantError: ErrMissingSecret,
		},
		{
			name: "secret too short",
			config: Config{
				Secret:  "short", // Less than 32 bytes
				BaseURL: "http://localhost:3000",
			},
			wantError: ErrSecretTooShort,
		},
		{
			name: "missing base URL",
			config: Config{
				Secret:  validSecret,
				BaseURL: "",
			},
			wantError: ErrMissingBaseURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if err != tt.wantError {
				t.Errorf("validate() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestWithSecret(t *testing.T) {
	cfg := DefaultConfig()
	secret := "my-super-secret-key"
	WithSecret(secret)(&cfg)

	if cfg.Secret != secret {
		t.Errorf("Secret = %s, want %s", cfg.Secret, secret)
	}
}

func TestWithBaseURL(t *testing.T) {
	cfg := DefaultConfig()
	url := "https://api.example.com"
	WithBaseURL(url)(&cfg)

	if cfg.BaseURL != url {
		t.Errorf("BaseURL = %s, want %s", cfg.BaseURL, url)
	}
}

func TestWithSessionDuration(t *testing.T) {
	cfg := DefaultConfig()
	duration := 48 * time.Hour
	WithSessionDuration(duration)(&cfg)

	if cfg.SessionDuration != duration {
		t.Errorf("SessionDuration = %v, want %v", cfg.SessionDuration, duration)
	}
}

func TestWithSessionCookie(t *testing.T) {
	cfg := DefaultConfig()
	name := "my_session"
	WithSessionCookie(name)(&cfg)

	if cfg.SessionCookie != name {
		t.Errorf("SessionCookie = %s, want %s", cfg.SessionCookie, name)
	}
}

func TestWithPasswordPolicy(t *testing.T) {
	cfg := DefaultConfig()
	WithPasswordPolicy(12, 64)(&cfg)

	if cfg.PasswordMinLength != 12 {
		t.Errorf("PasswordMinLength = %d, want 12", cfg.PasswordMinLength)
	}
	if cfg.PasswordMaxLength != 64 {
		t.Errorf("PasswordMaxLength = %d, want 64", cfg.PasswordMaxLength)
	}
}

func TestWithPasswordComplexity(t *testing.T) {
	cfg := DefaultConfig()
	WithPasswordComplexity(false)(&cfg)

	if cfg.RequirePasswordComplexity {
		t.Error("RequirePasswordComplexity should be false")
	}
}

func TestWithEmailVerification(t *testing.T) {
	cfg := DefaultConfig()
	WithEmailVerification(true, 48*time.Hour)(&cfg)

	if !cfg.RequireEmailVerification {
		t.Error("RequireEmailVerification should be true")
	}
	if cfg.EmailVerificationExpiry != 48*time.Hour {
		t.Errorf("EmailVerificationExpiry = %v, want %v", cfg.EmailVerificationExpiry, 48*time.Hour)
	}
}

func TestWithPasswordResetExpiry(t *testing.T) {
	cfg := DefaultConfig()
	expiry := 2 * time.Hour
	WithPasswordResetExpiry(expiry)(&cfg)

	if cfg.PasswordResetExpiry != expiry {
		t.Errorf("PasswordResetExpiry = %v, want %v", cfg.PasswordResetExpiry, expiry)
	}
}

func TestWithAutoSignIn(t *testing.T) {
	cfg := DefaultConfig()
	WithAutoSignIn(false)(&cfg)

	if cfg.AutoSignIn {
		t.Error("AutoSignIn should be false")
	}
}

func TestWithCSRF(t *testing.T) {
	cfg := DefaultConfig()
	WithCSRF(false)(&cfg)

	if cfg.CSRFEnabled {
		t.Error("CSRFEnabled should be false")
	}
}

func TestWithCSRFCookie(t *testing.T) {
	cfg := DefaultConfig()
	name := "_csrf"
	WithCSRFCookie(name)(&cfg)

	if cfg.CSRFCookieName != name {
		t.Errorf("CSRFCookieName = %s, want %s", cfg.CSRFCookieName, name)
	}
}

func TestWithCSRFHeader(t *testing.T) {
	cfg := DefaultConfig()
	name := "X-XSRF-Token"
	WithCSRFHeader(name)(&cfg)

	if cfg.CSRFHeaderName != name {
		t.Errorf("CSRFHeaderName = %s, want %s", cfg.CSRFHeaderName, name)
	}
}

func TestWithRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	WithRateLimit(false, 30*time.Second, 50)(&cfg)

	if cfg.RateLimitEnabled {
		t.Error("RateLimitEnabled should be false")
	}
	if cfg.RateLimitWindow != 30*time.Second {
		t.Errorf("RateLimitWindow = %v, want %v", cfg.RateLimitWindow, 30*time.Second)
	}
	if cfg.RateLimitMax != 50 {
		t.Errorf("RateLimitMax = %d, want 50", cfg.RateLimitMax)
	}
}

func TestWithAuthRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	WithAuthRateLimit(5)(&cfg)

	if cfg.AuthRateLimitMax != 5 {
		t.Errorf("AuthRateLimitMax = %d, want 5", cfg.AuthRateLimitMax)
	}
}

func TestWithSessionCleanupInterval(t *testing.T) {
	cfg := DefaultConfig()
	interval := 30 * time.Minute
	WithSessionCleanupInterval(interval)(&cfg)

	if cfg.SessionCleanupInterval != interval {
		t.Errorf("SessionCleanupInterval = %v, want %v", cfg.SessionCleanupInterval, interval)
	}
}

func TestWithTrustedOrigins(t *testing.T) {
	cfg := DefaultConfig()
	origins := []string{"https://example.com", "https://api.example.com"}
	WithTrustedOrigins(origins...)(&cfg)

	if len(cfg.TrustedOrigins) != 2 {
		t.Errorf("TrustedOrigins length = %d, want 2", len(cfg.TrustedOrigins))
	}
	if cfg.TrustedOrigins[0] != origins[0] {
		t.Errorf("TrustedOrigins[0] = %s, want %s", cfg.TrustedOrigins[0], origins[0])
	}
}

func TestWithTrustedProxies(t *testing.T) {
	cfg := DefaultConfig()
	proxies := []string{"10.0.0.1", "10.0.0.2"}
	WithTrustedProxies(proxies...)(&cfg)

	if len(cfg.TrustedProxies) != 2 {
		t.Errorf("TrustedProxies length = %d, want 2", len(cfg.TrustedProxies))
	}
	if cfg.TrustedProxies[0] != proxies[0] {
		t.Errorf("TrustedProxies[0] = %s, want %s", cfg.TrustedProxies[0], proxies[0])
	}
}

func TestWithHooks(t *testing.T) {
	cfg := DefaultConfig()
	h := hooks.Hooks{
		OnUserCreated: func(ctx context.Context, user *models.User) error {
			return nil
		},
	}
	WithHooks(h)(&cfg)

	if cfg.Hooks.OnUserCreated == nil {
		t.Error("OnUserCreated hook should be set")
	}
}

func TestMinSecretLength(t *testing.T) {
	if MinSecretLength != 32 {
		t.Errorf("MinSecretLength = %d, want 32", MinSecretLength)
	}
}

func TestConfigOptionsChaining(t *testing.T) {
	cfg := DefaultConfig()

	// Apply multiple options
	opts := []Option{
		WithSecret("this-is-a-valid-32-byte-secret!!"),
		WithBaseURL("https://api.example.com"),
		WithSessionDuration(24 * time.Hour),
		WithCSRF(false),
		WithRateLimit(true, time.Minute, 200),
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.Secret != "this-is-a-valid-32-byte-secret!!" {
		t.Error("Secret not set correctly")
	}
	if cfg.BaseURL != "https://api.example.com" {
		t.Error("BaseURL not set correctly")
	}
	if cfg.SessionDuration != 24*time.Hour {
		t.Error("SessionDuration not set correctly")
	}
	if cfg.CSRFEnabled {
		t.Error("CSRFEnabled not set correctly")
	}
	if cfg.RateLimitMax != 200 {
		t.Error("RateLimitMax not set correctly")
	}
}
