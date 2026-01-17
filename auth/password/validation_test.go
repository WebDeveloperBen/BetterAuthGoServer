package password_test

import (
	"testing"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/password"
)

func TestValidatePassword(t *testing.T) {
	defaultConfig := password.DefaultConfig()

	t.Run("accepts valid password with complexity", func(t *testing.T) {
		err := password.ValidatePassword("SecureP@ss1", defaultConfig)
		if err != nil {
			t.Errorf("expected valid password, got error: %v", err)
		}
	})

	t.Run("rejects too short password", func(t *testing.T) {
		err := password.ValidatePassword("Short1!", defaultConfig)
		if err != password.ErrPasswordTooShort {
			t.Errorf("expected ErrPasswordTooShort, got: %v", err)
		}
	})

	t.Run("rejects too long password", func(t *testing.T) {
		// Create a password longer than MaxLength (128)
		longPassword := ""
		for i := 0; i < 130; i++ {
			longPassword += "a"
		}
		err := password.ValidatePassword(longPassword, defaultConfig)
		if err != password.ErrPasswordTooLong {
			t.Errorf("expected ErrPasswordTooLong, got: %v", err)
		}
	})

	t.Run("rejects password without uppercase", func(t *testing.T) {
		err := password.ValidatePassword("lowercase123!", defaultConfig)
		if err != password.ErrPasswordTooWeak {
			t.Errorf("expected ErrPasswordTooWeak, got: %v", err)
		}
	})

	t.Run("rejects password without lowercase", func(t *testing.T) {
		err := password.ValidatePassword("UPPERCASE123!", defaultConfig)
		if err != password.ErrPasswordTooWeak {
			t.Errorf("expected ErrPasswordTooWeak, got: %v", err)
		}
	})

	t.Run("rejects password without digit", func(t *testing.T) {
		err := password.ValidatePassword("NoDigits!Here", defaultConfig)
		if err != password.ErrPasswordTooWeak {
			t.Errorf("expected ErrPasswordTooWeak, got: %v", err)
		}
	})

	t.Run("rejects password without special character", func(t *testing.T) {
		err := password.ValidatePassword("NoSpecial123Abc", defaultConfig)
		if err != password.ErrPasswordTooWeak {
			t.Errorf("expected ErrPasswordTooWeak, got: %v", err)
		}
	})

	t.Run("accepts simple password when complexity disabled", func(t *testing.T) {
		config := password.Config{
			MinLength:         8,
			MaxLength:         128,
			RequireComplexity: false,
		}
		err := password.ValidatePassword("simplepass", config)
		if err != nil {
			t.Errorf("expected valid password without complexity, got error: %v", err)
		}
	})

	t.Run("custom min length", func(t *testing.T) {
		config := password.Config{
			MinLength:         12,
			MaxLength:         128,
			RequireComplexity: false,
		}
		err := password.ValidatePassword("shortpass", config)
		if err != password.ErrPasswordTooShort {
			t.Errorf("expected ErrPasswordTooShort, got: %v", err)
		}
	})

	t.Run("custom max length", func(t *testing.T) {
		config := password.Config{
			MinLength:         1,
			MaxLength:         10,
			RequireComplexity: false,
		}
		err := password.ValidatePassword("verylongpassword", config)
		if err != password.ErrPasswordTooLong {
			t.Errorf("expected ErrPasswordTooLong, got: %v", err)
		}
	})

	t.Run("accepts various special characters", func(t *testing.T) {
		specialChars := []string{
			"Password1!", "Password1@", "Password1#", "Password1$",
			"Password1%", "Password1^", "Password1&", "Password1*",
			"Password1(", "Password1)", "Password1_", "Password1+",
			"Password1-", "Password1=", "Password1[", "Password1]",
			"Password1{", "Password1}", "Password1|", "Password1;",
			"Password1:", "Password1'", "Password1\"", "Password1,",
			"Password1.", "Password1/", "Password1<", "Password1>",
			"Password1?", "Password1`", "Password1~",
		}

		for _, pw := range specialChars {
			err := password.ValidatePassword(pw, defaultConfig)
			if err != nil {
				t.Errorf("expected password %q to be valid, got error: %v", pw, err)
			}
		}
	})

	t.Run("edge case - exactly min length", func(t *testing.T) {
		config := password.Config{
			MinLength:         8,
			MaxLength:         128,
			RequireComplexity: false,
		}
		err := password.ValidatePassword("12345678", config)
		if err != nil {
			t.Errorf("expected password at min length to be valid, got: %v", err)
		}
	})

	t.Run("edge case - exactly max length", func(t *testing.T) {
		config := password.Config{
			MinLength:         1,
			MaxLength:         10,
			RequireComplexity: false,
		}
		err := password.ValidatePassword("1234567890", config)
		if err != nil {
			t.Errorf("expected password at max length to be valid, got: %v", err)
		}
	})
}
