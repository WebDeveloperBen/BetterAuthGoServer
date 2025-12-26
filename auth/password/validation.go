package password

import "errors"

// Password validation errors.
var (
	ErrPasswordTooShort = errors.New("password too short")
	ErrPasswordTooLong  = errors.New("password too long")
	ErrPasswordTooWeak  = errors.New("password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character")
)

// ValidatePassword checks if a password meets the requirements.
func ValidatePassword(password string, cfg Config) error {
	if len(password) < cfg.MinLength {
		return ErrPasswordTooShort
	}
	if len(password) > cfg.MaxLength {
		return ErrPasswordTooLong
	}

	// Check complexity requirements if enabled
	if cfg.RequireComplexity {
		var hasUpper, hasLower, hasDigit, hasSpecial bool
		for _, c := range password {
			switch {
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			case c >= 'a' && c <= 'z':
				hasLower = true
			case c >= '0' && c <= '9':
				hasDigit = true
			case isSpecialChar(c):
				hasSpecial = true
			}
		}
		if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
			return ErrPasswordTooWeak
		}
	}

	return nil
}

// isSpecialChar returns true if the rune is a special character.
func isSpecialChar(c rune) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
	for _, s := range specialChars {
		if c == s {
			return true
		}
	}
	return false
}
