package password

import "errors"

// Password plugin errors
var (
	// Validation errors
	ErrPasswordTooShort = errors.New("password: too short")
	ErrPasswordTooLong  = errors.New("password: too long")
	ErrPasswordTooWeak  = errors.New("password: must contain at least one uppercase letter, one lowercase letter, one digit, and one special character")

	// Authentication errors
	ErrInvalidCredentials = errors.New("password: invalid email or password")
	ErrUserNotFound       = errors.New("password: user not found")
	ErrUserAlreadyExists  = errors.New("password: user already exists")

	// Password reset errors
	ErrPasswordResetNotAvailable = errors.New("password: password reset not available")
	ErrVerificationNotFound      = errors.New("password: verification token not found or expired")
	ErrVerificationExpired       = errors.New("password: verification token has expired")
)
