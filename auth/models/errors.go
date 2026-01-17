package models

import "errors"

// Core auth errors used across the main auth package.
// Plugin-specific errors should be defined in their respective packages
// with the format "package: error message" (e.g., "oauth: state mismatch").
var (
	// User errors
	ErrUserNotFound      = errors.New("auth: user not found")
	ErrUserAlreadyExists = errors.New("auth: user already exists")
	ErrUserBanned        = errors.New("auth: user is banned")
	ErrInvalidEmail      = errors.New("auth: invalid email address")

	// Session errors
	ErrSessionNotFound = errors.New("auth: session not found")
	ErrSessionExpired  = errors.New("auth: session expired")

	// Verification errors
	ErrVerificationNotFound          = errors.New("auth: verification not found")
	ErrVerificationExpired           = errors.New("auth: verification expired")
	ErrEmailAlreadyVerified          = errors.New("auth: email already verified")
	ErrEmailVerificationNotAvailable = errors.New("auth: email verification not available")
	ErrEmailNotVerified              = errors.New("auth: email not verified")

	// Account errors
	ErrAccountNotFound         = errors.New("auth: account not found")
	ErrAccountAlreadyLinked    = errors.New("auth: account already linked")
	ErrCannotUnlinkLastAccount = errors.New("auth: cannot unlink last authentication method")

	// General errors
	ErrInvalidRequest       = errors.New("auth: invalid request")
	ErrForbidden            = errors.New("auth: forbidden")
	ErrMissingStore         = errors.New("auth: store is required")
	ErrInvalidProfileUpdate = errors.New("auth: invalid profile update")
)
