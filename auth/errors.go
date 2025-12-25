package auth

import "errors"

// Sentinel errors for authentication operations
var (
	// User errors
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidEmail      = errors.New("invalid email address")

	// Password errors
	ErrInvalidPassword      = errors.New("invalid password")
	ErrPasswordTooShort     = errors.New("password too short")
	ErrPasswordTooLong      = errors.New("password too long")
	ErrPasswordTooWeak      = errors.New("password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character")
	ErrInvalidCredentials   = errors.New("invalid credentials") // Generic to prevent user enumeration

	// Session errors
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrInvalidToken    = errors.New("invalid token")

	// Verification errors
	ErrVerificationNotFound = errors.New("verification not found")
	ErrVerificationExpired  = errors.New("verification expired")
	ErrEmailAlreadyVerified = errors.New("email already verified")

	// OAuth errors
	ErrOAuthProviderNotFound = errors.New("oauth provider not found")
	ErrOAuthStateMismatch    = errors.New("oauth state mismatch")
	ErrOAuthStateExpired     = errors.New("oauth state expired")
	ErrInvalidRedirect       = errors.New("invalid redirect URL")

	// Account errors
	ErrAccountNotFound      = errors.New("account not found")
	ErrAccountAlreadyLinked = errors.New("account already linked")

	// CSRF errors
	ErrCSRFTokenMissing  = errors.New("csrf token missing")
	ErrCSRFTokenMismatch = errors.New("csrf token mismatch")

	// Rate limiting errors
	ErrRateLimitExceeded = errors.New("rate limit exceeded")

	// Configuration errors
	ErrMissingSecret  = errors.New("secret is required")
	ErrSecretTooShort = errors.New("secret must be at least 32 bytes")
	ErrMissingBaseURL = errors.New("base url is required")
	ErrMissingStore   = errors.New("store is required")
)
