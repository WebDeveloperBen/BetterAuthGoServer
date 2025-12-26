package jwt

import "errors"

// JWT plugin errors
var (
	// Token validation errors
	ErrInvalidToken         = errors.New("jwt: invalid token")
	ErrExpiredToken         = errors.New("jwt: token expired")
	ErrInvalidTokenType     = errors.New("jwt: invalid token type")
	ErrTokenRevoked         = errors.New("jwt: token revoked")
	ErrInvalidSigningKey    = errors.New("jwt: invalid signing key")
	ErrUnsupportedAlgorithm = errors.New("jwt: unsupported algorithm")

	// Plugin errors
	ErrNotInitialized = errors.New("jwt: plugin not initialized")

	// Request errors
	ErrInvalidRequest     = errors.New("jwt: invalid request")
	ErrInvalidGrantType   = errors.New("jwt: invalid grant type")
	ErrInvalidCredentials = errors.New("jwt: invalid credentials")
	ErrUserBanned         = errors.New("jwt: user banned")
)
