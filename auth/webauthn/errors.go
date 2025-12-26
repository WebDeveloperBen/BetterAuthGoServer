// Package webauthn provides WebAuthn authentication support.
package webauthn

import "errors"

var (
	ErrNotConfigured      = errors.New("webauthn: not configured")
	ErrInvalidRequest     = errors.New("webauthn: invalid request")
	ErrInvalidResponse    = errors.New("webauthn: invalid response")
	ErrCredentialNotFound = errors.New("webauthn: credential not found")
	ErrSessionNotFound    = errors.New("webauthn: session not found")
	ErrSessionExpired     = errors.New("webauthn: session expired")
	ErrUserNotAllowed     = errors.New("webauthn: user not allowed")
	ErrUserAlreadyExists  = errors.New("webauthn: user already exists")
)
