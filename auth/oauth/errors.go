// Package oauth provides OAuth 2.0 authentication integration for the auth server.
// It handles OAuth provider configuration, user account linking, and authentication flows.
package oauth

import "errors"

// OAuth plugin errors
var (
	ErrProviderNotFound = errors.New("oauth: provider not found")
	ErrStateMismatch    = errors.New("oauth: state mismatch")
	ErrStateExpired     = errors.New("oauth: state expired")
	ErrStateNotFound    = errors.New("oauth: state not found")
	ErrMissingCode      = errors.New("oauth: missing code or state parameter")
	ErrNoUserInfo       = errors.New("oauth: no user info in result")
	ErrStoreRequired    = errors.New("oauth: plugin store is required")
)
