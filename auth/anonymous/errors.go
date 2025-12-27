// Package anonymous provides anonymous authentication functionality.
package anonymous

import "errors"

var (
	// ErrAlreadyAnonymous is returned when an anonymous user tries to sign in anonymously again
	ErrAlreadyAnonymous = errors.New("anonymous: user is already anonymous")

	// ErrNotConfigured is returned when the plugin is not properly configured
	ErrNotConfigured = errors.New("anonymous: plugin not configured")

	// ErrUserCreation is returned when anonymous user creation fails
	ErrUserCreation = errors.New("anonymous: failed to create anonymous user")

	// ErrSessionCreation is returned when session creation fails
	ErrSessionCreation = errors.New("anonymous: failed to create session")
)
