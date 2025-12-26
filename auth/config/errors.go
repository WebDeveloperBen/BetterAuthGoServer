// Package config provides configuration options and utilities for the authentication system.
package config

import "errors"

// Configuration errors
var (
	ErrMissingSecret  = errors.New("config: secret is required")
	ErrSecretTooShort = errors.New("config: secret must be at least 32 bytes")
	ErrMissingBaseURL = errors.New("config: base URL is required")
	ErrMissingStore   = errors.New("config: store is required")
)

// MinSecretLength is the minimum required length for the secret key
const MinSecretLength = 32
