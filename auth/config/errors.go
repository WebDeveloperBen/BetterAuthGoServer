package config

import "errors"

// Configuration errors
var (
	ErrMissingSecret  = errors.New("secret is required")
	ErrSecretTooShort = errors.New("secret must be at least 32 bytes")
	ErrMissingBaseURL = errors.New("base URL is required")
	ErrMissingStore   = errors.New("store is required")
)

// MinSecretLength is the minimum required length for the secret key
const MinSecretLength = 32
