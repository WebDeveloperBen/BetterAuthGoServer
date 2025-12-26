package otp

import "errors"

var (
	// ErrTokenNotFound is returned when a verification token is not found or has wrong type.
	ErrTokenNotFound = errors.New("otp: token not found")

	// ErrTokenExpired is returned when a verification token has expired.
	ErrTokenExpired = errors.New("otp: token expired")

	// Plugin configuration errors
	ErrPluginNotConfigured = errors.New("otp: plugin not configured")
)
