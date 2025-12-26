package admin

import "errors"

// Common errors for admin operations.
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidRequest    = errors.New("invalid request")
	ErrAdminNotSupported = errors.New("admin operations not supported by store")
)
