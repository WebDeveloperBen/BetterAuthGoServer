package admin

import "errors"

// Admin plugin errors
var (
	ErrUserNotFound      = errors.New("admin: user not found")
	ErrInvalidRequest    = errors.New("admin: invalid request")
	ErrAdminNotSupported = errors.New("admin: operations not supported by store")
)
