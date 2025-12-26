package admin

import "errors"

// Admin plugin errors
var (
	ErrUserNotFound      = errors.New("admin: user not found")
	ErrInvalidRequest    = errors.New("admin: invalid request")
	ErrAdminNotSupported = errors.New("admin: operations not supported by store")

	// Impersonation errors
	ErrImpersonationNotAllowed     = errors.New("admin: you are not allowed to impersonate users")
	ErrCannotImpersonateAdmins     = errors.New("admin: you cannot impersonate admin users")
	ErrNotImpersonating            = errors.New("admin: you are not currently impersonating anyone")
	ErrImpersonationSessionInvalid = errors.New("admin: original admin session is invalid or expired")
	ErrImpersonationNotSupported   = errors.New("admin: impersonation not supported")
)
