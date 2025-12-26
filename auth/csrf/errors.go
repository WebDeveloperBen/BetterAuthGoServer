package csrf

import "errors"

// CSRF plugin errors
var (
	ErrTokenMissing  = errors.New("csrf: token missing")
	ErrTokenMismatch = errors.New("csrf: token mismatch")
)
