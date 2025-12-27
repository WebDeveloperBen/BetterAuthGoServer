// Package apikey provides API key authentication as a plugin.
package apikey

import (
	"errors"
	"fmt"
	"time"
)

// Package-level errors
var (
	ErrInvalidAPIKey     = errors.New("apikey: invalid api key")
	ErrExpiredAPIKey     = errors.New("apikey: api key expired")
	ErrDisabledAPIKey    = errors.New("apikey: api key disabled")
	ErrRateLimited       = errors.New("apikey: rate limited")
	ErrNoRemainingUses   = errors.New("apikey: no remaining uses")
	ErrInsufficientPerms = errors.New("apikey: insufficient permissions")
	ErrKeyNotFound       = errors.New("apikey: key not found")
	ErrInvalidPrefix     = errors.New("apikey: invalid prefix")
	ErrInvalidName       = errors.New("apikey: invalid name")
	ErrUnauthorized      = errors.New("apikey: unauthorized")
)

// RateLimitError is returned when a rate limit is exceeded.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("apikey: rate limited, retry after %s", e.RetryAfter)
}

func (e *RateLimitError) Unwrap() error {
	return ErrRateLimited
}

// VerifyError represents an API key verification error with additional details.
type VerifyError struct {
	Code    string
	Message string
	Err     error
}

func (e *VerifyError) Error() string {
	return e.Message
}

func (e *VerifyError) Unwrap() error {
	return e.Err
}

// Error codes for API responses
const (
	ErrCodeInvalidKey        = "INVALID_API_KEY"
	ErrCodeExpiredKey        = "API_KEY_EXPIRED"
	ErrCodeDisabledKey       = "API_KEY_DISABLED"
	ErrCodeRateLimited       = "RATE_LIMITED"
	ErrCodeNoRemaining       = "NO_REMAINING_USES"
	ErrCodeInsufficientPerms = "INSUFFICIENT_PERMISSIONS"
	ErrCodeKeyNotFound       = "KEY_NOT_FOUND"
)
