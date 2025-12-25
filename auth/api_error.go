package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// APIError is returned from hooks to abort with a specific HTTP status.
// It provides a structured way to return errors from middleware hooks.
type APIError struct {
	Status  string `json:"status"`            // Status name: "BAD_REQUEST", "UNAUTHORIZED", etc.
	Message string `json:"message"`           // Human-readable error message
	Code    string `json:"code,omitempty"`    // Optional error code for clients
	Details any    `json:"details,omitempty"` // Optional additional details
}

// Error implements the error interface
func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("%s: %s (%s)", e.Status, e.Message, e.Code)
	}
	return fmt.Sprintf("%s: %s", e.Status, e.Message)
}

// HTTPStatus converts the status string to an HTTP status code
func (e *APIError) HTTPStatus() int {
	switch e.Status {
	case "BAD_REQUEST":
		return http.StatusBadRequest
	case "UNAUTHORIZED":
		return http.StatusUnauthorized
	case "FORBIDDEN":
		return http.StatusForbidden
	case "NOT_FOUND":
		return http.StatusNotFound
	case "METHOD_NOT_ALLOWED":
		return http.StatusMethodNotAllowed
	case "CONFLICT":
		return http.StatusConflict
	case "GONE":
		return http.StatusGone
	case "UNPROCESSABLE_ENTITY":
		return http.StatusUnprocessableEntity
	case "TOO_MANY_REQUESTS":
		return http.StatusTooManyRequests
	case "INTERNAL_ERROR", "INTERNAL_SERVER_ERROR":
		return http.StatusInternalServerError
	case "NOT_IMPLEMENTED":
		return http.StatusNotImplemented
	case "SERVICE_UNAVAILABLE":
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// NewAPIError creates a new APIError with the given status and message
func NewAPIError(status, message string) *APIError {
	return &APIError{
		Status:  status,
		Message: message,
	}
}

// NewAPIErrorWithCode creates a new APIError with status, message, and code
func NewAPIErrorWithCode(status, message, code string) *APIError {
	return &APIError{
		Status:  status,
		Message: message,
		Code:    code,
	}
}

// NewAPIErrorWithDetails creates a new APIError with all fields
func NewAPIErrorWithDetails(status, message, code string, details any) *APIError {
	return &APIError{
		Status:  status,
		Message: message,
		Code:    code,
		Details: details,
	}
}

// Common API errors for convenience
var (
	ErrAPIBadRequest          = NewAPIError("BAD_REQUEST", "bad request")
	ErrAPIUnauthorized        = NewAPIError("UNAUTHORIZED", "unauthorized")
	ErrAPIForbidden           = NewAPIError("FORBIDDEN", "forbidden")
	ErrAPINotFound            = NewAPIError("NOT_FOUND", "not found")
	ErrAPIConflict            = NewAPIError("CONFLICT", "conflict")
	ErrAPITooManyRequests     = NewAPIError("TOO_MANY_REQUESTS", "too many requests")
	ErrAPIInternalServerError = NewAPIError("INTERNAL_ERROR", "internal server error")
)

// WriteAPIError writes an APIError as a JSON response
func WriteAPIError(w http.ResponseWriter, err *APIError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.HTTPStatus())
	json.NewEncoder(w).Encode(err)
}

// IsAPIError checks if an error is an APIError
func IsAPIError(err error) bool {
	_, ok := err.(*APIError)
	return ok
}

// AsAPIError attempts to convert an error to an APIError.
// If the error is not an APIError, it wraps it as an internal error.
func AsAPIError(err error) *APIError {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr
	}
	return &APIError{
		Status:  "INTERNAL_ERROR",
		Message: err.Error(),
	}
}
