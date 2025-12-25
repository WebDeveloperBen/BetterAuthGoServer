// Package handlers provides HTTP handlers for the auth package.
// These handlers are thin wrappers that parse HTTP requests, call the
// appropriate auth business methods, and write HTTP responses.
//
// Usage:
//
//	authService, _ := auth.New(store, auth.WithSecret("..."))
//	router := handlers.NewRouter(authService)
//	http.Handle("/auth/", http.StripPrefix("/auth", router))
package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// UserResponse represents a user in API responses
type UserResponse struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Name          string  `json:"name"`
	Image         *string `json:"image,omitempty"`
	Banned        bool    `json:"banned"`
	BanReason     *string `json:"ban_reason,omitempty"`
	Role          string  `json:"role"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

// SessionResponse represents a session in API responses
type SessionResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AccountResponse represents an OAuth account in API responses
type AccountResponse struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
}

// ToUserResponse converts a User to UserResponse
func ToUserResponse(u *models.User) *UserResponse {
	if u == nil {
		return nil
	}
	return &UserResponse{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Banned:        u.Banned,
		BanReason:     u.BanReason,
		Role:          u.Role,
		CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:     u.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// ToSessionResponse converts a Session to SessionResponse
func ToSessionResponse(s *models.Session) *SessionResponse {
	if s == nil {
		return nil
	}
	return &SessionResponse{
		ID:        s.ID,
		ExpiresAt: s.ExpiresAt,
	}
}

// WriteJSON writes a JSON response
func WriteJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
	}
}

// WriteError writes an error response
func WriteError(w http.ResponseWriter, status int, err error) {
	WriteJSON(w, status, ErrorResponse{
		Error:   http.StatusText(status),
		Message: err.Error(),
	})
}

// DecodeJSON decodes a JSON request body
func DecodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
