package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// JSON response helpers

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
}

// SessionResponse represents a session in API responses
type SessionResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// toUserResponse converts a User to UserResponse
func toUserResponse(u *User) *UserResponse {
	return &UserResponse{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
	}
}

// toSessionResponse converts a Session to SessionResponse
func toSessionResponse(s *Session) *SessionResponse {
	return &SessionResponse{
		ID:        s.ID,
		ExpiresAt: s.ExpiresAt,
	}
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		_ = json.NewEncoder(w).Encode(data)
	}
}

// writeError writes an error response
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, ErrorResponse{
		Error:   http.StatusText(status),
		Message: err.Error(),
	})
}

// Cookie helpers

// SetSessionCookie sets the session cookie on the response
// After setting the cookie, the RawToken is cleared from the session to minimize
// the time sensitive data remains in memory
func (a *Auth) SetSessionCookie(w http.ResponseWriter, session *Session) {
	secure := strings.HasPrefix(a.config.BaseURL, "https://")

	http.SetCookie(w, &http.Cookie{
		Name:     a.config.SessionCookie,
		Value:    session.RawToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
	})

	// Clear the raw token from memory after setting the cookie
	session.RawToken = ""
}

// ClearSessionCookie clears the session cookie
func (a *Auth) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.config.SessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// GetSessionToken extracts the session token from the request
func (a *Auth) GetSessionToken(r *http.Request) string {
	// Check cookie first
	cookie, err := r.Cookie(a.config.SessionCookie)
	if err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// Check Authorization header (Bearer token)
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

// decodeJSON decodes a JSON request body
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
