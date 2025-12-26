package auth

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
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

// Cookie helpers

// SetSessionCookie sets the session cookie on the response
// After setting the cookie, the RawToken is cleared from the session to minimize the time sensitive data remains in memory
func (a *Auth) SetSessionCookie(w http.ResponseWriter, session *models.Session) {
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

// SetPluginSessionCookie sets the session cookie from a plugin session.
// This is used by plugins that need to set session cookies.
func (a *Auth) SetPluginSessionCookie(w http.ResponseWriter, session *plugin.Session) {
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

// DecodeJSON decodes a JSON request body
func DecodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}
