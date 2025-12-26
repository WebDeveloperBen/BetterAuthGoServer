package password

import (
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Request types.
type signUpRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type signInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

type passwordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type passwordChangeRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// Response types.
type authResponse struct {
	User    *userResponse    `json:"user"`
	Session *sessionResponse `json:"session,omitempty"`
}

type userResponse struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"email_verified"`
	Name          string  `json:"name"`
	Image         *string `json:"image,omitempty"`
	Role          string  `json:"role"`
	CreatedAt     string  `json:"created_at"`
	UpdatedAt     string  `json:"updated_at"`
}

type sessionResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Handler errors.
var (
	errInvalidRequest = errors.New("invalid request")
	errInvalidEmail   = errors.New("invalid email address")
)

// emailRegex is a regex for email validation.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

// handleSignUp returns a handler for POST /sign-up.
func (p *Plugin) handleSignUp() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req signUpRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if req.Email == "" || req.Password == "" || req.Name == "" {
			writeError(w, http.StatusBadRequest, errors.New("email, password, and name are required"))
			return
		}

		if err := validateEmail(req.Email); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		req.Name = sanitizeName(req.Name)

		user, session, err := p.service.SignUp(r.Context(), req.Email, req.Password, req.Name, r)
		if err != nil {
			switch {
			case errors.Is(err, ErrUserAlreadyExists):
				writeError(w, http.StatusConflict, err)
			case errors.Is(err, ErrPasswordTooShort), errors.Is(err, ErrPasswordTooLong), errors.Is(err, ErrPasswordTooWeak):
				writeError(w, http.StatusBadRequest, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}

		resp := authResponse{
			User: toUserResponse(user),
		}

		if session != nil && p.sessionCookie != nil {
			p.sessionCookie.SetPluginSessionCookie(w, session)
			resp.Session = toSessionResponse(session)
		}

		writeJSON(w, http.StatusCreated, resp)
	}
}

// handleSignIn returns a handler for POST /sign-in.
func (p *Plugin) handleSignIn() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req signInRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if req.Email == "" || req.Password == "" {
			writeError(w, http.StatusBadRequest, errors.New("email and password are required"))
			return
		}

		user, session, err := p.service.SignIn(r.Context(), req.Email, req.Password, r)
		if err != nil {
			if errors.Is(err, ErrInvalidCredentials) {
				writeError(w, http.StatusUnauthorized, err)
			} else {
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}

		if p.sessionCookie != nil {
			p.sessionCookie.SetPluginSessionCookie(w, session)
		}

		writeJSON(w, http.StatusOK, authResponse{
			User:    toUserResponse(user),
			Session: toSessionResponse(session),
		})
	}
}

// handlePasswordReset returns a handler for POST /password/reset.
func (p *Plugin) handlePasswordReset() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req passwordResetRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if req.Email == "" {
			writeError(w, http.StatusBadRequest, errors.New("email is required"))
			return
		}

		// Always return success to prevent user enumeration
		_ = p.service.RequestPasswordReset(r.Context(), req.Email)

		w.WriteHeader(http.StatusNoContent)
	}
}

// handlePasswordConfirm returns a handler for POST /password/confirm.
func (p *Plugin) handlePasswordConfirm() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req passwordResetConfirmRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if req.Token == "" || req.NewPassword == "" {
			writeError(w, http.StatusBadRequest, errors.New("token and new_password are required"))
			return
		}

		if err := p.service.ConfirmPasswordReset(r.Context(), req.Token, req.NewPassword); err != nil {
			switch {
			case errors.Is(err, ErrVerificationNotFound), errors.Is(err, ErrVerificationExpired):
				writeError(w, http.StatusBadRequest, err)
			case errors.Is(err, ErrPasswordTooShort), errors.Is(err, ErrPasswordTooLong), errors.Is(err, ErrPasswordTooWeak):
				writeError(w, http.StatusBadRequest, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// handlePasswordChange returns a handler for POST /password/change.
func (p *Plugin) handlePasswordChange() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get session from context (requires auth middleware)
		if p.sessionGetter == nil {
			writeError(w, http.StatusInternalServerError, errors.New("session getter not available"))
			return
		}

		session := p.sessionGetter.GetSessionFromRequest(r)
		if session == nil {
			writeError(w, http.StatusUnauthorized, errors.New("session not found"))
			return
		}

		var req passwordChangeRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		if req.OldPassword == "" || req.NewPassword == "" {
			writeError(w, http.StatusBadRequest, errors.New("old_password and new_password are required"))
			return
		}

		if err := p.service.ChangePassword(r.Context(), session.UserID, req.OldPassword, req.NewPassword); err != nil {
			switch {
			case errors.Is(err, ErrInvalidCredentials):
				writeError(w, http.StatusUnauthorized, err)
			case errors.Is(err, ErrPasswordTooShort), errors.Is(err, ErrPasswordTooLong), errors.Is(err, ErrPasswordTooWeak):
				writeError(w, http.StatusBadRequest, err)
			default:
				writeError(w, http.StatusInternalServerError, err)
			}
			return
		}

		// Clear session cookie since all sessions are invalidated
		if p.sessionCookie != nil {
			p.sessionCookie.ClearSessionCookie(w)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// validateEmail validates an email address.
func validateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return errInvalidEmail
	}
	if len(email) > 254 {
		return errInvalidEmail
	}
	if !emailRegex.MatchString(email) {
		return errInvalidEmail
	}
	return nil
}

// sanitizeName sanitizes a user name.
func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	name = html.EscapeString(name)
	return name
}

// toUserResponse converts a plugin.User to userResponse.
func toUserResponse(u *plugin.User) *userResponse {
	if u == nil {
		return nil
	}
	return &userResponse{
		ID:            u.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Image:         u.Image,
		Role:          u.Role,
		CreatedAt:     u.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:     u.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// toSessionResponse converts a plugin.Session to sessionResponse.
func toSessionResponse(s *plugin.Session) *sessionResponse {
	if s == nil {
		return nil
	}
	return &sessionResponse{
		ID:        s.ID,
		ExpiresAt: s.ExpiresAt,
	}
}

// Helper functions.
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{
		"error":   http.StatusText(status),
		"message": err.Error(),
	})
}
