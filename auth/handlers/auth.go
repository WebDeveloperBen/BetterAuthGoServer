package handlers

import (
	"errors"
	"html"
	"net/http"
	"regexp"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// Request types

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

type passwordResetConfirm struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type passwordChangeRequest struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// Response types

type authResponse struct {
	User    *UserResponse    `json:"user"`
	Session *SessionResponse `json:"session,omitempty"`
}

// emailRegex is a regex for email validation
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

func validateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return auth.ErrInvalidEmail
	}
	if len(email) > 254 {
		return auth.ErrInvalidEmail
	}
	if !emailRegex.MatchString(email) {
		return auth.ErrInvalidEmail
	}
	return nil
}

func sanitizeName(name string) string {
	name = strings.TrimSpace(name)
	name = html.EscapeString(name)
	return name
}

// SignUp returns a handler for POST /sign-up
func SignUp(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req signUpRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, err)
			return
		}

		if req.Email == "" || req.Password == "" || req.Name == "" {
			WriteError(w, http.StatusBadRequest, errors.New("email, password, and name are required"))
			return
		}

		if err := validateEmail(req.Email); err != nil {
			WriteError(w, http.StatusBadRequest, err)
			return
		}

		req.Name = sanitizeName(req.Name)

		user, session, err := a.SignUp(r.Context(), auth.SignUpRequest(req), r)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrUserAlreadyExists):
				WriteError(w, http.StatusConflict, err)
			case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong), errors.Is(err, auth.ErrPasswordTooWeak):
				WriteError(w, http.StatusBadRequest, err)
			default:
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		resp := authResponse{
			User: ToUserResponse(user),
		}

		if session != nil {
			a.SetSessionCookie(w, session)
			resp.Session = ToSessionResponse(session)
		}

		WriteJSON(w, http.StatusCreated, resp)
	}
}

// SignIn returns a handler for POST /sign-in
func SignIn(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req signInRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, err)
			return
		}

		if req.Email == "" || req.Password == "" {
			WriteError(w, http.StatusBadRequest, errors.New("email and password are required"))
			return
		}

		user, session, err := a.SignIn(r.Context(), req.Email, req.Password, r)
		if err != nil {
			if errors.Is(err, auth.ErrInvalidCredentials) {
				WriteError(w, http.StatusUnauthorized, err)
			} else {
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		a.SetSessionCookie(w, session)

		WriteJSON(w, http.StatusOK, authResponse{
			User:    ToUserResponse(user),
			Session: ToSessionResponse(session),
		})
	}
}

// SignOut returns a handler for POST /sign-out
func SignOut(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		if session == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		if err := a.SignOut(r.Context(), session.ID); err != nil {
			WriteError(w, http.StatusInternalServerError, err)
			return
		}

		a.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

// GetMe returns a handler for GET /me
func GetMe(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		if session == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		user, err := a.GetUser(r.Context(), session.UserID)
		if err != nil {
			if errors.Is(err, auth.ErrUserNotFound) {
				WriteError(w, http.StatusNotFound, err)
			} else {
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		WriteJSON(w, http.StatusOK, authResponse{
			User:    ToUserResponse(user),
			Session: ToSessionResponse(session),
		})
	}
}

// RequestPasswordReset returns a handler for POST /password/reset
func RequestPasswordReset(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req passwordResetRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, err)
			return
		}

		if req.Email == "" {
			WriteError(w, http.StatusBadRequest, errors.New("email is required"))
			return
		}

		// Always return success to prevent user enumeration
		_ = a.RequestPasswordReset(r.Context(), req.Email)

		w.WriteHeader(http.StatusNoContent)
	}
}

// ConfirmPasswordReset returns a handler for POST /password/confirm
func ConfirmPasswordReset(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req passwordResetConfirm
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, err)
			return
		}

		if req.Token == "" || req.NewPassword == "" {
			WriteError(w, http.StatusBadRequest, errors.New("token and new_password are required"))
			return
		}

		if err := a.ConfirmPasswordReset(r.Context(), req.Token, req.NewPassword); err != nil {
			switch {
			case errors.Is(err, auth.ErrVerificationNotFound), errors.Is(err, auth.ErrVerificationExpired):
				WriteError(w, http.StatusBadRequest, err)
			case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong), errors.Is(err, auth.ErrPasswordTooWeak):
				WriteError(w, http.StatusBadRequest, err)
			default:
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// ChangePassword returns a handler for POST /password/change
func ChangePassword(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		if session == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		var req passwordChangeRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, err)
			return
		}

		if req.OldPassword == "" || req.NewPassword == "" {
			WriteError(w, http.StatusBadRequest, errors.New("old_password and new_password are required"))
			return
		}

		if err := a.ChangePassword(r.Context(), session.UserID, req.OldPassword, req.NewPassword); err != nil {
			switch {
			case errors.Is(err, auth.ErrInvalidCredentials):
				WriteError(w, http.StatusUnauthorized, err)
			case errors.Is(err, auth.ErrPasswordTooShort), errors.Is(err, auth.ErrPasswordTooLong), errors.Is(err, auth.ErrPasswordTooWeak):
				WriteError(w, http.StatusBadRequest, err)
			default:
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		a.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

// SendVerificationEmail returns a handler for POST /email/verify/send
func SendVerificationEmail(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		if session == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		if err := a.SendVerificationEmail(r.Context(), session.UserID); err != nil {
			switch {
			case errors.Is(err, auth.ErrEmailAlreadyVerified):
				WriteError(w, http.StatusBadRequest, err)
			default:
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// VerifyEmail returns a handler for GET /email/verify
func VerifyEmail(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			WriteError(w, http.StatusBadRequest, errors.New("token is required"))
			return
		}

		if err := a.VerifyEmail(r.Context(), token); err != nil {
			switch {
			case errors.Is(err, auth.ErrVerificationNotFound), errors.Is(err, auth.ErrVerificationExpired):
				WriteError(w, http.StatusBadRequest, err)
			default:
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}
