package handlers

import (
	"errors"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// Response types

type authResponse struct {
	User    *UserResponse    `json:"user"`
	Session *SessionResponse `json:"session,omitempty"`
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
