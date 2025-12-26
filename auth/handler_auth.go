package auth

import (
	"errors"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// authResponse is used for auth endpoints that return user and session
type authResponse struct {
	User    *UserResponse    `json:"user"`
	Session *SessionResponse `json:"session,omitempty"`
}

// handleSignOut handles POST /sign-out
func (a *Auth) handleSignOut(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	if err := a.SignOut(r.Context(), session.ID); err != nil {
		WriteError(w, http.StatusInternalServerError, err)
		return
	}

	a.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleGetMe handles GET /me
func (a *Auth) handleGetMe(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	user, err := a.GetUser(r.Context(), session.UserID)
	if err != nil {
		if errors.Is(err, models.ErrUserNotFound) {
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

// handleSendVerificationEmail handles POST /email/verify/send
func (a *Auth) handleSendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	if err := a.SendVerificationEmail(r.Context(), session.UserID); err != nil {
		switch {
		case errors.Is(err, models.ErrEmailAlreadyVerified):
			WriteError(w, http.StatusBadRequest, err)
		default:
			WriteError(w, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleVerifyEmail handles GET /email/verify
func (a *Auth) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		WriteError(w, http.StatusBadRequest, errors.New("token is required"))
		return
	}

	if err := a.VerifyEmail(r.Context(), token); err != nil {
		switch {
		case errors.Is(err, models.ErrVerificationNotFound), errors.Is(err, models.ErrVerificationExpired):
			WriteError(w, http.StatusBadRequest, err)
		default:
			WriteError(w, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
