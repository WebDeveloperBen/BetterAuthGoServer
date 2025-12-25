package auth

import (
	"errors"
	"html"
	"net/http"
	"regexp"
	"strings"
)

// Request types for handlers

type signUpRequestBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type signInRequestBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type passwordResetRequestBody struct {
	Email string `json:"email"`
}

type passwordResetConfirmBody struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type passwordChangeBody struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

// emailRegex is a regex for email validation
// Validates standard email format: local@domain.tld (requires at least one dot in domain)
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

// validateEmail checks if the email is valid
func validateEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return ErrInvalidEmail
	}
	// Check length limits
	if len(email) > 254 {
		return ErrInvalidEmail
	}
	if !emailRegex.MatchString(email) {
		return ErrInvalidEmail
	}
	return nil
}

// sanitizeName sanitizes a user name to prevent XSS
func sanitizeName(name string) string {
	// Trim whitespace
	name = strings.TrimSpace(name)
	// HTML escape to prevent XSS
	name = html.EscapeString(name)
	return name
}

// Response types

type authResponse struct {
	User    *UserResponse    `json:"user"`
	Session *SessionResponse `json:"session,omitempty"`
}

type sessionsResponse struct {
	Sessions []*SessionResponse `json:"sessions"`
}

// handleSignUp handles POST /auth/sign-up
func (a *Auth) handleSignUp(w http.ResponseWriter, r *http.Request) {
	var req signUpRequestBody
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.Email == "" || req.Password == "" || req.Name == "" {
		writeError(w, http.StatusBadRequest, errors.New("email, password, and name are required"))
		return
	}

	// Validate email format
	if err := validateEmail(req.Email); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// Sanitize user name to prevent XSS
	req.Name = sanitizeName(req.Name)

	user, session, err := a.SignUp(r.Context(), SignUpRequest(req), r)
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

	if session != nil {
		a.SetSessionCookie(w, session)
		resp.Session = toSessionResponse(session)
	}

	writeJSON(w, http.StatusCreated, resp)
}

// handleSignIn handles POST /auth/sign-in
func (a *Auth) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var req signInRequestBody
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, errors.New("email and password are required"))
		return
	}

	user, session, err := a.SignIn(r.Context(), req.Email, req.Password, r)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			writeError(w, http.StatusUnauthorized, err)
		} else {
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	a.SetSessionCookie(w, session)

	writeJSON(w, http.StatusOK, authResponse{
		User:    toUserResponse(user),
		Session: toSessionResponse(session),
	})
}

// handleSignOut handles POST /auth/sign-out
func (a *Auth) handleSignOut(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	if err := a.SignOut(r.Context(), session.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	a.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleGetMe handles GET /auth/me
func (a *Auth) handleGetMe(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	user, err := a.GetUser(r.Context(), session.UserID)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeError(w, http.StatusNotFound, err)
		} else {
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	writeJSON(w, http.StatusOK, authResponse{
		User:    toUserResponse(user),
		Session: toSessionResponse(session),
	})
}

// handlePasswordResetRequest handles POST /auth/password/reset
func (a *Auth) handlePasswordResetRequest(w http.ResponseWriter, r *http.Request) {
	var req passwordResetRequestBody
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, errors.New("email is required"))
		return
	}

	// Always return success to prevent user enumeration
	_ = a.RequestPasswordReset(r.Context(), req.Email)

	w.WriteHeader(http.StatusNoContent)
}

// handlePasswordResetConfirm handles POST /auth/password/confirm
func (a *Auth) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	var req passwordResetConfirmBody
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, errors.New("token and new_password are required"))
		return
	}

	if err := a.ConfirmPasswordReset(r.Context(), req.Token, req.NewPassword); err != nil {
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

// handlePasswordChange handles POST /auth/password/change
func (a *Auth) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	var req passwordChangeBody
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	if req.OldPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, errors.New("old_password and new_password are required"))
		return
	}

	if err := a.ChangePassword(r.Context(), session.UserID, req.OldPassword, req.NewPassword); err != nil {
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

	a.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleSendVerificationEmail handles POST /auth/email/verify/send
func (a *Auth) handleSendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	if err := a.SendVerificationEmail(r.Context(), session.UserID); err != nil {
		switch {
		case errors.Is(err, ErrEmailAlreadyVerified):
			writeError(w, http.StatusBadRequest, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleVerifyEmail handles GET /auth/email/verify?token=xxx
func (a *Auth) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, errors.New("token is required"))
		return
	}

	if err := a.VerifyEmail(r.Context(), token); err != nil {
		switch {
		case errors.Is(err, ErrVerificationNotFound), errors.Is(err, ErrVerificationExpired):
			writeError(w, http.StatusBadRequest, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleListSessions handles GET /auth/sessions
func (a *Auth) handleListSessions(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	sessions, err := a.ListSessions(r.Context(), session.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	resp := sessionsResponse{
		Sessions: make([]*SessionResponse, len(sessions)),
	}
	for i, s := range sessions {
		resp.Sessions[i] = toSessionResponse(s)
	}

	writeJSON(w, http.StatusOK, resp)
}

// handleRevokeSession handles DELETE /auth/sessions/:id
func (a *Auth) handleRevokeSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	currentSession := SessionFromContext(r.Context())
	if currentSession == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	// Get the session to revoke
	targetSession, err := a.store.GetSessionByID(r.Context(), sessionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if targetSession == nil {
		writeError(w, http.StatusNotFound, ErrSessionNotFound)
		return
	}

	// Ensure user owns this session
	if targetSession.UserID != currentSession.UserID {
		writeError(w, http.StatusNotFound, ErrSessionNotFound)
		return
	}

	if err := a.RevokeSession(r.Context(), sessionID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Clear cookie if revoking current session
	if sessionID == currentSession.ID {
		a.ClearSessionCookie(w)
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleRevokeAllSessions handles DELETE /auth/sessions
func (a *Auth) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		writeError(w, http.StatusUnauthorized, ErrSessionNotFound)
		return
	}

	if err := a.SignOutAll(r.Context(), session.UserID); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	a.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
