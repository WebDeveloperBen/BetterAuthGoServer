package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Request types.
type registerBeginRequest struct {
	UserID string `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
	Name   string `json:"name,omitempty"`
}

type registerFinishRequest struct {
	SessionID  string          `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

type loginBeginRequest struct {
	UserID string `json:"user_id,omitempty"`
	Email  string `json:"email,omitempty"`
}

type loginFinishRequest struct {
	SessionID  string          `json:"session_id"`
	Credential json.RawMessage `json:"credential"`
}

// Response types.
type beginResponse struct {
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
	Options   any       `json:"options"`
}

type registerFinishResponse struct {
	CredentialID string `json:"credential_id"`
}

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

func (p *Plugin) handleRegisterBegin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req registerBeginRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		user, err := p.resolveUserForRegistration(r, req)
		if err != nil {
			p.writeErrorForHandler(w, err)
			return
		}

		options, session, err := p.service.BeginRegistration(r.Context(), user)
		if err != nil {
			p.writeErrorForHandler(w, err)
			return
		}

		writeJSON(w, http.StatusOK, beginResponse{
			SessionID: session.ID,
			ExpiresAt: session.ExpiresAt,
			Options:   options,
		})
	}
}

func (p *Plugin) handleRegisterFinish() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		var req registerFinishRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.SessionID == "" || len(req.Credential) == 0 {
			writeError(w, http.StatusBadRequest, ErrInvalidRequest)
			return
		}

		session, err := p.service.store.GetSession(r.Context(), req.SessionID)
		if err != nil {
			p.writeErrorForHandler(w, err)
			return
		}
		if session == nil || session.UserID == nil {
			p.writeErrorForHandler(w, ErrSessionNotFound)
			return
		}

		user, err := p.auth.GetPluginUser(r.Context(), *session.UserID)
		if err != nil || user == nil {
			p.writeErrorForHandler(w, ErrUserNotAllowed)
			return
		}

		resetBody(r, req.Credential)
		credential, err := p.service.FinishRegistration(r.Context(), user, req.SessionID, r)
		if err != nil {
			p.writeErrorForHandler(w, err)
			return
		}

		writeJSON(w, http.StatusCreated, registerFinishResponse{
			CredentialID: base64.RawURLEncoding.EncodeToString(credential.CredentialID),
		})
	}
}

func (p *Plugin) handleLoginBegin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.config.AllowSecondFactor && !p.config.AllowPasswordlessAccounts {
			p.writeErrorForHandler(w, ErrNotConfigured)
			return
		}

		var req loginBeginRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		user, err := p.resolveUserForLogin(r, req)
		if err != nil {
			p.writeErrorForHandler(w, err)
			return
		}

		options, session, err := p.service.BeginLogin(r.Context(), user)
		if err != nil {
			p.writeErrorForHandler(w, err)
			return
		}

		writeJSON(w, http.StatusOK, beginResponse{
			SessionID: session.ID,
			ExpiresAt: session.ExpiresAt,
			Options:   options,
		})
	}
}

func (p *Plugin) handleLoginFinish() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !p.config.AllowSecondFactor && !p.config.AllowPasswordlessAccounts {
			p.writeErrorForHandler(w, ErrNotConfigured)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}

		var req loginFinishRequest
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.SessionID == "" || len(req.Credential) == 0 {
			writeError(w, http.StatusBadRequest, ErrInvalidRequest)
			return
		}

		session, err := p.service.store.GetSession(r.Context(), req.SessionID)
		if err != nil {
			p.writeErrorForHandler(w, err)
			return
		}
		if session == nil || session.UserID == nil {
			p.writeErrorForHandler(w, ErrSessionNotFound)
			return
		}

		user, err := p.auth.GetPluginUser(r.Context(), *session.UserID)
		if err != nil || user == nil {
			p.writeErrorForHandler(w, ErrUserNotAllowed)
			return
		}

		resetBody(r, req.Credential)
		_, err = p.service.FinishLogin(r.Context(), user, req.SessionID, r)
		if err != nil {
			p.writeErrorForHandler(w, err)
			return
		}

		if user.Banned {
			p.writeErrorForHandler(w, ErrUserNotAllowed)
			return
		}

		sessionResult, err := p.auth.CreateSessionForUser(r.Context(), user.ID, r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		writeJSON(w, http.StatusOK, authResponse{
			User:    toUserResponse(user),
			Session: toSessionResponse(sessionResult),
		})
	}
}

func (p *Plugin) resolveUserForRegistration(r *http.Request, req registerBeginRequest) (*plugin.User, error) {
	if user, err := p.auth.GetUserFromRequest(r); err == nil && user != nil {
		if user.Banned {
			return nil, ErrUserNotAllowed
		}
		return user, nil
	}

	if !p.config.AllowPasswordlessAccounts {
		return nil, ErrUserNotAllowed
	}
	if req.Email == "" || req.Name == "" {
		return nil, ErrInvalidRequest
	}

	existing, err := p.auth.GetPluginUserByEmail(r.Context(), req.Email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, ErrUserAlreadyExists
	}

	user, err := p.auth.CreatePluginUser(r.Context(), plugin.CreateUserRequest{
		Email:         req.Email,
		Name:          req.Name,
		EmailVerified: false,
	})
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (p *Plugin) resolveUserForLogin(r *http.Request, req loginBeginRequest) (*plugin.User, error) {
	if req.UserID == "" && req.Email == "" {
		return nil, ErrInvalidRequest
	}

	if req.UserID != "" {
		user, err := p.auth.GetPluginUser(r.Context(), req.UserID)
		if err != nil {
			return nil, err
		}
		if user == nil {
			return nil, ErrUserNotAllowed
		}
		return user, nil
	}

	user, err := p.auth.GetPluginUserByEmail(r.Context(), req.Email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotAllowed
	}
	return user, nil
}

func (p *Plugin) writeErrorForHandler(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrInvalidResponse):
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, ErrSessionNotFound), errors.Is(err, ErrSessionExpired):
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, ErrCredentialNotFound):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, ErrUserAlreadyExists):
		writeError(w, http.StatusConflict, err)
	case errors.Is(err, ErrUserNotAllowed):
		writeError(w, http.StatusUnauthorized, err)
	case errors.Is(err, ErrNotConfigured):
		writeError(w, http.StatusServiceUnavailable, err)
	default:
		writeError(w, http.StatusInternalServerError, err)
	}
}

func resetBody(r *http.Request, payload []byte) {
	r.Body = io.NopCloser(bytes.NewReader(payload))
	r.ContentLength = int64(len(payload))
}

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

func toSessionResponse(s *plugin.Session) *sessionResponse {
	if s == nil {
		return nil
	}
	return &sessionResponse{
		ID:        s.ID,
		ExpiresAt: s.ExpiresAt,
	}
}

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
