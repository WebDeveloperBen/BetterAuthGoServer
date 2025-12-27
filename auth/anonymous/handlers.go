// Package anonymous provides HTTP handlers for anonymous authentication.
package anonymous

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/plugin"
)

// Response types

type userResponse struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	Name          string    `json:"name"`
	IsAnonymous   bool      `json:"isAnonymous"`
	EmailVerified bool      `json:"emailVerified"`
	CreatedAt     time.Time `json:"createdAt"`
}

type sessionResponse struct {
	ID        string    `json:"id"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type anonymousResponse struct {
	User    userResponse    `json:"user"`
	Session sessionResponse `json:"session"`
}

// handleAnonymousSignIn handles POST /anonymous
func (p *Plugin) handleAnonymousSignIn() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		// Check if current user is already anonymous
		currentPluginUser, _ := p.auth.GetUserFromRequest(r)
		if currentPluginUser != nil {
			// Query the is_anonymous status from our plugin's column
			isAnonymous, err := IsUserAnonymous(ctx, p.ctx.DB, currentPluginUser.ID)
			if err != nil {
				p.ctx.Logger.Error("failed to check anonymous status", "error", err)
			}
			if isAnonymous {
				writeError(w, http.StatusBadRequest, ErrAlreadyAnonymous)
				return
			}
		}

		// Create anonymous user and session
		user, session, err := p.service.CreateAnonymousUser(ctx, r)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Write auth response (sets cookies/JWT)
		if err := p.ctx.Sessions.WriteAuthResponse(ctx, w, session, user.ToPluginUser()); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		// Return JSON response
		_ = writeJSON(w, http.StatusCreated, anonymousResponse{
			User:    toUserResponse(user),
			Session: toSessionResponse(session),
		})
	}
}

// Helper functions

func toUserResponse(u *User) userResponse {
	return userResponse{
		ID:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		IsAnonymous:   u.IsAnonymous,
		EmailVerified: u.EmailVerified,
		CreatedAt:     u.CreatedAt,
	}
}

func toSessionResponse(s *plugin.Session) sessionResponse {
	return sessionResponse{
		ID:        s.ID,
		ExpiresAt: s.ExpiresAt,
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	_ = writeJSON(w, status, map[string]string{"error": err.Error()})
}
