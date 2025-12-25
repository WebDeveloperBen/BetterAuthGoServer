package handlers

import (
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// Response types

type sessionsResponse struct {
	Sessions []*SessionResponse `json:"sessions"`
}

// ListSessions returns a handler for GET /sessions
func ListSessions(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		if session == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		sessions, err := a.ListSessions(r.Context(), session.UserID)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, err)
			return
		}

		resp := sessionsResponse{
			Sessions: make([]*SessionResponse, len(sessions)),
		}
		for i, s := range sessions {
			resp.Sessions[i] = ToSessionResponse(s)
		}

		WriteJSON(w, http.StatusOK, resp)
	}
}

// RevokeSession returns a handler for DELETE /sessions/:id
func RevokeSession(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, sessionID string) {
		currentSession := auth.SessionFromContext(r.Context())
		if currentSession == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		// Get the session to revoke and verify ownership
		targetSession, err := a.GetSessionByID(r.Context(), sessionID)
		if err != nil {
			WriteError(w, http.StatusInternalServerError, err)
			return
		}
		if targetSession == nil {
			WriteError(w, http.StatusNotFound, auth.ErrSessionNotFound)
			return
		}

		// Ensure user owns this session
		if targetSession.UserID != currentSession.UserID {
			WriteError(w, http.StatusNotFound, auth.ErrSessionNotFound)
			return
		}

		if err := a.RevokeSession(r.Context(), sessionID); err != nil {
			WriteError(w, http.StatusInternalServerError, err)
			return
		}

		// Clear cookie if revoking current session
		if sessionID == currentSession.ID {
			a.ClearSessionCookie(w)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// RevokeAllSessions returns a handler for DELETE /sessions
func RevokeAllSessions(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.SessionFromContext(r.Context())
		if session == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		if err := a.SignOutAll(r.Context(), session.UserID); err != nil {
			WriteError(w, http.StatusInternalServerError, err)
			return
		}

		a.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

// parseSessionID extracts the session ID from the path
func parseSessionID(path string) string {
	return strings.TrimPrefix(path, "/sessions/")
}
