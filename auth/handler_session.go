package auth

import (
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// sessionsResponse is used for listing sessions
type sessionsResponse struct {
	Sessions []*SessionResponse `json:"sessions"`
}

// handleListSessions handles GET /sessions
func (a *Auth) handleListSessions(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
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

// handleRevokeSession handles DELETE /sessions/:id
func (a *Auth) handleRevokeSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	currentSession := SessionFromContext(r.Context())
	if currentSession == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	// Get the session to revoke and verify ownership
	targetSession, err := a.GetSessionByID(r.Context(), sessionID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, err)
		return
	}
	if targetSession == nil {
		WriteError(w, http.StatusNotFound, models.ErrSessionNotFound)
		return
	}

	// Ensure user owns this session
	if targetSession.UserID != currentSession.UserID {
		WriteError(w, http.StatusNotFound, models.ErrSessionNotFound)
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

// handleRevokeAllSessions handles DELETE /sessions
func (a *Auth) handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	session := SessionFromContext(r.Context())
	if session == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	if err := a.SignOutAll(r.Context(), session.UserID); err != nil {
		WriteError(w, http.StatusInternalServerError, err)
		return
	}

	a.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}
