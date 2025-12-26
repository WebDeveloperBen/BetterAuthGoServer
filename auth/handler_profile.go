package auth

import (
	"errors"
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth/models"
)

// profileUpdateRequest is the request body for updating profile
type profileUpdateRequest struct {
	Name  *string `json:"name,omitempty"`
	Image *string `json:"image,omitempty"`
}

// handleGetProfile handles GET /profile
func (a *Auth) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	WriteJSON(w, http.StatusOK, ToUserResponse(user))
}

// handleUpdateProfile handles PATCH /profile
func (a *Auth) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	var req profileUpdateRequest
	if err := DecodeJSON(r, &req); err != nil {
		WriteError(w, http.StatusBadRequest, models.ErrInvalidRequest)
		return
	}

	updatedUser, err := a.UpdateProfile(r.Context(), user.ID, ProfileUpdates(req))
	if err != nil {
		WriteError(w, http.StatusInternalServerError, err)
		return
	}

	WriteJSON(w, http.StatusOK, ToUserResponse(updatedUser))
}

// handleDeleteAccount handles DELETE /account
func (a *Auth) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	if err := a.DeleteOwnAccount(r.Context(), user.ID); err != nil {
		WriteError(w, http.StatusInternalServerError, err)
		return
	}

	a.ClearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

// handleListLinkedAccounts handles GET /accounts
func (a *Auth) handleListLinkedAccounts(w http.ResponseWriter, r *http.Request) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	accounts, err := a.ListLinkedAccounts(r.Context(), user.ID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, err)
		return
	}

	response := make([]*AccountResponse, len(accounts))
	for i, acc := range accounts {
		response[i] = &AccountResponse{
			ID:       acc.ID,
			Provider: string(acc.Provider),
		}
	}

	WriteJSON(w, http.StatusOK, response)
}

// handleUnlinkAccount handles DELETE /accounts/:provider
func (a *Auth) handleUnlinkAccount(w http.ResponseWriter, r *http.Request, provider string) {
	user := GetUserFromContext(r.Context())
	if user == nil {
		WriteError(w, http.StatusUnauthorized, models.ErrSessionNotFound)
		return
	}

	err := a.UnlinkAccount(r.Context(), user.ID, provider)
	if err != nil {
		switch {
		case errors.Is(err, models.ErrAccountNotFound):
			WriteError(w, http.StatusNotFound, err)
		case errors.Is(err, models.ErrCannotUnlinkLastAccount):
			WriteError(w, http.StatusBadRequest, err)
		default:
			WriteError(w, http.StatusInternalServerError, err)
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
