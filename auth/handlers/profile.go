package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// Request types

type profileUpdateRequest struct {
	Name  *string `json:"name,omitempty"`
	Image *string `json:"image,omitempty"`
}

// GetProfile returns a handler for GET /profile
func GetProfile(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		WriteJSON(w, http.StatusOK, ToUserResponse(user))
	}
}

// UpdateProfile returns a handler for PATCH /profile
func UpdateProfile(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		var req profileUpdateRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		updatedUser, err := a.UpdateProfile(r.Context(), user.ID, auth.ProfileUpdates{
			Name:  req.Name,
			Image: req.Image,
		})
		if err != nil {
			WriteError(w, http.StatusInternalServerError, err)
			return
		}

		WriteJSON(w, http.StatusOK, ToUserResponse(updatedUser))
	}
}

// DeleteAccount returns a handler for DELETE /account
func DeleteAccount(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		if err := a.DeleteOwnAccount(r.Context(), user.ID); err != nil {
			WriteError(w, http.StatusInternalServerError, err)
			return
		}

		a.ClearSessionCookie(w)
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListLinkedAccounts returns a handler for GET /accounts
func ListLinkedAccounts(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
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
}

// UnlinkAccount returns a handler for DELETE /accounts/:provider
func UnlinkAccount(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, provider string) {
		user := auth.GetUserFromContext(r.Context())
		if user == nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrSessionNotFound)
			return
		}

		err := a.UnlinkAccount(r.Context(), user.ID, provider)
		if err != nil {
			switch {
			case errors.Is(err, auth.ErrAccountNotFound):
				WriteError(w, http.StatusNotFound, err)
			case errors.Is(err, auth.ErrCannotUnlinkLastAccount):
				WriteError(w, http.StatusBadRequest, err)
			default:
				WriteError(w, http.StatusInternalServerError, err)
			}
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// parseAccountProvider extracts the provider from the path
func parseAccountProvider(path string) string {
	return strings.TrimPrefix(path, "/accounts/")
}
