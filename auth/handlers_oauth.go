package auth

import (
	"errors"
	"net/http"
)

// handleOAuthBegin handles GET /auth/oauth/:provider
func (a *Auth) handleOAuthBegin(w http.ResponseWriter, r *http.Request, provider string) {
	if a.oauth == nil {
		writeError(w, http.StatusNotFound, ErrOAuthProviderNotFound)
		return
	}

	// Get redirect URL from query params
	redirectTo := r.URL.Query().Get("redirect_to")

	authStart, err := a.BeginOAuth(r.Context(), provider, redirectTo)
	if err != nil {
		switch {
		case errors.Is(err, ErrOAuthProviderNotFound):
			writeError(w, http.StatusNotFound, err)
		case errors.Is(err, ErrInvalidRedirect):
			writeError(w, http.StatusBadRequest, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	// Redirect to provider
	http.Redirect(w, r, authStart.URL, http.StatusTemporaryRedirect)
}

// handleOAuthCallback handles GET /auth/oauth/:provider/callback
func (a *Auth) handleOAuthCallback(w http.ResponseWriter, r *http.Request, provider string) {
	if a.oauth == nil {
		writeError(w, http.StatusNotFound, ErrOAuthProviderNotFound)
		return
	}

	// Get code and state from query params
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" || state == "" {
		// Check for error from provider
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			errDesc := r.URL.Query().Get("error_description")
			writeError(w, http.StatusBadRequest, errors.New(errParam+": "+errDesc))
			return
		}
		writeError(w, http.StatusBadRequest, errors.New("code and state are required"))
		return
	}

	user, session, redirectTo, err := a.CompleteOAuth(r.Context(), provider, code, state, r)
	if err != nil {
		switch {
		case errors.Is(err, ErrOAuthProviderNotFound):
			writeError(w, http.StatusNotFound, err)
		case errors.Is(err, ErrOAuthStateMismatch), errors.Is(err, ErrOAuthStateExpired):
			writeError(w, http.StatusBadRequest, err)
		default:
			writeError(w, http.StatusInternalServerError, err)
		}
		return
	}

	// Set session cookie
	a.SetSessionCookie(w, session)

	// For API clients, return JSON
	// For browser clients, redirect to app
	accept := r.Header.Get("Accept")
	if accept == "application/json" {
		writeJSON(w, http.StatusOK, authResponse{
			User:    toUserResponse(user),
			Session: toSessionResponse(session),
		})
		return
	}

	// Use redirect URL from state if provided (already validated during BeginOAuth)
	// Otherwise fall back to BaseURL
	redirectURL := redirectTo
	if redirectURL == "" {
		redirectURL = a.config.BaseURL
	}

	http.Redirect(w, r, redirectURL, http.StatusTemporaryRedirect)
}

// handleListOAuthProviders handles GET /auth/oauth/providers
func (a *Auth) handleListOAuthProviders(w http.ResponseWriter, r *http.Request) {
	var providers []string
	if a.oauth != nil {
		providers = a.oauth.ListProviders()
	} else {
		providers = []string{}
	}

	writeJSON(w, http.StatusOK, map[string][]string{
		"providers": providers,
	})
}
