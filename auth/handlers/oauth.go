package handlers

import (
	"net/http"
	"strings"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// Response types

type oauthProvidersResponse struct {
	Providers []string `json:"providers"`
}

// ListOAuthProviders returns a handler for GET /oauth/providers
func ListOAuthProviders(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providers := a.ListOAuthProviders()
		WriteJSON(w, http.StatusOK, oauthProvidersResponse{
			Providers: providers,
		})
	}
}

// OAuthBegin returns a handler for GET /oauth/:provider
func OAuthBegin(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, provider string) {
		redirectTo := r.URL.Query().Get("redirect_to")

		result, err := a.BeginOAuth(r.Context(), provider, redirectTo)
		if err != nil {
			WriteError(w, http.StatusBadRequest, err)
			return
		}

		http.Redirect(w, r, result.URL, http.StatusFound)
	}
}

// OAuthCallback returns a handler for GET /oauth/:provider/callback
func OAuthCallback(a *auth.Auth) func(http.ResponseWriter, *http.Request, string) {
	return func(w http.ResponseWriter, r *http.Request, provider string) {
		code := r.URL.Query().Get("code")
		state := r.URL.Query().Get("state")

		if code == "" || state == "" {
			WriteError(w, http.StatusBadRequest, auth.ErrOAuthStateMismatch)
			return
		}

		user, session, redirectTo, err := a.CompleteOAuth(r.Context(), provider, code, state, r)
		if err != nil {
			WriteError(w, http.StatusBadRequest, err)
			return
		}

		a.SetSessionCookie(w, session)

		// Redirect to the URL from state if provided, otherwise return JSON
		if redirectTo != "" {
			http.Redirect(w, r, redirectTo, http.StatusFound)
			return
		}

		WriteJSON(w, http.StatusOK, map[string]any{
			"user":    ToUserResponse(user),
			"session": ToSessionResponse(session),
		})
	}
}

// parseOAuthPath extracts provider and action from /oauth/:provider or /oauth/:provider/callback
func parseOAuthPath(path string) (provider string, isCallback bool) {
	path = strings.TrimPrefix(path, "/oauth/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		return "", false
	}

	provider = parts[0]
	isCallback = len(parts) >= 2 && parts[1] == "callback"
	return provider, isCallback
}
