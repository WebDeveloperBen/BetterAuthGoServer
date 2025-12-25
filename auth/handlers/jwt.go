package handlers

import (
	"net/http"

	"github.com/webdeveloperben/BetterAuthGoServer/auth"
)

// Request types

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	Email        string `json:"email,omitempty"`
	Password     string `json:"password,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type revokeTokenRequest struct {
	Token string `json:"token"`
}

type introspectTokenRequest struct {
	Token string `json:"token"`
}

// Response types

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// Token returns a handler for POST /token
func Token(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.JWTEnabled() {
			WriteError(w, http.StatusNotImplemented, auth.ErrJWTNotEnabled)
			return
		}

		var req tokenRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		switch req.GrantType {
		case "password":
			handlePasswordGrant(a, w, r, req)
		case "refresh_token":
			handleRefreshGrant(a, w, r, req)
		default:
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidGrantType)
		}
	}
}

func handlePasswordGrant(a *auth.Auth, w http.ResponseWriter, r *http.Request, req tokenRequest) {
	if req.Email == "" || req.Password == "" {
		WriteError(w, http.StatusBadRequest, auth.ErrInvalidCredentials)
		return
	}

	pair, err := a.JWTPasswordGrant(r.Context(), req.Email, req.Password, r)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, err)
		return
	}

	WriteJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	})
}

func handleRefreshGrant(a *auth.Auth, w http.ResponseWriter, r *http.Request, req tokenRequest) {
	if req.RefreshToken == "" {
		WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
		return
	}

	pair, err := a.JWTRefreshGrant(r.Context(), req.RefreshToken)
	if err != nil {
		WriteError(w, http.StatusUnauthorized, auth.ErrInvalidToken)
		return
	}

	WriteJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	})
}

// TokenRefresh returns a handler for POST /token/refresh
func TokenRefresh(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.JWTEnabled() {
			WriteError(w, http.StatusNotImplemented, auth.ErrJWTNotEnabled)
			return
		}

		var req refreshTokenRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		if req.RefreshToken == "" {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		pair, err := a.JWTRefreshGrant(r.Context(), req.RefreshToken)
		if err != nil {
			WriteError(w, http.StatusUnauthorized, auth.ErrInvalidToken)
			return
		}

		WriteJSON(w, http.StatusOK, tokenResponse{
			AccessToken:  pair.AccessToken,
			RefreshToken: pair.RefreshToken,
			TokenType:    pair.TokenType,
			ExpiresIn:    pair.ExpiresIn,
		})
	}
}

// TokenRevoke returns a handler for POST /token/revoke
func TokenRevoke(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.JWTEnabled() {
			WriteError(w, http.StatusNotImplemented, auth.ErrJWTNotEnabled)
			return
		}

		var req revokeTokenRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		if req.Token == "" {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		if err := a.JWTRevokeToken(r.Context(), req.Token); err != nil {
			WriteError(w, http.StatusInternalServerError, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// TokenIntrospect returns a handler for POST /token/introspect
func TokenIntrospect(a *auth.Auth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.JWTEnabled() {
			WriteError(w, http.StatusNotImplemented, auth.ErrJWTNotEnabled)
			return
		}

		var req introspectTokenRequest
		if err := DecodeJSON(r, &req); err != nil {
			WriteError(w, http.StatusBadRequest, auth.ErrInvalidRequest)
			return
		}

		if req.Token == "" {
			WriteJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}

		result, err := a.JWTIntrospect(r.Context(), req.Token)
		if err != nil {
			WriteJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}

		WriteJSON(w, http.StatusOK, result)
	}
}
