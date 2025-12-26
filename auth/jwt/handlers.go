package jwt

import (
	"encoding/json"
	"errors"
	"net/http"
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

// TokenHandler returns a handler for POST /token
func (p *Plugin) TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req tokenRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, errInvalidRequest)
			return
		}

		switch req.GrantType {
		case "password":
			p.handlePasswordGrant(w, r, req)
		case "refresh_token":
			p.handleRefreshGrant(w, r, req)
		default:
			writeError(w, http.StatusBadRequest, errInvalidGrantType)
		}
	}
}

func (p *Plugin) handlePasswordGrant(w http.ResponseWriter, r *http.Request, req tokenRequest) {
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, errInvalidCredentials)
		return
	}

	// Get user by email
	user, err := p.auth.GetPluginUserByEmail(r.Context(), req.Email)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, errInvalidCredentials)
		return
	}

	// Check if user is banned
	if user.Banned {
		writeError(w, http.StatusForbidden, errUserBanned)
		return
	}

	// Verify password
	valid, err := p.auth.VerifyPassword(r.Context(), user.ID, req.Password)
	if err != nil || !valid {
		writeError(w, http.StatusUnauthorized, errInvalidCredentials)
		return
	}

	// Create session for the JWT
	session, err := p.auth.CreateSessionForUser(r.Context(), user.ID, r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	// Generate JWT tokens
	userInfo := UserInfo{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
	}

	pair, err := p.service.GenerateTokenPair(userInfo, session.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	})
}

func (p *Plugin) handleRefreshGrant(w http.ResponseWriter, r *http.Request, req tokenRequest) {
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest)
		return
	}

	// Validate refresh token to get user info
	claims, err := p.service.ValidateRefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errInvalidToken)
		return
	}

	// Get user info
	user, err := p.auth.GetPluginUser(r.Context(), claims.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, errInvalidToken)
		return
	}

	userInfo := UserInfo{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
	}

	// Generate new token pair
	pair, err := p.service.RefreshTokens(r.Context(), req.RefreshToken, userInfo)
	if err != nil {
		writeError(w, http.StatusUnauthorized, errInvalidToken)
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	})
}

// TokenRefreshHandler returns a handler for POST /token/refresh
func (p *Plugin) TokenRefreshHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req refreshTokenRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, errInvalidRequest)
			return
		}

		if req.RefreshToken == "" {
			writeError(w, http.StatusBadRequest, errInvalidRequest)
			return
		}

		// Validate refresh token to get user info
		claims, err := p.service.ValidateRefreshToken(r.Context(), req.RefreshToken)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errInvalidToken)
			return
		}

		// Get user info
		user, err := p.auth.GetPluginUser(r.Context(), claims.UserID)
		if err != nil || user == nil {
			writeError(w, http.StatusUnauthorized, errInvalidToken)
			return
		}

		userInfo := UserInfo{
			ID:            user.ID,
			Email:         user.Email,
			Name:          user.Name,
			EmailVerified: user.EmailVerified,
		}

		// Generate new token pair
		pair, err := p.service.RefreshTokens(r.Context(), req.RefreshToken, userInfo)
		if err != nil {
			writeError(w, http.StatusUnauthorized, errInvalidToken)
			return
		}

		writeJSON(w, http.StatusOK, tokenResponse{
			AccessToken:  pair.AccessToken,
			RefreshToken: pair.RefreshToken,
			TokenType:    pair.TokenType,
			ExpiresIn:    pair.ExpiresIn,
		})
	}
}

// TokenRevokeHandler returns a handler for POST /token/revoke
func (p *Plugin) TokenRevokeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req revokeTokenRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, errInvalidRequest)
			return
		}

		if req.Token == "" {
			writeError(w, http.StatusBadRequest, errInvalidRequest)
			return
		}

		if err := p.service.RevokeToken(r.Context(), req.Token); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// TokenIntrospectHandler returns a handler for POST /token/introspect
func (p *Plugin) TokenIntrospectHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req introspectTokenRequest
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, errInvalidRequest)
			return
		}

		if req.Token == "" {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}

		// Validate token and build introspection response
		claims, err := p.service.ValidateToken(r.Context(), req.Token)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}

		response := map[string]any{
			"active":     true,
			"sub":        claims.Subject,
			"uid":        claims.UserID,
			"email":      claims.Email,
			"name":       claims.Name,
			"token_type": string(claims.TokenType),
		}

		if claims.ExpiresAt != nil {
			response["exp"] = claims.ExpiresAt.Unix()
		}

		if claims.IssuedAt != nil {
			response["iat"] = claims.IssuedAt.Unix()
		}

		writeJSON(w, http.StatusOK, response)
	}
}

// Helper functions (adapted from handlers package)
func decodeJSON(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

// Error variables
var (
	errInvalidRequest     = errors.New("invalid request")
	errInvalidGrantType   = errors.New("invalid grant type")
	errInvalidCredentials = errors.New("invalid credentials")
	errInvalidToken       = errors.New("invalid token")
	errUserBanned         = errors.New("user banned")
)
