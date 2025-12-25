package auth

import (
	"encoding/json"
	"net/http"
	"strings"

	authjwt "github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"
)

// TokenRequest represents the request body for /token endpoint
type TokenRequest struct {
	GrantType    string `json:"grant_type"`     // "password" or "refresh_token"
	Email        string `json:"email,omitempty"`
	Password     string `json:"password,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// TokenResponse represents the response from /token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// handleToken handles POST /token for generating JWT tokens
func (a *Auth) handleToken(w http.ResponseWriter, r *http.Request) {
	if a.jwt == nil {
		writeError(w, http.StatusNotImplemented, ErrJWTNotEnabled)
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	switch req.GrantType {
	case "password":
		a.handlePasswordGrant(w, r, req)
	case "refresh_token":
		a.handleRefreshGrant(w, r, req)
	default:
		writeError(w, http.StatusBadRequest, ErrInvalidGrantType)
	}
}

// handlePasswordGrant handles the password grant type
func (a *Auth) handlePasswordGrant(w http.ResponseWriter, r *http.Request, req TokenRequest) {
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidCredentials)
		return
	}

	// Authenticate user
	user, session, err := a.SignIn(r.Context(), req.Email, req.Password, r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}

	// Generate JWT tokens
	userInfo := authjwt.UserInfo{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
	}

	pair, err := a.jwt.GenerateTokenPair(userInfo, session.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	})
}

// handleRefreshGrant handles the refresh_token grant type
func (a *Auth) handleRefreshGrant(w http.ResponseWriter, r *http.Request, req TokenRequest) {
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	// Validate refresh token
	claims, err := a.jwt.ValidateRefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrInvalidToken)
		return
	}

	// Get user info
	user, err := a.store.GetUserByID(r.Context(), claims.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, ErrUserNotFound)
		return
	}

	userInfo := authjwt.UserInfo{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
	}

	// Generate new token pair
	pair, err := a.jwt.RefreshTokens(r.Context(), req.RefreshToken, userInfo)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrInvalidToken)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	})
}

// handleTokenRefresh handles POST /token/refresh for refreshing tokens
func (a *Auth) handleTokenRefresh(w http.ResponseWriter, r *http.Request) {
	if a.jwt == nil {
		writeError(w, http.StatusNotImplemented, ErrJWTNotEnabled)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	// Validate refresh token
	claims, err := a.jwt.ValidateRefreshToken(r.Context(), req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrInvalidToken)
		return
	}

	// Get user info
	user, err := a.store.GetUserByID(r.Context(), claims.UserID)
	if err != nil || user == nil {
		writeError(w, http.StatusUnauthorized, ErrUserNotFound)
		return
	}

	userInfo := authjwt.UserInfo{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
	}

	// Generate new token pair
	pair, err := a.jwt.RefreshTokens(r.Context(), req.RefreshToken, userInfo)
	if err != nil {
		writeError(w, http.StatusUnauthorized, ErrInvalidToken)
		return
	}

	writeJSON(w, http.StatusOK, TokenResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	})
}

// handleTokenRevoke handles POST /token/revoke for revoking tokens
func (a *Auth) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	if a.jwt == nil {
		writeError(w, http.StatusNotImplemented, ErrJWTNotEnabled)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	if req.Token == "" {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	if err := a.jwt.RevokeToken(r.Context(), req.Token); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleTokenIntrospect handles POST /token/introspect for validating tokens
func (a *Auth) handleTokenIntrospect(w http.ResponseWriter, r *http.Request) {
	if a.jwt == nil {
		writeError(w, http.StatusNotImplemented, ErrJWTNotEnabled)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, ErrInvalidRequest)
		return
	}

	if req.Token == "" {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	claims, err := a.jwt.ValidateToken(r.Context(), req.Token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	response := map[string]any{
		"active":    true,
		"sub":       claims.Subject,
		"uid":       claims.UserID,
		"email":     claims.Email,
		"name":      claims.Name,
		"token_type": string(claims.TokenType),
	}

	if claims.ExpiresAt != nil {
		response["exp"] = claims.ExpiresAt.Unix()
	}
	if claims.IssuedAt != nil {
		response["iat"] = claims.IssuedAt.Unix()
	}
	if claims.Issuer != "" {
		response["iss"] = claims.Issuer
	}

	writeJSON(w, http.StatusOK, response)
}

// GetJWTUserFromRequest extracts user info from a JWT bearer token in the request.
// Returns nil if no valid JWT is present (doesn't check session cookies).
func (a *Auth) GetJWTUserFromRequest(r *http.Request) (*User, error) {
	if a.jwt == nil {
		return nil, ErrJWTNotEnabled
	}

	// Get token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, ErrNoToken
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, ErrInvalidToken
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == "" {
		return nil, ErrInvalidToken
	}

	// Validate token
	claims, err := a.jwt.ValidateAccessToken(r.Context(), tokenString)
	if err != nil {
		return nil, err
	}

	// Get user from store
	return a.store.GetUserByID(r.Context(), claims.UserID)
}

// JWT errors are defined in errors.go:
// - ErrJWTNotEnabled
// - ErrInvalidGrantType
// - ErrNoToken
// - ErrInvalidToken (shared with session errors)
