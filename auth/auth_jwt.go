package auth

import (
	"context"
	"net/http"

	authjwt "github.com/webdeveloperben/BetterAuthGoServer/auth/jwt"
)

// JWTTokenPair represents the response from JWT token operations
type JWTTokenPair struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
}

// JWTEnabled returns whether JWT authentication is enabled
func (a *Auth) JWTEnabled() bool {
	return a.jwt != nil
}

// JWTPasswordGrant authenticates a user and returns JWT tokens
func (a *Auth) JWTPasswordGrant(ctx context.Context, email, password string, r *http.Request) (*JWTTokenPair, error) {
	if a.jwt == nil {
		return nil, ErrJWTNotEnabled
	}

	// Authenticate user
	user, session, err := a.SignIn(ctx, email, password, r)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	return &JWTTokenPair{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	}, nil
}

// JWTRefreshGrant validates a refresh token and returns new JWT tokens
func (a *Auth) JWTRefreshGrant(ctx context.Context, refreshToken string) (*JWTTokenPair, error) {
	if a.jwt == nil {
		return nil, ErrJWTNotEnabled
	}

	// Validate refresh token
	claims, err := a.jwt.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Get user info
	user, err := a.store.GetUserByID(ctx, claims.UserID)
	if err != nil || user == nil {
		return nil, ErrUserNotFound
	}

	userInfo := authjwt.UserInfo{
		ID:            user.ID,
		Email:         user.Email,
		Name:          user.Name,
		EmailVerified: user.EmailVerified,
	}

	// Generate new token pair
	pair, err := a.jwt.RefreshTokens(ctx, refreshToken, userInfo)
	if err != nil {
		return nil, ErrInvalidToken
	}

	return &JWTTokenPair{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	}, nil
}

// JWTRevokeToken revokes a JWT token
func (a *Auth) JWTRevokeToken(ctx context.Context, token string) error {
	if a.jwt == nil {
		return ErrJWTNotEnabled
	}
	return a.jwt.RevokeToken(ctx, token)
}

// JWTIntrospect validates a JWT token and returns its claims
func (a *Auth) JWTIntrospect(ctx context.Context, token string) (map[string]any, error) {
	if a.jwt == nil {
		return nil, ErrJWTNotEnabled
	}

	claims, err := a.jwt.ValidateToken(ctx, token)
	if err != nil {
		return nil, err
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
	if claims.Issuer != "" {
		response["iss"] = claims.Issuer
	}

	return response, nil
}
